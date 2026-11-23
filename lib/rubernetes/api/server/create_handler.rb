# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # POST of a resource: name generation, the decode-default-admit-validate
      # sequence, and the registry strategies' PrepareForCreate hooks.
      module CreateHandler
        MAX_GENERATE_NAME_ATTEMPTS = 8

        private

        def create_response(request, route)
          namespace = storage_namespace(route, operation: :create)
          validate_write_options!(request, "CreateOptions")
          object = normalize_object(request, route)
          generate_name = object["metadata"]["generateName"].to_s
          ensure_nameable!(object, route)
          ensure_namespace_exists!(route.resource, namespace)
          unknown_mode = enforce_field_validation(route.resource, object, request,
                                                  duplicates: request_duplicate_fields(request))
          generate = metadata_value(object, "name").to_s.empty?
          attempts = 0
          last_generated_name = nil
          loop do
            attempts += 1
            candidate = deep_copy(object)
            candidate["metadata"]["name"] = generated_name(generate_name) if candidate["metadata"]["name"].to_s.empty?
            last_generated_name = metadata_value(candidate, "name")
            begin
              with_registry_allocations(route) do |allocation|
                candidate = admitted_for_create(request, route, candidate, namespace, unknown_mode, allocation: allocation)
                if dry_run?(request)
                  preview = dry_run_create(route.resource, namespace, candidate)
                  return json_response(preview, status: 201)
                end
                created = @store.create(resource: route.resource, namespace: namespace, object: candidate,
                                        **(allocation&.write_preconditions || {}))
                allocation&.commit!
                after_commit(route.resource, created)
                return json_response(created, status: 201)
              end
            rescue MemoryStore::AlreadyExists
              raise unless generate && attempts < MAX_GENERATE_NAME_ATTEMPTS
            end
          end
        rescue MemoryStore::AlreadyExists
          raise existing_resource(route, last_generated_name)
        end

        def dry_run_create(resource, namespace, candidate)
          @store.get(resource: resource, namespace: namespace, name: metadata_value(candidate, "name"))
          raise MemoryStore::AlreadyExists
        rescue MemoryStore::NotFound
          candidate = Schema::JobSelector.decode_labels(candidate) if Schema::JobSelector.resource?(resource)
          dry_run_view(candidate, namespace)
        end

        def ensure_nameable!(object, route)
          metadata = object["metadata"]
          return unless metadata["name"].to_s.empty? && metadata["generateName"].to_s.empty?

          cause = {
            "reason" => "FieldValueRequired",
            "message" => "Required value: name or generateName is required",
            "field" => "metadata.name"
          }
          group = route.resource.group
          kind = [route.resource.kind, group].reject { |part| part.to_s.empty? }.join(".")
          details = {"kind" => route.resource.kind, "causes" => [cause]}
          details["group"] = group unless group.to_s.empty?
          raise Status::Invalid.new("#{kind} \"\" is invalid: metadata.name: #{cause.fetch("message")}", details: details)
        end

        # Defaulting and field ownership follow decoding. Mutating admission
        # can repair a semantically invalid object before registry validation.
        def admitted_for_create(request, route, candidate, namespace, unknown_mode, allocation:)
          inherited_labels = Schema::JobSelector.inherited_labels(candidate) if Schema::JobSelector.resource?(route.resource)
          # SetDefaults_* runs at decode time upstream, i.e. before the schema
          # validator requires a ReplicationController selector.
          candidate = apply_pre_validation_defaults(route.resource, candidate)
          candidate = default_schema_for_write(route.resource, candidate, unknown_fields: unknown_mode)
          candidate = before_mutation = with_managed_fields(candidate, record_managed_update(request, route, nil, candidate))
          candidate = admit_mutating(request, route, "CREATE", candidate, nil, namespace)
          candidate = redefault_after_mutation(route.resource, candidate, before_mutation, unknown_fields: unknown_mode)
          finish_admitted_create(request, route, candidate, namespace, allocation: allocation, inherited_job_labels: inherited_labels)
        end

        def finish_admitted_create(request, route, candidate, namespace, allocation:, inherited_job_labels:)
          candidate = clear_status_on_create(route.resource, candidate)
          job = Schema::JobSelector.resource?(route.resource)
          if job
            candidate = prepare_created_metadata(candidate, resource: route.resource)
            Schema::JobSelector.generate!(candidate, inherited_labels: inherited_job_labels)
          end
          candidate = validate_schema(route.resource, candidate, operation: :create)
          candidate = drop_disabled_pod_fields(route.resource, candidate)
          merge_label_keys!(candidate) if pod_resource?(route.resource)
          candidate = inject_csr_requester(request, route.resource, candidate)
          validate_object!(route.resource, candidate)
          candidate = prepare_created_metadata(candidate, resource: route.resource) unless job
          authorize_storage_create!(request, route, metadata_value(candidate, "name"))
          admit_validating(request, route, "CREATE", candidate, nil, namespace)
          candidate = prepare_registry_create(route.resource, candidate, dry_run: dry_run?(request), allocation: allocation)
          deep_copy(candidate)
        end

        # An update or apply that inserts an object needs create permission as
        # well. A named custom-resource POST can likewise create the body name.
        def authorize_storage_create!(request, route, name)
          authorizer = @security&.authorizer
          return unless authorizer
          return if request.method == "POST" && (!route.name || route.name == name)

          attributes = request.attributes.with(verb: "create", name: name)
          decision = authorizer.authorize(attributes)
          return if decision.allowed?

          forbidden = Security::Pipeline::Forbidden.new(decision.reason || "forbidden", decision: decision, user: attributes.user, attributes: attributes)
          raise forbidden_status(forbidden, request, route)
        end

        # NamespaceLifecycle admission: a namespaced object cannot be created in
        # a namespace that does not exist, and the system namespaces always do.
        def ensure_namespace_exists!(resource, namespace)
          return unless @namespace_lifecycle
          return if resource.cluster_scoped? || namespace == :cluster || namespace == :all || namespace.to_s.empty?
          return if resource.kind == "Namespace"

          namespaces = namespaces_resource
          return if namespaces.nil?

          found = @store.get(resource: namespaces, namespace: :cluster, name: namespace.to_s)
          # plugin/pkg/admission/namespace/lifecycle: while a namespace is being
          # terminated no new content may be created inside it, or the namespace
          # controller races new objects forever and never finishes.
          return unless metadata_value(found, "deletionTimestamp")

          raise Status::Forbidden.new(
            "unable to create new content in namespace #{namespace} because it is being terminated",
            details: {"name" => namespace.to_s, "kind" => resource.kind.to_s.downcase,
                      "causes" => [{"reason" => "NamespaceTerminating", "message" => "namespace #{namespace} is being terminated",
                                    "field" => "metadata.namespace"}]}
          )
        rescue MemoryStore::NotFound
          return if admission_chain&.names&.include?("NamespaceAutoProvision")

          raise Status::NotFound.new("namespaces #{namespace.to_s.inspect} not found",
                                     details: {"name" => namespace.to_s, "kind" => "namespaces"})
        end

        def namespaces_resource
          return @namespaces_resource if defined?(@namespaces_resource)

          @namespaces_resource = @registry.find_gvr(group: "", version: "v1", resource: "namespaces")
        end

        # Pod strategy PrepareForCreate mutatePodAffinity: each matchLabelKeys
        # key the Pod carries becomes `key In (value)` in the term's selector,
        # each mismatchLabelKeys key `key NotIn (value)`.  A nil selector
        # matches nothing and is left alone.
        def merge_label_keys!(pod)
          labels = pod.dig("metadata", "labels")
          labels = {} unless labels.is_a?(Hash)
          spec = pod["spec"]
          return pod unless spec.is_a?(Hash)

          merge = lambda do |holder, keys, operator|
            selector = holder["labelSelector"]
            Array(keys).each do |key|
              next unless labels.key?(key.to_s)

              (selector["matchExpressions"] ||= []) << {"key" => key.to_s, "operator" => operator, "values" => [labels[key.to_s].to_s]}
            end
          end
          affinity = spec["affinity"]
          if affinity.is_a?(Hash)
            %w[podAffinity podAntiAffinity].each do |section|
              terms = affinity[section]
              next unless terms.is_a?(Hash)

              required = Array(terms["requiredDuringSchedulingIgnoredDuringExecution"])
              preferred = Array(terms["preferredDuringSchedulingIgnoredDuringExecution"]).map do |weighted|
                weighted.is_a?(Hash) ? weighted["podAffinityTerm"] : nil
              end
              (required + preferred).each do |term|
                next unless term.is_a?(Hash) && term["labelSelector"].is_a?(Hash)
                next if Array(term["matchLabelKeys"]).empty? && Array(term["mismatchLabelKeys"]).empty?

                merge.call(term, term["matchLabelKeys"], "In")
                merge.call(term, term["mismatchLabelKeys"], "NotIn")
              end
            end
          end
          pod
        end

        # csrStrategy.PrepareForCreate: whatever the client wrote, the request
        # names the user who created it (username, uid, groups, extra).  It
        # runs after mutating admission and before validation, as upstream.
        def inject_csr_requester(request, resource, object)
          return object unless csr_resource?(resource) && object.is_a?(Hash)

          result = deep_copy(object)
          spec = result["spec"].is_a?(Hash) ? result["spec"] : (result["spec"] = {})
          %w[username uid groups extra].each { |key| spec.delete(key) }
          identity = identity_fields(request.identity)
          if identity
            username = (identity["username"] || identity[:username] || identity["name"] || identity[:name]).to_s
            uid = (identity["uid"] || identity[:uid]).to_s
            groups = Array(identity["groups"] || identity[:groups]).map(&:to_s)
            extra = identity["extra"] || identity[:extra] || {}
            spec["username"] = username unless username.empty?
            spec["uid"] = uid unless uid.empty?
            spec["groups"] = groups unless groups.empty?
            spec["extra"] = extra.to_h { |key, values| [key.to_s, Array(values).map(&:to_s)] } unless extra.empty?
          end
          # registry/certificates/csr metrics: a CSR that asks for a duration.
          if spec["expirationSeconds"]
            @metrics&.increment("apiserver_certificates_registry_csr_requested_duration_total", {"signerName" => spec["signerName"].to_s})
          end
          result
        end

        # Strategy.PrepareForCreate resets .status -- but only for the kinds whose
        # strategy actually does it.  NOT every kind: a Node is REGISTERED with
        # its status by the kubelet (nodeStrategy.PrepareForCreate touches only
        # disabled fields), and a Pod's binding-time status likewise.  Clearing
        # it everywhere left every Node without conditions, so no Node ever
        # became Ready and the cluster never came up.
        #
        # This is the exact set: `grep -A 12 "func .*) PrepareForCreate"
        # pkg/registry/*/*/strategy.go | grep "\.Status = .*{}"`.
        STATUS_CLEARED_ON_CREATE = [
          ["admissionregistration.k8s.io", "validatingadmissionpolicies"],
          ["internal.apiserver.k8s.io", "storageversions"],
          ["apps", "daemonsets"], ["apps", "deployments"], ["apps", "replicasets"],
          ["apps", "statefulsets"],
          ["autoscaling", "horizontalpodautoscalers"],
          ["batch", "cronjobs"], ["batch", "jobs"],
          ["certificates.k8s.io", "certificatesigningrequests"], ["certificates.k8s.io", "podcertificaterequests"],
          ["", "persistentvolumeclaims"], ["", "persistentvolumes"],
          ["", "replicationcontrollers"], ["", "resourcequotas"], ["", "services"],
          ["flowcontrol.apiserver.k8s.io", "flowschemas"],
          ["flowcontrol.apiserver.k8s.io", "prioritylevelconfigurations"],
          ["networking.k8s.io", "ingresses"], ["networking.k8s.io", "servicecidrs"],
          ["policy", "poddisruptionbudgets"],
          ["resource.k8s.io", "devicetaintrules"], ["resource.k8s.io", "resourceclaims"],
          ["scheduling.k8s.io", "podgroups"],
          ["storagemigration.k8s.io", "storageversionmigrations"],
          ["storage.k8s.io", "volumeattachments"]
        ].freeze

        def clear_status_on_create(resource, object)
          return object unless object.is_a?(Hash)
          if !resource.custom? && Schema::KubernetesValidator.pdb_v1?(resource)
            return object.merge("status" => Schema::KubernetesValidator::PDB_ZERO_STATUS.dup)
          end
          return object unless object.key?("status")
          return resource.subresource("status") ? object.except("status") : object if resource.custom?
          return object.except("status") if resource_pool_status_request_resource?(resource)
          return object unless STATUS_CLEARED_ON_CREATE.include?([resource.group.to_s, resource.resource.to_s])

          result = deep_copy(object)
          result["status"] = {}
          result
        end

        def with_registry_allocations(route, &)
          return yield(nil) unless route.subresource.nil? && @service_allocator.instance_of?(ServiceAllocator) && @service_allocator.service?(route.resource)

          @service_allocator.transaction(&)
        end

        # Registry strategy PrepareForCreate hooks by kind. apiextensions clears
        # status, records the storage version, and defaults the conversion strategy.
        # kube-aggregator clears status and marks local APIServices available.
        def prepare_registry_create(resource, object, dry_run:, allocation:)
          object = clear_status_on_create(resource, object)
          object = drop_stateful_set_disabled_fields(resource, object, nil)
          if crd_resource?(resource) then prepare_crd_create(object)
          elsif @service_allocator && @service_allocator.service?(resource)
            options = allocation ? {allocation: allocation} : {}
            @service_allocator.prepare_create(object, dry_run: dry_run, **options)
          elsif replication_controller_resource?(resource) then default_replication_controller(object)
          elsif persistent_volume_resource?(resource) then prepare_persistent_volume_create(object)
          elsif persistent_volume_claim_resource?(resource) then prepare_persistent_volume_claim_create(object)
          elsif pod_resource?(resource) then prepare_pod_create(object)
          elsif namespace_resource?(resource) then prepare_namespace_create(object)
          elsif apiservice_resource?(resource) then prepare_apiservice_create(object)
          else object
          end
        end

        def prepare_crd_create(object)
          result = deep_copy(object)
          result["spec"] ||= {}
          result["spec"]["conversion"] ||= {"strategy" => "None"}
          storage = Array(result.dig("spec", "versions")).find { |version| version["storage"] == true }
          result["status"] = {"conditions" => nil, "acceptedNames" => {"plural" => "", "kind" => ""},
                              "storedVersions" => storage ? [storage["name"]] : []}
          result
        end

        # pkg/registry/core/persistentvolume/strategy.go PrepareForCreate:
        # a new PersistentVolume starts in phase Pending.
        def prepare_persistent_volume_create(object)
          result = deep_copy(object)
          result["status"] = {"phase" => "Pending", "lastPhaseTransitionTime" => @clock.call.utc.iso8601}
          result
        end

        # The claim strategy clears status; the PV controller then stamps
        # Pending on its first sync, which clients observe within
        # milliseconds upstream.  Stamping it here gives the same view
        # without a race against the controller's reconcile latency.
        def prepare_persistent_volume_claim_create(object)
          result = deep_copy(object)
          result["status"] = {"phase" => "Pending"}
          result
        end

        # pkg/registry/core/pod/strategy.go PrepareForCreate: a created Pod
        # always carries a status of Pending plus its QoS class.  Storing it
        # without one leaves `kubectl get pods` and every client that reads
        # status.phase with nothing to show.
        def prepare_pod_create(object)
          result = deep_copy(object)
          # v1 SetDefaults_Pod: a container limit without a request defaults
          # the request to the limit.
          %w[containers initContainers].each do |field|
            Array(result.dig("spec", field)).each do |container|
              next unless container.is_a?(Hash) && container["resources"].is_a?(Hash)

              limits = container["resources"]["limits"]
              next unless limits.is_a?(Hash) && !limits.empty?

              requests = (container["resources"]["requests"] ||= {})
              limits.each { |name, value| requests[name] = value unless requests.key?(name) }
            end
          end
          result["status"] = {"phase" => "Pending", "qosClass" => pod_qos_class(result)}
          # applySchedulingGatedCondition: a Pod created with scheduling
          # gates says why it is not being scheduled.
          unless Array(result.dig("spec", "schedulingGates")).empty?
            result["status"]["conditions"] = [{"type" => "PodScheduled", "status" => "False", "lastProbeTime" => nil,
                                               "lastTransitionTime" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                               "reason" => "SchedulingGated",
                                               "message" => "Scheduling is blocked due to non-empty scheduling gates"}]
          end
          result
        end

        # pkg/registry/core/namespace/strategy.go PrepareForCreate: a created
        # Namespace is Active and always carries the built-in "kubernetes"
        # finalizer.  Without it DELETE removes the Namespace immediately and
        # every object inside it is orphaned instead of being collected.
        def prepare_namespace_create(object)
          result = deep_copy(object)
          result["status"] = {"phase" => "Active"}
          # Upstream APPENDS the kubernetes finalizer rather than replacing the
          # list, so a Namespace created with a finalizer of its own keeps it
          # (pkg/registry/core/namespace/strategy.go:78-84).
          existing_finalizers = Array((result["spec"] || {})["finalizers"]).map(&:to_s)
          existing_finalizers << "kubernetes" unless existing_finalizers.include?("kubernetes")
          result["spec"] = (result["spec"] || {}).merge("finalizers" => existing_finalizers)
          # namespaceStrategy.Canonicalize repeats SetDefaults_Namespace here
          # because a generateName Namespace has no name to label until the
          # registry has assigned one.
          name = result.dig("metadata", "name").to_s
          unless name.empty?
            metadata = result["metadata"].is_a?(Hash) ? result["metadata"] : {}
            labels = metadata["labels"].is_a?(Hash) ? metadata["labels"] : {}
            result["metadata"] = metadata.merge(
              "labels" => labels.merge("kubernetes.io/metadata.name" => name)
            )
          end
          result
        end

        def prepare_apiservice_create(object)
          result = deep_copy(object)
          result["status"] = {}
          if result.dig("spec", "service").nil?
            result["status"]["conditions"] = [{"type" => "Available", "status" => "True", "lastTransitionTime" => @clock.call.utc.iso8601,
                                               "reason" => "Local", "message" => "Local APIServices are always available"}]
          end
          result
        end

        # v1 defaults that validation itself relies on (SetDefaults_* runs at
        # decode time upstream, before ValidateReplicationController requires a
        # selector).
        def apply_pre_validation_defaults(resource, object)
          return object unless replication_controller_resource?(resource) && object.is_a?(Hash)

          default_replication_controller(object)
        end

        # pkg/apis/core/v1/defaults.go SetDefaults_ReplicationController:
        # spec.replicas defaults to 1 and a missing selector is the
        # template's labels.
        def default_replication_controller(object)
          result = deep_copy(object)
          result["spec"] = {} unless result["spec"].is_a?(Hash)
          result["spec"]["replicas"] = 1 if result["spec"]["replicas"].nil?
          labels = result.dig("spec", "template", "metadata", "labels")
          if (result["spec"]["selector"].nil? || result["spec"]["selector"] == {}) && labels.is_a?(Hash) && !labels.empty?
            result["spec"]["selector"] = deep_copy(labels)
          end
          result
        end

        # qos.ComputePodQOS, pod-level resources included (ResourceHelpers).
        def pod_qos_class(pod)
          ResourceHelpers.qos_class(pod, pod_level_resources: feature_gate_enabled?("PodLevelResources"))
        end

        # rest.BeforeCreate -> FillObjectMetaSystemFields: uid and
        # creationTimestamp are the server's, whatever the client sent.  Keeping
        # a client-supplied uid let a controller's stale apply of a cached Node
        # re-create the Node the e2e suite had just deleted -- as the same
        # object, same uid, same creationTimestamp -- and every later spec then
        # waited seven minutes for the ghost node to become Ready.
        def prepare_created_metadata(object, resource: nil)
          result = deep_copy(object)
          result["metadata"] ||= {}
          result["metadata"]["uid"] = @uid_generator.call.to_s
          result["metadata"]["creationTimestamp"] = @clock.call.utc.iso8601(resource&.custom? ? 0 : 6)
          # Server-owned, 1 on create for the kinds whose strategy tracks it;
          # the rest never carry one (see GENERATION_TRACKED_KINDS).
          if tracks_generation?(result, resource)
            result["metadata"]["generation"] = 1
          else
            result["metadata"].delete("generation")
          end
          apply_daemonset_template_generation(resource, result)
        end

        def generated_name(prefix)
          suffix = if @name_generator
                     parameters = @name_generator.parameters
                     parameters.empty? ? @name_generator.call : @name_generator.call(prefix)
                   else
                     SecureRandom.alphanumeric(DEFAULT_GENERATE_NAME_SUFFIX_LENGTH).downcase
                   end
          suffix = suffix.to_s
          raise Status::Invalid.new("metadata.generateName must produce a non-empty suffix") if suffix.empty?

          "#{prefix}#{suffix}"
        rescue ArgumentError => error
          raise Status::Invalid.new("metadata.generateName could not be generated: #{error.message}")
        end
      end
    end
  end
end
