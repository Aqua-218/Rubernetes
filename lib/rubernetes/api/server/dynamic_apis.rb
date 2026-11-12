# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The dynamic API surface: CustomResourceDefinitions (serving, status
      # conditions, the cleanup finalizer) and aggregated APIServices (availability,
      # proxying), kept in sync from the commit paths of their objects.
      module DynamicAPIs
        # Each apiserver installs a CustomResourceDefinition from its own
        # watch, so a custom resource request that reaches a peer right after
        # the CRD was created elsewhere answered 404 until that watch caught up
        # (the e2e client balances across apiservers through the kubernetes
        # Service).  A path under /apis/<group>/ that no served resource
        # matches re-reads the definitions of that group -- after this
        # request's read barrier, so it sees every committed CRD -- and
        # installs any this server has not yet before routing again.
        def catch_up_dynamic_route(request, route)
          return route if @crd_manager.nil? || route.kind == :resource

          segments = route.path.to_s.split("/").reject(&:empty?)
          return route unless segments.first == "apis" && segments.length >= 2

          group = segments[1]
          return route unless %i[unknown api_group resource_list].include?(route.kind)
          return route if route.kind != :unknown && enabled_resources.any? do |resource|
            resource.group == group && (route.version.nil? || resource.version == route.version.to_s)
          end

          crd_resource = @registry.find_gvr(group: CRD_GVR[0], version: CRD_GVR[1], resource: CRD_GVR[2])
          return route if crd_resource.nil?

          served = @crd_manager.served_names
          pending = @store.list(resource: crd_resource, namespace: :all, selectors: nil).items.select do |crd|
            crd.dig("spec",
                    "group") == group && !served.include?(crd.dig("metadata", "name")) && crd.dig("metadata", "deletionTimestamp").nil?
          end
          return route if pending.empty?

          pending.each { |crd| @crd_manager.sync(crd) }
          @router.route(request)
        rescue MemoryStore::Error, Status::Error
          route
        end

        # ---- dynamic API surface: CRDs and aggregation --------------------------

        CRD_GVR = ["apiextensions.k8s.io", "v1", "customresourcedefinitions"].freeze

        APISERVICE_GVR = ["apiregistration.k8s.io", "v1", "apiservices"].freeze

        def crd_resource?(resource)
          [resource.group, resource.version, resource.resource] == CRD_GVR
        end

        def apiservice_resource?(resource)
          [resource.group, resource.version, resource.resource] == APISERVICE_GVR
        end

        # Called after a CRD / APIService object is committed (create, update,
        # patch, delete).  CRD status conditions are written back through the
        # store so the served state is observable; a deleted CRD first removes
        # its custom resources (the customresourcecleanup finalizer), then is
        # withdrawn from the registry and OpenAPI.
        def after_commit(resource, object, deleted: false)
          if @crd_manager && crd_resource?(resource)
            sync_crd(object, deleted: deleted)
          elsif @aggregator && apiservice_resource?(resource)
            if deleted
              @aggregator.remove(metadata_value(object, "name"))
            else
              @aggregator.sync(object)
              schedule_apiservice_availability(metadata_value(object, "name"))
            end
          end
        end

        # kube-aggregator's available controller: the APIService status
        # Available condition is recomputed when the object is written and
        # then periodically, off the request path.
        APISERVICE_AVAILABILITY_INTERVAL = 5

        def schedule_apiservice_availability(name)
          start_apiservice_availability_loop
          thread = Thread.new { refresh_apiservice_availability(name) }
          thread.name = "apiservice-availability-#{name}"
          thread
        end

        def refresh_apiservice_availability(name)
          return if @aggregator.nil?

          resource = @registry.find_gvr(group: APISERVICE_GVR[0], version: APISERVICE_GVR[1], resource: APISERVICE_GVR[2])
          return if resource.nil?

          current = @store.get(resource: resource, namespace: :cluster, name: name)
          backend = @aggregator.backend(name)
          condition = if backend.nil?
                        {"type" => "Available", "status" => "True", "reason" => "Local", "message" => "Local APIServices are always available",
                         "lastTransitionTime" => @clock.call.utc.iso8601}
                      else
                        @aggregator.availability_condition(backend, service: lookup_service(backend),
                                                                    endpoint_slices: lookup_endpoint_slices(backend))
                      end
          @aggregator.mark_available(name, condition["status"] == "True") if backend
          existing = Array(current.dig("status", "conditions"))
          previous = existing.find { |entry| entry["type"] == "Available" }
          observe_apiservice_availability(name, previous, condition)
          return if previous && previous.values_at("status", "reason", "message") == condition.values_at("status", "reason", "message")

          if previous && previous["status"] == condition["status"] && previous["lastTransitionTime"]
            condition["lastTransitionTime"] =
              previous["lastTransitionTime"]
          end
          status = (current["status"] || {}).merge("conditions" => existing.reject { |entry| entry["type"] == "Available" } + [condition])
          @store.update(resource: resource, namespace: :cluster, name: name, object: current.merge("status" => status),
                        resource_version: metadata_value(current, "resourceVersion"))
        rescue MemoryStore::NotFound, MemoryStore::Conflict, Status::Error
          nil
        end

        # kube-aggregator available controller metrics: the gauge on every
        # sync, the counter when an APIService turns unavailable.
        def observe_apiservice_availability(name, previous, condition)
          return unless @metrics

          unless @aggregator_metrics_registered
            @metrics.register("aggregator_unavailable_apiservice", type: :gauge,
                                                                   help: "Gauge of APIServices which are marked as unavailable broken down by APIService name.")
            @metrics.register("aggregator_unavailable_apiservice_total", type: :counter,
                                                                         help: "Counter of APIServices which are marked as unavailable broken down by " \
                                                                               "APIService name and reason.")
            @aggregator_metrics_registered = true
          end
          available = condition["status"] == "True"
          @metrics.set("aggregator_unavailable_apiservice", available ? 0 : 1, {"name" => name.to_s})
          was_available = previous && previous["status"] == "True"
          # setUnavailableCounter: only a change from available (an absent
          # condition is Unknown, not available).
          return if available || !was_available

          @metrics.increment("aggregator_unavailable_apiservice_total",
                             {"name" => name.to_s, "reason" => (condition["reason"] || "UnknownReason").to_s})
        end

        def start_apiservice_availability_loop
          return if @apiservice_availability_thread&.alive?

          @apiservice_availability_thread = Thread.new do
            loop do
              sleep APISERVICE_AVAILABILITY_INTERVAL
              # A round that fails (the store has no quorum, say) is tried
              # again at the next interval.
              best_effort { @aggregator.backends.each { |backend| refresh_apiservice_availability(backend.name) } }
            end
          end
          @apiservice_availability_thread.name = "apiservice-availability"
        end

        def lookup_service(backend)
          services = @registry.find_gvr(group: "", version: "v1", resource: "services")
          return nil if services.nil?

          @store.get(resource: services, namespace: backend.service_namespace.to_s, name: backend.service_name.to_s)
        rescue MemoryStore::NotFound, Status::Error
          nil
        end

        def lookup_endpoint_slices(backend)
          slices = @registry.find_gvr(group: "discovery.k8s.io", version: "v1", resource: "endpointslices")
          return [] if slices.nil?

          selectors = Selectors.new(label_selector: "kubernetes.io/service-name=#{backend.service_name}")
          @store.list(resource: slices, namespace: backend.service_namespace.to_s, selectors: selectors).items
        rescue MemoryStore::NotFound, Status::Error
          []
        end

        def sync_crd(object, deleted:)
          if deleted
            @crd_manager.withdraw(metadata_value(object, "name"))
            return
          end
          conditions = @crd_manager.sync(object)
          return if conditions.empty?

          status = (object["status"] || {}).merge(
            "conditions" => conditions,
            "acceptedNames" => accepted_crd_names(object, conditions),
            "storedVersions" => stored_crd_versions(object, conditions)
          )
          return if status == object["status"]

          crd_resource = @registry.find_gvr(group: CRD_GVR[0], version: CRD_GVR[1], resource: CRD_GVR[2])
          begin
            @store.update(resource: crd_resource, namespace: :cluster, name: metadata_value(object, "name"),
                          object: object.merge("status" => status), resource_version: metadata_value(object, "resourceVersion"))
          rescue MemoryStore::Conflict, MemoryStore::NotFound
            nil
          end
        end

        # Deleting a CRD: finalize by deleting every custom resource, then let
        # the delete proceed once the finalizer is gone.
        def mark_crd_terminating(route, existing, namespace)
          object = deep_copy(existing)
          object["metadata"]["deletionTimestamp"] ||= @clock.call.utc.iso8601(6)
          finalizers = Array(object["metadata"]["finalizers"])
          object["metadata"]["finalizers"] = finalizers | [CRD::Manager::CLEANUP_FINALIZER]
          object["status"] = set_crd_condition(object["status"] || {}, "Terminating", "True", "InstanceDeletionPending",
                                               "CustomResourceDefinition marked for deletion; CustomResource deletion will begin soon")
          @store.update(resource: route.resource, namespace: namespace, name: route.name, object: object,
                        resource_version: metadata_value(existing, "resourceVersion"))
        end

        def set_crd_condition(status, type, value, reason, message)
          conditions = Array(status["conditions"]).reject { |condition| condition["type"] == type }
          previous = Array(status["conditions"]).find { |condition| condition["type"] == type }
          transition = previous && previous["status"] == value ? previous["lastTransitionTime"] : @clock.call.utc.iso8601
          status.merge("conditions" => conditions + [{"type" => type, "status" => value, "lastTransitionTime" => transition,
                                                      "reason" => reason, "message" => message}])
        end

        # apiextensions crd_finalizer controller: delete every custom resource,
        # then drop the cleanup finalizer so the CRD object disappears.
        def schedule_crd_finalizer(name)
          # Nobody joins this thread: a finalization that fails leaves the
          # CRD terminating, to be finalized by the next delete.
          thread = Thread.new { best_effort { finalize_crd(name) } }
          thread.name = "crd-finalizer-#{name}"
          thread
        end

        def finalize_crd(name)
          crd_resource = @registry.find_gvr(group: CRD_GVR[0], version: CRD_GVR[1], resource: CRD_GVR[2])
          existing = @store.get(resource: crd_resource, namespace: :cluster, name: name)
          return unless metadata_value(existing, "deletionTimestamp")

          in_progress = deep_copy(existing)
          in_progress["status"] = set_crd_condition(in_progress["status"] || {}, "Terminating", "True", "InstanceDeletionInProgress",
                                                    "CustomResource deletion is in progress")
          existing = @store.update(resource: crd_resource, namespace: :cluster, name: name, object: in_progress,
                                   resource_version: metadata_value(existing, "resourceVersion"))
          finalize_crd_resources(existing)
          remaining = Array(metadata_value(existing, "finalizers")) - [CRD::Manager::CLEANUP_FINALIZER]
          if remaining.empty?
            @store.delete(resource: crd_resource, namespace: :cluster, name: name,
                          resource_version: metadata_value(existing, "resourceVersion"))
            after_commit(crd_resource, existing, deleted: true)
          else
            released = deep_copy(existing)
            released["metadata"]["finalizers"] = remaining
            released["status"] = set_crd_condition(released["status"] || {}, "Terminating", "True", "InstanceDeletionCompleted",
                                                   "removed all instances")
            @store.update(resource: crd_resource, namespace: :cluster, name: name, object: released,
                          resource_version: metadata_value(existing, "resourceVersion"))
          end
        rescue MemoryStore::NotFound, MemoryStore::Conflict
          nil
        end

        def finalize_crd_resources(existing)
          spec = existing["spec"] || {}
          storage_version = Array(spec["versions"]).find { |version| version["storage"] == true }&.fetch("name")
          return if storage_version.nil?

          custom = @registry.find_gvr(group: spec["group"], version: storage_version, resource: spec.dig("names", "plural"))
          return if custom.nil?

          @crd_manager.cleanup_resources(existing) do |object|
            namespace = metadata_value(object, "namespace")
            @store.delete(resource: custom, namespace: namespace.nil? || namespace.to_s.empty? ? :cluster : namespace, name: metadata_value(object, "name"),
                          resource_version: metadata_value(object, "resourceVersion"))
          rescue MemoryStore::NotFound, MemoryStore::Conflict
            nil
          end
        end

        # Requests for a group/version that no registered resource serves are
        # proxied when an APIService claims them; discovery for such groups is
        # merged from the backend.
        def aggregated_response(request, route)
          return nil unless @aggregator

          group = route.group.to_s
          version = route.version.to_s
          case route.kind
          when :resource, :resource_list
            return nil if route.kind == :resource && route.resource
            return nil if group.empty?
            return nil unless @aggregator.claims?(group, version)

            if route.kind == :resource_list
              document = @aggregator.resource_list(group, version)
              return document ? json_response(document) : @aggregator.unavailable_response
            end
            @aggregator.proxy(request, group: group, version: version)
          when :unknown
            segments = route.path.to_s.split("/").reject(&:empty?)
            return nil unless segments.first == "apis" && segments.length >= 3 && @aggregator.claims?(segments[1], segments[2])

            @aggregator.proxy(request, group: segments[1], version: segments[2])
          end
        end

        private

        # status.acceptedNames: the spec's names once NamesAccepted is True.
        def accepted_crd_names(object, conditions)
          accepted = conditions.find { |condition| condition["type"] == "NamesAccepted" }
          if accepted && accepted["status"] == "True"
            object.dig("spec", "names") || {}
          else
            object.dig("status", "acceptedNames") || {}
          end
        end

        # status.storedVersions: an established CRD adds its storage version.
        def stored_crd_versions(object, conditions)
          established = conditions.any? { |condition| condition["type"] == "Established" && condition["status"] == "True" }
          return Array(object.dig("status", "storedVersions")) unless established

          storage = Array(object.dig("spec", "versions")).select { |version| version["storage"] }.map { |version| version["name"] }
          (object.dig("status", "storedVersions") || []) | storage
        end
      end
    end
  end
end
