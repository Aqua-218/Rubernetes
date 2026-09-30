# frozen_string_literal: true

require "base64"
require "digest"
require "ipaddr"
require "json"
require "openssl"
require "socket"
require "time"

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"
require_relative "registry"

module Rubernetes
  module Controller
    # Concrete security and lifecycle controllers derived from the pinned
    # Kubernetes v1.36.2 controller sources.  These planners intentionally
    # expose only diff operations; informer snapshots are never modified in
    # place and every operation carries the resource UID when a delete is
    # requested.
    module SecurityLifecycleSupport
      POD = ResourceDescriptor.parse("Pod")
      SERVICE_ACCOUNT = ResourceDescriptor.parse("ServiceAccount")
      SECRET = ResourceDescriptor.parse("Secret")
      CONFIG_MAP = ResourceDescriptor.parse("ConfigMap")
      NODE = ResourceDescriptor.parse("Node")
      JOB = ResourceDescriptor.parse("Job")
      CSR = ResourceDescriptor.parse("CertificateSigningRequest")
      PDB = ResourceDescriptor.parse(
        {"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget"},
        resource: "poddisruptionbudgets", scope: :namespaced
      )
      PCR = ResourceDescriptor.parse(
        {"apiVersion" => "certificates.k8s.io/v1beta1", "kind" => "PodCertificateRequest"},
        resource: "podcertificaterequests", scope: :namespaced
      )

      BOOTSTRAP_SECRET_TYPE = "bootstrap.kubernetes.io/token"
      BOOTSTRAP_TOKEN_PREFIX = "bootstrap-token-"
      TOKEN_SECRET_NAMESPACE = "kube-system"
      BOOTSTRAP_TOKEN_ID_KEY = "token-id"
      BOOTSTRAP_TOKEN_SECRET_KEY = "token-secret"
      BOOTSTRAP_TOKEN_USAGE_SIGNING_KEY = "usage-bootstrap-signing"
      BOOTSTRAP_TOKEN_EXPIRATION_KEY = "expiration"
      JWS_SIGNATURE_PREFIX = "jws-kubeconfig-"
      KUBECONFIG_KEY = "kubeconfig"

      KUBELET_CLIENT_SIGNER = "kubernetes.io/kube-apiserver-client-kubelet"
      KUBELET_SERVING_SIGNER = "kubernetes.io/kubelet-serving"
      KUBE_APISERVER_CLIENT_SIGNER = "kubernetes.io/kube-apiserver-client"
      LEGACY_UNKNOWN_SIGNER = "kubernetes.io/legacy-unknown"
      SUPPORTED_SIGNERS = [KUBELET_CLIENT_SIGNER, KUBELET_SERVING_SIGNER,
                           KUBE_APISERVER_CLIENT_SIGNER, LEGACY_UNKNOWN_SIGNER].freeze

      DISRUPTION_TIMEOUT = 120
      CSR_APPROVED_EXPIRATION = 3_600
      CSR_DENIED_EXPIRATION = 3_600
      CSR_PENDING_EXPIRATION = 86_400
      PCR_EXPIRATION = 1_800
      MIN_CERTIFICATE_DURATION = 600
      DEFAULT_CERTIFICATE_TTL = 365 * 24 * 60 * 60

      module_function

      def empty_result(resource, controller:, descriptor: nil)
        ReconcileResult.new(operations: [], status: Support.deep_copy(Support.status(resource)),
                            controller: controller,
                            key: resource && lifecycle_object_key(resource, descriptor: descriptor))
      end

      def lifecycle_object_key(resource, descriptor: nil)
        if descriptor
          namespace = descriptor.cluster_scoped? ? nil : Support.namespace(resource)
          return [namespace, Support.name(resource)].compact.join("/")
        end

        [Support.namespace(resource), Support.name(resource)].compact.join("/")
      end

      def condition_list(resource_or_status)
        source = if resource_or_status.is_a?(Hash) && Support.value(resource_or_status, "status", nil).is_a?(Hash)
                   Support.status(resource_or_status)
                 else
                   resource_or_status
                 end
        Array(Support.value(source, "conditions", [])).grep(Hash)
      end

      def true_condition?(resource_or_status, type)
        condition_list(resource_or_status).any? do |condition|
          Support.value(condition, "type", "").to_s == type.to_s &&
            (Support.value(condition, "status", "").to_s == "True" || Support.value(condition, "status", false) == true)
        end
      end

      def condition(resource_or_status, type)
        condition_list(resource_or_status).find { |item| Support.value(item, "type", "").to_s == type.to_s }
      end

      def condition_time(condition_value)
        return nil unless condition_value.is_a?(Hash)

        Support.parse_time(
          Support.value(condition_value, "lastTransitionTime", nil) ||
          Support.value(condition_value, "lastUpdateTime", nil) ||
          Support.value(condition_value, "transitionTime", nil)
        )
      end

      def time_value(value, fallback = nil)
        parsed = Support.parse_time(value)
        return parsed if parsed
        return value.utc if value.is_a?(Time)

        fallback
      end

      def stale?(timestamp, now, seconds)
        timestamp && now.to_f - timestamp.to_f > seconds.to_f
      end

      def upsert_condition(conditions, type, status, reason, message = nil, observed_generation: nil)
        values = Array(conditions).map { |item| Support.deep_copy(item) }
        current = values.find { |item| Support.value(item, "type", "").to_s == type.to_s }
        candidate = current || {"type" => type.to_s}
        candidate["status"] = status.to_s
        candidate["reason"] = reason.to_s
        candidate["message"] = message.to_s unless message.nil?
        candidate["observedGeneration"] = observed_generation unless observed_generation.nil?
        values << candidate unless current
        values
      end

      def parse_certificate_request(value)
        return nil if value.nil? || value.to_s.empty?

        request = begin
          OpenSSL::X509::Request.new(binary_value(value))
        rescue OpenSSL::OpenSSLError, ArgumentError
          encoded = value.is_a?(String) ? Base64.strict_decode64(value) : nil
          encoded && OpenSSL::X509::Request.new(encoded)
        end
        return nil unless request
        return nil unless request.verify(request.public_key)

        request
      rescue OpenSSL::OpenSSLError, ArgumentError, TypeError
        nil
      end

      # Kubernetes JSON serializers may expose status/spec byte fields as a
      # string, an array of octets, or (in a hand-built test snapshot) an
      # array of strings.  Preserve the bytes before handing them to OpenSSL.
      def binary_value(value)
        return value if value.is_a?(String)

        if value.is_a?(Array)
          return value.pack("C*") if value.all? { |item| item.is_a?(Integer) && item.between?(0, 255) }

          return value.join
        end
        value.to_s
      end

      def base64url(value)
        Base64.strict_encode64(value.to_s).tr("+/", "-_").delete("=")
      end

      def parse_expiration(value)
        Support.parse_time(value)
      end

      def secret_data(secret, key)
        data = Support.value(secret, "data", {})
        return "" unless data.is_a?(Hash)

        Support.value(data, key, "").to_s
      end

      def owner_controller_reference(object)
        Support.owner_references(object).find do |reference|
          value = Support.value(reference, "controller", nil)
          value == true || value.to_s.casecmp("true").zero?
        end
      end

      def pod_cidrs(node)
        values = Array(Support.value(Support.spec(node), "podCIDRs", []))
        primary = Support.value(Support.spec(node), "podCIDR", nil)
        values = [primary] if values.empty? && !primary.to_s.empty?
        values.filter_map { |value| value.to_s unless value.to_s.empty? }.uniq
      end

      def intstr_value(value)
        return value unless value.is_a?(Hash)

        string_value = Support.value(value, "strVal", nil)
        return string_value unless string_value.nil?

        Support.value(value, "intVal", nil)
      end

      def valid_kubelet_client_request?(request, usages)
        return false unless request

        organizations = request.subject.to_a.filter_map do |name, value, _type|
          value.to_s if name.to_s == "O"
        end
        common_name = request.subject.to_a.filter_map do |name, value, _type|
          value.to_s if name.to_s == "CN"
        end.first.to_s
        return false unless organizations == ["system:nodes"]
        return false unless common_name.start_with?("system:node:")
        return false unless request_extension_values(request, :dns_names).empty? &&
                            request_extension_values(request, :email_addresses).empty? &&
                            request_extension_values(request, :ip_addresses).empty? &&
                            request_extension_values(request, :uris).empty?

        values = Array(usages).map(&:to_s).sort
        values == ["client auth", "digital signature"].sort ||
          values == ["client auth", "digital signature", "key encipherment"].sort
      end

      def valid_kubelet_serving_request?(request, usages)
        return false unless request

        organizations = request.subject.to_a.filter_map do |name, value, _type|
          value.to_s if name.to_s == "O"
        end
        common_name = request.subject.to_a.filter_map do |name, value, _type|
          value.to_s if name.to_s == "CN"
        end.first.to_s
        return false unless organizations == ["system:nodes"]
        return false unless common_name.start_with?("system:node:")
        return false if request_extension_values(request, :email_addresses).any? ||
                        request_extension_values(request, :uris).any?
        return false if request_extension_values(request, :dns_names).empty? &&
                        request_extension_values(request, :ip_addresses).empty?

        values = Array(usages).map(&:to_s).sort
        values == ["digital signature", "server auth"].sort ||
          values == ["digital signature", "key encipherment", "server auth"].sort
      end

      def valid_apiserver_client_usages?(usages)
        values = Array(usages).map(&:to_s).sort
        values == ["client auth"].sort ||
          values == ["client auth", "digital signature"].sort ||
          values == ["client auth", "digital signature", "key encipherment"].sort
      end

      def request_extension_values(request, method)
        direct = request.respond_to?(method) ? Array(request.public_send(method)) : []
        return direct unless direct.empty?

        extension_oid = {
          dns_names: ["2.5.29.17", "subjectAltName"], ip_addresses: ["2.5.29.17", "subjectAltName"],
          email_addresses: ["2.5.29.17", "subjectAltName"], uris: ["2.5.29.17", "subjectAltName"]
        }.fetch(method, nil)
        return [] unless extension_oid

        attribute = request.attributes.find { |candidate| %w[extReq extensionRequest 1.2.840.113549.1.9.14].include?(candidate.oid.to_s) }
        return [] unless attribute && attribute.value.respond_to?(:value)

        extension = Array(attribute.value.value).find do |candidate|
          candidate.respond_to?(:value) && Array(candidate.value).first.respond_to?(:oid) &&
            extension_oid.include?(Array(candidate.value).first.oid.to_s)
        end
        return [] unless extension

        octets = Array(extension.value).find { |candidate| candidate.respond_to?(:value) && candidate.tag.to_i == 4 }
        return [] unless octets

        raw = octets.value.to_s
        general_names = OpenSSL::ASN1.decode(raw)
        values = general_name_values(general_names, method)
        values.empty? ? textual_general_name_values(raw, method) : values
      rescue OpenSSL::ASN1::ASN1Error, ArgumentError, TypeError
        textual_general_name_values(raw, method)
      end

      def textual_general_name_values(raw, method)
        prefixes = {dns_names: "DNS:", ip_addresses: "IP:", email_addresses: "email:", uris: "URI:"}
        prefix = prefixes.fetch(method)
        raw.to_s.split(",").filter_map do |entry|
          value = entry.strip
          value.delete_prefix(prefix) unless value.empty? || !value.start_with?(prefix)
        end
      end

      def general_name_values(node, method, values = [])
        if node.respond_to?(:tag_class) && node.tag_class == :CONTEXT_SPECIFIC
          target_tag = {dns_names: 2, ip_addresses: 7, email_addresses: 1, uris: 6}.fetch(method)
          if node.tag.to_i == target_tag
            raw = node.value.to_s
            values << if (method == :ip_addresses && raw.bytesize == 4) || (method == :ip_addresses && raw.bytesize == 16)
                        IPAddr.ntop(raw)
                      else
                        raw
                      end
          end
        end
        Array(node.value).each { |child| general_name_values(child, method, values) } if node.respond_to?(:value) && node.value.is_a?(Array)
        values
      end

      def valid_signer_request?(request, signer_name, usages)
        case signer_name.to_s
        when KUBELET_CLIENT_SIGNER
          valid_kubelet_client_request?(request, usages)
        when KUBELET_SERVING_SIGNER
          valid_kubelet_serving_request?(request, usages)
        when KUBE_APISERVER_CLIENT_SIGNER
          valid_apiserver_client_usages?(usages)
        when LEGACY_UNKNOWN_SIGNER
          true
        else
          false
        end
      end

      def normalized_namespace(resource)
        Support.namespace(resource).to_s
      end
    end

    # Computes PodDisruptionBudget status from the current Pod and workload
    # snapshots.  It mirrors v1.36.2's safe-zero rule: no expected Pods means
    # zero allowed disruptions even when the arithmetic difference is positive.
    class DisruptionController < BaseController
      include SecondarySupport
      include SecurityLifecycleSupport

      REPLICA_SET = ResourceDescriptor.parse("ReplicaSet")
      DEPLOYMENT = ResourceDescriptor.parse("Deployment")
      STATEFUL_SET = ResourceDescriptor.parse("StatefulSet")
      REPLICATION_CONTROLLER = ResourceDescriptor.parse("ReplicationController")
      # DeletionTimeout / stalePodDisruptionTimeout.
      DELETION_TIMEOUT = 120
      STALE_POD_DISRUPTION_TIMEOUT = 120
      UNMANAGED_MESSAGE = "Pods selected by this PodDisruptionBudget (selector: %s) were found to be unmanaged. As a result, " \
                          "the status of the PDB cannot be calculated correctly, which may result in undefined behavior. " \
                          "To account for these pods please set \".spec.minAvailable\" field of the PDB to an integer value."

      class SyncError < StandardError; end

      def plan(object, store: nil, pods: nil, replica_sets: nil, deployments: nil, stateful_sets: nil,
               replication_controllers: nil, now: Time.now.utc, scale_client: nil, rest_mapper: nil, **_options)
        return plan_stale_pod(object, now: now) if Support.kind(object) == "Pod"
        return empty_result(object, controller: name, descriptor: PDB) unless Support.kind(object) == "PodDisruptionBudget"

        adapter = adapter_for(store)
        namespace = Support.namespace(object)
        finders = {
          pods: pods || list_for(adapter, POD, namespace: namespace),
          replica_sets: replica_sets || list_for(adapter, REPLICA_SET, namespace: namespace),
          deployments: deployments || list_for(adapter, DEPLOYMENT, namespace: namespace),
          stateful_sets: stateful_sets || list_for(adapter, STATEFUL_SET, namespace: namespace),
          replication_controllers: replication_controllers || list_for(adapter, REPLICATION_CONTROLLER, namespace: namespace),
          scale_client: scale_client || (adapter && ScaleClient.new(adapter: adapter)),
          rest_mapper: rest_mapper || RESTMapper.new
        }
        result = try_sync(object, finders, now)
        # The Pod sharing this PDB's namespace/name reaches the same key.
        pod = adapter && find_for(adapter, POD, Support.name(object), namespace: namespace)
        return result unless pod

        stale = plan_stale_pod(pod, now: now)
        ReconcileResult.new(operations: result.operations + stale.operations, status: result.status, events: result.events,
                            controller: name, key: result.key, requeue_after: [result.requeue_after, stale.requeue_after].compact.min)
      end

      private

      # trySync; any failure goes to failSafe.
      def try_sync(pdb, finders, now)
        events = []
        selector = Support.value(Support.spec(pdb), "selector", nil)
        # metav1.LabelSelectorAsSelector: a nil selector selects nothing.
        pods = if selector.nil?
                 []
               else
                 Array(finders[:pods]).select do |pod|
                   Support.namespace(pod).to_s == Support.namespace(pdb).to_s && Support.selector_matches?(selector, pod)
                 end
               end
        events << {"type" => "Normal", "reason" => "NoPods", "message" => "No matching pods found"} if pods.empty?

        begin
          expected_count, desired_healthy, unmanaged = expected_pod_count(pdb, pods, finders)
        rescue SyncError => error
          events << {"type" => "Warning", "reason" => "CalculateExpectedPodCountFailed",
                     "message" => "Failed to calculate the number of expected pods: #{error.message}"}
          return fail_safe(pdb, error.message, events, now)
        end
        unless unmanaged.empty?
          events << {"type" => "Warning", "reason" => "UnmanagedPods", "message" => format(UNMANAGED_MESSAGE, selector_text(selector))}
        end

        disrupted, recheck, not_deleted = disrupted_pod_map(pods, pdb, now)
        not_deleted.each do |pod|
          reference = {"apiVersion" => "v1", "kind" => "Pod", "name" => Support.name(pod), "namespace" => Support.namespace(pod),
                       "uid" => Support.uid(pod)}
          events << {"type" => "Warning", "reason" => "NotDeleted", "involvedObject" => reference,
                     "message" => "Pod was expected by PDB #{Support.namespace(pdb)}/#{Support.namespace(pdb)} to be deleted but it wasn't"}
        end
        current_healthy = healthy_pods(pods, disrupted, now)
        result = update_status(pdb, current_healthy, desired_healthy, expected_count, disrupted, now)
        requeue = recheck && [(recheck - now).to_f, 0.0].max
        ReconcileResult.new(operations: result[:operations], status: result[:status],
                            events: once_per_state(lifecycle_object_key(pdb), events), controller: name,
                            key: lifecycle_object_key(pdb), requeue_after: requeue)
      end

      # getExpectedPodCount: maxUnavailable first, then minAvailable.
      def expected_pod_count(pdb, pods, finders)
        spec = Support.spec(pdb)
        max_unavailable = Support.value(spec, "maxUnavailable", nil)
        min_available = Support.value(spec, "minAvailable", nil)
        if !max_unavailable.nil?
          expected, unmanaged = expected_scale(pods, finders)
          unavailable = scaled_value(max_unavailable, expected)
          [expected, [expected - unavailable, 0].max, unmanaged]
        elsif !min_available.nil?
          if intstr_value(min_available).is_a?(Integer)
            [pods.length, intstr_value(min_available), []]
          else
            expected, unmanaged = expected_scale(pods, finders)
            [expected, scaled_value(min_available, expected), unmanaged]
          end
        else
          [0, 0, []]
        end
      end

      # intstr.GetScaledValueFromIntOrPercent(value, total, roundUp=true).
      def scaled_value(value, total)
        value = intstr_value(value)
        return value if value.is_a?(Integer)

        text = value.to_s
        raise SyncError, "invalid value for IntOrString: invalid type: string is not a percentage" unless text.end_with?("%")

        percent = begin
          Integer(text.delete_suffix("%"), 10)
        rescue ArgumentError
          raise SyncError, "invalid value for IntOrString: invalid value #{text.dump}: strconv.Atoi: parsing " \
                           "#{text.delete_suffix("%").dump}: invalid syntax"
        end
        (percent.to_f * total / 100).ceil
      end

      # getExpectedScale: each distinct controller's scale, summed.
      def expected_scale(pods, finders)
        scales = {}
        unmanaged = []
        pods.each do |pod|
          reference = owner_controller_reference(pod)
          if reference.nil?
            unmanaged << Support.name(pod)
            next
          end
          next if scales.key?(Support.value(reference, "uid", "").to_s)

          found = nil
          %i[replication_controller deployment replica_set stateful_set scale_controller].each do |finder|
            found = send(:"find_#{finder}", reference, Support.namespace(pod), finders)
            break if found
          end
          raise SyncError, "found no controllers for pod #{Support.name(pod).dump}" unless found

          scales[found[0]] = found[1]
        end
        [scales.values.sum, unmanaged]
      end

      # verifyGroupKind.
      def group_kind?(reference, kind, groups)
        return false unless Support.value(reference, "kind", "").to_s == kind

        group, = ResourceDescriptor.split_api_version(Support.value(reference, "apiVersion", "").to_s)
        groups.include?(group.to_s)
      end

      def named(list, reference)
        Array(list).find do |candidate|
          Support.name(candidate) == Support.value(reference, "name", "").to_s
        end
      end

      def replicas_of(object) = Support.integer(Support.value(Support.spec(object), "replicas", 1), 1)

      def find_replica_set(reference, _namespace, finders)
        return nil unless group_kind?(reference, "ReplicaSet", %w[apps extensions])

        replica_set = named(finders[:replica_sets], reference)
        return nil unless replica_set && Support.uid(replica_set).to_s == Support.value(reference, "uid", "").to_s

        owner = owner_controller_reference(replica_set)
        return nil if owner && Support.value(owner, "kind", "").to_s == "Deployment"

        [Support.uid(replica_set).to_s, replicas_of(replica_set)]
      end

      def find_stateful_set(reference, _namespace, finders)
        return nil unless group_kind?(reference, "StatefulSet", %w[apps])

        set = named(finders[:stateful_sets], reference)
        return nil unless set && Support.uid(set).to_s == Support.value(reference, "uid", "").to_s

        [Support.uid(set).to_s, replicas_of(set)]
      end

      def find_deployment(reference, _namespace, finders)
        return nil unless group_kind?(reference, "ReplicaSet", %w[apps extensions])

        replica_set = named(finders[:replica_sets], reference)
        return nil unless replica_set && Support.uid(replica_set).to_s == Support.value(reference, "uid", "").to_s

        owner = owner_controller_reference(replica_set)
        return nil unless owner && group_kind?(owner, "Deployment", %w[apps extensions])

        deployment = named(finders[:deployments], owner)
        return nil unless deployment && Support.uid(deployment).to_s == Support.value(owner, "uid", "").to_s

        [Support.uid(deployment).to_s, replicas_of(deployment)]
      end

      def find_replication_controller(reference, _namespace, finders)
        return nil unless group_kind?(reference, "ReplicationController", [""])

        controller = named(finders[:replication_controllers], reference)
        return nil unless controller && Support.uid(controller).to_s == Support.value(reference, "uid", "").to_s

        [Support.uid(controller).to_s, replicas_of(controller)]
      end

      # getScaleController: any kind with a scale subresource.
      def find_scale_controller(reference, namespace, finders)
        descriptor = begin
          finders[:rest_mapper].resolve(reference)
        rescue UnknownGVKError, ArgumentError => error
          raise SyncError, error.message
        end
        client = finders[:scale_client]
        raise SyncError, "#{descriptor.identifier} does not implement the scale subresource" unless client

        snapshot = begin
          client.get_scale(descriptor: descriptor, name: Support.value(reference, "name", "").to_s, namespace: namespace)
        rescue StoreError
          return nil
        rescue ArgumentError
          raise SyncError, "#{descriptor.resource}.#{descriptor.group} does not implement the scale subresource".delete_suffix(".")
        end
        return nil unless Support.uid(snapshot.target).to_s == Support.value(reference, "uid", "").to_s

        [Support.uid(snapshot.target).to_s, snapshot.replicas]
      end

      # countHealthyPods.
      def healthy_pods(pods, disrupted, now)
        pods.count do |pod|
          next false unless Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?

          disruption = disrupted[Support.name(pod)]
          next false if disruption && time_value(disruption) && time_value(disruption) + DELETION_TIMEOUT > now

          Support.ready?(pod)
        end
      end

      # buildDisruptedPodMap: [still-expected disruptions, earliest recheck,
      # Pods that outlived their expected deletion].
      def disrupted_pod_map(pods, pdb, now)
        current = Support.value(Support.status(pdb), "disruptedPods", nil)
        return [{}, nil, []] unless current.is_a?(Hash)

        result = {}
        recheck = nil
        not_deleted = []
        pods.each do |pod|
          next unless Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?

          stamp = current[Support.name(pod)]
          next if stamp.nil?

          disrupted_at = time_value(stamp)
          next unless disrupted_at

          expected_deletion = disrupted_at + DELETION_TIMEOUT
          if expected_deletion < now
            not_deleted << pod
          else
            recheck = expected_deletion if recheck.nil? || expected_deletion < recheck
            result[Support.name(pod)] = stamp
          end
        end
        [result, recheck, not_deleted]
      end

      # failSafe: no disruptions while the status cannot be computed.
      def fail_safe(pdb, message, events, now)
        status = Support.deep_copy(Support.status(pdb))
        status["disruptionsAllowed"] = 0
        status["conditions"] = set_status_condition(Array(status["conditions"]), "DisruptionAllowed", "False", "SyncFailed", message,
                                                    status["observedGeneration"], now)
        ReconcileResult.new(operations: [operation_status(pdb, status, descriptor: PDB, reason: "PodDisruptionBudget fail-safe")].compact,
                            status: status, events: events, controller: name, key: lifecycle_object_key(pdb))
      end

      # updatePdbStatus: only when something changed.
      def update_status(pdb, current_healthy, desired_healthy, expected_count, disrupted, now)
        allowed = current_healthy - desired_healthy
        allowed = 0 if expected_count <= 0 || allowed <= 0
        generation = Support.integer(Support.value(Support.metadata(pdb), "generation", 0), 0)
        status = Support.status(pdb)
        stored_disrupted = Support.value(status, "disruptedPods", nil)
        stored_disrupted = {} unless stored_disrupted.is_a?(Hash)
        unchanged = Support.integer(Support.value(status, "currentHealthy", 0), 0) == current_healthy &&
                    Support.integer(Support.value(status, "desiredHealthy", 0), 0) == desired_healthy &&
                    Support.integer(Support.value(status, "expectedPods", 0), 0) == expected_count &&
                    Support.integer(Support.value(status, "disruptionsAllowed", 0), 0) == allowed &&
                    stored_disrupted == disrupted &&
                    Support.integer(Support.value(status, "observedGeneration", 0), 0) == generation &&
                    conditions_up_to_date?(status, allowed)
        return {operations: [], status: Support.deep_copy(status)} if unchanged

        updated = {"currentHealthy" => current_healthy, "desiredHealthy" => desired_healthy, "expectedPods" => expected_count,
                   "disruptionsAllowed" => allowed, "observedGeneration" => generation}
        updated["disruptedPods"] = disrupted unless disrupted.empty?
        conditions = Array(Support.value(status, "conditions", [])).map { |condition| Support.deep_copy(condition) }
        updated["conditions"] = if allowed.positive?
                                  set_status_condition(conditions, "DisruptionAllowed", "True", "SufficientPods", "", generation, now)
                                else
                                  set_status_condition(conditions, "DisruptionAllowed", "False", "InsufficientPods", "", generation, now)
                                end
        {operations: [operation_status(pdb, updated, descriptor: PDB, reason: "PodDisruptionBudget status reconciliation", force: true)],
         status: updated}
      end

      # pdbhelper.ConditionsAreUpToDate.
      def conditions_up_to_date?(status, allowed)
        condition = Array(Support.value(status, "conditions", [])).find { |entry| Support.value(entry, "type", "") == "DisruptionAllowed" }
        return false unless condition

        observed = Support.integer(Support.value(status, "observedGeneration", 0), 0)
        Support.integer(Support.value(condition, "observedGeneration", 0), 0) == observed &&
          Support.value(condition, "status", "").to_s == (allowed.positive? ? "True" : "False")
      end

      # meta.SetStatusCondition.
      def set_status_condition(conditions, type, status, reason, message, observed_generation, now)
        values = conditions.map { |condition| Support.deep_copy(condition) }
        current = values.find { |condition| Support.value(condition, "type", "").to_s == type }
        stamp = now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        unless current
          values << {"type" => type, "status" => status, "observedGeneration" => observed_generation.to_i, "lastTransitionTime" => stamp,
                     "reason" => reason, "message" => message.to_s}.reject { |key, value| key == "observedGeneration" && value.zero? }
          return values
        end

        current["lastTransitionTime"] = stamp if current["status"].to_s != status || current["lastTransitionTime"].to_s.empty?
        current["status"] = status
        current["reason"] = reason
        current["message"] = message.to_s
        if observed_generation.to_i.zero?
          current.delete("observedGeneration")
        else
          current["observedGeneration"] = observed_generation.to_i
        end
        values
      end

      # %v of *metav1.LabelSelector (its generated String()).
      def selector_text(selector)
        labels = (Support.value(selector, "matchLabels", {}) || {}).sort.map { |key, value| "#{key}: #{value}," }.join
        expressions = Array(Support.value(selector, "matchExpressions", [])).map do |expression|
          values = Array(Support.value(expression, "values", [])).join(" ")
          "LabelSelectorRequirement{Key:#{Support.value(expression, "key", "")},Operator:#{Support.value(expression, "operator", "")}," \
            "Values:[#{values}],},"
        end.join
        "&LabelSelector{MatchLabels:map[string]string{#{labels}},MatchExpressions:[]LabelSelectorRequirement{#{expressions}},}"
      end

      # syncStalePodDisruption: a DisruptionTarget=True condition nobody
      # acted on for two minutes is reset to False.
      def plan_stale_pod(pod, now:)
        empty = ReconcileResult.new(operations: [], controller: name, key: lifecycle_object_key(pod))
        return empty unless Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?
        return empty if %w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)

        conditions = Array(Support.value(Support.status(pod), "conditions", []))
        condition = conditions.find { |entry| Support.value(entry, "type", "") == "DisruptionTarget" }
        return empty unless condition && Support.value(condition, "status", "") == "True"
        return empty if Support.value(condition, "reason", "") == "TerminationByKubelet"

        since = time_value(Support.value(condition, "lastTransitionTime", nil)) || now
        wait = STALE_POD_DISRUPTION_TIMEOUT - (now - since)
        return ReconcileResult.new(operations: [], controller: name, key: lifecycle_object_key(pod), requeue_after: wait) if wait.positive?

        stamp = now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        updated = conditions.map do |entry|
          next Support.deep_copy(entry) unless Support.value(entry, "type", "") == "DisruptionTarget"

          # podutil.UpdatePodCondition with only type and status: reason and
          # message are cleared, the transition time moves.
          {"type" => "DisruptionTarget", "status" => "False", "lastProbeTime" => nil, "lastTransitionTime" => stamp}
        end
        status = Support.deep_copy(Support.status(pod)).merge("conditions" => updated)
        ReconcileResult.new(operations: [operation_status(pod, status, descriptor: POD, reason: "reset stale DisruptionTarget condition")].compact,
                            controller: name, key: lifecycle_object_key(pod))
      end
    end

    # pkg/controller/certificates/approver/sarapprove.go: a kubelet client
    # CSR is approved when its requester may create
    # certificatesigningrequests/selfnodeclient (renewing its own identity:
    # the requester is the certificate's CN) or .../nodeclient (bootstrap),
    # asked through a SubjectAccessReview for the requester.  A recognized
    # request whose review is not allowed is left alone.
    class CertificateSigningRequestApprovingController < BaseController
      include SecurityLifecycleSupport

      RECOGNIZERS = [
        ["selfnodeclient", "Auto approving self kubelet client certificate after SubjectAccessReview."],
        ["nodeclient", "Auto approving kubelet client certificate after SubjectAccessReview."]
      ].freeze

      # +authorization+: (csr, subresource) -> true/false; without one the
      # store's API client answers the SubjectAccessReview.  +authorized+
      # decides every recognizer at once (tests, snapshots).
      def plan(csr, store: nil, authorized: nil, authorization: nil, **_options)
        return empty_result(csr, controller: name, descriptor: CSR) unless Support.kind(csr) == "CertificateSigningRequest"

        status = Support.status(csr)
        return empty_result(csr, controller: name, descriptor: CSR) if certificate_present?(status)
        return empty_result(csr, controller: name, descriptor: CSR) if true_condition?(status,
                                                                                       "Approved") || true_condition?(status, "Denied")
        return empty_result(csr, controller: name, descriptor: CSR) unless recognized_kubelet_client_csr?(csr)

        message = nil
        RECOGNIZERS.each do |subresource, success|
          next if subresource == "selfnodeclient" && !self_node_client?(csr)
          next unless approval_allowed?(csr, subresource, store: store, authorized: authorized, authorization: authorization)

          message = success
          break
        end
        return empty_result(csr, controller: name, descriptor: CSR) if message.nil?

        candidate_status = Support.deep_copy(status)
        conditions = Array(Support.value(candidate_status, "conditions", [])).map { |item| Support.deep_copy(item) }
        conditions << {"type" => "Approved", "status" => "True", "reason" => "AutoApproved", "message" => message}
        candidate_status["conditions"] = conditions
        operation = operation_status(csr, candidate_status, descriptor: CSR, reason: "CSR approval")
        event = {"type" => "Normal", "reason" => "CertificateApproved",
                 "message" => "CertificateSigningRequest #{Support.name(csr)} approved"}
        ReconcileResult.new(operations: [operation].compact, status: candidate_status, events: [event],
                            controller: name, key: lifecycle_object_key(csr))
      end

      private

      def certificate_present?(status)
        value = Support.value(status, "certificate", nil)
        !value.nil? && !(value.respond_to?(:empty?) && value.empty?)
      end

      # isSelfNodeClientCert: the requester asks for its own name.
      def self_node_client?(csr)
        request = Support.value(Support.spec(csr), "request", nil)
        parsed = request && !request.to_s.empty? ? parse_certificate_request(request) : nil
        common_name = parsed&.subject&.to_a&.find { |entry| entry[0].to_s == "CN" }&.fetch(1, nil)
        !common_name.nil? && common_name.to_s == Support.value(Support.spec(csr), "username", "").to_s
      end

      def approval_allowed?(csr, subresource, store:, authorized:, authorization:)
        if authorization.respond_to?(:call)
          return (authorization.arity == 1 ? authorization.call(csr) : authorization.call(csr, subresource)) == true
        end
        return authorized == true unless authorized.nil?

        client = store.respond_to?(:client) ? store.client : nil
        return false unless client.respond_to?(:create)

        subject_access_review(client, csr, subresource)
      end

      # sarapprove.authorize: the review is for the CSR's requester.
      def subject_access_review(client, csr, subresource)
        specification = Support.spec(csr)
        review = {"apiVersion" => "authorization.k8s.io/v1", "kind" => "SubjectAccessReview",
                  "spec" => {"user" => Support.value(specification, "username", "").to_s,
                             "uid" => Support.value(specification, "uid", "").to_s,
                             "groups" => Array(Support.value(specification, "groups", [])),
                             "extra" => Support.value(specification, "extra", {}) || {},
                             "resourceAttributes" => {"group" => "certificates.k8s.io", "version" => "*",
                                                      "resource" => "certificatesigningrequests", "subresource" => subresource,
                                                      "verb" => "create"}}}
        response = client.create(review, api_version: "authorization.k8s.io/v1",
                                         path: "/apis/authorization.k8s.io/v1/subjectaccessreviews")
        response.to_h.dig("status", "allowed") == true
      rescue StandardError
        false
      end

      def recognized_kubelet_client_csr?(csr)
        specification = Support.spec(csr)
        return false unless Support.value(specification, "signerName", "").to_s == KUBELET_CLIENT_SIGNER

        usages = Array(Support.value(specification, "usages", [])).map(&:to_s)
        username = Support.value(specification, "username", "").to_s

        request = Support.value(specification, "request", nil)
        if request && !request.to_s.empty?
          parsed = parse_certificate_request(request)
          return false unless parsed && valid_kubelet_client_request?(parsed, usages)
        else
          # A decoded CSR is required by the upstream recognizer.  Keep the
          # snapshot-friendly fallback deliberately narrow when a caller has
          # not supplied request bytes.
          return false unless username.start_with?("system:node:") && usages.include?("client auth")
        end

        true
      end
    end

    # Signs approved CSRs for the four Kubernetes built-in signer names.  A
    # caller supplies signer material or a signer callable; without material
    # an approved request fails closed instead of receiving a fake certificate.
    class CertificateSigningRequestSigningController < BaseController
      include SecurityLifecycleSupport

      # kube-controller-manager --cluster-signing-{cert,key}-file (ca_certificate
      # / ca_key) and the per-signer --cluster-signing-<signer>-{cert,key}-file
      # (signer_cas: {signerName => {certificate:, key:}}).  Upstream starts a
      # signing controller only for a signer with CA material, so a signer
      # without any leaves its approved requests alone.
      def plan(csr, signer: nil, certificate: nil, ca_certificate: nil, ca_key: nil, signer_cas: nil,
               cert_ttl_seconds: DEFAULT_CERTIFICATE_TTL, now: Time.now.utc, **_options)
        return empty_result(csr, controller: name, descriptor: CSR) unless Support.kind(csr) == "CertificateSigningRequest"

        signer_name = Support.value(Support.spec(csr), "signerName", "").to_s
        ca_certificate, ca_key = signer_material(signer_cas, signer_name, ca_certificate, ca_key)
        if signer.nil? && certificate.nil? && (ca_certificate.nil? || ca_key.nil?)
          return empty_result(csr, controller: name, descriptor: CSR)
        end

        status = Support.status(csr)
        specification = Support.spec(csr)
        return empty_result(csr, controller: name, descriptor: CSR) if certificate_present?(status)
        return empty_result(csr, controller: name, descriptor: CSR) unless true_condition?(status, "Approved")
        return empty_result(csr, controller: name, descriptor: CSR) if true_condition?(status,
                                                                                       "Denied") || true_condition?(status, "Failed")
        return empty_result(csr, controller: name, descriptor: CSR) unless SUPPORTED_SIGNERS.include?(Support.value(specification,
                                                                                                                    "signerName", "").to_s)

        request = Support.value(specification, "request", nil)
        nil
        if request && !request.to_s.empty?
          parsed_request = parse_certificate_request(request)
          return failed_result(csr, status, "SignerValidationFailure", "unable to parse certificate signing request") unless parsed_request

          unless valid_signer_request?(parsed_request, Support.value(specification, "signerName", ""),
                                       Support.value(specification, "usages", []))
            return failed_result(csr, status, "SignerValidationFailure", "certificate request is not valid for signer")
          end
        end

        duration = duration_for(Support.value(specification, "expirationSeconds", nil), cert_ttl_seconds)
        issued_certificate = issue_certificate(csr, signer: signer, certificate: certificate,
                                                    ca_certificate: ca_certificate, ca_key: ca_key,
                                                    duration: duration, now: now,
                                                    usages: Array(Support.value(specification, "usages", [])))
        if issued_certificate.nil? || issued_certificate.to_s.empty?
          raise ArgumentError,
                "an approved CSR requires signer, certificate, or CA material"
        end

        candidate_status = Support.deep_copy(status)
        candidate_status["certificate"] = issued_certificate
        operation = operation_status(csr, candidate_status, descriptor: CSR, reason: "CSR certificate issued")
        event = {"type" => "Normal", "reason" => "CertificateIssued",
                 "message" => "CertificateSigningRequest #{Support.name(csr)} signed"}
        ReconcileResult.new(operations: [operation].compact, status: candidate_status, events: [event],
                            controller: name, key: lifecycle_object_key(csr))
      end

      def duration_for(expiration_seconds, cert_ttl_seconds = DEFAULT_CERTIFICATE_TTL)
        ttl = Integer(cert_ttl_seconds)
        raise ArgumentError, "certificate TTL must be positive" unless ttl.positive?
        return ttl if expiration_seconds.nil?

        requested = Integer(expiration_seconds)
        [[requested, MIN_CERTIFICATE_DURATION].max, ttl].min
      rescue ArgumentError => error
        raise ArgumentError, "invalid certificate duration: #{error.message}"
      end

      private

      def certificate_present?(status)
        value = Support.value(status, "certificate", nil)
        !value.nil? && !(value.respond_to?(:empty?) && value.empty?)
      end

      def failed_result(csr, status, reason, message)
        candidate_status = Support.deep_copy(status)
        conditions = Array(Support.value(candidate_status, "conditions", [])).map { |item| Support.deep_copy(item) }
        conditions << {"type" => "Failed", "status" => "True", "reason" => reason, "message" => message}
        candidate_status["conditions"] = conditions
        operation = operation_status(csr, candidate_status, descriptor: CSR, reason: "CSR signing failure")
        event = {"type" => "Warning", "reason" => "CertificateFailed", "message" => message}
        ReconcileResult.new(operations: [operation].compact, status: candidate_status, events: [event],
                            controller: name, key: lifecycle_object_key(csr))
      end

      def signer_material(signer_cas, signer_name, ca_certificate, ca_key)
        if signer_cas.is_a?(Hash)
          entry = signer_cas[signer_name] || signer_cas[signer_name.to_sym]
          return [entry[:certificate] || entry["certificate"], entry[:key] || entry["key"]] if entry.is_a?(Hash)
        end
        [ca_certificate, ca_key]
      end

      # authority.PermissiveSigningPolicy: 5 minutes of backdating (none
      # for certificates shorter than 8 hours), never past the CA's own
      # expiry.
      BACKDATE = 5 * 60
      SHORT = 8 * 3600
      KEY_USAGES = {
        "signing" => "digitalSignature", "digital signature" => "digitalSignature",
        "content commitment" => "nonRepudiation", "key encipherment" => "keyEncipherment",
        "key agreement" => "keyAgreement", "data encipherment" => "dataEncipherment",
        "cert sign" => "keyCertSign", "crl sign" => "cRLSign",
        "encipher only" => "encipherOnly", "decipher only" => "decipherOnly"
      }.freeze
      # In x509.ExtKeyUsage order, which upstream sorts by.
      EXT_KEY_USAGES = [
        ["any", "anyExtendedKeyUsage"], ["server auth", "serverAuth"], ["client auth", "clientAuth"],
        ["code signing", "codeSigning"], ["email protection", "emailProtection"], ["s/mime", "emailProtection"],
        ["ipsec end system", "ipsecEndSystem"], ["ipsec tunnel", "ipsecTunnel"], ["ipsec user", "ipsecUser"],
        ["timestamping", "timeStamping"], ["ocsp signing", "OCSPSigning"],
        ["microsoft sgc", "msSGC"], ["netscape sgc", "nsSGC"]
      ].freeze

      def issue_certificate(csr, signer:, certificate:, ca_certificate:, ca_key:, duration:, now:, usages: [])
        if signer.respond_to?(:call)
          return signer.call if signer.arity.zero?
          return signer.call(csr) if signer.arity == 1
          return signer.call(csr, duration) if signer.arity == 2

          return signer.call(csr, duration, now)
        end
        return certificate unless certificate.nil?
        return nil unless ca_certificate && ca_key

        request = parse_certificate_request(Support.value(Support.spec(csr), "request", nil))
        raise ArgumentError, "CA signing requires a valid CSR request" unless request

        ca = ca_certificate.is_a?(OpenSSL::X509::Certificate) ? ca_certificate : OpenSSL::X509::Certificate.new(ca_certificate.to_s)
        key = ca_key.is_a?(OpenSSL::PKey::PKey) ? ca_key : OpenSSL::PKey.read(ca_key.to_s)
        key_usages, ext_key_usages = x509_usages(usages)
        not_before = now - BACKDATE
        not_after = duration < SHORT ? now + duration : now + duration - BACKDATE
        not_after = ca.not_after unless not_after < ca.not_after
        raise ArgumentError, "the signer has expired: NotAfter=#{ca.not_after.utc.iso8601}" unless not_before < ca.not_after
        unless now < ca.not_after
          raise ArgumentError,
                "refusing to sign a certificate that expired in the past: NotAfter=#{ca.not_after.utc.iso8601}"
        end

        issued = OpenSSL::X509::Certificate.new
        issued.serial = OpenSSL::BN.rand(128) # rand.Int below 2^128
        issued.version = 2
        issued.subject = request.subject
        issued.issuer = ca.subject
        issued.public_key = request.public_key
        issued.not_before = not_before
        issued.not_after = not_after
        extensions = OpenSSL::X509::ExtensionFactory.new
        extensions.subject_certificate = issued
        extensions.issuer_certificate = ca
        issued.add_extension(extensions.create_extension("keyUsage", key_usages.join(","), true)) unless key_usages.empty?
        issued.add_extension(extensions.create_extension("extendedKeyUsage", ext_key_usages.join(","), false)) unless ext_key_usages.empty?
        issued.add_extension(extensions.create_extension("basicConstraints", "CA:FALSE", true))
        if ca.extensions.any? { |extension| extension.oid == "subjectKeyIdentifier" }
          issued.add_extension(extensions.create_extension("authorityKeyIdentifier", "keyid:always", false))
        end
        san = requested_subject_alt_names(request)
        issued.add_extension(OpenSSL::X509::Extension.new("subjectAltName", san.value, san.critical?)) if san
        issued.sign(key, OpenSSL::Digest.new("SHA256"))
        # status.certificate is []byte: base64 on the JSON wire.
        Base64.strict_encode64(issued.to_pem)
      rescue OpenSSL::OpenSSLError, ArgumentError => error
        raise ArgumentError, "failed to sign CSR #{Support.name(csr)}: #{error.message}"
      end

      # keyUsagesFromStrings: unknown usages refuse the whole request.
      def x509_usages(usages)
        key_usages = []
        ext_key_usages = []
        unrecognized = []
        usages.map(&:to_s).each do |usage|
          if (value = KEY_USAGES[usage])
            key_usages << value unless key_usages.include?(value)
          elsif (index = EXT_KEY_USAGES.index { |name, _| name == usage })
            ext_key_usages << [index, EXT_KEY_USAGES[index][1]]
          else
            unrecognized << usage
          end
        end
        raise ArgumentError, "unrecognized usage values: [#{unrecognized.map(&:inspect).join(" ")}]" unless unrecognized.empty?

        [key_usages, ext_key_usages.uniq { |_, value| value }.sort_by(&:first).map(&:last)]
      end

      # The CSR's DNS/IP/email/URI names, copied as the request carries them.
      def requested_subject_alt_names(request)
        attribute = request.attributes.find { |item| %w[extReq msExtReq].include?(item.oid) }
        return nil unless attribute

        sequence = attribute.value.value.first
        Array(sequence&.value).each do |der|
          extension = OpenSSL::X509::Extension.new(der)
          return extension if extension.oid == "subjectAltName"
        end
        nil
      rescue OpenSSL::OpenSSLError, TypeError, NoMethodError
        nil
      end
    end

    class CertificateSigningRequestCleanerController < BaseController
      include SecurityLifecycleSupport

      def plan(csr, now: Time.now.utc, approved_expiration: CSR_APPROVED_EXPIRATION,
               denied_expiration: CSR_DENIED_EXPIRATION, pending_expiration: CSR_PENDING_EXPIRATION, **_options)
        return empty_result(csr, controller: name, descriptor: CSR) unless Support.kind(csr) == "CertificateSigningRequest"
        return empty_result(csr, controller: name, descriptor: CSR) unless Support.value(Support.metadata(csr), "deletionTimestamp",
                                                                                         nil).nil?

        status = Support.status(csr)
        creation_time = Support.creation_time(csr)
        approved = condition(status, "Approved")
        denied = condition(status, "Denied")
        failed = condition(status, "Failed")
        issued = certificate_present?(status)
        expired = issued && certificate_expired?(Support.value(status, "certificate", nil), now)
        delete = (issued && true_condition?(status, "Approved") &&
                  (stale?(condition_time(approved), now, approved_expiration) || expired)) ||
                 stale?(condition_time(denied), now, denied_expiration) ||
                 stale?(condition_time(failed), now, denied_expiration) ||
                 (condition_list(status).empty? && stale?(creation_time, now, pending_expiration)) ||
                 (!issued && true_condition?(status, "Approved") &&
                  stale?(condition_time(approved), now, pending_expiration))
        return empty_result(csr, controller: name, descriptor: CSR) unless delete

        operation = operation_delete(csr, descriptor: CSR, reason: "certificate signing request cleanup")
        event = {"type" => "Normal", "reason" => "CertificateDeleted",
                 "message" => "CertificateSigningRequest #{Support.name(csr)} deleted"}
        ReconcileResult.new(operations: [operation], status: Support.deep_copy(status), events: [event],
                            controller: name, key: lifecycle_object_key(csr))
      end

      private

      def certificate_present?(status)
        value = Support.value(status, "certificate", nil)
        !value.nil? && !(value.respond_to?(:empty?) && value.empty?)
      end

      def certificate_expired?(value, now)
        return false if value.nil? || value.to_s.empty?

        certificate = begin
          OpenSSL::X509::Certificate.new(binary_value(value))
        rescue OpenSSL::OpenSSLError, ArgumentError
          encoded = value.is_a?(String) ? Base64.strict_decode64(value) : nil
          encoded && OpenSSL::X509::Certificate.new(encoded)
        end
        return false unless certificate

        certificate.not_after < now
      rescue OpenSSL::OpenSSLError, ArgumentError
        false
      end
    end

    # Deletes PodCertificateRequests after the v1.36.2 thirty-minute window,
    # guarded by the request UID so a recreated object cannot be removed.
    class PodCertificateRequestCleanerController < BaseController
      include SecurityLifecycleSupport

      def plan(request, now: Time.now.utc, threshold_seconds: PCR_EXPIRATION, threshold: nil, **_options)
        return empty_result(request, controller: name, descriptor: PCR) unless Support.kind(request) == "PodCertificateRequest"
        return empty_result(request, controller: name, descriptor: PCR) unless Support.value(Support.metadata(request),
                                                                                             "deletionTimestamp", nil).nil?

        threshold_seconds = threshold unless threshold.nil?
        threshold_seconds = Float(threshold_seconds)
        raise ArgumentError, "PodCertificateRequest cleanup threshold must be non-negative" if threshold_seconds.negative?

        created = Support.creation_time(request)
        return empty_result(request, controller: name, descriptor: PCR) unless created && now.to_f >= created.to_f + threshold_seconds

        operation = operation_delete(request, descriptor: PCR, reason: "PodCertificateRequest cleanup")
        event = {"type" => "Normal", "reason" => "PodCertificateRequestDeleted",
                 "message" => "PodCertificateRequest #{Support.name(request)} deleted"}
        ReconcileResult.new(operations: [operation], status: Support.deep_copy(Support.status(request)), events: [event],
                            controller: name, key: lifecycle_object_key(request))
      end
    end

    # Deletes finished Jobs only after their TTL has elapsed.  The optional
    # fresh snapshot models the upstream controller's final GET before delete.
    class TTLController < BaseController
      include SecondarySupport
      include SecurityLifecycleSupport

      def plan(job, store: nil, fresh: nil, now: Time.now.utc, **_options)
        candidate = fresh
        if candidate.nil? && store
          adapter = adapter_for(store)
          candidate = adapter.find(JOB, name: Support.name(job), namespace: Support.namespace(job)) if adapter
          return empty_result(job, controller: name, descriptor: JOB) unless candidate
        end
        candidate ||= job
        return empty_result(job, controller: name, descriptor: JOB) unless Support.kind(candidate) == "Job"
        return empty_result(candidate, controller: name, descriptor: JOB) unless Support.value(Support.metadata(candidate),
                                                                                               "deletionTimestamp", nil).nil?

        ttl_value = Support.value(Support.spec(candidate), "ttlSecondsAfterFinished", nil)
        return empty_result(candidate, controller: name, descriptor: JOB) if ttl_value.nil?

        ttl = Integer(ttl_value)
        raise ArgumentError, "Job TTL must be non-negative" if ttl.negative?

        finished_at = job_finish_time(candidate)
        return empty_result(candidate, controller: name, descriptor: JOB) unless finished_at
        return empty_result(candidate, controller: name, descriptor: JOB) if now.to_f < finished_at.to_f + ttl

        expired_at = Time.at(finished_at.to_f + ttl).utc
        # metrics.JobDeletionDurationSeconds: from expiry to the delete.
        operation = operation_delete(candidate, descriptor: JOB, reason: "TTLExpired").observed do |succeeded, _|
          ControllerMetrics.observe("ttl_after_finished_controller_job_deletion_duration_seconds", Time.now.utc - expired_at) if succeeded
        end
        event = {"type" => "Normal", "reason" => "TTLExpired",
                 "message" => "Job #{Support.name(candidate)} TTL expired"}
        ReconcileResult.new(operations: [operation], status: Support.deep_copy(Support.status(candidate)), events: [event],
                            controller: name, key: lifecycle_object_key(candidate))
      rescue ArgumentError => error
        raise ArgumentError, "invalid Job TTL: #{error.message}"
      end

      private

      def job_finish_time(job)
        status = Support.status(job)
        completion = Support.parse_time(Support.value(status, "completionTime", nil))
        return completion if completion

        Array(Support.value(status, "conditions", [])).filter_map do |condition_value|
          next unless %w[Complete Failed].include?(Support.value(condition_value, "type", "").to_s)
          next unless Support.value(condition_value, "status", "").to_s == "True" || Support.value(condition_value, "status", false) == true

          condition_time(condition_value)
        end.min
      end
    end

    # Recomputes detached HS256 kubeconfig signatures for valid bootstrap
    # tokens, removing stale signatures from the target ConfigMap.
    class BootstrapSignerController < BaseController
      include SecondarySupport
      include SecurityLifecycleSupport

      def plan(config_map, store: nil, secrets: nil, now: Time.now.utc,
               config_map_name: "cluster-info", config_map_namespace: "kube-public",
               token_secret_namespace: TOKEN_SECRET_NAMESPACE, secret_data_encoded: false, **_options)
        return empty_result(config_map, controller: name, descriptor: CONFIG_MAP) unless Support.kind(config_map) == "ConfigMap"
        return empty_result(config_map, controller: name, descriptor: CONFIG_MAP) unless Support.name(config_map) == config_map_name.to_s &&
                                                                                         Support.namespace(config_map).to_s == config_map_namespace.to_s

        adapter = adapter_for(store)
        secrets ||= list_for(adapter, SECRET, namespace: token_secret_namespace)
        data = Support.value(config_map, "data", {})
        return empty_result(config_map, controller: name, descriptor: CONFIG_MAP) unless data.is_a?(Hash)

        content = Support.value(data, KUBECONFIG_KEY, nil)
        return empty_result(config_map, controller: name, descriptor: CONFIG_MAP) if content.nil?

        tokens = valid_tokens(secrets, now: now, namespace: token_secret_namespace,
                                       secret_data_encoded: secret_data_encoded)
        desired_data = Support.deep_copy(data)
        desired_data.keys.grep(/\A#{Regexp.escape(JWS_SIGNATURE_PREFIX)}/o).each { |key| desired_data.delete(key) }
        tokens.keys.sort.each do |token_id|
          desired_data[JWS_SIGNATURE_PREFIX + token_id] = detached_signature(content.to_s, token_id, tokens.fetch(token_id))
        end
        return empty_result(config_map, controller: name, descriptor: CONFIG_MAP) if desired_data == data

        candidate = Support.deep_copy(config_map)
        candidate["data"] = desired_data
        operation = operation_update(config_map, candidate, descriptor: CONFIG_MAP, reason: "bootstrap kubeconfig signatures")
        event = {"type" => "Normal", "reason" => "BootstrapSignerUpdated",
                 "message" => "bootstrap token signatures reconciled"}
        ReconcileResult.new(operations: [operation].compact, status: {"data" => desired_data}, events: [event],
                            controller: name, key: lifecycle_object_key(config_map))
      end

      private

      def valid_tokens(secrets, now:, namespace:, secret_data_encoded:)
        selected = {}
        Array(secrets).sort_by { |secret| [Support.name(secret), Support.uid(secret).to_s] }.each do |secret|
          next unless Support.kind(secret) == "Secret" && Support.namespace(secret).to_s == namespace.to_s
          next unless Support.value(secret, "type", "").to_s == BOOTSTRAP_SECRET_TYPE

          match = Support.name(secret).match(/\A#{Regexp.escape(BOOTSTRAP_TOKEN_PREFIX)}([a-z0-9]{6})\z/o)
          next unless match

          token_id = decode_secret_data(secret, BOOTSTRAP_TOKEN_ID_KEY, secret_data_encoded)
          token_secret = decode_secret_data(secret, BOOTSTRAP_TOKEN_SECRET_KEY, secret_data_encoded)
          next unless token_id == match[1] && !token_secret.to_s.empty?
          next unless decode_secret_data(secret, BOOTSTRAP_TOKEN_USAGE_SIGNING_KEY, secret_data_encoded).to_s == "true"

          expiration = decode_secret_data(secret, BOOTSTRAP_TOKEN_EXPIRATION_KEY, secret_data_encoded)
          expires_at = parse_expiration(expiration)
          next if !expiration.to_s.empty? && expires_at.nil?
          next if expires_at && now.to_f >= expires_at.to_f

          selected[token_id] ||= token_secret
        end
        selected
      end

      def decode_secret_data(secret, key, encoded)
        value = secret_data(secret, key)
        return value unless encoded

        Base64.strict_decode64(value.to_s)
      rescue ArgumentError
        nil
      end

      def detached_signature(content, token_id, token_secret)
        header = JSON.generate("alg" => "HS256", "kid" => token_id)
        signing_input = "#{base64url(header)}.#{base64url(content)}"
        digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new("SHA256"), token_secret, signing_input)
        "#{base64url(header)}..#{base64url(digest)}"
      end
    end

    # Removes expired bootstrap token Secrets, retaining UID preconditions for
    # the same race protection used by the upstream token cleaner.
    class TokenCleanerController < BaseController
      include SecurityLifecycleSupport

      def plan(secret, now: Time.now.utc, token_secret_namespace: TOKEN_SECRET_NAMESPACE, secret_data_encoded: false, **_options)
        return empty_result(secret, controller: name, descriptor: SECRET) unless Support.kind(secret) == "Secret"
        unless Support.namespace(secret).to_s == token_secret_namespace.to_s
          return empty_result(secret, controller: name,
                                      descriptor: SECRET)
        end
        return empty_result(secret, controller: name, descriptor: SECRET) unless Support.value(secret, "type",
                                                                                               "").to_s == BOOTSTRAP_SECRET_TYPE
        return empty_result(secret, controller: name, descriptor: SECRET) unless Support.value(Support.metadata(secret),
                                                                                               "deletionTimestamp", nil).nil?

        expiration = secret_data(secret, BOOTSTRAP_TOKEN_EXPIRATION_KEY)
        if secret_data_encoded
          begin
            expiration = Base64.strict_decode64(expiration.to_s)
          rescue ArgumentError
            expiration = nil
          end
        end
        expires_at = parse_expiration(expiration)
        return empty_result(secret, controller: name, descriptor: SECRET) if expiration.to_s.empty?
        return empty_result(secret, controller: name, descriptor: SECRET) if expires_at && now.to_f < expires_at.to_f

        operation = operation_delete(secret, descriptor: SECRET, reason: "expired bootstrap token")
        event = {"type" => "Normal", "reason" => "TokenCleaned",
                 "message" => "expired bootstrap token Secret #{Support.name(secret)} deleted"}
        ReconcileResult.new(operations: [operation], status: Support.deep_copy(Support.status(secret)), events: [event],
                            controller: name, key: lifecycle_object_key(secret))
      end
    end

    # Allocates deterministic, non-overlapping Pod CIDRs from the configured
    # cluster CIDRs.  Existing assignments are immutable and allocator
    # exhaustion is reported as a warning event without mutating the Node.
    class NodeIPAMController < BaseController
      include SecondarySupport
      include SecurityLifecycleSupport

      def plan(node, store: nil, nodes: nil, cluster_cidrs: nil, cluster_cidr: nil,
               node_cidr_mask_sizes: nil, node_cidr_mask_size: nil, allocator_type: :range,
               cidr_allocator: nil, cloud_allocator: nil, **_options)
        return empty_result(node, controller: name, descriptor: NODE) unless Support.kind(node) == "Node"
        return empty_result(node, controller: name, descriptor: NODE) unless Support.value(Support.metadata(node), "deletionTimestamp",
                                                                                           nil).nil?
        return empty_result(node, controller: name, descriptor: NODE) unless pod_cidrs(node).empty?

        adapter = adapter_for(store)
        nodes ||= list_for(adapter, NODE, namespace: :all)
        nodes = (Array(nodes) + [node]).uniq { |candidate| [Support.name(candidate), Support.uid(candidate).to_s] }
        assigned = if cidr_allocator.respond_to?(:call)
                     cidr_allocator.call(node, nodes)
                   elsif allocator_type.to_sym == :cloud && cloud_allocator.respond_to?(:call)
                     cloud_allocator.call(node, nodes)
                   else
                     allocations = []
                     allocate_from_cluster(node, nodes, cluster_cidrs: cluster_cidrs || cluster_cidr,
                                                        node_cidr_mask_sizes: node_cidr_mask_sizes || node_cidr_mask_size, allocations: allocations)
                   end
        assigned = Array(assigned).filter_map { |value| value.to_s unless value.to_s.empty? }
        if assigned.empty?
          event = {"type" => "Warning", "reason" => "CIDRAssignmentFailed",
                   "message" => "no Pod CIDR is available for Node #{Support.name(node)}"}
          return ReconcileResult.new(operations: [], status: Support.deep_copy(Support.status(node)), events: [event],
                                     controller: name, key: lifecycle_object_key(node))
        end

        candidate = Support.deep_copy(node)
        candidate["spec"] ||= {}
        candidate["spec"]["podCIDRs"] = assigned
        candidate["spec"]["podCIDR"] = assigned.first
        operation = operation_update(node, candidate, descriptor: NODE, reason: "Node Pod CIDR allocation")
        operation = operation.observed { |succeeded, _| record_cidr_allocations(allocations, succeeded) } if operation && allocations&.any?
        event = {"type" => "Normal", "reason" => "CIDRAssigned",
                 "message" => "assigned #{assigned.join(", ")} to Node #{Support.name(node)}"}
        status = Support.deep_copy(Support.status(node))
        status["podCIDR"] = assigned.first
        ReconcileResult.new(operations: [operation].compact, status: status, events: [event],
                            controller: name, key: lifecycle_object_key(node))
      end

      private

      # cidrset (pkg/controller/nodeipam/ipam/cidrset): per cluster CIDR the
      # number of node CIDRs it holds, and for each allocation that reached
      # the Node the candidates found occupied before the free one, the
      # allocation and the share now in use.  A Node update that failed was
      # an allocation released again, as upstream's range allocator does.
      def record_cidr_allocations(allocations, succeeded)
        allocations.each do |allocation|
          labels = {"clusterCIDR" => allocation[:cluster_cidr]}
          ControllerMetrics.increment("node_ipam_controller_cidrset_cidrs_allocations_total", labels)
          ControllerMetrics.observe("node_ipam_controller_cidrset_allocation_tries_per_request", allocation[:tries], labels)
          if succeeded
            ControllerMetrics.set("node_ipam_controller_cidrset_usage_cidrs", allocation[:used].to_f / allocation[:max], labels)
          else
            ControllerMetrics.increment("node_ipam_controller_cidrset_cidrs_releases_total", labels)
            ControllerMetrics.set("node_ipam_controller_cidrset_usage_cidrs", (allocation[:used] - 1).to_f / allocation[:max], labels)
          end
        end
      end

      def allocate_from_cluster(node, nodes, cluster_cidrs:, node_cidr_mask_sizes:, allocations: nil)
        configured = Array(cluster_cidrs).flat_map { |value| value.is_a?(Array) ? value : [value] }.filter_map(&:to_s).reject(&:empty?)
        return [] if configured.empty?

        masks = node_cidr_mask_sizes
        existing = Array(nodes).flat_map { |candidate| pod_cidrs(candidate) }.map { |value| canonical_cidr(value) }
        occupied = existing.dup
        unassigned = Array(nodes).reject do |candidate|
          !pod_cidrs(candidate).empty? || !Support.value(Support.metadata(candidate), "deletionTimestamp", nil).nil?
        end
        unassigned = unassigned.sort_by { |candidate| [Support.name(candidate), Support.uid(candidate).to_s] }
        position = unassigned.index do |candidate|
          Support.name(candidate) == Support.name(node) && Support.uid(candidate).to_s == Support.uid(node).to_s
        end
        return [] unless position

        configured.filter_map.with_index do |cidr, family_index|
          candidates = subnet_candidates(cidr, mask_for(masks, cidr, family_index))
          label = cidr_label(cidr)
          ControllerMetrics.set("node_ipam_controller_cirdset_max_cidrs", candidates.length, {"clusterCIDR" => label}) if label
          taken = candidates.map { |candidate| occupied.any? { |value| cidr_overlap?(candidate, value) } }
          available = candidates.each_index.reject { |index| taken[index] }
          index = available.fetch(position, nil)
          selected = index && candidates[index]
          if selected && allocations && label
            allocations << {cluster_cidr: label, tries: taken.first(index).count(true), used: taken.count(true) + 1, max: candidates.length}
          end
          occupied << selected if selected
          selected
        end
      end

      # net.IPNet#String of the cluster CIDR (the cidrset label).
      def cidr_label(cidr)
        address_text, prefix_text = cidr.to_s.split("/", 2)
        "#{IPAddr.new(address_text).mask(Integer(prefix_text))}/#{Integer(prefix_text)}"
      rescue ArgumentError, TypeError
        nil
      end

      def mask_for(masks, cidr, index)
        if masks.is_a?(Array)
          value = masks[index]
          raise ArgumentError, "node CIDR mask size for family #{index} is required" if value.nil?

          return Integer(value)
        end
        unless masks.is_a?(Hash)
          raise ArgumentError, "node CIDR mask size is required" if masks.nil?

          return Integer(masks)
        end

        family = IPAddr.new(cidr.split("/", 2).first).ipv4? ? "ipv4" : "ipv6"
        value = masks[family] || masks[family.to_sym] || masks[index] || masks[index.to_s]
        raise ArgumentError, "node CIDR mask size for #{family} is required" if value.nil?

        Integer(value)
      rescue ArgumentError, TypeError => error
        raise ArgumentError, "invalid cluster CIDR #{cidr.inspect}: #{error.message}"
      end

      def canonical_cidr(value)
        address_text, prefix_text = value.to_s.split("/", 2)
        raise ArgumentError, "assigned Pod CIDR must include a prefix" if prefix_text.to_s.empty?

        address = IPAddr.new(address_text)
        prefix = Integer(prefix_text)
        bits = address.ipv4? ? 32 : 128
        raise ArgumentError, "assigned Pod CIDR prefix is outside address family" unless prefix.between?(0, bits)

        "#{address.mask(prefix)}/#{prefix}"
      rescue ArgumentError => error
        raise ArgumentError, "invalid assigned Pod CIDR #{value.inspect}: #{error.message}"
      end

      def cidr_overlap?(left, right)
        left_start, left_end, left_bits = cidr_interval(left)
        right_start, right_end, right_bits = cidr_interval(right)
        return false unless left_bits == right_bits

        left_start <= right_end && right_start <= left_end
      end

      def cidr_interval(value)
        address_text, prefix_text = value.to_s.split("/", 2)
        address = IPAddr.new(address_text)
        bits = address.ipv4? ? 32 : 128
        prefix = Integer(prefix_text)
        raise ArgumentError, "CIDR prefix is outside address family" unless prefix.between?(0, bits)

        start = address.to_i & (((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1))
        [start, start + (1 << (bits - prefix)) - 1, bits]
      rescue ArgumentError => error
        raise ArgumentError, "invalid CIDR #{value.inspect}: #{error.message}"
      end

      def subnet_candidates(cidr, node_prefix)
        address_text, cluster_prefix_text = cidr.to_s.split("/", 2)
        raise ArgumentError, "cluster CIDR must include a prefix" if cluster_prefix_text.to_s.empty?

        address = IPAddr.new(address_text)
        bits = address.ipv4? ? 32 : 128
        cluster_prefix = Integer(cluster_prefix_text)
        raise ArgumentError, "cluster CIDR prefix is outside address family" unless cluster_prefix.between?(0, bits)
        raise ArgumentError, "node CIDR mask must cover cluster CIDR" unless node_prefix.between?(cluster_prefix, bits)

        cluster_network = address.to_i & (((1 << bits) - 1) ^ ((1 << (bits - cluster_prefix)) - 1))
        subnet_size = 1 << (bits - node_prefix)
        subnet_count = 1 << (node_prefix - cluster_prefix)
        raise ArgumentError, "cluster CIDR produces too many node subnets" if subnet_count > 1_048_576

        Array.new(subnet_count) do |index|
          family = bits == 32 ? Socket::AF_INET : Socket::AF_INET6
          network = IPAddr.new(cluster_network + (index * subnet_size), family)
          "#{network.mask(node_prefix)}/#{node_prefix}"
        end
      rescue ArgumentError => error
        raise ArgumentError, "invalid CIDR allocation input #{cidr.inspect}: #{error.message}"
      end
    end

    # Immutable metadata and definition factory for this controller batch.
    # Registration is deliberately opt-in so the controller manager owner can
    # integrate the batch with the existing registry in one atomic step.
    module SecurityLifecycleRegistration
      CONTROLLER_NAMES = %w[
        disruption-controller
        certificatesigningrequest-signing-controller
        certificatesigningrequest-approving-controller
        certificatesigningrequest-cleaner-controller
        podcertificaterequest-cleaner-controller
        ttl-controller
        bootstrap-signer-controller
        token-cleaner-controller
        node-ipam-controller
      ].freeze

      WATCHES = {
        "disruption-controller" => [
          ["PodDisruptionBudget", :all], ["Pod", :label], ["ReplicaSet", :all],
          ["Deployment", :all], ["StatefulSet", :all], ["ReplicationController", :all],
          # stalePodDisruptionQueue: the Pod itself, for its DisruptionTarget condition.
          ["Pod", :all, :self]
        ],
        "certificatesigningrequest-signing-controller" => [["CertificateSigningRequest", :all]],
        "certificatesigningrequest-approving-controller" => [["CertificateSigningRequest", :all]],
        "certificatesigningrequest-cleaner-controller" => [["CertificateSigningRequest", :all]],
        "podcertificaterequest-cleaner-controller" => [["PodCertificateRequest", :all]],
        "ttl-controller" => [["Job", :all]],
        "bootstrap-signer-controller" => [["ConfigMap", :all], ["Secret", :label]],
        "token-cleaner-controller" => [["Secret", :label]],
        "node-ipam-controller" => [["Node", :all]]
      }.freeze

      IMPLEMENTATIONS = {
        "disruption-controller" => DisruptionController,
        "certificatesigningrequest-signing-controller" => CertificateSigningRequestSigningController,
        "certificatesigningrequest-approving-controller" => CertificateSigningRequestApprovingController,
        "certificatesigningrequest-cleaner-controller" => CertificateSigningRequestCleanerController,
        "podcertificaterequest-cleaner-controller" => PodCertificateRequestCleanerController,
        "ttl-controller" => TTLController,
        "bootstrap-signer-controller" => BootstrapSignerController,
        "token-cleaner-controller" => TokenCleanerController,
        "node-ipam-controller" => NodeIPAMController
      }.freeze

      METADATA = CONTROLLER_NAMES.each_with_object({}) do |controller_name, result|
        entry = BuiltinControllerCorpus.fetch(controller_name)
        result[controller_name] = entry.to_h
      end.freeze

      module_function

      def entries
        CONTROLLER_NAMES.map do |name|
          BuiltinControllerCorpus.fetch(name) || raise(ValidationError, "missing pinned corpus entry #{name.inspect}")
        end
      end

      def names
        CONTROLLER_NAMES
      end

      def implementation(name)
        IMPLEMENTATIONS.fetch(name.to_s)
      end

      def metadata(name = nil)
        return entries.map(&:to_h).freeze if name.nil?

        entries.find { |entry| entry.name == name.to_s }&.to_h ||
          raise(ValidationError, "missing pinned corpus entry #{name.inspect}")
      end

      def definitions(registry: nil)
        entries.map do |entry|
          implementation = IMPLEMENTATIONS.fetch(entry.name)
          definition_descriptor = usable_descriptor(descriptor_for(entry.kind), registry)
          watch_specs = WATCHES.fetch(entry.name).each_with_index.map do |(kind, relationship, route), index|
            descriptor = usable_descriptor(descriptor_for(kind), registry)
            WatchSpec.new(resource: descriptor, via: relationship,
                          index_name: "security/#{entry.name}/#{index}",
                          predicate: watch_predicate(relationship, entry.name, kind),
                          queue_key: ->(object) { [Support.namespace(object), Support.name(object)].compact.join("/") },
                          scope: descriptor.scope, route: route || :fan_out)
          end
          definition = nil
          mutex = Mutex.new
          instance = nil
          reconcile = lambda do |resource, context = nil|
            context = {} unless context.is_a?(Hash)
            controller = context[:controller] || context["controller"]
            controller ||= mutex.synchronize { instance ||= implementation.new(definition: definition) }
            options = context[:options] || context["options"] || {}
            options = options.dup if options.is_a?(Hash)
            options[:store] = context[:store] || context["store"] if options.is_a?(Hash) && !options.key?(:store) && !options.key?("store")
            controller.plan(resource, **(options.is_a?(Hash) ? options : {}))
          end
          definition = ControllerDefinition.new(
            name: entry.name, kind: definition_descriptor, owns: [], watches: watch_specs,
            reconcile_block: reconcile, feature_gates: entry.feature_gates,
            startup_conditions: entry.startup_conditions, sync_targets: entry.sync_targets,
            status_fields: entry.status_fields, events: entry.events, implementation: implementation
          )
          definition
        end.freeze
      end

      alias build_definitions definitions

      def definition(name, registry: nil)
        definitions(registry: registry).find { |candidate| candidate.name == name.to_s } ||
          raise(ValidationError, "missing security lifecycle controller #{name.inspect}")
      end

      def register!(registry)
        definitions(registry: registry).each { |definition| registry.register(definition) }
        registry
      end

      alias register register!

      def descriptor_for(kind)
        case kind.to_s
        when "PodDisruptionBudget"
          SecurityLifecycleSupport::PDB
        when "PodCertificateRequest"
          SecurityLifecycleSupport::PCR
        else
          ResourceDescriptor.parse(kind)
        end
      end

      def usable_descriptor(descriptor, registry)
        return descriptor unless registry

        registry.validate_descriptor!(descriptor)
        descriptor
      rescue UnknownGVKError
        # The current registry may predate policy/v1 or certificates/v1beta1
        # descriptors.  The pinned corpus still validates kind ownership, so a
        # kind-only descriptor keeps registration atomic until schema integration
        # adds those GVKs.
        ResourceDescriptor.parse(descriptor.kind)
      end

      def watch_predicate(relationship, controller_name = nil, kind = nil)
        if controller_name.to_s == "bootstrap-signer-controller"
          return lambda do |object|
            if kind.to_s == "ConfigMap"
              Support.kind(object) == "ConfigMap" &&
              Support.name(object) == "cluster-info" &&
              Support.namespace(object).to_s == "kube-public"
            elsif kind.to_s == "Secret"
              bootstrap_token_secret?(object)
            else
              false
            end
          end
        end

        return ->(object) { bootstrap_token_secret?(object) } if controller_name.to_s == "token-cleaner-controller"

        if controller_name.to_s == "ttl-controller"
          return lambda do |object|
            Support.kind(object) == "Job" &&
            Support.value(Support.metadata(object), "deletionTimestamp", nil).nil? &&
            !Support.value(Support.spec(object), "ttlSecondsAfterFinished", nil).nil? &&
            ttl_job_finished?(object)
          end
        end

        case relationship.to_sym
        when :label
          ->(object) { !Support.labels(object).empty? }
        else
          ->(_object) { true }
        end
      end

      def bootstrap_token_secret?(object)
        Support.kind(object) == "Secret" &&
          Support.namespace(object).to_s == SecurityLifecycleSupport::TOKEN_SECRET_NAMESPACE.to_s &&
          Support.value(object, "type", "").to_s == SecurityLifecycleSupport::BOOTSTRAP_SECRET_TYPE
      end

      def ttl_job_finished?(object)
        status = Support.status(object)
        return true if Support.parse_time(Support.value(status, "completionTime", nil))

        Array(Support.value(status, "conditions", [])).any? do |condition|
          %w[Complete Failed].include?(Support.value(condition, "type", "").to_s) &&
            (Support.value(condition, "status", "").to_s == "True" || Support.value(condition, "status", false) == true)
        end
      end
    end

    SecurityLifecycleControllerFactory = SecurityLifecycleRegistration
    PinnedSecurityLifecycleControllerFactory = SecurityLifecycleRegistration
    TTLControllerAlias = TTLController
    TtlController = TTLController
  end
end
