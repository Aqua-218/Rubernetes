# frozen_string_literal: true

# Node-local admission.  Scheduling is owned by the scheduler, but a node
# agent must repeat the safety checks immediately before creating a sandbox:
# resource availability, node identity, OS/architecture and runtime support.

require_relative "registration"
require_relative "resource_manager"
require_relative "../resource_helpers"
require_relative "../node_declared_features"

module Rubernetes
  module Node
    class Admission
      class Rejected < StandardError
        attr_reader :decision

        def initialize(decision)
          @decision = decision
          super("#{decision.reason}: #{decision.message}")
        end
      end

      Decision = Data.define(:accepted, :reason, :message, :requested, :available, :pod, :details) do
        def allowed?
          accepted
        end

        alias accepted? allowed?
        alias ok? allowed?
        # Helpers.success_result? asks #success?; without it every Decision --
        # rejections included -- read as success, so the lifecycle never
        # refused a Pod the node's own admission turned down.
        alias success? allowed?

        alias admitted? allowed?

        def rejected?
          !accepted
        end

        def to_h
          {
            "accepted" => accepted,
            "reason" => reason,
            "message" => message,
            "requested" => requested,
            "available" => available,
            "pod" => pod,
            "details" => details
          }
        end
      end

      DEFAULT_OS = if RUBY_PLATFORM.include?("linux")
                     "linux"
                   elsif RUBY_PLATFORM.include?("darwin")
                     "darwin"
                   else
                     RUBY_PLATFORM.split("-").first
                   end.freeze
      DEFAULT_ARCH = if RUBY_PLATFORM.include?("x86_64") || RUBY_PLATFORM.include?("amd64")
                       "amd64"
                     elsif RUBY_PLATFORM.include?("aarch64") || RUBY_PLATFORM.include?("arm64")
                       "arm64"
                     else
                       RUBY_PLATFORM.split("-").first
                     end.freeze

      # pkg/kubelet/sysctl/safe_sysctls.go: namespaced and isolated sysctls
      # every Pod may set.  The kernel-gated entries are all namespaced on
      # the kernels this node supports (>= 5.x).
      SAFE_SYSCTLS = %w[
        kernel.shm_rmid_forced net.ipv4.ip_local_port_range net.ipv4.tcp_syncookies net.ipv4.ping_group_range
        net.ipv4.ip_unprivileged_port_start net.ipv4.ip_local_reserved_ports net.ipv4.tcp_keepalive_time
        net.ipv4.tcp_fin_timeout net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_keepalive_probes net.ipv4.tcp_rmem
        net.ipv4.tcp_wmem
      ].freeze
      SYSCTL_NAME = /\A[a-z0-9_.\-\/]+\z/i.freeze

      def initialize(node_name:, resource_manager: nil, capacity: {}, allocatable: nil, node_labels: {},
                     operating_system: DEFAULT_OS, architecture: DEFAULT_ARCH, runtime_classes: {},
                     runtime_handlers: nil, node_schedulable: true, features: {}, allowed_unsafe_sysctls: [],
                     declared_features: nil, declared_features_framework: NodeDeclaredFeatures::DEFAULT_FRAMEWORK,
                     version: NodeDeclaredFeatures::KUBERNETES_VERSION, node_labels_provider: nil)
        # The kubelet admits against the live Node (getNodeAnyWayFunc): labels
        # added after the agent started -- `kubectl label node`, which is how
        # nodeSelector tests steer Pods -- count.  The configured labels are
        # the fallback when the Node cannot be read.
        @node_labels_provider = node_labels_provider
        @cached_labels = nil
        @labels_mutex = Mutex.new
        @node_name = String(node_name)
        @allowed_unsafe_sysctls = Array(allowed_unsafe_sysctls).map(&:to_s)
        @resource_manager = resource_manager || ResourceManager.new(capacity: capacity, allocatable: allocatable)
        @node_labels = Support.stringify_keys(node_labels || {})
        @operating_system = normalize_os(operating_system)
        @architecture = normalize_architecture(architecture)
        @runtime_classes = if runtime_classes.nil? && Array(runtime_handlers).empty?
                             nil
                           else
                             normalize_runtime_classes(runtime_classes, runtime_handlers)
                           end
        @node_schedulable = !!node_schedulable
        @features = Support.stringify_keys(features || {})
        # NodeDeclaredFeatures: nil when the gate is off (no handler).
        @declared_features_framework = declared_features_framework
        @declared_features = declared_features && declared_features_framework.map_sorted(Array(declared_features).sort)
        @version = version
      end

      attr_reader :node_name, :resource_manager, :operating_system, :architecture
      # The eviction manager's admit handler, the kubelet's first: a callable
      # (pod) -> [reason, message] to refuse, nil to admit.
      attr_accessor :eviction_admit_handler
      # The container manager's resource allocation handler (the topology
      # manager, which has the CPU and memory managers allocate): a callable
      # (pod) -> TopologyManager::AdmitResult.
      attr_accessor :allocation_admit_handler
      # The node shutdown manager's handler, the kubelet's last: a callable
      # (pod) -> [reason, message] to refuse, nil to admit.
      attr_accessor :shutdown_admit_handler

      # +other_pods+: the Pods already admitted to this node (their allocated
      # specs).  With them, resources are checked the way the kubelet's
      # predicate admit handler does -- against what the node has left, not
      # against the whole node.
      def admit(pod, reserve: false, resource_requests: nil, other_pods: nil)
        pod_hash = Support.object_hash(pod)
        # The Node's labels are read only when a check needs them, from the
        # last copy read; a label check that would reject re-reads the live
        # Node once first (see #with_fresh_labels).  Reading the Node on every
        # admission was a GET per Pod start.
        Thread.current[:rubernetes_admission_node_labels] = nil
        Thread.current[:rubernetes_admission_labels_fresh] = false
        checks = [
          method(:check_eviction),
          method(:check_node_identity),
          method(:check_schedulable),
          method(:check_os),
          method(:check_architecture),
          method(:check_selector),
          method(:check_affinity),
          method(:check_runtime),
          method(:check_sysctls),
          method(:check_resource_allocation),
          method(:check_resources),
          method(:check_pod_features),
          method(:check_declared_features),
          method(:check_node_shutdown)
        ]
        checks.each do |check|
          decision = check.call(pod_hash, resource_requests: resource_requests, other_pods: other_pods)
          next unless decision

          return decision
        end
        @resource_manager.reserve(pod_hash, requests: resource_requests) if reserve
        accepted(pod_hash, requested: resource_requests || @resource_manager.request_for(pod_hash),
                 available: @resource_manager.available)
      rescue ResourceManager::InsufficientResources => error
        rejected(pod_hash, "OutOfresource", error.message, requested: error.requested, available: error.available)
      ensure
        Thread.current[:rubernetes_admission_node_labels] = nil
        Thread.current[:rubernetes_admission_labels_fresh] = nil
      end

      # The labels this admission judges by: the cached live labels (read
      # once when there are none yet), else the configured ones.
      def current_node_labels
        Thread.current[:rubernetes_admission_node_labels] ||= begin
          cached = @labels_mutex.synchronize { @cached_labels }
          cached || refresh_node_labels
        end
      end

      def refresh_node_labels
        live = live_node_labels
        @labels_mutex.synchronize { @cached_labels = live } if live
        Thread.current[:rubernetes_admission_labels_fresh] = true
        Thread.current[:rubernetes_admission_node_labels] = live || @node_labels
      end

      # Run a label check; when it rejects on cached labels, read the Node
      # again and give it one more chance (a label added just before the Pod
      # was scheduled here, which the scheduler saw).
      def with_fresh_labels
        decision = yield
        return decision if decision.nil? || @node_labels_provider.nil? || Thread.current[:rubernetes_admission_labels_fresh]

        refresh_node_labels
        yield
      end

      def live_node_labels
        return nil unless @node_labels_provider

        labels = @node_labels_provider.call
        labels.is_a?(Hash) ? Support.stringify_keys(labels) : nil
      rescue StandardError
        nil
      end

      alias check admit
      alias validate admit

      def admit!(pod, **options)
        decision = admit(pod, **options)
        raise Rejected, decision unless decision.accepted

        decision
      end

      alias validate! admit!

      def admitted?(pod, **options)
        admit(pod, **options).accepted
      end

      def available
        @resource_manager.available
      end

      # The node's declared features (sorted), or nil when NodeDeclaredFeatures is off.
      def declared_features
        @declared_features && @declared_features_framework.unmap(@declared_features)
      end

      # kubelet HandlePodUpdates: the declared features an update of a
      # running Pod needs and this node does not declare ([] when none).
      def missing_update_features(old_pod, new_pod)
        return [] if @declared_features.nil? || old_pod.nil?

        required = @declared_features_framework.infer_for_pod_update(Support.object_hash(old_pod), Support.object_hash(new_pod), @version)
        return [] if required.empty?

        @declared_features_framework.match_node_feature_set(required, @declared_features).unsatisfied_requirements
      end

      private

      def accepted(pod, requested:, available:, details: {})
        Decision.new(accepted: true, reason: "Admitted", message: "pod is admissible on #{@node_name}",
                     requested: stringify_quantities(requested), available: stringify_quantities(available),
                     pod: pod, details: Support.deep_copy(details))
      end

      def rejected(pod, reason, message, requested: {}, available: {}, details: {})
        Decision.new(accepted: false, reason: reason, message: message,
                     requested: stringify_quantities(requested), available: stringify_quantities(available),
                     pod: pod, details: Support.deep_copy(details))
      end

      def check_node_identity(pod, **_options)
        assigned = Support.value(Support.value(pod, "spec", {}), "nodeName")
        return nil if assigned.nil? || assigned.to_s.empty? || assigned.to_s == @node_name

        rejected(pod, "NodeNameMismatch", "pod is assigned to node #{assigned.inspect}, not #{@node_name}")
      end

      def check_schedulable(pod, **_options)
        return nil if @node_schedulable

        rejected(pod, "NodeUnschedulable", "node #{@node_name} is unschedulable")
      end

      def check_os(pod, **_options)
        spec = Support.object_hash(Support.value(pod, "spec", {}))
        requested = Support.value(Support.value(spec, "os", {}), "name")
        # A Pod created by the Job controller carries "annotations": null; indexing
        # that nil failed every start of GitLab's hook Jobs (30 min of retries).
        requested ||= Support.object_hash(Support.value(Support.metadata(pod), "annotations", {}))["kubernetes.io/os"]
        return nil if requested.nil? || requested.to_s.empty? || normalize_os(requested) == @operating_system

        rejected(pod, "UnsupportedOS", "pod requires OS #{requested.inspect}, node provides #{@operating_system.inspect}",
                 details: {"requestedOS" => requested, "nodeOS" => @operating_system})
      end

      def check_architecture(pod, **_options)
        metadata = Support.metadata(pod)
        annotations = Support.object_hash(Support.value(metadata, "annotations", {}))
        requested = Support.value(Support.value(pod, "spec", {}), "architecture") ||
          annotations["kubernetes.io/arch"] || annotations["kubernetes.io/architecture"]
        return nil if requested.nil? || requested.to_s.empty? || normalize_architecture(requested) == @architecture

        rejected(pod, "UnsupportedArchitecture", "pod requires architecture #{requested.inspect}, node provides #{@architecture.inspect}",
                 details: {"requestedArchitecture" => requested, "nodeArchitecture" => @architecture})
      end

      def check_selector(pod, **options)
        with_fresh_labels { check_selector_once(pod, **options) }
      end

      def check_selector_once(pod, **_options)
        selector = Support.object_hash(Support.value(Support.value(pod, "spec", {}), "nodeSelector", {}))
        selector.each do |key, expected|
          actual = node_label(key)
          next if actual.to_s == expected.to_s

          return rejected(pod, "NodeSelectorMismatch", "node label #{key.inspect} is #{actual.inspect}, expected #{expected.inspect}",
                          details: {"key" => key, "expected" => expected, "actual" => actual})
        end
        nil
      end

      def check_affinity(pod, **options)
        with_fresh_labels { check_affinity_once(pod, **options) }
      end

      def check_affinity_once(pod, **_options)
        affinity = Support.object_hash(Support.value(Support.value(pod, "spec", {}), "affinity", {}))
        node_affinity = Support.object_hash(Support.value(affinity, "nodeAffinity", {}))
        required = Support.value(node_affinity, "requiredDuringSchedulingIgnoredDuringExecution")
        return nil if required.nil?

        terms = Array(Support.value(required, "nodeSelectorTerms", []))
        return rejected(pod, "NodeAffinityMismatch", "pod has no satisfiable node affinity term") if terms.empty?

        return nil if terms.any? { |term| affinity_term_matches?(term) }

        rejected(pod, "NodeAffinityMismatch", "node does not satisfy required node affinity")
      end

      def check_runtime(pod, **_options)
        runtime = Support.value(Support.value(pod, "spec", {}), "runtimeClassName")
        return nil if runtime.nil? || runtime.to_s.empty?
        # `runtime_classes: nil` means no list was configured and the runtime
        # resolves classes itself; a configured (even empty) list is authoritative.
        return nil if @runtime_classes.nil?
        return nil if @runtime_classes.key?(runtime.to_s)

        rejected(pod, "RuntimeClassNotFound", "runtime class #{runtime.inspect} is not provided by #{@node_name}",
                 details: {"runtimeClassName" => runtime})
      end

      # pkg/kubelet/sysctl/allowlist.go: a sysctl outside the safe set and
      # the node's allowed-unsafe patterns is refused (SysctlForbidden), as
      # is a namespaced sysctl for a namespace the Pod shares with the host.
      def check_sysctls(pod, **_options)
        spec = Support.value(pod, "spec", {})
        context = Support.value(spec, "securityContext", {}) || {}
        sysctls = Array(Support.value(context, "sysctls", []))
        return nil if sysctls.empty?

        host_net = Support.value(spec, "hostNetwork", false) == true
        host_ipc = Support.value(spec, "hostIPC", false) == true
        sysctls.each do |entry|
          name = Support.value(entry, "name", "").to_s.tr("/", ".")
          return rejected(pod, "SysctlForbidden", "forbidden sysctl: #{name.inspect} is not a valid sysctl name") unless name.match?(SYSCTL_NAME)
          unless SAFE_SYSCTLS.include?(name) || unsafe_allowed?(name)
            return rejected(pod, "SysctlForbidden", "forbidden sysctl: #{name.inspect} not allowlisted")
          end
          if host_net && name.start_with?("net.")
            return rejected(pod, "SysctlForbidden", "forbidden sysctl: #{name.inspect} not allowed with host net enabled")
          end
          if host_ipc && (name.start_with?("kernel.shm", "kernel.msg", "fs.mqueue.") || name == "kernel.sem")
            return rejected(pod, "SysctlForbidden", "forbidden sysctl: #{name.inspect} not allowed with host ipc enabled")
          end
        end
        nil
      end

      def unsafe_allowed?(name)
        @allowed_unsafe_sysctls.any? do |pattern|
          pattern.end_with?("*") ? name.start_with?(pattern.chomp("*")) : name == pattern
        end
      end

      def check_resources(pod, resource_requests: nil, other_pods: nil, **_options)
        return check_fit(pod, other_pods) if other_pods && resource_requests.nil?

        requested = resource_requests || @resource_manager.request_for(pod)
        available = @resource_manager.available
        return nil if @resource_manager.fits?(requested, available: available)

        missing = requested.each_with_object({}) do |(resource, amount), output|
          requested_value = @resource_manager.parse_quantity(amount, resource)
          available_value = @resource_manager.parse_quantity(Support.value(available, resource, 0), resource)
          output[resource] = @resource_manager.format_quantity(requested_value - available_value, resource) if requested_value > available_value
        end
        resource = missing.keys.first || "resource"
        reason = resource == "cpu" ? "OutOfcpu" : (resource == "memory" ? "OutOfmemory" : "OutOfresource")
        rejected(pod, reason, "node has insufficient #{resource} capacity", requested: requested, available: available,
                 details: {"missing" => missing})
      end

      # pkg/kubelet/lifecycle/handlers.go declaredFeaturesAdmitHandler.
      def check_eviction(pod, **_options)
        return nil unless @eviction_admit_handler

        refusal = @eviction_admit_handler.call(pod)
        refusal && rejected(pod, refusal[0], refusal[1])
      end

      # podFeaturesAdmitHandler (features_linux.go): pod-level resources
      # need the PodLevelResources gate (on by default).
      def check_pod_features(pod, **_options)
        return nil unless @features.fetch("PodLevelResources", true) == false
        return nil unless ResourceHelpers.pod_level_resources_set?(pod)

        rejected(pod, "PodLevelResourcesNotSupported", "PodLevelResources feature gate is disabled")
      end

      def check_node_shutdown(pod, **_options)
        return nil unless @shutdown_admit_handler

        refusal = @shutdown_admit_handler.call(pod)
        refusal && rejected(pod, refusal[0], refusal[1])
      end

      # GetAllocateResourcesPodAdmitHandler: runs after the sysctl handler
      # and before the predicate checks, as upstream registers it.
      def check_resource_allocation(pod, **_options)
        return nil unless @allocation_admit_handler

        result = @allocation_admit_handler.call(pod)
        return nil if result.nil? || result.admit

        rejected(pod, result.reason, result.message)
      end

      def check_declared_features(pod, **_options)
        return nil if @declared_features.nil?

        framework = @declared_features_framework
        begin
          required = framework.infer_for_pod_scheduling(pod, @version)
        rescue NodeDeclaredFeatures::Error => error
          return rejected(pod, "PodFeatureUnsupported", "Failed to infer pod's feature requirements: #{error.message}")
        end
        return nil if required.empty?

        result = framework.match_node_feature_set(required, @declared_features)
        return nil if result.match?

        rejected(pod, "PodFeatureUnsupported",
                 "Pod requires node features that are not available: #{result.unsatisfied_requirements.join(", ")}",
                 details: {"missingFeatures" => result.unsatisfied_requirements})
      end

      # noderesources.Fits through lifecycle/predicate.go: pods first, then
      # cpu, memory, ephemeral-storage and scalar resources; the first
      # shortfall is the rejection (OutOfpods / OutOfcpu / OutOfmemory /
      # OutOfephemeral-storage / OutOf<name>) with the kubelet's message.
      # Extended resources the node does not have at all are dropped first
      # (removeMissingExtendedResources).
      def check_fit(pod, other_pods)
        allocatable = @resource_manager.allocatable_values
        others = Array(other_pods).map { |other| Support.object_hash(other) }.reject do |other|
          uid = Support.value(Support.metadata(other), "uid", nil)
          !uid.nil? && uid == Support.value(Support.metadata(pod), "uid", nil)
        end
        allowed = allocatable["pods"]
        if allowed && others.length + 1 > allowed
          return insufficient(pod, "pods", 1, others.length, allowed.to_i)
        end

        requested = fit_requests(pod, allocatable)
        used = others.each_with_object(Hash.new(0r)) do |other, total|
          fit_requests(other, allocatable, drop_missing: false).each { |name, value| total[name] += value }
        end
        order = %w[cpu memory ephemeral-storage] + (requested.keys - %w[cpu memory ephemeral-storage pods]).sort
        order.each do |name|
          amount = requested[name]
          next if amount.nil? || amount.zero?

          capacity = allocatable.fetch(name, 0r)
          next if amount <= capacity - used[name]

          return insufficient(pod, name, amount, used[name], capacity) if name == "cpu"

          return insufficient(pod, name, amount.ceil, used[name].ceil, capacity.ceil)
        end
        nil
      end

      def fit_requests(pod, allocatable, drop_missing: true)
        requests = @resource_manager.request_for(pod).to_h { |name, value| [name.to_s, @resource_manager.parse_quantity(value, name)] }
        requests.reject! { |name, _| ResourceManager.extended_resource?(name) && !allocatable.key?(name) } if drop_missing
        requests
      end

      def insufficient(pod, name, requested, used, capacity)
        reason = case name
                 when "cpu" then "OutOfcpu"
                 when "memory" then "OutOfmemory"
                 when "ephemeral-storage" then "OutOfephemeral-storage"
                 when "pods" then "OutOfpods"
                 else "OutOf#{name}"
                 end
        milli = ->(value) { name == "cpu" ? (value * 1000).ceil : value.to_i }
        # InsufficientResourceError's fields: the critical-Pod preemption
        # handler derives the shortfall (requested - (capacity - used)) from them.
        rejected(pod, reason,
                 "Node didn't have enough resource: #{name}, requested: #{milli.call(requested)}, used: #{milli.call(used)}, capacity: #{milli.call(capacity)}",
                 details: {"resource" => name, "requested" => milli.call(requested), "used" => milli.call(used),
                           "capacity" => milli.call(capacity)})
      end

      def affinity_term_matches?(term)
        term = Support.object_hash(term)
        expressions_match = Array(Support.value(term, "matchExpressions", [])).all? { |requirement| selector_requirement_matches?(requirement) }
        fields_match = Array(Support.value(term, "matchFields", [])).all? { |requirement| field_requirement_matches?(requirement) }
        expressions_match && fields_match
      end

      def selector_requirement_matches?(requirement)
        requirement = Support.object_hash(requirement)
        key = Support.value(requirement, "key").to_s
        operator = Support.value(requirement, "operator").to_s
        values = Array(Support.value(requirement, "values", [])).map(&:to_s)
        actual = node_label(key)
        match_selector_value?(actual, operator, values)
      end

      def field_requirement_matches?(requirement)
        requirement = Support.object_hash(requirement)
        key = Support.value(requirement, "key").to_s
        operator = Support.value(requirement, "operator").to_s
        values = Array(Support.value(requirement, "values", [])).map(&:to_s)
        actual = key == "metadata.name" ? @node_name : nil
        match_selector_value?(actual, operator, values)
      end

      def match_selector_value?(actual, operator, values)
        present = !actual.nil? && !actual.to_s.empty?
        case operator
        when "In" then present && values.include?(actual.to_s)
        when "NotIn" then !present || !values.include?(actual.to_s)
        when "Exists" then present
        when "DoesNotExist" then !present
        when "Gt" then present && actual.to_f > values.fetch(0).to_f
        when "Lt" then present && actual.to_f < values.fetch(0).to_f
        else false
        end
      end

      def node_label(key)
        return @node_name if key.to_s == "metadata.name"
        return @operating_system if key.to_s == "kubernetes.io/os" || key.to_s == "beta.kubernetes.io/os"
        return @architecture if key.to_s == "kubernetes.io/arch" || key.to_s == "beta.kubernetes.io/arch"

        current_node_labels[key.to_s]
      end

      def normalize_runtime_classes(classes, handlers)
        values = if classes.is_a?(Array)
                   classes.each_with_object({}) { |entry, output| output[Support.value(entry, "name", entry).to_s] = entry }
                 else
                   Support.object_hash(classes || {})
                 end
        Array(handlers).each do |handler|
          name = Support.value(handler, "name")
          values[name.to_s] = handler if name
        end
        values.transform_keys(&:to_s)
      end

      def normalize_os(value)
        value.to_s.downcase.gsub(/\A.*?\b(linux|windows|darwin|freebsd)\b.*/, '\\1')
      end

      def normalize_architecture(value)
        case value.to_s.downcase
        when "x86_64", "x86-64", "amd64" then "amd64"
        when "aarch64", "arm64" then "arm64"
        when "armv7", "arm" then "arm"
        when "ppc64le" then "ppc64le"
        when "s390x" then "s390x"
        else value.to_s.downcase
        end
      end

      def stringify_quantities(values)
        return {} if values.nil?
        Support.object_hash(values).each_with_object({}) do |(resource, value), output|
          output[resource.to_s] = if value.is_a?(String)
                                    value
                                  else
                                    @resource_manager.format_quantity(value, resource)
                                  end
        end
      end
    end

    NodeAdmission = Admission unless const_defined?(:NodeAdmission, false)
  end
end
