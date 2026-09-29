# frozen_string_literal: true

# Node registration and heartbeat primitives.  The class intentionally does
# not know about an HTTP transport or a particular storage implementation;
# callers inject a small API client and can therefore exercise registration in
# a deterministic unit test.

require "digest"
require "securerandom"
require "time"

module Rubernetes
  module Node
    # Small, transport-neutral helpers shared by the node operational classes.
    # Keeping the helpers here lets every node component be required on its own
    # while avoiding a dependency on generated API classes in pure tests.
    module Support
      module_function

      def value(object, key, default = nil)
        return default if object.nil?

        if object.is_a?(Hash)
          string_key = key.to_s
          return object[string_key] if object.key?(string_key)
          symbol_key = key.to_sym
          return object[symbol_key] if object.key?(symbol_key)
        end

        candidates = [key.to_s, camel_to_snake(key.to_s)]
        candidates.each do |candidate|
          return object.public_send(candidate) if object.respond_to?(candidate)
        end
        return object.field(key.to_s) if object.respond_to?(:field)

        default
      end

      def present?(object, key)
        !value(object, key, :__missing__).equal?(:__missing__)
      end

      def object_hash(object)
        source = if object.is_a?(Array)
                   {}
                 elsif object.respond_to?(:to_h)
                   object.to_h
                 elsif object.respond_to?(:to_hash)
                   object.to_hash
                 else
                   object
                 end
        stringify_keys(source || {})
      end

      def stringify_keys(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, child), output|
            output[key.to_s] = stringify_keys(child)
          end
        when Array
          value.map { |child| stringify_keys(child) }
        else
          value
        end
      end

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, child), output| output[key] = deep_copy(child) }
        when Array
          value.map { |child| deep_copy(child) }
        else
          value
        end
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each { |key, child| deep_freeze(key); deep_freeze(child) }
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end

      def merge_hashes(left, right)
        left = object_hash(left)
        right = object_hash(right)
        left.merge(right) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            merge_hashes(old_value, new_value)
          else
            deep_copy(new_value)
          end
        end
      end

      def camel_to_snake(name)
        name.to_s.gsub(/([a-z\d])([A-Z])/, "\\1_\\2").tr("-", "_").downcase
      end

      def iso8601(time)
        value = time.respond_to?(:call) ? time.call : time
        value = Time.parse(value.to_s) unless value.respond_to?(:utc)
        value.utc.iso8601(6)
      end

      def metadata(object)
        object_hash(value(object, "metadata", {}))
      end

      def name(object)
        value(metadata(object), "name") || value(object, "name")
      end

      def uid(object)
        value(metadata(object), "uid") || value(object, "uid")
      end

      def namespace(object, default = nil)
        value(metadata(object), "namespace") || value(object, "namespace") || default
      end

      def not_found?(error)
        error.class.name.to_s.end_with?("::NotFound") ||
          error.class.name.to_s == "NotFound" ||
          error.is_a?(KeyError) ||
          error.respond_to?(:reason) && error.reason.to_s.casecmp?("NotFound")
      end

      def conflict?(error)
        error.class.name.to_s.end_with?("::Conflict") ||
          error.class.name.to_s == "Conflict" ||
          error.respond_to?(:reason) && %w[AlreadyExists Conflict].include?(error.reason.to_s)
      end

      # Invoke a client with either keyword or positional contracts.  This is
      # deliberately based on the method signature rather than rescue/retry:
      # an ArgumentError raised by the client itself must reach the caller.
      def invoke(client, method_name, resource:, namespace:, name:, object: nil, subresource: nil)
        raise ArgumentError, "client does not implement ##{method_name}" unless client.respond_to?(method_name)

        method = client.method(method_name)
        parameters = method.parameters
        keywords = {
          resource: resource,
          gvr: resource,
          namespace: namespace,
          name: name,
          object: object,
          body: object,
          resource_version: value(metadata(object), "resourceVersion"),
          subresource: subresource
        }
        accepts_keywords = parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
        selected_keywords = if parameters.any? { |kind, _| kind == :keyrest }
                              keywords
                            else
                              names = parameters.filter_map { |kind, parameter| parameter if %i[key keyreq].include?(kind) }
                              keywords.select { |key, _value| names.include?(key) }
                            end
        positional_parameters = parameters.select { |kind, _| %i[req opt].include?(kind) }
        positional = positional_parameters.map.with_index do |(_kind, parameter), index|
          case parameter
          when :key, :resource, :gvr then resource
          when :object, :body, :pod then object
          when :namespace then namespace
          when :name then name
          else
            method_name.to_sym == :get || method_name.to_sym == :read || method_name.to_sym == :fetch ?
              [resource, namespace, name][index] : [resource, namespace, object][index]
          end
        end
        positional = [resource, namespace, object] if parameters.any? { |kind, _| kind == :rest }
        positional_count = parameters.any? { |kind, _| kind == :rest } ? positional.length : positional_parameters.length
        if accepts_keywords
          method.call(*positional.first(positional_count), **selected_keywords)
        else
          method.call(*positional.first(positional_count))
        end
      end
    end unless const_defined?(:Support, false)

    class Registration
      Result = Data.define(:node, :lease, :node_action, :lease_action) do
        def to_h
          {"node" => node, "lease" => lease, "nodeAction" => node_action, "leaseAction" => lease_action}
        end
      end

      NODE_RESOURCE = "v1/nodes".freeze
      LEASE_RESOURCE = "coordination.k8s.io/v1/leases".freeze
      LEASE_NAMESPACE = "kube-node-lease".freeze
      DEFAULT_LEASE_DURATION_SECONDS = 40

      def initialize(node_name:, client: nil, api: nil, store: nil, capacity: {}, allocatable: nil, labels: {}, annotations: {},
                     node_info: {}, conditions: nil, addresses: [], taints: nil, lease_duration_seconds: DEFAULT_LEASE_DURATION_SECONDS,
                     clock: -> { Time.now.utc }, uid_generator: -> { SecureRandom.uuid }, operating_system: nil,
                     architecture: nil, os: nil, arch: nil, kubelet_version: nil, container_runtime_version: nil, kernel_version: nil,
                     os_image: nil, host_ip: nil)
        @node_name = String(node_name)
        raise ArgumentError, "node_name must not be empty" if @node_name.empty? || @node_name.include?("/")

        @client = client || api || store
        @capacity = Support.stringify_keys(capacity || {}).freeze
        @allocatable = Support.stringify_keys(allocatable || capacity || {}).freeze
        # Assigned below so the well-known labels can use them.
        @operating_system = normalize_operating_system(os || operating_system || RUBY_PLATFORM)
        @architecture = normalize_architecture(arch || architecture || RUBY_PLATFORM)
        # The kubelet always applies the well-known topology labels; workloads
        # and conformance both select on them, and a node without them is
        # unschedulable for anything with a nodeSelector.  Explicit labels win.
        @labels = well_known_labels.merge(Support.stringify_keys(labels || {})).freeze
        @annotations = Support.stringify_keys(annotations || {}).freeze
        @node_info = Support.stringify_keys(node_info || {}).freeze
        @conditions = conditions && Support.deep_copy(conditions)
        @addresses = Support.deep_copy(addresses || [])
        @taints = taints && Support.deep_copy(taints)
        @lease_duration_seconds = Integer(lease_duration_seconds)
        raise ArgumentError, "lease_duration_seconds must be positive" unless @lease_duration_seconds.positive?

        @clock = clock
        @uid_generator = uid_generator
        @kubelet_version = kubelet_version
        @container_runtime_version = container_runtime_version
        @kernel_version = kernel_version
        @os_image = os_image
        @host_ip = host_ip
      end

      attr_reader :node_name, :client, :lease_duration_seconds

      alias name node_name

      # v1.WellKnownLabels applied by the kubelet on every registration.
      def well_known_labels
        {
          "kubernetes.io/hostname" => @node_name,
          "kubernetes.io/os" => @operating_system,
          "kubernetes.io/arch" => @architecture,
          "beta.kubernetes.io/os" => @operating_system,
          "beta.kubernetes.io/arch" => @architecture
        }
      end

      # Kubernetes speaks Go's GOARCH ("amd64"), not uname's ("x86_64"); node
      # labels, image selection and nodeAffinity all match on the Go form.
      # Exposed so the node agent normalises identically.
      def self.normalize_architecture(value)
        text = String(value).downcase
        return "amd64" if text.include?("x86_64") || text.include?("amd64")
        return "arm64" if text.include?("aarch64") || text.include?("arm64")

        text.split("-").first
      end

      def node_object(status: nil, metadata: {})
        now = Support.iso8601(@clock)
        metadata = Support.merge_hashes(
          {
            "name" => @node_name,
            "labels" => @labels,
            "annotations" => @annotations
          }, metadata
        )
        {
          "apiVersion" => "v1",
          "kind" => "Node",
          "metadata" => metadata,
          "spec" => {"taints" => Support.deep_copy(@taints)}.compact,
          "status" => status || node_status(now: now)
        }
      end

      alias build_node node_object

      def node_status(now: Support.iso8601(@clock), conditions: nil, capacity: @capacity, allocatable: @allocatable)
        info = {
          "architecture" => @architecture,
          "operatingSystem" => @operating_system,
          "kubeletVersion" => @kubelet_version,
          "containerRuntimeVersion" => @container_runtime_version,
          "kernelVersion" => @kernel_version,
          "osImage" => @os_image
        }.compact.merge(@node_info)
        status = {
          "capacity" => Support.deep_copy(capacity),
          "allocatable" => Support.deep_copy(allocatable),
          "conditions" => Support.deep_copy(conditions || default_conditions(now: now)),
          "nodeInfo" => info
        }
        status["addresses"] = Support.deep_copy(@addresses) unless @addresses.empty?
        status["addresses"] = [{"type" => "InternalIP", "address" => @host_ip}] if @host_ip && @addresses.empty?
        status
      end

      alias build_node_status node_status

      def default_conditions(now: Support.iso8601(@clock))
        [{
          "type" => "Ready",
          "status" => "Unknown",
          "reason" => "KubeletNotReady",
          "message" => "node is registering",
          "lastHeartbeatTime" => now,
          "lastTransitionTime" => now
        }]
      end

      def lease_object(now: Support.iso8601(@clock), existing: nil, holder_identity: @node_name)
        previous = Support.object_hash(Support.value(existing, "spec", {}))
        previous_holder = Support.value(previous, "holderIdentity")
        transitions = Integer(Support.value(previous, "leaseTransitions", 0) || 0)
        transitions += 1 if previous_holder && previous_holder != holder_identity
        transitions = 0 if transitions.negative?
        {
          "apiVersion" => "coordination.k8s.io/v1",
          "kind" => "Lease",
          "metadata" => {
            "name" => @node_name,
            "namespace" => LEASE_NAMESPACE,
            "labels" => {"kubernetes.io/hostname" => @node_name}
          },
          "spec" => {
            "holderIdentity" => String(holder_identity),
            "leaseDurationSeconds" => @lease_duration_seconds,
            "acquireTime" => Support.value(previous, "acquireTime") || now,
            "renewTime" => now,
            "leaseTransitions" => transitions
          }
        }
      end

      alias build_lease lease_object

      def register
        desired_node = node_object
        existing_node = read(NODE_RESOURCE, namespace: nil, name: @node_name)
        node, node_action = if existing_node
                              [update_resource(NODE_RESOURCE, namespace: nil, name: @node_name,
                                               object: preserve_server_metadata(desired_node, existing_node)), "updated"]
                            else
                              [create_resource(NODE_RESOURCE, namespace: nil, name: @node_name, object: desired_node), "created"]
                            end

        existing_lease = read(LEASE_RESOURCE, namespace: LEASE_NAMESPACE, name: @node_name)
        desired_lease = lease_object(existing: existing_lease)
        lease, lease_action = if existing_lease
                                [update_resource(LEASE_RESOURCE, namespace: LEASE_NAMESPACE, name: @node_name,
                                                 object: preserve_server_metadata(desired_lease, existing_lease)), "updated"]
                              else
                                [create_resource(LEASE_RESOURCE, namespace: LEASE_NAMESPACE, name: @node_name, object: desired_lease), "created"]
                              end
        Result.new(node: node || desired_node, lease: lease || desired_lease,
                   node_action: node_action, lease_action: lease_action)
      end

      alias register! register

      alias register_node register

      def heartbeat
        existing_lease = read(LEASE_RESOURCE, namespace: LEASE_NAMESPACE, name: @node_name)
        desired = lease_object(existing: existing_lease)
        result = if existing_lease
                   update_resource(LEASE_RESOURCE, namespace: LEASE_NAMESPACE, name: @node_name,
                                   object: preserve_server_metadata(desired, existing_lease))
                 else
                   create_resource(LEASE_RESOURCE, namespace: LEASE_NAMESPACE, name: @node_name, object: desired)
                 end
        result || desired
      end

      alias renew heartbeat
      alias renew_lease heartbeat
      alias update_lease heartbeat

      def update_status(status: nil, conditions: nil, capacity: @capacity, allocatable: @allocatable)
        existing = read(NODE_RESOURCE, namespace: nil, name: @node_name)
        current_status = Support.object_hash(Support.value(existing, "status", {}))
        next_status = if status
                        Support.object_hash(status)
                      else
                        Support.merge_hashes(current_status, node_status(conditions: conditions, capacity: capacity,
                                                                          allocatable: allocatable))
                      end
        desired = if existing
                    Support.merge_hashes(Support.object_hash(existing), {"status" => next_status})
                  else
                    node_object(status: next_status)
                  end
        result = if existing
                   update_resource(NODE_RESOURCE, namespace: nil, name: @node_name,
                                   object: preserve_server_metadata(desired, existing), subresource: "status")
                 else
                   create_resource(NODE_RESOURCE, namespace: nil, name: @node_name, object: desired)
                 end
        result || desired
      end

      alias update_node_status update_status

      private

      def read(resource, namespace:, name:)
        return nil unless @client
        return nil unless @client.respond_to?(:get) || @client.respond_to?(:read) || @client.respond_to?(:fetch)

        Support.invoke(@client, @client.respond_to?(:get) ? :get : (@client.respond_to?(:read) ? :read : :fetch),
                       resource: resource, namespace: namespace, name: name)
      rescue StandardError => error
        raise unless Support.not_found?(error)

        nil
      end

      def create_resource(resource, namespace:, name:, object:)
        return object unless @client
        return object unless @client.respond_to?(:create)

        result = Support.invoke(@client, :create, resource: resource, namespace: namespace, name: name, object: object)
        result || object
      rescue StandardError => error
        if Support.conflict?(error)
          existing = read(resource, namespace: namespace, name: name)
          return update_resource(resource, namespace: namespace, name: name, object: object) if existing
        end
        raise
      end

      def update_resource(resource, namespace:, name:, object:, subresource: nil)
        return object unless @client
        method_name = if subresource == "status" && @client.respond_to?(:update_status)
                        :update_status
                      elsif @client.respond_to?(:update)
                        :update
                      elsif @client.respond_to?(:replace)
                        :replace
                      end
        return object unless method_name

        result = Support.invoke(@client, method_name, resource: resource, namespace: namespace, name: name,
                                object: object, subresource: subresource)
        result || object
      end

      def preserve_server_metadata(desired, existing)
        existing_metadata = Support.metadata(existing)
        metadata = Support.object_hash(desired["metadata"])
        %w[uid resourceVersion generation creationTimestamp managedFields].each do |field|
          metadata[field] = existing_metadata[field] if existing_metadata.key?(field)
        end
        desired.merge("metadata" => metadata)
      end

      def normalize_operating_system(value)
        text = String(value).downcase
        return "linux" if text.include?("linux")
        return "windows" if text.include?("windows")
        return "darwin" if text.include?("darwin") || text.include?("macos")

        text.split("-").first
      end

      def normalize_architecture(value)
        self.class.normalize_architecture(value)
      end
    end

    NodeRegistration = Registration unless const_defined?(:NodeRegistration, false)
  end
end
