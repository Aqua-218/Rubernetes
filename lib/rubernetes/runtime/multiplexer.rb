# frozen_string_literal: true

module Rubernetes
  module Runtime
    # Routes the node's runtime calls to the backend that serves a Pod's
    # RuntimeClass handler: rubernetes-native (default), rubernetes-firecracker
    # and rubernetes-firecracker-restricted.  Sandboxes and containers are
    # remembered by the backend that created them so every later call lands
    # on the owner; an unknown handler is rejected before any effect.
    class Multiplexer
      DEFAULT_HANDLER = "rubernetes-native"

      class CheckpointUnsupported < StandardError; end

      def initialize(backends:, default: DEFAULT_HANDLER)
        @backends = backends.transform_keys(&:to_s)
        @default = default
        raise ArgumentError, "no backend for the default handler #{default}" unless @backends.key?(default)

        @sandbox_owner = {}
        @container_owner = {}
        @mutex = Mutex.new
      end

      attr_reader :backends

      def handlers = @backends.keys

      def backend_for(handler)
        @backends.fetch(handler.to_s) { raise ArgumentError, "runtime class handler #{handler.inspect} is not provided by this node" }
      end

      def run_sandbox(config, runtime_class: nil, **options)
        handler = runtime_class || config["runtime_class"] || config[:runtime_class] || @default
        backend = backend_for(handler)
        id = backend.run_sandbox(config, runtime_class: handler, **options)
        key = id.respond_to?(:id) ? id.id : id.to_s
        @mutex.synchronize { @sandbox_owner[key] = backend }
        id
      end

      def create_container(sandbox, spec, **options)
        backend = owner_of_sandbox(sandbox)
        container = backend.create_container(sandbox, spec, **options)
        key = container.respond_to?(:id) ? container.id : container.to_s
        @mutex.synchronize { @container_owner[key] = backend }
        container
      end

      %i[stop_sandbox remove_sandbox network_sandbox_context].each do |name|
        define_method(name) do |sandbox, *arguments, **options|
          backend = owner_of_sandbox(sandbox)
          result = backend.public_send(name, sandbox, *arguments, **options)
          @mutex.synchronize { @sandbox_owner.delete(sandbox_key(sandbox)) } if name == :remove_sandbox
          result
        end
      end

      %i[start_container stop_container remove_container container_status exec attach logs stats wait_container port_forward http_get tcp_socket].each do |name|
        define_method(name) do |container, *arguments, **options, &block|
          backend = owner_of_container(container)
          result = backend.public_send(name, container, *arguments, **options, &block)
          @mutex.synchronize { @container_owner.delete(container_key(container)) } if name == :remove_container
          result
        end
      end

      # In-place resize goes to the backend that owns the sandbox/container; a
      # backend without the capability reports it as unsupported (nil).
      %i[update_pod_resources pod_cgroup_readback pod_usage].each do |name|
        define_method(name) do |sandbox, *arguments, **options|
          backend = owner_of_sandbox(sandbox)
          backend.respond_to?(name) ? backend.public_send(name, sandbox, *arguments, **options) : nil
        end
      end

      def update_container_resources(container, *arguments, **options)
        backend = owner_of_container(container)
        backend.respond_to?(:update_container_resources) ? backend.update_container_resources(container, *arguments, **options) : nil
      end

      def update_container_cpuset(container, cpus)
        backend = owner_of_container(container)
        backend.respond_to?(:update_container_cpuset) ? backend.update_container_cpuset(container, cpus) : nil
      end

      # A backend that streams through its own server (a CRI runtime)
      # answers the URL the node relays exec / attach / port-forward to;
      # nil for the others, which stream through the node itself.
      def streaming_url(operation, container, **options)
        backend = owner_of_container(container)
        backend.respond_to?(:streaming_url) ? backend.streaming_url(operation, container, **options) : nil
      end

      def streaming_backends? = @backends.values.any? { |backend| backend.respond_to?(:streaming_url) }

      # kubelet CheckpointContainer (ContainerCheckpoint): the owning runtime
      # writes the checkpoint archive to +location+.
      def checkpoint_container(container, location:, timeout: nil)
        backend = owner_of_container(container)
        unless backend.respond_to?(:checkpoint_container)
          raise CheckpointUnsupported, "checkpoint/restore support not available: the runtime handling this container cannot checkpoint containers"
        end

        backend.checkpoint_container(container, location: location, timeout: timeout)
      end

      def recover(**options)
        @backends.transform_values { |backend| backend.respond_to?(:recover) ? backend.recover(**options) : nil }
      end

      def profile
        backend_for(@default).profile
      end

      def respond_to_missing?(name, include_private = false)
        backend_for(@default).respond_to?(name, include_private) || super
      end

      def method_missing(name, *arguments, **options, &block)
        backend = backend_for(@default)
        return backend.public_send(name, *arguments, **options, &block) if backend.respond_to?(name)

        super
      end

      private

      def sandbox_key(value)
        value.respond_to?(:id) ? value.id.to_s : value.to_s
      end

      def container_key(value)
        value.respond_to?(:id) ? value.id.to_s : value.to_s
      end

      # A sandbox or container this process did not create (the agent
      # restarted) is claimed by the backend that knows it -- asked only of
      # backends that can tell -- else it is the default backend's.
      def owner_of_sandbox(sandbox)
        key = sandbox_key(sandbox)
        known = @mutex.synchronize { @sandbox_owner[key] }
        return known if known

        # Asked once: the answer (the default's, when nobody claims it) sticks.
        owner = claimant(:owns_sandbox?, key) || backend_for(@default)
        @mutex.synchronize { @sandbox_owner[key] = owner } if @backends.size > 1
        owner
      end

      def owner_of_container(container)
        key = container_key(container)
        known = @mutex.synchronize { @container_owner[key] }
        return known if known

        # Asked once: the answer (the default's, when nobody claims it) sticks.
        owner = claimant(:owns_container?, key) || backend_for(@default)
        @mutex.synchronize { @container_owner[key] = owner } if @backends.size > 1
        owner
      end

      def claimant(question, key)
        @backends.each do |handler, backend|
          next if handler == @default || !backend.respond_to?(question)

          return backend if backend.public_send(question, key)
        rescue StandardError
          next
        end
        nil
      end
    end
  end
end
