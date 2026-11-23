# frozen_string_literal: true

require_relative "../watch/reflector"

module Rubernetes
  module Bootstrap
    # Reconciles the cluster API view with the network attachments this node
    # owns. A remote Pod supplies peer addresses, never a local rule target.
    class NetworkPolicySync
      include TransientLoopErrors

      RESOURCES = {
        "pods" => %w[Pod v1],
        "namespaces" => %w[Namespace v1],
        "networkpolicies" => %w[NetworkPolicy networking.k8s.io/v1]
      }.freeze
      RETRY_SECONDS = 0.5

      # A Reflector sink retains only the fields used for policy compilation.
      # Replacing the collection is atomic even when a relist has no items.
      Collection = Data.define(:sync, :resource) do
        def replace(objects, **)
          sync.replace(resource, objects)
        end

        def add(object, **)
          sync.update(resource, object)
        end
        alias_method :update, :add

        def delete(object, **)
          sync.update(resource, object, deleted: true)
        end
      end

      def initialize(client:, engine:, node_name:, logger:, own_client: false)
        @client = client
        @engine = engine
        @node_name = node_name
        @logger = logger
        @own_client = own_client
        @mutex = Mutex.new
        @changed = ConditionVariable.new
        @objects = RESOURCES.to_h { |resource, _| [resource, {}] }
        @local_pods = []
        @reflectors = RESOURCES.map do |resource, (kind, version)|
          descriptor = Controller::ResourceDescriptor.parse(kind, version: version, resource: resource)
          source = KubernetesResourceSource.new(client: client, descriptor: descriptor)
          Watch::Reflector.new(client: source, fifo: Collection.new(self, resource), resource: descriptor,
                               error_handler: ->(error, *) { log_error("watch_failed", resource, error) })
        end
      end

      def start(pods:)
        @reflectors.each { |reflector| initial_list(reflector) }
        @mutex.synchronize do
          @published_empty = false
          publish(pods)
          @local_pods = pods
          @running = true
          @thread = Thread.new { reconcile }
        end
        @reflectors.each(&:start)
      rescue StandardError
        stop
        raise
      end

      def stop
        thread = @mutex.synchronize do
          @running = false
          @changed.broadcast
          @thread
        end
        @reflectors.each(&:stop)
        thread&.join
        @client.close if @own_client
      end

      def ready?
        @mutex.synchronize { @running && !@publish_error }
      end

      # Network ADD waits for its policy installation before a container can
      # run. Failed kernel publication never advances the accepted inventory.
      def sync_pods(pods)
        @mutex.synchronize do
          publish(pods) if @running && (pods != @local_pods || @dirty)
          @local_pods = pods
        end
      end

      def replace(resource, objects)
        entries = objects.to_h { |object| [object_key(object), project(resource, object)] }
        @mutex.synchronize do
          return if entries == @objects.fetch(resource)

          @objects[resource] = entries
          changed
        end
      end

      def update(resource, object, deleted: false)
        key = object_key(object)
        value = project(resource, object) unless deleted
        @mutex.synchronize do
          collection = @objects.fetch(resource)
          previous = collection[key]
          if deleted
            return unless previous && previous.dig("metadata", "uid") == object.dig("metadata", "uid")

            collection.delete(key)
          else
            return if previous == value

            collection[key] = value
          end
          changed
        end
      end

      def self.ports(spec)
        containers = Array(spec["containers"] || spec[:containers])
        sidecars = Array(spec["initContainers"] || spec[:initContainers]).select do |container|
          (container["restartPolicy"] || container[:restartPolicy]) == "Always"
        end
        (containers + sidecars).flat_map do |container|
          Array(container["ports"] || container[:ports]).filter_map do |port|
            name, number, protocol = port.transform_keys(&:to_s).values_at("name", "containerPort", "protocol")
            next if name.to_s.empty? || number.nil?

            {"name" => name, "containerPort" => number, "protocol" => protocol}.compact
          end
        end
      end

      private

      def initial_list(reflector)
        failures = 0
        begin
          reflector.list!
        rescue StandardError => error
          failures += 1
          raise if failures > 2 || !transient_loop_error?(error)

          log_error("initial_list_retry", nil, error)
          sleep(loop_backoff(failures))
          retry
        end
      end

      def object_key(object)
        metadata = object.fetch("metadata")
        [metadata["namespace"], metadata.fetch("name")]
      end

      def project(resource, object)
        metadata = object.fetch("metadata").slice("namespace", "name", "uid", "labels")
        case resource
        when "networkpolicies"
          {"metadata" => metadata, "spec" => object.fetch("spec")}
        when "namespaces"
          {"metadata" => metadata}
        else
          spec = object.fetch("spec", {})
          state = object.fetch("status", {})
          ips = Array(state["podIPs"]).filter_map { |item| item["ip"] }
          ips = [state["podIP"]].compact if ips.empty?
          {"metadata" => metadata, "node" => spec["nodeName"], "ports" => self.class.ports(spec),
           "ips" => ips, "eligible" => !spec["hostNetwork"] && !%w[Succeeded Failed].include?(state["phase"])}
        end
      end

      def changed
        @dirty = true
        @changed.signal
      end

      def reconcile
        @mutex.synchronize do
          while @running
            @changed.wait(@mutex) until @dirty || !@running
            break unless @running

            begin
              publish(@local_pods)
            rescue StandardError => error
              @publish_error = true
              log_error("publish_failed", nil, error)
              @changed.wait(@mutex, RETRY_SECONDS)
            end
          end
        end
      end

      def publish(local)
        policies = @objects.fetch("networkpolicies").values
        # Namespace and Pod churn cannot affect the dataplane when no policy
        # exists. Publish the first empty set or the transition to empty so
        # stale rules from a previous activation are still removed.
        unless policies.empty? && @published_empty
          labels = @objects.fetch("namespaces").values.to_h do |namespace|
            metadata = namespace.fetch("metadata")
            [metadata.fetch("name"), metadata.fetch("labels", {})]
          end
          @engine.apply(policies, namespace_labels: labels, pod_index: pod_index(local))
          @published_empty = policies.empty?
        end
        @dirty = false
        @publish_error = false
      end

      def pod_index(local)
        pods = @objects.fetch("pods")
        owned_uids = local.filter_map { |pod| pod["uid"] }.to_set
        remote = pods.values.filter_map do |pod|
          metadata = pod.fetch("metadata")
          uid = metadata["uid"]
          next if pod["node"].nil? || pod["node"] == @node_name || owned_uids.include?(uid)
          next unless pod["eligible"] && !pod.fetch("ips").empty?

          metadata.slice("namespace", "name", "labels").merge(pod.slice("ips", "ports"), "local" => false)
        end
        remote + local.map do |attached|
          api = pods[attached.values_at("namespace", "name")]
          if api && attached["uid"] && api.dig("metadata", "uid") == attached["uid"]
            attached.merge("labels" => api.dig("metadata", "labels") || {}, "ports" => api.fetch("ports"))
          else
            attached
          end
        end
      end

      def log_error(event, resource, error)
        @logger.warn("network.policy.#{event}", resource: resource, error: error.class.name, message: error.message)
      end
    end
  end
end
