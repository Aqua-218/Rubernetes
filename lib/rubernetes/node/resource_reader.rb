# frozen_string_literal: true

require "json"

module Rubernetes
  module Node
    # Read-only access to the API objects a kubelet needs while building a
    # Pod: ConfigMaps and Secrets for env/volumes, Services for the service
    # environment, PersistentVolumeClaims/PersistentVolumes for claim
    # volumes, and the Node's own object.  Everything goes through the agent's
    # API client so authorization is the Node authorizer's, never the pod's.
    #
    # Reads are cached for a short window: a Pod start touches the same
    # ConfigMap several times (env, envFrom, volume) and kubelet serves those
    # from its informer cache rather than hitting the API server each time.
    class ResourceReader
      class NotFound < StandardError; end

      DEFAULT_TTL_SECONDS = 5.0

      RESOURCES = {
        "configmaps" => "v1", "secrets" => "v1", "services" => "v1",
        "persistentvolumeclaims" => "v1", "persistentvolumes" => "v1", "nodes" => "v1",
        "serviceaccounts" => "v1", "endpointslices" => "discovery.k8s.io/v1",
        "runtimeclasses" => "node.k8s.io/v1", "clustertrustbundles" => "certificates.k8s.io/v1beta1"
      }.freeze
      CLUSTER_SCOPED = %w[persistentvolumes nodes runtimeclasses clustertrustbundles].freeze

      SLOW_FETCH_SECONDS = 2.0

      def initialize(client:, ttl: DEFAULT_TTL_SECONDS, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, logger: nil)
        raise ArgumentError, "client is required" unless client

        @client = client
        @logger = logger
        @ttl = Float(ttl)
        @clock = clock
        @cache = {}
        @mutex = Mutex.new
      end

      # Returns the object as a String-keyed Hash, or nil when it does not
      # exist.  Any other API failure is raised: a kubelet that cannot read a
      # ConfigMap must not guess its contents.
      def get(resource, name, namespace: nil)
        plural = plural_for(resource)
        key = [plural, namespace.to_s, name.to_s]
        cached = read_cache(key)
        return cached.fetch(:value) if cached

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        value = begin
          fetch_object(plural, name, namespace: namespace)
        rescue StandardError => error
          log_slow(plural, name, namespace, started, error: error)
          raise unless not_found?(error)

          nil
        end
        log_slow(plural, name, namespace, started)
        write_cache(key, value)
        value
      end

      # A volume whose 50 ConfigMap reads each took 23 s spent 19 minutes in
      # MountVolume.SetUp with nothing in any log; this names the slow read.
      def log_slow(plural, name, namespace, started, error: nil)
        return unless @logger

        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        return if elapsed < SLOW_FETCH_SECONDS && error.nil?

        @logger.call(:warn, "resource_reader.slow", resource: plural, name: name.to_s, namespace: namespace.to_s,
                                                    seconds: elapsed.round(3), error: error && "#{error.class}: #{error.message}"[0, 200])
      rescue StandardError
        nil
      end

      def fetch(resource, name, namespace: nil)
        value = get(resource, name, namespace: namespace)
        raise NotFound, "#{singular_for(resource)} #{namespace ? "#{namespace}/" : ""}#{name} not found" if value.nil?

        value
      end

      # Lists a namespaced collection (or, with namespace: :all, every one).
      def list(resource, namespace: nil)
        plural = plural_for(resource)
        key = [plural, "list:#{namespace}", nil]
        cached = read_cache(key)
        return cached.fetch(:value) if cached

        response = if @client.respond_to?(:list_objects)
                     @client.list_objects(plural, namespace: namespace, api_version: RESOURCES.fetch(plural, "v1"))
                   else
                     raw_get(plural, nil, namespace: namespace)
                   end
        body = normalize(response)
        items = Array(body["items"]).map { |item| stringify(item) }
        write_cache(key, items)
        items
      end

      def invalidate(resource = nil, name = nil, namespace: nil)
        @mutex.synchronize do
          if resource.nil?
            @cache.clear
          else
            plural = plural_for(resource)
            @cache.delete_if { |key, _| key[0] == plural && (name.nil? || key[2] == name.to_s) && (namespace.nil? || key[1] == namespace.to_s) }
          end
        end
      end

      # A status write (the kubelet's PVC resize status); the cached copy is
      # dropped so the next read sees it.
      def patch_status(resource, name, patch, namespace: nil, type: :merge)
        plural = plural_for(resource)
        client = if @client.respond_to?(:patch)
                   @client
                 elsif @client.respond_to?(:client) && @client.client.respond_to?(:patch)
                   @client.client
                 else
                   raise ArgumentError, "resource reader client cannot patch"
                 end
        scope = CLUSTER_SCOPED.include?(plural) ? nil : namespace
        result = client.patch(plural, patch, type: type, namespace: scope, api_version: RESOURCES.fetch(plural, "v1"),
                                             name: name, subresource: "status")
        invalidate(plural, name, namespace: scope)
        result
      end

      private

      def fetch_object(plural, name, namespace:)
        response = if @client.respond_to?(:read_object)
                     @client.read_object(plural, name, namespace: namespace, api_version: RESOURCES.fetch(plural, "v1"))
                   else
                     raw_get(plural, name, namespace: namespace)
                   end
        value = normalize(response)
        return nil if value.nil? || value.empty?
        raise NotFound, "#{plural} #{name} not found" if value["kind"] == "Status" && value["code"].to_i == 404

        value
      end

      def raw_get(plural, name, namespace:)
        api_version = RESOURCES.fetch(plural, "v1")
        scope = CLUSTER_SCOPED.include?(plural) ? nil : namespace
        if @client.respond_to?(:get)
          @client.get(plural, name, namespace: scope, api_version: api_version)
        elsif @client.respond_to?(:client) && @client.client.respond_to?(:get)
          @client.client.get(plural, name, namespace: scope, api_version: api_version)
        else
          raise ArgumentError, "resource reader client must implement get"
        end
      end

      def normalize(response)
        value = if response.respond_to?(:json)
                  response.json
                elsif response.respond_to?(:body) && !response.is_a?(Hash)
                  body = response.body
                  body.is_a?(String) ? (body.empty? ? nil : JSON.parse(body)) : body
                else
                  response
                end
        value.nil? ? nil : stringify(value)
      end

      def stringify(value)
        case value
        when Hash then value.each_with_object({}) { |(key, child), result| result[key.to_s] = stringify(child) }
        when Array then value.map { |child| stringify(child) }
        else value
        end
      end

      def not_found?(error)
        return true if error.is_a?(NotFound)
        return error.status.to_i == 404 if error.respond_to?(:status) && !error.status.nil?
        return error.response.status.to_i == 404 if error.respond_to?(:response) && error.response.respond_to?(:status)

        error.message.to_s.match?(/\b404\b|not found/i)
      end

      def read_cache(key)
        @mutex.synchronize do
          entry = @cache[key]
          return nil unless entry
          return nil if @clock.call - entry.fetch(:at) > @ttl

          entry
        end
      end

      def write_cache(key, value)
        @mutex.synchronize { @cache[key] = {value: value, at: @clock.call} }
        value
      end

      PLURALS = {
        "configmap" => "configmaps", "secret" => "secrets", "service" => "services",
        "persistentvolumeclaim" => "persistentvolumeclaims", "persistentvolume" => "persistentvolumes",
        "node" => "nodes", "serviceaccount" => "serviceaccounts", "endpointslice" => "endpointslices",
        "runtimeclass" => "runtimeclasses", "clustertrustbundle" => "clustertrustbundles"
      }.freeze

      def plural_for(resource)
        value = resource.to_s
        lowered = value.downcase
        return lowered if RESOURCES.key?(lowered)
        return PLURALS.fetch(lowered) if PLURALS.key?(lowered)

        raise ArgumentError, "unsupported node resource #{resource.inspect}"
      end

      def singular_for(resource)
        PLURALS.key(plural_for(resource)) || plural_for(resource)
      end
    end
  end
end
