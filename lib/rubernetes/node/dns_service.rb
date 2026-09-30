# frozen_string_literal: true

require_relative "../network/dns"
require_relative "../network/dns_server"

module Rubernetes
  module Node
    # The node-local cluster DNS server (spec §5.9.7): the Network::DNS
    # resolver fed by Service/EndpointSlice/Pod watches, served on the Pod
    # bridge's node address so every Pod's /etc/resolv.conf points at it.
    # Cluster-external names are forwarded to the node's own upstreams.
    class DNSService
      class Error < StandardError; end

      WATCHED = [
        ["services", "v1"],
        ["endpointslices", "discovery.k8s.io/v1"],
        ["pods", "v1"]
      ].freeze
      RECONNECT_DELAY = 2.0

      attr_reader :resolver, :server, :bind_addresses, :port

      def initialize(client:, bind_addresses:, port: 53, cluster_domain: "cluster.local", upstreams: [],
                     resolv_conf: "/etc/resolv.conf", logger: nil, positive_ttl: 5, negative_ttl: 5)
        raise ArgumentError, "client is required" unless client
        raise ArgumentError, "at least one DNS bind address is required" if Array(bind_addresses).empty?

        @client = client
        @bind_addresses = Array(bind_addresses).map(&:to_s).freeze
        @port = Integer(port)
        @logger = logger
        forwarders = Array(upstreams).map(&:to_s).reject(&:empty?)
        forwarders = host_nameservers(resolv_conf) if forwarders.empty?
        forwarders = forwarders.reject { |server| server.start_with?("127.") || server == "::1" }
        @resolver = Network::DNS::Resolver.new(domain: cluster_domain, cluster_ip: @bind_addresses.first,
                                               upstreams: forwarders, positive_ttl: positive_ttl, negative_ttl: negative_ttl,
                                               upstream_adapter: Network::DNS::UpstreamClient.new)
        @server = Network::DNS::Server.new(resolver: @resolver, bind_addresses: @bind_addresses, port: @port,
                                           upstream_client: Network::DNS::UpstreamClient.new, logger: logger)
        @threads = []
        @stop = false
        @mutex = Mutex.new
      end

      def start
        @mutex.synchronize do
          raise Error, "DNS service is already running" if @threads.any?(&:alive?)

          @stop = false
          @server.start
          @threads = WATCHED.map do |resource, api_version|
            Thread.new { watch_loop(resource, api_version) }
          end
        end
        self
      end

      def stop
        @mutex.synchronize { @stop = true }
        @server.stop if @server.respond_to?(:stop)
        @threads.each { |thread| thread.join(5) }
        @threads = []
        self
      end

      def running?
        @server.running?
      end

      def endpoints
        @server.endpoints
      end

      private

      # List then watch, forever; every object becomes a resolver record.
      def watch_loop(resource, api_version)
        until stopped?
          begin
            resource_version = initial_list(resource, api_version)
            watch(resource, api_version, resource_version)
          rescue StandardError => error
            # A resolver that stopped following the API answers stale records
            # for every new Service; that is a warning, not a debug line.
            @logger&.warn("dns.watch_error", resource: resource, error: error.class.name, message: error.message.to_s[0, 300])
            sleep(RECONNECT_DELAY)
          end
        end
      end

      def initial_list(resource, api_version)
        response = @client.get(resource, api_version: api_version, namespace: :all)
        body = response.respond_to?(:json) ? response.json : response
        body = body.to_h if body.respond_to?(:to_h) && !body.is_a?(Hash)
        items = Array(body["items"])
        kind = body["kind"].to_s.sub(/List\z/, "")
        items.each do |item|
          object = item.merge("kind" => item["kind"] || kind)
          consume_object("ADDED", object, resource)
        end
        body.dig("metadata", "resourceVersion")
      end

      def watch(resource, api_version, resource_version)
        query = {"allowWatchBookmarks" => "true"}
        query["resourceVersion"] = resource_version if resource_version
        @client.watch_each(resource, api_version: api_version, namespace: :all, query: query,
                                     reconnect: true) do |event|
          break if stopped?

          type = event["type"].to_s
          next if type == "BOOKMARK"
          raise Error, "watch expired" if type == "ERROR"

          object = event["object"]
          next unless object.is_a?(Hash)

          consume_object(type, object, resource)
        end
      end

      # One object the resolver refuses (a slice with a port 0, a malformed
      # address) is logged and skipped; aborting the list-and-watch on it
      # left every later Service unresolvable.
      def consume_object(type, object, resource)
        @resolver.watch("type" => type, "object" => object)
      rescue Network::DNSQueryError, ArgumentError => error
        @logger&.warn("dns.object_rejected", resource: resource, type: type,
                                             object: "#{object.dig("metadata", "namespace")}/#{object.dig("metadata", "name")}",
                                             message: error.message.to_s[0, 200])
      end

      def stopped?
        @mutex.synchronize { @stop }
      end

      # The node's real upstream resolvers.  A systemd-resolved stub file
      # (nameserver 127.0.0.53) names nothing a Pod can reach, so the
      # resolved-managed file behind it is read instead, as kubelet's
      # --resolv-conf guidance recommends.
      RESOLVED_UPSTREAM_FILE = "/run/systemd/resolve/resolv.conf"

      def host_nameservers(path)
        servers = read_nameservers(path)
        return servers unless servers.empty? || servers.all? { |server| server.start_with?("127.") || server == "::1" }

        fallback = read_nameservers(RESOLVED_UPSTREAM_FILE)
        fallback.empty? ? servers : fallback
      end

      def read_nameservers(path)
        return [] unless path && File.file?(path)

        File.foreach(path).filter_map do |line|
          fields = line.sub(/[#;].*/, "").split
          fields[1] if fields.first == "nameserver" && fields[1]
        end
      rescue SystemCallError
        []
      end
    end
  end
end
