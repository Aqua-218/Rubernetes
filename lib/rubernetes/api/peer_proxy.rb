# frozen_string_literal: true

require_relative "peer_transport"

module Rubernetes
  module API
    # kube-apiserver's mixed-version proxy makes routing decisions from the
    # peer's local discovery document, and only for resource requests.
    class PeerProxy
      Entry = Data.define(:endpoint, :groups, :resources, :complete)
      EXCLUSION_GRACE = 300
      SYNC_INTERVAL = 5

      def initialize(transport:, directory:, logger:, clock: -> { Time.now.utc })
        @transport = transport
        @directory = directory
        @logger = logger
        @clock = clock
        @entries = {}
        @excluded = {}
        @mutex = Mutex.new
        @refresh_mutex = Mutex.new
        @condition = ConditionVariable.new
        @stopping = false
      end

      attr_writer :metrics

      def start
        @mutex.synchronize do
          return if @thread&.alive?

          @stopping = false
          @thread = Thread.new do
            Thread.current.name = "apiserver-peer-discovery"
            loop do
              refresh
              break if @mutex.synchronize do
                @condition.wait(@mutex, SYNC_INTERVAL) unless @stopping
                @stopping
              end
            end
          end
        end
      end

      def stop
        thread = @mutex.synchronize do
          @stopping = true
          @condition.broadcast
          @thread
        end
        return unless thread

        thread.kill unless thread.join(PeerTransport::TIMEOUT)
        thread.join
      end

      def refresh
        @refresh_mutex.synchronize do
          begin
            endpoints, exclusions = @directory.snapshot
          rescue StandardError => error
            sync_error("lease_list", error)
            return
          end
          previous = @mutex.synchronize { @entries }
          entries = endpoints.filter_map do |id, endpoint|
            if endpoint.nil?
              sync_error("hostport_resolution", "endpoint is unavailable", peer: id)
              next
            end

            cached = previous[id]
            next [id, cached.with(endpoint: endpoint)] if cached&.complete && same_peer?(cached.endpoint, endpoint)

            groups, complete = fetch_groups(id, endpoint)
            matches = groups.each_with_object(Set.new) do |group, result|
              name = group.dig("metadata", "name")
              group.fetch("versions").each do |version|
                version.fetch("resources").each do |resource|
                  result.add([name, version.fetch("version"), resource.fetch("resource")])
                end
              end
            end
            [id, Entry.new(endpoint, groups, matches, complete)]
          end.to_h
          @mutex.synchronize do
            update_exclusions(exclusions)
            @entries = entries
          end
        end
      end

      def forward(request)
        attributes = request.attributes
        return unless attributes&.resource_request? && request.header(PeerTransport::PROXIED_HEADER) != "true"

        gvr = [attributes.api_group, attributes.api_version, attributes.resource]
        candidates = @mutex.synchronize do
          next [] if @excluded.key?(gvr.first(2))

          @entries.select { |_id, entry| entry.resources.include?(gvr) }.to_a
        end
        return if candidates.empty?

        labels = %w[group version resource].zip(gvr).to_h
        endpoints = candidates.filter_map do |id, entry|
          endpoint = @directory.resolve(id, entry.endpoint.holder)
          endpoint if endpoint && same_peer?(entry.endpoint, endpoint)
        end
        if endpoints.empty?
          @metrics&.increment("apiserver_peer_proxy_errors_total", labels.merge("type" => "endpoint_resolution"))
          raise Status::ServiceUnavailable.new("Error getting ip and port info of the remote server while proxying")
        end
        if request.identity.nil?
          @metrics&.increment("apiserver_peer_proxy_errors_total", labels.merge("type" => "proxy_transport"))
          raise Status::BadRequest.new("no user details present in request")
        end
        response = @transport.forward(endpoints.sample, request, request.identity)
        @metrics&.increment("apiserver_rerouted_request_total", labels.merge("code" => response.status.to_s))
        response
      rescue *PeerTransport::ERRORS => error
        @logger.warn("peer_proxy.request_failed", **labels, error: error.class.name)
        @metrics&.increment("apiserver_rerouted_request_total", labels.merge("code" => "503"))
        Response.new(status: 503, headers: {"content-type" => "text/plain; charset=utf-8"}, body: "peer API server unavailable\n")
      end

      def aggregate(local_groups)
        @mutex.synchronize do
          now = @clock.call.to_f
          peers = @entries.filter_map do |id, entry|
            [id, excluded_groups(entry.groups)] if entry.endpoint.expires > now
          end.to_h
          groups_by_server = peers.merge(@directory.identity => local_groups).sort.to_h.values
          signature = groups_by_server
          if @discovery_cache && @discovery_cache.first == signature
            @metrics&.increment("aggregator_discovery_peer_aggregated_cache_hits_total")
          else
            @metrics&.increment("aggregator_discovery_peer_aggregated_cache_misses_total")
            merged = groups_by_server.reduce { |groups, peer| merge_groups(groups, peer) }
            by_name = merged.to_h { |group| [group.dig("metadata", "name"), group] }
            order = groups_by_server.map { |groups| groups.map { |group| group.dig("metadata", "name") } }
            @discovery_cache = [signature, merge_order(order, by_name.keys).map { |name| by_name.fetch(name) }]
          end
          @discovery_cache.last
        end
      end

      private

      def same_peer?(left, right)
        left.holder == right.holder && left.host == right.host && left.port == right.port
      end

      def fetch_groups(id, endpoint)
        complete = true
        groups = %w[/api /apis].flat_map do |path|
          document = @transport.discovery(endpoint, path) do |status|
            @metrics&.increment("apiserver_rerouted_request_total", {"group" => "", "version" => "", "resource" => "", "code" => status.to_s})
          end
          document.filter_map do |group|
            next unless group.is_a?(Hash)

            name = group.dig("metadata", "name")
            next unless name.is_a?(String) && name.empty? == (path == "/api")

            versions = Array(group["versions"]).filter_map do |version|
              next unless version.is_a?(Hash) && version["version"].is_a?(String)

              resources = Array(version["resources"]).select { |resource| resource.is_a?(Hash) && resource["resource"].is_a?(String) }
              version.merge("resources" => resources)
            end
            group.merge("versions" => versions)
          end
        rescue *PeerTransport::ERRORS, JSON::ParserError, TypeError => error
          complete = false
          sync_error("fetch_discovery", error, peer: id, path: path)
          []
        end
        [groups, complete]
      end

      def sync_error(type, error, **fields)
        @metrics&.increment("apiserver_peer_discovery_sync_errors_total", {"type" => type})
        @logger.debug("peer_proxy.discovery_failed", type: type, error: error.to_s, **fields)
      end

      def update_exclusions(exclusions)
        now = @clock.call
        @excluded.transform_values! { |expires| expires || (now + EXCLUSION_GRACE) }
        @excluded.delete_if { |_, expires| expires <= now }
        exclusions.each { |gv| @excluded[gv] = nil }
      end

      def excluded_groups(groups)
        groups.filter_map do |group|
          name = group.dig("metadata", "name")
          next if name.empty?

          versions = group.fetch("versions").reject { |version| @excluded.key?([name, version.fetch("version")]) }
          group.merge("versions" => versions) unless versions.empty?
        end
      end

      def merge_groups(local, peer)
        merge_by(local, peer, ->(group) { group.dig("metadata", "name") }) do |left, right|
          versions = merge_by(left.fetch("versions"), right.fetch("versions"), ->(version) { version.fetch("version") }) do |a, b|
            resources = merge_by(a.fetch("resources"), b.fetch("resources"), ->(resource) { resource.fetch("resource") }) do |x, y|
              merge_capabilities(x, y)
            end
            a.merge("resources" => resources)
          end
          left.merge("versions" => versions)
        end
      end

      def merge_capabilities(left, right)
        return left if left == right

        verbs = (Array(left["verbs"]) | Array(right["verbs"])).sort
        subresources = (Array(left["subresources"]) + Array(right["subresources"])).to_h { |entry| [entry.fetch("subresource"), entry] }
        left.merge("verbs" => verbs).tap do |merged|
          merged["subresources"] = subresources.sort.map(&:last) unless subresources.empty?
        end
      end

      # Keep relative ordering across discovery documents when possible.
      # The upstream topological merge breaks contradictory ordering by name.
      def merge_by(left, right, key)
        return left if left == right

        records = left.to_h { |record| [key.call(record), record] }
        right.each do |record|
          name = key.call(record)
          records[name] = records.key?(name) ? yield(records.fetch(name), record) : record
        end
        order = [left, right].map { |list| list.map(&key) }
        merge_order(order, records.keys).map { |name| records.fetch(name) }
      end

      def merge_order(order, names)
        complete = order.find { |items| items.size == names.size && items.uniq.size == names.size }
        return complete if complete

        predecessors = names.to_h { |name| [name, Set.new] }
        order.each do |names|
          names.each_cons(2) { |a, b| predecessors.fetch(b).add(a) unless a == b }
        end
        ordered = []
        until predecessors.empty?
          ready = predecessors.keys.select { |name| predecessors.fetch(name).empty? }.min
          return names.sort unless ready

          ordered << ready
          predecessors.delete(ready)
          predecessors.each_value { |deps| deps.delete(ready) }
        end
        ordered
      end
    end
  end
end
