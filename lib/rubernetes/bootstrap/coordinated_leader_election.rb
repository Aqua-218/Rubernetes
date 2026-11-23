# frozen_string_literal: true

require "securerandom"
require "time"
require_relative "../coordination/version"
require_relative "../controller/lease"
require_relative "../controller/store_adapter"

module Rubernetes
  module Bootstrap
    # Kubernetes v1.36.2 controlplane/controller/leaderelection. The
    # coordinator is itself lease-elected. Election state stays in the
    # candidates' ping and renewal timestamps, so a new coordinator can
    # continue an in-flight election after failover.
    class CoordinatedLeaderElection
      GATE = "CoordinatedLeaderElection"
      LOCK_NAME = "leader-election-controller"
      OLDEST = "OldestEmulationVersion"
      CANDIDATE_TTL = 30 * 60
      ELECTION_DURATION = 5
      RECONCILE_INTERVAL = 1
      LEASE = Controller::ResourceDescriptor.parse("Lease")
      CANDIDATE = Controller::ResourceDescriptor.new(group: "coordination.k8s.io", version: "v1beta1",
                                                     kind: "LeaseCandidate", resource: "leasecandidates", scope: :namespaced,
                                                     allow_unknown: true)
      SUPPORT = Controller::Support

      Candidate = Data.define(:object, :renewal, :ping) do
        def name = object.dig("metadata", "name")
        def namespace = object.dig("metadata", "namespace")
        def spec = object.fetch("spec", {})
      end

      # The control plane's loopback identity resolves the same resources and
      # passes the same update preconditions as an external client.
      class Store < Controller::StoreAdapter
        IDENTITY = {"username" => "system:apiserver", "groups" => ["system:masters"].freeze}.freeze
        ERROR_CLASSES = {409 => API::Status::Conflict, 429 => API::Status::TooManyRequests,
                         503 => API::Status::ServiceUnavailable}.freeze

        def candidates
          listing = request("GET", collection(CANDIDATE))
          listing ? listing.fetch("items") : []
        end

        def find(descriptor, name:, namespace:)
          request("GET", "#{collection(descriptor, namespace)}/#{name}")
        end

        def create(object, descriptor:)
          request("POST", collection(descriptor, object.dig("metadata", "namespace")), object)
        end

        def update(object, descriptor:, existing: nil)
          path = "#{collection(descriptor, object.dig("metadata", "namespace"))}/#{object.dig("metadata", "name")}"
          request("PUT", path, object)
        end

        def delete_candidate(candidate)
          metadata = candidate.object.fetch("metadata")
          path = "#{collection(CANDIDATE, candidate.namespace)}/#{candidate.name}"
          request("DELETE", path, {"apiVersion" => "v1", "kind" => "DeleteOptions",
                                   "preconditions" => metadata.slice("uid", "resourceVersion")})
        end

        private

        def collection(descriptor, namespace = nil)
          scope = namespace ? "/namespaces/#{namespace}" : ""
          "/apis/#{descriptor.api_version}#{scope}/#{descriptor.resource}"
        end

        def request(method, path, body = nil)
          response = store.call(method: method, path: path, identity: IDENTITY, body: body)
          return response.body if (200..299).cover?(response.status)
          return nil if response.status == 404 && %w[GET DELETE].include?(method)

          error = ERROR_CLASSES.fetch(response.status, API::Status::InternalError)
          raise error, "#{method} #{path} returned #{response.status}: #{response.body["message"]}"
        end
      end

      def initialize(api_server:, logger:, identity:, clock: -> { Time.now.utc })
        @api_server = api_server
        @logger = logger
        @clock = clock
        @store = Store.new(api_server)
        @elector = Controller::LeaseElector.new(store: @store, identity: "#{identity}_#{SecureRandom.uuid}", name: LOCK_NAME, clock: clock)
        @mutex = Mutex.new
        @condition = ConditionVariable.new
      end

      def start
        @mutex.synchronize do
          return self if @thread&.alive?

          @stopping = false
          @thread = Thread.new { run }
          @thread.name = "apiserver-coordinated-leader-election"
        end
        self
      end

      def stop
        @mutex.synchronize do
          @stopping = true
          @condition.broadcast
        end
        @thread&.join(2)
        self
      end

      private

      def run
        until @mutex.synchronize { @stopping }
          reconcile if @api_server.ready?
          @mutex.synchronize { @condition.wait(@mutex, RECONCILE_INTERVAL) unless @stopping }
        end
      ensure
        release_lock
      end

      def release_lock
        @elector.release if @elector.leader?
      rescue API::Status::Error, Controller::StoreError => error
        @logger.debug("coordination.lock.release_failed", error: error.message)
      end

      def reconcile
        @elector.step
        return unless @elector.leader?

        now = @clock.call
        candidates = @store.candidates.map do |object|
          Candidate.new(object, SUPPORT.parse_time(object.dig("spec", "renewTime")),
                        SUPPORT.parse_time(object.dig("spec", "pingTime")))
        end
        collect_expired(candidates, now)
        active = candidates.select { |candidate| candidate.renewal && candidate.renewal + CANDIDATE_TTL >= now }
        active.group_by { |candidate| [candidate.namespace, candidate.spec["leaseName"]] }.each do |(namespace, name), group|
          # LeaseCandidate validates that leaseName is present. The Lease
          # itself requires a DNS subdomain, also keeping names inside one
          # loopback API resource path segment.
          next unless name.is_a?(String) && name.match?(/\A[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\z/)

          reconcile_lease(namespace, name, group, now)
        rescue API::Status::Error, Controller::StoreError => error
          @logger.debug("coordination.lease.retry", lease: name, namespace: namespace, error: error.message)
        end
      rescue API::Status::Error, Controller::StoreError => error
        @logger.debug("coordination.reconcile_retry", error: error.message)
      end

      def collect_expired(candidates, now)
        return if @last_gc && now - @last_gc < CANDIDATE_TTL

        candidates.reject { |candidate| candidate.renewal && candidate.renewal + CANDIDATE_TTL >= now }.each do |candidate|
          @store.delete_candidate(candidate)
        rescue API::Status::Conflict
          # A renewal arrived after the list. The version precondition keeps
          # the live candidate in this election.
          next
        end
        @last_gc = now
      end

      def reconcile_lease(namespace, name, candidates, now)
        lease = @store.find(LEASE, name: name, namespace: namespace)
        return unless election_needed?(lease, candidates, now)

        acknowledged = collect_votes(candidates, now)
        return if acknowledged.empty?

        strategy = best_strategy(acknowledged)
        holder = best_candidate(acknowledged)&.name if strategy == OLDEST
        return if strategy == OLDEST && holder.nil?

        record_election(namespace, name, lease, strategy, holder, now)
      end

      def election_needed?(lease, candidates, now)
        holder = lease&.dig("spec", "holderIdentity").to_s
        return true if holder.empty? || expired?(lease, now)
        return true if candidates.any? { |candidate| candidate.renewal + (CANDIDATE_TTL / 2) < now }
        return false unless best_strategy(candidates) == OLDEST

        candidate = best_candidate(candidates)
        candidate && candidate.name != holder
      end

      def collect_votes(candidates, now)
        waiting = false
        fresh = candidates.select do |candidate|
          pending = candidate.ping && candidate.renewal < candidate.ping
          if pending && candidate.ping + ELECTION_DURATION > now
            waiting = true
            next false
          end
          next true if candidate.renewal + ELECTION_DURATION > now
          next false if pending

          object = SUPPORT.deep_copy(candidate.object)
          object.fetch("spec")["pingTime"] = now.utc.iso8601(6)
          @store.update(object, descriptor: CANDIDATE)
          waiting = true
          false
        end
        waiting ? [] : fresh
      end

      def best_strategy(candidates)
        versions = candidates.group_by { |candidate| Coordination::Version.key(candidate.spec["binaryVersion"]) || Coordination::Version::ZERO }
        top = versions.fetch(versions.keys.max)
        strategies = top.map { |candidate| candidate.spec.fetch("strategy") }.uniq
        return strategies.first if strategies.one?

        raise Controller::StoreError, "candidates with the same highest binary version disagree on the election strategy"
      end

      def best_candidate(candidates)
        candidates.filter_map do |candidate|
          emulation = Coordination::Version.key(candidate.spec["emulationVersion"])
          binary = Coordination::Version.key(candidate.spec["binaryVersion"])
          next unless emulation && binary

          creation = SUPPORT.parse_time(candidate.object.dig("metadata", "creationTimestamp")) || Time.at(0)
          [[emulation, binary, creation, candidate.name], candidate]
        end.min_by(&:first)&.last
      end

      def expired?(lease, now)
        renew = SUPPORT.parse_time(lease.dig("spec", "renewTime"))
        duration = lease.dig("spec", "leaseDurationSeconds")
        renew.nil? || duration.nil? || renew + duration < now
      end

      def record_election(namespace, name, lease, strategy, holder, now)
        if lease.nil?
          spec = {"strategy" => strategy, "renewTime" => now.utc.iso8601(6), "leaseDurationSeconds" => ELECTION_DURATION}
          spec["holderIdentity"] = holder if holder
          @store.create({"apiVersion" => LEASE.api_version, "kind" => LEASE.kind,
                         "metadata" => {"name" => name, "namespace" => namespace}, "spec" => spec}, descriptor: LEASE)
          return
        end

        updated = SUPPORT.deep_copy(lease)
        spec = (updated["spec"] ||= {})
        spec["strategy"] = strategy
        if holder && holder != spec["holderIdentity"]
          if spec["holderIdentity"].to_s.empty? || expired?(lease, now)
            spec["holderIdentity"] = holder
            spec["renewTime"] = now.utc.iso8601(6)
            spec["leaseDurationSeconds"] = ELECTION_DURATION
            spec.delete("preferredHolder")
            spec.delete("acquireTime")
          else
            spec["preferredHolder"] = holder
          end
        end
        @store.update(updated, descriptor: LEASE) unless updated == lease
      end
    end
  end
end
