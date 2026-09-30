# frozen_string_literal: true

require_relative "../observability/metrics"
require_relative "iptables"

module Rubernetes
  module Proxy
    # pkg/proxy/metrics: what kube-proxy records around a rules sync, with
    # upstream's names, labels and buckets (declared by the v1.36.2
    # inventory).  The proxy engine, ConntrackReconciler and the iptables
    # backend call these.  metrics.RegisterMetrics(mode): the iptables
    # families exist only in iptables mode and the nftables sync-failure
    # counter only in nftables mode.
    class Metrics
      FAMILIES = %w[IPv4 IPv6].freeze
      IPTABLES_FAMILIES = %w[kubeproxy_sync_proxy_rules_iptables_last kubeproxy_sync_proxy_rules_iptables_total
                             kubeproxy_sync_proxy_rules_iptables_restore_failures_total
                             kubeproxy_sync_proxy_rules_iptables_partial_restore_failures_total].freeze
      # Custom collectors over the nfacct counters (iptables mode only).
      IPTABLES_NFACCT_FAMILIES = {
        "kubeproxy_iptables_ct_state_invalid_dropped_packets_total" => Iptables::CT_STATE_INVALID_COUNTER,
        "kubeproxy_iptables_localhost_nodeports_accepted_packets_total" => Iptables::LOCALHOST_NODEPORTS_COUNTER
      }.freeze
      NFTABLES_FAMILIES = %w[kubeproxy_sync_proxy_rules_nftables_sync_failures_total kubeproxy_sync_proxy_rules_nftables_cleanup_failures_total].freeze
      # EndpointSlice annotation the network programming latency starts from.
      LAST_CHANGE_TRIGGER_TIME = "endpoints.kubernetes.io/last-change-trigger-time"

      attr_reader :registry

      attr_reader :mode
      # ->() { {counter_name => [packets, bytes]} }: the iptables backend's nfacct reader.
      attr_accessor :nfacct_counters

      def initialize(registry: nil, clock: -> { Time.now.to_f }, mode: :nftables)
        @registry = registry || Observability::Metrics.new(apiserver: false, component: "kube-proxy")
        @clock = clock
        @mode = mode.to_s.downcase.to_sym
        @nfacct_counters = nil
        register_mode_families
        @mutex = Mutex.new
        @service_changes_pending = 0
        @endpoint_changes_pending = 0
        @trigger_times = []
        @last_queued = {}
        @last_synced = {}
        @no_local_endpoints = Hash.new(0)
        @registry.add_collector { |registry| collect(registry) }
      end

      # -- change tracking (ServiceChangeTracker / EndpointsChangeTracker) --

      def service_changed
        @mutex.synchronize { @service_changes_pending += 1 }
        increment("kubeproxy_sync_proxy_rules_service_changes_total")
      end

      # +trigger_time+: the slice's last-change-trigger-time annotation, a
      # Time, for kubeproxy_network_programming_duration_seconds.
      def endpoint_changed(trigger_time: nil)
        @mutex.synchronize do
          @endpoint_changes_pending += 1
          @trigger_times << trigger_time.to_f if trigger_time
        end
        increment("kubeproxy_sync_proxy_rules_endpoint_changes_total")
      end

      # A sync was requested (syncRunner.Run): the last queued timestamp.
      def sync_queued(families = FAMILIES)
        now = @clock.call
        @mutex.synchronize { families.each { |family| @last_queued[family] = now } }
        families.each { |family| set("kubeproxy_sync_proxy_rules_last_queued_timestamp_seconds", now, {"ip_family" => family}) }
      end

      # -- one syncProxyRules ------------------------------------------------

      # +full+: a full resync (the first sync, or a backend catch-up) rather
      # than a partial (diff) one.
      def synced(seconds, families: FAMILIES, full: false)
        now = @clock.call
        pending_triggers = @mutex.synchronize do
          @service_changes_pending = 0
          @endpoint_changes_pending = 0
          families.each { |family| @last_synced[family] = now }
          @trigger_times.shift(@trigger_times.length)
        end
        families.each do |family|
          labels = {"ip_family" => family}
          observe("kubeproxy_sync_proxy_rules_duration_seconds", seconds, labels)
          observe(full ? "kubeproxy_sync_full_proxy_rules_duration_seconds" : "kubeproxy_sync_partial_proxy_rules_duration_seconds", seconds, labels)
          set("kubeproxy_sync_proxy_rules_last_timestamp_seconds", now, labels)
          pending_triggers.each do |trigger|
            latency = now - trigger
            observe("kubeproxy_network_programming_duration_seconds", latency, labels) if latency >= 0
          end
        end
      end

      def sync_failed(families: FAMILIES)
        families.each { |family| increment("kubeproxy_sync_proxy_rules_nftables_sync_failures_total", {"ip_family" => family}) }
      end

      def cleanup_failed(families: FAMILIES)
        families.each { |family| increment("kubeproxy_sync_proxy_rules_nftables_cleanup_failures_total", {"ip_family" => family}) }
      end

      # kubeproxy_sync_proxy_rules_no_local_endpoints_total{ip_family,
      # traffic_policy}: Services with a Local policy and no local endpoint,
      # recounted each sync.
      def no_local_endpoints(counts)
        @mutex.synchronize do
          @no_local_endpoints = Hash.new(0)
          counts.each { |(family, policy), count| @no_local_endpoints[[family, policy]] = count }
        end
      end

      # -- the proxy's own health server -----------------------------------------

      def healthz(code)
        increment("kubeproxy_proxy_healthz_total", {"code" => code.to_s})
      end

      def livez(code)
        increment("kubeproxy_proxy_livez_total", {"code" => code.to_s})
      end

      # proxier_health.go: healthy when the last sync is not older than the
      # last queued sync plus the timeout (2 x the max sync period, 60s).
      HEALTH_TIMEOUT_SECONDS = 60.0

      def healthy?(now = @clock.call)
        @mutex.synchronize do
          FAMILIES.all? do |family|
            queued = @last_queued[family]
            synced = @last_synced[family]
            next true if queued.nil?
            next false if synced.nil? && now - queued > HEALTH_TIMEOUT_SECONDS

            synced.nil? || synced >= queued || now - queued <= HEALTH_TIMEOUT_SECONDS
          end
        end
      end

      def last_synced(family) = @mutex.synchronize { @last_synced[family] }

      # -- iptables proxier (pkg/proxy/iptables) --

      # One syncProxyRules: rules written this sync and owned in total, per table.
      def iptables_synced(family, filter_last:, filter_total:, nat_last:, nat_total:)
        set("kubeproxy_sync_proxy_rules_iptables_last", filter_last, {"ip_family" => family.to_s, "table" => "filter"})
        set("kubeproxy_sync_proxy_rules_iptables_last", nat_last, {"ip_family" => family.to_s, "table" => "nat"})
        set("kubeproxy_sync_proxy_rules_iptables_total", filter_total, {"ip_family" => family.to_s, "table" => "filter"})
        set("kubeproxy_sync_proxy_rules_iptables_total", nat_total, {"ip_family" => family.to_s, "table" => "nat"})
      end

      # iptables-restore failed (a partial sync also counts the partial family).
      def iptables_restore_failed(family, partial: false)
        increment("kubeproxy_sync_proxy_rules_iptables_restore_failures_total", {"ip_family" => family.to_s})
        increment("kubeproxy_sync_proxy_rules_iptables_partial_restore_failures_total", {"ip_family" => family.to_s}) if partial
      end

      def render(now: nil) = @registry.render(now: now)

      private

      def register_mode_families
        if @mode == :iptables
          NFTABLES_FAMILIES.each { |name| @registry.unregister(name) }
          IPTABLES_NFACCT_FAMILIES.each_key do |name|
            @registry.register(name, type: :counter) unless @registry.registered?(name)
          end
        else
          (IPTABLES_FAMILIES + IPTABLES_NFACCT_FAMILIES.keys).each { |name| @registry.unregister(name) }
        end
      end

      def collect(registry)
        collect_nfacct(registry) if @mode == :iptables && @nfacct_counters
        services, endpoints, no_local = @mutex.synchronize { [@service_changes_pending, @endpoint_changes_pending, @no_local_endpoints.dup] }
        registry.set("kubeproxy_sync_proxy_rules_service_changes_pending", services)
        registry.set("kubeproxy_sync_proxy_rules_endpoint_changes_pending", endpoints)
        registry.reset("kubeproxy_sync_proxy_rules_no_local_endpoints_total")
        FAMILIES.each do |family|
          %w[internal external].each do |policy|
            registry.set("kubeproxy_sync_proxy_rules_no_local_endpoints_total", no_local[[family, policy]], {"ip_family" => family, "traffic_policy" => policy})
          end
        end
      end

      # nfacct counter values as the two Custom counters (a missing counter
      # publishes nothing, as upstream's collector does on a failed Get).
      def collect_nfacct(registry)
        counters = @nfacct_counters.call
        IPTABLES_NFACCT_FAMILIES.each do |name, counter|
          packets = counters[counter]&.first
          registry.set(name, packets) if packets
        end
      rescue StandardError
        nil
      end

      public

      # pkg/proxy/conntrack.CleanStaleEntries, one family: how long the
      # reconcile took and how many stale UDP flows it deleted.
      def conntrack_reconciled(family, seconds, deleted)
        labels = {"ip_family" => family.to_s}
        observe("kubeproxy_conntrack_reconciler_sync_duration_seconds", seconds, labels)
        @registry.increment("kubeproxy_conntrack_reconciler_deleted_entries_total", labels, by: deleted.to_i) if deleted.to_i.positive?
      rescue StandardError
        nil
      end

      private

      def observe(name, value, labels = {})
        @registry.observe(name, value, labels)
      rescue StandardError
        nil
      end

      def increment(name, labels = {})
        @registry.increment(name, labels)
      rescue StandardError
        nil
      end

      def set(name, value, labels = {})
        @registry.set(name, value, labels)
      rescue StandardError
        nil
      end
    end
  end
end
