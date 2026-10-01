# frozen_string_literal: true

require "json"
require_relative "../version"

module Rubernetes
  module Observability
    # The Prometheus text exposition a Kubernetes component serves on
    # `/metrics`: counters, gauges and histograms with the names and label
    # sets the upstream components publish, so existing dashboards and the
    # `MetricsGrabber` e2e helper read them unchanged.
    #
    # Registration is explicit and the registry is safe for concurrent
    # observation from request threads.
    class Metrics
      CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

      # apiserver_request_duration_seconds, upstream's bucket boundaries.
      REQUEST_DURATION_BUCKETS = [0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3,
                                  4, 5, 6, 8, 10, 15, 20, 30, 45, 60].freeze

      # apiserver_request_sli_duration_seconds (the _slo_ twin, ALPHA and
      # deprecated in 1.27, is hidden in 1.36).
      SLO_DURATION_BUCKETS = [0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 45, 60].freeze
      # apiserver_watch_events_sizes: ExponentialBuckets(1024, 2, 8).
      WATCH_EVENT_SIZE_BUCKETS = Array.new(8) { |index| 1024 * (2**index) }.freeze
      # How long a storage object count stays current (upstream refreshes
      # its storage stats about once a minute).
      STORAGE_OBJECTS_REFRESH = 60.0

      # +labels+: the declared label names -- [] for a plain metric, which
      # client_golang exposes as 0 before anything is observed, and a vector
      # otherwise, which shows nothing until a series exists.  nil when the
      # declaration is not known.
      Metric = Struct.new(:name, :type, :help, :buckets, :values, :labels, keyword_init: true)

      # prometheus.DefBuckets.
      DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10].freeze
      UPSTREAM_PATH = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/metrics.json", __dir__)
      UPSTREAM_TYPES = {"Counter" => :counter, "Gauge" => :gauge, "Histogram" => :histogram,
                        "TimingRatioHistogram" => :histogram, "Summary" => :summary}.freeze
      # client_golang summaries: the quantiles component-base declares and
      # the default sliding window (MaxAge 10 minutes).
      SUMMARY_OBJECTIVES = [0.5, 0.9, 0.99].freeze
      SUMMARY_MAX_AGE_SECONDS = 600.0
      SUMMARY_MAX_SAMPLES = 20_000

      # The v1.36.2 metric inventory (tools/schema/import_kubernetes_metrics.rb):
      # name => type, help, stability, labels, buckets, components.
      def self.upstream
        @upstream ||= begin
          metrics = JSON.parse(File.read(UPSTREAM_PATH)).fetch("metrics")
          # Bucket bounds are floats (an inventory imported before the
          # importer converted them held "1e-05" as a string).
          metrics.each_value do |entry|
            next unless entry["buckets"]

            entry["buckets"] = entry["buckets"].map do |bound|
              bound.is_a?(String) ? Float(bound) : bound
            end
          end
          metrics.freeze
        rescue SystemCallError, JSON::ParserError
          {}.freeze
        end
      end

      # component-base's annotated help: "[STABILITY] (Deprecated since
      # X) help".
      def self.annotated_help(entry)
        help = entry["help"].to_s
        help = "(Deprecated since #{entry["deprecatedVersion"]}) #{help}" if entry["deprecatedVersion"]
        "[#{entry["stabilityLevel"]}] #{help}"
      end

      # +apiserver+: register the API server's series (a kubelet, scheduler
      # or controller-manager serves only its own and the process collector).
      # +component+ ("kube-apiserver", "kubelet", "kube-controller-manager",
      # ...): register that component's inventory and the families
      # component-base gives every binary (build info, feature gates,
      # registered metrics).  +feature_gates+ overrides the gates' defaults.
      def initialize(apiserver: true, process: true, component: nil, feature_gates: {})
        @mutex = Mutex.new
        @metrics = {}
        @hidden_names = {}
        @unimplemented_reasons = {}
        @storage_source = nil
        @storage_counted_at = nil
        @collectors = []
        @process = process
        register_apiserver_defaults if apiserver
        register_process_defaults if process
        component ||= "kube-apiserver" if apiserver
        return unless component

        register_upstream(component)
        register_component_base(feature_gates)
        register_compat_version if COMPAT_VERSION_COMPONENTS.include?(component)
      end

      # ComponentGlobalsRegistry.AddMetrics runs in kube-apiserver, the
      # scheduler and the controller manager (kubelet and kube-proxy only add
      # their feature gates): the "kube" component's binary, emulation and
      # minimum compatibility versions.
      COMPAT_VERSION_COMPONENTS = %w[kube-apiserver kube-controller-manager kube-scheduler].freeze

      def register_compat_version
        register("version_info", type: :gauge) unless registered?("version_info")
        set("version_info", 1, {"component" => "kube", "binary" => BUILD_INFO["git_version"].delete_prefix("v"),
                                "emulation" => "#{BUILD_INFO["major"]}.#{BUILD_INFO["minor"]}",
                                "min_compat" => "#{BUILD_INFO["major"]}.#{BUILD_INFO["minor"].to_i - 1}"})
      end

      FEATURES_PATH = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/features.json", __dir__)
      BUILD_INFO = {"major" => "1", "minor" => "36", "git_version" => "v1.36.2", "git_commit" => "", "git_tree_state" => "clean",
                    "build_date" => "", "go_version" => "", "compiler" => "ruby", "platform" => Rubernetes.go_platform}.freeze

      def self.feature_gates
        @feature_gates ||= begin
          JSON.parse(File.read(FEATURES_PATH)).fetch("gates").freeze
        rescue SystemCallError, JSON::ParserError, KeyError
          {}.freeze
        end
      end

      # featuregate AddMetrics's stage label: the prerelease as featuregate
      # spells it, "" for GA.
      def self.feature_stage(stage)
        value = stage.to_s.upcase
        value == "GA" ? "" : value
      end

      # component-base: kubernetes_build_info (version.Get()), one
      # kubernetes_feature_enabled per known gate, and at scrape time
      # registered_metrics_total by stability level.
      def register_component_base(overrides = {})
        set("kubernetes_build_info", 1, BUILD_INFO)
        # --disabled-metrics: no metric is disabled by flag here, and the
        # counter component-base keeps for that reads 0 like upstream's.
        register("disabled_metrics_total", type: :counter) unless registered?("disabled_metrics_total")
        set("disabled_metrics_total", 0)
        self.class.feature_gates.each do |name, gate|
          enabled = overrides.key?(name) ? overrides[name] == true : gate["default"] == true
          set("kubernetes_feature_enabled", enabled ? 1 : 0, {"name" => name, "stage" => self.class.feature_stage(gate["stage"])})
        end
        add_collector do |registry|
          counts = Hash.new(0)
          registry.registered_names.each do |name|
            entry = self.class.upstream[name]
            next unless entry

            counts[[entry["stabilityLevel"].to_s, entry["deprecatedVersion"].to_s]] += 1
          end
          counts.each do |(level, deprecated), count|
            registry.set("registered_metrics_total", count, {"stability_level" => level, "deprecated_version" => deprecated})
          end
        end
        self
      end

      def registered_names = @mutex.synchronize { @metrics.keys }

      # The families that have at least one series.
      def names_with_values
        @mutex.synchronize { @metrics.values.reject { |metric| metric.values.empty? }.map(&:name) }
      end

      # component-base's legacyregistry: the families client-go (rest_client_*)
      # and the workqueues (workqueue_*) record process-wide, which every
      # component's /metrics serves alongside its own.
      def self.global
        @global_mutex ||= Mutex.new
        @global_mutex.synchronize { @global ||= new(apiserver: false, process: false) }
      end

      # Drops the process-wide registry so the next `global` starts empty.
      # For tests that assert what one component serves: in a real process
      # only that component's code records here, in a test process every
      # earlier test did.
      def self.reset_global!
        @global_mutex ||= Mutex.new
        @global_mutex.synchronize { @global = nil }
      end

      # +source+ answers [[group, resource, count]] for every stored
      # resource; it is asked at scrape time, at most once a refresh period.
      attr_writer :storage_source

      # A block run at every scrape (gauges read from live state).
      def add_collector(&block)
        @mutex.synchronize { @collectors << block }
        self
      end

      # A metric upstream declares takes its annotated help, label names and
      # buckets from the inventory unless given here.
      def register(name, type:, help: nil, buckets: nil, labels: nil)
        entry = self.class.upstream[name]
        # A hidden metric is not registered; hidden_metrics_total counts it.
        if entry && self.class.hidden?(entry)
          @mutex.synchronize { @hidden_names[name] = true }
          set("hidden_metrics_total", @hidden_names.length)
          return self
        end
        if entry
          help = self.class.annotated_help(entry)
          labels ||= entry["labels"]
          buckets ||= entry["buckets"]
        end
        buckets ||= DEFAULT_BUCKETS if type == :histogram
        @mutex.synchronize do
          @metrics[name] ||= Metric.new(name: name, type: type, help: help.to_s, buckets: buckets, values: {},
                                        labels: labels&.map(&:to_s)&.freeze)
        end
        self
      end

      # Upstream metrics whose feature Rubernetes does not implement, by
      # component: left unregistered (a series that could only ever read 0
      # would claim a measurement that is not taking place), with the reason
      # tools/differential/metrics_inventory_differential.rb reports.
      no_list_to_log = "every LIST is served by the apiserver's local replica (apiserver_cache_list_*); none reaches the raft log"
      no_ring = "no per-resource watch cache ring: one shared MVCC history, sized by revisions and age"
      no_exec_plugins = "exec credential plugins are refused by the kubeconfig loader (Kubeconfig::UnsupportedCredentialError)"
      no_stream_translation = "exec, attach and port-forward websocket requests are served natively by the subresource bridge: nothing is translated to " \
                              "SPDY (no StreamTranslator) and no SPDY is tunneled over websocket (no StreamTunnel)"
      no_peer_proxy = "no UnknownVersionInteroperabilityProxy / peer aggregated discovery: every replica serves the same API set from the shared raft log, " \
                      "so no request is rerouted to a peer and no peer discovery is fetched"
      no_delegation = "this is the kube-apiserver itself: delegated authn/authz (an aggregated server asking the kube-apiserver) is not a role it plays"
      no_declarative = "declarative validation (DeclarativeValidation / +k8s: validation tags) is not implemented; every rule is hand-written in " \
                       "Schema::KubernetesValidator"
      windows_only = "Windows HostProcess containers do not exist on Linux"
      UNIMPLEMENTED = {
        "kube-apiserver" => {
          "apiserver_delegated_authn_request_duration_seconds" => no_delegation,
          "apiserver_delegated_authn_request_total" => no_delegation,
          "apiserver_delegated_authz_request_duration_seconds" => no_delegation,
          "apiserver_delegated_authz_request_total" => no_delegation,
          "apiserver_validation_declarative_validation_mismatch_total" => no_declarative,
          "apiserver_validation_declarative_validation_panic_total" => no_declarative,
          "apiserver_validation_declarative_validation_panics_total" => no_declarative,
          "apiserver_validation_declarative_validation_parity_discrepancies_total" => no_declarative,
          "apiserver_stream_translator_requests_total" => no_stream_translation,
          "apiserver_stream_tunnel_requests_total" => no_stream_translation,
          "apiserver_storage_decode_errors_total" => "stored objects live decoded in the replica; a record that fails to decode is WAL or snapshot " \
                                                     "corruption, fatal at recovery, never a per-resource read error",
          "apiserver_storage_consistency_checks_total" => "no watch cache consistency checker: the local replica is the raft state machine itself, applied " \
                                                          "in log order, so there is no second store to compare it with",
          "aggregator_discovery_nopeer_requests_total" => no_peer_proxy,
          "aggregator_discovery_peer_aggregated_cache_hits_total" => no_peer_proxy,
          "aggregator_discovery_peer_aggregated_cache_misses_total" => no_peer_proxy,
          "apiserver_peer_discovery_sync_errors_total" => no_peer_proxy,
          "apiserver_peer_proxy_errors_total" => no_peer_proxy,
          "apiserver_rerouted_request_total" => no_peer_proxy,
          "etcd_lease_object_counts" => "no etcd leases: Events and other TTL'd objects expire through the raft store's own TTL index, not through attached " \
                                        "etcd leases",
          "apiserver_storage_list_total" => no_list_to_log,
          "apiserver_storage_list_fetched_objects_total" => no_list_to_log,
          "apiserver_storage_list_evaluated_objects_total" => no_list_to_log,
          "apiserver_storage_list_returned_objects_total" => no_list_to_log,
          "watch_cache_capacity" => no_ring,
          "watch_cache_capacity_increase_total" => no_ring,
          "watch_cache_capacity_decrease_total" => no_ring,
          "apiserver_watch_cache_initializations_total" => "the local replica is built once for all resources, never initialized per resource"
        }.freeze,
        "kube-controller-manager" => {}.freeze,
        "kube-scheduler" => {}.freeze,
        "kubelet" => {
          "kubelet_started_host_process_containers_total" => windows_only,
          "kubelet_started_host_process_containers_errors_total" => windows_only
        }.freeze
      }.freeze

      # client-go families every component would serve but that measure
      # machinery Rubernetes' client does not have.
      SHARED_UNIMPLEMENTED = {
        "rest_client_exec_plugin_call_total" => no_exec_plugins,
        "rest_client_exec_plugin_certificate_rotation_age" => no_exec_plugins,
        "rest_client_exec_plugin_policy_call_total" => no_exec_plugins,
        "rest_client_exec_plugin_ttl_seconds" => no_exec_plugins,
        "rest_client_rate_limiter_duration_seconds" => "no client-side rate limiter: the client has no QPS/burst token bucket, requests are never delayed " \
                                                       "before sending"
      }.freeze

      # Every metric the inventory lists for +component+ ("kube-apiserver",
      # "kubelet", "kube-controller-manager", ...) that is not registered
      # yet; custom collectors and summaries are left to their collectors.
      # Plain (label-less) families client-go registers unconditionally, so
      # every upstream component shows them even when the feature behind
      # them never runs: kept in the exposition for parity, listed as
      # unimplemented for the inventory.  The exec plugin TTL gauge starts
      # at +Inf upstream ("no credentials with an expiry").
      ALWAYS_PRESENT_EMPTY = {
        "rest_client_exec_plugin_certificate_rotation_age" => nil,
        "rest_client_exec_plugin_ttl_seconds" => Float::INFINITY
      }.freeze

      def register_upstream(component, endpoint: "/metrics")
        unimplemented = SHARED_UNIMPLEMENTED.merge(UNIMPLEMENTED.fetch(component, {}))
        self.class.upstream.each do |name, entry|
          next unless entry["components"].include?(component)
          next unless Array(entry.dig("endpoints", component)).include?(endpoint)

          if ALWAYS_PRESENT_EMPTY.key?(name)
            type = UPSTREAM_TYPES[entry["type"]]
            next unless type && !@mutex.synchronize { @metrics.key?(name) }

            register(name, type: type)
            initial = ALWAYS_PRESENT_EMPTY[name]
            set(name, initial) if initial
            next
          end
          type = UPSTREAM_TYPES[entry["type"]]
          if unimplemented.key?(name)
            register_unimplemented(component, name, entry, unimplemented[name], type)
            next
          end
          next unless type
          next if @mutex.synchronize { @metrics.key?(name) }

          register(name, type: type)
        end
        set("hidden_metrics_total", @hidden_names.length) unless @hidden_names.empty?
        self
      end

      # A family whose feature Rubernetes does not have is still declared, so
      # a dashboard built for upstream finds the series name: its HELP says
      # why it never moves, and the reason is logged once at registration
      # (Metrics.logger, set by the bootstrap) as metrics.unimplemented.
      def register_unimplemented(component, name, entry, reason, type)
        return if @mutex.synchronize { @metrics.key?(name) }

        type ||= name.end_with?("_total") ? :counter : :gauge
        register(name, type: type)
        @mutex.synchronize do
          @metrics[name].help = "#{self.class.annotated_help(entry)} (not implemented in Rubernetes, always empty: #{reason})"
          @unimplemented_reasons[name] = reason
        end
        # debug: --check-config shares stdout between the log and its JSON report.
        logger = self.class.logger
        logger.debug("metrics.unimplemented", component: component, metric: name, reason: reason) if logger.respond_to?(:debug)
        self
      end

      # {metric name => reason} for the families register_unimplemented declared.
      def unimplemented_reasons = @mutex.synchronize { @unimplemented_reasons.dup }

      class << self
        # The process logger unimplemented registrations are reported to.
        attr_accessor :logger
      end

      # x509metrics: a serving certificate with no Subject Alternative Name
      # extension, and one signed with SHA-1 (the legacy checks the
      # aggregator and webhook clients count).
      def self.certificate_has_san?(certificate)
        certificate.extensions.any? { |extension| extension.oid == "subjectAltName" }
      end

      def self.certificate_sha1?(certificate)
        certificate.signature_algorithm.to_s.match?(/sha1/i)
      end

      # component-base shouldHide: a deprecated metric is served for its
      # stability level's deprecation period (STABLE 3 minors, BETA 1,
      # ALPHA 0) after its deprecated version and hidden from then on --
      # an ALPHA metric deprecated in this release is already hidden.
      DEPRECATION_PERIOD_MINORS = {"STABLE" => 3, "BETA" => 1}.freeze

      def self.hidden?(entry)
        deprecated = entry["deprecatedVersion"]
        return false unless deprecated

        major, minor = deprecated.to_s.split(".").map(&:to_i)
        current_major = BUILD_INFO["major"].to_i
        current_minor = BUILD_INFO["minor"].to_i
        return major < current_major unless major == current_major

        minor + DEPRECATION_PERIOD_MINORS.fetch(entry["stabilityLevel"].to_s, 0) <= current_minor
      end

      def registered?(name) = @mutex.synchronize { @metrics.key?(name) }

      def increment(name, labels = {}, by: 1)
        observe_value(name, labels) { |current| current.to_f + by }
      end

      # A family the component does not register in this configuration.
      def unregister(name)
        @mutex.synchronize { @metrics.delete(name) }
        self
      end

      # GaugeVec.Reset: every series of +name+ dropped.
      def reset(name)
        @mutex.synchronize { @metrics[name]&.values&.clear }
        self
      end

      # Drops one labelled series (a collector's stale label set).
      def delete(name, labels = {})
        @mutex.synchronize do
          metric = @metrics[name]
          metric&.values&.delete(label_key(labels))
        end
        self
      end

      # A series created and never observed (WithLabelValues without Set or
      # Observe): it is exposed with zero counts.
      def touch(name, labels = {})
        @mutex.synchronize do
          metric = @metrics[name]
          return self unless metric

          key = label_key(labels)
          metric.values[key] ||= metric.type == :histogram ? {buckets: Hash.new(0), sum: 0.0, count: 0} : 0
        end
        self
      end

      def set(name, value, labels = {})
        observe_value(name, labels) { value.to_f }
      end

      # A histogram observation updates the bucket counts, the sum and count.
      def observe(name, value, labels = {})
        @mutex.synchronize do
          metric = @metrics[name]
          return self unless metric && %i[histogram summary].include?(metric.type)

          key = label_key(labels)
          if metric.type == :summary
            entry = metric.values[key] ||= {samples: [], sum: 0.0, count: 0}
            entry[:sum] += value.to_f
            entry[:count] += 1
            entry[:samples] << [Process.clock_gettime(Process::CLOCK_MONOTONIC), value.to_f]
            entry[:samples].shift(entry[:samples].length - SUMMARY_MAX_SAMPLES) if entry[:samples].length > SUMMARY_MAX_SAMPLES
            return self
          end
          entry = metric.values[key] ||= {buckets: Hash.new(0), sum: 0.0, count: 0}
          entry[:sum] += value.to_f
          entry[:count] += 1
          metric.buckets.each { |bound| entry[:buckets][bound] += 1 if value.to_f <= bound }
        end
        self
      end

      # A weighted histogram observation (component-base prometheusextension):
      # +weight+ is added to the value's bucket and the count, weight x value
      # to the sum.
      def observe_weighted(name, value, weight, labels = {})
        @mutex.synchronize do
          metric = @metrics[name]
          return self unless metric && metric.type == :histogram

          entry = metric.values[label_key(labels)] ||= {buckets: Hash.new(0), sum: 0.0, count: 0}
          entry[:sum] += value.to_f * weight
          entry[:count] += weight
          metric.buckets.each { |bound| entry[:buckets][bound] += weight if value.to_f <= bound }
        end
        self
      end

      # apiserver/pkg/util/flowcontrol/metrics TimingRatioHistogram: a
      # numerator and a denominator whose ratio is integrated over time --
      # every nanosecond the ratio holds weighs one in its bucket.  The
      # series exists from creation (the time until the first change is
      # observed at the next scrape).
      class RatioGauge
        def initialize(registry, name, labels, numerator, denominator, clock)
          @registry = registry
          @name = name
          @labels = labels
          @numerator = numerator.to_f
          @denominator = denominator.to_f
          @clock = clock
          @last = clock.call
          @mutex = Mutex.new
        end

        def add(delta) = update { @numerator += delta }
        def set(value) = update { @numerator = value.to_f }
        def set_denominator(value) = update { @denominator = value.to_f }
        def flush = update { nil }

        private

        def update
          @mutex.synchronize do
            now = @clock.call
            nanoseconds = ((now - @last) * 1e9).to_i
            if nanoseconds.positive?
              @registry.observe_weighted(@name, @numerator / @denominator, nanoseconds, @labels)
              @last = now
            end
            yield
          end
          self
        end
      end

      MONOTONIC = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

      # The RatioGauge for +name+ and +labels+ (NewForLabelValuesSafe),
      # created with the initial numerator and denominator.
      def ratio_gauge(name, labels, numerator: 0, denominator: 1, clock: MONOTONIC)
        key = [name, labels]
        @mutex.synchronize do
          (@ratio_gauges ||= {})[key] ||= RatioGauge.new(self, name, labels, numerator, denominator, clock)
        end
      end

      # Prometheus text format, metrics in registration order.
      def render(now: nil)
        return render_own if equal?(self.class.global)

        # A family this registry holds but has nothing for is the shared
        # registry's to show when it has values (client-go and the shared
        # collectors record there); a plain series nobody observed renders
        # here as 0, a vector nobody observed renders nowhere.
        shared_values = self.class.global.names_with_values
        empty_here = @mutex.synchronize { @metrics.values.select { |metric| metric.values.empty? }.map(&:name) }
        handoff = empty_here & shared_values
        mine = @mutex.synchronize { @metrics.keys } - handoff - empty_here.select { |name| labelled?(name) }
        own = render_own(except: handoff)
        shared = self.class.global.render_own(except: mine)
        return own if shared.empty?
        return shared if own.empty?

        own + shared
      end

      def labelled?(name)
        metric = @mutex.synchronize { @metrics[name] }
        metric&.labels&.any? || false
      end

      # This registry's families only (+except+: names already rendered).
      def render_own(except: [])
        @mutex.synchronize { @ratio_gauges&.values.to_a }.each(&:flush)
        collect_process_metrics if @process
        collect_storage_objects
        @mutex.synchronize { @collectors.dup }.each do |collector|
          collector.call(self)
        rescue StandardError
          nil
        end
        lines = []
        @mutex.synchronize do
          @metrics.each_value do |metric|
            next if except.include?(metric.name)

            values = metric.values
            if values.empty?
              if metric.labels.nil?
                next unless metric.type == :gauge
              elsif metric.labels.empty?
                values = {[].freeze => case metric.type
                                       when :histogram then {buckets: Hash.new(0), sum: 0.0, count: 0}
                                       when :summary then {samples: [], sum: 0.0, count: 0}
                                       else 0
                                       end}
              else
                next
              end
            end

            lines << "# HELP #{metric.name} #{metric.help}"
            lines << "# TYPE #{metric.name} #{metric.type}"
            case metric.type
            when :histogram then render_histogram(metric, lines, values)
            when :summary then render_summary(metric, lines, values)
            else
              values.each { |labels, value| lines << "#{metric.name}#{format_labels(labels)} #{format_number(value)}" }
            end
          end
        end
        lines << "" unless lines.empty?
        lines.join("\n")
      end

      # apiserver_response_sizes: ExponentialBuckets(1000, 10, 7).
      RESPONSE_SIZE_BUCKETS = [1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9].freeze

      # Records one served API request the way kube-apiserver's
      # endpoints/metrics does (component "apiserver").  A "resource/sub"
      # resource is split into its subresource label.
      #
      # As MonitorRequest: the response size of GET and LIST only, and the
      # SLO/SLI latency (less the admission webhooks' time) for everything
      # but a watch and a dry run.
      def record_request(verb:, resource:, code:, group: "", version: "", scope: "cluster", duration: nil, subresource: nil,
                         dry_run: "", response_size: nil, webhook_seconds: 0.0)
        labels = self.class.request_labels(verb: verb, resource: resource, group: group, version: version, scope: scope,
                                           subresource: subresource)
        dry = labels.merge("dry_run" => dry_run.to_s)
        increment("apiserver_request_total", dry.merge("code" => code.to_s))
        if duration
          observe("apiserver_request_duration_seconds", duration, dry)
          if dry_run.to_s.empty? && labels["verb"] != "WATCH"
            sli = [duration - webhook_seconds.to_f, 0.0].max
            observe("apiserver_request_sli_duration_seconds", sli, labels)
          end
        end
        observe("apiserver_response_sizes", response_size, labels) if response_size && %w[GET LIST].include?(labels["verb"])
        self
      end

      # apiserver_response_sizes for a read whose body the transport encoded
      # after the request was recorded.
      def response_size(labels, bytes) = observe("apiserver_response_sizes", bytes, labels)

      # The endpoint label set; a "resource/sub" resource is split into its
      # subresource label.
      def self.request_labels(verb:, resource:, group: "", version: "", scope: "cluster", subresource: nil)
        resource, split = resource.to_s.split("/", 2)
        subresource ||= split
        {"verb" => verb.to_s, "group" => group.to_s, "version" => version.to_s, "resource" => resource.to_s,
         "subresource" => subresource.to_s, "scope" => scope.to_s, "component" => "apiserver"}
      end

      # apiserver_longrunning_requests (RecordLongRunning), by the request's
      # endpoint labels.
      def longrunning(labels, delta)
        observe_value("apiserver_longrunning_requests", labels) { |current| current.to_f + delta }
      end

      # apiserver_watch_events_total / _sizes, labels group, version, resource.
      def watch_event(labels) = increment("apiserver_watch_events_total", labels)
      def watch_event_size(labels, bytes) = observe("apiserver_watch_events_sizes", bytes, labels)

      # apiserver_current_inflight_requests{request_kind="readOnly"|"mutating"}.
      def inflight(kind, delta)
        observe_value("apiserver_current_inflight_requests", {"request_kind" => kind.to_s}) { |current| current.to_f + delta }
      end

      def self.go_float(number)
        return "NaN" if number.nan?
        return number.positive? ? "+Inf" : "-Inf" if number.infinite?
        return "0" if number.zero?

        sign = number.negative? ? "-" : ""
        mantissa, _, exponent = number.abs.to_s.partition("e")
        whole, _, fraction = mantissa.partition(".")
        digits = whole + fraction
        point = whole.length + exponent.to_i
        leading = digits[/\A0*/].length
        digits = digits[leading..]
        point -= leading
        digits = digits.sub(/0+\z/, "")
        exp = point - 1
        if exp < -4 || exp >= 6
          tail = digits.length > 1 ? ".#{digits[1..]}" : ""
          "#{sign}#{digits[0]}#{tail}e#{exp.negative? ? "-" : "+"}#{format("%02d", exp.abs)}"
        elsif point <= 0
          "#{sign}0.#{"0" * -point}#{digits}"
        elsif digits.length <= point
          "#{sign}#{digits}#{"0" * (point - digits.length)}"
        else
          "#{sign}#{digits[0, point]}.#{digits[point..]}"
        end
      end

      private

      def register_apiserver_defaults
        register("apiserver_request_total", type: :counter,
                                            help: "Counter of apiserver requests broken out for each verb, group, version, resource, scope and HTTP " \
                                                  "response code.")
        register("apiserver_request_duration_seconds", type: :histogram, buckets: REQUEST_DURATION_BUCKETS,
                                                       help: "Response latency distribution in seconds for each verb, group, version, resource and scope.")
        register("apiserver_response_sizes", type: :histogram, buckets: RESPONSE_SIZE_BUCKETS,
                                             help: "Response size distribution in bytes for each group, version, verb, resource, subresource, scope and " \
                                                   "component.")
        register("apiserver_current_inflight_requests", type: :gauge,
                                                        help: "Maximal number of currently used inflight request limit of this apiserver per request kind " \
                                                              "in last second.")
        register("apiserver_longrunning_requests", type: :gauge,
                                                   help: "Gauge of all active long-running apiserver requests broken out by verb, group, version, resource, " \
                                                         "scope and " \
                                                         "component. Not all requests are tracked this way.")
        latency = "Response latency distribution (not counting webhook duration and priority & fairness queue wait times) in " \
                  "seconds for each verb, group, version, resource, subresource, scope and component."
        register("apiserver_request_sli_duration_seconds", type: :histogram, buckets: SLO_DURATION_BUCKETS, help: latency)
        register("apiserver_watch_events_total", type: :counter, help: "Number of events sent in watch clients")
        register("apiserver_watch_events_sizes", type: :histogram, buckets: WATCH_EVENT_SIZE_BUCKETS,
                                                 help: "Watch event size distribution in bytes")
        register("apiserver_storage_objects", type: :gauge,
                                              help: "[DEPRECATED, consider using apiserver_resource_objects instead] Number of stored objects at the time of " \
                                                    "last check split by kind. In case of a fetching error, the value will be -1.")
        register("apiserver_resource_objects", type: :gauge,
                                               help: "Number of stored objects at the time of last check split by kind. In case of a fetching error, the " \
                                                     "value will be -1.")
      end

      def register_process_defaults
        # client_golang's process collector, which every component serves.
        register("process_cpu_seconds_total", type: :counter, help: "Total user and system CPU time spent in seconds.")
        register("process_open_fds", type: :gauge, help: "Number of open file descriptors.")
        register("process_max_fds", type: :gauge, help: "Maximum number of open file descriptors.")
        register("process_virtual_memory_bytes", type: :gauge, help: "Virtual memory size in bytes.")
        register("process_resident_memory_bytes", type: :gauge, help: "Resident memory size in bytes.")
        register("process_start_time_seconds", type: :gauge, help: "Start time of the process since unix epoch in seconds.")
        start = process_start_time
        set("process_start_time_seconds", start) if start
      end

      CLOCK_TICKS = 100
      PAGE_SIZE = 4096

      # /proc/self/stat (utime, stime, vsize, rss) and fd counts, read at
      # every scrape as the Go collector does.
      def collect_process_metrics
        fields = File.read("/proc/self/stat").then { |stat| stat[(stat.rindex(")") + 2)..].split }
        set("process_cpu_seconds_total", (Integer(fields[11]) + Integer(fields[12])).to_f / CLOCK_TICKS)
        set("process_virtual_memory_bytes", Integer(fields[20]))
        set("process_resident_memory_bytes", Integer(fields[21]) * PAGE_SIZE)
        set("process_open_fds", Dir.children("/proc/self/fd").length)
        limit = File.foreach("/proc/self/limits").find { |line| line.start_with?("Max open files") }
        set("process_max_fds", Integer(limit.split[3])) if limit
      rescue SystemCallError, ArgumentError, IndexError, NoMethodError
        nil
      end

      # UpdateStoreStats: apiserver_storage_objects{resource="<resource>.<group>"}
      # and apiserver_resource_objects{group, resource}; -1 for every known
      # resource when the count fails.
      def collect_storage_objects
        source = @storage_source
        return unless source

        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        return if @storage_counted_at && now - @storage_counted_at < STORAGE_OBJECTS_REFRESH

        @storage_counted_at = now
        begin
          Array(source.call).each do |group, resource, count, bytes|
            set_storage_count(group, resource, count)
            # apiserver_resource_size_estimate_bytes, when the source knows sizes.
            set("apiserver_resource_size_estimate_bytes", bytes, {"group" => group.to_s, "resource" => resource.to_s}) if bytes
          end
        rescue StandardError
          known = @mutex.synchronize { @metrics["apiserver_resource_objects"].values.keys.map(&:to_h) }
          known.each { |labels| set_storage_count(labels["group"], labels["resource"], -1) }
        end
      end

      def set_storage_count(group, resource, count)
        group_resource = group.to_s.empty? ? resource.to_s : "#{resource}.#{group}"
        set("apiserver_storage_objects", count, {"resource" => group_resource})
        set("apiserver_resource_objects", count, {"group" => group.to_s, "resource" => resource.to_s})
      end

      # starttime (field 22, clock ticks after boot) + btime.
      def process_start_time
        stat = File.read("/proc/self/stat")
        ticks = Integer(stat[(stat.rindex(")") + 2)..].split.fetch(19))
        boot = File.foreach("/proc/stat").find { |line| line.start_with?("btime ") }
        Integer(boot.split[1]) + (ticks.to_f / CLOCK_TICKS)
      rescue SystemCallError, ArgumentError, IndexError, NoMethodError
        nil
      end

      def observe_value(name, labels)
        @mutex.synchronize do
          metric = @metrics[name]
          return self unless metric

          key = label_key(labels)
          metric.values[key] = yield(metric.values[key])
        end
        self
      end

      # Label sets repeat (a metric's label cardinality is bounded), and
      # stringifying and sorting them on every observation was most of the
      # cost of recording a request.  Keyed by content, so a fresh Hash with
      # the same labels finds its entry.
      LABEL_KEY_CACHE_LIMIT = 50_000

      def label_key(labels)
        cache = (@label_keys ||= {})
        cached = cache[labels]
        return cached if cached

        key = labels.map { |name, value| [name.to_s, value.to_s] }.sort.freeze
        cache.clear if cache.length >= LABEL_KEY_CACHE_LIMIT
        cache[labels.frozen? ? labels : labels.dup.freeze] = key
        key
      end

      def format_labels(labels)
        return "" if labels.empty?

        rendered = labels.map { |name, value| "#{name}=\"#{escape(value)}\"" }.join(",")
        "{#{rendered}}"
      end

      def escape(value)
        value.to_s.gsub("\\", "\\\\\\\\").gsub("\"", "\\\"").gsub("\n", "\\n")
      end

      # expfmt writeFloat: strconv.FormatFloat(v, 'g', -1, 64) -- the
      # shortest digits that read back as the same float, in %e form when
      # the exponent is below -4 or at least 6 ("1e+06", "1.5e-05").
      def format_number(value)
        self.class.go_float(value.to_f)
      end

      # A summary: the objectives' quantiles over the samples of the last
      # MaxAge (NaN when the window is empty, as client_golang prints), then
      # _sum and _count over everything ever observed.
      def render_summary(metric, lines, values = metric.values)
        horizon = Process.clock_gettime(Process::CLOCK_MONOTONIC) - SUMMARY_MAX_AGE_SECONDS
        values.each do |labels, entry|
          entry[:samples].shift(entry[:samples].index { |at, _| at >= horizon } || entry[:samples].length) unless entry[:samples].empty?
          window = entry[:samples].map(&:last).sort
          SUMMARY_OBJECTIVES.each do |quantile|
            value = if window.empty?
                      Float::NAN
                    else
                      window[[((quantile * window.length).ceil - 1), 0].max]
                    end
            lines << "#{metric.name}#{format_labels(labels.to_h.merge("quantile" => format_number(quantile)))} #{format_number(value)}"
          end
          lines << "#{metric.name}_sum#{format_labels(labels)} #{format_number(entry[:sum])}"
          lines << "#{metric.name}_count#{format_labels(labels)} #{entry[:count]}"
        end
      end

      def render_histogram(metric, lines, values = metric.values)
        values.each do |labels, entry|
          cumulative = 0
          metric.buckets.each do |bound|
            cumulative = entry[:buckets][bound]
            lines << "#{metric.name}_bucket#{format_labels(labels.to_h.merge("le" => format_number(bound)))} #{cumulative}"
          end
          lines << "#{metric.name}_bucket#{format_labels(labels.to_h.merge("le" => "+Inf"))} #{entry[:count]}"
          lines << "#{metric.name}_sum#{format_labels(labels)} #{format_number(entry[:sum])}"
          lines << "#{metric.name}_count#{format_labels(labels)} #{entry[:count]}"
        end
      end
    end
  end
end
