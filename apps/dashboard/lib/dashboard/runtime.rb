# frozen_string_literal: true

require "monitor"
require_relative "config"
require_relative "../tsdb/store"
require_relative "../promql/engine"
require_relative "../prom/targets"
require_relative "../prom/scraper"
require_relative "../prom/collector"
require_relative "../prom/rules"
require_relative "../prom/kube_state"

module Dashboard
  # The process-wide objects: the Kubernetes client, the time-series store,
  # the query engine, rules and the collector.  Built lazily from
  # Dashboard::Config; tests replace them with #configure.
  class Runtime
    class << self
      def current
        @current ||= new
      end

      # Replace the runtime (tests) or reset it (nil).
      def configure(runtime)
        @current&.stop
        @current = runtime
      end
    end

    attr_reader :started_at, :errors

    def initialize(client: nil, store: nil, engine: nil, targets: nil, rules: nil, collector: nil, kubeconfig_context: nil, logger: nil)
      @client = client
      @store = store
      @engine = engine
      @targets = targets
      @rules = rules
      @collector = collector
      @kubeconfig_context = kubeconfig_context
      @logger = logger || method(:log)
      @started_at = Time.now.utc
      @errors = {}
      # Re-entrant: building the collector builds the store, the scraper and
      # the engine inside the same critical section.
      @mutex = Monitor.new
    end

    # Every component is built once, under one lock: the first web request
    # and the collector thread race for these at boot, and two Tsdb::Store
    # instances over the same directory would each treat the other's series
    # as orphans and delete them.
    def client
      memoize(:client) do
        require "rubernetes/client"
        Rubernetes::Client::KubernetesClient.from_kubeconfig(path: Config.kubeconfig_path)
      rescue StandardError => e
        @errors[:client] = "#{e.class}: #{e.message}"
        nil
      end
    end

    def kubeconfig_context
      memoize(:kubeconfig_context) do
        require "rubernetes/client"
        Rubernetes::Client::Kubeconfig.load(path: Config.kubeconfig_path).resolve
      rescue StandardError => e
        @errors[:kubeconfig] = "#{e.class}: #{e.message}"
        nil
      end
    end

    def store
      memoize(:store) { Tsdb::Store.new(Config.data_dir, block_range_ms: Config.block_range_ms, retention_ms: Config.retention_ms) }
    end

    def engine
      memoize(:engine) { Promql::Engine.new(store) }
    end

    def kube_state
      memoize(:kube_state) { client && Prom::KubeState.new(client: client) }
    end

    def targets
      memoize(:targets) do
        discovery = Prom::Targets.new(client: client, cluster_json: Config.cluster_json, kubeconfig_context: kubeconfig_context)
        state = kube_state
        -> { discovery.discover + (state ? [state.target] : []) }
      end
    end

    def rules
      memoize(:rules) do
        path = Config.rules_path
        if File.file?(path)
          Prom::Rules.load_file(path, webhook_url: Config.alert_webhook_url, logger: @logger,
                                default_interval_ms: (Config.evaluation_interval_seconds * 1000).to_i)
        else
          Prom::Rules.new({"groups" => []}, webhook_url: Config.alert_webhook_url, logger: @logger)
        end
      rescue Prom::Rules::Error => e
        @errors[:rules] = e.message
        Prom::Rules.new({"groups" => []}, logger: @logger)
      end
    end

    def scraper
      memoize(:scraper) { Prom::Scraper.new(store, timeout_seconds: Config.scrape_timeout_seconds, logger: @logger) }
    end

    def collector
      memoize(:collector) do
        Prom::Collector.new(store: store, targets: targets, scraper: scraper, engine: engine, rules: rules,
                            interval_seconds: Config.scrape_interval_seconds,
                            evaluation_interval_seconds: Config.evaluation_interval_seconds, logger: @logger)
      end
    end

    def start
      collector.start
    end

    def stop
      @collector&.stop
      @store&.flush
    rescue StandardError
      nil
    end

    def build_info
      {"version" => "rubernetes-dashboard 0.1.0", "revision" => "", "branch" => "", "buildUser" => "", "buildDate" => "",
       "goVersion" => RUBY_DESCRIPTION}
    end

    private

    # Memoise under the runtime lock; a nil result (a failed client) is
    # retried on the next call so a cluster that comes up later is found.
    def memoize(name)
      variable = :"@#{name}"
      value = instance_variable_get(variable)
      return value unless value.nil?

      @mutex.synchronize do
        value = instance_variable_get(variable)
        return value unless value.nil?

        value = yield
        instance_variable_set(variable, value)
        value
      end
    end

    def log(level, event, **fields)
      line = {"timestamp" => Time.now.utc.iso8601(6), "level" => level.to_s, "event" => event}.merge(fields.transform_keys(&:to_s))
      if defined?(Rails) && Rails.logger
        Rails.logger.public_send(%i[debug info warn error].include?(level) ? level : :info, line.to_json)
      else
        warn line.to_json
      end
    end
  end
end
