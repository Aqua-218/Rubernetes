# frozen_string_literal: true

require "test_helper"
require "tmpdir"

module Dashboard
  class RuntimeTest < ActiveSupport::TestCase
    test "components are built once, lazily, and nested builds do not deadlock" do
      Dir.mktmpdir do |dir|
        saved = ENV.slice("DASHBOARD_DATA_DIR", "RUBERNETES_CLUSTER_JSON")
        ENV["DASHBOARD_DATA_DIR"] = dir
        ENV["RUBERNETES_CLUSTER_JSON"] = File.join(dir, "absent.json") # no host cluster leaks in
        client = Object.new
        client.define_singleton_method(:get) { |*| {"items" => []} }
        runtime = Dashboard::Runtime.new(client: client, kubeconfig_context: {server: "https://api"})
        collector = runtime.collector # builds store, scraper, engine, rules, targets inside one lock

        assert_same collector, runtime.collector
        assert_same runtime.store, runtime.engine.store
        assert_same runtime.scraper, collector.scraper
        # Concurrent first access yields one store, never two writers.
        threads = Array.new(8) { Thread.new { runtime.store } }

        assert_equal 1, threads.map(&:value).uniq.length
        assert_kind_of Prom::Rules, runtime.rules
        collector.round

        assert_equal 1, collector.targets.length, "the built-in kube-state target"
        runtime.stop
      ensure
        %w[DASHBOARD_DATA_DIR RUBERNETES_CLUSTER_JSON].each { |k| saved[k].nil? ? ENV.delete(k) : ENV[k] = saved[k] }
      end
    end

    test "the dashboard runtime applies histogram conversion environment settings" do
      keys = %w[DASHBOARD_CONVERT_CLASSIC_HISTOGRAMS_TO_NHCB DASHBOARD_ALWAYS_SCRAPE_CLASSIC_HISTOGRAMS]
      saved = ENV.slice(*keys)
      ENV[keys[0]] = "1"
      ENV[keys[1]] = "0"
      Dir.mktmpdir do |dir|
        store = Tsdb::Store.new(dir)
        runtime = Dashboard::Runtime.new(store: store)
        metrics = <<~TEXT
          # TYPE latency histogram
          latency_bucket{le="0.3"} 1
          latency_bucket{le="+Inf"} 4
          latency_count 4
          latency_sum 2.5
        TEXT
        target = Prom::Target.new(job: "test", instance: "source", fetch: -> { [200, metrics] })
        status = runtime.scraper.scrape(target)
        counts = runtime.engine.query("histogram_count(latency)").value.map { |series| series.point.last }

        assert_equal "up", status.health
        assert_equal [4.0], counts
        assert_empty runtime.engine.query("latency_count").value
      ensure
        store&.close
      end
    ensure
      keys.each { |key| saved.key?(key) ? ENV[key] = saved[key] : ENV.delete(key) }
    end
  end
end
