# frozen_string_literal: true

module Api
  module V1
    class StatusController < BaseController
      # GET /api/v1/targets
      def targets
        statuses = runtime.scraper.statuses.values.sort_by { |s| [s.target.job, s.target.instance] }
        active = statuses.map do |status|
          target = status.target
          {"discoveredLabels" => {"__address__" => target.instance, "__metrics_path__" => target.url, "job" => target.job}.merge(target.labels || {}),
           "labels" => {"job" => target.job, "instance" => target.instance}.merge(target.labels || {}),
           "scrapePool" => target.job, "scrapeUrl" => target.url, "globalUrl" => target.url,
           "lastError" => status.last_error.to_s,
           "lastScrape" => status.last_scrape_ms ? Time.at(status.last_scrape_ms / 1000.0).utc.iso8601(3) : nil,
           "lastScrapeDuration" => status.last_duration_seconds.to_f, "health" => status.health,
           "scrapeInterval" => "#{Dashboard::Config.scrape_interval_seconds.to_i}s",
           "scrapeTimeout" => "#{Dashboard::Config.scrape_timeout_seconds.to_i}s"}
        end
        state = params[:state].to_s
        active = active.select { |t| t["health"] == "up" } if state == "active"
        success({"activeTargets" => active, "droppedTargets" => [], "droppedTargetCounts" => {}})
      end

      # GET /api/v1/rules
      def rules
        data = runtime.rules.to_api
        data["groups"].each { |g| g["rules"] = g["rules"].select { |r| r["type"] == params[:type] } } if params[:type].present?
        success(data)
      end

      # GET /api/v1/alerts
      def alerts
        success({"alerts" => runtime.rules.alerts.map { |a| runtime.rules.alert_to_api(a) }})
      end

      def buildinfo
        success(runtime.build_info)
      end

      def tsdb
        stats = store.stats
        top = top_series_by_metric
        success({"headStats" => {"numSeries" => stats["head_series"], "numLabelPairs" => nil, "chunkCount" => stats["head_chunks"],
                                 "minTime" => nil, "maxTime" => nil},
                 "seriesCountByMetricName" => top,
                 "labelValueCountByLabelName" => [], "memoryInBytesByLabelName" => [], "seriesCountByLabelValuePair" => [],
                 "storage" => stats})
      end

      def runtimeinfo
        collector = runtime.collector
        success({"startTime" => runtime.started_at.iso8601, "CWD" => Dir.pwd, "reloadConfigSuccess" => true,
                 "lastConfigTime" => runtime.started_at.iso8601, "corruptionCount" => 0, "goroutineCount" => Thread.list.length,
                 "GOMAXPROCS" => nil, "GOGC" => nil, "GODEBUG" => nil, "storageRetention" => "#{Dashboard::Config.retention_ms / 1000}s",
                 "collectorRunning" => collector.running?, "lastRound" => collector.last_round_at,
                 "discoveryError" => collector.discovery_error})
      end

      def config_status
        success({"yaml" => {"global" => {"scrape_interval" => "#{Dashboard::Config.scrape_interval_seconds.to_i}s",
                                         "scrape_timeout" => "#{Dashboard::Config.scrape_timeout_seconds.to_i}s",
                                         "evaluation_interval" => "#{Dashboard::Config.evaluation_interval_seconds.to_i}s"},
                            "rule_files" => [Dashboard::Config.rules_path],
                            "storage" => {"retention" => ENV.fetch("DASHBOARD_RETENTION", "15d"), "path" => Dashboard::Config.data_dir},
                            "kubeconfig" => Dashboard::Config.kubeconfig_path}.to_yaml})
      end

      private

      def top_series_by_metric
        counts = Hash.new(0)
        runtime.scraper.statuses.each_value { |s| counts[s.target.job] += s.samples.to_i }
        counts.sort_by { |_, v| -v }.first(10).map { |name, value| {"name" => name, "value" => value} }
      end
    end
  end
end
