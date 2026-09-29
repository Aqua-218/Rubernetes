# frozen_string_literal: true

class MonitoringController < ApplicationController
  def targets
    @statuses = runtime.scraper.statuses.values.sort_by { |s| [s.target.job, s.target.instance] }
    @by_job = @statuses.group_by { |s| s.target.job }
    @collector = runtime.collector
  end

  def rules
    @groups = runtime.rules.groups
    @errors = runtime.errors
  end

  def alerts
    @rules = runtime.rules
    @alerting = runtime.rules.rules.select(&:alerting?)
    @notifications = runtime.rules.notifications.last(20).reverse
  end

  def status
    @build = runtime.build_info
    @stats = runtime.store.stats
    @blocks = runtime.store.blocks
    @collector = runtime.collector
    @config = {
      "kubeconfig" => Dashboard::Config.kubeconfig_path,
      "cluster.json" => Dashboard::Config.cluster_json_path,
      "data dir" => Dashboard::Config.data_dir,
      "scrape interval" => "#{Dashboard::Config.scrape_interval_seconds}s",
      "scrape timeout" => "#{Dashboard::Config.scrape_timeout_seconds}s",
      "evaluation interval" => "#{Dashboard::Config.evaluation_interval_seconds}s",
      "retention" => ENV.fetch("DASHBOARD_RETENTION", "15d"),
      "block range" => ENV.fetch("DASHBOARD_BLOCK_RANGE", "2h"),
      "rules file" => Dashboard::Config.rules_path,
      "alert webhook" => Dashboard::Config.alert_webhook_url || "(none)",
      "writes" => writes_allowed? ? "allowed" : "disabled",
      "authentication" => Dashboard::Config.password ? "basic auth" : "none"
    }
    @errors = runtime.errors
  end
end
