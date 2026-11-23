# frozen_string_literal: true

require "yaml"
require "json"
require "net/http"
require "uri"
require_relative "../tsdb/store"
require_relative "alert_template"

module Prom
  # Recording and alerting rules in the Prometheus rule-file format:
  #
  #   groups:
  #   - name: cluster
  #     interval: 30s            # optional, else the evaluator's interval
  #     rules:
  #     - record: job:up:avg
  #       expr: avg by (job) (up)
  #     - alert: TargetDown
  #       expr: up == 0
  #       for: 2m
  #       keep_firing_for: 0s
  #       labels: { severity: critical }
  #       annotations:
  #         summary: "{{ $labels.job }}/{{ $labels.instance }} is down"
  #
  # Recording rules append their result as new series named by `record`.
  # Alerting rules keep per-label-set state (pending -> firing -> resolved,
  # honouring `for` and `keep_firing_for`), write ALERTS and
  # ALERTS_FOR_STATE series, and post Alertmanager-style webhook
  # notifications on transitions. Rule labels and annotations can use
  # Prometheus template variables and query helpers.
  class Rules
    class Error < StandardError; end

    Group = Struct.new(:name, :interval_ms, :rules, :file, :last_evaluation_ms, :evaluation_seconds, keyword_init: true)

    Rule = Struct.new(:group, :name, :kind, :expr, :for_ms, :keep_firing_for_ms, :labels, :annotations,
                      :health, :last_error, :last_evaluation_ms, :evaluation_seconds, keyword_init: true) do
      def recording? = kind == :record
      def alerting? = kind == :alert
    end

    Alert = Struct.new(:rule, :labels, :annotations, :state, :active_at_ms, :fired_at_ms, :resolved_at_ms,
                       :last_sent_state, :value, :keep_firing_since_ms, keyword_init: true)

    attr_reader :groups, :external_labels, :webhook_url, :notifications

    def self.load_file(path, **)
      raise Error, "rules file #{path} not found" unless File.file?(path)

      document = YAML.safe_load_file(path, aliases: true) || {}
      new(document, file: path, **)
    end

    def initialize(document, file: nil, webhook_url: nil, external_labels: {}, external_url: nil, logger: nil, http: nil,
                   default_interval_ms: 15_000)
      @file = file
      @webhook_url = webhook_url
      @external_labels = external_labels.transform_keys(&:to_s).transform_values(&:to_s)
      @external_url = external_url
      @logger = logger
      @http = http || method(:post_json)
      @default_interval_ms = default_interval_ms
      @active = {} # [rule object_id, labels fingerprint] -> Alert
      @notifications = [] # recent notification records
      @mutex = Mutex.new
      @groups = parse(document)
    end

    # Every rule of every group.
    def rules
      @groups.flat_map(&:rules)
    end

    # Currently active alerts (pending or firing), Prometheus API shape.
    def alerts
      @mutex.synchronize { @active.values.select { |a| %w[pending firing].include?(a.state) } }
    end

    # Evaluate every group whose interval has elapsed.
    def evaluate(engine, now_ms = (Time.now.to_f * 1000).to_i, force: false)
      @groups.each do |group|
        interval = group.interval_ms || @default_interval_ms
        next if !force && group.last_evaluation_ms && now_ms - group.last_evaluation_ms < interval - 1

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        group.rules.each { |rule| evaluate_rule(engine, rule, now_ms) }
        group.last_evaluation_ms = now_ms
        group.evaluation_seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      end
      flush_notifications(now_ms)
    end

    # /api/v1/rules shape.
    def to_api
      {"groups" => @groups.map do |group|
        {"name" => group.name, "file" => group.file.to_s, "interval" => (group.interval_ms || @default_interval_ms) / 1000.0,
         "lastEvaluation" => iso(group.last_evaluation_ms), "evaluationTime" => group.evaluation_seconds.to_f,
         "rules" => group.rules.map { |rule| rule_to_api(rule) }}
      end}
    end

    def rule_to_api(rule)
      base = {"name" => rule.name, "query" => rule.expr, "health" => rule.health || "unknown", "lastError" => rule.last_error.to_s,
              "lastEvaluation" => iso(rule.last_evaluation_ms), "evaluationTime" => rule.evaluation_seconds.to_f,
              "labels" => rule.labels}
      if rule.alerting?
        base.merge("type" => "alerting", "duration" => rule.for_ms / 1000.0, "keepFiringFor" => rule.keep_firing_for_ms / 1000.0,
                   "annotations" => rule.annotations, "state" => rule_state(rule),
                   "alerts" => alerts_for(rule).map { |alert| alert_to_api(alert) })
      else
        base.merge("type" => "recording")
      end
    end

    def alert_to_api(alert)
      {"labels" => alert.labels, "annotations" => alert.annotations, "state" => alert.state,
       "activeAt" => iso(alert.active_at_ms), "value" => alert.value.to_s}
    end

    private

    def iso(ms)
      return nil if ms.nil?

      Time.at(ms / 1000.0).utc.iso8601(3)
    end

    def parse(document)
      groups = Array(document["groups"])
      raise Error, "rules: `groups` must be a list" unless groups.is_a?(Array)

      names = {}
      groups.map do |raw|
        name = raw["name"].to_s
        raise Error, "rule group without a name" if name.empty?
        raise Error, "duplicate rule group #{name.inspect}" if names.key?(name)

        names[name] = true
        interval = raw["interval"] ? duration_ms(raw["interval"]) : nil
        group = Group.new(name: name, interval_ms: interval, rules: [], file: @file)
        Array(raw["rules"]).each_with_index do |rule, index|
          group.rules << parse_rule(rule, group, index)
        end
        group
      end
    end

    def parse_rule(raw, group, index)
      record = raw["record"]
      alert = raw["alert"]
      raise Error, "group #{group.name}: rule #{index} must set exactly one of record/alert" unless [record, alert].compact.length == 1

      expr = raw["expr"].to_s
      raise Error, "group #{group.name}: rule #{index} has no expr" if expr.empty?

      begin
        Promql::Parser.parse(expr)
      rescue Promql::ParseError => e
        raise Error, "group #{group.name}: rule #{index}: #{e.message}"
      end
      labels = (raw["labels"] || {}).to_h { |k, v| [k.to_s, v.to_s] }
      if record
        raise Error, "invalid recording rule name #{record.inspect}" unless record.to_s.match?(/\A[a-zA-Z_:][a-zA-Z0-9_:]*\z/)
        raise Error, "recording rules may not set for/annotations" if raw.key?("for") || raw.key?("annotations")

        Rule.new(group: group.name, name: record.to_s, kind: :record, expr: expr, for_ms: 0, keep_firing_for_ms: 0,
                 labels: labels, annotations: {})
      else
        raise Error, "invalid alert name #{alert.inspect}" unless alert.to_s.match?(/\A[a-zA-Z_][a-zA-Z0-9_]*\z/)

        Rule.new(group: group.name, name: alert.to_s, kind: :alert, expr: expr,
                 for_ms: raw["for"] ? duration_ms(raw["for"]) : 0,
                 keep_firing_for_ms: raw["keep_firing_for"] ? duration_ms(raw["keep_firing_for"]) : 0,
                 labels: labels, annotations: (raw["annotations"] || {}).to_h { |k, v| [k.to_s, v.to_s] })
      end
    end

    def duration_ms(text)
      Promql::Lexer.duration_ms(text.to_s)
    rescue Promql::ParseError => e
      raise Error, e.message
    end

    def evaluate_rule(engine, rule, now_ms)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = engine.query(rule.expr, now_ms)
      vector = case result.type
               when :vector then result.value
               when :scalar then [Promql::Engine::Series.new(metric: {}, point: result.value)]
               else raise Error, "rule #{rule.name} evaluated to #{result.type}, expected an instant vector"
               end
      rule.recording? ? record(engine, rule, vector, now_ms) : alert(engine, rule, vector, now_ms)
      rule.health = "ok"
      rule.last_error = nil
    rescue StandardError => e
      rule.health = "err"
      rule.last_error = "#{e.class}: #{e.message}"
      @logger&.call(:warn, "rule.failed", rule: rule.name, error: rule.last_error)
    ensure
      rule.last_evaluation_ms = now_ms
      rule.evaluation_seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    end

    def record(engine, rule, vector, now_ms)
      rows = vector.map do |series|
        labels = series.metric.merge(rule.labels).merge("__name__" => rule.name)
        [labels, now_ms, series.point[1]]
      end
      engine.store.append_batch(rows)
    end

    def alert(engine, rule, vector, now_ms)
      seen = {}
      rows = []
      vector.each do |series|
        value = series.point[1]
        expander = AlertTemplate.new(labels: series.metric, value: value, external_labels: @external_labels, external_url: @external_url,
                                     timestamp_ms: now_ms, engine: engine)
        labels = series.metric.merge(rule.labels.transform_values { |template| expand(template, expander, rule) })
        labels.delete("__name__")
        labels.delete_if { |_, label| label.empty? }
        labels["alertname"] = rule.name
        key = [rule.object_id, labels.sort]
        raise Error, "vector contains metrics with the same labelset after applying alert labels" if seen.key?(key)

        annotations = rule.annotations.transform_values { |template| expand(template, expander, rule) }
        seen[key] = [labels, annotations, value]
      end

      @mutex.synchronize do
        seen.each do |key, (labels, annotations, value)|
          entry = @active[key]
          if entry.nil? || entry.state == "resolved"
            entry = Alert.new(rule: rule, labels: labels, annotations: annotations, state: "pending", active_at_ms: now_ms,
                              value: value, keep_firing_since_ms: nil)
            entry.state = "firing" if rule.for_ms.zero?
            entry.fired_at_ms = now_ms if entry.state == "firing"
            @active[key] = entry
          else
            entry.annotations = annotations
            entry.value = value
            entry.keep_firing_since_ms = nil
            if entry.state == "pending" && now_ms - entry.active_at_ms >= rule.for_ms
              entry.state = "firing"
              entry.fired_at_ms = now_ms
            end
          end
        end
        @active.each do |key, entry|
          next unless key[0] == rule.object_id
          next if seen.key?(key)

          case entry.state
          when "pending"
            entry.state = "resolved"
            entry.resolved_at_ms = now_ms
          when "firing"
            if rule.keep_firing_for_ms.positive?
              entry.keep_firing_since_ms ||= now_ms
              next if now_ms - entry.keep_firing_since_ms < rule.keep_firing_for_ms
            end
            entry.state = "resolved"
            entry.resolved_at_ms = now_ms
          end
        end
        # A second pass on purpose: the first one above skips the alerts that
        # are still active (`next if seen`), this one writes a row for every
        # alert of the rule, active or just resolved.
        @active.each do |key, entry|
          next unless key[0] == rule.object_id

          alert_labels = entry.labels.merge("__name__" => "ALERTS", "alertstate" => entry.state)
          if entry.state == "resolved"
            rows << [alert_labels.merge("alertstate" => "firing"), now_ms, Tsdb::Store::STALE_NAN] if entry.fired_at_ms
            rows << [alert_labels.merge("alertstate" => "pending"), now_ms, Tsdb::Store::STALE_NAN]
            rows << [entry.labels.merge("__name__" => "ALERTS_FOR_STATE"), now_ms, Tsdb::Store::STALE_NAN]
          else
            rows << [alert_labels, now_ms, 1.0]
            other = entry.state == "firing" ? "pending" : "firing"
            if entry.state == "firing" && entry.fired_at_ms == now_ms
              rows << [alert_labels.merge("alertstate" => other), now_ms,
                       Tsdb::Store::STALE_NAN]
            end
            rows << [entry.labels.merge("__name__" => "ALERTS_FOR_STATE"), now_ms, entry.active_at_ms / 1000.0]
          end
        end
        # Resolved alerts are kept for the resolved notification, then dropped.
        @active.delete_if { |key, entry| key[0] == rule.object_id && entry.state == "resolved" && entry.last_sent_state == "resolved" }
        @active.delete_if { |key, entry| key[0] == rule.object_id && entry.state == "resolved" && entry.fired_at_ms.nil? }
      end
      engine.store.append_batch(rows) unless rows.empty?
    end

    def rule_state(rule)
      states = alerts_for(rule).map(&:state)
      return "firing" if states.include?("firing")
      return "pending" if states.include?("pending")

      "inactive"
    end

    def alerts_for(rule)
      @mutex.synchronize { @active.select { |key, a| key[0] == rule.object_id && a.state != "resolved" }.values }
    end

    # ---------------------------------------------------------- templates

    def expand(template, expander, rule)
      expander.expand(template)
    rescue StandardError => e
      @logger&.call(:warn, "rule.template_failed", rule: rule.name, error: e.message)
      "<error expanding template: #{e.message}>"
    end

    # ------------------------------------------------------- notifications

    def flush_notifications(now_ms)
      pending = []
      @mutex.synchronize do
        @active.each_value do |alert|
          next if alert.state == "pending"
          next if alert.last_sent_state == alert.state

          pending << alert.dup
          alert.last_sent_state = alert.state
        end
        @active.delete_if { |_, alert| alert.state == "resolved" && alert.last_sent_state == "resolved" }
      end
      return if pending.empty?

      payload = pending.map do |alert|
        {"status" => alert.state == "firing" ? "firing" : "resolved",
         "labels" => @external_labels.merge(alert.labels), "annotations" => alert.annotations,
         "startsAt" => iso(alert.fired_at_ms || alert.active_at_ms),
         "endsAt" => alert.state == "resolved" ? iso(alert.resolved_at_ms || now_ms) : "0001-01-01T00:00:00Z",
         "generatorURL" => ""}
      end
      @mutex.synchronize do
        @notifications << {"at" => iso(now_ms), "alerts" => payload}
        @notifications.shift while @notifications.length > 100
      end
      return if @webhook_url.nil?

      Thread.new do
        Thread.current.report_on_exception = false
        3.times do |attempt|
          break if @http.call(@webhook_url, payload)

          sleep(2**attempt)
        end
      rescue StandardError => e
        @logger&.call(:warn, "alerts.notify_failed", error: "#{e.class}: #{e.message}")
      end
    end

    def post_json(url, payload)
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = 5
      http.read_timeout = 10
      request = Net::HTTP::Post.new(uri.request_uri, {"Content-Type" => "application/json"})
      request.body = JSON.generate(payload)
      response = http.request(request)
      response.code.to_i.between?(200, 299)
    rescue StandardError => e
      @logger&.call(:warn, "alerts.webhook_failed", url: url, error: "#{e.class}: #{e.message}")
      false
    end
  end
end
