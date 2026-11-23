# frozen_string_literal: true

require "test_helper"
require "tmpdir"

module Prom
  class RulesTest < ActiveSupport::TestCase
    T0 = 1_700_000_010_000

    def setup
      @dir = Dir.mktmpdir("rules")
      @store = Tsdb::Store.new(@dir)
      @now = T0
      @engine = Promql::Engine.new(@store, now: -> { @now })
      @posted = []
    end

    def teardown
      @store.close
      FileUtils.rm_rf(@dir)
    end

    def rules(yaml, **)
      Prom::Rules.new(YAML.safe_load(yaml), webhook_url: "http://alertmanager.test/api/v2/alerts",
                                            http: lambda { |url, payload|
                                              @posted << [url, payload]
                                              true
                                            }, **)
    end

    def up(instance, value, at = @now)
      @store.append({"__name__" => "up", "job" => "j", "instance" => instance}, at, value.to_f)
    end

    def wait_threads
      Thread.list.each { |t| t.join(2) if t != Thread.current && t.name.nil? }
    end

    test "recording rules write new series with the rule labels" do
      up("a", 1)
      up("b", 0)
      r = rules(<<~YAML)
        groups:
        - name: recording
          rules:
          - record: job:up:avg
            expr: avg by (job) (up)
            labels: { source: rule }
      YAML
      r.evaluate(@engine, @now)
      result = @engine.query("job:up:avg")

      assert_equal([[{"__name__" => "job:up:avg", "job" => "j", "source" => "rule"}, 0.5]], result.value.map { |s| [s.metric, s.point[1]] })
      api = r.to_api["groups"][0]

      assert_equal "recording", api["rules"][0]["type"]
      assert_equal "ok", api["rules"][0]["health"]
    end

    test "alerts go pending, then firing after `for`, then resolved, with notifications and ALERTS series" do
      up("a", 0)
      r = rules(<<~YAML)
        groups:
        - name: alerts
          rules:
          - alert: TargetDown
            expr: up == 0
            for: 30s
            labels: { severity: critical }
            annotations:
              summary: "{{ $labels.instance }} of {{ $labels.job }} is down (value {{ $value }})"
              pct: "{{ humanizePercentage 0.256 }}"
      YAML
      r.evaluate(@engine, @now)
      alert = r.alerts.first

      assert_equal "pending", alert.state
      assert_equal "a of j is down (value 0)", alert.annotations["summary"]
      assert_equal "25.6%", alert.annotations["pct"]
      assert_equal({"alertname" => "TargetDown", "job" => "j", "instance" => "a", "severity" => "critical"}, alert.labels)
      assert_equal [], @posted, "pending alerts are not notified"
      assert_equal([1.0], @engine.query('ALERTS{alertstate="pending"}').value.map { |s| s.point[1] })
      assert_equal([T0 / 1000.0], @engine.query("ALERTS_FOR_STATE").value.map { |s| s.point[1] })

      @now += 15_000
      up("a", 0)
      r.evaluate(@engine, @now, force: true)

      assert_equal "pending", r.alerts.first.state

      @now += 15_000
      up("a", 0)
      r.evaluate(@engine, @now, force: true)

      assert_equal "firing", r.alerts.first.state
      wait_threads

      assert_equal 1, @posted.length
      payload = @posted[0][1]

      assert_equal "firing", payload[0]["status"]
      assert_equal "TargetDown", payload[0]["labels"]["alertname"]
      assert_equal([1.0], @engine.query('ALERTS{alertstate="firing"}').value.map { |s| s.point[1] })
      assert_equal [], @engine.query('ALERTS{alertstate="pending"}').value
      api = r.to_api["groups"][0]["rules"][0]

      assert_equal "firing", api["state"]
      assert_in_delta(30.0, api["duration"])
      assert_equal 1, api["alerts"].length

      @now += 15_000
      up("a", 1)
      r.evaluate(@engine, @now, force: true)

      assert_equal [], r.alerts
      wait_threads

      assert_equal 2, @posted.length
      assert_equal "resolved", @posted[1][1][0]["status"]
      refute_equal "0001-01-01T00:00:00Z", @posted[1][1][0]["endsAt"]
      assert_equal [], @engine.query("ALERTS").value
      assert_equal "inactive", r.to_api["groups"][0]["rules"][0]["state"]
    end

    test "keep_firing_for holds a firing alert after its condition clears" do
      up("a", 0)
      r = rules(<<~YAML)
        groups:
        - name: g
          rules:
          - alert: Flap
            expr: up == 0
            keep_firing_for: 1m
      YAML
      r.evaluate(@engine, @now)

      assert_equal "firing", r.alerts.first.state, "no `for` means firing at once"
      @now += 15_000
      up("a", 1)
      r.evaluate(@engine, @now, force: true)

      assert_equal "firing", r.alerts.first.state
      @now += 60_000
      up("a", 1)
      r.evaluate(@engine, @now, force: true)

      assert_equal [], r.alerts
    end

    test "group intervals are honoured and rule errors are reported not raised" do
      r = rules(<<~YAML)
        groups:
        - name: slow
          interval: 1m
          rules:
          - record: bad
            expr: up / on(instance) up_other
        - name: fast
          rules:
          - record: fine
            expr: vector(1)
      YAML
      r.evaluate(@engine, @now)
      slow = r.groups.find { |g| g.name == "slow" }
      fast = r.groups.find { |g| g.name == "fast" }

      assert_equal @now, slow.last_evaluation_ms
      assert_equal @now, fast.last_evaluation_ms
      @now += 15_000
      r.evaluate(@engine, @now)

      assert_equal @now - 15_000, slow.last_evaluation_ms, "not due yet"
      assert_equal @now, fast.last_evaluation_ms
      assert_equal "ok", slow.rules[0].health, "an empty result is fine"
      assert_equal([1.0], @engine.query("fine").value.map { |s| s.point[1] })
    end

    test "invalid rule files are rejected with a reason" do
      assert_raises(Prom::Rules::Error) { rules("groups:\n- name: a\n  rules:\n  - record: bad name\n    expr: up\n") }
      assert_raises(Prom::Rules::Error) { rules("groups:\n- name: a\n  rules:\n  - alert: A\n    expr: up ==\n") }
      assert_raises(Prom::Rules::Error) { rules("groups:\n- name: a\n  rules:\n  - alert: A\n    record: b\n    expr: up\n") }
      assert_raises(Prom::Rules::Error) { rules("groups:\n- name: a\n- name: a\n") }
      assert_raises(Prom::Rules::Error) { rules("groups:\n- name: a\n  rules:\n  - alert: A\n    expr: up\n    for: soon\n") }
    end

    test "real alert evaluation expands label templates and conditional query annotations" do
      up("a.example.test:80", 1)
      up("b.example.test:80", 0)
      r = rules(<<~YAML, external_labels: {"cluster" => "test", "instance" => "external"}, external_url: "https://dash.example/monitor")
        groups:
        - name: g
          rules:
          - alert: Example
            expr: up == 1
            labels:
              node: '{{ $labels.instance | stripDomain | stripPort }}'
            annotations:
              summary: '{{ $labels.__name__ }} {{ $labels.node }}{{- if eq $value 1.0 }}: {{ query "up" | sortByLabel "instance" | first | label "instance" }}{{ else }} unavailable{{ end }}'
              using_range: '{{ range $i, $s := query "up" | sortByLabel "instance" }}{{ $i }}={{ $s.Value }} {{ else }}none{{ end }}{{ with query "absent_metric" }}found{{ else }}none{{ end }}'
              external: '{{ $externalLabels.cluster }} {{ $externalURL }} {{ pathPrefix }}'
              link: '{{ "up == 1" | tableLink }}'
              invalid: '{{ first (query "absent_metric") }}'
      YAML
      r.evaluate(@engine, @now)
      alert = r.alerts.first

      assert_equal "a", alert.labels["node"]
      assert_equal "up : a.example.test:80", alert.annotations["summary"]
      assert_equal "0=1 1=0 none", alert.annotations["using_range"]
      assert_equal "test https://dash.example/monitor /monitor", alert.annotations["external"]
      assert_equal "/graph?g0.expr=up+%3D%3D+1&g0.tab=1", alert.annotations["link"]
      assert_match(/error expanding template: first called on an empty vector/, alert.annotations["invalid"])
      assert_equal "ok", r.rules.first.health
      assert_equal "a.example.test:80", r.notifications.first["alerts"].first["labels"]["instance"]
    end

    test "duplicate template-derived labels fail the alert rule before any alert is activated" do
      up("a", 1)
      up("b", 1)
      r = rules(<<~YAML)
        groups:
        - name: g
          rules:
          - alert: Collision
            expr: up
            labels:
              instance: '{{ $labels.job }}'
      YAML
      r.evaluate(@engine, @now)

      assert_empty r.alerts
      assert_equal "err", r.rules.first.health
      assert_match(/same labelset/, r.rules.first.last_error)
    end

    test "named templates use a fresh scope and loop control preserves preceding output" do
      up("a", 1)
      r = rules(<<~YAML)
        groups:
        - name: g
          rules:
          - alert: Loop
            expr: up
            annotations:
              rendered: >-
                {{define "row"}}{{.arg0}}={{.arg1}}{{end}}{{define "empty"}}[{{.}}]{{end}}
                {{- $last := "initial" -}}
                {{ range $i := 8 }}{{ if eq $i 1 }}{{continue}}{{end}}{{ if eq $i 5 }}stop{{break}}{{end}}
                {{- $last = printf "%d" $i -}}{{ template "row" (args $i $last) }};{{end}}
                {{$last}}{{template "empty"}} {{block "footer" .Labels}}{{.job}}{{end}}
              scope: '{{ $local := "outer" }}{{define "isolated"}}{{$local}}{{end}}{{template "isolated" .}}'
              bad_break: '{{if false}}{{break}}{{end}}'
              recursion: '{{define "recursive"}}{{template "recursive" .}}{{end}}{{template "recursive" .}}'
      YAML

      r.evaluate(@engine, @now)
      annotations = r.alerts.first.annotations

      assert_equal "0=0;2=2;3=3;4=4;stop 4[<no value>] j", annotations["rendered"]
      assert_match(/undefined template variable \$local/, annotations["scope"])
      assert_match(/break outside range/, annotations["bad_break"])
      assert_match(/template recursion limit exceeded/, annotations["recursion"])
    end

    test "templates: humanize functions and printf" do
      template = AlertTemplate.new(labels: {}, value: 3.14159, external_labels: {}, external_url: nil, timestamp_ms: T0, engine: @engine)

      assert_equal "1.5k", template.expand("{{ humanize 1500 }}")
      assert_equal "1.465ki", template.expand("{{ humanize1024 1500 }}")
      assert_equal "1h 1m 1s", template.expand("{{ humanizeDuration 3661 }}")
      assert_equal "500ms", template.expand("{{ humanizeDuration 0.5 }}")
      assert_equal "3.14", template.expand("{{ printf \"%.2f\" $value }}")
      assert_equal "Job J", template.expand("{{ title \"job j\" }}")
      assert_raises(AlertTemplate::Error) { template.expand("{{ nope }}") }
    end
  end
end
