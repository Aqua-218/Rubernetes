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

    test "templates: humanize functions and printf" do
      r = rules("groups: []")

      assert_equal "1.5k", r.send(:expand, "{{ humanize 1500 }}", {}, 0)
      assert_equal "1.465Ki", r.send(:expand, "{{ humanize1024 1500 }}", {}, 0)
      assert_equal "1h 1m 1s", r.send(:expand, "{{ humanizeDuration 3661 }}", {}, 0)
      assert_equal "500ms", r.send(:expand, "{{ humanizeDuration 0.5 }}", {}, 0)
      assert_equal "3.14", r.send(:expand, "{{ printf \"%.2f\" $value }}", {}, 3.14159)
      assert_equal "Job J", r.send(:expand, "{{ title \"job j\" }}", {}, 0)
      assert_equal "{{ nope }}", r.send(:expand, "{{ nope }}", {}, 0), "unknown templates are left visible"
    end
  end
end
