# frozen_string_literal: true

require "test_helper"
require "tmpdir"

# PromQL semantics checked against the behaviour documented and tested in
# prometheus/promql (testdata/functions.test, operators.test, aggregators.test).
module Promql
  class EngineTest < ActiveSupport::TestCase
    T0 = 1_700_000_010_000 # a fixed "now" in ms, a multiple of 15s

    def setup
      @dir = Dir.mktmpdir("promql")
      @store = Tsdb::Store.new(@dir)
      @engine = Promql::Engine.new(@store, now: -> { T0 })
    end

    def teardown
      @store.close
      FileUtils.rm_rf(@dir)
    end

    # load "15s" style series: values per 15s step ending at T0.
    def load(name, labels, values, step_ms: 15_000, end_ms: T0)
      start = end_ms - ((values.length - 1) * step_ms)
      values.each_with_index do |value, i|
        next if value.nil?

        @store.append({"__name__" => name}.merge(labels), start + (i * step_ms), value.to_f)
      end
    end

    def vector(expr, t = T0)
      result = @engine.query(expr, t)

      assert_equal :vector, result.type, "#{expr}: #{result.inspect}"
      result.value.map { |s| [s.metric, s.point[1]] }
    end

    def scalar(expr, t = T0)
      result = @engine.query(expr, t)

      assert_equal :scalar, result.type
      result.value[1]
    end

    def values(expr, t = T0)
      vector(expr, t).map(&:last)
    end

    # ---------------------------------------------------------- selectors

    test "instant selectors use a five minute lookback and honour offset and @" do
      load("up", {"job" => "a"}, [1, 1, 1, 1, 1])
      load("up", {"job" => "b"}, [0], end_ms: T0 - (6 * 60_000)) # older than the lookback

      assert_equal [[{"__name__" => "up", "job" => "a"}, 1.0]], vector("up")
      assert_equal [], vector('up{job="b"}')
      assert_equal [[{"__name__" => "up", "job" => "b"}, 0.0]], vector('up{job="b"} offset 6m')
      assert_equal [[{"__name__" => "up", "job" => "b"}, 0.0]], vector("up{job=\"b\"} @ #{(T0 - (6 * 60_000)) / 1000}")
      assert_equal 1, vector('{__name__=~"u.*"}').length
      assert_equal 1, vector('up{job!="b"}').length
    end

    test "stale markers end a series" do
      load("m", {}, [1, 2, 3])
      @store.append({"__name__" => "m"}, T0 + 15_000, Tsdb::Store::STALE_NAN)

      assert_equal [3.0], values("m")
      assert_equal [], vector("m", T0 + 30_000)
    end

    test "range selectors are left-open windows" do
      load("c", {}, [1, 2, 3, 4, 5]) # T0-60s .. T0
      result = @engine.query("c[1m]")

      assert_equal :matrix, result.type
      # (T0-60s, T0] holds four samples: the one exactly at T0-60s is excluded.
      assert_equal [2.0, 3.0, 4.0, 5.0], result.value[0].points.map(&:last)
    end

    # ---------------------------------------------------------- range functions

    test "rate and increase extrapolate to the window edges and handle counter resets" do
      # 5 samples 15s apart: 0, 10, 20, 30, 40 -> exact rate 10/15 = 0.6667/s over a 60s window
      load("http_requests_total", {}, [0, 10, 20, 30, 40])
      # Window (T0-75s, T0] contains all five.  The first sample is 15s from
      # the window start, under the 1.1 * interval threshold, so the increase
      # would extrapolate 15s back -- but a counter is never extrapolated below
      # zero, and the first value is 0, so nothing is added: 40 over 75s.
      rate = values("rate(http_requests_total[75s])").first

      assert_in_delta 40.0 / 75, rate, 1e-9
      increase = values("increase(http_requests_total[75s])").first

      assert_in_delta 40.0, increase, 1e-9

      load("resets_total", {}, [10, 20, 5, 15])
      # 10 -> 20 (+10), reset to 5 (+5 from zero), 5 -> 15 (+10): 25 over 45s
      # of samples, extrapolated the 1s to the window start: 25 * 46/45.
      inc = values("increase(resets_total[46s])").first

      assert_in_delta 25.0 * 46 / 45, inc, 1e-6
      assert_equal [1.0], values("resets(resets_total[1m])")
      assert_equal [3.0], values("changes(resets_total[1m])")
    end

    test "rate needs two samples and the result has no metric name" do
      load("one", {"a" => "b"}, [5])

      assert_equal [], vector("rate(one[1m])")
      load("two", {"a" => "b"}, [5, 6])

      assert_equal [{"a" => "b"}], vector("rate(two[1m])").map(&:first)
    end

    test "irate, idelta, delta, deriv and predict_linear" do
      load("g", {}, [10, 20, 40, 30])

      assert_in_delta 30.0 / 15, values("irate(g[1m])").first, 1e-9 # counter reset: last value / interval
      assert_equal [-10.0], values("idelta(g[1m])")
      # 45s of samples inside a 60s window; the 15s to the window start is
      # under the threshold, so delta extrapolates the full 15s.
      delta = values("delta(g[1m])").first

      assert_in_delta 20.0 * 60 / 45, delta, 1e-6
      load("lin", {}, [0, 1, 2, 3, 4])

      assert_in_delta 1.0 / 15, values("deriv(lin[2m])").first, 1e-9
      assert_in_delta 4.0 + (60.0 / 15), values("predict_linear(lin[2m], 60)").first, 1e-6
    end

    test "over_time functions" do
      load("v", {}, [1, 2, 3, 4])

      assert_equal [10.0], values("sum_over_time(v[1m])")
      assert_equal [2.5], values("avg_over_time(v[1m])")
      assert_equal [1.0], values("min_over_time(v[1m])")
      assert_equal [4.0], values("max_over_time(v[1m])")
      assert_equal [4.0], values("count_over_time(v[1m])")
      assert_equal [4.0], values("last_over_time(v[1m])")
      assert_equal [1.0], values("present_over_time(v[1m])")
      assert_in_delta 2.5, values("quantile_over_time(0.5, v[1m])").first
      assert_in_delta 1.25, values("stdvar_over_time(v[1m])").first
      assert_in_delta Math.sqrt(1.25), values("stddev_over_time(v[1m])").first
      assert_equal [1.0], values("absent_over_time(missing[1m])")
      assert_equal [], vector("absent_over_time(v[1m])")
    end

    # ---------------------------------------------------------- operators

    test "arithmetic drops the metric name and comparisons filter unless bool" do
      load("x", {"i" => "1"}, [2])
      load("x", {"i" => "2"}, [8])

      assert_equal [[{"i" => "1"}, 4.0], [{"i" => "2"}, 16.0]], vector("x * 2")
      assert_equal [[{"i" => "1"}, 0.5], [{"i" => "2"}, 0.125]], vector("1 / x")
      assert_equal [[{"__name__" => "x", "i" => "2"}, 8.0]], vector("x > 5")
      assert_equal [[{"i" => "1"}, 0.0], [{"i" => "2"}, 1.0]], vector("x > bool 5")
      assert_in_delta(1.0, scalar("3 > bool 2"))
      assert_in_delta(8.0, scalar("2 ^ 3"))
      assert_in_delta(-1.0, scalar("-7 % 3"))
      assert_in_delta(2.0, scalar("7 % -5"))
      assert_predicate scalar("1 / 0"), :infinite?
      assert_predicate scalar("0 / 0"), :nan?
    end

    test "vector matching: one-to-one, on, ignoring, group_left and errors" do
      load("requests", {"method" => "get", "code" => "500"}, [24])
      load("requests", {"method" => "get", "code" => "200"}, [100])
      load("requests", {"method" => "post", "code" => "500"}, [6])
      load("requests", {"method" => "post", "code" => "200"}, [100])
      load("total", {"method" => "get"}, [124])
      load("total", {"method" => "post"}, [106])
      result = vector('requests{code="500"} / ignoring(code) total').sort_by { |m, _| m["method"] }

      assert_equal [[{"method" => "get"}, 24.0 / 124], [{"method" => "post"}, 6.0 / 106]], result
      result = vector('requests{code="500"} / on(method) total').sort_by { |m, _| m["method"] }

      assert_equal [{"method" => "get"}, {"method" => "post"}], result.map(&:first)

      result = vector("requests / ignoring(code) group_left total").sort_by { |m, _| [m["method"], m["code"]] }

      assert_equal 4, result.length
      assert_equal({"code" => "200", "method" => "get"}, result[0][0])
      assert_in_delta 100.0 / 124, result[0][1]

      error = assert_raises(Promql::EvalError) { vector("requests / ignoring(code) total") }
      assert_match(/many-to-one matching must be explicit/, error.message)

      assert_equal 2, vector('requests{code="500"} and on(method) total').length
      assert_equal 0, vector('requests{code="500"} unless on(method) total').length
      assert_equal 6, vector("requests or total").length
    end

    test "group_right carries labels from the many side" do
      load("a", {"k" => "1", "extra" => "x"}, [1])
      load("a", {"k" => "1", "extra" => "y"}, [2])
      load("b", {"k" => "1"}, [10])
      result = vector("b * on(k) group_right a").sort_by { |m, _| m["extra"] }

      assert_equal [[{"extra" => "x", "k" => "1"}, 10.0], [{"extra" => "y", "k" => "1"}, 20.0]], result
      # Labels listed in group_right() come from the "one" side; b has no
      # `extra`, so both results collapse onto the same labels -- an error,
      # exactly as in Prometheus.
      error = assert_raises(Promql::EvalError) { vector("b * on(k) group_right(extra) a") }
      assert_match(/grouping labels must ensure unique matches/, error.message)
    end

    # ---------------------------------------------------------- aggregations

    test "aggregations with by and without" do
      load("n", {"job" => "a", "instance" => "1"}, [1])
      load("n", {"job" => "a", "instance" => "2"}, [3])
      load("n", {"job" => "b", "instance" => "3"}, [10])

      assert_equal [[{}, 14.0]], vector("sum(n)")
      assert_equal([[{"job" => "a"}, 4.0], [{"job" => "b"}, 10.0]], vector("sum by (job) (n)").sort_by { |m, _| m["job"] })
      assert_equal([[{"job" => "a"}, 4.0], [{"job" => "b"}, 10.0]], vector("sum without (instance) (n)").sort_by { |m, _| m["job"] })
      assert_equal([[{"job" => "a"}, 2.0], [{"job" => "b"}, 10.0]], vector("avg by (job) (n)").sort_by { |m, _| m["job"] })
      assert_equal [[{}, 3.0]], vector("count(n)")
      assert_equal [[{}, 1.0]], vector("min(n)")
      assert_equal [[{}, 10.0]], vector("max(n)")
      assert_equal([[{"job" => "a"}, 1.0], [{"job" => "b"}, 1.0]], vector("group by (job) (n)").sort_by { |m, _| m["job"] })
      assert_in_delta 1.0, vector("stdvar by (job) (n)").find { |m, _| m["job"] == "a" }[1]
      assert_in_delta 3.0, vector("quantile(0.5, n)")[0][1]
      top = vector("topk(2, n)").map(&:last)

      assert_equal [10.0, 3.0], top
      assert_equal [1.0], vector("bottomk(1, n)").map(&:last)
      counts = vector("count_values(\"v\", n)").to_h { |m, c| [m["v"], c] }

      assert_equal({"1" => 1.0, "3" => 1.0, "10" => 1.0}, counts)
    end

    # ---------------------------------------------------------- functions

    test "histogram_quantile interpolates within the bucket" do
      {"0.1" => 10, "0.5" => 30, "1" => 40, "+Inf" => 40}.each do |le, count|
        load("d_bucket", {"le" => le}, [count])
      end
      # rank 0.5*40 = 20 lies in the (0.1, 0.5] bucket at (20-10)/20 -> 0.3
      assert_in_delta 0.3, values("histogram_quantile(0.5, d_bucket)").first, 1e-9
      assert_in_delta 0.1, values("histogram_quantile(0.25, d_bucket)").first, 1e-9
      assert_equal [1.0], values("histogram_quantile(1, d_bucket)")
      summed = vector("histogram_quantile(0.5, sum by (le) (d_bucket))")

  # ---------------------------------------------------------- functions

  test "histogram_quantile interpolates within the bucket" do
    {"0.1" => 10, "0.5" => 30, "1" => 40, "+Inf" => 40}.each do |le, count|
      load("d_bucket", {"le" => le}, [count])
    end
    # rank 0.5*40 = 20 lies in the (0.1, 0.5] bucket at (20-10)/20 -> 0.3
    assert_in_delta 0.3, values("histogram_quantile(0.5, d_bucket)").first, 1e-9
    assert_in_delta 0.1, values("histogram_quantile(0.25, d_bucket)").first, 1e-9
    assert_equal [1.0], values("histogram_quantile(1, d_bucket)")
    summed = vector("histogram_quantile(0.5, sum by (le) (d_bucket))")

    assert_equal [{}], summed.map(&:first)
    assert_in_delta 0.3, summed[0][1], 1e-9
  end

  test "label_replace, label_join, sort and clamp" do
    load("s", {"instance" => "host-1:9100"}, [3])
    load("s", {"instance" => "host-2:9100"}, [1])
    replaced = vector('label_replace(s, "host", "$1", "instance", "(.*):.*")').map { |m, _| m["host"] }.sort

    assert_equal %w[host-1 host-2], replaced
    joined = vector('label_join(s, "j", "-", "instance", "instance")').map { |m, _| m["j"] }.sort

    assert_equal ["host-1:9100-host-1:9100", "host-2:9100-host-2:9100"], joined
    assert_equal [1.0, 3.0], values("sort(s)")
    assert_equal [3.0, 1.0], values("sort_desc(s)")
    assert_equal [2.0, 2.0], values("clamp(s, 2, 2)")
    assert_equal [3.0, 2.0], values("clamp_min(s, 2)")
    assert_equal [2.0, 1.0], values("clamp_max(s, 2)")
    assert_equal [3.0, 1.0], values("round(s)")
    assert_equal [5.0, 0.0], values("round(s, 5)")
  end

  test "absent, scalar, vector, time and calendar functions" do
    assert_equal [[{"job" => "x"}, 1.0]], vector('absent(nothing{job="x"})')
    load("one", {}, [7])

    assert_equal [], vector("absent(one)")
    assert_in_delta(7.0, scalar("scalar(one)"))
    assert_equal [[{}, 2.0]], vector("vector(2)")
    assert_equal T0 / 1000.0, scalar("time()")
    assert_equal [T0 / 1000.0], values("timestamp(one)")
    utc = Time.at(T0 / 1000).utc

    assert_equal [utc.hour.to_f], values("hour()")
    assert_equal [utc.wday.to_f], values("day_of_week()")
    assert_equal [utc.year.to_f], values("year(vector(#{T0 / 1000}))")
    assert_in_delta Math::PI, scalar("pi()")
    assert_equal [Math.sqrt(7)], values("sqrt(one)")
    assert_predicate values("ln(vector(-1))").first, :nan?
  end

  test "subqueries evaluate the inner expression at each step" do
    load("sq", {}, [1, 2, 3, 4, 5])
    result = vector("max_over_time(sq[1m:15s])")

    assert_equal [5.0], result.map(&:last)
    # rate over a subquery of an instant expression
    rate = vector("sum_over_time((sq * 2)[1m:15s])").map(&:last)

    assert_equal [2 * (2 + 3 + 4 + 5).to_f], rate
  end

  # ---------------------------------------------------------- range queries

  test "query_range evaluates per step and formats like the HTTP API" do
    load("r", {"k" => "v"}, [1, 2, 3, 4, 5])
    result = @engine.query_range("r * 10", T0 - 60_000, T0, 30_000)

    assert_equal :matrix, result.type
    assert_equal [[T0 - 60_000, 10.0], [T0 - 30_000, 30.0], [T0, 50.0]], result.value[0].points
    api = result.to_api

    assert_equal "matrix", api["resultType"]
    assert_equal [[(T0 - 60_000) / 1000.0, "10"], [(T0 - 30_000) / 1000.0, "30"], [T0 / 1000.0, "50"]], api["result"][0]["values"]
    scalar_range = @engine.query_range("2 + 2", T0 - 30_000, T0, 30_000)

    assert_equal [4.0, 4.0], scalar_range.value[0].points.map(&:last)
    assert_raises(Promql::EvalError) { @engine.query_range("r[1m]", T0 - 30_000, T0, 30_000) }
  end

  test "parser rejects what Prometheus rejects" do
    ["sum(", "up offset", "rate(up)", "up and 1", "{}", '{job=~".*"}', "1 == 1", "topk(up)", "unknown_fn(up)",
     'label_replace(up, "a")', "up[5m] + 1"].each do |bad|
      assert_raises(Promql::ParseError, "#{bad.inspect} should not parse") { Promql::Parser.parse(bad) }
    end
    good = Promql::Parser.parse('sum by (job) (rate(http_requests_total{code=~"5.."}[5m] offset 1h)) > bool 0.1')

    assert_instance_of Promql::AST::BinaryExpr, good
    assert good.return_bool
    assert_equal 3_600_000, good.lhs.expr.args[0].selector.offset_ms
  end
end
