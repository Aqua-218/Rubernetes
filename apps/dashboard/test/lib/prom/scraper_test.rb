# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "socket"

class Prom::ScraperTest < ActiveSupport::TestCase
  M = Tsdb::Store::Matcher

  def setup
    @dir = Dir.mktmpdir("scraper")
    @store = Tsdb::Store.new(@dir)
    @now = 1_700_000_000_000
    @scraper = Prom::Scraper.new(@store, timeout_seconds: 2, clock: -> { @now })
  end

  def teardown
    @store.close
    FileUtils.rm_rf(@dir)
  end

  def target(body, job: "test", instance: "t:1", labels: {}, status: 200, &block)
    fetch = block || -> { [status, body] }
    Prom::Target.new(job: job, instance: instance, labels: labels, url: "http://#{instance}/metrics", fetch: fetch)
  end

  def value_of(name, extra = {})
    matchers = [M.new(name: "__name__", op: "=", value: name)] + extra.map { |k, v| M.new(name: k, op: "=", value: v) }
    @store.query(matchers, 0, @now + 1).map { |series, points| [series.labels, points.last] }
  end

  test "samples get job and instance labels, conflicts become exported_" do
    body = "# TYPE a counter\na{path=\"/x\",job=\"inner\"} 5\nb 1\n"
    status = @scraper.scrape(target(body, labels: {"node" => "worker-0"}))
    assert_equal "up", status.health
    assert_equal 2, status.samples
    a = value_of("a")
    assert_equal 1, a.length
    assert_equal({"__name__" => "a", "path" => "/x", "job" => "test", "exported_job" => "inner", "instance" => "t:1", "node" => "worker-0"}, a[0][0])
    assert_equal 5.0, a[0][1][1]
    up = value_of("up")
    assert_equal [1.0], up.map { |_, point| point[1] }
    assert_equal({"__name__" => "up", "job" => "test", "instance" => "t:1", "node" => "worker-0"}, up[0][0])
    assert_equal [2.0], value_of("scrape_samples_scraped").map { |_, p| p[1] }
    assert_equal [2.0], value_of("scrape_series_added").map { |_, p| p[1] }
  end

  test "a series that disappears gets a stale marker and up goes to 0 on failure" do
    @scraper.scrape(target("a 1\nb 2\n"))
    @now += 15_000
    @scraper.scrape(target("a 2\n"))
    b = value_of("b")[0][1]
    assert Tsdb::Store.stale_marker?(b[1])
    assert_equal @now, b[0]
    assert_equal [0.0], value_of("scrape_series_added").map { |_, p| p[1] }

    @now += 15_000
    status = @scraper.scrape(target(nil, status: 500))
    assert_equal "down", status.health
    assert_match(/HTTP status 500/, status.last_error)
    assert_equal 0.0, value_of("up")[0][1][1]
    assert Tsdb::Store.stale_marker?(value_of("a")[0][1][1])

    @now += 15_000
    failing = target(nil) { raise Errno::ECONNREFUSED, "connection refused" }
    status = @scraper.scrape(failing)
    assert_equal "down", status.health
    assert_match(/ECONNREFUSED/, status.last_error)
  end

  test "parse errors and timeouts are recorded as failures" do
    status = @scraper.scrape(target("this is not{ metrics\n"))
    assert_equal "down", status.health
    assert_match(/parse error/, status.last_error)
    slow = target(nil) { sleep 3; [200, "a 1\n"] }
    status = @scraper.scrape(slow)
    assert_match(/deadline exceeded/, status.last_error)
  end

  test "scrape_all runs targets concurrently and retires targets that vanish" do
    first = target("a 1\n", instance: "one:1")
    second = target("a 2\n", instance: "two:1")
    @scraper.scrape_all([first, second])
    assert_equal 2, value_of("a").length
    @now += 15_000
    @scraper.scrape_all([first])
    two = value_of("a", "instance" => "two:1")[0][1]
    assert Tsdb::Store.stale_marker?(two[1])
    assert Tsdb::Store.stale_marker?(value_of("up", "instance" => "two:1")[0][1][1])
    assert_equal ["one:1"], @scraper.statuses.values.map { |s| s.target.instance }
  end

  test "scrapes a real HTTP endpoint and queries it through the engine" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    thread = Thread.new do
      loop do
        client = server.accept
        client.gets
        while (line = client.gets) && !line.strip.empty?; end
        body = "# TYPE requests_total counter\nrequests_total{code=\"200\"} 42\nrequests_total{code=\"500\"} 1\n"
        client.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
        client.close
      end
    rescue IOError
      nil
    end
    targets = Prom::Targets.new(client: Object.new, cluster_json: {})
    t = Prom::Target.new(job: "http", instance: "127.0.0.1:#{port}", labels: {}, url: "http://127.0.0.1:#{port}/metrics",
                         fetch: -> { targets.send(:plain_http_fetch, "http://127.0.0.1:#{port}/metrics") })
    status = @scraper.scrape(t)
    assert_equal "up", status.health, status.last_error.to_s
    engine = Promql::Engine.new(@store, now: -> { @now })
    result = engine.query("sum(requests_total)")
    assert_equal [43.0], result.value.map { |s| s.point[1] }
    assert_equal [1.0], engine.query('up{job="http"}').value.map { |s| s.point[1] }
  ensure
    server&.close
    thread&.kill
  end

  test "collector rounds discover, scrape, evaluate and maintain" do
    calls = 0
    targets = -> { calls += 1; [target("gauge #{calls}\n")] }
    evaluated = []
    rules = Object.new
    rules.define_singleton_method(:evaluate) { |_engine, now| evaluated << now }
    collector = Prom::Collector.new(store: @store, targets: targets, scraper: @scraper, rules: rules,
                                    interval_seconds: 15, clock: -> { @now })
    collector.round
    @now += 15_000
    collector.round
    assert_equal 2, calls
    assert_equal 2, evaluated.length
    assert_equal [1.0, 2.0], @store.samples(@store.select_series([M.new(name: "__name__", op: "=", value: "gauge")]).first.id, 0, @now + 1).map(&:last)
    assert_equal 1, collector.targets.length
  end
end
