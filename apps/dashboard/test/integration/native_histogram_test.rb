# frozen_string_literal: true

require "test_helper"
require "support/fake_cluster"
require "socket"

class NativeHistogramTest < ActionDispatch::IntegrationTest
  setup do
    @now = (Time.now.to_f * 1000).to_i
    @runtime, _, @dir = DashboardTestRuntime.build(now_ms: @now)
    @store = @runtime.store
    Dashboard::Runtime.configure(@runtime)
  end

  teardown do
    Dashboard::Runtime.configure(nil)
    @store.close unless @store_closed
    FileUtils.rm_rf(@dir)
  end

  test "negotiates, stores and queries a native histogram without losing legacy float samples" do
    at = @now - 15_000
    scraper = Prom::Scraper.new(@store, clock: -> { at })
    body = metric_family(count: 8, sum: 11.25, deltas: [4, -2])
    scrape_over_http(scraper, body) do |target|
      at = @now
      second = metric_family(count: 12, sum: 17.25, deltas: [7, -4])
      fresh_target = Prom::Target.new(job: target.job, instance: target.instance, labels: target.labels, url: target.url,
                                      fetch: -> { [200, second, Prom::ProtobufExposition::MEDIA_TYPE] })

      assert_equal "up", scraper.scrape(fresh_target).health
    end

    get "/api/v1/query", params: {query: "latency", time: @now / 1000.0}

    assert_response :success
    json = response.parsed_body
    point = json.dig("data", "result", 0, "histogram", 1)

    assert_equal "12", point["count"]
    assert_equal "17.25", point["sum"]
    assert_equal [[3, "-0.25", "0.25", "2"], [0, "1", "2", "7"], [0, "2", "4", "3"]], point["buckets"]
    assert_equal "seconds", scraper.metadata.dig("latency", 0, "unit")
    assert_equal ["1.4375"], instant_values("histogram_avg(latency)")
    assert_equal ["12"], instant_values("histogram_count(latency)")
    assert_equal ["17.25"], instant_values("histogram_sum(latency)")
    mean = 17.25 / 12
    variance = ((2 * (mean**2)) + (7 * ((Math.sqrt(2) - mean)**2)) + (3 * ((Math.sqrt(8) - mean)**2))) / 12

    assert_in_delta variance, instant_values("histogram_stdvar(latency)").first.to_f, 1e-12
    assert_in_delta Math.sqrt(variance), instant_values("histogram_stddev(latency)").first.to_f, 1e-12
    assert_in_delta 2**(4.0 / 7), instant_values("histogram_quantile(0.5, latency)").first.to_f, 1e-12
    assert_in_delta 9.0 / 12, instant_values("histogram_fraction(0, 2, latency)").first.to_f, 1e-12
    assert_equal ["1.5"], instant_values("histogram_avg(sum(rate(latency[30s])))")
    assert_equal [], instant_values("histogram_avg(requests_total)")
    assert_equal [], instant_values("sqrt(latency)")

    @store.flush

    assert_equal ["1.4375"], instant_values("histogram_avg(latency)")
    assert_equal ["123"], instant_values("sum(requests_total)")
    labels = json.dig("data", "result", 0, "metric")
    @store.append_batch([[labels, @now + 15_000, 2.0]])
    get "/api/v1/query_range", params: {query: "latency", start: @now / 1000.0, end: (@now + 15_000) / 1000.0, step: "15s"}

    assert_response :success
    range = response.parsed_body.dig("data", "result", 0)

    assert_equal [[(@now + 15_000) / 1000.0, "2"]], range.fetch("values")
    assert_equal [[@now / 1000.0, point]], range.fetch("histograms")

    get "/api/v1/query", params: {query: "rate(latency[30s])", time: (@now + 15_000) / 1000.0}

    assert_response :success
    assert_equal [], response.parsed_body.dig("data", "result")
    assert_match(/mix of histograms and floats/, response.parsed_body.fetch("warnings").first)
  end

  test "reopens native WAL records, recovers a torn tail, and preserves later samples through compaction" do
    labels = {"__name__" => "latency"}
    histogram = Prom::ProtobufExposition.parse(metric_family(count: 12, sum: 17.25, deltas: [7, -4])).first.samples.first.value
    t = @now - 45_000
    @store.append_batch([[labels, t, 1.0], [labels, t + 15_000, histogram]])
    @store.close
    @store_closed = true
    wal = File.join(@store.dir, "wal", "head.wal")
    File.open(wal, "ab") { |io| io.write("H\x00") }

    reopened = Tsdb::Store.new(@store.dir)
    engine = Promql::Engine.new(reopened)

    assert_equal histogram, engine.query("latency", t + 15_000).value.first.point.last
    reopened.append_batch([[labels, t + 30_000, Tsdb::Store::STALE_NAN], [labels, t + 45_000, histogram]])
    reopened.close
    reopened = nil

    reopened = Tsdb::Store.new(@store.dir)
    engine = Promql::Engine.new(reopened)

    assert_empty engine.query("latency", t + 30_000).value
    reopened.flush

    assert_equal %w[values histograms metric].sort, engine.query("latency[1m]", @now).to_api.dig("result", 0).keys.sort
  ensure
    reopened&.close
  end

  test "converts text and protobuf classic histograms, persists custom bounds, and reconciles layouts in PromQL" do
    t = @now - 15_000
    scraper = Prom::Scraper.new(@store, clock: -> { t }, convert_classic_histograms_to_nhcb: true, keep_classic_histograms: false)
    body = <<~TEXT
      # TYPE custom_latency histogram
      custom_latency_bucket{le="-1"} 2
      custom_latency_bucket{le="1"} 5
      custom_latency_bucket{le="4"} 8
      custom_latency_bucket{le="+Inf"} 10
      custom_latency_count 10
      custom_latency_sum 12
    TEXT
    content_type = "text/plain"
    target = Prom::Target.new(instance: "local", job: "custom", fetch: -> { [200, body, content_type] })

    assert_equal "up", scraper.scrape(target).health
    t = @now
    body = classic_protobuf
    content_type = Prom::ProtobufExposition::MEDIA_TYPE

    assert_equal "up", scraper.scrape(target).health
    assert_empty instant_values("custom_latency_bucket")
    assert_equal ["13"], instant_values("histogram_count(custom_latency)")
    original = "custom_latency @ #{(@now - 15_000) / 1000.0}"

    assert_equal ["1"], instant_values("histogram_quantile(0.5, #{original})")
    assert_in_delta 0.4, instant_values("histogram_fraction(0, 2, #{original})").first.to_f
    assert_in_delta 3.0 / 13, instant_values("histogram_fraction(-1, 1, custom_latency)").first.to_f

    get "/api/v1/query", params: {query: "rate(custom_latency[30s])", time: @now / 1000.0}

    assert_response :success
    assert_match(/mismatched custom buckets were reconciled during subtraction/, response.parsed_body.fetch("infos").first)
    buckets = response.parsed_body.dig("data", "result", 0, "histogram", 1, "buckets")

    assert_equal([[3, "-Inf", "-1"], [0, "1", "4"], [0, "4", "+Inf"]], buckets.map { |bucket| bucket.first(3) })
    assert_in_delta 7.0 / 3, instant_values("histogram_avg(rate(custom_latency[30s]))").first.to_f
    assert_equal ["0"], instant_values("resets(custom_latency[30s])")

    @store.close
    @store_closed = true
    reopened = Tsdb::Store.new(@store.dir)
    engine = Promql::Engine.new(reopened)

    assert_equal [-1.0, 1.0, 3.0, 4.0], engine.query("custom_latency", @now).value.first.point.last.custom_bounds
    reopened.flush

    assert_equal [-1.0, 1.0, 3.0, 4.0], engine.query("custom_latency", @now).value.first.point.last.custom_bounds

    exponential = Prom::ProtobufExposition.parse(metric_family(count: 12, sum: 17.25, deltas: [7, -4])).first.samples.first.value
    reopened.append_batch([[{"__name__" => "custom_latency", "instance" => "other"}, @now, exponential]])
    mixed = engine.query("sum(custom_latency)", @now)

    assert_empty mixed.value
    assert_match(/mix of histograms with exponential and custom buckets/, mixed.warnings.first)
  ensure
    reopened&.close
  end

  private

  def instant_values(query)
    get "/api/v1/query", params: {query: query, time: @now / 1000.0}

    assert_response :success
    response.parsed_body.dig("data", "result").map { |s| s.fetch("value").last }
  end

  def metric_family(count:, sum:, deltas:)
    pb = Prom::MetricsPb
    histogram = pb::Histogram.new(schema: 0, sample_count: count, sample_sum: sum, zero_threshold: 0.25, zero_count: 2,
                                  positive_span: [pb::BucketSpan.new(offset: 1, length: 2)], positive_delta: deltas)
    metric = pb::Metric.new(label: [pb::LabelPair.new(name: "route", value: "/api")], histogram: histogram)
    family = pb::MetricFamily.new(name: "latency", help: "Latency", unit: "seconds", type: :HISTOGRAM, metric: [metric])
    encoded = pb::MetricFamily.encode(family)
    raise "test message exceeded one-byte length encoding" if encoded.bytesize >= 128

    [encoded.bytesize].pack("C") + encoded
  end

  def classic_protobuf
    pb = Prom::MetricsPb
    buckets = [[-1, 3], [1, 6], [3, 8], [4, 10]].map do |bound, count|
      pb::Bucket.new(upper_bound: bound, cumulative_count: count)
    end
    histogram = pb::Histogram.new(sample_count: 13, sample_sum: 19, bucket: buckets)
    family = pb::MetricFamily.new(name: "custom_latency", type: :HISTOGRAM, metric: [pb::Metric.new(histogram: histogram)])
    encoded = pb::MetricFamily.encode(family)
    raise "test message exceeded one-byte length encoding" if encoded.bytesize >= 128

    [encoded.bytesize].pack("C") + encoded
  end

  def scrape_over_http(scraper, body)
    server = TCPServer.new("127.0.0.1", 0)
    request = Queue.new
    thread = Thread.new do
      socket = server.accept
      begin
        headers = +""
        while (line = socket.gets) && line != "\r\n"
          headers << line
        end
        request << headers
        socket.write("HTTP/1.1 200 OK\r\n",
                     "Content-Type: #{Prom::ProtobufExposition::MEDIA_TYPE}; encoding=delimited\r\n",
                     "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n")
        socket.write(body)
      ensure
        socket.close
      end
    end
    url = "http://127.0.0.1:#{server.addr[1]}/metrics"
    targets = Prom::Targets.new(client: nil)
    target = Prom::Target.new(job: "sample", instance: "localhost", url: url, fetch: -> { targets.send(:plain_http_fetch, url) })

    assert_equal "up", scraper.scrape(target).health
    assert_match(/accept:.*proto=io\.prometheus\.client\.MetricFamily/i, request.pop(true))
    yield target
  ensure
    server&.close
    thread&.join(3)
  end
end
