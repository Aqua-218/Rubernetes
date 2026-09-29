# frozen_string_literal: true

require "test_helper"

class Prom::ExpositionTest < ActiveSupport::TestCase
  DOC = <<~TEXT
    # HELP http_requests_total The total number of HTTP requests.
    # TYPE http_requests_total counter
    http_requests_total{method="post",code="200"} 1027 1395066363000
    http_requests_total{method="post",code="400"}    3 1395066363000

    # Escaping in label values:
    msdos_file_access_time_seconds{path="C:\\\\DIR\\\\FILE.TXT",error="Cannot find file:\\n\\"FILE.TXT\\""} 1.458255915e9

    # Minimalistic line:
    metric_without_timestamp_and_labels 12.47

    # A weird metric from before the epoch:
    something_weird{problem="division by zero"} +Inf -3982045

    # A histogram, which has a pretty complex representation in the text format:
    # HELP http_request_duration_seconds A histogram of the request duration.
    # TYPE http_request_duration_seconds histogram
    http_request_duration_seconds_bucket{le="0.05"} 24054
    http_request_duration_seconds_bucket{le="0.1"} 33444
    http_request_duration_seconds_bucket{le="+Inf"} 144320
    http_request_duration_seconds_sum 53423
    http_request_duration_seconds_count 144320

    # Finally a summary, which has a complex representation, too:
    # HELP rpc_duration_seconds A summary of the RPC duration in seconds.
    # TYPE rpc_duration_seconds summary
    rpc_duration_seconds{quantile="0.01"} 3102
    rpc_duration_seconds{quantile="0.99"} 76656
    rpc_duration_seconds_sum 1.7560473e+07
    rpc_duration_seconds_count 2693
  TEXT

  test "parses the reference document from the exposition format specification" do
    families = Prom::Exposition.parse(DOC)
    by_name = families.to_h { |family| [family.name, family] }
    assert_equal %w[http_requests_total msdos_file_access_time_seconds metric_without_timestamp_and_labels something_weird
                    http_request_duration_seconds rpc_duration_seconds], families.map(&:name)

    requests = by_name["http_requests_total"]
    assert_equal "counter", requests.type
    assert_equal "The total number of HTTP requests.", requests.help
    assert_equal 2, requests.samples.length
    assert_equal({"method" => "post", "code" => "200"}, requests.samples[0].labels)
    assert_equal 1027.0, requests.samples[0].value
    assert_equal 1_395_066_363_000, requests.samples[0].timestamp_ms

    msdos = by_name["msdos_file_access_time_seconds"].samples[0]
    assert_equal "C:\\DIR\\FILE.TXT", msdos.labels["path"]
    assert_equal "Cannot find file:\n\"FILE.TXT\"", msdos.labels["error"]
    assert_in_delta 1.458255915e9, msdos.value

    weird = by_name["something_weird"].samples[0]
    assert_equal Float::INFINITY, weird.value
    assert_equal(-3_982_045, weird.timestamp_ms)

    histogram = by_name["http_request_duration_seconds"]
    assert_equal "histogram", histogram.type
    assert_equal 5, histogram.samples.length
    assert_equal %w[http_request_duration_seconds_bucket http_request_duration_seconds_sum http_request_duration_seconds_count],
                 histogram.samples.map(&:name).uniq
    assert_equal "+Inf", histogram.samples[2].labels["le"]

    summary = by_name["rpc_duration_seconds"]
    assert_equal "summary", summary.type
    assert_equal({"quantile" => "0.99"}, summary.samples[1].labels)
    assert_equal 2693.0, summary.samples.last.value
  end

  test "flat samples keep component names for storage" do
    samples = Prom::Exposition.samples(DOC)
    assert_equal 14, samples.length
    assert_includes samples.map(&:name), "http_request_duration_seconds_bucket"
  end

  test "NaN, negative infinity, EOF marker and unknown comments" do
    doc = "# random comment\nm_nan 1 NaN\n"
    assert_raises(Prom::Exposition::ParseError) { Prom::Exposition.parse(doc) }
    doc = "a NaN\nb -Inf\n# EOF\nignored 1\n"
    families = Prom::Exposition.parse(doc)
    assert_equal %w[a b], families.map(&:name)
    assert families[0].samples[0].value.nan?
    assert_equal(-Float::INFINITY, families[1].samples[0].value)
  end

  test "rejects malformed lines" do
    assert_raises(Prom::Exposition::ParseError) { Prom::Exposition.parse("1bad_name 1\n") }
    assert_raises(Prom::Exposition::ParseError) { Prom::Exposition.parse("m{a=\"x\" 1\n") }
    assert_raises(Prom::Exposition::ParseError) { Prom::Exposition.parse("m{a=\"x\"} abc\n") }
    assert_raises(Prom::Exposition::ParseError) { Prom::Exposition.parse("# TYPE m bogus\n") }
  end

  test "parses real Rubernetes API server and kubelet scrapes" do
    apiserver = File.expand_path("../../fixtures/apiserver_metrics.txt", __dir__)
    kubelet = File.expand_path("../../fixtures/kubelet_metrics.txt", __dir__)
    families = Prom::Exposition.parse(File.read(apiserver))
    assert_operator families.sum { |f| f.samples.length }, :>, 2000
    assert_includes families.map(&:type), "histogram"
    assert families.all? { |family| family.samples.all? { |sample| sample.value.is_a?(Float) } }

    node = Prom::Exposition.parse(File.read(kubelet))
    assert_operator node.length, :>, 50
    assert_operator node.map(&:type).tally.fetch("histogram", 0), :>, 5
    assert_operator node.sum { |f| f.samples.length }, :>, 1000
  end
end
