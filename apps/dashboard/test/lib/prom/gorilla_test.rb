# frozen_string_literal: true

require "test_helper"

class Prom::GorillaTest < ActiveSupport::TestCase
  def roundtrip(samples)
    encoder = Prom::Gorilla::Encoder.new
    samples.each { |t, v| encoder.append(t, v) }
    bytes = encoder.bytes
    decoded = Prom::Gorilla.decode(bytes)
    [bytes, decoded]
  end

  test "roundtrips regular scrape data compactly" do
    t0 = 1_700_000_000_000
    samples = 240.times.map { |i| [t0 + i * 15_000 + (i % 7 == 0 ? 3 : 0), 1000.0 + i] }
    bytes, decoded = roundtrip(samples)
    assert_equal samples, decoded
    assert_operator bytes.bytesize, :<, samples.length * 3, "about 1-2 bytes per sample, got #{bytes.bytesize}"
  end

  test "roundtrips floats with awkward bit patterns" do
    values = [0.0, -0.0, 1.0, -1.0, 3.14159, 1e-300, 1e300, 123_456_789.0, 0.1, 0.2, 0.30000000000000004,
              Float::INFINITY, -Float::INFINITY, 2.0**52, 5e-324, 42.0, 42.0, 42.0, 41.999]
    samples = values.each_with_index.map { |v, i| [1000 + i * 1000, v] }
    _, decoded = roundtrip(samples)
    assert_equal samples, decoded
  end

  test "NaN survives as NaN" do
    _, decoded = roundtrip([[1, 1.0], [2, Float::NAN], [3, 2.0]])
    assert decoded[1][1].nan?
    assert_equal [1, 1.0], decoded[0]
    assert_equal [3, 2.0], decoded[2]
  end

  test "single sample and two samples" do
    assert_equal [[5, 9.5]], roundtrip([[5, 9.5]]).last
    assert_equal [[5, 9.5], [65, 9.5]], roundtrip([[5, 9.5], [65, 9.5]]).last
    assert_equal [], Prom::Gorilla.decode([0].pack("n"))
  end

  test "irregular and large timestamp gaps use the wider delta-of-delta buckets" do
    t = 0
    samples = []
    [1, 1, 5000, 10_000, 70_000, 600_000, 10_000_000, 1, 1, 3_000_000_000].each_with_index do |gap, i|
      t += gap
      samples << [t, i.to_f]
    end
    _, decoded = roundtrip(samples)
    assert_equal samples, decoded
  end

  test "timestamps must not go backwards" do
    encoder = Prom::Gorilla::Encoder.new
    encoder.append(10, 1.0).append(20, 1.0)
    assert_raises(ArgumentError) { encoder.append(15, 1.0) }
  end

  test "counts and bounds are tracked" do
    encoder = Prom::Gorilla::Encoder.new
    encoder.append(100, 1.0).append(200, 2.0).append(300, 3.0)
    assert_equal 3, encoder.count
    assert_equal 100, encoder.min_time
    assert_equal 300, encoder.max_time
  end
end
