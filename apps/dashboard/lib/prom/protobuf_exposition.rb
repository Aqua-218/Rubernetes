# frozen_string_literal: true

require "stringio"
require_relative "exposition"
require_relative "metrics_pb"
require_relative "native_histogram"

module Prom
  # Prometheus' binary scrape protocol is a stream of length-prefixed
  # client_model MetricFamily messages.
  module ProtobufExposition
    MEDIA_TYPE = "application/vnd.google.protobuf"
    ACCEPT = "#{MEDIA_TYPE};proto=io.prometheus.client.MetricFamily;encoding=delimited, text/plain;version=0.0.4;q=0.8".freeze

    module_function

    def parse(body)
      io = StringIO.new(body.b)
      families = []
      until io.eof?
        length = read_length(io)
        raise Exposition::ParseError, "truncated MetricFamily" if length > io.size - io.pos

        family = MetricsPb::MetricFamily.decode(io.read(length))
        name = family.name
        raise Exposition::ParseError, "invalid metric name #{name.inspect}" unless Exposition::NAME.match?(name)

        samples = family.metric.flat_map { |metric| samples_for(family, metric) }
        type = family.type.to_s.downcase.delete("_")
        families << Exposition::Family.new(name: name, type: type, help: family.help, unit: family.unit, samples: samples)
      end
      families
    rescue Google::Protobuf::ParseError, ArgumentError => e
      raise Exposition::ParseError, e.message
    end

    def read_length(io)
      length = 0
      5.times do |i|
        byte = io.getbyte
        break if byte.nil? || (i == 4 && byte > 15)

        length |= (byte & 127) << (7 * i)
        return length if byte < 128
      end
      raise Exposition::ParseError, "invalid MetricFamily length"
    end

    def samples_for(family, metric)
      labels = metric.label.to_h { |label| [label.name, label.value] }
      name = family.name
      raise Exposition::ParseError, "invalid labels for #{name}" if labels.length != metric.label.size || labels.key?("__name__") || labels.key?("")

      sample = lambda do |metric_name, value, tags = labels|
        Exposition::Sample.new(name: metric_name, value: value, labels: tags, timestamp_ms: metric.timestamp_ms)
      end

      case family.type
      when :HISTOGRAM, :GAUGE_HISTOGRAM
        histogram = metric.histogram || raise(Exposition::ParseError, "missing histogram for #{name}")
        histogram_samples(name, histogram, labels, sample, gauge: family.type == :GAUGE_HISTOGRAM)
      when :SUMMARY
        summary = metric.summary || raise(Exposition::ParseError, "missing summary for #{name}")
        [sample.call("#{name}_count", summary.sample_count.to_f), sample.call("#{name}_sum", summary.sample_sum)] +
          summary.quantile.map { |q| sample.call(name, q.value, labels.merge("quantile" => label_number(q.quantile))) }
      when :COUNTER, :GAUGE, :UNTYPED
        value = metric.public_send(family.type.to_s.downcase)
        raise Exposition::ParseError, "missing #{family.type.to_s.downcase} for #{name}" unless value

        [sample.call(name, value.value)]
      else
        raise Exposition::ParseError, "unknown metric type #{family.type.inspect}"
      end
    end

    def histogram_samples(name, histogram, labels, sample, gauge:)
      native = !histogram.negative_span.empty? || !histogram.positive_span.empty? || histogram.zero_threshold.positive? ||
               histogram.zero_count.positive? || histogram.zero_count_float.positive?
      rows = native ? [sample.call(name, native_histogram(histogram, gauge: gauge))] : []
      return rows if native && histogram.bucket.empty?

      count = count_value(histogram.sample_count, histogram.sample_count_float)
      rows << sample.call("#{name}_count", count)
      rows << sample.call("#{name}_sum", histogram.sample_sum)
      histogram.bucket.each do |bucket|
        bucket_count = count_value(bucket.cumulative_count, bucket.cumulative_count_float)
        rows << sample.call("#{name}_bucket", bucket_count, labels.merge("le" => label_number(bucket.upper_bound)))
      end
      rows << sample.call("#{name}_bucket", count, labels.merge("le" => "+Inf")) unless histogram.bucket.any? { |bucket| bucket.upper_bound == Float::INFINITY }
      rows
    end

    def count_value(integer, float)
      float.zero? ? integer.to_f : float
    end

    def label_number(number)
      return NativeHistogram.number_text(number) unless number.finite?

      text = number.to_s
      text.sub(".0e", "e")
    end

    def native_histogram(histogram, gauge:)
      raise Exposition::ParseError, "unsupported protobuf native histogram schema #{histogram.schema}" unless (-4..8).cover?(histogram.schema)

      floats = !histogram.negative_count.empty? || !histogram.positive_count.empty? ||
               histogram.sample_count_float.positive? || histogram.zero_count_float.positive?
      negative = read_buckets(histogram.negative_span, histogram.negative_delta, histogram.negative_count, floats)
      positive = read_buckets(histogram.positive_span, histogram.positive_delta, histogram.positive_count, floats)
      NativeHistogram.new(schema: histogram.schema, sum: histogram.sample_sum, zero_threshold: histogram.zero_threshold,
                          count: floats ? histogram.sample_count_float : histogram.sample_count,
                          zero_count: floats ? histogram.zero_count_float : histogram.zero_count,
                          negative: negative, positive: positive, gauge: gauge)
    end

    def read_buckets(spans, deltas, counts, floats)
      values = floats ? counts : deltas
      unless spans.sum(&:length) == values.size && (floats ? deltas.empty? : counts.empty?)
        raise Exposition::ParseError, "native histogram bucket spans do not match counts"
      end

      index = 0
      position = 0
      count = 0
      spans.each_with_object({}) do |span, result|
        index += span.offset
        span.length.times do
          count = floats ? values[position] : count + values[position]
          raise Exposition::ParseError, "invalid native histogram bucket count" unless count.finite? && count >= 0

          result[index] = count.to_f
          index += 1
          position += 1
        end
      end
    end
  end
end
