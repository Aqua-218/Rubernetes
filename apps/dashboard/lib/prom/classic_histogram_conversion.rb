# frozen_string_literal: true

require_relative "exposition"
require_relative "native_histogram"

module Prom
  # Classic exposition carries one cumulative time series per bucket.
  # Convert each label set to a native histogram with absolute bucket counts.
  module ClassicHistogramConversion
    module_function

    def samples(family, convert:, keep_classic:)
      return family.samples unless %w[histogram gaugehistogram].include?(family.type)

      native = family.samples.select { |sample| sample.value.is_a?(NativeHistogram) }.to_h { |sample| [sample.labels, true] }
      groups = {}
      retained = family.samples.select do |sample|
        part = component(family.name, sample)
        next true unless part

        key, boundary = part
        if native.key?(key)
          keep_classic
        elsif convert
          group = (groups[key] ||= {})
          group[boundary] ||= sample
          keep_classic
        else
          true
        end
      end

      groups.each do |labels, parts|
        histogram = build(parts, gauge: family.type == "gaugehistogram")
        next unless histogram

        retained << Exposition::Sample.new(name: family.name, labels: labels, value: histogram, timestamp_ms: parts.values.first.timestamp_ms)
      end
      retained
    end

    def component(name, sample)
      case sample.name
      when "#{name}_count" then [sample.labels, :count]
      when "#{name}_sum" then [sample.labels, :sum]
      when "#{name}_bucket"
        boundary = sample.labels["le"]
        return unless boundary

        value = parse_boundary(boundary)
        return if value.nan?

        [sample.labels.reject { |key, _| key == "le" }, value]
      end
    rescue ArgumentError
      nil
    end

    def parse_boundary(value)
      case value
      when "+Inf", "Inf" then Float::INFINITY
      when "-Inf" then -Float::INFINITY
      else Float(value)
      end
    end

    def build(parts, gauge:)
      bounds = parts.keys.grep(Float).sort
      count = parts[:count]&.value || parts[bounds.last]&.value || 0.0
      previous = 0.0
      buckets = {}
      infinity = parts[Float::INFINITY]&.value || count
      return nil unless count.finite? && count >= 0 && infinity == count

      bounds.delete(Float::INFINITY)
      bounds.each_with_index do |bound, index|
        current = parts.fetch(bound).value
        return nil unless bound.finite? && current.finite? && current >= previous && current <= count

        buckets[index] = current - previous
        previous = current
      end
      buckets[bounds.size] = count - previous
      NativeHistogram.custom(count: count, sum: parts[:sum]&.value || 0.0, bounds: bounds, buckets: buckets, gauge: gauge)
    end
  end
end
