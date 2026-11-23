# frozen_string_literal: true

module Prom
  # A native histogram sample. Exponential schemas have separate bucket
  # maps for each sign. Custom schemas use the positive map for all buckets.
  class NativeHistogram
    class IncompatibleSchema < StandardError; end

    CUSTOM_SCHEMA = -53
    EMPTY_BOUNDS = [].freeze
    BOUNDARY_CODES = {negative: 1, positive: 0, zero: 3, custom: 0, custom_first: 3}.freeze
    BOUNDARY_MARKS = [["(", "]"], ["[", ")"], ["(", ")"], ["[", "]"]].freeze

    attr_reader :schema, :count, :sum, :zero_threshold, :zero_count, :negative, :positive, :gauge, :custom_bounds

    def initialize(schema:, count:, sum:, zero_threshold: 0.0, zero_count: 0.0, negative: {}, positive: {}, gauge: false, custom_bounds: EMPTY_BOUNDS)
      raise ArgumentError, "unsupported native histogram schema #{schema}" unless schema == CUSTOM_SCHEMA || (-4..8).cover?(schema)
      raise ArgumentError, "invalid native histogram zero threshold" unless zero_threshold.finite? && zero_threshold >= 0

      @schema = schema
      @custom_bounds = custom_bounds.frozen? ? custom_bounds : custom_bounds.dup.freeze
      validate_custom_bounds(zero_threshold, zero_count, negative, positive)
      @count = count.to_f
      @sum = sum.to_f
      @zero_threshold = zero_threshold
      @zero_count = zero_count.to_f
      @negative = negative.reject { |_, value| value.zero? }.freeze
      @positive = positive.reject { |_, value| value.zero? }.freeze
      @gauge = gauge
      freeze
    end

    def custom? = schema == CUSTOM_SCHEMA
    def average = sum / count
    def empty = build(count: 0, sum: 0, zero_count: 0, zero_threshold: 0.0, negative: {}, positive: {})

    def self.custom(count:, sum:, bounds:, buckets:, gauge: false)
      new(schema: CUSTOM_SCHEMA, count: count, sum: sum, positive: buckets, gauge: gauge, custom_bounds: bounds)
    end

    def variance
      mean = average
      buckets.sum do |kind, lower, upper, n|
        center = if custom?
                   (lower + upper) / 2
                 elsif kind == :zero
                   0.0
                 else
                   Math.sqrt(lower * upper) * (kind == :negative ? -1 : 1)
                 end
        n * ((center - mean)**2)
      end / count
    end

    def standard_deviation
      result = variance
      result.negative? ? Float::NAN : Math.sqrt(result)
    end

    def +(other) = combine(other, 1)
    def -(other) = combine(other, -1)
    def -@ = self * -1

    def *(other)
      build(count: count * other, sum: sum * other, zero_count: custom? ? 0.0 : zero_count * other,
            negative: negative.transform_values { |v| v * other }, positive: positive.transform_values { |v| v * other },
            gauge: gauge || other.negative?)
    end

    def /(other)
      if other.zero?
        build(count: count / other, sum: sum / other, zero_count: custom? ? 0.0 : zero_count / other,
              negative: {}, positive: {}, gauge: gauge || (1.0 / other).negative?)
      else
        self * (1.0 / other)
      end
    end

    def as_gauge = gauge ? self : build(gauge: true)

    def ==(other)
      other.is_a?(self.class) && schema == other.schema && zero_threshold == other.zero_threshold &&
        [count, sum, zero_count].pack("G3") == [other.count, other.sum, other.zero_count].pack("G3") &&
        negative == other.negative && positive == other.positive && custom_bounds == other.custom_bounds
    end

    def reset_from?(previous)
      return true if count < previous.count || custom? != previous.custom? || schema > previous.schema || zero_threshold < previous.zero_threshold

      if custom?
        bounds = custom_bounds & previous.custom_bounds
        return decreased?(custom_buckets_for(bounds), previous.custom_buckets_for(bounds))
      end

      projected = previous.project(schema, zero_threshold)
      return true if projected.zero_threshold != zero_threshold || zero_count < projected.zero_count

      decreased?(negative, projected.negative) || decreased?(positive, projected.positive)
    end

    def quantile(q)
      return -Float::INFINITY if q < 0
      return Float::INFINITY if q > 1
      return Float::NAN if q.nan? || count.zero?

      rank = q * count
      reverse = q >= 0.5 && !sum.nan?
      rank = (1 - q) * count if reverse
      ordered = buckets
      ordered.reverse! if reverse
      seen = 0.0
      ordered.each do |kind, lower, upper, n|
        next if n.zero?

        if seen + n >= rank
          fraction = (rank - seen) / n
          fraction = 1 - fraction if reverse
          return interpolate(kind, lower, upper, fraction)
        end
        seen += n
      end
      sum.nan? ? Float::NAN : (ordered.last&.[](2) || Float::NAN)
    end

    def fraction(lower, upper)
      return Float::NAN if count.zero? || lower.nan? || upper.nan?
      return 0.0 if lower >= upper

      included = buckets.sum do |kind, first, last, n|
        n * (rank_in_bucket(kind, first, last, upper) - rank_in_bucket(kind, first, last, lower))
      end
      included / count
    end

    def to_api
      result = {"count" => self.class.number_text(count), "sum" => self.class.number_text(sum)}
      rows = buckets.map do |kind, lower, upper, n|
        code = BOUNDARY_CODES.fetch(kind)
        [code, *[lower, upper, n].map { |v| self.class.number_text(v) }]
      end
      result["buckets"] = rows unless rows.empty?
      result
    end

    def to_s
      rendered = buckets.map do |kind, lower, upper, n|
        left, right = BOUNDARY_MARKS.fetch(BOUNDARY_CODES.fetch(kind))
        "#{left}#{self.class.number_text(lower)},#{self.class.number_text(upper)}#{right}:#{self.class.number_text(n)}"
      end
      fields = ["count:#{self.class.number_text(count)}", "sum:#{self.class.number_text(sum)}"]
      fields.concat(rendered)
      "{#{fields.join(", ")}}"
    end

    def self.number_text(value)
      return "NaN" if value.nan?
      return "+Inf" if value == Float::INFINITY
      return "-Inf" if value == -Float::INFINITY
      return value.to_i.to_s if value == value.floor && value.abs < 1e15

      value.to_s
    end

    protected

    def custom_buckets_for(bounds)
      return positive if bounds == custom_bounds

      positive.each_with_object(Hash.new(0.0)) do |(index, value), buckets|
        upper = index == custom_bounds.length ? Float::INFINITY : custom_bounds.fetch(index)
        new_index = bounds.bsearch_index { |bound| bound >= upper } || bounds.length
        buckets[new_index] += value
      end
    end

    def project(target_schema, threshold)
      return self if target_schema == schema && threshold == zero_threshold

      # Include the whole bucket if the new zero threshold intersects a
      # populated bucket after merging schemas.
      shift = schema - target_schema
      reduced = [negative, positive].map do |side|
        side.each_with_object(Hash.new(0.0)) do |(index, n), result|
          result[((index - 1) >> shift) + 1] += n
        end
      end
      if threshold.positive?
        reduced.each do |side|
          crossing = side.keys.find { |index| bucket_bound(index - 1, target_schema) < threshold && bucket_bound(index, target_schema) > threshold }
          threshold = bucket_bound(crossing, target_schema) if crossing
        end
      end
      total_zero = zero_count
      reduced.each do |side|
        side.delete_if do |index, n|
          inside = bucket_bound(index, target_schema) <= threshold
          total_zero += n if inside
          inside
        end
      end
      build(schema: target_schema, zero_threshold: threshold, zero_count: total_zero, negative: reduced[0], positive: reduced[1])
    end

    private

    def validate_custom_bounds(threshold, zero, negative, positive)
      unless custom?
        raise ArgumentError, "exponential histogram has custom bounds" unless custom_bounds.empty?

        return
      end
      unless threshold.zero? && zero.zero? && negative.empty? &&
             custom_bounds.all?(&:finite?) && custom_bounds.each_cons(2).all? { |a, b| a < b } &&
             positive.keys.all? { |index| (0..custom_bounds.length).cover?(index) }
        raise ArgumentError, "invalid custom histogram buckets"
      end
    end

    def combine(other, sign)
      raise IncompatibleSchema, "cannot combine custom and exponential histogram buckets" if custom? != other.custom?

      total_count = count + (sign * other.count)
      total_sum = sum + (sign * other.sum)
      result_gauge = sign.negative? || gauge || other.gauge
      if custom?
        bounds = custom_bounds & other.custom_bounds
        counts = merge_counts(custom_buckets_for(bounds), other.custom_buckets_for(bounds), sign)
        return self.class.custom(count: total_count, sum: total_sum, bounds: bounds, buckets: counts, gauge: result_gauge)
      end

      target_schema = [schema, other.schema].min
      threshold = [zero_threshold, other.zero_threshold].max
      a = project(target_schema, threshold)
      b = other.project(target_schema, threshold)
      while a.zero_threshold != b.zero_threshold
        threshold = [a.zero_threshold, b.zero_threshold].max
        a = a.project(target_schema, threshold)
        b = b.project(target_schema, threshold)
      end
      build(schema: target_schema, count: total_count, sum: total_sum, gauge: result_gauge,
            zero_threshold: threshold, zero_count: a.zero_count + (sign * b.zero_count),
            negative: merge_counts(a.negative, b.negative, sign), positive: merge_counts(a.positive, b.positive, sign))
    end

    def merge_counts(a, b, sign)
      result = a.dup
      b.each { |index, n| result[index] = result.fetch(index, 0.0) + (sign * n) }
      result
    end

    def decreased?(current, previous)
      previous.any? { |index, n| n > current.fetch(index, 0.0) }
    end

    def build(**changes)
      self.class.new(schema: schema, count: count, sum: sum, zero_threshold: zero_threshold, zero_count: zero_count,
                     negative: negative, positive: positive, gauge: gauge, custom_bounds: custom_bounds, **changes)
    end

    def buckets
      if custom?
        return positive.sort.map do |index, n|
          kind = index.zero? ? :custom_first : :custom
          lower = index.zero? ? -Float::INFINITY : custom_bounds.fetch(index - 1)
          upper = index == custom_bounds.length ? Float::INFINITY : custom_bounds.fetch(index)
          [kind, lower, upper, n]
        end
      end

      result = negative.sort.reverse_each.map do |index, n|
        [:negative, -bucket_bound(index, schema), -[zero_threshold, bucket_bound(index - 1, schema)].max, n]
      end
      result << [:zero, -zero_threshold, zero_threshold, zero_count] unless zero_count.zero?
      result.concat(positive.sort.map do |index, n|
        [:positive, [zero_threshold, bucket_bound(index - 1, schema)].max, bucket_bound(index, schema), n]
      end)
    end

    def effective_bounds(kind, lower, upper)
      return [lower, upper] unless kind == :zero

      lower = 0.0 if negative.empty? && !positive.empty?
      upper = 0.0 if positive.empty? && !negative.empty?
      [lower, upper]
    end

    def interpolate(kind, lower, upper, fraction)
      if custom?
        return upper if lower.infinite? && upper <= 0
        return lower if lower.finite? && upper.infinite?

        lower = 0.0 if lower.infinite?
        return lower + ((upper - lower) * fraction)
      end

      lower, upper = effective_bounds(kind, lower, upper)
      return lower if upper.infinite? || fraction.zero?
      return upper if lower.infinite? || fraction == 1
      return lower + ((upper - lower) * fraction) if kind == :zero || lower.zero? || upper.zero?

      if kind == :positive
        2.0**((Math.log2(lower) * (1 - fraction)) + (Math.log2(upper) * fraction))
      else
        -(2.0**((Math.log2(-lower) * (1 - fraction)) + (Math.log2(-upper) * fraction)))
      end
    end

    def rank_in_bucket(kind, lower, upper, value)
      lower, upper = effective_bounds(kind, lower, upper)
      # Prometheus' fraction calculation treats the bucket spanning zero
      # as nonnegative because custom buckets use positive-side storage.
      lower = 0.0 if custom? && lower <= 0 && upper >= 0
      return 0.0 if value <= lower
      return 1.0 if value >= upper
      return 1.0 if lower.infinite?
      return 0.0 if upper.infinite?
      return (value - lower) / (upper - lower) if custom? || kind == :zero || lower.zero? || upper.zero?

      log_lower = Math.log2(lower.abs)
      (Math.log2(value.abs) - log_lower) / (Math.log2(upper.abs) - log_lower)
    end

    def bucket_bound(index, schema)
      exponent = index * (2.0**-schema)
      return Float::MAX if exponent == 1024

      2.0**exponent
    end
  end
end
