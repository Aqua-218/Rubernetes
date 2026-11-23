# frozen_string_literal: true

require_relative "cron_time_zone"

module Rubernetes
  # Kubernetes v1.36 uses the five-field robfig/cron v3.0.1 standard parser.
  module CronSchedule
    class ParseError < ArgumentError; end

    STAR = 1 << 63
    FIELD_BOUNDS = [0..59, 0..23, 1..31, 1..12, 0..6].freeze
    MONTHS = %w[jan feb mar apr may jun jul aug sep oct nov dec].each_with_index.to_h { |name, index| [name, index + 1] }.freeze
    WEEKDAYS = %w[sun mon tue wed thu fri sat].each_with_index.to_h.freeze
    FIELD_NAMES = [nil, nil, nil, MONTHS, WEEKDAYS].freeze
    DESCRIPTORS = {
      "@yearly" => "0 0 1 1 *", "@annually" => "0 0 1 1 *", "@monthly" => "0 0 1 * *",
      "@weekly" => "0 0 * * 0", "@daily" => "0 0 * * *", "@midnight" => "0 0 * * *", "@hourly" => "0 * * * *"
    }.freeze
    NANOSECONDS_PER_SECOND = 1_000_000_000
    DURATION_LIMIT = 1 << 63
    DURATION_UNITS = {
      "ns" => 1, "us" => 1_000, "µs" => 1_000, "μs" => 1_000, "ms" => 1_000_000,
      "s" => NANOSECONDS_PER_SECOND, "m" => 60 * NANOSECONDS_PER_SECOND, "h" => 3_600 * NANOSECONDS_PER_SECOND
    }.freeze

    module_function

    def parse(expression, time_zone: nil)
      raise ParseError, "empty spec string" if expression.empty?

      expression, zone = extract_zone(expression, time_zone)
      if expression.start_with?("@every ")
        duration = duration_nanoseconds(expression.delete_prefix("@every "), expression)
        return Interval.new([duration.div(NANOSECONDS_PER_SECOND), 1].max)
      end
      expression = DESCRIPTORS.fetch(expression) { raise ParseError, "unrecognized descriptor: #{expression}" } if expression.start_with?("@")

      fields = expression.scan(/[^[:space:]]+/)
      raise ParseError, "expected exactly 5 fields, found #{fields.length}: [#{fields.join(" ")}]" unless fields.length == FIELD_BOUNDS.length

      masks = fields.each_with_index.map do |field, index|
        field.split(",").reject(&:empty?).reduce(0) do |mask, part|
          mask | range_mask(part, FIELD_BOUNDS.fetch(index), FIELD_NAMES[index])
        end
      end
      Calendar.new(masks, zone)
    end

    def extract_zone(expression, time_zone)
      if expression.start_with?("TZ=", "CRON_TZ=")
        finish = expression.index(" ")
        start = expression.index("=") + 1
        raise ParseError, "invalid schedule format: runtime error: slice bounds out of range [:-1]" unless finish

        name = expression[start...finish]
        zone = embedded_zone(name)
        [trim_space(expression[finish..]), zone]
      elsif time_zone
        [trim_space(expression), time_zone == "Local" ? nil : CronTimeZone.resolve(time_zone)]
      else
        [expression, nil]
      end
    rescue TZInfo::InvalidTimezoneIdentifier
      raise ParseError, "provided bad location #{time_zone}: unknown time zone #{time_zone}"
    end

    def embedded_zone(name)
      return nil if ["", "Local"].include?(name)
      raise ParseError, "provided bad location #{name}: time: invalid location name" if name.include?("..") || name.start_with?("/", "\\")

      TZInfo::Timezone.get(name)
    rescue TZInfo::InvalidTimezoneIdentifier
      raise ParseError, "provided bad location #{name}: unknown time zone #{name}"
    end

    def trim_space(expression)
      expression.gsub(/\A[[:space:]]+|[[:space:]]+\z/, "")
    end

    def range_mask(part, bounds, names)
      range, step_text, *other = part.split("/", -1)
      low, high, *extra = range.split("-", -1)
      wild = ["*", "?"].include?(low)
      if wild
        first = bounds.begin
        last = bounds.end
      else
        first = names&.fetch(low.to_s.downcase, nil) || field_integer(low.to_s)
        raise ParseError, "too many hyphens: #{part}" unless extra.empty?

        last = high.nil? ? first : (names&.fetch(high.downcase, nil) || field_integer(high))
      end
      raise ParseError, "too many slashes: #{part}" unless other.empty?

      step = step_text.nil? ? 1 : field_integer(step_text)
      last = bounds.end if step_text && high.nil?
      raise ParseError, "beginning of range (#{first}) below minimum (#{bounds.begin}): #{part}" if first < bounds.begin
      raise ParseError, "end of range (#{last}) above maximum (#{bounds.end}): #{part}" if last > bounds.end
      raise ParseError, "beginning of range (#{first}) beyond end of range (#{last}): #{part}" if first > last
      raise ParseError, "step of range should be a positive number: #{part}" if step.zero?

      initial_mask = wild && step == 1 ? STAR : 0
      (first..last).step(step).reduce(initial_mask) { |mask, value| mask | (1 << value) }
    end

    def field_integer(text)
      if text.match?(/\A[+-]?\d+\z/)
        digits = text.sub(/\A[+-]?0*/, "")
        value = digits.to_i if digits.length <= 19
        value = -value if value && text.start_with?("-")
        if value.nil? || value < -DURATION_LIMIT || value >= DURATION_LIMIT
          problem = "value out of range"
        elsif value.negative?
          raise ParseError, "negative number (#{value}) not allowed: #{text}"
        else
          return value
        end
      else
        problem = "invalid syntax"
      end
      raise ParseError, "failed to parse int from #{text}: strconv.Atoi: parsing #{text.inspect}: #{problem}"
    end

    def duration_nanoseconds(value, expression)
      negative = value.start_with?("-")
      rest = value.sub(/\A[+-]/, "")
      return 0 if rest == "0"

      total = 0
      loop do
        match = /\A(\d*)(?:\.(\d*))?([^0-9.]*)/.match(rest)
        whole, fraction, suffix = match.captures
        digits = whole.sub(/\A0+/, "")
        integer = digits.length <= 19 ? digits.to_i : nil
        duration_error(expression, "invalid duration", value) if integer.nil? || integer > DURATION_LIMIT
        duration_error(expression, "invalid duration", value) if whole.empty? && fraction.to_s.empty?
        duration_error(expression, "missing unit in duration", value) if suffix.empty?

        unit = DURATION_UNITS[suffix]
        duration_error(expression, "unknown unit #{duration_quote(suffix)} in duration", value) unless unit

        total += (integer * unit) + fractional_nanoseconds(fraction, unit)
        duration_error(expression, "invalid duration", value) if total > DURATION_LIMIT

        rest = match.post_match
        break if rest.empty?
      end
      return -total if negative

      duration_error(expression, "invalid duration", value) if total == DURATION_LIMIT
      total
    end

    def fractional_nanoseconds(fraction, unit)
      return 0 if fraction.nil?

      numerator = 0
      scale = 1.0
      fraction.each_byte do |digit|
        break if numerator > (DURATION_LIMIT - 1) / 10

        next_numerator = (numerator * 10) + digit - 48
        break if next_numerator > DURATION_LIMIT

        numerator = next_numerator
        scale *= 10
      end
      (numerator * (unit / scale)).to_i
    end

    def duration_error(expression, message, value)
      raise ParseError, "failed to parse duration #{expression}: time: #{message} #{duration_quote(value)}"
    end

    def duration_quote(value)
      escaped = value.b.gsub(/[^\x20-\x7f]|["\\]/) do |byte|
        byte.ord.between?(32, 127) ? "\\#{byte}" : format("\\x%02x", byte.ord)
      end
      %("#{escaped}")
    end

    class Interval
      def initialize(seconds)
        @seconds = seconds
      end

      def next_after(time)
        time + (@seconds - time.subsec)
      end
    end

    class Calendar
      def initialize(masks, zone)
        @minute, @hour, @day, @month, @weekday = masks
        @zone = zone
      end

      def next_after(time)
        return nil if @minute.zero? || @hour.zero? || @month.zero?

        original_zone = input_zone(time)
        zone = @zone || original_zone
        cursor = local_time(Time.at(time.to_i + 1), zone)
        year_limit = cursor.year + 5
        advanced = false
        while cursor.year <= year_limit
          return local_time(cursor, original_zone) if matches?(cursor)

          cursor = advance(cursor, zone, advanced)
          advanced = true
        end
        nil
      end

      private

      def matches?(time)
        selected?(@month, time.month) && day_matches?(time) && selected?(@hour, time.hour) &&
          selected?(@minute, time.min) && time.sec.zero?
      end

      # Advance at the first mismatched calendar field. Months and days are
      # wall-clock increments. Hours, minutes and seconds are elapsed time,
      # so skipped and repeated DST hours follow the same ordering as Go.
      def advance(time, zone, advanced)
        if !selected?(@month, time.month)
          time = wall_time(zone, time.year, time.month, 1) unless advanced
          next_month = (time.month % 12) + 1
          wall_time(zone, time.year + (next_month == 1 ? 1 : 0), next_month, time.day, time.hour, time.min, time.sec)
        elsif !day_matches?(time)
          time = wall_time(zone, time.year, time.month, time.day) unless advanced
          next_day = wall_time(zone, time.year, time.month, time.day + 1, time.hour, time.min, time.sec)
          shift = next_day.hour > 12 ? 24 - next_day.hour : -next_day.hour
          local_time(next_day + (shift * 3_600), zone)
        elsif !selected?(@hour, time.hour)
          time = wall_time(zone, time.year, time.month, time.day, time.hour) unless advanced
          local_time(time + 3_600, zone)
        elsif !selected?(@minute, time.min)
          time = Time.at(time.to_i.div(60) * 60) unless advanced
          local_time(time + 60, zone)
        else
          local_time(time + 1, zone)
        end
      end

      def day_matches?(time)
        day = selected?(@day, time.day)
        weekday = selected?(@weekday, time.wday)
        return day || weekday if (@day | @weekday).nobits?(STAR)

        day && weekday
      end

      def selected?(mask, value)
        mask.anybits?(1 << value)
      end

      def input_zone(time)
        return "UTC" if time.utc?
        return time.utc_offset if time.zone.nil?
        return time.zone unless time.zone.is_a?(String)

        nil
      end

      def local_time(time, zone)
        zone.nil? ? time.getlocal : time.getlocal(zone)
      end

      # Go's time.Date first guesses the offset at the wall time interpreted
      # as UTC, then checks the offset at the resulting instant. This also
      # defines which side of a DST gap or fold calendar jumps land on.
      def wall_time(zone, year, month, day, hour = 0, minute = 0, second = 0)
        naive = Time.utc(year, month, 1, hour, minute, second) + ((day - 1) * 86_400)
        guess = naive - local_time(naive, zone).utc_offset
        local_time(naive - local_time(guess, zone).utc_offset, zone)
      end
    end
  end
end
