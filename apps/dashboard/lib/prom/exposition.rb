# frozen_string_literal: true

module Prom
  # Parser for the Prometheus text exposition format (the format every
  # Rubernetes component serves on /metrics and that the Go expfmt oracle
  # validated).  It yields metric families in document order; each sample
  # carries its full label set, so a histogram's `_bucket`/`_sum`/`_count`
  # rows and a summary's quantiles are ordinary samples with `le`/`quantile`
  # labels, exactly as Prometheus ingests them.
  #
  # Faithful to prometheus/common/expfmt TextParser:
  #   * `# HELP <name> <text>` / `# TYPE <name> <type>` describe a family;
  #     other comments are ignored.  TYPE may be counter, gauge, histogram,
  #     summary or untyped; a sample with no TYPE is untyped.
  #   * Label values may contain `\\`, `\"` and `\n` escapes.  HELP text
  #     unescapes `\\` and `\n`.
  #   * Values are Go float literals including `+Inf`, `-Inf`, `NaN`.
  #   * An optional integer timestamp in milliseconds follows the value.
  #   * `# EOF` (OpenMetrics) ends the document.
  module Exposition
    class ParseError < StandardError; end

    Family = Struct.new(:name, :type, :help, :samples, keyword_init: true)
    Sample = Struct.new(:name, :labels, :value, :timestamp_ms, keyword_init: true) do
      # Base family name for histogram/summary component rows.
      def family_name
        return name.delete_suffix("_bucket") if name.end_with?("_bucket") && labels.key?("le")
        return name.delete_suffix("_sum") if name.end_with?("_sum")
        return name.delete_suffix("_count") if name.end_with?("_count")

        name
      end
    end

    TYPES = %w[counter gauge histogram summary untyped].freeze
    NAME = /\A[a-zA-Z_:][a-zA-Z0-9_:]*\z/
    LABEL_NAME = /\A[a-zA-Z_][a-zA-Z0-9_]*\z/

    module_function

    # Parse the whole document.  Returns an Array of Family in order of first
    # appearance; samples that belong to a family by prefix (histogram and
    # summary components) are attached to it.
    def parse(text)
      families = {}
      order = []
      text.each_line do |raw|
        line = raw.chomp
        next if line.strip.empty?

        if line.start_with?("#")
          break if line.strip == "# EOF"

          parse_comment(line, families, order)
          next
        end
        sample = parse_sample(line)
        key = sample.family_name
        family = families[key] || families[sample.name]
        if family.nil?
          family = Family.new(name: sample.name, type: "untyped", help: nil, samples: [])
          families[sample.name] = family
          order << sample.name
        end
        family.samples << sample
      end
      order.map { |name| families[name] }
    end

    # Every sample of the document as a flat list (what a scrape stores).
    def samples(text)
      parse(text).flat_map(&:samples)
    end

    def parse_comment(line, families, order)
      parts = line[1..].strip.split(/\s+/, 3)
      keyword = parts[0]
      return unless %w[HELP TYPE].include?(keyword)

      name = parts[1].to_s
      raise ParseError, "invalid metric name #{name.inspect}" unless NAME.match?(name)

      family = families[name]
      if family.nil?
        family = Family.new(name: name, type: "untyped", help: nil, samples: [])
        families[name] = family
        order << name
      end
      if keyword == "HELP"
        family.help = unescape_help(parts[2].to_s)
      else
        type = parts[2].to_s.strip
        raise ParseError, "unknown metric type #{type.inspect} for #{name}" unless TYPES.include?(type)

        family.type = type
      end
    end

    def unescape_help(text)
      text.gsub(/\\(\\|n)/) { Regexp.last_match(1) == "n" ? "\n" : "\\" }
    end

    def parse_sample(line)
      scanner = Scanner.new(line)
      name = scanner.metric_name
      labels = scanner.peek == "{" ? scanner.labels : {}
      scanner.skip_space
      value = parse_value(scanner.token)
      scanner.skip_space
      timestamp = nil
      unless scanner.eos?
        raw = scanner.token
        raise ParseError, "invalid timestamp #{raw.inspect}" unless raw.match?(/\A-?\d+\z/)

        timestamp = Integer(raw)
        scanner.skip_space
        raise ParseError, "trailing data after timestamp in #{line.inspect}" unless scanner.eos?
      end
      Sample.new(name: name, labels: labels, value: value, timestamp_ms: timestamp)
    end

    def parse_value(token)
      case token
      when "+Inf", "Inf" then Float::INFINITY
      when "-Inf" then -Float::INFINITY
      when "NaN" then Float::NAN
      else
        Float(token)
      end
    rescue ArgumentError, TypeError
      raise ParseError, "invalid sample value #{token.inspect}"
    end

    class Scanner
      def initialize(line)
        @line = line
        @pos = 0
      end

      def eos? = @pos >= @line.length
      def peek = @line[@pos]

      def skip_space
        @pos += 1 while !eos? && [" ", "\t"].include?(peek)
      end

      def metric_name
        skip_space
        start = @pos
        @pos += 1 while !eos? && peek.match?(/[a-zA-Z0-9_:]/)
        name = @line[start...@pos]
        raise ParseError, "invalid metric name in #{@line.inspect}" unless NAME.match?(name)

        name
      end

      def token
        start = @pos
        @pos += 1 while !eos? && !peek.match?(/[ \t]/)
        @line[start...@pos]
      end

      def labels
        expect("{")
        result = {}
        loop do
          skip_space
          if peek == "}"
            @pos += 1
            break
          end
          start = @pos
          @pos += 1 while !eos? && peek.match?(/[a-zA-Z0-9_]/)
          name = @line[start...@pos]
          raise ParseError, "invalid label name in #{@line.inspect}" unless LABEL_NAME.match?(name)

          skip_space
          expect("=")
          skip_space
          result[name] = quoted
          skip_space
          case peek
          when "," then @pos += 1
          when "}" then next
          else raise ParseError, "expected , or } in #{@line.inspect}"
          end
        end
        result
      end

      def quoted
        expect('"')
        out = +""
        loop do
          raise ParseError, "unterminated label value in #{@line.inspect}" if eos?

          char = @line[@pos]
          @pos += 1
          case char
          when '"' then return out
          when "\\"
            raise ParseError, "unterminated escape in #{@line.inspect}" if eos?

            escaped = @line[@pos]
            @pos += 1
            out << case escaped
                   when "n" then "\n"
                   when "\\" then "\\"
                   when '"' then '"'
                   else "\\#{escaped}"
                   end
          else out << char
          end
        end
      end

      def expect(char)
        raise ParseError, "expected #{char.inspect} at #{@pos} in #{@line.inspect}" unless peek == char

        @pos += 1
      end
    end
  end
end
