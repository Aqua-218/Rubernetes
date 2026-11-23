# frozen_string_literal: true

require "ipaddr"
require "json"
require "strscan"
require "uri"

module Prom
  # Text expansion for Prometheus alert rule labels and annotations.
  # Template expressions may only call the functions listed below.
  class AlertTemplate
    class Error < StandardError; end

    ACTION = %r{\{\{(-\s)?\s*((?:/\*.*?\*/|"(?:[^"\\]|\\.)*"|`[^`]*`|(?!\}\}).)*?)(\s-)?\}\}}m
    TOKEN = /"(?:[^"\\]|\\.)*"|`[^`]*`|:=|[|(),=]|[^\s|(),=]+/m
    BLOCKS = %w[if with range].freeze
    MAX_TEMPLATE_DEPTH = 100
    Execution = Struct.new(:output, :templates, :depth, keyword_init: true)
    LoopControl = Struct.new(:break_tag, :continue_tag)

    class Scope
      def initialize(variables = {}, parent: nil)
        @variables = variables
        @parent = parent
      end

      def child = Scope.new(parent: self)

      def fetch(name)
        return @variables.fetch(name) if @variables.key?(name) || !@parent

        @parent.fetch(name)
      rescue KeyError
        raise Error, "undefined template variable #{name}"
      end

      def bind(name, value, assign:)
        if !assign || @variables.key?(name)
          @variables[name] = value
        elsif @parent
          @parent.bind(name, value, assign: true)
        else
          raise Error, "undefined template variable #{name}"
        end
      end
    end
    PREFIXES = {
      small: %w[m u n p f a z y],
      large: %w[k M G T P E Z Y],
      binary: %w[ki Mi Gi Ti Pi Ei Zi Yi]
    }.freeze

    def initialize(labels:, value:, external_labels:, external_url:, timestamp_ms:, engine:)
      @engine = engine
      @timestamp_ms = timestamp_ms
      @external_url = external_url.to_s
      @data = {"Labels" => labels, "Value" => value, "ExternalLabels" => external_labels, "ExternalURL" => @external_url}
    end

    def expand(template)
      return template unless template.include?("{{")

      tokens = tokenize_template(template)
      templates = {}
      nodes, ending = parse_block(tokens, templates, top_level: true)
      raise Error, "unexpected #{ending}" if ending

      scope = Scope.new({"$" => @data, "$labels" => @data["Labels"], "$value" => @data["Value"],
                         "$externalLabels" => @data["ExternalLabels"], "$externalURL" => @external_url})
      execution = Execution.new(output: +"", templates: templates, depth: 0)
      render(nodes, @data, scope, execution)
      execution.output
    end

    private

    def tokenize_template(template)
      tokens = []
      position = 0
      trim = false
      template.to_enum(:scan, ACTION).each do
        match = Regexp.last_match
        text = template[position...match.begin(0)]
        text = text.lstrip if trim
        text = text.rstrip if match[1]
        raise Error, "unclosed template action" if text.include?("{{")

        tokens << [:text, text]
        action = match[2].strip
        tokens << [:action, action] unless action.start_with?("/*") && action.end_with?("*/")
        trim = !match[3].nil?
        position = match.end(0)
      end
      tail = template[position..]
      raise Error, "unclosed template action" if tail.include?("{{")

      tokens << [:text, trim ? tail.lstrip : tail]
    end

    def parse_block(tokens, templates, top_level: false, in_range: false)
      nodes = []
      until tokens.empty?
        kind, text = tokens.shift
        if kind == :text
          nodes << [kind, text]
          next
        end

        command, expression = text.split(/\s+/, 2)
        return [nodes, text] if %w[end else].include?(command)

        case command
        when *BLOCKS
          nodes << parse_control(tokens, templates, command, expression, in_range: in_range)
        when "define", "block"
          raise Error, "template definitions must be at the top level" if command == "define" && !top_level

          name, arguments = named_action(expression)
          raise Error, "define expects only a template name" if command == "define" && arguments.any?
          raise Error, "block needs a pipeline" if command == "block" && arguments.empty?

          body, ending = parse_block(tokens, templates)
          raise Error, "unclosed #{command} #{name.inspect}" unless ending == "end"

          register_template(templates, name, body)
          nodes << [:template, name, arguments] if command == "block"
        when "template"
          name, arguments = named_action(expression)
          nodes << [:template, name, arguments]
        when "break", "continue"
          raise Error, "unexpected argument for #{command}" if expression
          raise Error, "#{command} outside range" unless in_range

          nodes << [command.to_sym]
        else
          nodes << [:print, expression_tokens(text)]
        end
      end
      [nodes, nil]
    end

    def named_action(expression)
      tokens = expression_tokens(expression.to_s)
      literal = tokens.shift
      name = case literal
             when /\A"/ then JSON.parse(literal)
             when /\A`/ then literal[1...-1].delete("\r")
             else raise Error, "expected a quoted template name"
             end
      [name, tokens]
    end

    def register_template(templates, name, body)
      previous = templates[name]
      return if previous && empty_template?(body)
      raise Error, "multiple definitions of template #{name.inspect}" if previous && !empty_template?(previous)

      templates[name] = body
    end

    def empty_template?(body)
      body.all? { |kind, text| kind == :text && text.strip.empty? }
    end

    def parse_control(tokens, templates, command, expression, in_range:)
      body, ending = parse_block(tokens, templates, in_range: in_range || command == "range")
      other = []
      if ending == "else"
        other, ending = parse_block(tokens, templates, in_range: in_range)
      elsif ending&.start_with?("else ")
        _, chained, condition = ending.split(/\s+/, 3)
        raise Error, "invalid else branch" unless %w[if with].include?(chained)

        other = [parse_control(tokens, templates, chained, condition, in_range: in_range)]
        ending = "end"
      end
      raise Error, "unclosed #{command} block" unless ending == "end"

      [command, expression_tokens(expression.to_s), body, other]
    end

    def expression_tokens(text)
      scanner = StringScanner.new(text)
      tokens = []
      until scanner.eos?
        scanner.skip(/\s+/)
        break if scanner.eos?

        token = scanner.scan(TOKEN)
        raise Error, "invalid template expression" unless token

        tokens << token
      end
      raise Error, "empty template action" if tokens.empty?

      tokens
    end

    def render(nodes, dot, scope, execution, control = nil)
      nodes.each do |kind, expression, body, other|
        case kind
        when :text then execution.output << expression
        when :print
          value, assigned = evaluate(expression, dot, scope)
          execution.output << stringify(value) unless assigned
        when :break then throw control.break_tag
        when :continue then throw control.continue_tag
        when :template then render_template(expression, body, dot, scope, execution)
        when "if", "with"
          local = scope.child
          value = evaluate(expression, dot, local).first
          active = truthy?(value)
          render(active ? body : other, kind == "with" && active ? value : dot, local, execution, control)
        when "range"
          render_range(expression, body, other, dot, scope.child, execution, control)
        end
      end
    end

    def render_template(name, arguments, dot, scope, execution)
      nodes = execution.templates.fetch(name) { raise Error, "template #{name.inspect} is not defined" }
      value = evaluate(arguments, dot, scope).first unless arguments.empty?
      execution.depth += 1
      begin
        raise Error, "template recursion limit exceeded" if execution.depth > MAX_TEMPLATE_DEPTH

        render(nodes, value, Scope.new({"$" => value}), execution)
      ensure
        execution.depth -= 1
      end
    end

    def render_range(expression, body, other, dot, scope, execution, parent_control)
      variables, tokens, assign = assignment(expression)
      raise Error, "range accepts at most two variables" if variables.length > 2

      value = evaluate(tokens, dot, scope).first
      variables.each { |name| scope.bind(name, value, assign: assign) }
      pairs = case value
              when nil then []
              when Array then value.each_with_index.lazy.map { |item, index| [index, item] }
              when Hash then value.sort
              when Integer
                raise Error, "integer range accepts at most one variable" if variables.length > 1

                (0...value).lazy.map { |index| [index, index] }
              else raise Error, "cannot range over #{value.inspect}"
              end
      control = LoopControl.new(Object.new, Object.new)
      visited = false
      catch(control.break_tag) do
        pairs.each do |key, item|
          visited = true
          scope.bind(variables[0], variables.length == 1 ? item : key, assign: true) if variables[0]
          scope.bind(variables[1], item, assign: true) if variables[1]
          catch(control.continue_tag) { render(body, item, scope.child, execution, control) }
        end
      end
      render(other, dot, scope, execution, parent_control) unless visited
    end

    def evaluate(tokens, dot, scope)
      variables, tokens, assign = assignment(tokens)
      value = pipeline(tokens, dot, scope)
      raise Error, "unexpected #{tokens.first.inspect}" unless tokens.empty?

      if variables.any?
        raise Error, "expected one template variable" unless variables.length == 1

        scope.bind(variables.first, value, assign: assign)
      end
      [value, !variables.empty?]
    end

    def assignment(tokens)
      return [[], tokens.dup, false] unless tokens.first&.start_with?("$")

      variables = [tokens[0]]
      position = 1
      while tokens[position] == ","
        variables << tokens[position + 1]
        position += 2
      end
      separator = tokens[position]
      return [[], tokens.dup, false] unless %w[:= =].include?(separator)
      raise Error, "invalid template variable" unless variables.all? { |name| name&.match?(/\A\$\w+\z/) }

      [variables, tokens.drop(position + 1), separator == "="]
    end

    def pipeline(tokens, dot, scope)
      value = command(tokens, dot, scope, [])
      while tokens.first == "|"
        tokens.shift
        value = command(tokens, dot, scope, [value])
      end
      value
    end

    def command(tokens, dot, scope, appended)
      first = tokens.shift
      raise Error, "empty pipeline command" if first.nil? || %w[| )].include?(first)

      arguments = []
      if literal?(first)
        value = argument(first, tokens, dot, scope)
        raise Error, "unexpected template argument" unless appended.empty? && [nil, "|", ")"].include?(tokens.first)

        return value
      end
      until [nil, "|", ")"].include?(tokens.first)
        token = tokens.shift
        if (first == "and" && arguments.any? { |value| !truthy?(value) }) ||
           (first == "or" && arguments.any? { |value| truthy?(value) })
          skip_argument(token, tokens)
        else
          arguments << argument(token, tokens, dot, scope)
        end
      end
      call(first, arguments + appended)
    end

    def skip_argument(token, tokens)
      return unless token == "("

      depth = 1
      until depth.zero?
        case tokens.shift
        when "(" then depth += 1
        when ")" then depth -= 1
        when nil then raise Error, "unclosed template parentheses"
        end
      end
      tokens.shift if tokens.first&.start_with?(".") && tokens.first != "."
    end

    def literal?(token)
      token.start_with?("$", ".", '"', "`", "(") || %w[true false nil].include?(token) || token.match?(/\A[+-]?(?:\d|\.\d)/)
    end

    def argument(token, tokens, dot, scope)
      case token
      when "("
        result = pipeline(tokens, dot, scope)
        raise Error, "unclosed template parentheses" unless tokens.shift == ")"

        result = member(result, tokens.shift[1..].split(".")) if tokens.first&.start_with?(".") && tokens.first != "."
        result
      when /\A"/ then JSON.parse(token)
      when /\A`/ then token[1...-1].delete("\r")
      when "true" then true
      when "false" then false
      when "nil" then nil
      when /\A[+-]?\d+\z/ then Integer(token, 10)
      when /\A[+-]?(?:\d|\.\d)/ then Float(token)
      when /\A\$/
        name, *path = token.split(".")
        member(scope.fetch(name), path)
      when "." then dot
      when /\A\./ then member(dot, token[1..].split("."))
      else call(token, [])
      end
    end

    def member(value, path)
      path.reduce(value) do |current, key|
        case current
        when Hash then current.fetch(key, "")
        when NativeHistogram
          field = {"Count" => :count, "Sum" => :sum, "ZeroCount" => :zero_count}.fetch(key) { raise Error, "unknown histogram field #{key}" }
          current.public_send(field)
        else raise Error, "cannot access template field #{key}"
        end
      end
    end

    def query(expression)
      raise Error, "query is unavailable" unless @engine

      result = @engine.query(expression, @timestamp_ms)
      case result.type
      when :vector then result.value.map { |s| {"Labels" => s.metric, "Value" => s.point[1]} }
      when :scalar then [{"Labels" => {}, "Value" => result.value[1]}]
      else raise Error, "query must yield an instant vector or scalar"
      end
    end

    def call(name, args)
      a, b, c = args
      case name
      when "query" then query(a)
      when "first" then a.fetch(0) { raise Error, "first called on an empty vector" }
      when "label" then b.fetch("Labels").fetch(a, "")
      when "value" then a.fetch("Value")
      when "strvalue" then a.fetch("Labels").fetch("__value__", "")
      when "sortByLabel" then b.each_with_index.sort_by { |sample, i| [sample.fetch("Labels").fetch(a, ""), i] }.map(&:first)
      when "args" then args.each_with_index.to_h { |value, i| ["arg#{i}", value] }
      when "reReplaceAll" then regexp_replace(a, b, c)
      when "match" then Regexp.new(a).match?(b)
      when "title" then a.gsub(/\b\p{L}/, &:upcase)
      when "toUpper" then a.upcase
      when "toLower" then a.downcase
      when "safeHtml" then a
      when "graphLink", "tableLink" then "/graph?g0.expr=#{escape_query(a)}&g0.tab=#{name == "graphLink" ? 0 : 1}"
      when "stripPort" then host_port(a).first
      when "stripDomain" then strip_domain(a)
      when "humanize" then humanize(number(a))
      when "humanize1024" then humanize(number(a), base: 1024)
      when "humanizePercentage" then "#{significant(number(a) * 100)}%"
      when "humanizeDuration" then humanize_duration(number(a))
      when "humanizeTimestamp" then humanize_timestamp(number(a))
      when "toTime" then humanize_timestamp(number(a), strict: true)
      when "toDuration" then duration_text(number(a))
      when "now" then @timestamp_ms / 1000.0
      when "pathPrefix" then URI.parse(@external_url).path.to_s
      when "externalURL" then @external_url
      when "parseDuration" then Promql::Lexer.duration_ms(a.delete_prefix("-")) / (a.start_with?("-") ? -1000.0 : 1000.0)
      when "urlQueryEscape", "urlquery" then escape_query(a)
      when "print" then args.map { |arg| stringify(arg) }.join
      when "println" then "#{args.map { |arg| stringify(arg) }.join(" ")}\n"
      when "printf" then printf(a, args.drop(1))
      when "len" then a.length
      when "index" then args.drop(1).reduce(a) { |object, index| index_value(object, index) }
      when "and" then args.fetch(args.index { |value| !truthy?(value) } || -1)
      when "or" then args.find { |value| truthy?(value) } || args.last
      when "not" then !truthy?(a)
      when "eq" then args.drop(1).include?(a)
      when "ne" then a != b
      when "lt" then a < b
      when "le" then a <= b
      when "gt" then a > b
      when "ge" then a >= b
      else raise Error, "unknown template function #{name}"
      end
    end

    def index_value(object, key)
      object.is_a?(Hash) ? object.fetch(key, "") : object.fetch(key)
    end

    def printf(template, args)
      index = 0
      template.gsub(/%(?:%|[-+# 0]*\d*(?:\.\d+)?[vTqsdxXbfFeEgG])/) do |spec|
        next "%" if spec == "%%"

        value = args.fetch(index)
        index += 1
        case spec[-1]
        when "v" then stringify(value)
        when "T" then value.is_a?(Float) ? "float64" : value.class.to_s.downcase
        when "q" then JSON.generate(stringify(value))
        when "s" then format(spec, stringify(value))
        else format(spec, value)
        end
      end
    end

    def regexp_replace(pattern, replacement, input)
      input.gsub(Regexp.new(pattern)) do
        match = Regexp.last_match
        replacement.gsub(/\$\$|\$\{([[:alnum:]_]+)\}|\$([[:alnum:]_]+)/) do |ref|
          next "$" if ref == "$$"

          key = Regexp.last_match(1) || Regexp.last_match(2)
          key = key.to_i if key.match?(/\A\d+\z/)
          match[key].to_s
        rescue IndexError
          ""
        end
      end
    end

    def host_port(value)
      case value
      when /\A\[([^\]]+)\]:([^:]*)\z/, /\A([^:]*):([^:]*)\z/
        [Regexp.last_match(1), Regexp.last_match(2)]
      else [value, nil]
      end
    end

    def strip_domain(value)
      host, port = host_port(value)
      value if IPAddr.new(host)
    rescue IPAddr::InvalidAddressError
      host = host.split(".", 2).first
      port.to_s.empty? ? host : "#{host}:#{port}"
    end

    def truthy?(value)
      return false if value.nil? || value == false
      return !value.zero? if value.is_a?(Numeric)
      return !value.empty? if value.respond_to?(:empty?)

      true
    end

    def stringify(value)
      case value
      when Float, NativeHistogram then Promql::Engine.format_value(value)
      when nil then "<no value>"
      else value.to_s
      end
    end

    def escape_query(value)
      URI.encode_www_form_component(value).gsub("*", "%2A").gsub("%7E", "~")
    end

    def number(value)
      case value
      when "NaN" then Float::NAN
      when "+Inf", "Inf" then Float::INFINITY
      when "-Inf" then -Float::INFINITY
      else Float(value)
      end
    end

    def significant(value)
      value.finite? ? format("%.4g", value) : Promql::Engine.format_value(value)
    end

    def humanize(value, base: 1000)
      return significant(value) if value.zero? || !value.finite?

      if value.abs < 1
        return significant(value) unless base == 1000

        value, prefix = scale_small(value)
      else
        prefix = ""
        PREFIXES.fetch(base == 1000 ? :large : :binary).each do |unit|
          break if value.abs < base

          value /= base
          prefix = unit
        end
      end
      "#{significant(value)}#{prefix}"
    end

    def scale_small(value)
      prefix = ""
      PREFIXES.fetch(:small).each do |unit|
        break if value.abs >= 1

        value *= 1000
        prefix = unit
      end
      [value, prefix]
    end

    def humanize_duration(value)
      return significant(value) unless value.finite?
      return "0s" if value.zero?

      if value.abs < 1
        scaled, prefix = scale_small(value)
        return "#{significant(scaled)}#{prefix}s"
      end
      return "#{significant(value)}s" if value.abs < 60

      days, rest = value.abs.to_i.divmod(86_400)
      hours, rest = rest.divmod(3600)
      minutes, seconds = rest.divmod(60)
      parts = ["#{days}d", "#{hours}h", "#{minutes}m", "#{seconds}s"]
      parts.shift if days.zero?
      parts.shift if days.zero? && hours.zero?
      "#{"-" if value.negative?}#{parts.join(" ")}"
    end

    def duration_text(value)
      nanoseconds = convert_nanoseconds(value)
      sign = nanoseconds.negative? ? "-" : ""
      nanoseconds = nanoseconds.abs
      return "0s" if nanoseconds.zero?

      if nanoseconds < 1_000_000_000
        scale, unit = if nanoseconds < 1000 then [1, "ns"]
                      elsif nanoseconds < 1_000_000 then [1000, "µs"]
                      else [1_000_000, "ms"]
                      end
        return "#{sign}#{duration_decimal(nanoseconds, scale)}#{unit}"
      end

      hours, remainder = nanoseconds.divmod(3_600_000_000_000)
      minutes, seconds = remainder.divmod(60_000_000_000)
      prefix = hours.positive? ? "#{hours}h" : ""
      prefix += "#{minutes}m" if hours.positive? || minutes.positive?
      "#{sign}#{prefix}#{duration_decimal(seconds, 1_000_000_000)}s"
    end

    def duration_decimal(value, scale)
      whole, fraction = value.divmod(scale)
      return whole.to_s if fraction.zero?

      "#{whole}.#{(scale + fraction).to_s[1..].sub(/0+\z/, "")}"
    end

    def convert_nanoseconds(value)
      nanoseconds = value * 1e9
      raise Error, "time out of range" unless nanoseconds.finite? && ((-(2**63))...(2**63)).cover?(nanoseconds)

      nanoseconds.to_i
    end

    def humanize_timestamp(value, strict: false)
      return significant(value) unless strict || value.finite?

      time = Time.at(Rational(convert_nanoseconds(value), 1_000_000_000)).utc
      fraction = time.nsec.zero? ? "" : format(".%09d", time.nsec).sub(/0+\z/, "")
      "#{time.strftime("%Y-%m-%d %H:%M:%S")}#{fraction} +0000 UTC"
    end
  end
end
