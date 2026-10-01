# frozen_string_literal: true

module Promql
  class ParseError < StandardError
    attr_reader :position

    def initialize(message, position = nil)
      super(position ? "#{position}: #{message}" : message)
      @position = position
    end
  end

  # ------------------------------------------------------------------ AST
  #
  # Node classes mirror prometheus/promql/parser: every expression knows the
  # value type it evaluates to (scalar, string, instant vector, range vector,
  # or matrix for a subquery).
  module AST
    NumberLiteral = Struct.new(:value) { def type = :scalar }
    StringLiteral = Struct.new(:value) { def type = :string }

    LabelMatcher = Struct.new(:name, :op, :value)

    VectorSelector = Struct.new(:name, :matchers, :offset_ms, :at) do
      def type = :vector
    end

    MatrixSelector = Struct.new(:selector, :range_ms) do
      def type = :matrix
    end

    SubqueryExpr = Struct.new(:expr, :range_ms, :step_ms, :offset_ms, :at) do
      def type = :matrix
    end

    ParenExpr = Struct.new(:expr) do
      def type = expr.type
    end

    UnaryExpr = Struct.new(:op, :expr) do
      def type = expr.type
    end

    BinaryExpr = Struct.new(:op, :lhs, :rhs, :matching, :return_bool) do
      def type
        lhs.type == :scalar && rhs.type == :scalar ? :scalar : :vector
      end
    end

    # on/ignoring + group_left/group_right(labels)
    VectorMatching = Struct.new(:card, :labels, :on, :include) do
      def initialize(card = :one_to_one, labels = [], on = false, include = []) # rubocop:disable Style/OptionalBooleanParameter -- Struct members mirror the AST node
        super
      end
    end

    AggregateExpr = Struct.new(:op, :expr, :param, :grouping, :without) do
      def type = :vector
    end

    Call = Struct.new(:func, :args) do
      def type = FUNCTION_RETURN_TYPES.fetch(func, :vector)
    end

    FUNCTION_RETURN_TYPES = {
      "time" => :scalar, "scalar" => :scalar, "pi" => :scalar,
      "vector" => :vector
    }.freeze
  end

  # ---------------------------------------------------------------- Lexer

  Token = Struct.new(:type, :value, :pos)

  class Lexer
    KEYWORDS = %w[and or unless by without on ignoring group_left group_right offset bool].freeze
    AGGREGATORS = %w[sum avg min max count stddev stdvar topk bottomk count_values quantile group limitk limit_ratio].freeze
    DURATION = /\A(?:(\d+)y)?(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?\z/

    def initialize(input)
      @input = input
      @pos = 0
    end

    def tokens
      list = []
      loop do
        token = next_token
        list << token
        break if token.type == :eof
      end
      list
    end

    def self.duration_ms(text)
      match = DURATION.match(text)
      raise ParseError, "bad duration #{text.inspect}" if match.nil? || text.empty?

      y, w, d, h, m, s, ms = match.captures.map { |c| c.nil? ? 0 : Integer(c) }
      (((((((((y * 365) + (w * 7) + d) * 24) + h) * 60) + m) * 60) + s) * 1000) + ms
    end

    private

    def next_token
      skip_space_and_comments
      return Token.new(:eof, nil, @pos) if @pos >= @input.length

      start = @pos
      char = @input[@pos]
      case char
      when "(" then advance(:lparen, char)
      when ")" then advance(:rparen, char)
      when "{" then advance(:lbrace, char)
      when "}" then advance(:rbrace, char)
      when "[" then advance(:lbracket, char)
      when "]" then advance(:rbracket, char)
      when "," then advance(:comma, char)
      when ":" then advance(:colon, char)
      when "@" then advance(:at, char)
      when "+", "-", "*", "/", "%", "^" then advance(:op, char)
      when "="
        if @input[@pos + 1] == "="
          @pos += 2
          Token.new(:op, "==", start)
        elsif @input[@pos + 1] == "~"
          @pos += 2
          Token.new(:op, "=~", start)
        else
          advance(:op, "=")
        end
      when "!"
        if @input[@pos + 1] == "="
          @pos += 2
          Token.new(:op, "!=", start)
        elsif @input[@pos + 1] == "~"
          @pos += 2
          Token.new(:op, "!~", start)
        else
          raise ParseError.new("unexpected !", @pos)
        end
      when "<"
        if @input[@pos + 1] == "="
          @pos += 2
          Token.new(:op, "<=", start)
        else
          advance(:op, "<")
        end
      when ">"
        if @input[@pos + 1] == "="
          @pos += 2
          Token.new(:op, ">=", start)
        else
          advance(:op, ">")
        end
      when '"', "'", "`" then string_token(char)
      else
        if char.match?(/[0-9]/) || (char == "." && @input[@pos + 1].to_s.match?(/[0-9]/))
          number_or_duration
        elsif char.match?(/[a-zA-Z_:]/)
          identifier
        else
          raise ParseError.new("unexpected character #{char.inspect}", @pos)
        end
      end
    end

    def advance(type, value)
      token = Token.new(type, value, @pos)
      @pos += value.length
      token
    end

    def skip_space_and_comments
      loop do
        @pos += 1 while @pos < @input.length && @input[@pos].match?(/\s/)
        break unless @input[@pos] == "#"

        @pos += 1 while @pos < @input.length && @input[@pos] != "\n"
      end
    end

    def string_token(quote)
      start = @pos
      @pos += 1
      out = +""
      loop do
        raise ParseError.new("unterminated string", start) if @pos >= @input.length

        char = @input[@pos]
        @pos += 1
        if char == quote
          return Token.new(:string, out, start)
        elsif char == "\\" && quote != "`"
          escaped = @input[@pos]
          @pos += 1
          out << case escaped
                 when "n" then "\n"
                 when "t" then "\t"
                 when "r" then "\r"
                 when "\\" then "\\"
                 when '"' then '"'
                 when "'" then "'"
                 else "\\#{escaped}"
                 end
        else
          out << char
        end
      end
    end

    def number_or_duration
      start = @pos
      @pos += 1 while @pos < @input.length && @input[@pos].match?(/[0-9a-zA-Z_.]/)
      text = @input[start...@pos]
      return Token.new(:duration, text, start) if text.match?(/\A\d+(?:y|w|d|h|m|s|ms)/) && Lexer::DURATION.match?(text)
      return Token.new(:number, Integer(text, 16).to_f, start) if text.match?(/\A0x[0-9a-fA-F]+\z/)

      # Scientific notation: the exponent sign is consumed here.
      if text.match?(/[eE]\z/) && @input[@pos].to_s.match?(/[+-]/)
        @pos += 1
        @pos += 1 while @pos < @input.length && @input[@pos].match?(/[0-9]/)
        text = @input[start...@pos]
      end
      begin
        Token.new(:number, Float(text), start)
      rescue ArgumentError
        raise ParseError.new("bad number #{text.inspect}", start)
      end
    end

    def identifier
      start = @pos
      @pos += 1 while @pos < @input.length && @input[@pos].match?(/[a-zA-Z0-9_:]/)
      text = @input[start...@pos]
      lowered = text.downcase
      case lowered
      when "inf" then Token.new(:number, Float::INFINITY, start)
      when "nan" then Token.new(:number, Float::NAN, start)
      else
        if KEYWORDS.include?(lowered)
          Token.new(:keyword, lowered, start)
        elsif AGGREGATORS.include?(lowered)
          Token.new(:aggregator, lowered, start)
        else
          Token.new(:identifier, text, start)
        end
      end
    end
  end

  # --------------------------------------------------------------- Parser
  #
  # Precedence (low to high), as in Prometheus:
  #   or
  #   and, unless
  #   == != <= < >= >
  #   + -
  #   * / % atan2
  #   ^ (right associative)
  #   unary + -
  #   @ offset [range] postfix
  class Parser
    COMPARISON = %w[== != <= < >= >].freeze
    ARITHMETIC = %w[+ - * / % ^ atan2].freeze
    SET_OPS = %w[and or unless].freeze

    def self.parse(input)
      new(input).parse
    end

    def initialize(input)
      @tokens = Lexer.new(input).tokens
      @index = 0
      @input = input
    end

    def parse
      expr = parse_expr
      expect(:eof)
      check_types(expr)
      expr
    end

    private

    def peek = @tokens[@index]
    def peek_next = @tokens[@index + 1]

    def take
      token = @tokens[@index]
      @index += 1
      token
    end

    def accept(type, value = nil)
      token = peek
      return nil unless token.type == type && (value.nil? || token.value == value)

      take
    end

    def expect(type, value = nil)
      token = accept(type, value)
      return token if token

      got = peek
      raise ParseError.new("expected #{value || type}, got #{got.value.nil? ? got.type : got.value.inspect}", got.pos)
    end

    def parse_expr
      parse_or
    end

    def parse_or
      left = parse_and
      while (token = accept(:keyword, "or"))
        matching = parse_matching_clause(set: true)
        right = parse_and
        left = AST::BinaryExpr.new(token.value, left, right, matching, false)
      end
      left
    end

    def parse_and
      left = parse_comparison
      while peek.type == :keyword && %w[and unless].include?(peek.value)
        token = take
        matching = parse_matching_clause(set: true)
        right = parse_comparison
        left = AST::BinaryExpr.new(token.value, left, right, matching, false)
      end
      left
    end

    def parse_comparison
      left = parse_additive
      while peek.type == :op && COMPARISON.include?(peek.value)
        token = take
        bool = !accept(:keyword, "bool").nil?
        matching = parse_matching_clause
        right = parse_additive
        left = AST::BinaryExpr.new(token.value, left, right, matching, bool)
      end
      left
    end

    def parse_additive
      left = parse_multiplicative
      while peek.type == :op && %w[+ -].include?(peek.value)
        token = take
        matching = parse_matching_clause
        right = parse_multiplicative
        left = AST::BinaryExpr.new(token.value, left, right, matching, false)
      end
      left
    end

    def parse_multiplicative
      left = parse_power
      while (peek.type == :op && %w[* / %].include?(peek.value)) || (peek.type == :identifier && peek.value == "atan2")
        token = take
        matching = parse_matching_clause
        right = parse_power
        left = AST::BinaryExpr.new(token.value, left, right, matching, false)
      end
      left
    end

    def parse_power
      base = parse_unary
      if peek.type == :op && peek.value == "^"
        take
        matching = parse_matching_clause
        exponent = parse_power # right associative
        return AST::BinaryExpr.new("^", base, exponent, matching, false)
      end
      base
    end

    def parse_unary
      if peek.type == :op && %w[+ -].include?(peek.value)
        token = take
        operand = parse_unary
        return operand if token.value == "+"
        return AST::NumberLiteral.new(-operand.value) if operand.is_a?(AST::NumberLiteral)

        return AST::UnaryExpr.new("-", operand)
      end
      parse_postfix(parse_primary)
    end

    def parse_postfix(expr)
      loop do
        if peek.type == :lbracket
          take
          range = expect(:duration).value
          if accept(:colon)
            step = peek.type == :duration ? take.value : nil
            expect(:rbracket)
            sub = AST::SubqueryExpr.new(expr, Lexer.duration_ms(range), step && Lexer.duration_ms(step), 0, nil)
            expr = sub
          else
            expect(:rbracket)
            raise ParseError.new("range selector needs an instant vector selector", peek.pos) unless expr.is_a?(AST::VectorSelector)

            expr = AST::MatrixSelector.new(expr, Lexer.duration_ms(range))
          end
        elsif peek.type == :keyword && peek.value == "offset"
          take
          negative = accept(:op, "-") ? -1 : 1
          value = Lexer.duration_ms(expect(:duration).value) * negative
          apply_offset(expr, value)
        elsif peek.type == :at
          take
          at = parse_at_modifier
          apply_at(expr, at)
        else
          return expr
        end
      end
    end

    def parse_at_modifier
      if peek.type == :number
        (take.value * 1000).round
      elsif peek.type == :op && peek.value == "-"
        take
        -(expect(:number).value * 1000).round
      elsif peek.type == :identifier && %w[start end].include?(peek.value) && peek_next.type == :lparen
        name = take.value
        take
        expect(:rparen)
        name.to_sym
      else
        raise ParseError.new("bad @ modifier", peek.pos)
      end
    end

    def apply_offset(expr, value)
      target = expr.is_a?(AST::MatrixSelector) ? expr.selector : expr
      case target
      when AST::VectorSelector, AST::SubqueryExpr
        raise ParseError.new("offset may not be set multiple times", peek.pos) if target.offset_ms.to_i != 0

        target.offset_ms = value
      else
        raise ParseError.new("offset modifier must be preceded by an instant vector selector or range vector selector", peek.pos)
      end
    end

    def apply_at(expr, at)
      target = expr.is_a?(AST::MatrixSelector) ? expr.selector : expr
      case target
      when AST::VectorSelector, AST::SubqueryExpr
        raise ParseError.new("@ may not be set multiple times", peek.pos) unless target.at.nil?

        target.at = at
      else
        raise ParseError.new("@ modifier must be preceded by an instant vector selector or range vector selector", peek.pos)
      end
    end

    def parse_primary
      token = peek
      case token.type
      when :number then AST::NumberLiteral.new(take.value)
      when :string then AST::StringLiteral.new(take.value)
      when :lparen
        take
        expr = parse_expr
        expect(:rparen)
        AST::ParenExpr.new(expr)
      when :lbrace
        AST::VectorSelector.new(nil, parse_label_matchers, 0, nil).tap { |s| validate_selector(s, token.pos) }
      when :aggregator then parse_aggregate
      when :identifier
        if peek_next.type == :lparen
          parse_call
        else
          name = take.value
          matchers = peek.type == :lbrace ? parse_label_matchers : []
          AST::VectorSelector.new(name, matchers, 0, nil).tap { |s| validate_selector(s, token.pos) }
        end
      when :keyword
        # Keywords used as metric names (e.g. `on`, `and`) are not valid PromQL
        # metric names, except when written as {__name__="and"}.
        raise ParseError.new("unexpected keyword #{token.value.inspect}", token.pos)
      else
        raise ParseError.new("unexpected #{token.type}", token.pos)
      end
    end

    def validate_selector(selector, pos)
      if selector.name
        raise ParseError.new("metric name must not be set twice", pos) if selector.matchers.any? { |m| m.name == "__name__" }

        selector.matchers.unshift(AST::LabelMatcher.new("__name__", "=", selector.name))
      end
      unless selector.matchers.any? do |m|
        %w[= =~].include?(m.op) ? !m.value.empty? && !(m.op == "=~" && m.value.match?(/\A(?:\.\*|\.\+)?\z/) && m.value != ".+") : false
      end ||
             selector.matchers.any? { |m| m.op == "=~" && m.value == ".+" }
        raise ParseError.new("vector selector must contain at least one non-empty matcher", pos)
      end
    end

    def parse_label_matchers
      expect(:lbrace)
      matchers = []
      until accept(:rbrace)
        name_token = take
        raise ParseError.new("expected label name", name_token.pos) unless %i[identifier keyword aggregator].include?(name_token.type)

        op = expect(:op)
        raise ParseError.new("bad label matcher operator #{op.value}", op.pos) unless %w[= != =~ !~].include?(op.value)

        value = expect(:string).value
        if %w[=~ !~].include?(op.value)
          begin
            Regexp.new(value)
          rescue RegexpError => e
            raise ParseError.new("invalid regex #{value.inspect}: #{e.message}", op.pos)
          end
        end
        matchers << AST::LabelMatcher.new(name_token.value, op.value, value)
        break if accept(:rbrace)

        expect(:comma)
      end
      matchers
    end

    def parse_grouping
      expect(:lparen)
      labels = []
      until accept(:rparen)
        token = take
        raise ParseError.new("expected label name", token.pos) unless %i[identifier keyword aggregator].include?(token.type)

        labels << token.value
        break if accept(:rparen)

        expect(:comma)
      end
      labels
    end

    def parse_aggregate
      op = take.value
      grouping = nil
      without = false
      if peek.type == :keyword && %w[by without].include?(peek.value)
        without = take.value == "without"
        grouping = parse_grouping
      end
      expect(:lparen)
      param = nil
      if %w[topk bottomk count_values quantile limitk limit_ratio].include?(op)
        param = parse_expr
        expect(:comma)
      end
      expr = parse_expr
      expect(:rparen)
      if peek.type == :keyword && %w[by without].include?(peek.value) && grouping.nil?
        without = take.value == "without"
        grouping = parse_grouping
      end
      raise ParseError.new("count_values needs a string label as first argument", peek.pos) if op == "count_values" && !param.is_a?(AST::StringLiteral)

      AST::AggregateExpr.new(op, expr, param, grouping || [], without)
    end

    def parse_call
      name = take.value
      raise ParseError.new("unknown function #{name.inspect}", peek.pos) unless Functions.known?(name)

      expect(:lparen)
      args = []
      until accept(:rparen)
        args << parse_expr
        break if accept(:rparen)

        expect(:comma)
      end
      Functions.check_arity!(name, args)
      AST::Call.new(name, args)
    end

    def parse_matching_clause(set: false)
      matching = AST::VectorMatching.new(set ? :many_to_many : :one_to_one)
      if peek.type == :keyword && %w[on ignoring].include?(peek.value)
        matching.on = take.value == "on"
        matching.labels = parse_grouping
      end
      if peek.type == :keyword && %w[group_left group_right].include?(peek.value)
        raise ParseError.new("no grouping allowed for set operators", peek.pos) if set

        matching.card = take.value == "group_left" ? :many_to_one : :one_to_many
        matching.include = peek.type == :lparen ? parse_grouping : []
      end
      matching
    end

    # Static type checks that Prometheus performs at parse time.
    def check_types(node)
      case node
      when AST::BinaryExpr
        check_types(node.lhs)
        check_types(node.rhs)
        lt = node.lhs.type
        rt = node.rhs.type
        raise ParseError, "set operator #{node.op} not allowed in binary scalar expression" if SET_OPS.include?(node.op) && !(lt == :vector && rt == :vector)
        raise ParseError, "bool modifier can only be used on comparison operators" if node.return_bool && !COMPARISON.include?(node.op)
        if COMPARISON.include?(node.op) && lt == :scalar && rt == :scalar && !node.return_bool
          raise ParseError, "comparisons between scalars must use BOOL modifier"
        end
        if %i[matrix string].include?(lt) || %i[matrix string].include?(rt)
          raise ParseError, "binary expression must contain only scalar and instant vector types"
        end
        if node.matching && (lt == :scalar || rt == :scalar) && node.matching.card != :one_to_one && !SET_OPS.include?(node.op)
          raise ParseError, "vector matching only allowed between instant vectors"
        end
      when AST::AggregateExpr
        check_types(node.expr)
        check_types(node.param) if node.param
        raise ParseError, "aggregation operator expected an instant vector" unless node.expr.type == :vector
      when AST::Call
        node.args.each { |arg| check_types(arg) }
        Functions.check_types!(node)
      when AST::ParenExpr, AST::UnaryExpr
        check_types(node.expr)
        if node.is_a?(AST::UnaryExpr) && !%i[scalar vector].include?(node.expr.type)
          raise ParseError, "unary expression only allowed on scalars and instant vectors"
        end
      when AST::SubqueryExpr
        check_types(node.expr)
        raise ParseError, "subquery is only allowed on instant vector" unless node.expr.type == :vector
      when AST::MatrixSelector
        nil
      end
    end
  end
end
