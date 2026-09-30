# frozen_string_literal: true

# Security::Error is the parent of every CEL error; requiring it here keeps
# the CEL subtree loadable on its own (rubernetes/security/cel/types was not,
# which silently turned every result_type call into "error").
require_relative "../identity"

module Rubernetes
  module Security
    module CEL
      class Error < Security::Error; end
      class SyntaxError < Error; end
      class EvaluationError < Error; end
      class TypeMismatch < EvaluationError; end

      Token = Struct.new(:type, :value, :position)

      # CEL lexer (github.com/google/cel-spec/doc/langdef.md).
      class Lexer
        KEYWORDS = %w[true false null in].freeze
        RESERVED = %w[as break const continue else for function if import let loop package namespace return var void while].freeze
        OPERATORS = [".?", "[?", "==", "!=", "<=", ">=", "&&", "||", "+", "-", "*", "/", "%", "<", ">", "!", "?", ":", ".", ",", ";",
                     "[", "]", "{", "}", "(", ")", "="].freeze

        def initialize(source)
          @source = source.to_s
          @position = 0
        end

        def tokens
          list = []
          loop do
            skip_whitespace_and_comments
            break if @position >= @source.length

            list << next_token
          end
          list << Token.new(:eof, nil, @position)
          list
        end

        private

        def skip_whitespace_and_comments
          loop do
            if /\s/.match?(@source[@position])
              @position += 1
            elsif @source[@position, 2] == "//"
              newline = @source.index("\n", @position) || @source.length
              @position = newline
            else
              break
            end
          end
        end

        def next_token
          start = @position
          char = @source[@position]
          if /[A-Za-z_]/.match?(char)
            return lex_identifier(start)
          elsif char =~ /[0-9]/ || (char == "." && @source[@position + 1] =~ /[0-9]/)
            return lex_number(start)
          elsif ['"', "'"].include?(char)
            return Token.new(:string, lex_string(char), start)
          elsif %w[r R].include?(char) && ['"', "'"].include?(@source[@position + 1])
            @position += 1
            return Token.new(:string, lex_string(@source[@position], raw: true), start)
          elsif %w[b B].include?(char) && ['"', "'"].include?(@source[@position + 1])
            @position += 1
            return Token.new(:bytes, lex_string(@source[@position]).b, start)
          end

          OPERATORS.each do |operator|
            next unless @source[@position, operator.length] == operator

            @position += operator.length
            return Token.new(:operator, operator, start)
          end
          raise SyntaxError, "unexpected character #{char.inspect} at #{start}"
        end

        def lex_identifier(start)
          match = @source[@position..].match(/\A[A-Za-z_][A-Za-z0-9_]*/)
          word = match[0]
          @position += word.length
          if %w[r b R B].include?(word) && ['"', "'"].include?(@source[@position])
            raw = word.casecmp("r").zero?
            value = lex_string(@source[@position], raw: raw)
            return Token.new(raw ? :string : :bytes, raw ? value : value.b, start)
          end
          return Token.new(:reserved, word, start) if RESERVED.include?(word)
          return Token.new(:bool, word == "true", start) if %w[true false].include?(word)
          return Token.new(:null, nil, start) if word == "null"
          return Token.new(:operator, "in", start) if word == "in"

          Token.new(:identifier, word, start)
        end

        def lex_number(start)
          rest = @source[@position..]
          if (match = rest.match(/\A0[xX][0-9a-fA-F]+[uU]?/))
            @position += match[0].length
            unsigned = match[0].end_with?("u", "U")
            return Token.new(unsigned ? :uint : :int, Integer(match[0].sub(/[uU]\z/, ""), 16), start)
          end
          # NUM_FLOAT: digits are required after the dot ("1." is the int 1
          # followed by a selection).
          match = rest.match(/\A(?:[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?|\.[0-9]+(?:[eE][+-]?[0-9]+)?|[0-9]+[eE][+-]?[0-9]+)/)
          if match
            @position += match[0].length
            return Token.new(:double, Float(match[0].sub(/\A\./, "0.")), start)
          end
          match = rest.match(/\A[0-9]+[uU]?/)
          @position += match[0].length
          unsigned = match[0].end_with?("u", "U")
          Token.new(unsigned ? :uint : :int, Integer(match[0].sub(/[uU]\z/, ""), 10), start)
        end

        def lex_string(quote, raw: false)
          triple = @source[@position, 3] == quote * 3
          @position += triple ? 3 : 1
          buffer = +""
          loop do
            raise SyntaxError, "unterminated string" if @position >= @source.length

            if triple ? @source[@position, 3] == quote * 3 : @source[@position] == quote
              @position += triple ? 3 : 1
              break
            end
            char = @source[@position]
            if char == "\\" && !raw
              @position += 1
              buffer << lex_escape
            else
              raise SyntaxError, "newline in string literal" if char == "\n" && !triple

              buffer << char
              @position += 1
            end
          end
          buffer
        end

        def lex_escape
          char = @source[@position]
          @position += 1
          case char
          when "n" then "\n"
          when "t" then "\t"
          when "r" then "\r"
          when "a" then "\a"
          when "b" then "\b"
          when "f" then "\f"
          when "v" then "\v"
          when "\\" then "\\"
          when "?" then "?"
          when '"' then '"'
          when "'" then "'"
          when "`" then "`"
          when "x", "X"
            hex = @source[@position, 2]
            @position += 2
            hex.hex.chr(Encoding::UTF_8)
          when "u"
            hex = @source[@position, 4]
            @position += 4
            [hex.hex].pack("U")
          when "U"
            hex = @source[@position, 8]
            @position += 8
            [hex.hex].pack("U")
          when /[0-3]/
            octal = char + @source[@position, 2]
            @position += 2
            octal.oct.chr(Encoding::UTF_8)
          else
            raise SyntaxError, "invalid escape \\#{char}"
          end
        end
      end
    end
  end
end
