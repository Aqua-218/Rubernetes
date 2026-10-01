# frozen_string_literal: true

# A small, dependency-free protobuf descriptor reader and concrete Kubernetes
# message codec.  The Kubernetes corpus is generated proto2, but the parser is
# intentionally conservative: it understands the common proto2/proto3
# declarations and skips annotations without evaluating them.

# Define the descriptor namespace before loading the codec facade.  This lets
# callers require this file directly without making codec.rb require this same
# in-progress feature at the end of its load sequence.
module Rubernetes
  module Schema
    class Codec
      module ProtoDescriptor
      end
    end
  end
end

require_relative "../codec" unless defined?(Rubernetes::Schema::Codec::Protobuf)

module Rubernetes
  module Schema
    class Codec
      # Parses generated.proto files and uses the resulting descriptors to
      # encode/decode concrete Kubernetes messages.  This is deliberately a
      # generic descriptor implementation.  It does not claim to implement
      # generator-specific Go transformations (for example custom marshalers
      # or semantic time/quantity conversions).
      module ProtoDescriptor
        DEFAULT_MAX_BYTES = Codec::DEFAULT_MAX_BYTES
        DEFAULT_MAX_DEPTH = Codec::DEFAULT_MAX_DEPTH
        MAX_FIELD_NUMBER = Codec::Protobuf::MAX_FIELD_NUMBER
        MAX_DESCRIPTOR_FILES = 512

        SCALAR_TYPES = %w[
          double float int64 uint64 int32 fixed64 fixed32 bool string bytes
          uint32 sfixed32 sfixed64 sint32 sint64
        ].freeze
        INTEGER_TYPES = %i[int32 int64 uint32 uint64 fixed64 fixed32 sfixed32 sfixed64 sint32 sint64 enum].freeze
        VARINT_TYPES = %i[int32 int64 uint32 uint64 sint32 sint64 bool enum].freeze
        FIXED64_TYPES = %i[fixed64 sfixed64 double].freeze
        FIXED32_TYPES = %i[fixed32 sfixed32 float].freeze
        MAP_KEY_TYPES = %i[bool int32 int64 uint32 uint64 sint32 sint64 fixed32 fixed64 sfixed32 sfixed64 string].freeze

        class Error < StandardError; end
        class ParseError < Error; end
        class DuplicateFieldError < ParseError; end
        class DuplicateMessageError < ParseError; end
        class DuplicateEnumError < ParseError; end
        class UnknownMessageError < Error; end
        class UnknownFieldError < Codec::UnknownFieldError; end
        class LimitError < Error; end
        class UnsupportedTypeError < Error; end

        # A token is kept small and immutable so parse errors can include a
        # useful source location without retaining the full source string.
        Token = Struct.new(:kind, :value, :line, :column, keyword_init: true) do
          def initialize(**keywords)
            super
            freeze
          end
        end

        # A protobuf field descriptor.  +type+ is a scalar symbol or a message
        # / enum reference string.  +type_kind+ identifies which interpretation
        # applies; references are resolved by Registry after all files load.
        class FieldDescriptor
          attr_reader :name, :json_name, :number, :label, :type, :type_kind,
                      :type_name, :map, :key_type, :value_type, :value_type_kind,
                      :value_type_name, :packed, :oneof, :options, :parent

          def initialize(name:, json_name:, number:, label:, type:, type_kind:, parent: nil,
                         map: false, key_type: nil, value_type: nil, value_type_kind: nil,
                         value_type_name: nil, packed: false, oneof: nil, options: {})
            @name = String(name).freeze
            @json_name = String(json_name).freeze
            @number = Integer(number)
            @label = (label || :optional).to_sym
            @type_kind = type_kind.to_sym
            @type = @type_kind == :scalar ? type.to_sym : String(type).freeze
            @type_name = @type_kind == :scalar ? nil : @type
            @map = !!map
            @key_type = key_type&.to_sym
            @value_type_kind = value_type_kind&.to_sym
            @value_type = if @value_type_kind == :scalar
                            value_type.to_sym
                          elsif value_type.nil?
                            nil
                          else
                            String(value_type).freeze
                          end
            @value_type_name = @value_type_kind == :scalar ? nil : @value_type
            @packed = !!packed
            @oneof = oneof&.to_s&.freeze
            @options = (options || {}).transform_keys(&:to_s).freeze
            @parent = parent
            freeze
          end

          def scalar?
            type_kind == :scalar
          end

          def message?
            type_kind == :message
          end

          def enum?
            type_kind == :enum
          end

          def repeated?
            label == :repeated
          end

          def optional?
            label == :optional
          end

          def required?
            label == :required
          end

          alias map? map
          alias message_type? message?

          def packed?
            packed
          end

          def type_ref
            type_name || type
          end

          def value_type_ref
            value_type_name || value_type
          end

          def to_h
            {
              name: name,
              json_name: json_name,
              number: number,
              label: label,
              type: type,
              type_kind: type_kind,
              map: map,
              key_type: key_type,
              value_type: value_type,
              value_type_kind: value_type_kind,
              packed: packed,
              oneof: oneof
            }.compact.freeze
          end
        end

        class EnumValueDescriptor
          attr_reader :name, :number, :options

          def initialize(name:, number:, options: {})
            @name = String(name).freeze
            @number = Integer(number)
            @options = (options || {}).transform_keys(&:to_s).freeze
            freeze
          end

          def to_h
            {name: name, number: number, options: options}.freeze
          end
        end

        class EnumDescriptor
          attr_reader :name, :full_name, :package, :values, :values_by_name, :values_by_number, :parent

          def initialize(name:, full_name:, package:, values:, parent: nil, options: {})
            @name = String(name).freeze
            @full_name = String(full_name).freeze
            @package = String(package || "").freeze
            @values = values.sort_by(&:number).freeze
            @values_by_name = values.to_h { |value| [value.name, value] }.freeze
            @values_by_number = values.to_h { |value| [value.number, value] }.freeze
            @parent = parent
            @options = (options || {}).transform_keys(&:to_s).freeze
            freeze
          end

          def [](value)
            case value
            when Integer then values_by_number[value]
            else values_by_name[value.to_s]
            end
          end

          def value(value)
            self[value]
          end

          def to_h
            {name: name, full_name: full_name, package: package, values: values.map(&:to_h)}.freeze
          end
        end

        class MessageDescriptor
          attr_reader :name, :full_name, :package, :fields, :fields_by_name,
                      :fields_by_json_name, :fields_by_number, :nested_messages,
                      :enums, :parent, :map_entry, :options

          def initialize(name:, full_name:, package:, fields:, parent: nil, nested_messages: [],
                         enums: [], map_entry: false, options: {})
            @name = String(name).freeze
            @full_name = String(full_name).freeze
            @package = String(package || "").freeze
            @fields = fields.sort_by(&:number).freeze
            @fields_by_name = fields.to_h { |field| [field.name, field] }.freeze
            @fields_by_json_name = fields.to_h { |field| [field.json_name, field] }.freeze
            @fields_by_number = fields.to_h { |field| [field.number, field] }.freeze
            @nested_messages = nested_messages.freeze
            @enums = enums.freeze
            @parent = parent
            @map_entry = !!map_entry
            @options = (options || {}).transform_keys(&:to_s).freeze
            freeze
          end

          def [](name_or_number)
            field(name_or_number)
          end

          def field(name_or_number)
            return fields_by_number[name_or_number] if name_or_number.is_a?(Integer)

            value = name_or_number.to_s
            fields_by_name[value] || fields_by_json_name[value] || fields.find { |item| item.name.casecmp?(value) }
          end

          alias field_for field

          def message?
            true
          end

          def to_h
            {
              name: name,
              full_name: full_name,
              package: package,
              map_entry: map_entry,
              fields: fields.map(&:to_h)
            }.freeze
          end
        end

        class FileDescriptor
          attr_reader :path, :package, :syntax, :imports, :messages, :enums, :options

          def initialize(path:, package:, syntax:, imports:, messages:, enums:, options: {})
            @path = path && String(path).freeze
            @package = String(package || "").freeze
            @syntax = String(syntax || "proto2").freeze
            @imports = Array(imports).map { |item| String(item).freeze }.freeze
            @messages = messages.freeze
            @enums = enums.freeze
            @options = (options || {}).transform_keys(&:to_s).freeze
            freeze
          end
        end

        Field = FieldDescriptor
        Message = MessageDescriptor
        Enum = EnumDescriptor
        File = FileDescriptor

        # Lexer for the generated corpus.  It does not execute option values;
        # quoted strings are decoded only enough to expose import/option text.
        class Lexer
          PUNCTUATION = "{}[]=;<>(),.:+-"
          PUNCTUATION_BYTES = PUNCTUATION.bytes.freeze
          IDENTIFIER_START = /[A-Za-z_]/
          IDENTIFIER_CONTINUATION = /[A-Za-z0-9_]/

          def initialize(source, max_bytes: DEFAULT_MAX_BYTES)
            raise ParseError, "protobuf source must be a String" unless source.is_a?(String)
            raise LimitError, "protobuf source exceeds #{max_bytes} bytes" if source.bytesize > max_bytes

            @source = source.dup.force_encoding(Encoding::UTF_8)
            raise ParseError, "protobuf source must be valid UTF-8" unless @source.valid_encoding?

            @length = @source.bytesize
            @index = 0
            @line = 1
            @column = 1
            @tokens = nil
          end

          def tokens
            return @tokens if @tokens

            result = []
            until eof?
              skip_space_and_comments
              break if eof?

              token_line = @line
              token_column = @column
              char = current_char
              byte = current_byte
              if char.match?(IDENTIFIER_START)
                value = consume_identifier
                result << Token.new(kind: :identifier, value: value, line: token_line, column: token_column)
              elsif digit_byte?(byte) || ([43, 45].include?(byte) && digit_byte?(next_byte))
                value = consume_number
                result << Token.new(kind: :number, value: value, line: token_line, column: token_column)
              elsif byte == 34
                result << Token.new(kind: :string, value: consume_string, line: token_line, column: token_column)
              elsif PUNCTUATION_BYTES.include?(byte)
                advance_char
                result << Token.new(kind: :punctuation, value: char, line: token_line, column: token_column)
              else
                raise ParseError, "unexpected character #{char.inspect} at #{token_line}:#{token_column}"
              end
            end
            result.freeze
          end

          private

          def eof?
            @index >= @length
          end

          def current_char
            byte = current_byte
            byte&.chr(Encoding::BINARY)
          end

          def next_char
            byte = next_byte
            byte&.chr(Encoding::BINARY)
          end

          def current_byte
            @source.getbyte(@index)
          end

          def next_byte
            @source.getbyte(@index + 1)
          end

          def advance_char
            byte = current_byte
            @index += 1
            if byte == 10
              @line += 1
              @column = 1
            else
              @column += 1
            end
            byte&.chr(Encoding::BINARY)
          end

          def skip_space_and_comments
            loop do
              advance_char while !eof? && whitespace_byte?(current_byte)
              if current_byte == 47 && next_byte == 47
                advance_char
                advance_char
                advance_char until eof? || current_byte == 10
                next
              end
              if current_byte == 47 && next_byte == 42
                start_line = @line
                start_column = @column
                advance_char
                advance_char
                advance_char until eof? || (current_byte == 42 && next_byte == 47)
                raise ParseError, "unterminated comment at #{start_line}:#{start_column}" if eof?

                advance_char
                advance_char
                next
              end
              break
            end
          end

          def consume_identifier
            start = @index
            advance_char
            advance_char while !eof? && identifier_continuation_byte?(current_byte)
            @source.byteslice(start, @index - start)
          end

          def consume_number
            start = @index
            advance_char if [43, 45].include?(current_byte)
            if current_byte == 48 && [120, 88].include?(next_byte)
              advance_char
              advance_char
              advance_char while !eof? && hex_byte?(current_byte)
            else
              advance_char while !eof? && digit_byte?(current_byte)
              if current_byte == 46
                advance_char
                advance_char while !eof? && digit_byte?(current_byte)
              end
              if [101, 69].include?(current_byte)
                advance_char
                advance_char if [43, 45].include?(current_byte)
                advance_char while !eof? && digit_byte?(current_byte)
              end
            end
            @source.byteslice(start, @index - start)
          end

          def consume_string
            advance_char # opening quote
            output = +"".b
            until eof?
              byte = current_byte
              advance_char
              return output.dup.force_encoding(Encoding::UTF_8) if byte == 34

              if byte == 92
                raise ParseError, "unterminated string at #{@line}:#{@column}" if eof?

                escaped = current_byte
                advance_char
                output << case escaped
                          when 97 then "\a"
                          when 98 then "\b"
                          when 102 then "\f"
                          when 110 then "\n"
                          when 114 then "\r"
                          when 116 then "\t"
                          when 118 then "\v"
                          when 92 then "\\"
                          when 34 then '"'
                          when 39 then "'"
                          when 120
                            hex = Array.new(2) { advance_char }.join
                            raise ParseError, "invalid hex escape" unless hex.match?(/\A[0-9a-fA-F]{2}\z/)

                            hex.to_i(16).chr(Encoding::BINARY)
                          when 48..55
                            digits = escaped.chr
                            2.times do
                              break unless digit_octal_byte?(current_byte)

                              digits << advance_char
                            end
                            digits.to_i(8).chr(Encoding::BINARY)
                          else
                            escaped.chr(Encoding::BINARY)
                          end
              else
                raise ParseError, "newline in string literal" if [10, 13].include?(byte)

                output << byte
              end
            end
            raise ParseError, "unterminated string literal"
          end

          def digit_byte?(byte)
            byte && byte >= 48 && byte <= 57
          end

          def digit_octal_byte?(byte)
            byte && byte >= 48 && byte <= 55
          end

          def hex_byte?(byte)
            digit_byte?(byte) || (byte && byte >= 65 && byte <= 70) || (byte && byte >= 97 && byte <= 102)
          end

          def identifier_continuation_byte?(byte)
            (byte && byte >= 65 && byte <= 90) || (byte && byte >= 97 && byte <= 122) ||
              (byte && byte >= 48 && byte <= 57) || byte == 95
          end

          def whitespace_byte?(byte)
            byte && [9, 10, 11, 12, 13, 32].include?(byte)
          end
        end

        # Recursive-descent parser.  Generated files contain no executable
        # constructs; unknown declarations are skipped with balanced braces so
        # a newer generator annotation cannot desynchronise parsing.
        class Parser
          def initialize(source, path: nil, max_bytes: DEFAULT_MAX_BYTES, max_depth: DEFAULT_MAX_DEPTH)
            @tokens = Lexer.new(source, max_bytes: max_bytes).tokens
            @path = path
            @max_depth = Integer(max_depth)
            raise ArgumentError, "max_depth must be non-negative" if @max_depth.negative?

            @position = 0
          end

          def parse
            package = ""
            syntax = "proto2"
            imports = []
            options = {}
            messages = []
            enums = []
            until eof?
              case current_value
              when "syntax"
                advance
                expect("=")
                syntax = expect_kind(:string).value
                expect(";")
              when "package"
                advance
                package = parse_qualified_name
                expect(";")
              when "import"
                advance
                advance if %w[public weak].include?(current_value)
                imports << expect_kind(:string).value
                expect(";")
              when "option"
                advance
                key, value = parse_option_statement
                options[key] = value if key
              when "message"
                messages << parse_message(package, nil, 0)
              when "enum"
                enums << parse_enum(package, nil, 0)
              when "extend"
                skip_declaration
              else
                skip_declaration
              end
            end
            FileDescriptor.new(path: @path, package: package, syntax: syntax, imports: imports,
                               messages: messages, enums: enums, options: options)
          rescue ParseError
            raise
          rescue StandardError => error
            raise ParseError, "cannot parse #{@path || "protobuf source"}: #{error.message}"
          end

          private

          def parse_message(package, parent, depth)
            check_depth!(depth)
            expect("message")
            name = expect_identifier
            full_name = if parent
                          "#{parent.full_name}.#{name}"
                        elsif package.empty?
                          name
                        else
                          "#{package}.#{name}"
                        end
            expect("{")
            fields = []
            nested_messages = []
            enums = []
            options = {}
            map_entry = false
            nil
            until eof? || current_value == "}"
              case current_value
              when "message"
                nested_messages << parse_message(package, placeholder_message(name, full_name, package, parent), depth + 1)
              when "enum"
                enums << parse_enum(package, placeholder_message(name, full_name, package, parent), depth + 1)
              when "option"
                advance
                key, value = parse_option_statement
                options[key] = value if key
                map_entry = true if key.to_s == "map_entry" && truthy_option?(value)
              when "oneof"
                oneof = parse_oneof(package, full_name, parent, fields, depth)
                oneof.each { |field| fields << field }
              when "reserved", "extensions"
                skip_declaration
              when "extend", "service"
                skip_declaration
              when "optional", "required", "repeated"
                label = advance.value.to_sym
                fields << parse_field(package, full_name, parent, label, nil)
              when "map"
                fields << parse_map_field(package, full_name, parent)
              else
                # Proto3 permits an unlabeled field.  If the declaration does
                # not look like a field, consume it safely as an annotation.
                fields << parse_field(package, full_name, parent, :optional, nil)
              end
            end
            expect("}")
            descriptor = MessageDescriptor.new(name: name, full_name: full_name, package: package,
                                               fields: fields, parent: parent,
                                               nested_messages: nested_messages, enums: enums,
                                               map_entry: map_entry, options: options)
            # Field descriptors retain their parent for resolution.  Rebuild
            # them once the immutable message descriptor exists.
            rebound_fields = fields.map { |field| rebind_field(field, descriptor) }
            rebound_nested = nested_messages.map { |nested| rebind_parent(nested, descriptor) }
            MessageDescriptor.new(name: name, full_name: full_name, package: package,
                                  fields: rebound_fields, parent: parent,
                                  nested_messages: rebound_nested, enums: enums,
                                  map_entry: map_entry, options: options)
          end

          def parse_oneof(package, full_name, parent, _fields, depth)
            check_depth!(depth)
            expect("oneof")
            oneof_name = expect_identifier
            expect("{")
            fields = []
            until eof? || current_value == "}"
              if current_value == "option"
                skip_declaration
              else
                fields << parse_field(package, full_name, parent, :optional, oneof_name)
              end
            end
            expect("}")
            fields
          end

          def parse_field(_package, _full_name, parent, label, oneof)
            type = parse_type_name
            name = expect_identifier
            expect("=")
            number = parse_field_number
            options = parse_field_options
            expect(";")
            type_kind = scalar_type?(type) ? :scalar : :message
            type_value = type_kind == :scalar ? type.to_sym : type
            FieldDescriptor.new(
              name: name,
              json_name: option_value(options, "json_name") || camelize(name),
              number: number,
              label: label,
              type: type_value,
              type_kind: type_kind,
              parent: parent,
              packed: truthy_option?(option_value(options, "packed")),
              oneof: oneof,
              options: options
            )
          end

          def parse_map_field(_package, _full_name, parent)
            expect("map")
            expect("<")
            key_type = parse_type_name
            expect(",")
            value_type = parse_type_name
            expect(">")
            name = expect_identifier
            expect("=")
            number = parse_field_number
            options = parse_field_options
            expect(";")
            key_type = key_type.to_sym
            value_kind = scalar_type?(value_type) ? :scalar : :message
            value = value_kind == :scalar ? value_type.to_sym : value_type
            raise ParseError, "invalid protobuf map key type #{key_type.inspect}" unless MAP_KEY_TYPES.include?(key_type)

            FieldDescriptor.new(
              name: name,
              json_name: option_value(options, "json_name") || camelize(name),
              number: number,
              label: :repeated,
              type: value,
              type_kind: value_kind,
              parent: parent,
              map: true,
              key_type: key_type,
              value_type: value,
              value_type_kind: value_kind,
              value_type_name: value_kind == :message ? value : nil,
              options: options
            )
          end

          def parse_enum(package, parent, depth)
            check_depth!(depth)
            expect("enum")
            name = expect_identifier
            full_name = if parent
                          "#{parent.full_name}.#{name}"
                        elsif package.empty?
                          name
                        else
                          "#{package}.#{name}"
                        end
            expect("{")
            values = []
            options = {}
            until eof? || current_value == "}"
              if current_value == "option"
                advance
                key, value = parse_option_statement
                options[key] = value if key
              else
                value_name = expect_identifier
                expect("=")
                value_number = parse_signed_integer
                value_options = parse_field_options
                expect(";")
                raise DuplicateFieldError, "duplicate enum value #{full_name}.#{value_name}" if values.any? { |item| item.name == value_name }

                values << EnumValueDescriptor.new(name: value_name, number: value_number, options: value_options)
              end
            end
            expect("}")
            EnumDescriptor.new(name: name, full_name: full_name, package: package,
                               values: values, parent: parent, options: options)
          end

          def parse_option_statement
            key_parts = []
            value = nil
            depth = 0
            until eof?
              token = current
              break if depth.zero? && token.value == ";"

              if token.value == "=" && depth.zero?
                advance
                value = parse_option_value
                # Consume any trailing tokens until the semicolon.  This keeps
                # custom option syntax parseable without evaluating it.
                advance while !eof? && current_value != ";"
                break
              end
              depth += 1 if ["(", "[", "{"].include?(token.value)
              depth -= 1 if [")", "]", "}"].include?(token.value)
              key_parts << token.value
              advance
            end
            expect(";")
            [key_parts.join, value]
          end

          def parse_option_value
            token = current
            case token.kind
            when :string
              advance
              token.value
            when :number
              advance
              parse_number(token.value)
            when :identifier
              advance
              case token.value
              when "true" then true
              when "false" then false
              else token.value
              end
            else
              token.value.tap { advance }
            end
          end

          def parse_field_options
            return {} unless current_value == "["

            expect("[")
            options = {}
            until eof? || current_value == "]"
              key_parts = []
              depth = 0
              until eof?
                token = current
                break if depth.zero? && ["=", ",", "]"].include?(token.value)

                depth += 1 if token.value == "("
                depth -= 1 if token.value == ")"
                key_parts << token.value
                advance
              end
              key = key_parts.join
              if current_value == "="
                advance
                options[key] = parse_option_value
              else
                options[key] = true unless key.empty?
              end
              advance if current_value == ","
            end
            expect("]")
            options
          end

          def skip_declaration
            depth = 0
            until eof?
              token = advance
              if token.value == "{"
                depth += 1
              elsif token.value == "}"
                if depth.zero?
                  @position -= 1
                  break
                end
                depth -= 1
              elsif token.value == ";" && depth.zero?
                break
              end
            end
          end

          def parse_type_name
            leading_dot = false
            if current_value == "."
              leading_dot = true
              advance
            end
            parts = [expect_identifier]
            while current_value == "."
              advance
              parts << expect_identifier
            end
            value = parts.join(".")
            leading_dot ? ".#{value}" : value
          end

          def parse_qualified_name
            parse_type_name.delete_prefix(".")
          end

          def parse_field_number
            value = parse_signed_integer
            raise ParseError, "protobuf field number #{value} is outside 1..#{MAX_FIELD_NUMBER}" unless (1..MAX_FIELD_NUMBER).cover?(value)

            value
          end

          def parse_signed_integer
            token = expect_kind(:number)
            value = parse_number(token.value)
            raise ParseError, "protobuf field number must be an integer" unless value.is_a?(Integer)

            value
          end

          def parse_number(value)
            string = String(value)
            if string.match?(/\A[+-]?0[xX][0-9a-fA-F]+\z/)
              sign = string.start_with?("-") ? -1 : 1
              sign * string.sub(/\A[+-]?0[xX]/, "").to_i(16)
            elsif string.match?(/\A[+-]?\d+\z/)
              string.to_i
            else
              Float(string)
            end
          rescue ArgumentError
            raise ParseError, "invalid protobuf number #{value.inspect}"
          end

          def expect_identifier
            expect_kind(:identifier).value
          end

          def expect_kind(kind)
            token = current
            return advance if token&.kind == kind

            raise ParseError, "expected #{kind}, got #{token&.value.inspect} at #{token&.line}:#{token&.column}"
          end

          def expect(value)
            token = current
            return advance if token && token.value == value

            raise ParseError, "expected #{value.inspect}, got #{token&.value.inspect} at #{token&.line}:#{token&.column}"
          end

          def current
            @tokens[@position]
          end

          def current_value
            current&.value
          end

          def advance
            token = current
            @position += 1 unless eof?
            token
          end

          def eof?
            @position >= @tokens.length
          end

          def check_depth!(depth)
            raise LimitError, "protobuf descriptor nesting exceeds #{@max_depth}" if depth > @max_depth
          end

          def scalar_type?(type)
            SCALAR_TYPES.include?(type.to_s.delete_prefix("."))
          end

          def option_value(options, key)
            options[key] || options["(#{key})"]
          end

          def truthy_option?(value)
            value == true || value.to_s == "true" || value.to_s == "1"
          end

          def camelize(name)
            name.to_s.split("_").each_with_index.map { |part, index| index.zero? ? part : part[0].to_s.upcase + part[1..].to_s }.join
          end

          # During parsing nested references need a parent-like object before
          # the final immutable descriptor exists.  It only supplies names.
          def placeholder_message(name, full_name, package, parent)
            MessageDescriptor.new(name: name, full_name: full_name, package: package,
                                  fields: [], parent: parent)
          end

          def rebind_field(field, message)
            FieldDescriptor.new(
              name: field.name, json_name: field.json_name, number: field.number,
              label: field.label, type: field.type, type_kind: field.type_kind,
              parent: message, map: field.map, key_type: field.key_type,
              value_type: field.value_type, value_type_kind: field.value_type_kind,
              packed: field.packed, oneof: field.oneof, options: field.options
            )
          end

          def rebind_parent(message, parent)
            fields = message.fields.map { |field| rebind_field(field, message) }
            nested = message.nested_messages.map { |child| rebind_parent(child, message) }
            MessageDescriptor.new(name: message.name, full_name: message.full_name,
                                  package: message.package, fields: fields, parent: parent,
                                  nested_messages: nested, enums: message.enums,
                                  map_entry: message.map_entry, options: message.options)
          end
        end

        # A decoded concrete message is still a Hash for ergonomic API use, but
        # wire-level unknown fields live out-of-band so they cannot collide with
        # a user field called "unknown_fields".
        class MessageValue < Hash
          attr_reader :unknown_fields, :original_bytes

          def initialize(values = {}, unknown_fields: [], original_bytes: nil)
            super()
            update(values)
            @unknown_fields = Array(unknown_fields).map { |field| normalize_unknown(field) }.freeze
            @original_bytes = original_bytes&.then { |bytes| bytes.dup.force_encoding(Encoding::BINARY).freeze }
            @original_fingerprint = fingerprint
          end

          def encoded
            original_bytes
          end

          alias raw original_bytes

          def unknown_fields=(fields)
            @unknown_fields = Array(fields).map { |field| normalize_unknown(field) }.freeze
            @original_fingerprint = nil
          end

          def [](key)
            return unknown_fields if %w[unknown_fields unknownFields __protobuf_unknown_fields__].include?(key.to_s)

            super
          end

          def fetch(key, *args, &block)
            return unknown_fields if %w[unknown_fields unknownFields __protobuf_unknown_fields__].include?(key.to_s) && args.none? && !block

            super
          end

          def original_unchanged?
            !original_bytes.nil? && @original_fingerprint == fingerprint
          end

          private

          def normalize_unknown(field)
            hash = field.respond_to?(:to_h) ? field.to_h : field
            hash = hash.transform_keys(&:to_sym)
            encoded = hash[:encoded]
            raise EncodeError, "unknown protobuf field requires encoded bytes" unless encoded.is_a?(String)

            hash.merge(encoded: encoded.dup.force_encoding(Encoding::BINARY).freeze).freeze
          end

          def fingerprint
            Marshal.dump([to_h, @unknown_fields])
          rescue TypeError
            [to_h, @unknown_fields].hash
          end
        end

        DecodedMessage = MessageValue

        class EnvelopeMessage < MessageValue
          attr_reader :type_meta, :content_encoding, :content_type, :raw

          def initialize(values = {}, type_meta:, content_encoding:, content_type:, raw:, unknown_fields: [], original_bytes: nil)
            super(values, unknown_fields: unknown_fields, original_bytes: original_bytes)
            @type_meta = type_meta
            @content_encoding = content_encoding
            @content_type = content_type
            @raw = raw.dup.force_encoding(Encoding::BINARY).freeze
            freeze
          end

          alias payload itself

          def itself
            self
          end
        end

        # Descriptor registry and concrete wire codec.
        class Registry
          attr_reader :files, :messages, :enums, :gvk_index, :openapi_index

          class << self
            def parse(source, path: nil, **)
              new([Parser.new(source, path: path, **).parse], **)
            end

            def load(path, **)
              new.load_path(path, **)
            end

            alias from_path load
            alias build load
          end

          def initialize(files = nil, max_bytes: DEFAULT_MAX_BYTES, max_depth: DEFAULT_MAX_DEPTH,
                         max_files: MAX_DESCRIPTOR_FILES)
            @max_bytes = Integer(max_bytes)
            @max_depth = Integer(max_depth)
            @max_files = Integer(max_files)
            raise ArgumentError, "max_bytes must be non-negative" if @max_bytes.negative?
            raise ArgumentError, "max_depth must be non-negative" if @max_depth.negative?
            raise ArgumentError, "max_files must be positive" unless @max_files.positive?

            @files = []
            @messages = {}
            @enums = {}
            @gvk_index = {}
            @openapi_index = {}
            add_files(files) if files
          end

          def load_path(path, **_options)
            paths = descriptor_paths(path)
            raise LimitError, "protobuf descriptor file count exceeds #{@max_files}" if paths.length > @max_files

            paths.each do |file_path|
              source = ::File.binread(file_path)
              add_file(Parser.new(source, path: file_path, max_bytes: @max_bytes, max_depth: @max_depth).parse)
            end
            finalize!
            self
          end

          def add_files(descriptors)
            Array(descriptors).each { |descriptor| add_file(descriptor) }
            finalize!
            self
          end

          def add_file(descriptor)
            raise ArgumentError, "descriptor must be a FileDescriptor" unless descriptor.is_a?(FileDescriptor)
            return self if @files.any? { |item| item.path == descriptor.path && descriptor.path }

            descriptor.messages.each { |message| register_message(message) }
            descriptor.enums.each { |enum| register_enum(enum) }
            @files << descriptor
            self
          end

          def finalize!
            @messages.each_value do |message|
              message.fields.each do |field|
                next unless field.message? || field.enum? || (field.map? && field.value_type_kind != :scalar)

                # Validate references early.  Keep unresolved descriptors
                # readable, but fail registry construction rather than emit a
                # wire message with a guessed field type.
                resolve_field_type(field, message)
              end
            end
            build_indexes!
            self
          end

          def [](name)
            resolve(name)
          end

          def fetch(name)
            resolve(name) || raise(UnknownMessageError, "unknown protobuf message #{name.inspect}")
          end

          def resolve(name = nil, group: nil, version: nil, kind: nil, gvk: nil, schema: nil)
            return resolve_gvk(gvk || {group: group, version: version, kind: kind}) if gvk || group || version || kind

            name = schema unless schema.nil?
            return name if name.is_a?(MessageDescriptor)
            return nil if name.nil?

            value = name.to_s
            @messages[value] || @messages[value.delete_prefix(".")] ||
              @messages[openapi_to_proto(value)] || resolve_gvk_string(value)
          end

          alias resolve_openapi resolve
          alias resolve_schema resolve
          alias message resolve
          alias message_for resolve

          def resolve_gvk(value = nil, group: nil, version: nil, kind: nil)
            if value && !group && !version && !kind
              if value.respond_to?(:group) && value.respond_to?(:version) && value.respond_to?(:kind)
                group = value.group
                version = value.version
                kind = value.kind
              elsif value.is_a?(Hash)
                group = value[:group] || value["group"] || ""
                version = value[:version] || value["version"]
                kind = value[:kind] || value["kind"]
              elsif value.is_a?(String)
                return resolve_gvk_string(value)
              end
            end
            raise ArgumentError, "GVK requires version and kind" if version.nil? || kind.nil?

            @gvk_index[[String(group || ""), String(version), String(kind)]]
          end

          alias message_for_gvk resolve_gvk
          alias lookup_gvk resolve_gvk

          # Resolves a field's concrete descriptor (or returns its scalar
          # symbol).  This is useful to descriptor-driven generators without
          # exposing the registry's protobuf name-resolution internals.
          def type_for(field)
            raise ArgumentError, "field must be a FieldDescriptor" unless field.is_a?(FieldDescriptor)

            if field.map?
              return field.value_type if field.value_type_kind == :scalar

              resolve_map_value_message(field)
            elsif field.scalar?
              field.type
            elsif field.enum?
              resolve_enum(field.type_ref, field.parent)
            else
              resolve_message_field(field)
            end
          end

          alias resolve_type type_for

          def encode(message, object, strict: true, max_bytes: @max_bytes, max_depth: @max_depth)
            descriptor = fetch(message)
            if object.is_a?(EnvelopeMessage) && object.original_unchanged?
              return Codec.validate_output!(object.raw.dup.b, max_bytes)
            elsif object.is_a?(MessageValue) && object.original_unchanged? && object.original_bytes
              return Codec.validate_output!(object.original_bytes.dup.b, max_bytes)
            end

            normalized = normalize_object(object, max_depth: max_depth)
            encoded = encode_descriptor(descriptor, normalized, strict: strict, max_bytes: max_bytes,
                                                                max_depth: max_depth, depth: 0)
            Codec.validate_output!(encoded, max_bytes)
          rescue Codec::Error
            raise
          rescue Error
            raise
          rescue StandardError => error
            raise Codec::EncodeError.new("cannot encode #{descriptor_name(message)}: #{error.message}"), cause: error
          end

          alias encode_message encode
          alias encode_concrete encode
          alias dump encode

          def decode(message, input, strict: true, max_bytes: @max_bytes, max_depth: @max_depth,
                     keys: :json, unknown_fields: :preserve, compatibility: nil)
            descriptor = fetch(message)
            Codec.validate_body!(input, max_bytes)
            unknown_policy = normalize_unknown_policy(unknown_fields, compatibility)
            decode_descriptor(descriptor, input, strict: strict, max_bytes: max_bytes,
                                                 max_depth: max_depth, depth: 0, keys: keys,
                                                 unknown_policy: unknown_policy)
          rescue Codec::Error
            raise
          rescue Error
            raise
          rescue StandardError => error
            raise Codec::ParseError.new("cannot decode #{descriptor_name(message)}: #{error.message}"), cause: error
          end

          alias decode_message decode
          alias decode_concrete decode
          alias load decode

          # Kubernetes protobuf serializes a concrete object as the raw payload
          # of runtime.Unknown behind the k8s\0 marker.  TypeMeta is derived from
          # the indexed GVK when it is not supplied by the caller.
          def encode_envelope(message, object, type_meta: nil,
                              content_type: nil,
                              content_encoding: nil, strict: true,
                              max_bytes: @max_bytes, max_depth: @max_depth)
            descriptor = fetch(message)
            if object.is_a?(EnvelopeMessage) && type_meta.nil? && content_type.nil? && content_encoding.nil? &&
               object.original_unchanged? && object.original_bytes
              return Codec.validate_output!(object.original_bytes.dup.b, max_bytes)
            end

            raw = encode(descriptor, object, strict: strict, max_bytes: max_bytes, max_depth: max_depth)
            type_meta ||= default_type_meta(descriptor)
            content_type ||= object.content_type if object.is_a?(EnvelopeMessage)
            content_encoding ||= object.content_encoding if object.is_a?(EnvelopeMessage)
            content_type ||= "application/vnd.kubernetes.protobuf"
            Codec::Protobuf.encode_envelope(
              raw: raw, content_type: content_type, content_encoding: content_encoding,
              type_meta: type_meta, max_bytes: max_bytes, max_depth: max_depth
            )
          end

          alias encode_kubernetes encode_envelope
          alias encode_kubernetes_protobuf encode_envelope
          alias encode_runtime_unknown encode_envelope
          alias encode_protobuf encode_envelope

          def decode_envelope(message, input, strict: true, max_bytes: @max_bytes,
                              max_depth: @max_depth, keys: :json,
                              unknown_fields: :preserve, compatibility: nil)
            descriptor = fetch(message)
            envelope = Codec::Protobuf.decode_envelope(input, strict: strict,
                                                              max_bytes: max_bytes, max_depth: max_depth)
            value = decode(descriptor, envelope.raw, strict: strict, max_bytes: max_bytes,
                                                     max_depth: max_depth, keys: keys, unknown_fields: unknown_fields,
                                                     compatibility: compatibility)
            preserve_original = normalize_unknown_policy(unknown_fields, compatibility) == :preserve
            EnvelopeMessage.new(value, type_meta: envelope.type_meta,
                                       content_encoding: envelope.content_encoding,
                                       content_type: envelope.content_type, raw: value.original_bytes,
                                       unknown_fields: value.unknown_fields,
                                       original_bytes: preserve_original ? input : nil)
          end

          alias decode_kubernetes decode_envelope
          alias decode_kubernetes_protobuf decode_envelope
          alias decode_runtime_unknown decode_envelope
          alias decode_protobuf decode_envelope

          def encode_descriptor(descriptor, value, strict:, max_bytes:, max_depth:, depth:)
            check_depth!(depth, max_depth)
            hash = value.respond_to?(:to_h) ? value.to_h : value
            raise Codec::UnsupportedTypeError, "#{descriptor.full_name} requires a Hash or to_h" unless hash.is_a?(Hash)

            fields = {}
            hash.each do |key, item|
              next if unknown_key?(key)

              field = descriptor.field(key)
              if field.nil?
                raise UnknownFieldError, "unknown field #{key.inspect} for #{descriptor.full_name}" if strict

                next
              end
              raise Codec::DuplicateKeyError, "duplicate field #{field.json_name.inspect}" if fields.key?(field)

              fields[field] = item
            end

            output = +"".b
            descriptor.fields.each do |field|
              next unless fields.key?(field)

              item = fields[field]
              next if item.nil?

              if field.map?
                output << encode_map_field(field, item, strict: strict, max_bytes: max_bytes,
                                                        max_depth: max_depth, depth: depth + 1)
              elsif field.repeated?
                raise Codec::EncodeError, "repeated field #{field.json_name} must be an Array" unless item.is_a?(Array)

                output << encode_repeated_field(field, item, strict: strict, max_bytes: max_bytes,
                                                             max_depth: max_depth, depth: depth + 1)
              else
                output << Codec::Protobuf.encode_field(field.number,
                                                       encode_value(field, item, strict: strict,
                                                                                 max_bytes: max_bytes,
                                                                                 max_depth: max_depth, depth: depth + 1),
                                                       type: wire_type_for(field))
              end
            end
            unknown_fields_for(value).each { |field| output << field.fetch(:encoded) }
            Codec.validate_output!(output, max_bytes)
          end

          def decode_descriptor(descriptor, input, strict:, max_bytes:, max_depth:, depth:, keys:,
                                unknown_policy:)
            check_depth!(depth, max_depth)
            return input if input.is_a?(MessageValue) && input.original_unchanged?

            fields = Codec::Protobuf.parse_fields(input, strict: strict, max_bytes: max_bytes,
                                                         max_depth: max_depth)
            values = {}
            unknown = []
            fields.each do |wire_field|
              field = descriptor.fields_by_number[wire_field[:number]]
              if field.nil?
                unknown << wire_field.slice(:number, :wire_type, :value, :encoded) if unknown_policy == :preserve
                next
              end
              if field.map?
                key, map_value = decode_map_entry(field, wire_field[:value], strict: strict,
                                                                             max_bytes: max_bytes, max_depth: max_depth,
                                                                             depth: depth + 1, keys: keys,
                                                                             unknown_policy: unknown_policy)
                output_key = output_key(field, keys)
                values[output_key] ||= {}
                values[output_key][key] = map_value
              elsif field.repeated? && packed_wire?(field, wire_field[:wire_type])
                output_key = output_key(field, keys)
                values[output_key] ||= []
                values[output_key].concat(decode_packed(field, wire_field[:value], strict: strict,
                                                                                   max_bytes: max_bytes, max_depth: max_depth,
                                                                                   depth: depth + 1, keys: keys))
              else
                item = decode_value(field, wire_field, strict: strict, max_bytes: max_bytes,
                                                       max_depth: max_depth, depth: depth + 1, keys: keys,
                                                       unknown_policy: unknown_policy)
                output_key = output_key(field, keys)
                if field.repeated?
                  values[output_key] ||= []
                  values[output_key] << item
                else
                  values[output_key] = item
                end
              end
            end
            original_bytes = if unknown_policy == :discard
                               fields.filter_map do |wire_field|
                                 wire_field[:encoded] if descriptor.fields_by_number.key?(wire_field[:number])
                               end.join.b
                             else
                               input
                             end
            MessageValue.new(values, unknown_fields: unknown, original_bytes: original_bytes)
          end

          private

          def register_message(message)
            raise DuplicateMessageError, "duplicate protobuf message #{message.full_name}" if @messages.key?(message.full_name)

            validate_duplicate_fields!(message)
            @messages[message.full_name] = message
            message.nested_messages.each { |nested| register_message(nested) }
            message.enums.each { |enum| register_enum(enum) }
          end

          def register_enum(enum)
            raise DuplicateEnumError, "duplicate protobuf enum #{enum.full_name}" if @enums.key?(enum.full_name)

            @enums[enum.full_name] = enum
          end

          def validate_duplicate_fields!(message)
            names = {}
            numbers = {}
            message.fields.each do |field|
              raise DuplicateFieldError, "duplicate protobuf field #{message.full_name}.#{field.name}" if names.key?(field.name)
              raise DuplicateFieldError, "duplicate protobuf field number #{message.full_name}.#{field.number}" if numbers.key?(field.number)

              names[field.name] = true
              numbers[field.number] = true
            end
          end

          def resolve_field_type(field, current_message)
            if field.map?
              return resolve_reference(field.value_type_ref, current_message) if field.value_type_kind == :message

              resolve_enum(field.value_type_ref, current_message) if field.value_type_kind == :enum
            elsif field.message?
              resolve_reference(field.type_ref, current_message)
            elsif field.enum?
              resolve_enum(field.type_ref, current_message)
            end
          end

          def resolve_reference(reference, current_message)
            resolved = resolve_name(reference, current_message)
            unless resolved && @messages.key?(resolved)
              raise UnknownMessageError,
                    "unresolved protobuf type #{reference.inspect} in #{current_message.full_name}"
            end

            @messages[resolved]
          end

          def resolve_enum(reference, current_message)
            resolved = resolve_name(reference, current_message)
            unless resolved && @enums.key?(resolved)
              raise UnknownMessageError,
                    "unresolved protobuf enum #{reference.inspect} in #{current_message.full_name}"
            end

            @enums[resolved]
          end

          # Resolved names are remembered per (message, reference); a miss is
          # not, since a later registration can make it resolvable.
          def resolve_name(reference, current_message)
            per_message = (@resolved_names ||= {}.compare_by_identity)[current_message] ||= {}
            known = per_message[reference]
            return known if known

            resolved = resolve_name_uncached(reference, current_message)
            per_message[reference] = resolved if resolved && reference.is_a?(String)
            resolved
          end

          def resolve_name_uncached(reference, current_message)
            value = String(reference).delete_prefix(".")
            return value if @messages.key?(value) || @enums.key?(value)

            ancestors = []
            cursor = current_message
            while cursor
              ancestors << cursor.full_name
              cursor = cursor.parent
            end
            ancestors.each do |ancestor|
              candidate = "#{ancestor}.#{value}"
              return candidate if @messages.key?(candidate) || @enums.key?(candidate)
            end
            package = current_message.package
            candidate = package.empty? ? value : "#{package}.#{value}"
            return candidate if @messages.key?(candidate) || @enums.key?(candidate)

            nil
          end

          def build_indexes!
            @gvk_index.clear
            @openapi_index.clear
            @messages.each_value do |message|
              gvk = gvk_for_message(message)
              next unless gvk

              key = [gvk[:group], gvk[:version], gvk[:kind]]
              @gvk_index[key] ||= message
              openapi = "io.k8s.api.#{gvk[:group].empty? ? "core" : gvk[:group]}.#{gvk[:version]}.#{gvk[:kind]}"
              @openapi_index[openapi] ||= message
            end
          end

          def gvk_for_message(message)
            parts = message.package.split(".")
            return nil unless parts.length >= 5 && parts[0, 3] == %w[k8s io api]

            group = parts[-2]
            version = parts[-1]
            return nil if group.nil? || version.nil?

            {group: group == "core" ? "" : group, version: version, kind: message.name}
          end

          def resolve_gvk_string(value)
            parsed = value.split("/")
            if parsed.length == 2
              resolve_gvk(group: "", version: parsed[0], kind: parsed[1])
            elsif parsed.length == 3
              resolve_gvk(group: parsed[0], version: parsed[1], kind: parsed[2])
            end
          end

          def openapi_to_proto(value)
            return value unless value.start_with?("io.k8s.")

            # OpenAPI uses Go import-path package spelling, while protoc turns
            # hyphens in those package segments into underscores.
            "k8s.io.#{value.delete_prefix("io.k8s.").tr("-", "_")}"
          end

          def descriptor_paths(path)
            path = path.to_path if path.respond_to?(:to_path)
            path = String(path)
            if ::File.directory?(path)
              Dir.glob(::File.join(path, "**", "*.proto")).select { |item| ::File.file?(item) }.sort
            elsif ::File.file?(path)
              [path]
            else
              raise Errno::ENOENT, path
            end
          end

          def default_type_meta(descriptor)
            gvk = gvk_for_message(descriptor)
            if gvk
              {api_version: gvk[:group].empty? ? gvk[:version] : "#{gvk[:group]}/#{gvk[:version]}", kind: gvk[:kind]}
            else
              {kind: descriptor.name}
            end
          end

          def descriptor_name(name)
            name.respond_to?(:full_name) ? name.full_name : name.inspect
          end

          def normalize_unknown_policy(value, compatibility)
            if compatibility
              mode = compatibility.to_sym
              unless %i[kubernetes upstream kubernetes_v1_36_2].include?(mode)
                raise ArgumentError, "unknown protobuf compatibility mode #{compatibility.inspect}"
              end

              return :discard
            end

            policy = value.to_sym
            return policy if %i[preserve discard].include?(policy)

            raise ArgumentError, "unknown_fields must be :preserve or :discard"
          rescue NoMethodError
            raise ArgumentError, "unknown_fields must be :preserve or :discard"
          end

          def check_depth!(depth, max_depth)
            raise LimitError, "protobuf message depth exceeds #{max_depth}" if depth > max_depth
          end

          def normalize_object(value, max_depth:, depth: 0, seen: {})
            raise LimitError, "protobuf message depth exceeds #{max_depth}" if depth > max_depth

            case value
            when NilClass, TrueClass, FalseClass, Integer, String
              value
            when Float
              raise Codec::EncodeError, "protobuf float must be finite" unless value.finite?

              value
            when Array
              object_id = value.object_id
              raise Codec::UnsupportedTypeError, "cyclic protobuf value graph is not supported" if seen.key?(object_id)

              seen[object_id] = true
              begin
                value.map { |item| normalize_object(item, depth: depth + 1, max_depth: max_depth, seen: seen) }
              ensure
                seen.delete(object_id)
              end
            when Hash
              object_id = value.object_id
              raise Codec::UnsupportedTypeError, "cyclic protobuf value graph is not supported" if seen.key?(object_id)

              seen[object_id] = true
              begin
                normalized = value.each_with_object({}) do |(key, item), result|
                  normalized_key = Codec.normalize_key(key)
                  raise Codec::DuplicateKeyError, "duplicate protobuf field key #{normalized_key.inspect}" if result.key?(normalized_key)

                  result[normalized_key] = normalize_object(item, depth: depth + 1, max_depth: max_depth, seen: seen)
                end
                if value.is_a?(MessageValue)
                  MessageValue.new(normalized, unknown_fields: value.unknown_fields,
                                               original_bytes: value.original_bytes)
                else
                  normalized
                end
              ensure
                seen.delete(object_id)
              end
            else
              raise Codec::UnsupportedTypeError, "unsupported protobuf value #{value.class}" unless value.respond_to?(:to_h)

              hash = value.to_h
              raise Codec::UnsupportedTypeError, "to_h for #{value.class} must return a Hash" unless hash.is_a?(Hash)

              normalize_object(hash, depth: depth, max_depth: max_depth, seen: seen)

            end
          end

          def unknown_key?(key)
            %w[unknown_fields unknownFields __protobuf_unknown_fields__].include?(key.to_s)
          end

          def unknown_fields_for(value)
            if value.respond_to?(:unknown_fields)
              value.unknown_fields
            elsif value.is_a?(Hash)
              value[:unknown_fields] || value["unknown_fields"] || value["unknownFields"] || value[:__protobuf_unknown_fields__] || []
            else
              []
            end
          end

          def resolve_message_field(field)
            current = field.parent
            name = resolve_name(field.type_ref, current)
            @messages.fetch(name) { raise UnknownMessageError, "unresolved protobuf type #{field.type_ref.inspect}" }
          end

          def resolve_map_value_message(field)
            name = resolve_name(field.value_type_ref, field.parent)
            @messages.fetch(name) { raise UnknownMessageError, "unresolved protobuf map type #{field.value_type_ref.inspect}" }
          end

          def encode_map_field(field, value, strict:, max_bytes:, max_depth:, depth:)
            raise Codec::EncodeError, "map field #{field.json_name} must be a Hash" unless value.is_a?(Hash)

            entries = value.map do |key, item|
              encoded_key = encode_map_scalar(field.key_type, key)
              encoded_value = if field.value_type_kind == :scalar
                                encode_map_scalar(field.value_type, item)
                              else
                                encode_descriptor(resolve_map_value_message(field), item, strict: strict,
                                                                                          max_bytes: max_bytes, max_depth: max_depth, depth: depth)
                              end
              key_field = Codec::Protobuf.encode_field(1, decode_map_key_for_wire(field.key_type, key),
                                                       type: field.key_type)
              value_field = Codec::Protobuf.encode_field(2, encoded_value,
                                                         type: field.value_type_kind == :scalar ? field.value_type : :message)
              [encoded_key, key_field + value_field]
            end
            entries.sort_by!(&:first)
            entries.map { |_sort_key, entry| Codec::Protobuf.encode_field(field.number, entry, type: :message) }.join.b
          end

          def encode_repeated_field(field, values, strict:, max_bytes:, max_depth:, depth:)
            if field.packed? && field.scalar?
              scalar_values = values.map do |item|
                encode_scalar_value(field, item, strict: strict, max_bytes: max_bytes, max_depth: max_depth, depth: depth)
              end
              return Codec::Protobuf.encode_field(field.number, scalar_values, type: field.type, packed: true)
            end
            values.map do |item|
              encoded = encode_value(field, item, strict: strict, max_bytes: max_bytes,
                                                  max_depth: max_depth, depth: depth)
              Codec::Protobuf.encode_field(field.number, encoded, type: wire_type_for(field))
            end.join.b
          end

          def encode_value(field, value, strict:, max_bytes:, max_depth:, depth:)
            if field.message?
              encode_descriptor(resolve_message_field(field), value, strict: strict, max_bytes: max_bytes,
                                                                     max_depth: max_depth, depth: depth)
            elsif field.enum?
              encode_enum_value(field, value)
            else
              encode_scalar_value(field, value, strict: strict, max_bytes: max_bytes,
                                                max_depth: max_depth, depth: depth)
            end
          end

          def encode_scalar_value(field, value, strict:, max_bytes:, max_depth:, depth:)
            if field.type_kind == :message
              return encode_descriptor(resolve_map_value_message(field), value, strict: strict,
                                                                                max_bytes: max_bytes, max_depth: max_depth, depth: depth)
            end
            encode_scalar(field.type, value)
          end

          def encode_enum_value(field, value)
            return Integer(value) if value.is_a?(Integer)

            enum = resolve_enum(field.type_ref, field.parent)
            item = enum[value.to_s]
            raise Codec::EncodeError, "unknown enum value #{value.inspect}" unless item

            item.number
          end

          def encode_scalar(type, value)
            type = type.to_sym
            case type
            when :string
              string = String(value)
              unless string.encoding == Encoding::UTF_8 && string.valid_encoding?
                raise Codec::EncodeError,
                      "protobuf string must be valid UTF-8"
              end

              string
            when :bytes
              String(value).dup.force_encoding(Encoding::BINARY)
            when :bool
              raise Codec::EncodeError, "protobuf bool must be true or false" unless [true, false].include?(value)

              value
            when :double, :float
              number = Float(value)
              raise Codec::EncodeError, "protobuf float must be finite" unless number.finite?

              number
            when *INTEGER_TYPES
              Integer(value)
            else
              raise UnsupportedTypeError, "unsupported protobuf scalar #{type.inspect}"
            end
          rescue TypeError, ArgumentError => error
            raise Codec::EncodeError.new("invalid protobuf scalar #{type}: #{error.message}"), cause: error
          end

          def wire_type_for(field)
            return :message if field.message?
            return :enum if field.enum?

            field.type
          end

          def decode_value(field, wire_field, strict:, max_bytes:, max_depth:, depth:, keys:,
                           unknown_policy:)
            expected = expected_wire_type(field)
            unless wire_field[:wire_type] == expected
              raise Codec::ParseError, "protobuf field #{field.json_name} has wire type #{wire_field[:wire_type]}, expected #{expected}"
            end

            if field.message?
              decode_descriptor(resolve_message_field(field), wire_field[:value], strict: strict,
                                                                                  max_bytes: max_bytes, max_depth: max_depth, depth: depth, keys: keys,
                                                                                  unknown_policy: unknown_policy)
            elsif field.enum?
              decode_varint_scalar(:enum, wire_field[:value])
            else
              decode_scalar(field.type, wire_field[:value], wire_type: wire_field[:wire_type])
            end
          end

          def expected_wire_type(field)
            return Codec::Protobuf::WIRE_LENGTH_DELIMITED if field.message? || field.type == :string || field.type == :bytes
            return Codec::Protobuf::WIRE_VARINT if field.enum? || VARINT_TYPES.include?(field.type)
            return Codec::Protobuf::WIRE_FIXED64 if FIXED64_TYPES.include?(field.type)
            return Codec::Protobuf::WIRE_FIXED32 if FIXED32_TYPES.include?(field.type)

            raise UnsupportedTypeError, "unsupported protobuf field type #{field.type.inspect}"
          end

          def packed_wire?(field, wire_type)
            field.repeated? && field.scalar? && field.packed? && wire_type == Codec::Protobuf::WIRE_LENGTH_DELIMITED
          end

          def decode_packed(field, input, strict:, max_bytes:, max_depth:, depth:, keys:)
            values = []
            offset = 0
            expected = expected_wire_type(field)
            while offset < input.bytesize
              case expected
              when Codec::Protobuf::WIRE_VARINT
                raw, offset = Codec::Protobuf.decode_varint_with_offset(input, offset: offset, strict: strict)
              when Codec::Protobuf::WIRE_FIXED64
                raise Codec::ParseError, "truncated packed fixed64" if offset + 8 > input.bytesize

                raw = input.byteslice(offset, 8).unpack1("Q<")
                offset += 8
              when Codec::Protobuf::WIRE_FIXED32
                raise Codec::ParseError, "truncated packed fixed32" if offset + 4 > input.bytesize

                raw = input.byteslice(offset, 4).unpack1("V")
                offset += 4
              else
                raise Codec::ParseError, "invalid packed field type"
              end
              values << decode_scalar(field.type, raw, wire_type: expected)
            end
            values
          end

          def decode_scalar(type, raw, wire_type: nil)
            type = type.to_sym
            case type
            when :string
              value = raw.dup.force_encoding(Encoding::UTF_8)
              raise Codec::ParseError, "protobuf string is not valid UTF-8" unless value.valid_encoding?

              value
            when :bytes
              raw.dup.force_encoding(Encoding::BINARY)
            when :bool
              raise Codec::ParseError, "invalid protobuf bool" unless [0, 1].include?(raw)

              raw == 1
            when :int32
              Codec::Protobuf.decode_signed_varint(Codec::Protobuf.encode_varint(raw), bits: 32)
            when :int64
              Codec::Protobuf.decode_signed_varint(Codec::Protobuf.encode_varint(raw), bits: 64)
            when :uint32
              raise Codec::ParseError, "protobuf uint32 out of range" if raw >= (1 << 32)

              raw
            when :uint64
              raw
            when :sint32
              Codec::Protobuf.zigzag_decode(raw, bits: 32)
            when :sint64
              Codec::Protobuf.zigzag_decode(raw, bits: 64)
            when :fixed32
              raw & 0xffff_ffff
            when :fixed64
              raw & 0xffff_ffff_ffff_ffff
            when :sfixed32
              [raw].pack("V").unpack1("l<")
            when :sfixed64
              [raw].pack("Q<").unpack1("q<")
            when :float
              Codec::Protobuf.decode_float([raw].pack("V"))
            when :double
              Codec::Protobuf.decode_double([raw].pack("Q<"))
            when :enum
              raw
            else
              raise UnsupportedTypeError, "unsupported protobuf scalar #{type.inspect}"
            end
          end

          def decode_varint_scalar(type, raw)
            decode_scalar(type, raw, wire_type: Codec::Protobuf::WIRE_VARINT)
          end

          def decode_map_entry(field, input, strict:, max_bytes:, max_depth:, depth:, keys:,
                               unknown_policy:)
            fields = Codec::Protobuf.parse_fields(input, strict: strict, max_bytes: max_bytes, max_depth: max_depth)
            key = default_scalar(field.key_type)
            value = field.value_type_kind == :scalar ? default_scalar(field.value_type) : nil
            fields.each do |wire_field|
              case wire_field[:number]
              when 1
                expected = expected_wire_type_for_type(field.key_type)
                raise Codec::ParseError, "invalid protobuf map key wire type" unless wire_field[:wire_type] == expected

                key = decode_scalar(field.key_type, wire_field[:value], wire_type: expected)
              when 2
                expected = field.value_type_kind == :scalar ? expected_wire_type_for_type(field.value_type) : Codec::Protobuf::WIRE_LENGTH_DELIMITED
                raise Codec::ParseError, "invalid protobuf map value wire type" unless wire_field[:wire_type] == expected

                value = if field.value_type_kind == :scalar
                          decode_scalar(field.value_type, wire_field[:value], wire_type: expected)
                        else
                          decode_descriptor(resolve_map_value_message(field), wire_field[:value], strict: strict,
                                                                                                  max_bytes: max_bytes, max_depth: max_depth, depth: depth, keys: keys,
                                                                                                  unknown_policy: unknown_policy)
                        end
              else
                # Map-entry unknowns cannot be surfaced as top-level fields;
                # retaining them would require a synthetic nested unknown slot.
              end
            end
            [key, value]
          end

          def expected_wire_type_for_type(type)
            type = type.to_sym
            return Codec::Protobuf::WIRE_LENGTH_DELIMITED if %i[string bytes].include?(type)
            return Codec::Protobuf::WIRE_VARINT if VARINT_TYPES.include?(type)
            return Codec::Protobuf::WIRE_FIXED64 if FIXED64_TYPES.include?(type)
            return Codec::Protobuf::WIRE_FIXED32 if FIXED32_TYPES.include?(type)

            Codec::Protobuf::WIRE_LENGTH_DELIMITED
          end

          def default_scalar(type)
            case type.to_sym
            when :bool then false
            when :string, :bytes then type.to_sym == :bytes ? "".b : ""
            when :double, :float then 0.0
            else 0
            end
          end

          def encode_map_scalar(type, value)
            encode_scalar(type, value)
          end

          def decode_map_key_for_wire(type, value)
            encode_scalar(type, value)
          end

          def output_key(field, keys)
            case keys
            when :symbol, :symbols then field.json_name.to_sym
            when :proto, :protobuf, :name then field.name
            else field.json_name
            end
          end
        end

        class << self
          def parse(source, **)
            Registry.parse(source, **)
          end

          def load(path, **)
            Registry.load(path, **)
          end

          alias from_path load
        end
      end

      ProtoDescriptorCodec = ProtoDescriptor unless const_defined?(:ProtoDescriptorCodec, false)
    end
  end
end
