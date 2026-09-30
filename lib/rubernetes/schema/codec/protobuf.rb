# frozen_string_literal: true

module Rubernetes
  module Schema
    class Codec
      # Kubernetes puts a runtime.Unknown protobuf message behind the k8s\0
      # marker.  Without the generated descriptor for a concrete GVK this
      # module intentionally preserves the inner bytes instead of pretending to
      # decode them as a different Kubernetes message.
      module Protobuf
        MAGIC = "k8s\x00".b.freeze
        TYPE_META_FIELD = 1
        RAW_FIELD = 2
        CONTENT_ENCODING_FIELD = 3
        CONTENT_TYPE_FIELD = 4
        TYPE_META_API_VERSION_FIELD = 1
        TYPE_META_KIND_FIELD = 2
        MAX_FIELD_NUMBER = (1 << 29) - 1
        MAX_VARINT_BYTES = 10
        WIRE_VARINT = 0
        WIRE_FIXED64 = 1
        WIRE_LENGTH_DELIMITED = 2
        WIRE_FIXED32 = 5

        class RuntimeUnknown < Hash
          attr_reader :raw_present

          def initialize(raw:, type_meta: nil, content_encoding: nil, content_type: nil,
                         unknown_fields: [], raw_present: true, original: nil)
            super()
            self[:raw] = String(raw).b
            self[:type_meta] = type_meta unless type_meta.nil?
            self[:content_encoding] = content_encoding unless content_encoding.nil?
            self[:content_type] = content_type unless content_type.nil?
            self[:unknown_fields] = unknown_fields.freeze unless unknown_fields.empty?
            @raw_present = !!raw_present
            @original = original&.b&.freeze
            freeze
          end

          def raw
            self[:raw]
          end

          def type_meta
            self[:type_meta]
          end

          def content_encoding
            self[:content_encoding]
          end

          def content_type
            self[:content_type]
          end

          def unknown_fields
            self[:unknown_fields] || []
          end

          def encoded
            @original
          end

          def [](key)
            case key
            when "raw" then super(:raw)
            when "typeMeta" then super(:type_meta)
            when "contentEncoding" then super(:content_encoding)
            when "contentType" then super(:content_type)
            when "unknownFields" then super(:unknown_fields) || []
            else super
            end
          end

          def fetch(key, *default, &block)
            mapped = case key
                     when "raw" then :raw
                     when "typeMeta" then :type_meta
                     when "contentEncoding" then :content_encoding
                     when "contentType" then :content_type
                     when "unknownFields" then :unknown_fields
                     else key
                     end
            return unknown_fields if mapped == :unknown_fields && !key?(mapped) && default.empty? && !block

            super(mapped, *default, &block)
          end

          def to_h
            result = {raw: raw}
            result[:type_meta] = type_meta unless type_meta.nil?
            result[:content_encoding] = content_encoding unless content_encoding.nil?
            result[:content_type] = content_type unless content_type.nil?
            result[:unknown_fields] = unknown_fields unless unknown_fields.empty?
            result
          end
        end

        Unknown = RuntimeUnknown unless const_defined?(:Unknown, false)
        Envelope = RuntimeUnknown unless const_defined?(:Envelope, false)

        module_function

        def encode_envelope(object = nil, raw: nil, content_type: "application/json",
                            content_encoding: nil, type_meta: nil,
                            max_bytes: Codec::DEFAULT_MAX_BYTES, max_depth: Codec::DEFAULT_MAX_DEPTH)
          if object.is_a?(RuntimeUnknown) && raw.nil? && object.encoded &&
             content_type == "application/json" && content_encoding.nil? && type_meta.nil?
            return Codec.validate_output!(object.encoded.dup.b, max_bytes)
          end

          content_type = object.content_type if object.is_a?(RuntimeUnknown) && content_type == "application/json"
          content_encoding = object.content_encoding if content_encoding.nil? && object.is_a?(RuntimeUnknown)
          type_meta = object.type_meta if type_meta.nil? && object.is_a?(RuntimeUnknown)
          payload = if raw.nil?
                      extract_raw(object, max_bytes: max_bytes, max_depth: max_depth)
                    else
                      ensure_binary(raw, "protobuf raw payload")
                    end
          Codec.validate_output!(payload, max_bytes)
          encoded = +"".b
          # The generated Kubernetes runtime.Unknown marshaler emits all four
          # proto2 fields, including empty TypeMeta/content metadata.  Keeping
          # those fields makes the envelope byte-compatible with that wire
          # representation while still preserving descriptorless raw bytes.
          encoded << encode_field(TYPE_META_FIELD, encode_type_meta(type_meta || {}), type: :message)
          encoded << if object.is_a?(RuntimeUnknown) && !object.raw_present && raw.nil?
                       +"".b
                     else
                       encode_field(RAW_FIELD, payload, type: :bytes)
                     end
          content_encoding = "" if content_encoding.nil?
          content_encoding = String(content_encoding)
          validate_utf8!(content_encoding, "protobuf content encoding")
          encoded << encode_field(CONTENT_ENCODING_FIELD, content_encoding, type: :string)
          content_type = "" if content_type.nil?
          content_type = String(content_type)
          validate_utf8!(content_type, "protobuf content type")
          encoded << encode_field(CONTENT_TYPE_FIELD, content_type, type: :string)
          if object.is_a?(RuntimeUnknown)
            object.unknown_fields.each do |field|
              encoded << ensure_binary(field.fetch(:encoded), "protobuf unknown field")
            end
          end
          Codec.validate_output!(MAGIC + encoded, max_bytes)
        rescue Codec::Error
          raise
        rescue EncodingError, TypeError, ArgumentError => error
          raise Codec::EncodeError.new("cannot encode Kubernetes protobuf envelope: #{error.message}"), cause: error
        end

        def decode_envelope(input, strict: true, max_bytes: Codec::DEFAULT_MAX_BYTES,
                            max_depth: Codec::DEFAULT_MAX_DEPTH)
          Codec.validate_body!(input, max_bytes)
          raise Codec::ParseError, "Kubernetes protobuf payload must start with k8s\\0 magic" unless input.start_with?(MAGIC)

          fields = parse_fields(input.byteslice(MAGIC.bytesize..) || "".b, strict: strict, max_bytes: max_bytes,
                                                                           max_depth: max_depth)
          raw = nil
          type_meta = nil
          content_encoding = nil
          content_type = nil
          raw_present = false
          unknown_fields = []
          fields.each do |field|
            case field[:number]
            when TYPE_META_FIELD
              ensure_wire_type!(field, WIRE_LENGTH_DELIMITED, "runtime.Unknown.typeMeta")
              raise Codec::DuplicateKeyError, "duplicate runtime.Unknown.typeMeta field" if !type_meta.nil? && strict

              type_meta = decode_type_meta(field[:value], strict: strict, max_bytes: max_bytes,
                                                          max_depth: max_depth)
            when RAW_FIELD
              ensure_wire_type!(field, WIRE_LENGTH_DELIMITED, "runtime.Unknown.raw")
              raise Codec::DuplicateKeyError, "duplicate runtime.Unknown.raw field" if raw_present && strict

              raw = field[:value]
              raw_present = true
            when CONTENT_ENCODING_FIELD
              ensure_wire_type!(field, WIRE_LENGTH_DELIMITED, "runtime.Unknown.contentEncoding")
              raise Codec::DuplicateKeyError, "duplicate runtime.Unknown.contentEncoding field" if !content_encoding.nil? && strict

              content_encoding = field[:value].dup.force_encoding(Encoding::UTF_8)
              validate_utf8!(content_encoding, "runtime.Unknown.contentEncoding")
            when CONTENT_TYPE_FIELD
              ensure_wire_type!(field, WIRE_LENGTH_DELIMITED, "runtime.Unknown.contentType")
              raise Codec::DuplicateKeyError, "duplicate runtime.Unknown.contentType field" if !content_type.nil? && strict

              content_type = field[:value].dup.force_encoding(Encoding::UTF_8)
              validate_utf8!(content_type, "runtime.Unknown.contentType")
            else
              unknown_fields << field.slice(:number, :wire_type, :value, :encoded)
            end
          end
          RuntimeUnknown.new(
            raw: raw || "".b,
            type_meta: type_meta,
            content_encoding: content_encoding,
            content_type: content_type,
            unknown_fields: unknown_fields,
            raw_present: raw_present,
            original: input
          )
        rescue Codec::Error
          raise
        rescue EncodingError, TypeError, ArgumentError => error
          raise Codec::ParseError.new("invalid Kubernetes protobuf envelope: #{error.message}"), cause: error
        end

        def wrap(raw, content_type: "application/json", content_encoding: nil, type_meta: nil,
                 max_bytes: Codec::DEFAULT_MAX_BYTES, max_depth: Codec::DEFAULT_MAX_DEPTH)
          encode_envelope(
            raw: raw,
            content_type: content_type,
            content_encoding: content_encoding,
            type_meta: type_meta,
            max_bytes: max_bytes,
            max_depth: max_depth
          )
        end

        def unwrap(input, strict: true, max_bytes: Codec::DEFAULT_MAX_BYTES,
                   max_depth: Codec::DEFAULT_MAX_DEPTH)
          decode_envelope(input, strict: strict, max_bytes: max_bytes, max_depth: max_depth)
        end

        alias serialize encode_envelope
        alias deserialize decode_envelope
        module_function :serialize, :deserialize

        # One-byte varints, frozen: most keys, lengths and enum values.
        SMALL_VARINTS = Array.new(128) { |byte| byte.chr.b.freeze }.freeze

        def encode_varint(value, max_bits: 64)
          return SMALL_VARINTS[value] if value.is_a?(Integer) && value >= 0 && value < 128

          integer = Integer(value)
          raise ArgumentError, "varint value must be non-negative" if integer.negative?
          raise ArgumentError, "varint value exceeds #{max_bits} bits" if integer >= (1 << max_bits)

          output = +"".b
          loop do
            byte = integer & 0x7f
            integer >>= 7
            output << (integer.zero? ? byte : byte | 0x80)
            break if integer.zero?
          end
          output.b
        rescue TypeError, ArgumentError => error
          raise Codec::EncodeError.new("invalid protobuf varint: #{error.message}"), cause: error
        end

        def decode_varint(input, offset: 0, max_bits: 64, strict: true, return_offset: false)
          value, next_offset = read_varint(input, offset: offset, max_bits: max_bits, strict: strict)
          return [value, next_offset] if return_offset

          value
        end

        def decode_varint_with_offset(input, offset: 0, max_bits: 64, strict: true)
          decode_varint(input, offset: offset, max_bits: max_bits, strict: strict, return_offset: true)
        end

        def encode_length_delimited(value)
          bytes = ensure_binary(value, "protobuf length-delimited value")
          encode_varint(bytes.bytesize, max_bits: 64) + bytes
        end

        def decode_length_delimited(input, offset: 0, strict: true, return_offset: false)
          length, value_offset = read_varint(input, offset: offset, max_bits: 64, strict: strict)
          end_offset = value_offset + length
          raise Codec::ParseError, "protobuf length-delimited field exceeds body" if end_offset > input.bytesize

          value = input.byteslice(value_offset, length)
          value.force_encoding(Encoding::BINARY) unless value.encoding == Encoding::BINARY
          return [value, end_offset] if return_offset

          value
        end

        def encode_bytes(value)
          encode_length_delimited(value)
        end

        def decode_bytes(input, offset: 0, strict: true, return_offset: false)
          decode_length_delimited(input, offset: offset, strict: strict, return_offset: return_offset)
        end

        def encode_string(value)
          string = String(value)
          validate_utf8!(string, "protobuf string")
          encode_length_delimited(string)
        end

        def decode_string(input, offset: 0, strict: true, return_offset: false)
          value, next_offset = decode_length_delimited(input, offset: offset, strict: strict, return_offset: true)
          string = value.dup.force_encoding(Encoding::UTF_8)
          validate_utf8!(string, "protobuf string")
          return [string, next_offset] if return_offset

          string.tap do |decoded|
            validate_utf8!(decoded, "protobuf string")
          end
        end

        def encode_bool(value)
          raise Codec::EncodeError, "protobuf bool must be true or false" unless [true, false].include?(value)

          encode_varint(value ? 1 : 0, max_bits: 1)
        end

        def decode_bool(input)
          value = decode_varint(input, max_bits: 1)
          value == 1
        end

        # A field key depends only on (number, wire type): encoded once.
        KEY_CACHE = {}

        def encode_key(field_number, wire_type)
          integers = field_number.is_a?(Integer) && wire_type.is_a?(Integer)
          if integers && (cached = KEY_CACHE[(field_number << 3) | wire_type])
            return cached
          end

          validate_field_number!(field_number)
          raise ArgumentError, "unknown protobuf wire type #{wire_type.inspect}" unless [0, 1, 2, 5].include?(wire_type)

          code = (Integer(field_number) << 3) | Integer(wire_type)
          key = encode_varint(code, max_bits: 64).dup.freeze
          KEY_CACHE[code] = key if integers
          key
        end

        def encode_field(field_number, value, type: :bytes, packed: false)
          if value.is_a?(Array)
            if packed
              packed_type = packed_type_for(type)
              payload = value.map { |item| encode_scalar(item, packed_type) }.join
              return encode_key(field_number, WIRE_LENGTH_DELIMITED) + encode_length_delimited(payload)
            end
            return value.map { |item| encode_field(field_number, item, type: type) }.join
          end

          wire_type, encoded = encode_scalar_with_wire(value, type)
          encode_key(field_number, wire_type) + encoded
        rescue Codec::Error
          raise
        rescue TypeError, ArgumentError => error
          raise Codec::EncodeError.new("invalid protobuf field #{field_number}: #{error.message}"), cause: error
        end

        def parse_fields(input, strict: true, max_bytes: Codec::DEFAULT_MAX_BYTES, max_depth: Codec::DEFAULT_MAX_DEPTH)
          Codec.validate_body!(input, max_bytes)
          fields = []
          offset = 0
          size = input.bytesize
          while offset < size
            field_start = offset
            key = input.getbyte(offset)
            if key < 0x80
              offset += 1
            else
              key, offset = read_varint(input, offset: offset, max_bits: 64, strict: strict)
            end
            field_number = key >> 3
            wire_type = key & 0x07
            validate_field_number!(field_number) unless field_number >= 1 && field_number <= MAX_FIELD_NUMBER
            length = wire_type == WIRE_LENGTH_DELIMITED ? input.getbyte(offset) : nil
            small = wire_type == WIRE_VARINT ? input.getbyte(offset) : nil
            if small && small < 0x80
              value = small
              offset += 1
            elsif length && length < 0x80 && offset + 1 + length <= size
              # The common case, a length-delimited value under 128 bytes,
              # read without the general dispatch.
              value = input.byteslice(offset + 1, length)
              value.force_encoding(Encoding::BINARY) unless value.encoding == Encoding::BINARY
              offset += 1 + length
            else
              value, offset = read_wire_value(input, wire_type, offset: offset, strict: strict,
                                                                max_bytes: max_bytes, max_depth: max_depth)
            end
            encoded = input.byteslice(field_start, offset - field_start)
            encoded.force_encoding(Encoding::BINARY) unless encoded.encoding == Encoding::BINARY
            fields << {
              number: field_number,
              wire_type: wire_type,
              value: value,
              encoded: encoded
            }.freeze
          end
          fields.freeze
        rescue Codec::Error
          raise
        rescue TypeError, ArgumentError, EncodingError => error
          raise Codec::ParseError.new("invalid protobuf message: #{error.message}"), cause: error
        end

        alias decode_fields parse_fields
        module_function :decode_fields

        alias decode_message parse_fields
        module_function :decode_message

        def encode_message(fields)
          entries = if fields.is_a?(Hash)
                      fields.map { |number, value| [number, value, :bytes, false] }
                    else
                      Array(fields).map do |entry|
                        if entry.is_a?(Hash)
                          [entry.fetch(:number), entry.fetch(:value), entry.fetch(:type, :bytes), entry.fetch(:packed, false)]
                        else
                          number, value, type, packed = Array(entry)
                          [number, value, type || :bytes, !!packed]
                        end
                      end
                    end
          entries.map { |number, value, type, packed| encode_field(number, value, type: type, packed: packed) }.join.b
        end

        alias encode_fields encode_message
        module_function :encode_fields

        def encode_type_meta(type_meta)
          values = if type_meta.respond_to?(:to_h)
                     type_meta.to_h
                   else
                     raise Codec::UnsupportedTypeError, "protobuf typeMeta must be Hash-like"
                   end
          api_version = values[:api_version] || values["apiVersion"] || values["api_version"]
          kind = values[:kind] || values["kind"]
          api_version = type_meta.api_version if api_version.nil? && type_meta.respond_to?(:api_version)
          kind = type_meta.kind if kind.nil? && type_meta.respond_to?(:kind)
          # RawTypeMeta uses non-pointer Go string fields, so Kubernetes'
          # generated marshaler emits apiVersion and kind even when empty.
          api_version = "" if api_version.nil?
          kind = "" if kind.nil?
          encoded = +"".b
          encoded << encode_field(TYPE_META_API_VERSION_FIELD, api_version, type: :string)
          encoded << encode_field(TYPE_META_KIND_FIELD, kind, type: :string)
          Array(values[:unknown_fields] || values["unknownFields"]).each do |field|
            encoded << ensure_binary(field.fetch(:encoded), "protobuf typeMeta unknown field")
          end
          encoded
        end

        def decode_type_meta(input, strict:, max_bytes:, max_depth:)
          fields = parse_fields(input, strict: strict, max_bytes: max_bytes, max_depth: max_depth)
          result = {}
          unknown_fields = []
          fields.each do |field|
            ensure_wire_type!(field, WIRE_LENGTH_DELIMITED, "runtime.TypeMeta field")
            key = case field[:number]
                  when TYPE_META_API_VERSION_FIELD then :api_version
                  when TYPE_META_KIND_FIELD then :kind
                  end
            if key
              raise Codec::DuplicateKeyError, "duplicate runtime.TypeMeta.#{key} field" if result.key?(key) && strict

              value = field[:value].dup.force_encoding(Encoding::UTF_8)
              validate_utf8!(value, "runtime.TypeMeta.#{key}")
              result[key] = value
            else
              unknown_fields << field.slice(:number, :wire_type, :value, :encoded)
            end
          end
          result[:unknown_fields] = unknown_fields.freeze unless unknown_fields.empty?
          result.freeze
        end

        def encode_int32(value)
          encode_varint(encode_signed(value, bits: 32), max_bits: 64)
        end

        def decode_int32(input)
          decode_signed_varint(input, bits: 32)
        end

        def encode_int64(value)
          encode_varint(encode_signed(value, bits: 64), max_bits: 64)
        end

        def decode_int64(input)
          decode_signed_varint(input, bits: 64)
        end

        def encode_uint32(value)
          encode_varint(value, max_bits: 32)
        end

        def decode_uint32(input)
          decode_varint(input, max_bits: 32)
        end

        def encode_uint64(value)
          encode_varint(value, max_bits: 64)
        end

        def decode_uint64(input)
          decode_varint(input, max_bits: 64)
        end

        def encode_sint32(value)
          encode_varint(zigzag_encode(Integer(value), bits: 32), max_bits: 32)
        end

        def decode_sint32(input)
          zigzag_decode(decode_varint(input, max_bits: 32), bits: 32)
        end

        def encode_sint64(value)
          encode_varint(zigzag_encode(Integer(value), bits: 64), max_bits: 64)
        end

        def decode_sint64(input)
          zigzag_decode(decode_varint(input, max_bits: 64), bits: 64)
        end

        def encode_fixed32(value)
          [Integer(value)].pack("V")
        rescue TypeError, ArgumentError => error
          raise Codec::EncodeError.new("invalid protobuf fixed32: #{error.message}"), cause: error
        end

        def decode_fixed32(input)
          require_size!(input, 4, "protobuf fixed32")
          input.unpack1("V")
        end

        def encode_fixed64(value)
          [Integer(value)].pack("Q<")
        rescue TypeError, ArgumentError => error
          raise Codec::EncodeError.new("invalid protobuf fixed64: #{error.message}"), cause: error
        end

        def decode_fixed64(input)
          require_size!(input, 8, "protobuf fixed64")
          input.unpack1("Q<")
        end

        def encode_sfixed32(value)
          [Integer(value)].pack("l<")
        end

        def decode_sfixed32(input)
          require_size!(input, 4, "protobuf sfixed32")
          input.unpack1("l<")
        end

        def encode_sfixed64(value)
          [Integer(value)].pack("q<")
        end

        def decode_sfixed64(input)
          require_size!(input, 8, "protobuf sfixed64")
          input.unpack1("q<")
        end

        def encode_float(value)
          [Float(value)].pack("e")
        end

        def decode_float(input)
          require_size!(input, 4, "protobuf float")
          input.unpack1("e")
        end

        def encode_double(value)
          [Float(value)].pack("E")
        end

        def decode_double(input)
          require_size!(input, 8, "protobuf double")
          input.unpack1("E")
        end

        def zigzag_encode(value, bits: 64)
          integer = Integer(value)
          min = -(1 << (bits - 1))
          max = (1 << (bits - 1)) - 1
          raise ArgumentError, "signed value outside int#{bits} range" unless (min..max).cover?(integer)

          ((integer << 1) ^ (integer >> (bits - 1))) & ((1 << bits) - 1)
        end

        def zigzag_decode(value, bits: 64)
          integer = Integer(value)
          raise ArgumentError, "zigzag value outside uint#{bits} range" unless (0...(1 << bits)).cover?(integer)

          (integer >> 1) ^ -(integer & 1)
        end

        def packed_type_for(type)
          type = type.to_sym
          return type unless type == :packed

          raise ArgumentError, "packed protobuf fields require an element type"
        end

        def encode_scalar_with_wire(value, type)
          normalized = type.to_sym
          case normalized
          when :int32 then [WIRE_VARINT, encode_int32(value)]
          when :int64 then [WIRE_VARINT, encode_int64(value)]
          when :uint32 then [WIRE_VARINT, encode_uint32(value)]
          when :uint64 then [WIRE_VARINT, encode_uint64(value)]
          when :sint32 then [WIRE_VARINT, encode_sint32(value)]
          when :sint64 then [WIRE_VARINT, encode_sint64(value)]
          when :bool then [WIRE_VARINT, encode_bool(value)]
          when :enum then [WIRE_VARINT, encode_int32(value)]
          when :fixed64 then [WIRE_FIXED64, encode_fixed64(value)]
          when :sfixed64 then [WIRE_FIXED64, encode_sfixed64(value)]
          when :double then [WIRE_FIXED64, encode_double(value)]
          when :fixed32 then [WIRE_FIXED32, encode_fixed32(value)]
          when :sfixed32 then [WIRE_FIXED32, encode_sfixed32(value)]
          when :float then [WIRE_FIXED32, encode_float(value)]
          when :bytes, :message then [WIRE_LENGTH_DELIMITED, encode_length_delimited(value)]
          when :string
            string = String(value)
            validate_utf8!(string, "protobuf string")
            [WIRE_LENGTH_DELIMITED, encode_length_delimited(string)]
          else
            raise ArgumentError, "unsupported protobuf field type #{type.inspect}"
          end
        end

        def encode_scalar(value, type)
          encode_scalar_with_wire(value, type).last
        end

        def read_wire_value(input, wire_type, offset:, strict:, max_bytes:, max_depth:)
          case wire_type
          when WIRE_VARINT
            read_varint(input, offset: offset, max_bits: 64, strict: strict)
          when WIRE_FIXED64
            require_available!(input, offset, 8, "protobuf fixed64")
            [input.byteslice(offset, 8).unpack1("Q<"), offset + 8]
          when WIRE_LENGTH_DELIMITED
            decode_length_delimited(input, offset: offset, strict: strict, return_offset: true).tap do |value, _next_offset|
              Codec.validate_output!(value, max_bytes)
            end
          when WIRE_FIXED32
            require_available!(input, offset, 4, "protobuf fixed32")
            [input.byteslice(offset, 4).unpack1("V"), offset + 4]
          else
            raise Codec::ParseError, "unsupported protobuf wire type #{wire_type}"
          end
        end

        def read_varint(input, offset:, max_bits:, strict:)
          # Most varints (field keys, short lengths) are one byte: answer
          # those before the checks the general path needs.
          if offset.is_a?(Integer) && offset >= 0 && input.is_a?(String) &&
             (byte = input.getbyte(offset)) && byte < 0x80
            return [byte, offset + 1]
          end

          Codec.validate_body!(input, [input.bytesize, Codec::DEFAULT_MAX_BYTES].min)
          raise Codec::ParseError, "protobuf varint offset is outside body" unless offset.between?(0, input.bytesize)

          value = 0
          shift = 0
          cursor = offset
          MAX_VARINT_BYTES.times do |index|
            byte = input.getbyte(cursor)
            raise Codec::ParseError, "truncated protobuf varint" if byte.nil?

            cursor += 1
            value |= (byte & 0x7f) << shift
            if (byte & 0x80).zero?
              raise Codec::ParseError, "protobuf varint exceeds #{max_bits} bits" if value >= (1 << max_bits)
              raise Codec::ParseError, "non-canonical protobuf varint" if strict && index.positive? && value < (1 << (7 * index))

              return [value, cursor]
            end
            shift += 7
          end
          raise Codec::ParseError, "protobuf varint exceeds #{MAX_VARINT_BYTES} bytes"
        end

        def extract_raw(object, max_bytes:, max_depth:)
          return object.raw.dup.b if object.is_a?(RuntimeUnknown)
          if object.is_a?(Hash) && (object.key?(:raw) || object.key?("raw"))
            return ensure_binary(object[:raw] || object["raw"], "protobuf raw payload")
          end
          return ensure_binary(object, "protobuf raw payload") if object.is_a?(String)

          JSONCodec.dump(object, canonical: true, max_bytes: max_bytes, max_depth: max_depth).b
        end

        def ensure_binary(value, label)
          string = String(value).dup
          string.force_encoding(Encoding::BINARY)
          string
        rescue TypeError
          raise Codec::EncodeError, "#{label} must be a String"
        end

        def validate_utf8!(value, label)
          string = String(value)
          return string if string.encoding == Encoding::UTF_8 && string.valid_encoding?

          raise Codec::EncodeError, "#{label} must be valid UTF-8"
        end

        def validate_field_number!(field_number)
          number = Integer(field_number)
          unless (1..MAX_FIELD_NUMBER).cover?(number)
            raise Codec::EncodeError, "protobuf field number must be between 1 and #{MAX_FIELD_NUMBER}"
          end

          number
        rescue TypeError, ArgumentError => error
          raise Codec::EncodeError.new("invalid protobuf field number: #{error.message}"), cause: error
        end

        def ensure_wire_type!(field, expected, name)
          return if field[:wire_type] == expected

          raise Codec::ParseError, "#{name} must use protobuf wire type #{expected}"
        end

        def require_size!(input, size, label)
          ensure_binary(input, label)
          raise Codec::ParseError, "#{label} must be exactly #{size} bytes" unless input.bytesize == size

          input
        end

        def require_available!(input, offset, size, label)
          raise Codec::ParseError, "truncated #{label}" if offset.negative? || offset + size > input.bytesize
        end

        def encode_signed(value, bits:)
          integer = Integer(value)
          min = -(1 << (bits - 1))
          max = (1 << (bits - 1)) - 1
          raise ArgumentError, "signed value outside int#{bits} range" unless (min..max).cover?(integer)

          integer.negative? ? (1 << 64) + integer : integer
        end

        def decode_signed_varint(input, bits:)
          value = decode_varint(input, max_bits: 64)
          mask = (1 << bits) - 1
          value &= mask
          sign_bit = 1 << (bits - 1)
          value >= sign_bit ? value - (1 << bits) : value
        end

        def validate_body!(input, max_bytes)
          Codec.validate_body!(input, max_bytes)
        end

        def inspect
          "#{name}(generic Kubernetes runtime.Unknown envelope)"
        end
      end

      ProtobufCodec = Protobuf unless const_defined?(:ProtobufCodec, false)
    end
  end
end
