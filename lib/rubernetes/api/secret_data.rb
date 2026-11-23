# frozen_string_literal: true

require "base64"

module Rubernetes
  module API
    # The v1 Secret decodes its write-only stringData into the internal
    # data map, with stringData taking precedence over a duplicate key.
    module SecretData
      BASE64_ALPHABET = %r{[A-Za-z0-9+/]}n
      BASE64_ENCODING = %r{\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\z}n

      module_function

      def resource?(resource)
        resource.kind == "Secret" && resource.group.to_s.empty? && !resource.custom?
      end

      def normalize(object)
        return object unless object.is_a?(Hash) && object["stringData"].is_a?(Hash)

        strings = object.fetch("stringData")
        data = object["data"]
        return object unless strings.values.all? { |value| value.nil? || value.is_a?(String) } && (data.nil? || data.is_a?(Hash))

        result = object.except("stringData")
        result["data"] = (data || {}).merge(strings.transform_values { |value| Base64.strict_encode64(value.to_s) }) unless strings.empty?
        result
      end

      def normalize_request(object)
        return object unless object.is_a?(Hash) && object["stringData"].is_a?(Hash)

        data = object["data"]
        object = object.merge("data" => data.transform_values { |value| normalize_base64(value) }) if data.is_a?(Hash)
        normalize(object)
      end

      def normalize_base64(value)
        return value unless value.is_a?(String)

        return Base64.strict_encode64(Base64.decode64(value)) if BASE64_ENCODING.match?(value.b.delete("\r\n"))

        index = invalid_base64_offset(value.b)
        raise Status::BadRequest.new("Secret in version \"v1\" cannot be handled as a Secret: illegal base64 data at input byte #{index}")
      end

      # Go's padded standard encoding ignores CR and LF but reports an
      # offset into the original encoded string.
      def invalid_base64_offset(value)
        offsets = (0...value.bytesize).lazy.reject { |offset| [10, 13].include?(value.getbyte(offset)) }
        offsets.each_slice(4) do |positions|
          index = positions.index { |offset| !BASE64_ALPHABET.match?(value.byteslice(offset, 1)) }
          if index.nil?
            next if positions.size == 4

            return value.bytesize - positions.size
          end

          offset = positions.fetch(index)
          return offset if index < 2 || value.getbyte(offset) != 61
          return value.index(/[^\r\n]/n, offset + 1) if index == 3
          return value.bytesize if positions.size < 4

          second_padding = positions.fetch(3)
          return second_padding - 1 if value.getbyte(second_padding) != 61

          return value.index(/[^\r\n]/n, second_padding + 1)
        end
      end
    end
  end
end
