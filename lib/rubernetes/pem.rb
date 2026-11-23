# frozen_string_literal: true

require "base64"

module Rubernetes
  module PEM
    Block = Data.define(:type, :bytes, :headers)

    module_function

    # PEM readers skip text outside blocks and malformed blocks.
    def blocks(value)
      return enum_for(__method__, value) unless block_given?

      type = encoded = nil
      headers = reading_headers = false
      value.to_s.b.each_line do |raw|
        line = raw.chomp.delete_suffix("\r").sub(/[ \t]+\z/, "")
        if (begin_line = /\A-----BEGIN (.*)-----\z/.match(line))
          type = begin_line[1]
          encoded = +""
          headers = false
          reading_headers = true
        elsif line.start_with?("-----END ")
          if type && line == "-----END #{type}-----" && (bytes = decode_block(encoded))
            yield Block.new(type, bytes, headers)
          end
          type = nil
        elsif type
          if reading_headers && line.include?(":")
            headers = true
          else
            reading_headers = false
            encoded << line.delete(" \t")
          end
        end
      end
    end

    def decode_block(encoded)
      Base64.strict_decode64(encoded)
    rescue ArgumentError
      nil
    end

    def certificate(bytes)
      body = Base64.strict_encode64(bytes).scan(/.{1,64}/).join("\n")
      body += "\n" unless body.empty?
      "-----BEGIN CERTIFICATE-----\n#{body}-----END CERTIFICATE-----\n"
    end
  end
end
