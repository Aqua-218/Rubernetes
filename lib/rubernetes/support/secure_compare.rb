# frozen_string_literal: true

require "openssl"

module Rubernetes
  module SecureCompare
    def self.call(left, right)
      left.bytesize == right.bytesize && OpenSSL.fixed_length_secure_compare(left, right)
    end
  end
end
