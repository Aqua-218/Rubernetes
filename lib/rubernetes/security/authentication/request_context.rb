# frozen_string_literal: true

require "ipaddr"

module Rubernetes
  module Security
    module Authentication
      # The slice of an HTTP request that authenticators see: headers, the
      # verified TLS client certificate chain (if any) and the peer address.
      # Authenticators never see the body.
      class RequestContext
        attr_reader :headers, :client_certificate, :client_chain, :remote_address, :path

        def initialize(headers: {}, client_certificate: nil, client_chain: [], remote_address: nil, path: "/")
          @headers = headers
          @client_certificate = client_certificate
          @client_chain = Array(client_chain)
          @remote_address = remote_address
          @path = path
        end

        # Header names are case-insensitive whatever container carries them.
        def header(name)
          return @headers.get(name) if @headers.respond_to?(:get)
          return nil unless @headers.respond_to?(:each_pair)

          wanted = name.to_s.downcase
          @headers.each_pair { |key, value| return value.is_a?(Array) ? value.first : value if key.to_s.downcase == wanted }
          nil
        end

        def header_values(name)
          if @headers.respond_to?(:raw_values)
            @headers.raw_values(name)
          elsif @headers.respond_to?(:values_for)
            @headers.values_for(name)
          else
            value = header(name)
            value.nil? ? [] : Array(value)
          end
        end

        def bearer_token
          authorization = header("authorization").to_s
          return nil unless authorization.match?(/\Abearer\s+/i)

          token = authorization.sub(/\Abearer\s+/i, "").strip
          # RFC 6750: an empty or whitespace-only token is no token.
          token.empty? ? nil : token
        end

        def remote_ip
          value = @remote_address.to_s.sub(/\A\[(.*)\](?::\d+)?\z/, '\1')
          value = value.sub(/:\d+\z/, "") if value.count(":") == 1
          IPAddr.new(value)
        rescue IPAddr::InvalidAddressError
          nil
        end
      end
    end
  end
end
