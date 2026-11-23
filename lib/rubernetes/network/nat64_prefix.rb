# frozen_string_literal: true

require "ipaddr"

module Rubernetes
  module Network
    # RFC 6052 embeds IPv4 addresses in the translator's IPv6 prefix.
    class Nat64Prefix
      LENGTHS = [32, 40, 48, 56, 64, 96].freeze
      WELL_KNOWN = IPAddr.new("64:ff9b::/96").freeze
      UNICAST = %w[2000::/3 fc00::/7 64:ff9b:1::/48].map { |cidr| IPAddr.new(cidr).freeze }.freeze
      NON_GLOBAL_IPV4 = %w[
        0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
        172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16
        198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
      ].map { |cidr| IPAddr.new(cidr).freeze }.freeze
      GLOBAL_ANYCAST = %w[192.0.0.9 192.0.0.10].freeze

      def initialize(value)
        raise ArgumentError, "NAT64 prefix must be an IPv6 network in CIDR notation" unless value.is_a?(String) && value.match?(%r{\A[^/%]+/[0-9]{1,3}\z})

        host = IPAddr.new(value.split("/", 2).first)
        @prefix = IPAddr.new(value).freeze
        @well_known = @prefix.eql?(WELL_KNOWN)
        unicast = @well_known || UNICAST.any? { |range| range.include?(@prefix) }
        return if unicast && LENGTHS.include?(@prefix.prefix) && host.to_i == @prefix.to_i && @prefix.hton.getbyte(8).zero?

        raise ArgumentError, "NAT64 prefix must be an aligned IPv6 unicast /32, /40, /48, /56, /64 or /96 with a zero u octet"
      end

      def to_s
        "#{@prefix}/#{@prefix.prefix}"
      end

      def embed(ipv4)
        address = IPAddr.new(ipv4)
        return unless address.ipv4?
        return if @well_known && !GLOBAL_ANYCAST.include?(address.to_s) && NON_GLOBAL_IPV4.any? { |range| range.include?(address) }

        bytes = @prefix.hton
        ipv4_bytes = address.hton
        offset = @prefix.prefix / 8
        if offset == 12
          bytes[12, 4] = ipv4_bytes
        else
          # Octet 8 is reserved. Split IPv4 around it for prefixes below /96.
          before_u = 8 - offset
          bytes[offset, before_u] = ipv4_bytes[0, before_u]
          bytes[9, 4 - before_u] = ipv4_bytes[before_u, 4 - before_u]
        end
        IPAddr.new_ntoh(bytes).to_s
      end
    end
  end
end
