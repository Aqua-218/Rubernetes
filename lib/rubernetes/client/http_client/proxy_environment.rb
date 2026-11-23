# frozen_string_literal: true

require "ipaddr"
require "net/http"

module Rubernetes
  module Client
    class HTTPClient
      module ProxyEnvironment
        module_function

        def http(uri, env: ENV)
          exclusions = (env["no_proxy"] || env["NO_PROXY"]).to_s.split(",").map(&:strip)
          proxy = bypass?(uri, exclusions) ? nil : :ENV
          Net::HTTP.new(uri.hostname, uri.port, proxy)
        end

        def bypass?(uri, exclusions)
          return true if exclusions.include?("*")
          return false unless uri.hostname.include?(":")

          # Ruby's URI proxy matcher splits IPv6 addresses at colons. Match
          # these exclusions before it handles domains and IPv4 addresses.
          address = IPAddr.new(uri.hostname)
          exclusions.any? { |entry| ipv6_match?(address, uri.port, entry) }
        end

        def ipv6_match?(address, port, entry)
          return false unless entry.include?(":")

          if (bracketed = /\A\[([^\]]+)\](?::([0-9]+))?\z/.match(entry))
            return false if bracketed[2] && Integer(bracketed[2], 10) != port

            entry = bracketed[1]
          end

          IPAddr.new(entry).include?(address)
        rescue IPAddr::Error
          false
        end
      end
    end
  end
end
