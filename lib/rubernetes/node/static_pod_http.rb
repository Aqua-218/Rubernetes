# frozen_string_literal: true

require "net/http"
require "timeout"
require "uri"

module Rubernetes
  module Node
    # Transport used by kubelet's staticPodURL source.
    class StaticPodHTTP
      class Error < StandardError; end

      TIMEOUT = 10
      REDIRECTS = %w[301 302 303 307 308].freeze
      SENSITIVE_HEADERS = %w[authorization www-authenticate cookie cookie2].freeze

      class Request < Net::HTTP::Get
        # Net::HTTP normally folds repeated values into a comma-separated
        # field. Kubelet sends the configured values as individual fields.
        def each_capitalized
          return enum_for(__method__) unless block_given?

          each_key { |name| get_fields(name).each { |value| yield capitalize(name), value } }
        end
      end

      def initialize(url:, headers:, max_bytes:)
        @url = URI.parse(url)
        @headers = headers
        @max_bytes = max_bytes
      end

      def read
        Timeout.timeout(TIMEOUT) { fetch }
      rescue Timeout::Error
        raise Error, "request timed out"
      rescue IOError, SocketError, SystemCallError, OpenSSL::SSL::SSLError, Net::ProtocolError, URI::InvalidURIError => error
        # The URL may contain credentials, and transport errors can echo it.
        raise Error, "request failed (#{error.class})"
      end

      private

      def fetch
        target = @url
        10.times do
          headers = trusted_redirect?(target) ? @headers : @headers.reject { |name, _| SENSITIVE_HEADERS.include?(name.downcase) }
          response = request(target, headers)
          return response unless response.is_a?(URI)

          target = response
        end
        raise Error, "too many redirects"
      end

      def request(target, headers)
        request = Request.new(target.request_uri)
        headers.each { |name, values| values.each { |value| request.add_field(name, value) } }
        if !request["authorization"] && target.user
          request.basic_auth(URI::DEFAULT_PARSER.unescape(target.user), URI::DEFAULT_PARSER.unescape(target.password.to_s))
        end
        # Go's ProxyFromEnvironment treats * as a proxy bypass for every host.
        no_proxy = (ENV["NO_PROXY"] || ENV.fetch("no_proxy", nil)).to_s.split(",").map(&:strip)
        proxy = no_proxy.include?("*") ? nil : :ENV
        Net::HTTP.start(target.hostname, target.port, proxy, use_ssl: target.scheme == "https", max_retries: 0) do |http|
          http.request(request) do |response|
            return redirect_target(target, response) if REDIRECTS.include?(response.code) && response["location"]
            raise Error, "HTTP #{response.code}" unless response.code == "200"

            body = +"".b
            response.read_body do |chunk|
              raise Error, "manifest exceeds #{@max_bytes} bytes" if body.bytesize + chunk.bytesize > @max_bytes

              body << chunk
            end
            return body
          end
        end
      end

      def redirect_target(current, response)
        target = URI.join(current.to_s, response["location"])
        raise Error, "redirect requires HTTP or HTTPS" unless target.is_a?(URI::HTTP) && target.hostname

        target
      end

      def trusted_redirect?(target)
        host = target.hostname.downcase
        initial = @url.hostname.downcase
        host == initial || host.end_with?(".#{initial}")
      end
    end
  end
end
