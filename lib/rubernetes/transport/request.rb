# frozen_string_literal: true

require "json"
require "uri"

require_relative "headers"

module Rubernetes
  module Transport
    # Immutable value passed to an in-process API handler.
    class Request
      MISSING = Object.new.freeze
      attr_reader :target, :headers, :body, :http_version, :remote_address, :initial_data, :client_certificate, :client_chain

      def initialize(method:, target:, headers: Headers.new, body: "", http_version: "HTTP/1.1", remote_address: nil,
                     initial_data: "", client_certificate: nil, client_chain: [])
        @method_name = String(method).upcase.freeze
        # The TLS client certificate presented on this connection (verified
        # later by the x509 / request-header authenticators, never here).
        @client_certificate = client_certificate
        @client_chain = Array(client_chain).freeze
        @target = String(target).dup.freeze
        @headers = headers.is_a?(Headers) ? headers : Headers.new(headers)
        @body = String(body).dup.freeze
        @http_version = String(http_version).dup.freeze
        @remote_address = remote_address&.dup&.freeze
        @initial_data = String(initial_data).b.freeze
        @path, @query_string = split_target(@target)
        @query = parse_query(@query_string)
        freeze
      end

      # The HTTP method as an uppercase string.
      def method
        @method_name
      end

      alias verb method

      # The path component of the request target without its query string.
      attr_reader :path

      # The raw query string, without the leading question mark.
      attr_reader :query_string

      # Query parameters use CGI's repeated-key representation (Array values).
      def query
        @query.each_with_object({}) do |(key, value), copy|
          copy[key] = value.is_a?(Array) ? value.dup : value
        end
      end
      alias params query

      def header(name)
        headers[name]
      end

      def content_type
        header("content-type").to_s.split(";", 2).first
      end

      def query_value(name, default = nil)
        value = @query[name.to_s]
        value = value.first if value.is_a?(Array) && value.length == 1
        value.nil? ? default : value
      end

      def query_values(name)
        value = @query[name.to_s]
        value.is_a?(Array) ? value.dup : (value.nil? ? [] : [value])
      end

      def [](key)
        case key.to_sym
        when :method, :verb
          method
        when :target
          target
        when :path
          path
        when :query, :params
          query
        when :query_string
          query_string
        when :headers
          headers
        when :body
          body
        when :http_version
          http_version
        when :remote_address
          remote_address
        when :initial_data
          initial_data
        else
          nil
        end
      end

      def fetch(key, default = MISSING, &block)
        known_key = %i[method verb target path query params query_string headers body http_version remote_address initial_data].include?(key.to_sym)
        return self[key] if known_key
        return block.call(key) if block
        return default unless default.equal?(MISSING)

        raise KeyError, "key not found: #{key.inspect}"
      end

      def to_h
        {
          method: method,
          verb: method,
          target: target,
          path: path,
          query_string: query_string,
          query: query,
          params: query,
          headers: headers,
          body: body,
          http_version: http_version,
          remote_address: remote_address,
          initial_data: initial_data
        }
      end
      alias to_hash to_h

      def json
        return nil if body.empty?

        JSON.parse(body)
      end
      alias json_body json

      private

      def split_target(target)
        if target.start_with?("/")
          path, query = target.split("?", 2)
          return [path, query || ""]
        end

        return [target, ""] if target == "*"

        uri = URI.parse(target)
        [uri.path.empty? ? "/" : uri.path, uri.query.to_s]
      rescue URI::InvalidURIError
        [target.split("?", 2).first, target.split("?", 2).last.to_s]
      end

      def parse_query(value)
        URI.decode_www_form(value).each_with_object({}) do |(key, item), query|
          if query.key?(key)
            query[key] = Array(query[key]) << item
          else
            query[key] = [item]
          end
        end.freeze
      rescue ArgumentError => error
        raise BadRequest, "query string is malformed: #{error.message}"
      end
    end
  end
end
