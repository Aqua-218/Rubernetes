# frozen_string_literal: true

require "uri"

module Rubernetes
  module API
    # Transport-neutral request value passed to Handler#call.
    class Request
      attr_reader :method, :path, :headers, :query, :body, :identity, :client_certificate, :client_chain, :remote_address,
                  :request_id, :attributes

      # `path` has its trailing slash removed so routing does not have to care
      # about it.  The proxy subresource does care -- ".../proxy" redirects to
      # ".../proxy/" -- so the path exactly as the client wrote it is kept too.
      # Deciding that redirect from the normalized path made every request to
      # ".../proxy/" redirect to itself ("stopped after 10 redirects").
      attr_reader :raw_path

      def initialize(method: "GET", path: "/", headers: {}, query: nil, params: nil, body: nil, raw_body: nil,
                     identity: nil, user: nil, client_certificate: nil, client_chain: [], remote_address: nil,
                     request_id: nil, attributes: nil)
        @method = method.to_s.upcase.freeze
        @client_certificate = client_certificate
        @client_chain = Array(client_chain).freeze
        @remote_address = remote_address
        @request_id = request_id
        @attributes = attributes
        raw_path, raw_query = path.to_s.split("?", 2)
        @raw_path = raw_path.to_s.start_with?("/") ? raw_path.to_s : "/#{raw_path}"
        @path = normalize_path(raw_path)
        @headers = normalize_headers(headers)
        # A transport header collection keeps repeated fields apart
        # (Impersonate-Group may be sent once per group).
        @raw_headers = headers.respond_to?(:raw_values) ? headers : nil
        @query = parse_query(raw_query).merge(normalize_query(query || params))
        @body = body.nil? ? raw_body : body
        @identity = identity || user
      end

      # Build a request from a Rack-like environment without making Rack a
      # production dependency.
      def self.from_env(env)
        path = env["PATH_INFO"] || env[:path] || "/"
        query = env["QUERY_STRING"] || env[:query]
        body = env["rack.input"]
        body = body.read if body.respond_to?(:read)
        new(
          method: env["REQUEST_METHOD"] || env[:method] || "GET",
          path: query.to_s.empty? ? path : "#{path}?#{query}",
          headers: env.select { |key, _| key.to_s.start_with?("HTTP_") },
          body: body,
          identity: env["REMOTE_USER"] || env[:identity]
        )
      end

      def header(name)
        @headers[name.to_s.downcase]
      end

      # Every value of a repeated header, as sent.
      def header_values(name)
        return @raw_headers.raw_values(name) if @raw_headers

        value = header(name)
        value.nil? ? [] : [value]
      end

      def content_type
        header("content-type").to_s.split(";", 2).first
      end

      # The first value of a repeated key, as Go's url.Values.Get returns it
      # (every value is `query_values`).  Returning the whole Array for a
      # repeated key sent sonobuoy's `container=x&container=x` exec to the
      # node as the container `["x", "x"]`, a 60s wait and a 503.
      def query_value(name, default = nil)
        value = @query[name.to_s]
        value = value.first if value.is_a?(Array) && value.length == 1
        value.nil? ? default : value
      end

      def query_values(name)
        value = @query[name.to_s]
        if value.is_a?(Array)
          value
        else
          (value.nil? ? [] : [value])
        end
      end

      def json_body
        return body unless body.is_a?(String)

        require "json"
        JSON.parse(body)
      rescue JSON::ParserError => error
        raise Status::BadRequest, "request body is not valid JSON: #{error.message}"
      end

      def with(**changes)
        self.class.new(
          method: changes.fetch(:method, method),
          path: changes.fetch(:path, raw_path),
          headers: changes.fetch(:headers, @raw_headers || headers),
          query: changes.fetch(:query, query),
          body: changes.fetch(:body, body),
          identity: changes.fetch(:identity, identity),
          client_certificate: changes.fetch(:client_certificate, client_certificate),
          client_chain: changes.fetch(:client_chain, client_chain),
          remote_address: changes.fetch(:remote_address, remote_address),
          request_id: changes.fetch(:request_id, request_id),
          attributes: changes.fetch(:attributes, attributes)
        )
      end

      private

      def normalize_path(path)
        value = path.to_s
        value = "/#{value}" unless value.start_with?("/")
        value = value.squeeze("/")
        value = "/" if value.empty?
        value.length > 1 ? value.sub(%r{/$}, "") : value
      end

      def normalize_headers(headers)
        headers.each_with_object({}) do |(key, value), normalized|
          raw_name = key.to_s
          name = if raw_name.start_with?("HTTP_")
                   raw_name.delete_prefix("HTTP_").tr("_", "-").downcase
                 else
                   raw_name.downcase.sub(/^http-/, "")
                 end
          normalized[name] = value.to_s
        end.freeze
      end

      def parse_query(raw_query)
        return {} if raw_query.nil? || raw_query.empty?

        URI.decode_www_form(raw_query).each_with_object({}) do |(key, value), query|
          query[key] = if query.key?(key)
                         Array(query[key]) << value
                       else
                         value
                       end
        end
      rescue ArgumentError => error
        raise Status::BadRequest, "query string is malformed: #{error.message}"
      end

      def normalize_query(query)
        return {} if query.nil?

        query.each_with_object({}) do |(key, value), normalized|
          normalized[key.to_s] = value.is_a?(Array) ? value.map(&:to_s) : value.to_s
        end
      end
    end
  end
end
