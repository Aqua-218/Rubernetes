# frozen_string_literal: true

require "digest"
require "time"
require_relative "../openapi_v3_protobuf"
require_relative "openapi_v2_converter"

module Rubernetes
  module API
    class Aggregator
      # Publish each APIService's discovery URL under the aggregator origin.
      module OpenAPI
        PRIVATE_CACHE = "no-cache, private"
        FORWARDED_REDIRECT_ERROR = "the backend attempted to redirect this request, which is not permitted"

        class ConvertedDocument
          attr_reader :bytes, :etag, :source_etag, :source_digest

          def initialize(bytes:, etag:, source_etag:, source_digest:)
            @bytes = bytes
            @etag = etag
            @source_etag = source_etag
            @source_digest = source_digest
            @mutex = Mutex.new
          end

          def protobuf_bytes
            @mutex.synchronize { @protobuf_bytes ||= OpenAPIV3Protobuf.encode(JSON.parse(bytes)).freeze }
          end
        end

        def refresh_openapi(backend)
          key = "apis/#{backend.group}/#{backend.version}"
          response = openapi_get(backend, "/openapi/v3", "accept" => "application/json")
          return unless response

          case response.code.to_i
          when 200
            index = JSON.parse(response.body)
            publish_openapi(backend, key, local_openapi_url(key, index.dig("paths", key, "serverRelativeURL"))) if index.is_a?(Hash)
          when 404
            refresh_legacy_openapi(backend, key)
          end
        rescue JSON::ParserError, TypeError
          nil
        end

        def openapi_paths
          @mutex.synchronize { @openapi_paths.dup }
        end

        def openapi_response(request)
          key = request.path.delete_prefix("/openapi/v3/")
          prefix, group, version = key.split("/", 3)
          return unless prefix == "apis"

          backend, url, converted = @mutex.synchronize do
            [@backends["#{version}.#{group}"], @openapi_paths.dig(key, "serverRelativeURL"), @converted_openapi[key]]
          end
          return unless backend

          raise Status::NotFound.new("OpenAPI document was not found") unless url
          return converted_openapi_response(request, url, converted) if converted

          native_openapi_response(request, backend)
        end

        private

        def native_openapi_response(request, backend)
          # Discovery selects the backend. Its handler needs the client URL,
          # including a hash that may differ from the cached discovery entry.
          path = request.path
          path = "#{path}?#{URI.encode_www_form(request.query.sort)}" unless request.query.empty?
          headers = %w[accept if-none-match if-modified-since].to_h { |name| [name, request.header(name)] }.compact
          response = openapi_get(backend, path, headers)
          return unavailable_response unless response

          status = response.code.to_i
          if status.between?(300, 399) && !response["location"].to_s.empty?
            return Response.new(status: 502, headers: {"cache-control" => PRIVATE_CACHE, "content-type" => "text/plain; charset=utf-8"},
                                body: FORWARDED_REDIRECT_ERROR)
          end

          headers = %w[content-type etag last-modified vary expires].to_h { |name| [name, response[name]] }.compact
          backend_cache = response["cache-control"]
          # The kube-aggregator proxy appends backend directives to the
          # apiserver's private revalidation policy for forwarded responses.
          headers["cache-control"] = backend_cache.to_s.empty? ? PRIVATE_CACHE : "#{PRIVATE_CACHE}, #{backend_cache}"
          body = response.body.to_s
          Response.new(status: status, headers: headers, body: body, encoded_body: body)
        end

        def refresh_legacy_openapi(backend, key)
          previous = @mutex.synchronize { @converted_openapi[key] }
          headers = {"accept" => "application/json"}
          headers["if-none-match"] = previous.source_etag if previous&.source_etag
          response = openapi_get(backend, "/openapi/v2", headers)
          return unless response
          return publish_openapi(backend, key, nil) if response.code.to_i == 404
          return unless response.code.to_i == 200

          digest = Digest::SHA512.hexdigest(response.body)
          source_etag = response["etag"]
          source_etag = nil if source_etag == ""
          return if previous&.source_digest == digest && previous.source_etag == source_etag

          document = OpenAPIV2Converter.convert(JSON.parse(response.body))
          return unless document

          bytes = JSON.generate(document).freeze
          etag = Digest::SHA512.hexdigest(bytes).upcase
          converted = ConvertedDocument.new(bytes: bytes, etag: etag, source_etag: source_etag, source_digest: digest)
          publish_openapi(backend, key, "/openapi/v3/#{key}?hash=#{etag}", converted: converted)
        end

        def publish_openapi(backend, key, url, converted: nil)
          @mutex.synchronize do
            next unless @backends[backend.name].equal?(backend) && @availability[backend.name]

            forget_openapi(backend)
            @openapi_paths[key] = {"serverRelativeURL" => url} if url
            @converted_openapi[key] = converted if converted
          end
        end

        def converted_openapi_response(request, url, document)
          content_type = OpenAPIV3Protobuf.negotiate(request.header("accept"))
          headers = {"etag" => %("#{document.etag}"), "cache-control" => PRIVATE_CACHE, "vary" => "Accept"}
          requested_hash = request.query_value("hash").to_s
          unless requested_hash.empty?
            if requested_hash != document.etag
              return Response.new(status: 301, headers: headers.merge("location" => url, "content-type" => content_type), body: "")
            end

            headers["cache-control"] = "public, immutable"
            now = @clock.call.utc
            headers["expires"] = Time.utc(now.year + 1, now.month, now.day, now.hour, now.min, now.sec).httpdate
          end

          candidates = request.header("if-none-match").to_s.split(",")
          if candidates.any? { |candidate| ["*", headers["etag"]].include?(candidate.strip.delete_prefix("W/")) }
            return Response.new(status: 304, headers: headers, body: "")
          end

          bytes = content_type == OpenAPIV3Protobuf::CONTENT_TYPE ? document.protobuf_bytes : document.bytes
          headers["content-type"] = content_type
          Response.new(status: 200, headers: headers, body: bytes, encoded_body: bytes)
        end

        def forget_openapi(backend)
          return unless backend

          key = "apis/#{backend.group}/#{backend.version}"
          @openapi_paths.delete(key)
          @converted_openapi.delete(key)
        end

        def local_openapi_url(key, value)
          return unless value.is_a?(String)

          uri = URI.parse(value)
          return unless uri.relative? && !uri.host && !uri.fragment && uri.path == "/openapi/v3/#{key}"

          uri.to_s
        rescue URI::InvalidURIError
          nil
        end

        def openapi_get(backend, path, headers)
          http = build_http(URI.parse(resolve(backend)), backend)
          total = 0
          bytes = +"".b
          request = Net::HTTP::Get.new(path, headers.merge(AGGREGATOR_IDENTITY))
          response = http.request(request) do |incoming|
            incoming.read_body do |chunk|
              total += chunk.bytesize
              return nil if total > MAX_BODY_BYTES

              bytes << chunk
            end
          end
          response.body = bytes
          response
        rescue Net::OpenTimeout, Net::ReadTimeout, Net::ProtocolError, OpenSSL::SSL::SSLError,
               SystemCallError, SocketError, IOError
          nil
        end
      end
    end
  end
end
