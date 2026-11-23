# frozen_string_literal: true

require "date"
require "time"

module Rubernetes
  module API
    class Server
      # /openapi/v2 and /openapi/v3: the served index, the cached encodings and
      # their ETags.
      module OpenAPIDocuments
        private

        def openapi_response(request, route)
          if route.path.start_with?("/openapi/v3/apis/")
            remote = @aggregator&.openapi_response(request)
            return remote if remote
          end

          if route.path.start_with?("/openapi/v3/")
            index = @openapi.document_for("/openapi/v3")
            key = route.path.delete_prefix("/openapi/v3/")
            return openapi_not_found unless index && served_openapi_v3_index(index).fetch("paths").key?(key)
          end

          document = @openapi.document_for(route.path)
          return openapi_not_found if document.nil?

          if route.path == "/openapi/v3"
            document = served_openapi_v3_index(document)
            paths = @aggregator&.openapi_paths
            document = document.merge("paths" => document.fetch("paths").merge(paths)) unless paths.nil? || paths.empty?
          end

          format, content_type = openapi_format(route.path, request.header("accept"))
          bytes, etag = openapi_encoded(route.path, document, :json)
          headers = {"cache-control" => "no-cache, private", "etag" => %("#{etag}")}
          vary = openapi_vary(route.path)
          headers["vary"] = vary if vary
          if route.path.start_with?("/openapi/v3/") && !(hash = request.query_value("hash").to_s).empty?
            if hash != etag
              headers["location"] = "#{route.path}?hash=#{etag}"
              headers["content-type"] = content_type
              return Response.new(status: 301, headers: headers, body: "")
            end
            headers["cache-control"] = "public, immutable"
            headers["expires"] = (Time.now.utc.to_datetime >> 12).to_time.httpdate
          end
          return Response.new(status: 304, headers: headers, body: "") if etag_matches?(request.header("if-none-match"), etag)

          headers["content-type"] = content_type
          if format == :json
            Response.new(status: 200, headers: headers, body: document, encoded_body: bytes)
          else
            encoded, = openapi_encoded(route.path, document, format, etag: etag)
            Response.new(status: 200, headers: headers, body: encoded)
          end
        rescue Status::NotAcceptable
          Response.new(status: 406, headers: {"vary" => openapi_vary(route.path)}, body: "")
        end

        def openapi_not_found
          Response.new(status: 404, headers: {"cache-control" => "no-cache, private"}, body: "")
        end

        def openapi_vary(path)
          return "Accept-Encoding, Accept" if path == "/openapi/v2"
          return "Accept" if path.start_with?("/openapi/v3/")

          nil
        end

        def openapi_format(path, accept)
          if path.start_with?("/openapi/v3/")
            content_type = OpenAPIV3Protobuf.negotiate(accept)
            return [:v3_protobuf, content_type] if content_type == OpenAPIV3Protobuf::CONTENT_TYPE
          elsif path == "/openapi/v2"
            content_type = OpenAPIV2Protobuf.negotiate(accept)
            return [:v2_protobuf, content_type] if content_type == OpenAPIV2Protobuf::CONTENT_TYPE
          end
          [:json, "application/json"]
        end

        # The generated index lists every group/version the schema corpus
        # knows; kube-apiserver's lists only the ones it serves, so a
        # group/version that is off (alpha APIs without --runtime-config) is
        # dropped here, and a group entry stays only while one of its versions
        # is served.  One filtered copy per source document keeps the encoding
        # cache below effective.
        def served_openapi_v3_index(index)
          @openapi_index_mutex ||= Mutex.new
          @openapi_index_mutex.synchronize do
            cached = @served_openapi_index
            return cached.last if cached && cached.first.equal?(index)

            served = @registry.resources.select { |resource| version_served?(resource) }
            group_versions = served.to_set { |resource| resource.group.empty? ? "api/#{resource.version}" : "apis/#{resource.group}/#{resource.version}" }
            groups = served.map(&:group).reject(&:empty?).to_set { |group| "apis/#{group}" }
            paths = (index["paths"] || {}).select do |path, _|
              if path.match?(%r{\Aapi/[^/]+\z}) || path.match?(%r{\Aapis/[^/]+/[^/]+\z})
                group_versions.include?(path)
              elsif path.match?(%r{\Aapis/[^/]+\z})
                groups.include?(path)
              else
                true
              end
            end
            filtered = index.merge("paths" => paths).freeze
            @served_openapi_index = [index, filtered]
            filtered
          end
        end

        # kube-openapi serves every spec with an ETag (hex SHA-512 of the bytes)
        # and answers a matching If-None-Match with 304.  The CRD publishing
        # specs poll /openapi/v2 over fresh connections until ten reads in a
        # row agree; without the ETag each read re-sent -- and the client
        # re-parsed -- the whole 3 MB swagger document.  The encoding of one
        # document object is kept: the repository hands out the same object
        # until a definition is published or withdrawn.
        def openapi_encoded(path, document, format, etag: nil)
          return @openapi.encoded_group(path, document, format) { encode_openapi_document(document, format, etag) } if path.start_with?("/openapi/v3/")

          key = [path.to_s, format]
          cached = @openapi_encoded_mutex.synchronize { @openapi_encoded[key] }
          return cached.last if cached && cached.first.equal?(document)

          encoded = encode_openapi_document(document, format, etag)
          @openapi_encoded_mutex.synchronize { @openapi_encoded[key] = [document, encoded] }
          encoded
        end

        def encode_openapi_document(document, format, etag)
          bytes = case format
                  when :v3_protobuf then OpenAPIV3Protobuf.encode(document)
                  when :v2_protobuf then OpenAPIV2Protobuf.encode(document)
                  else JSON.generate(document)
                  end
          [bytes, etag || Digest::SHA512.hexdigest(bytes).upcase]
        end

        def etag_matches?(header, etag)
          return false if header.nil? || header.to_s.strip.empty?

          header.to_s.split(",").any? do |candidate|
            value = candidate.strip.delete_prefix("W/")
            value == "*" || value.delete_prefix('"').delete_suffix('"') == etag
          end
        end
      end
    end
  end
end
