# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # /openapi/v2 and /openapi/v3: the served index, the cached encodings and
      # their ETags.
      module OpenAPIDocuments
        private

        def openapi_response(request, route)
          document = @openapi.document_for(route.path)
          raise Status::NotFound.new("OpenAPI document was not found") if document.nil?

          document = served_openapi_v3_index(document) if route.path == "/openapi/v3"

          protobuf = route.path == "/openapi/v2" && OpenAPIV2Protobuf.accepts?(request.header("accept"))
          content_type = protobuf ? OpenAPIV2Protobuf::RESPONSE_CONTENT_TYPE : "application/json"
          bytes, etag = openapi_encoded(route.path, document, protobuf)
          headers = {"content-type" => content_type, "cache-control" => "no-cache, private", "etag" => %("#{etag}")}
          return Response.new(status: 304, headers: headers, body: "") if etag_matches?(request.header("if-none-match"), etag)
          return Response.new(status: 200, headers: headers, body: bytes) if protobuf

          Response.new(status: 200, headers: headers, body: document, encoded_body: bytes)
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
        def openapi_encoded(path, document, protobuf)
          key = [path.to_s, protobuf]
          cached = @openapi_encoded_mutex.synchronize { @openapi_encoded[key] }
          return cached.last if cached && cached.first.equal?(document)

          bytes = protobuf ? OpenAPIV2Protobuf.encode(document) : JSON.generate(document)
          encoded = [bytes, Digest::SHA512.hexdigest(bytes).upcase]
          @openapi_encoded_mutex.synchronize { @openapi_encoded[key] = [document, encoded] }
          encoded
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
