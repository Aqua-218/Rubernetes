# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # From the request to what a handler works with: the decoded body, duplicate
      # key detection, query parameters, and the checks of an object against the
      # route it was sent to.
      module RequestDecoding
        private

        def hash_value(hash, key)
          return nil unless hash.is_a?(Hash)

          hash[key] || hash[key.to_sym]
        end

        def normalize_object(request, route)
          body = request_body(request)
          raise Status::Invalid.new("request body must be a JSON object") unless body.is_a?(Hash)

          # A JSON or protobuf body was just decoded into a fresh object with
          # String keys (request_body keeps nothing): copying it again was a
          # tenth of a Pod PUT's normalization.  A Hash handed in-process, or
          # YAML (whose keys need not be Strings), is still copied.
          fresh = request.body.is_a?(String) && !request.content_type.to_s.include?("yaml")
          object = fresh ? body : stringify_keys(body)
          validate_route_identity!(object, route)
          object["apiVersion"] ||= route_identity(route).fetch(:api_version)
          object["kind"] ||= route_identity(route).fetch(:kind)
          object["metadata"] = stringify_keys(object["metadata"] || {})
          # kube-apiserver decodes a JSON null for a map, slice or pointer field of
          # a typed object as "absent" and never serves it back; a stored
          # "annotations": null reached every Pod a Job created from such a
          # template and crashed node admission.  Custom resources keep their
          # own nullable/pruning rules, but ObjectMeta is typed for every kind.
          if route.resource.custom?
            drop_null_fields!(object["metadata"])
          else
            drop_null_fields!(object)
          end
          object
        end

        def drop_null_fields!(value)
          case value
          when Hash
            value.delete_if { |_key, entry| entry.nil? }
            value.each_value { |entry| drop_null_fields!(entry) }
          when Array
            value.each { |entry| drop_null_fields!(entry) }
          end
          value
        end

        # sigs.k8s.io/json reports duplicate JSON object keys as strict violations.
        # Ruby's JSON parser keeps only the last of a duplicate pair, so the raw
        # body is scanned separately for repeated keys within one object.
        def request_duplicate_fields(request)
          body = request.body
          return [] unless body.is_a?(String) && !body.empty?

          media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
          return [] if media_type == Negotiation::PROTOBUF_TYPE

          text = body.dup.force_encoding(Encoding::UTF_8)
          return [] unless text.valid_encoding?

          begin
            duplicate_json_paths(text)
          rescue JSON::ParserError
            # A body JSON cannot parse is reported by the decoder itself.
            []
          end
        end

        # gopkg.in/yaml.v2, reached through sigs.k8s.io/yaml YAMLToJSONStrict,
        # refuses a repeated mapping key and names the line it found it on.  The
        # apiserver runs the body through it a second time purely to catch that
        # (runtime/serializer/json/json.go Serializer.unmarshal: "pass the
        # original data through the YAMLToJSONStrict converter ... to catch
        # duplicate fields in YAML that would have been dropped") and passes the
        # whole multi-line error through as ONE strict-decoding violation.  Ruby
        # and Go both keep the last of a repeated key, so without this a YAML
        # body could repeat any field and a Strict request would accept it.
        YAML_STRICT_PREFIX = "yaml: unmarshal errors:\n"

        YAML_MEDIA_TYPES = ["application/yaml", "application/x-yaml", "text/yaml",
                            "application/apply-patch+yaml"].freeze

        def request_duplicate_yaml_errors(request)
          body = request.body
          return [] unless body.is_a?(String) && !body.empty?

          media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
          return [] unless YAML_MEDIA_TYPES.include?(media_type)

          text = body.dup.force_encoding(Encoding::UTF_8)
          return [] unless text.valid_encoding?

          duplicates = begin
            duplicate_yaml_keys(text)
          rescue Psych::Exception
            # A body YAML cannot parse at all is a decoding failure the normal
            # path reports; it is not a duplicate-key finding.
            []
          end
          return [] if duplicates.empty?

          [YAML_STRICT_PREFIX + duplicates.map do |line, key|
            "  line #{line}: key #{key.inspect} already set in map"
          end.join("\n")]
        end

        # [[line, key], ...] in document order, 1-based lines, matching the
        # yaml.v2 decoder's own report.
        def duplicate_yaml_keys(text)
          found = []
          visit = lambda do |node|
            if node.is_a?(Psych::Nodes::Mapping)
              seen = {}
              node.children.each_slice(2) do |key, value|
                name = key.is_a?(Psych::Nodes::Scalar) ? key.value.to_s : nil
                if name.nil?
                  visit.call(key)
                elsif seen.key?(name)
                  found << [key.start_line + 1, name]
                else
                  seen[name] = true
                end
                visit.call(value) unless value.nil?
              end
            else
              # A Scalar or an Alias has no children at all (nil, not []).
              Array(node.children).each { |child| visit.call(child) }
            end
          end
          Psych.parse_stream(text).children.each { |document| visit.call(document) }
          found
        end

        # For Warn the apiserver splits the same block back into one warning per
        # line (endpoints/handlers/rest.go parseYAMLWarnings).
        def split_yaml_strict_error(message)
          text = message.to_s
          return [text] unless text.start_with?(YAML_STRICT_PREFIX)

          text.delete_prefix(YAML_STRICT_PREFIX).split("\n").map(&:strip).reject(&:empty?)
        end

        def duplicate_json_paths(text)
          scanner = StringScanner.new(text)
          duplicates = []
          stack = []
          seen = []
          pending_key = nil
          until scanner.eos?
            if scanner.scan(/\s+/)
              next
            elsif scanner.scan("{")
              stack.push(pending_key)
              seen.push({})
              pending_key = nil
            elsif scanner.scan("}")
              stack.pop
              seen.pop
            elsif scanner.scan("[")
              stack.push(pending_key)
              seen.push(nil)
              pending_key = nil
            elsif scanner.scan("]")
              stack.pop
              seen.pop
            elsif (literal = scanner.scan(/"(?:\\.|[^"\\])*"/))
              if seen.last.is_a?(Hash) && scanner.check(/\s*:/)
                key = JSON.parse(literal).to_s
                path = (stack.compact + [key]).join(".")
                duplicates << path if seen.last.key?(key)
                seen.last[key] = true
                pending_key = key
              end
            else
              scanner.getch
            end
          end
          duplicates.uniq
        end

        def request_body(request)
          body = request.body
          return {} if body.nil?
          return {} if body.is_a?(String) && body.empty?
          return body unless body.is_a?(String)

          media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
          unless media_type == Negotiation::PROTOBUF_TYPE
            # JSON and YAML bodies must be valid UTF-8 (RFC 8259); anything else
            # is a 400, never an exception from the encoder later on.
            text = body.dup.force_encoding(Encoding::UTF_8)
            raise Status::BadRequest.new("request body is not valid UTF-8") unless text.valid_encoding?
            raise Status::BadRequest.new("request body contains a NUL byte") if text.include?("\0")

            body = text
          end
          # A request that names no Content-Type is JSON, the way kube-apiserver
          # treats it.  Asking a nil for #include? turned every such request --
          # a Binding posted by a client that omits the header among them --
          # into a 500.
          content_type = request.content_type.to_s
          if media_type == Negotiation::PROTOBUF_TYPE
            decode_protobuf_body(body)
          elsif content_type.include?("yaml")
            YAML.safe_load(body, permitted_classes: [], aliases: false) || {}
          else
            JSON.parse(body)
          end
        end

        # Kubernetes protobuf bodies arrive as the runtime.Unknown envelope that
        # typed client-go clients send; decoding yields the same JSON-shaped
        # object the rest of the server works with.
        def decode_protobuf_body(body)
          protobuf_codec.decode(body.b)
        rescue Schema::Codec::KubernetesProtobuf::Error, Schema::Codec::ParseError => error
          raise Status::BadRequest.new("request body is not valid Kubernetes protobuf: #{error.message}")
        end

        # A PATCH route identifies a concrete GVR, so an apply document cannot
        # silently target another GVK. Kubernetes returns an Invalid (422)
        # Status with one cause per mismatching identity field.
        def validate_route_identity!(object, route)
          causes = []
          identity = route_identity(route)
          expected_api_version = identity.fetch(:api_version)
          expected_kind = identity.fetch(:kind)
          if object.key?("apiVersion") && object["apiVersion"].to_s != expected_api_version
            causes << {
              "reason" => "FieldValueInvalid",
              "message" => "apiVersion #{object["apiVersion"].inspect} does not match #{expected_api_version.inspect}",
              "field" => "apiVersion"
            }
          end
          if object.key?("kind") && object["kind"].to_s != expected_kind
            causes << {
              "reason" => "FieldValueInvalid",
              "message" => "kind #{object["kind"].inspect} does not match #{expected_kind.inspect}",
              "field" => "kind"
            }
          end
          return if causes.empty?

          raise Status::Invalid.new(
            "resource body does not match the requested #{expected_api_version}, Kind=#{expected_kind}",
            details: resource_details(route).merge("apiVersion" => expected_api_version,
                                                   "causes" => causes)
          )
        end

        def route_identity(route)
          subresource = route.subresource && route.resource.subresource(route.subresource)
          advertised_group = subresource&.advertised_group(route.resource.group)
          advertised_version = subresource&.advertised_version(route.resource.group, route.resource.version)
          {
            api_version: if advertised_group && advertised_version
                           advertised_group.to_s.empty? ? advertised_version.to_s : "#{advertised_group}/#{advertised_version}"
                         else
                           route.resource.api_version
                         end,
            kind: subresource&.kind || route.resource.kind
          }
        end

        def query(request, key)
          request.query_value(key)
        end

        def integer_query(request, key)
          value = query(request, key)
          return nil if value.nil? || value.to_s.empty?

          integer = Integer(value)
          if integer.negative?
            raise Status::BadRequest.new(
              "query parameter #{key} must be a non-negative integer",
              details: {"causes" => [{"reason" => "FieldValueInvalid",
                                      "message" => "must be a non-negative integer",
                                      "field" => key}]}
            )
          end

          integer
        rescue ArgumentError, TypeError
          raise Status::BadRequest.new(
            "query parameter #{key} must be an integer",
            details: {"causes" => [{"reason" => "FieldValueInvalid",
                                    "message" => "must be an integer",
                                    "field" => key}]}
          )
        end

        def truthy?(value)
          %w[1 true yes].include?(value.to_s.downcase)
        end

        def watch_request?(request)
          request.method == "GET" && truthy?(query(request, "watch"))
        end

        def storage_namespace(route, operation:)
          return :cluster if route.resource.cluster_scoped?
          return route.namespace unless route.namespace.nil?
          return :all if %i[list watch].include?(operation)

          raise Status::Invalid.new("namespace is required for #{operation} on namespaced resources")
        end

        def ensure_name!(object, expected_name)
          actual = metadata_value(object, "name")
          return if actual.to_s.empty? || actual.to_s == expected_name.to_s

          raise Status::Invalid.new("metadata.name #{actual.inspect} does not match URL name #{expected_name.inspect}")
        end

        def ensure_expected_version!(existing, expected)
          actual = metadata_value(existing, "resourceVersion").to_s
          return if expected.to_s == actual

          raise Status::Conflict.new("resourceVersion #{expected.inspect} does not match current #{actual.inspect}")
        end
      end
    end
  end
end
