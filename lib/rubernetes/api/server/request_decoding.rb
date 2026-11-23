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

        # Standalone payloads such as Scale and TokenRequest belong to a
        # different schema from the workload or service account in the URL.
        def typed_subresource(group, version, kind, resource)
          require_relative "../../../../generated/ruby/kubernetes_types"
          definition = Rubernetes::Generated.definition_for("io.k8s.api.#{group.split(".").first}.#{version}.#{kind}")
          Resource.new(group: group, version: version, kind: kind, resource: resource, scope: :namespaced, schema: definition)
        end

        def normalize_object(request, route)
          body = request_body(request, resource: route.resource)
          raise Status::Invalid.new("request body must be a JSON object") unless body.is_a?(Hash)

          # A JSON or protobuf body was just decoded into a fresh object with
          # String keys (request_body keeps nothing): copying it again was a
          # tenth of a Pod PUT's normalization.  A Hash handed in-process, or
          # YAML (whose keys need not be Strings), is still copied.
          fresh = request.body.is_a?(String) && !request.content_type.to_s.downcase.include?("yaml")
          object = fresh ? body : stringify_keys(body)
          identity = route_identity(route)
          object["apiVersion"] = identity.fetch(:api_version) if object["apiVersion"].to_s.empty?
          object["kind"] = identity.fetch(:kind) if object["kind"].to_s.empty?
          if route.resource.custom?
            validate_route_identity!(object, route)
          elsif object["apiVersion"] != identity.fetch(:api_version) || object["kind"] != identity.fetch(:kind)
            reject_mismatched_builtin!(object, identity)
          end
          object["metadata"] = stringify_keys(object["metadata"] || {})
          validate_wire_identity!(request, route.resource, object)
          match_request_namespace!(object, route)
          # kube-apiserver decodes a JSON null for a map, slice or pointer field of
          # a typed object as "absent" and never serves it back; a stored
          # "annotations": null reached every Pod a Job created from such a
          # template and crashed node admission.  Custom resources keep their
          # own nullable/pruning rules, but ObjectMeta is typed for every kind.
          if route.resource.custom?
            drop_null_fields!(object["metadata"])
          else
            object = SecretData.normalize_request(object) if SecretData.resource?(route.resource)
            Schema::JobSelector.normalize_label_values!(object) if Schema::JobSelector.resource?(route.resource)
            drop_null_fields!(object)
          end
          object
        end

        # ObjectMeta is decoded before storage preconditions are evaluated.
        # Custom resources decode metadata separately from their unstructured body.
        def validate_wire_identity!(request, resource, object)
          metadata = object["metadata"]
          return if metadata.nil?
          raise Status::BadRequest.new("metadata must be an object") unless metadata.is_a?(Hash)

          %w[uid resourceVersion].each do |key|
            value = metadata[key]
            next if value.nil? || value.is_a?(String)

            actual = case value
                     when Numeric then "number"
                     when true, false then "bool"
                     when Array then "array"
                     else "object"
                     end
            field = resource.custom? ? key : "metadata.#{key}"
            expected = key == "uid" ? "types.UID" : "string"
            refuse_undecodable_write!(resource, request, "json: cannot unmarshal #{actual} into Go struct field ObjectMeta.#{field} of type #{expected}")
          end
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
          return [] if [Negotiation::PROTOBUF_TYPE, Negotiation::CBOR_TYPE,
                        Schema::Codec::KubernetesCBOR::APPLY_CONTENT_TYPE].include?(media_type)

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

        def request_body(request, resource: nil)
          body = request.body
          media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
          unless request.method == "PATCH"
            supported = resource&.custom? ? [Negotiation::JSON_TYPE, Negotiation::YAML_TYPE] : Negotiation::STANDARD_TYPES
            supported = [*supported, Negotiation::CBOR_TYPE] if feature_gate_enabled?("CBORServingAndStorage")
            media_type = Negotiation.negotiate_input(media_type, supported: supported)
          end
          if cbor_request_media_type?(media_type)
            allowed = media_type == Negotiation::CBOR_TYPE ||
                      (request.method == "PATCH" && media_type == Schema::Codec::KubernetesCBOR::APPLY_CONTENT_TYPE)
            unless allowed && feature_gate_enabled?("CBORServingAndStorage")
              raise Status::UnsupportedMediaType.new("unsupported request content type #{media_type.inspect}")
            end
            return decode_cbor_body(body) if body.is_a?(String)
          end
          return {} if body.nil?
          return {} if body.is_a?(String) && body.empty?
          return body unless body.is_a?(String)

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
          if media_type == Negotiation::PROTOBUF_TYPE
            decode_protobuf_body(body)
          elsif media_type.include?("yaml")
            YAML.safe_load(body, permitted_classes: [], aliases: false) || {}
          else
            JSON.parse(body)
          end
        end

        def cbor_request_media_type?(media_type)
          [Negotiation::CBOR_TYPE, Negotiation::CBOR_SEQUENCE_TYPE, Schema::Codec::KubernetesCBOR::APPLY_CONTENT_TYPE].include?(media_type)
        end

        def decode_cbor_body(body)
          Schema::Codec::KubernetesCBOR.decode(body)
        rescue Schema::Codec::Error => error
          raise Status::BadRequest.new("request body is not valid Kubernetes CBOR: #{error.message}")
        end

        # Kubernetes protobuf bodies arrive as the runtime.Unknown envelope that
        # typed client-go clients send; decoding yields the same JSON-shaped
        # object the rest of the server works with.
        def decode_protobuf_body(body)
          protobuf_codec.decode(body.b)
        rescue Schema::Codec::KubernetesProtobuf::Error, Schema::Codec::ParseError => error
          raise Status::BadRequest.new("request body is not valid Kubernetes protobuf: #{error.message}")
        end

        # The core apiserver, apiextensions and aggregator each decode into
        # their own scheme. An unregistered GVK fails before field validation.
        BUILTIN_SCHEMES = {
          "apiextensions.k8s.io" => "pkg/apiserver/apiserver.go:55",
          "apiregistration.k8s.io" => "pkg/apiserver/scheme/scheme.go:28"
        }.freeze

        def reject_mismatched_builtin!(object, identity)
          api_version = object.fetch("apiVersion").to_s
          group, _, version = api_version.rpartition("/")
          kind = object.fetch("kind").to_s
          expected = identity.fetch(:kind)
          expected_version = identity.fetch(:api_version)
          target_group = expected_version.rpartition("/").first
          same_scheme = BUILTIN_SCHEMES[group] == BUILTIN_SCHEMES[target_group]
          known = same_scheme && protobuf_codec.supports?(api_version: api_version, kind: kind)
          if known && kind == expected && group == target_group
            raise Status::BadRequest.new("the API version in the data (#{api_version}) does not match the expected API version (#{expected_version})")
          end

          reason = if known
                     package = target_group.empty? ? "core" : target_group.split(".").first
                     "converting (#{version}.#{kind}) to (#{package}.#{expected}): unknown conversion"
                   else
                     scheme = BUILTIN_SCHEMES.fetch(target_group, "pkg/api/legacyscheme/scheme.go:30")
                     "no kind #{kind.inspect} is registered for version #{api_version.inspect} in scheme #{scheme.inspect}"
                   end
          raise Status::BadRequest.new("#{kind} in version #{version.inspect} cannot be handled as a #{expected}: #{reason}")
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

        def storage_namespace(route, operation:)
          return :cluster if route.resource.cluster_scoped?
          return route.namespace unless route.namespace.nil?
          return :all if %i[list watch].include?(operation)

          raise Status::Invalid.new("namespace is required for #{operation} on namespaced resources")
        end

        def check_update_name!(object, route)
          name = metadata_value(object, "name").to_s
          raise Status::BadRequest.new("the name of the object (#{route.name} based on URL) was undeterminable: name must be provided") if name.empty?
          return if name == route.name

          raise Status::BadRequest.new("the name of the object (#{name}) does not match the name on the URL (#{route.name})")
        end

        def match_request_namespace!(object, route)
          metadata = object["metadata"] ||= {}
          raise Status::BadRequest.new("metadata must be an object") unless metadata.is_a?(Hash)

          if route.resource.cluster_scoped?
            metadata.delete("namespace")
          elsif metadata["namespace"].to_s.empty?
            metadata["namespace"] = route.namespace
          elsif metadata["namespace"] != route.namespace
            raise Status::BadRequest.new("the namespace of the provided object does not match the namespace sent on the request")
          end
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
