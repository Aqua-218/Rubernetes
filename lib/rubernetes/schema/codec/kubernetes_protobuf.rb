# frozen_string_literal: true

require "base64"
require "json"
require "time"

require_relative "../codec"
require_relative "proto_descriptor"
require_relative "kubernetes_pointer_fields"
require_relative "../quantity"
require_relative "../go_duration"

module Rubernetes
  module Schema
    class Codec
      # Converts the JSON-shaped Hash representation used throughout the API
      # server to and from the Kubernetes protobuf wire format
      # (application/vnd.kubernetes.protobuf).
      #
      # The generic descriptor codec knows field numbers and wire types.  This
      # layer adds the Go-side semantics that make the bytes interoperable
      # with client-go: the runtime.Unknown envelope, the hand-written
      # marshalers for Time/Quantity/IntOrString/Duration/RawExtension/
      # FieldsV1/apiextensions JSON, base64 bytes, embedded (inline) structs,
      # and the gogo rule that every non-pointer field is written to the wire
      # while encoding/json hides its zero value under `omitempty`.
      class KubernetesProtobuf
        CONTENT_TYPE = "application/vnd.kubernetes.protobuf"
        WATCH_CONTENT_TYPE = "application/vnd.kubernetes.protobuf;stream=watch"
        DEFAULT_DESCRIPTOR_ROOT = File.expand_path("../../../../schema/kubernetes/v1.36.2/protobuf", __dir__).freeze
        META_PACKAGE = "k8s.io.apimachinery.pkg.apis.meta.v1"
        TIME = "#{META_PACKAGE}.Time".freeze
        MICRO_TIME = "#{META_PACKAGE}.MicroTime".freeze
        DURATION = "#{META_PACKAGE}.Duration".freeze
        FIELDS_V1 = "#{META_PACKAGE}.FieldsV1".freeze
        WATCH_EVENT = "#{META_PACKAGE}.WatchEvent".freeze
        # metav1.Verbs is `type Verbs []string` with a custom marshaler: the
        # wire form is a message holding one repeated string field, while JSON
        # is a plain array.  Encoding it as an ordinary message rejects the
        # array and makes every protobuf discovery request fail.
        VERBS = "#{META_PACKAGE}.Verbs".freeze
        # authentication/authorization ExtraValue is `type ExtraValue []string`
        # with the same shape as metav1.Verbs: the wire form is a message
        # holding one repeated string field, while JSON is a plain array.
        # Encoding it as an ordinary message rejects the array, so a
        # TokenReview or SubjectAccessReview whose user carries any `extra`
        # value failed with HTTP 500 for every protobuf client -- which is
        # every client-go client, and therefore the whole e2e suite.
        EXTRA_VALUES = [
          "k8s.io.api.authentication.v1.ExtraValue",
          "k8s.io.api.authentication.v1beta1.ExtraValue",
          "k8s.io.api.authentication.v1alpha1.ExtraValue",
          "k8s.io.api.authorization.v1.ExtraValue",
          "k8s.io.api.authorization.v1beta1.ExtraValue",
          "k8s.io.api.certificates.v1.ExtraValue",
          "k8s.io.api.certificates.v1alpha1.ExtraValue",
          "k8s.io.api.certificates.v1beta1.ExtraValue"
        ].freeze
        STATUS = "#{META_PACKAGE}.Status".freeze
        QUANTITY = "k8s.io.apimachinery.pkg.api.resource.Quantity"
        INT_OR_STRING = "k8s.io.apimachinery.pkg.util.intstr.IntOrString"
        RAW_EXTENSION = "k8s.io.apimachinery.pkg.runtime.RawExtension"
        APIEXTENSIONS_PACKAGE = "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1"
        APIEXTENSIONS_JSON = "#{APIEXTENSIONS_PACKAGE}.JSON".freeze
        JSON_SCHEMA_PROPS = "#{APIEXTENSIONS_PACKAGE}.JSONSchemaProps".freeze
        JSON_SCHEMA_OR_BOOL = "#{APIEXTENSIONS_PACKAGE}.JSONSchemaPropsOrBool".freeze
        JSON_SCHEMA_OR_ARRAY = "#{APIEXTENSIONS_PACKAGE}.JSONSchemaPropsOrArray".freeze
        # Values truncate_times hands back as they are: MicroTime keeps its
        # microseconds and the rest are opaque to the schema walk.
        TRUNCATE_OPAQUE = [MICRO_TIME, QUANTITY, INT_OR_STRING, DURATION, RAW_EXTENSION, FIELDS_V1, APIEXTENSIONS_JSON].freeze
        JSON_SCHEMA_OR_STRING_ARRAY = "#{APIEXTENSIONS_PACKAGE}.JSONSchemaPropsOrStringArray".freeze
        # JSONSchemaProps keeps JSON Schema spellings that are not valid proto
        # identifiers.
        JSON_SCHEMA_KEY_OVERRIDES = {"$ref" => "ref", "$schema" => "schema"}.freeze
        JSON_SCHEMA_FIELD_OVERRIDES = JSON_SCHEMA_KEY_OVERRIDES.invert.freeze
        # Kinds served from the core "v1" apiVersion whose messages live in the
        # apimachinery meta package rather than k8s.io.api.core.v1.
        META_KINDS = %w[
          Status WatchEvent APIGroup APIGroupList APIResourceList APIVersions
          PartialObjectMetadata PartialObjectMetadataList DeleteOptions ListOptions
          GetOptions CreateOptions UpdateOptions PatchOptions
        ].freeze
        GROUP_PACKAGES = {
          "apiextensions.k8s.io" => "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions",
          "apiregistration.k8s.io" => "k8s.io.kube_aggregator.pkg.apis.apiregistration",
          "meta.k8s.io" => "k8s.io.apimachinery.pkg.apis.meta",
          "internal.apiserver.k8s.io" => "k8s.io.api.apiserverinternal"
        }.freeze
        FRAME_LENGTH_BYTES = 4
        MAX_FRAME_BYTES = Codec::DEFAULT_MAX_BYTES
        INTEGER_TYPES = %i[int32 int64 uint32 uint64 sint32 sint64 fixed32 fixed64 sfixed32 sfixed64].freeze

        class Error < Codec::Error; end
        # The GVK has no generated protobuf message (custom resources, Table).
        class UnsupportedKind < Error; end
        class DecodeError < Codec::ParseError; end
        class EncodeError < Codec::EncodeError; end

        attr_reader :descriptor_root

        def initialize(descriptor_root: DEFAULT_DESCRIPTOR_ROOT, registry: nil)
          @descriptor_root = descriptor_root
          @registry = registry
          @mutex = Mutex.new
        end

        # Parsing 65 descriptor files takes a noticeable fraction of a second;
        # servers that never see a protobuf client should not pay for it.
        def registry
          @mutex.synchronize do
            @registry ||= ProtoDescriptor::Registry.load(@descriptor_root)
          end
        end

        def supports?(api_version:, kind:)
          !descriptor_for(api_version: api_version, kind: kind).nil?
        end

        def descriptor_for(api_version:, kind:)
          group, version = split_api_version(api_version)
          return nil if version.to_s.empty? || kind.to_s.empty?

          # metav1.AddToGroupVersion registers the option kinds, Status and
          # WatchEvent in EVERY group version, and client-go types a
          # DeleteOptions body with the resource's group ("apps/v1",
          # Kind=DeleteOptions).  Knowing them only under "v1" made every
          # protobuf DELETE body undecodable, so propagationPolicy=Orphan was
          # silently read as the default and the garbage collector removed
          # the ReplicaSet the spec expected to keep.
          if META_KINDS.include?(kind.to_s)
            return registry.resolve("#{META_PACKAGE}.#{kind}")
          end
          package = GROUP_PACKAGES[group]
          return registry.resolve("#{package}.#{version}.#{kind}") if package
          return registry.resolve_gvk(group: "", version: version, kind: kind.to_s) if group.empty?

          # k8s.io/api packages are named after the first label of the API
          # group (events.k8s.io -> k8s.io.api.events.v1).
          registry.resolve("k8s.io.api.#{group.split(".").first}.#{version}.#{kind}")
        end

        # metav1.Time is second precision on BOTH wires upstream: MarshalJSON
        # writes RFC3339 and ProtoTime drops the nanos ("our JSON only handled
        # seconds, so ... unexpected field mutation, which fails various
        # validation and equality code").  Our protobuf already dropped them,
        # but objects were stored and served as JSON with microseconds, so a
        # protobuf client and a JSON client read two different timestamps for
        # the same field and could never agree:
        # "[sig-node] Pod InPlace Resize Container resize pod via the replace
        # endpoint" compares the Pod from the typed (protobuf) client with the
        # Pod from the dynamic (JSON) client and waited out its 300 s.  This
        # returns the object with every metav1.Time field at second precision
        # and MicroTime and every other field untouched; an object the
        # descriptors do not cover comes back unchanged.
        def truncate_times(object)
          return object unless object.is_a?(Hash)

          # Already truncated by #truncated_frozen: nothing to do.
          return object if object.frozen? && TRUNCATED.key?(object)

          descriptor = descriptor_for(api_version: string_value(object, "apiVersion"), kind: string_value(object, "kind"))
          return object if descriptor.nil?

          truncate_message(descriptor, object)
        rescue StandardError
          object
        end

        # #truncate_times, frozen and remembered as truncated, so the same
        # object is not walked again on its way into the store (an update
        # truncates for its no-op check and then again in convert_in).
        def truncated_frozen(object)
          result = DeepFreeze.call(truncate_times(object))
          TRUNCATED[result] = true if result.is_a?(Hash)
          result
        end

        TRUNCATED = ObjectSpace::WeakMap.new

        # Full Kubernetes wire form: k8s\0 + runtime.Unknown{typeMeta, raw}.
        def encode(object)
          object = object.to_h if !object.is_a?(Hash) && object.respond_to?(:to_h)
          raise EncodeError, "protobuf encoding requires an object" unless object.is_a?(Hash)

          # A stored object is frozen all the way down and is encoded again
          # and again: the response to its write, every GET, the event for
          # each protobuf watcher.  Pure-Ruby encoding costs ~1.8 ms for a
          # Pod, so an immutable object's bytes are remembered by identity.
          immutable = deep_frozen?(object)
          if immutable && (known = ENCODED[object])
            return known
          end

          bytes = encode_fresh(object)
          ENCODED[object] = bytes.freeze if immutable
          bytes
        end

        ENCODED = ObjectSpace::WeakMap.new

        def deep_frozen?(object)
          return false unless object.frozen?

          (defined?(Rubernetes::Storage::MemoryStoreSupport) && Rubernetes::Storage::MemoryStoreSupport.deep_frozen?(object)) ||
            DeepFreeze.deep_frozen?(object)
        end

        def encode_fresh(object)
          api_version = string_value(object, "apiVersion")
          kind = string_value(object, "kind")
          descriptor = descriptor_for(api_version: api_version, kind: kind)
          if descriptor.nil?
            raise UnsupportedKind, "#{api_version.inspect}, Kind=#{kind.inspect} has no protobuf representation"
          end

          raw = encode_message(descriptor, object)
          # kube-apiserver leaves runtime.Unknown.contentType/contentEncoding
          # empty; the HTTP Content-Type header carries that information.
          Protobuf.encode_envelope(
            raw: raw,
            content_type: "",
            content_encoding: "",
            type_meta: {api_version: api_version, kind: kind}
          )
        end

        # Decodes a k8s\0 envelope into the JSON-shaped Hash.  +expected+ is
        # the route GVK used when the client omitted TypeMeta.
        def decode(bytes, expected: nil)
          Codec.validate_body!(bytes, MAX_FRAME_BYTES)
          raise DecodeError, "empty data" if bytes.empty?
          unless bytes.start_with?(Protobuf::MAGIC)
            raise DecodeError, "provided data does not appear to be a protobuf message, expected prefix [107 56 115 0]"
          end
          raise DecodeError, "empty body" if bytes.bytesize == Protobuf::MAGIC.bytesize

          envelope = Protobuf.decode_envelope(bytes)
          type_meta = envelope.type_meta || {}
          api_version = type_meta[:api_version].to_s
          kind = type_meta[:kind].to_s
          if expected
            api_version = expected.fetch(:api_version).to_s if api_version.empty?
            kind = expected.fetch(:kind).to_s if kind.empty?
          end
          descriptor = descriptor_for(api_version: api_version, kind: kind)
          if descriptor.nil?
            raise UnsupportedKind, "no kind #{kind.inspect} is registered for version #{api_version.inspect} in scheme"
          end

          result = {"kind" => kind, "apiVersion" => api_version}
          result.merge!(decode_message(descriptor, envelope.raw))
          result
        rescue Codec::ParseError => error
          raise DecodeError, error.message
        end

        # A watch frame is the bare (unprefixed) WatchEvent whose object is the
        # embedded, fully prefixed encoding of the event object.
        def encode_watch_event(type, object)
          descriptor = registry.resolve(WATCH_EVENT)
          payload = {
            "type" => type.to_s,
            "object" => {"raw" => encode(object)}
          }
          encode_message(descriptor, payload, embedded_raw: true)
        end

        def frame(bytes)
          raise EncodeError, "watch frame exceeds #{MAX_FRAME_BYTES} bytes" if bytes.bytesize > MAX_FRAME_BYTES

          [bytes.bytesize].pack("N") + bytes
        end

        def encode_watch_frame(type, object)
          frame(encode_watch_event(type, object))
        end

        # Splits a length-delimited stream into decoded {"type","object"} events.
        def decode_watch_frames(bytes, expected: nil)
          events = []
          offset = 0
          while offset < bytes.bytesize
            raise DecodeError, "truncated watch frame header" if offset + FRAME_LENGTH_BYTES > bytes.bytesize

            length = bytes.byteslice(offset, FRAME_LENGTH_BYTES).unpack1("N")
            offset += FRAME_LENGTH_BYTES
            raise DecodeError, "truncated watch frame" if offset + length > bytes.bytesize

            events << decode_watch_event(bytes.byteslice(offset, length), expected: expected)
            offset += length
          end
          events
        end

        def decode_watch_event(bytes, expected: nil)
          fields = Protobuf.parse_fields(bytes)
          event = {"type" => "", "object" => nil}
          fields.each do |field|
            case field[:number]
            when 1 then event["type"] = utf8(field[:value])
            when 2
              raw = Protobuf.parse_fields(field[:value]).find { |inner| inner[:number] == 1 }
              event["object"] = raw ? decode_raw_extension(raw[:value], expected: expected) : nil
            end
          end
          event
        rescue Codec::ParseError => error
          raise DecodeError, "#{WATCH_EVENT}: #{error.message}"
        end

        # Encodes a JSON-shaped Hash as the bare message (no envelope).
        def encode_message(descriptor, object, embedded_raw: false)
          descriptor = resolve!(descriptor)
          remaining = {}
          object.each { |key, value| remaining[key.to_s] = value }
          values = {}
          descriptor.fields.each do |field|
            next unless inline_field?(descriptor, field)

            # An embedded struct owns the parent keys that belong to its own
            # fields; encoding/json flattened them into the parent object.
            owned = inline_keys(registry.type_for(field))
            values[field] = remaining.select { |key, _| owned.include?(key) }
            remaining.reject! { |key, _| owned.include?(key) }
          end
          remaining.each do |key, value|
            field = field_for_key(descriptor, key)
            # A typed Go object cannot carry fields outside its struct (TypeMeta
            # travels in the envelope), so the same information is dropped here.
            next if field.nil?
            raise EncodeError, "field #{key.inspect} was supplied more than once" if values.key?(field)

            values[field] = value
          end
          # gogo marshalers emit fields in field-number order; matching that
          # keeps the bytes comparable with kube-apiserver output.
          output = +"".b
          descriptor.fields.each do |field|
            encoded = if values.key?(field)
                        encode_field(descriptor, field, values.fetch(field), embedded_raw: embedded_raw)
                      else
                        encode_absent(descriptor, field)
                      end
            output << encoded unless encoded.nil?
          end
          output
        end

        def decode_message(descriptor, bytes)
          descriptor = resolve!(descriptor)
          fields = Protobuf.parse_fields(bytes)
          result = {}
          fields.each do |wire|
            field = descriptor.fields_by_number[wire[:number]]
            next if field.nil?

            if field.map?
              key, value = decode_map_entry(field, wire[:value])
              result[json_key(descriptor, field)] ||= {}
              result[json_key(descriptor, field)][key] = value
            elsif field.repeated?
              key = json_key(descriptor, field)
              result[key] ||= []
              if packed_wire?(field, wire)
                result[key].concat(decode_packed(field, wire[:value]))
              else
                result[key] << decode_value(field, wire)
              end
            elsif inline_field?(descriptor, field)
              nested = decode_value(field, wire)
              result.merge!(nested) if nested.is_a?(Hash)
            else
              value = decode_value(field, wire)
              next if prune_zero?(descriptor, field, value)
              next if value.nil? && KubernetesPointerFields.omitzero?(descriptor.full_name, json_key(descriptor, field))

              result[json_key(descriptor, field)] = value
            end
          end
          # A nil Go slice or map serialized without omitempty is visible as
          # JSON null (for example Role.rules); it never occupies the wire.
          descriptor.fields.each do |field|
            next unless field.repeated? || field.map?

            key = json_key(descriptor, field)
            next if result.key?(key)

            result[key] = nil if KubernetesPointerFields.keep_zero?(descriptor.full_name, key)
          end
          result
        end

        private

        def resolve!(descriptor)
          return descriptor if descriptor.is_a?(ProtoDescriptor::MessageDescriptor)

          registry.fetch(descriptor)
        end

        def split_api_version(api_version)
          parts = api_version.to_s.split("/", 2)
          parts.length == 2 ? parts : ["", parts.first.to_s]
        end

        def string_value(object, key)
          value = object[key] || object[key.to_sym]
          value.nil? ? "" : value.to_s
        end

        def json_schema_props?(descriptor)
          descriptor.full_name == JSON_SCHEMA_PROPS
        end

        # JSON key -> descriptor field, honouring the JSON Schema spellings.
        # gogo generated a handful of Kubernetes messages from the Go *field*
        # name instead of its JSON tag, so the proto field is capitalised
        # while the wire JSON is not: Validation.Expression is "expression"
        # and ValidatingWebhookConfiguration.Webhooks is "webhooks".  Reading
        # them by the proto spelling dropped the field silently -- a
        # ValidatingAdmissionPolicy arrived with no expression and a webhook
        # configuration with no webhooks.  v1.DaemonEndpoint.Port is the one
        # field whose JSON name really is capitalised (`json:"Port"`).
        CAPITALISED_JSON_FIELDS = {"k8s.io.api.core.v1.DaemonEndpoint" => %w[Port].freeze}.freeze

        # KubernetesPointerFields.inline? for a field of its message, looked
        # up once per field instead of by message name on every value.
        def inline_field?(descriptor, field)
          cache = (@inline_fields ||= {}.compare_by_identity)
          return cache[field] if cache.key?(field)

          cache[field] = KubernetesPointerFields.inline?(descriptor.full_name, field.name)
        end

        # A field's JSON name is fixed: computed once per (message, field).
        def kubernetes_json_name(descriptor, field)
          (@json_names ||= {}.compare_by_identity)[field] ||= compute_kubernetes_json_name(descriptor, field)
        end

        def compute_kubernetes_json_name(descriptor, field)
          name = field.name
          return field.json_name unless name[0] && name[0] == name[0].upcase && name[0] =~ /[A-Za-z]/
          return field.json_name if CAPITALISED_JSON_FIELDS.fetch(descriptor.full_name, []).include?(name)

          (name[0].downcase + name[1..].to_s).freeze
        end

        def field_for_key(descriptor, key)
          field = descriptor.fields_by_json_name[key] || descriptor.fields_by_name[key]
          field ||= descriptor.fields.find { |candidate| kubernetes_json_name(descriptor, candidate) == key }
          return field if field || !json_schema_props?(descriptor)

          proto_name = JSON_SCHEMA_KEY_OVERRIDES[key]
          if proto_name.nil? && key.start_with?("x-kubernetes-")
            proto_name = key.split("-").each_with_index.map { |part, index| index.zero? ? part : part.capitalize }.join
          end
          proto_name && descriptor.fields_by_name[proto_name]
        end

        def json_key(descriptor, field)
          return kubernetes_json_name(descriptor, field) unless json_schema_props?(descriptor)

          override = JSON_SCHEMA_FIELD_OVERRIDES[field.name]
          return override if override
          return field.json_name unless field.name.start_with?("xKubernetes")

          field.name.gsub(/([A-Z])/) { "-#{Regexp.last_match(1).downcase}" }
        end

        def inline_keys(type)
          keys = []
          type.fields.each do |field|
            if inline_field?(type, field)
              keys.concat(inline_keys(registry.type_for(field)))
            else
              keys << json_key(type, field)
              keys << field.name
            end
          end
          keys
        end

        def encode_field(parent, field, value, embedded_raw: false)
          if field.map?
            return nil unless value.is_a?(Hash)

            return encode_map(field, value)
          end
          if field.repeated?
            return nil unless value.is_a?(Array)

            return encode_repeated(field, value)
          end
          if field.message?
            return encode_message_field(parent, field, value, embedded_raw: embedded_raw)
          end
          return encode_absent(parent, field) if value.nil?

          Protobuf.encode_field(field.number, scalar_for_wire(field.type, value, parent, field), type: field.type)
        end

        # Non-pointer Go fields are always marshaled, so an absent JSON value
        # still occupies the wire with its zero form.
        # What an absent field encodes to depends only on the field (and its
        # message): computed once.  A zero message is itself a full encode.
        def encode_absent(parent, field)
          cache = (@absent_encodings ||= {}.compare_by_identity)
          return cache[field] || nil if cache.key?(field)

          encoded = encode_absent_uncached(parent, field)
          cache[field] = encoded&.dup&.freeze || false
          cache[field] || nil
        end

        def encode_absent_uncached(parent, field)
          return nil if field.map? || field.repeated?
          return nil if field.type == :bytes
          return nil if KubernetesPointerFields.pointer?(parent.full_name, json_key(parent, field))

          if field.message?
            type = registry.type_for(field)
            return Protobuf.encode_field(field.number, encode_zero_message(type), type: :message)
          end
          Protobuf.encode_field(field.number, zero_scalar(field.type), type: field.type)
        end

        def encode_zero_message(type)
          case type.full_name
          when TIME, MICRO_TIME, RAW_EXTENSION, FIELDS_V1, APIEXTENSIONS_JSON then "".b
          when QUANTITY then Protobuf.encode_field(1, "0", type: :string)
          when INT_OR_STRING then encode_int_or_string(0)
          when DURATION then Protobuf.encode_field(1, 0, type: :int64)
          when JSON_SCHEMA_OR_BOOL then Protobuf.encode_field(1, false, type: :bool)
          when JSON_SCHEMA_OR_ARRAY, JSON_SCHEMA_OR_STRING_ARRAY then "".b
          else encode_message(type, {})
          end
        end

        def zero_scalar(type)
          case type
          when :string then ""
          when :bool then false
          when :double, :float then 0.0
          else 0
          end
        end

        def encode_map(field, value)
          entries = value.map do |key, item|
            key_string = key.to_s
            key_bytes = Protobuf.encode_field(1, key_string, type: field.key_type)
            value_bytes = if field.value_type_kind == :scalar
                            Protobuf.encode_field(2, scalar_for_wire(field.value_type, item, nil, field), type: field.value_type)
                          else
                            Protobuf.encode_field(2, encode_special_or_message(registry.type_for(field), item), type: :message)
                          end
            [key_string, key_bytes + value_bytes]
          end
          entries.sort_by!(&:first)
          entries.map { |_key, entry| Protobuf.encode_field(field.number, entry, type: :message) }.join.b
        end

        def encode_repeated(field, values)
          if field.message?
            type = registry.type_for(field)
            return values.map do |item|
              Protobuf.encode_field(field.number, encode_special_or_message(type, item), type: :message)
            end.join.b
          end
          if field.packed? && ProtoDescriptor::VARINT_TYPES.include?(field.type)
            return Protobuf.encode_field(field.number, values.map { |item| scalar_for_wire(field.type, item, nil, field) },
                                         type: field.type, packed: true)
          end
          values.map do |item|
            Protobuf.encode_field(field.number, scalar_for_wire(field.type, item, nil, field), type: field.type)
          end.join.b
        end

        def encode_message_field(parent, field, value, embedded_raw: false)
          type = registry.type_for(field)
          name = type.full_name
          # JSON null for a struct field is the zero struct (metav1.Time renders
          # as null); a nil pointer is omitted entirely.
          return encode_absent(parent, field) if value.nil?

          encoded = if name == RAW_EXTENSION && embedded_raw && value.is_a?(Hash) && value.key?("raw")
                      Protobuf.encode_field(1, value.fetch("raw").b, type: :bytes)
                    else
                      encode_special_or_message(type, value)
                    end
          Protobuf.encode_field(field.number, encoded, type: :message)
        end

        def encode_special_or_message(type, value)
          case type.full_name
          when TIME then encode_time(value, micro: false)
          when MICRO_TIME then encode_time(value, micro: true)
          when QUANTITY then Protobuf.encode_field(1, quantity_string(value), type: :string)
          when INT_OR_STRING then encode_int_or_string(value)
          when DURATION then Protobuf.encode_field(1, duration_nanos(value), type: :int64)
          when RAW_EXTENSION, FIELDS_V1, APIEXTENSIONS_JSON
            value.nil? ? "".b : Protobuf.encode_field(1, raw_json(value), type: :bytes)
          when JSON_SCHEMA_OR_BOOL
            if value.is_a?(Hash)
              Protobuf.encode_field(1, true, type: :bool) +
                Protobuf.encode_field(2, encode_message(registry.resolve(JSON_SCHEMA_PROPS), value), type: :message)
            else
              Protobuf.encode_field(1, value == true, type: :bool)
            end
          when JSON_SCHEMA_OR_ARRAY
            schema = registry.resolve(JSON_SCHEMA_PROPS)
            if value.is_a?(Array)
              value.map { |item| Protobuf.encode_field(2, encode_message(schema, item), type: :message) }.join.b
            else
              Protobuf.encode_field(1, encode_message(schema, value), type: :message)
            end
          when JSON_SCHEMA_OR_STRING_ARRAY
            if value.is_a?(Array)
              value.map { |item| Protobuf.encode_field(2, item.to_s, type: :string) }.join.b
            else
              Protobuf.encode_field(1, encode_message(registry.resolve(JSON_SCHEMA_PROPS), value), type: :message)
            end
          when VERBS
            Array(value).map { |item| Protobuf.encode_field(1, item.to_s, type: :string) }.join.b
          when *EXTRA_VALUES
            Array(value).map { |item| Protobuf.encode_field(1, item.to_s, type: :string) }.join.b
          else
            raise EncodeError, "expected an object for #{type.full_name}, got #{value.class}" unless value.is_a?(Hash)

            encode_message(type, value)
          end
        end

        def truncate_message(descriptor, object)
          descriptor = resolve!(descriptor)
          return object unless time_bearing?(descriptor)

          result = {}
          object.each { |key, value| result[key] = value }
          descriptor.fields.each do |field|
            next unless inline_field?(descriptor, field)

            type = registry.type_for(field)
            next unless time_bearing?(type)

            owned = inline_keys(type)
            embedded = result.select { |key, _| owned.include?(key.to_s) }
            result.merge!(truncate_message(type, embedded)) unless embedded.empty?
          end
          result.each_key.to_a.each do |key|
            field = field_for_key(descriptor, key.to_s)
            next if field.nil?

            result[key] = truncate_field(field, result[key])
          end
          result
        end

        def truncate_field(field, value)
          return value if value.nil?

          if field.map?
            return value unless value.is_a?(Hash) && field.value_type_kind != :scalar

            type = registry.type_for(field)
            return value unless time_bearing?(type)

            return value.transform_values { |item| truncate_typed(type, item) }
          end
          return value unless field.message?

          type = registry.type_for(field)
          return value unless time_bearing?(type)

          if field.repeated?
            return value unless value.is_a?(Array)

            return value.map { |item| truncate_typed(type, item) }
          end
          truncate_typed(type, value)
        end

        def truncate_typed(type, value)
          case type.full_name
          when TIME then second_precision(value)
          when *TRUNCATE_OPAQUE then value
          else value.is_a?(Hash) ? truncate_message(type, value) : value
          end
        end

        # Whether a message can hold a metav1.Time anywhere below it.  Most of
        # an object cannot -- a PodSpec, every container, every volume -- and
        # walking all of it made truncate_times 40% of a Pod update's CPU (the
        # no-op check and the store each truncate).  Memoised per root; each
        # answer is one exact depth-first search over the types it reaches.
        def time_bearing?(type)
          return false unless type.is_a?(ProtoDescriptor::MessageDescriptor)

          cache = (@time_bearing ||= {})
          cached = cache[type.full_name]
          return cached unless cached.nil?

          cache[type.full_name] = reaches_time?(type, {})
        end

        def reaches_time?(type, seen)
          return true if type.full_name == TIME
          return false if TRUNCATE_OPAQUE.include?(type.full_name) || seen[type.full_name]

          seen[type.full_name] = true
          type.fields.any? do |field|
            next false unless field.message? || (field.map? && field.value_type_kind != :scalar)

            nested = registry.type_for(field)
            nested.is_a?(ProtoDescriptor::MessageDescriptor) && reaches_time?(nested, seen)
          end
        end

        def second_precision(value)
          return value unless value.is_a?(String) && value.include?(".")

          Time.iso8601(value).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        rescue ArgumentError
          value
        end

        def encode_time(value, micro:)
          return "".b if value.nil? || value.to_s.empty?

          time = value.is_a?(Time) ? value : Time.iso8601(value.to_s)
          output = Protobuf.encode_field(1, time.to_i, type: :int64)
          nanos = micro ? (time.nsec / 1_000) * 1_000 : 0
          output << Protobuf.encode_field(2, nanos, type: :int32)
          output
        rescue ArgumentError => error
          raise EncodeError, "invalid time #{value.inspect}: #{error.message}"
        end

        def quantity_string(value)
          Quantity.from_json(value).to_s
        rescue Quantity::ParseError => error
          raise EncodeError, error.message
        end

        def encode_int_or_string(value)
          case value
          when Integer
            Protobuf.encode_field(1, 0, type: :int64) + Protobuf.encode_field(2, value, type: :int32) +
              Protobuf.encode_field(3, "", type: :string)
          when String
            Protobuf.encode_field(1, 1, type: :int64) + Protobuf.encode_field(2, 0, type: :int32) +
              Protobuf.encode_field(3, value, type: :string)
          else
            raise EncodeError, "IntOrString must be an Integer or String, got #{value.class}"
          end
        end

        def duration_nanos(value)
          return Integer(value) if value.is_a?(Integer)

          GoDuration.parse(value.to_s)
        rescue GoDuration::ParseError => error
          raise EncodeError, error.message
        end

        def raw_json(value)
          ::JSON.generate(value).b
        end

        def scalar_for_wire(type, value, parent, field)
          case type
          when :string
            raise EncodeError, "field #{field.json_name} must be a string, got #{value.class}" unless value.is_a?(String)

            string = value.dup.force_encoding(Encoding::UTF_8)
            raise EncodeError, "field #{field.json_name} is not valid UTF-8" unless string.valid_encoding?

            string
          when :bytes
            raise EncodeError, "field #{field.json_name} must be a base64 string, got #{value.class}" unless value.is_a?(String)

            begin
              Base64.strict_decode64(value)
            rescue ArgumentError
              raise EncodeError, "illegal base64 data in field #{field.json_name}"
            end
          when :bool
            raise EncodeError, "field #{field.json_name} must be a boolean" unless value == true || value == false

            value
          when *INTEGER_TYPES
            raise EncodeError, "field #{field.json_name} must be an integer, got #{value.class}" unless value.is_a?(Integer)

            value
          when :double, :float
            raise EncodeError, "field #{field.json_name} must be a number, got #{value.class}" unless value.is_a?(Numeric)

            Float(value)
          else
            raise EncodeError, "unsupported scalar #{type.inspect} in #{parent&.full_name}.#{field.json_name}"
          end
        end

        # encoding/json `omitempty` semantics: a non-pointer Go scalar is always
        # on the wire, so its zero value carries no information unless the Go
        # tag keeps it; a pointer field's explicit zero is real data.
        def prune_zero?(descriptor, field, value)
          return false if field.message?
          return false unless zero_scalar?(value)
          return false if KubernetesPointerFields.pointer?(descriptor.full_name, json_key(descriptor, field))

          !KubernetesPointerFields.keep_zero?(descriptor.full_name, json_key(descriptor, field))
        end

        def zero_scalar?(value)
          value.nil? || value == 0 || value == 0.0 || value == false || value == ""
        end

        def decode_value(field, wire)
          if field.message?
            type = registry.type_for(field)
            expected = Protobuf::WIRE_LENGTH_DELIMITED
            unless wire[:wire_type] == expected
              raise DecodeError, "field #{field.json_name} has wire type #{wire[:wire_type]}, expected #{expected}"
            end

            return decode_special_or_message(type, wire[:value])
          end
          decode_scalar(field.type, wire, field.json_name)
        end

        def decode_special_or_message(type, bytes)
          case type.full_name
          when TIME then decode_time(bytes, micro: false)
          when MICRO_TIME then decode_time(bytes, micro: true)
          when QUANTITY
            string = single_field(bytes, 1)
            string ? utf8(string[:value]) : "0"
          when INT_OR_STRING then decode_int_or_string(bytes)
          when DURATION
            nanos = single_field(bytes, 1)
            GoDuration.format(nanos ? signed(nanos[:value], 64) : 0)
          when RAW_EXTENSION
            raw = single_field(bytes, 1)
            raw ? decode_raw_extension(raw[:value]) : nil
          when FIELDS_V1
            raw = single_field(bytes, 1)
            raw && !raw[:value].empty? ? parse_json(raw[:value]) : {}
          when APIEXTENSIONS_JSON
            raw = single_field(bytes, 1)
            raw && !raw[:value].empty? ? parse_json(raw[:value]) : nil
          when JSON_SCHEMA_OR_BOOL
            schema = single_field(bytes, 2)
            return decode_message(registry.resolve(JSON_SCHEMA_PROPS), schema[:value]) if schema

            allows = single_field(bytes, 1)
            allows ? allows[:value] == 1 : false
          when JSON_SCHEMA_OR_ARRAY
            props = registry.resolve(JSON_SCHEMA_PROPS)
            fields = Protobuf.parse_fields(bytes)
            items = fields.select { |field| field[:number] == 2 }
            return items.map { |item| decode_message(props, item[:value]) } unless items.empty?

            schema = fields.find { |field| field[:number] == 1 }
            schema ? decode_message(props, schema[:value]) : nil
          when JSON_SCHEMA_OR_STRING_ARRAY
            fields = Protobuf.parse_fields(bytes)
            items = fields.select { |field| field[:number] == 2 }
            return items.map { |item| utf8(item[:value]) } unless items.empty?

            schema = fields.find { |field| field[:number] == 1 }
            schema ? decode_message(registry.resolve(JSON_SCHEMA_PROPS), schema[:value]) : nil
          when VERBS, *EXTRA_VALUES
            Protobuf.parse_fields(bytes).select { |field| field[:number] == 1 }
                    .map { |field| utf8(field[:value]) }
          else
            decode_message(type, bytes)
          end
        end

        def single_field(bytes, number)
          Protobuf.parse_fields(bytes).find { |field| field[:number] == number }
        end

        def signed(value, bits)
          Protobuf.decode_signed_varint(Protobuf.encode_varint(value), bits: bits)
        end

        def decode_time(bytes, micro:)
          return nil if bytes.empty?

          seconds = 0
          nanos = 0
          Protobuf.parse_fields(bytes).each do |field|
            case field[:number]
            when 1 then seconds = signed(field[:value], 64)
            when 2 then nanos = signed(field[:value], 32)
            end
          end
          time = Time.at(seconds, micro ? (nanos / 1_000) * 1_000 : 0, :nanosecond).utc
          micro ? time.strftime("%Y-%m-%dT%H:%M:%S.%6NZ") : time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end

        def decode_int_or_string(bytes)
          type = 0
          int_value = 0
          string_value = ""
          Protobuf.parse_fields(bytes).each do |field|
            case field[:number]
            when 1 then type = field[:value]
            when 2 then int_value = signed(field[:value], 32)
            when 3 then string_value = utf8(field[:value])
            end
          end
          type == 1 ? string_value : int_value
        end

        # RawExtension carries either JSON bytes or a nested Kubernetes
        # protobuf envelope (watch events, embedded objects).
        def decode_raw_extension(bytes, expected: nil)
          return nil if bytes.empty?
          return decode(bytes, expected: expected) if bytes.start_with?(Protobuf::MAGIC)

          parse_json(bytes)
        end

        def parse_json(bytes)
          ::JSON.parse(bytes.dup.force_encoding(Encoding::UTF_8), create_additions: false,
                                                                 max_nesting: Codec::DEFAULT_MAX_DEPTH)
        rescue ::JSON::ParserError => error
          raise DecodeError, "embedded JSON is invalid: #{error.message}"
        end

        def decode_scalar(type, wire, json_name)
          value = wire[:value]
          case type
          when :string then utf8(value)
          when :bytes then Base64.strict_encode64(value)
          when :bool then value == 1
          when :int32 then signed(value, 32)
          when :int64 then signed(value, 64)
          when :uint32, :uint64, :fixed32, :fixed64 then value
          when :sint32 then Protobuf.zigzag_decode(value, bits: 32)
          when :sint64 then Protobuf.zigzag_decode(value, bits: 64)
          when :sfixed32 then [value].pack("V").unpack1("l<")
          when :sfixed64 then [value].pack("Q<").unpack1("q<")
          when :float then json_number(Protobuf.decode_float([value].pack("V")))
          when :double then json_number(Protobuf.decode_double([value].pack("Q<")))
          else
            raise DecodeError, "unsupported scalar #{type.inspect} for #{json_name}"
          end
        end

        # encoding/json renders an integral float64 without a fraction.
        def json_number(value)
          return value unless value.finite?

          value == value.floor && value.abs < (1 << 53) ? value.to_i : value
        end

        def utf8(bytes)
          string = bytes.dup.force_encoding(Encoding::UTF_8)
          raise DecodeError, "protobuf string is not valid UTF-8" unless string.valid_encoding?

          string
        end

        def packed_wire?(field, wire)
          field.repeated? && field.scalar? && ProtoDescriptor::VARINT_TYPES.include?(field.type) &&
            wire[:wire_type] == Protobuf::WIRE_LENGTH_DELIMITED
        end

        def decode_packed(field, bytes)
          values = []
          offset = 0
          while offset < bytes.bytesize
            raw, offset = Protobuf.decode_varint_with_offset(bytes, offset: offset)
            values << decode_scalar(field.type, {value: raw, wire_type: Protobuf::WIRE_VARINT}, field.json_name)
          end
          values
        end

        def decode_map_entry(field, bytes)
          key = ""
          value = field.value_type_kind == :scalar ? zero_scalar(field.value_type) : nil
          Protobuf.parse_fields(bytes).each do |wire|
            case wire[:number]
            when 1 then key = decode_scalar(field.key_type, wire, field.json_name)
            when 2
              value = if field.value_type_kind == :scalar
                        decode_scalar(field.value_type, wire, field.json_name)
                      else
                        decode_special_or_message(registry.type_for(field), wire[:value])
                      end
            end
          end
          [key, value]
        end
      end
    end
  end
end
