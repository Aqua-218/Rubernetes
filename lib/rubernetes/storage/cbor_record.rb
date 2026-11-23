# frozen_string_literal: true

require "base64"
require "delegate"
require_relative "../schema/codec/kubernetes_cbor"

module Rubernetes
  module Storage
    # Raft commands and snapshots carry an object as either the existing JSON
    # map or tagged Kubernetes CBOR bytes armored for the Raft JSON envelope.
    module CBORRecord
      # Keep the encoding of each MVCC version across snapshot compaction and
      # gate transitions. The record otherwise behaves like any API object.
      class Object < Hash; end

      # Only the object's stored value failed decoding. Retain its exact bytes
      # and trusted MVCC key while keeping the replica available for repair.
      class Unreadable < Hash
        attr_reader :encoded, :key

        def initialize(encoded, key)
          super()
          @encoded = encoded.dup.freeze
          @key = key.to_s.freeze
        end
      end

      class Watch < SimpleDelegator
        def initialize(stream, corrupt_deletion:)
          @corrupt_deletion = corrupt_deletion
          super(stream)
        end

        def next(timeout: nil)
          event = __getobj__.next(timeout: timeout)
          readable_event(event) if event
        end

        def each(timeout: nil)
          return enum_for(:each, timeout: timeout) unless block_given?

          __getobj__.each(timeout: timeout) do |event|
            decoded = readable_event(event)
            yield decoded
            break if decoded.type == "ERROR"
          end
          self
        end

        def to_a(timeout: :default)
          events = []
          __getobj__.to_a(timeout: timeout).each do |event|
            decoded = readable_event(event)
            events << decoded
            break if decoded.type == "ERROR"
          end
          events
        end
        alias events to_a

        def each_json_line(timeout: :default)
          return enum_for(:each_json_line, timeout: timeout) unless block_given?

          each(timeout: timeout == :default ? 0 : timeout) { |event| yield JSON.generate(event.to_h) << "\n" }
        end

        private

        def readable_event(event)
          object = event.object
          return event unless object.is_a?(Unreadable)

          unreadable_delete = @corrupt_deletion && event.type == "DELETED"
          close
          error = CorruptObject.new(object.key, resource_version: object.dig("metadata", "resourceVersion"))
          error.watch_event(event.revision, unreadable_delete: unreadable_delete)
        end
      end

      module_function

      def encode(object)
        Base64.strict_encode64(Schema::Codec::KubernetesCBOR.encode(object))
      end

      def decode(value)
        bytes = Base64.strict_decode64(value)
        raise Schema::Codec::ParseError, "missing self-described CBOR storage tag" unless bytes.start_with?(Schema::Codec::KubernetesCBOR::PREFIX)

        object = Schema::Codec::KubernetesCBOR.decode(bytes)
        raise Schema::Codec::ParseError, "CBOR storage value must be an object" unless object.is_a?(Hash)

        Object[object]
      rescue ArgumentError => error
        raise Schema::Codec::ParseError, "invalid base64 CBOR storage value: #{error.message}"
      end

      def decode_record(value, key:, revision: nil)
        decode(value)
      rescue Schema::Codec::Error
        Unreadable.new(value, key).tap do |object|
          object["metadata"] = revision ? {"resourceVersion" => revision.to_s} : {}
        end
      end
    end
  end
end
