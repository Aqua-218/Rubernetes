# frozen_string_literal: true

require "base64"

require_relative "errors"
require_relative "types"

module Rubernetes
  module Volume
    # Fetches CSI credentials using the node identity. Only the reference
    # belongs to a mount record. Each attempt reads the current Secret.
    class KubernetesCSISecretResolver
      NAMESPACE = /\A[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\z/
      SECRET_NAME = /\A[a-z0-9](?:[-.a-z0-9]*[a-z0-9])?\z/

      def self.normalize_reference(value)
        namespace = Types.key(value, "namespace")
        name = Types.key(value, "name")
        unless namespace.is_a?(String) && namespace.bytesize <= 63 && NAMESPACE.match?(namespace)
          raise ValidationError, "CSI Secret reference must include a valid namespace"
        end
        raise ValidationError, "CSI Secret reference must include a valid name" unless name.is_a?(String) && name.bytesize <= 253 && SECRET_NAME.match?(name)

        {"namespace" => namespace, "name" => name}
      end

      def initialize(reader:)
        @reader = reader
      end

      def resolve(reference, **)
        identity = self.class.normalize_reference(reference)
        namespace, name = identity.values_at("namespace", "name")
        secret = read_secret(namespace, name)
        raise CSIUnavailable, "CSI Secret #{namespace}/#{name} does not exist" unless secret

        decode_data(secret.fetch("data", {}) || {})
      end

      private

      def read_secret(namespace, name)
        @reader.get("secrets", name, namespace: namespace)
      rescue StandardError
        raise CSIUnavailable, "could not read CSI Secret #{namespace}/#{name}", cause: nil
      end

      def decode_data(data)
        raise CSIUnavailable, "CSI Secret data is not a map" unless data.is_a?(Hash)

        data.each_with_object({}) do |(key, value), decoded|
          text = Base64.strict_decode64(value).force_encoding(Encoding::UTF_8)
          raise ArgumentError unless key.is_a?(String) && text.valid_encoding?

          decoded[key] = text
        end
      rescue ArgumentError, TypeError, NoMethodError
        raise CSIUnavailable, "CSI Secret contains invalid string data", cause: nil
      end
    end
  end
end
