# frozen_string_literal: true

module Rubernetes
  module Schema
    # Secret and ConfigMap: data keys, total size, the keys each built-in
    # Secret type requires, and immutability (ValidateSecret,
    # ValidateConfigMap and their Update functions).
    module KubernetesValidator
      module_function

      # ValidateSecret / ValidateConfigMap run IsConfigMapKey over every data
      # key (pkg/apis/core/validation/validation.go): a key must match
      # [-._a-zA-Z0-9]+, be at most 253 characters, and must not be "." or ".."
      # or start with "..".  An empty key is therefore rejected -- the
      # conformance spec "should fail to create secret due to empty secret key"
      # creates exactly that and requires the creation to fail.
      DATA_KEY_PATTERN = /\A[-._a-zA-Z0-9]+\z/
      DATA_KEY_MAX_LENGTH = 253
      DATA_KEY_MESSAGE = "a valid config key must consist of alphanumeric characters, '-', '_' or '.' " \
                         "(e.g. 'key.name', or 'KEY_NAME', or 'key-name', regex used for validation is " \
                         "'[-._a-zA-Z0-9]+')"

      # MaxSecretSize (pkg/apis/core/types.go:6626): a Secret's data, and a
      # ConfigMap's, may not exceed 1 MiB in total.  Nothing checked it, so an
      # object larger than any kubelet will project could be stored.
      MAX_SECRET_SIZE = 1 * 1024 * 1024

      def data_key_errors(root, kind)
        issues = []
        total = 0
        %w[data stringData binaryData].each do |section|
          values = fetch(root, section)
          next unless values.is_a?(Hash)

          total += values.sum { |_key, value| value.to_s.bytesize }
        end
        issues << issue(%w[data], :invalid, "must have at most #{MAX_SECRET_SIZE} bytes") if total > MAX_SECRET_SIZE
        %w[data stringData binaryData].each do |section|
          values = fetch(root, section)
          next unless values.is_a?(Hash)

          values.each_key do |raw_key|
            key = raw_key.to_s
            path = [section, "[#{key}]"]
            issues << issue(path, :invalid, "must be no more than #{DATA_KEY_MAX_LENGTH} characters") if key.length > DATA_KEY_MAX_LENGTH
            issues << issue(path, :invalid, DATA_KEY_MESSAGE) unless key.match?(DATA_KEY_PATTERN)
            issues << issue(path, :invalid, "must not be '.'") if key == "."
            issues << issue(path, :invalid, "must not be '..'") if key == ".."
            issues << issue(path, :invalid, "must not start with '..'") if key.start_with?("..") && key != ".."
          end
        end
        _ = kind
        issues
      end

      # ValidateSecret (validation.go:7781-7811): each built-in Secret type
      # requires its own keys.  Nothing checked them, so a
      # kubernetes.io/tls Secret with no certificate was accepted and every
      # consumer failed at use instead of at creation.
      SECRET_TYPE_REQUIRED_KEYS = {
        "kubernetes.io/dockercfg" => [".dockercfg"],
        "kubernetes.io/dockerconfigjson" => [".dockerconfigjson"],
        "kubernetes.io/basic-auth" => %w[username password],
        "kubernetes.io/ssh-auth" => ["ssh-privatekey"],
        "kubernetes.io/tls" => ["tls.crt", "tls.key"]
      }.freeze

      def secret_type_errors(root)
        type = fetch(root, "type").to_s
        required_keys = SECRET_TYPE_REQUIRED_KEYS[type]
        issues = []
        if type == "kubernetes.io/service-account-token"
          annotations = fetch(fetch(root, "metadata"), "annotations")
          name = annotations.is_a?(Hash) ? fetch(annotations, "kubernetes.io/service-account.name") : nil
          issues << issue(["metadata", "annotations", "kubernetes.io/service-account.name"], :required, "") if blank?(name)
        end
        return issues if required_keys.nil?

        data = fetch(root, "data")
        string_data = fetch(root, "stringData")
        required_keys.each do |key|
          present = (data.is_a?(Hash) && data.key?(key)) || (string_data.is_a?(Hash) && string_data.key?(key))
          issues << issue(["data", key], :required, "") unless present
        end
        issues
      end

      # ValidateSecretUpdate / ValidateConfigMapUpdate: once `immutable: true`
      # is set, neither the flag nor the data may change, and a Secret's type is
      # immutable outright.  None of it was enforced, so an immutable ConfigMap
      # or Secret could be rewritten -- the whole point of the field is that the
      # kubelet may cache it without watching.
      def immutable_data_errors(root, old, kind, operation)
        return [] unless operation == :update && old.is_a?(Hash)
        return [] unless %w[Secret ConfigMap].include?(kind)

        issues = []
        issues << issue(%w[type], :invalid, "field is immutable") if kind == "Secret" && fetch(root, "type").to_s != fetch(old, "type").to_s
        return issues unless fetch(old, "immutable") == true

        issues << issue(%w[immutable], :forbidden, "field is immutable when `immutable` is set") unless fetch(root, "immutable") == true
        %w[data binaryData].each do |section|
          next if fetch(root, section) == fetch(old, section)

          issues << issue([section], :forbidden, "field is immutable when `immutable` is set")
        end
        issues
      end
    end
  end
end
