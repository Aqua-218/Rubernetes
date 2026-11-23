# frozen_string_literal: true

require_relative "config_references"

module Rubernetes
  module Manifest
    # Collect names while building a workload, then merge them with the final PodSpec.
    class PodCredentials
      REGISTRY_TYPES = %w[kubernetes.io/dockerconfigjson kubernetes.io/dockercfg].freeze
      ACCOUNT_FIELDS = %w[serviceAccountName serviceAccount].freeze

      def initialize(helpers, namespace)
        @helpers = helpers
        @namespace = namespace
        @pull_names = []
      end

      def use_account(source, backtrace)
        reference = ResourceReferences.resolve(source, @helpers, @namespace, kinds: ["ServiceAccount"])
        raise Error, "use_service_account refers to different ServiceAccounts", backtrace if @account_name && @account_name != reference.name

        @account_name = reference.name
        @account_backtrace ||= backtrace
      end

      def add_pull_secrets(sources)
        names = sources.map do |source|
          reference = ResourceReferences.resolve(source, @helpers, @namespace, kinds: ["Secret"])
          if source.is_a?(Hash) && !REGISTRY_TYPES.include?(source["type"])
            raise Error, "Secret/#{reference.name} needs type kubernetes.io/dockerconfigjson or kubernetes.io/dockercfg"
          end

          reference.name
        end
        @pull_names.concat(names)
      end

      def used? = !@account_name.nil? || !@pull_names.empty?

      def apply(spec)
        if @account_name
          conflict = ACCOUNT_FIELDS.find { |field| spec.key?(field) && spec[field] != @account_name }
          raise Error, "use_service_account conflicts with #{conflict}", @account_backtrace if conflict

          spec["serviceAccountName"] = @account_name
        end
        return if @pull_names.empty?

        names = Set.new
        locals = spec.fetch("imagePullSecrets", nil) || []
        entries = locals + @pull_names.map { |name| {"name" => name} }
        spec["imagePullSecrets"] = entries.select do |entry|
          name = entry&.fetch("name", nil)
          name.nil? || names.add?(name)
        end
      end
    end

    module PodCredentialFields
      attr_writer :pod_credentials

      def use_service_account(account)
        @pod_credentials.use_account(account, caller)
      end

      def image_pull_secrets(*sources, **keywords, &block)
        # The generated PodSpec setter accepts the raw array or an explicit null.
        return super if sources.empty? || (sources.length == 1 && (sources.first.nil? || sources.first.is_a?(Array)))

        raise Error, "image_pull_secrets expects Secret references" unless keywords.empty? && block.nil?

        @pod_credentials.add_pull_secrets(sources)
      end
    end
  end
end
