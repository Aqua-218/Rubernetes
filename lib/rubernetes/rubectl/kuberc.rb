# frozen_string_literal: true

require "psych"

require_relative "../client/exec_credential"

module Rubernetes
  module Rubectl
    # Loads the exec credential policy from the first supported Preference
    # document, following kubectl's kuberc path precedence.
    module Kuberc
      V1ALPHA1 = "kubectl.config.k8s.io/v1alpha1"
      V1BETA1 = "kubectl.config.k8s.io/v1beta1"
      MAX_BYTES = 1_048_576

      module_function

      def disabled?(env)
        env["KUBECTL_KUBERC"].to_s.casecmp?("false")
      end

      def load(path:, env:, warn:)
        return if disabled?(env)

        explicit = path unless path.to_s.empty?
        configured = env["KUBERC"]
        if configured == "off"
          raise Client::ConfigurationError, "KUBERC=off cannot be combined with --kuberc" if explicit

          return
        end
        explicit ||= configured unless configured.to_s.empty?
        filename = explicit || default_path(env)
        preference = read_preference(filename, explicit: !explicit.nil?, warn: warn)
        return unless preference

        policy(preference, warn)
      end

      def default_path(env)
        home = env["HOME"]
        home = Dir.home if home.to_s.empty?
        File.join(home, ".kube", "kuberc")
      end

      def read_preference(path, explicit:, warn:)
        content = File.open(path, File::RDONLY | File::NONBLOCK) do |file|
          raise IOError, "must be a regular file" unless file.stat.file?

          file.read(MAX_BYTES + 1).to_s
        end
        raise IOError, "exceeds #{MAX_BYTES} bytes" if content.bytesize > MAX_BYTES

        found_document = false
        Psych.parse_stream(content, filename: path) do |document|
          root = document.root
          next unless root
          next if root.is_a?(Psych::Nodes::Scalar) && root.value.to_s.empty?

          found_document = true
          next unless preference_document?(root)

          reject_duplicate_keys!(document)
          return safe_value(document)
        end
        raise IOError, "no supported Preference document found" if found_document

        nil
      rescue Errno::ENOENT => error
        raise Client::ConfigurationError, "kuberc: #{error.message}" if explicit
      rescue SystemCallError, IOError, Psych::Exception, ArgumentError => error
        message = "kuberc: cannot read #{path}: #{error.message}"
        raise Client::ConfigurationError, message if explicit

        warn.call(message)
        nil
      end

      def preference_document?(root)
        return false unless root.is_a?(Psych::Nodes::Mapping)

        fields = root.children.each_slice(2).filter_map do |key, value|
          [key.value, value.value] if key.is_a?(Psych::Nodes::Scalar) && value.is_a?(Psych::Nodes::Scalar)
        end.to_h
        fields["kind"] == "Preference" && [V1ALPHA1, V1BETA1].include?(fields["apiVersion"])
      end

      def safe_value(document)
        loader = Psych::ClassLoader::Restricted.new([], [])
        Psych::Visitors::NoAliasRuby.new(Psych::ScalarScanner.new(loader), loader).accept(document)
      rescue Psych::Exception => error
        raise Client::ConfigurationError, "kuberc: invalid Preference document: #{error.message}"
      end

      def reject_duplicate_keys!(node)
        if node.is_a?(Psych::Nodes::Mapping)
          keys = node.children.each_slice(2).filter_map { |key, _| key.value if key.is_a?(Psych::Nodes::Scalar) }
          raise Client::ConfigurationError, "kuberc: duplicate preference field" if keys.length != keys.uniq.length
        end
        Array(node.children).each { |child| reject_duplicate_keys!(child) }
      end

      def policy(preference, warn)
        common = %w[apiVersion kind defaults overrides aliases]
        fields = %w[credentialPluginPolicy credentialPluginAllowlist] if preference["apiVersion"] == V1BETA1
        (preference.keys - common - Array(fields)).each { |key| warn.call("kuberc: ignoring unknown preference field #{key.inspect}") }
        return unless fields

        allowlist = preference["credentialPluginAllowlist"]
        raise Client::ConfigurationError, "kuberc: credentialPluginAllowlist must be a list" unless allowlist.nil? || allowlist.is_a?(Array)

        Client::ExecCredential.normalize_policy({"type" => preference["credentialPluginPolicy"],
                                                 "allowlist" => allowlist&.map { |entry| allowlist_command(entry, warn) }})
      end

      def allowlist_command(entry, warn)
        raise Client::ConfigurationError, "kuberc: credentialPluginAllowlist entries must be mappings" unless entry.is_a?(Hash)

        (entry.keys - %w[command name]).each { |key| warn.call("kuberc: ignoring unknown allowlist field #{key.inspect}") }
        command, name = entry.values_at("command", "name").map { |value| value unless value == "" }
        unless [command, name].all? { |value| value.nil? || value.is_a?(String) }
          raise Client::ConfigurationError, "kuberc: credential plugin allowlist command and name must be strings"
        end
        if command && name && command != name
          raise Client::ConfigurationError, "kuberc: command and deprecated name are different in a credential plugin allowlist entry"
        end

        command || name
      end
    end
  end
end
