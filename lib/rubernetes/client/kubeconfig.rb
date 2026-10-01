# frozen_string_literal: true

require "base64"
require "psych"
require "uri"

require_relative "errors"

module Rubernetes
  module Client
    # Safely parses kubeconfig files and resolves one context into transport credentials.
    #
    # This class deliberately does not execute kubeconfig `exec` plugins. An exec plugin is
    # arbitrary code with access to credentials, so it must be implemented by an explicitly
    # sandboxed process before it can be accepted here.
    class Kubeconfig
      MAX_BYTES = 1_048_576
      MAX_TOKEN_FILE_BYTES = 1_048_576
      DEFAULT_NAMESPACE = "default"

      KubeContext = Struct.new(
        :name,
        :server,
        :namespace,
        :ca_file,
        :ca_data,
        :client_certificate_file,
        :client_certificate_data,
        :client_key_file,
        :client_key_data,
        :bearer_token,
        :insecure_skip_tls_verify,
        keyword_init: true
      ) do
        # These aliases preserve the kubeconfig terminology used by callers and tests.
        def certificate_authority_file
          ca_file
        end

        def certificate_authority_data
          ca_data
        end

        def client_certificate
          client_certificate_file || client_certificate_data
        end

        def client_key
          client_key_file || client_key_data
        end

        def token
          bearer_token
        end

        def to_h
          {
            name: name,
            server: server,
            namespace: namespace,
            ca_file: ca_file,
            ca_data: ca_data,
            client_certificate_file: client_certificate_file,
            client_certificate_data: client_certificate_data,
            client_key_file: client_key_file,
            client_key_data: client_key_data,
            bearer_token: bearer_token,
            insecure_skip_tls_verify: insecure_skip_tls_verify
          }
        end
      end
      Context = KubeContext
      KubeConfig = self # rubocop:disable Naming/ConstantName -- alias of the class under its upstream name

      attr_reader :path, :data

      # Loads a kubeconfig from KUBECONFIG or the conventional ~/.kube/config path.
      #
      # Multiple KUBECONFIG entries are merged in order. Duplicate named entries are rejected
      # rather than silently changing credentials based on an environment-dependent merge order.
      def self.load(path = nil, env: ENV, **options)
        path = options.fetch(:path, path)
        env = options.fetch(:env, env)
        configured_path = path || env["KUBECONFIG"]
        raise ConfigurationError, "kubeconfig path must be a string" if configured_path && !configured_path.is_a?(String)

        paths = configured_path ? configured_path.split(File::PATH_SEPARATOR) : [File.expand_path("~/.kube/config")]
        paths = paths.reject(&:empty?).map do |entry|
          validate_source_path(entry, "kubeconfig")
          File.expand_path(entry)
        end
        raise ConfigurationError, "kubeconfig path is empty" if paths.empty?

        merged = {}
        paths.each do |file_path|
          loaded = load_file(file_path)
          merged = merge_documents(merged, loaded, file_path)
        end
        new(merged, path: paths.first)
      end

      # Builds a safe configuration object from a YAML string without touching the filesystem.
      def self.from_yaml(content, path: "<memory>")
        document = parse_yaml(content, filename: path)
        new(document, path: path)
      end

      # Builds a configuration object from an already parsed mapping.
      def self.from_hash(document = nil, path: "<memory>", **options)
        document = options if document.nil? && !options.empty?
        new(document, path: path)
      end

      def initialize(document, path: "<memory>")
        @path = path.to_s.freeze
        @data = self.class.__send__(:normalize_mapping, document, "kubeconfig")
        validate_document!
        @data = deep_freeze(@data)
        freeze
      end

      def current_context
        @data["current-context"]
      end

      alias current_context_name current_context

      def context_names
        @data.fetch("contexts").map { |entry| entry.fetch("name") }
      end

      def context(name = nil)
        resolve(name)
      end

      # Resolves a named or current context into server and authentication material.
      def resolve(name = nil, context: nil, **options)
        name = options.fetch(:name, name)
        context_name = (context || name || current_context).to_s
        raise ContextNotFoundError, "kubeconfig has no current-context; pass --context NAME" if context_name.empty?

        context_entry = find_named("contexts", context_name)
        context = context_entry.fetch("context")
        cluster_name = required_string(context, "cluster", "context #{context_name.inspect}")
        cluster = find_named("clusters", cluster_name).fetch("cluster")
        user_name = context["user"]
        user = user_name.nil? ? {} : find_named("users", user_name).fetch("user")

        server = required_server(cluster, cluster_name)
        namespace = context.fetch("namespace", DEFAULT_NAMESPACE)
        namespace = validate_namespace(namespace, context_name)
        insecure_skip_tls_verify = cluster.fetch("insecure-skip-tls-verify", false)
        unless [true, false].include?(insecure_skip_tls_verify)
          raise ConfigurationError, "cluster #{cluster_name.inspect} insecure-skip-tls-verify must be a boolean"
        end
        if insecure_skip_tls_verify && (cluster.key?("certificate-authority") || cluster.key?("certificate-authority-data"))
          raise ConfigurationError,
                "cluster #{cluster_name.inspect} cannot combine certificate authority data with insecure TLS verification"
        end
        credentials = resolve_credentials(user, context_name)
        certificate = resolve_certificate_material(cluster, credentials, context_name)

        KubeContext.new(
          name: context_name,
          server: server,
          namespace: namespace,
          ca_file: certificate[:ca_file],
          ca_data: certificate[:ca_data],
          client_certificate_file: certificate[:client_certificate_file],
          client_certificate_data: certificate[:client_certificate_data],
          client_key_file: certificate[:client_key_file],
          client_key_data: certificate[:client_key_data],
          bearer_token: credentials[:bearer_token],
          insecure_skip_tls_verify: insecure_skip_tls_verify
        ).freeze
      end

      private

      def self.load_file(path)
        content = read_limited_file(path, MAX_BYTES, "kubeconfig")
        parse_yaml(content, filename: path)
      rescue ConfigurationError
        raise
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR, Errno::ELOOP, Psych::Exception => error
        raise ConfigurationError.new("cannot load kubeconfig #{path}: #{error.message}", cause: error), cause: error
      end

      def self.read_limited_file(path, limit, label)
        validate_source_path(path, label)
        reject_symlink_components(path, label)

        flags = File::RDONLY
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        File.open(path, flags) do |file|
          file.binmode
          stat = file.stat
          raise ConfigurationError, "#{label} must be a regular file: #{path}" unless stat.file?

          mode = stat.mode & 0o777
          raise ConfigurationError, "#{label} has no read permission: #{path}" if mode.nobits?(0o444)
          raise ConfigurationError, "#{label} must not grant permissions to group or other users: #{path}" if mode.anybits?(0o077)

          content = file.read(limit + 1)
          raise ConfigurationError, "#{label} exceeds #{limit} bytes: #{path}" if content.bytesize > limit

          content
        end
      rescue ConfigurationError
        raise
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR, Errno::ELOOP => error
        raise ConfigurationError.new("cannot read #{label} #{path}: #{error.message}", cause: error), cause: error
      end

      def self.parse_yaml(content, filename:)
        raise ConfigurationError, "kubeconfig content must be a String" unless content.is_a?(String)

        reject_duplicate_yaml_keys(Psych.parse_stream(content, filename: filename), filename)
        document = Psych.safe_load(
          content,
          permitted_classes: [],
          permitted_symbols: [],
          aliases: false,
          filename: filename,
          fallback: {}
        )
        raise ConfigurationError, "kubeconfig root must be a mapping: #{filename}" unless document.is_a?(Hash)

        normalize_mapping(document, "kubeconfig")
      rescue Psych::Exception => error
        raise ConfigurationError.new("cannot parse kubeconfig #{filename}: #{error.message}", cause: error), cause: error
      end

      def self.merge_documents(left, right, source_path)
        merged = deep_dup(left)
        right.each do |key, value|
          if %w[clusters users contexts].include?(key)
            merged[key] ||= []
            raise ConfigurationError, "kubeconfig #{key} must be a list: #{source_path}" unless value.is_a?(Array)

            value.each do |entry|
              name = entry.is_a?(Hash) ? entry["name"] : nil
              if merged[key].any? { |existing| existing.is_a?(Hash) && existing["name"] == name }
                raise ConfigurationError, "duplicate kubeconfig #{key} entry: #{name.inspect}"
              end

              merged[key] << deep_dup(entry)
            end
          elsif merged.key?(key) && merged[key] != value
            merged[key] = value
          else
            merged[key] = deep_dup(value)
          end
        end
        merged
      end

      def self.deep_dup(value)
        case value
        when Hash
          value.to_h { |key, child| [key, deep_dup(child)] }
        when Array
          value.map { |child| deep_dup(child) }
        else
          value
        end
      end

      def self.normalize_mapping(value, context)
        case value
        when Hash
          value.to_h do |key, child|
            key_string = key.is_a?(String) ? key : key.to_s
            [key_string, normalize_mapping(child, "#{context}.#{key_string}")]
          end
        when Array
          value.map { |child| normalize_mapping(child, context) }
        else
          value
        end
      end

      def self.singularize(key)
        key.delete_suffix("s").sub(/ie\z/, "y")
      end

      def self.validate_source_path(path, label)
        raise ConfigurationError, "#{label} path must be a non-empty string" unless path.is_a?(String) && !path.empty?
        return unless path.match?(/[\x00-\x1f\x7f]/)

        raise ConfigurationError, "#{label} path must not contain control characters"
      end

      def self.reject_symlink_components(path, label)
        current = File::SEPARATOR
        File.expand_path(path).split(File::SEPARATOR).each do |component|
          next if component.empty?

          current = File.join(current, component)
          raise ConfigurationError, "#{label} path must not contain symlinks: #{path}" if File.symlink?(current)
        end
      end

      def self.reject_duplicate_yaml_keys(node, filename)
        case node
        when Psych::Nodes::Stream, Psych::Nodes::Document, Psych::Nodes::Sequence
          node.children.each { |child| reject_duplicate_yaml_keys(child, filename) }
        when Psych::Nodes::Mapping
          seen = {}
          node.children.each_slice(2) do |key_node, value_node|
            key = key_node.is_a?(Psych::Nodes::Scalar) ? key_node.value : nil
            raise ConfigurationError, "duplicate kubeconfig key #{key.inspect}: #{filename}" if key && seen.key?(key)

            seen[key] = true if key
            reject_duplicate_yaml_keys(key_node, filename)
            reject_duplicate_yaml_keys(value_node, filename)
          end
        end
      end

      private_class_method :load_file, :read_limited_file, :parse_yaml, :merge_documents, :deep_dup,
                           :normalize_mapping, :singularize, :validate_source_path,
                           :reject_symlink_components, :reject_duplicate_yaml_keys

      def find_named(collection, name)
        entry = @data.fetch(collection).find { |candidate| candidate["name"] == name }
        return entry if entry

        raise ContextNotFoundError, "kubeconfig #{collection} has no entry named #{name.inspect}"
      end

      def validate_document!
        %w[clusters users contexts].each do |collection|
          value = @data.fetch(collection, [])
          raise ConfigurationError, "kubeconfig #{collection} must be a list" unless value.is_a?(Array)

          names = value.map do |entry|
            raise ConfigurationError, "kubeconfig #{collection} entries must be mappings" unless entry.is_a?(Hash)

            name = entry["name"]
            unless name.is_a?(String) && !name.empty?
              raise ConfigurationError,
                    "kubeconfig #{collection} entry name must be a non-empty string"
            end

            name
          end
          duplicates = names.tally.select { |_name, count| count > 1 }.keys
          raise ConfigurationError, "duplicate kubeconfig #{collection} name: #{duplicates.join(", ")}" unless duplicates.empty?
        end
        raise ConfigurationError, "kubeconfig current-context must be a string" unless current_context.nil? || current_context.is_a?(String)
      end

      def required_string(mapping, key, context)
        value = mapping[key]
        return value if value.is_a?(String) && !value.empty?

        raise ConfigurationError, "#{context} requires a non-empty #{key}"
      end

      def required_server(cluster, cluster_name)
        server = required_string(cluster, "server", "cluster #{cluster_name.inspect}")
        uri = URI.parse(server)
        unless %w[http https].include?(uri.scheme) && uri.host && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
          raise ConfigurationError,
                "cluster #{cluster_name.inspect} server must be an http(s) URL without credentials, query, or fragment"
        end

        server
      rescue URI::InvalidURIError => error
        raise ConfigurationError.new("cluster #{cluster_name.inspect} server is not a valid URL", cause: error), cause: error
      end

      def validate_namespace(namespace, context_name)
        unless namespace.is_a?(String) && !namespace.empty? && namespace.match?(/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/)
          raise ConfigurationError, "context #{context_name.inspect} namespace must be a DNS label"
        end

        namespace
      end

      def resolve_credentials(user, context_name)
        if user.key?("exec")
          raise UnsupportedCredentialError,
                "context #{context_name.inspect} uses exec credentials; explicit isolated exec support is required"
        end
        if user.key?("auth-provider")
          raise UnsupportedCredentialError,
                "context #{context_name.inspect} uses auth-provider credentials; configure a bearer token or client certificate"
        end

        token = user["token"]
        token = read_secret_file(user["tokenFile"], "tokenFile") if token.nil? && user.key?("tokenFile")
        validate_bearer_token(token, "context #{context_name.inspect}") if token

        unsupported = user.keys & %w[username password]
        unless unsupported.empty?
          raise UnsupportedCredentialError,
                "context #{context_name.inspect} uses basic-auth credentials; use a bearer token or client certificate"
        end

        {
          bearer_token: token,
          client_certificate_file: resolve_path(user["client-certificate"], "client-certificate"),
          client_certificate_data: decode_data(user["client-certificate-data"], "client-certificate-data"),
          client_key_file: resolve_path(user["client-key"], "client-key"),
          client_key_data: decode_data(user["client-key-data"], "client-key-data")
        }
      end

      def resolve_certificate_material(cluster, credentials, context_name)
        ca_file = resolve_path(cluster["certificate-authority"], "certificate-authority")
        ca_data = decode_data(cluster["certificate-authority-data"], "certificate-authority-data")
        ca_file = nil if ca_data

        certificate_file = credentials[:client_certificate_file]
        certificate_data = credentials[:client_certificate_data]
        certificate_file = nil if certificate_data
        key_file = credentials[:client_key_file]
        key_data = credentials[:client_key_data]
        key_file = nil if key_data

        has_certificate = certificate_file || certificate_data
        has_key = key_file || key_data
        if has_certificate && !has_key
          raise ConfigurationError, "context #{context_name.inspect} has a client certificate without a client key"
        end
        if has_key && !has_certificate
          raise ConfigurationError, "context #{context_name.inspect} has a client key without a client certificate"
        end

        {
          ca_file: ca_file,
          ca_data: ca_data,
          client_certificate_file: certificate_file,
          client_certificate_data: certificate_data,
          client_key_file: key_file,
          client_key_data: key_data
        }
      end

      def decode_data(value, field)
        return nil if value.nil?
        raise ConfigurationError, "kubeconfig #{field} must be a non-empty base64 string" unless value.is_a?(String) && !value.empty?

        Base64.strict_decode64(value)
      rescue ArgumentError => error
        raise ConfigurationError.new("kubeconfig #{field} is not valid base64: #{error.message}", cause: error), cause: error
      end

      def resolve_path(value, field)
        return nil if value.nil?
        raise ConfigurationError, "kubeconfig #{field} must be a non-empty path" unless value.is_a?(String) && !value.empty?

        raise ConfigurationError, "kubeconfig #{field} path must not contain control characters" if value.match?(/[\x00-\x1f\x7f]/)
        raise ConfigurationError, "kubeconfig #{field} path traversal is not allowed" if value.split(%r{[/\\]}).include?("..")

        base_directory = @path == "<memory>" ? Dir.pwd : File.dirname(File.expand_path(@path))
        resolved_path = File.expand_path(value, base_directory)
        reject_symlink_components!(resolved_path, field)
        resolved_path
      end

      def read_secret_file(path, field)
        resolved_path = resolve_path(path, field)
        flags = File::RDONLY
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        content = File.open(resolved_path, flags) do |file|
          file.binmode
          stat = file.stat
          raise ConfigurationError, "kubeconfig #{field} must be a regular file" unless stat.file?

          mode = stat.mode & 0o777
          raise ConfigurationError, "kubeconfig #{field} has no read permission" if mode.nobits?(0o444)
          raise ConfigurationError, "kubeconfig #{field} must not be readable by group or other users" if mode.anybits?(0o077)

          value = file.read(MAX_TOKEN_FILE_BYTES + 1)
          raise ConfigurationError, "kubeconfig #{field} exceeds #{MAX_TOKEN_FILE_BYTES} bytes" if value.bytesize > MAX_TOKEN_FILE_BYTES

          value
        end
        token = content.strip
        raise ConfigurationError, "kubeconfig #{field} is empty" if token.empty?

        validate_bearer_token(token, "kubeconfig #{field}")

        token
      rescue ConfigurationError
        raise
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR, Errno::ELOOP => error
        raise ConfigurationError.new("cannot read kubeconfig #{field}: #{error.message}", cause: error), cause: error
      end

      def validate_bearer_token(token, context)
        raise ConfigurationError, "#{context} token must be a non-empty string" unless token.is_a?(String) && !token.empty?
        raise ConfigurationError, "#{context} token exceeds #{MAX_TOKEN_FILE_BYTES} bytes" if token.bytesize > MAX_TOKEN_FILE_BYTES
        return if token.b.match?(/\A[!-~]+\z/n)

        raise ConfigurationError, "#{context} token must contain only printable ASCII without whitespace"
      end

      def reject_symlink_components!(path, field)
        current = File::SEPARATOR
        File.expand_path(path).split(File::SEPARATOR).each do |component|
          next if component.empty?

          current = File.join(current, component)
          raise ConfigurationError, "kubeconfig #{field} path must not contain symlinks" if File.symlink?(current)
        end
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each do |key, child|
            key.freeze
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end
    end

    KubeConfig = Kubeconfig
  end
end
