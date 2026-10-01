# frozen_string_literal: true

require "digest"
require "json"
require "open3"
require "psych"
require "timeout"
require "uri"

module Rubernetes
  module Node
    # The kubelet's image credential provider plugins
    # (pkg/credentialprovider/plugin, v1.36.2; --image-credential-provider-
    # config and --image-credential-provider-bin-dir).  A provider is an
    # executable named in a CredentialProviderConfig: for an image matching
    # its matchImages it is run with a CredentialProviderRequest on stdin and
    # answers a CredentialProviderResponse (registry auths, a cache key type
    # and duration) on stdout.  With tokenAttributes
    # (KubeletServiceAccountTokenForCredentialProviders, Beta on) the request
    # carries a token for the Pod's ServiceAccount bound to the Pod, and the
    # credentials are attributed to that ServiceAccount.
    class CredentialProviders
      CONFIG_GROUP = "kubelet.config.k8s.io"
      CONFIG_VERSIONS = %w[v1 v1beta1 v1alpha1].freeze
      API_VERSIONS = %w[credentialprovider.kubelet.k8s.io/v1 credentialprovider.kubelet.k8s.io/v1beta1
                        credentialprovider.kubelet.k8s.io/v1alpha1].freeze
      CACHE_TYPES = %w[ServiceAccount Token].freeze
      EXEC_TIMEOUT = 60.0
      GLOBAL_CACHE_KEY = "global"
      CACHE_PURGE_INTERVAL = 15 * 60

      class ConfigError < StandardError; end
      class PluginError < StandardError; end

      # One auth a provider returned; +service_account+ ({uid:, namespace:,
      # name:}) when a ServiceAccount token obtained it.
      Credential = Struct.new(:registry, :username, :password, :service_account, keyword_init: true) do
        def to_h = {username: username, password: password}.compact
      end

      # --image-credential-provider-config (a file, or a directory of
      # .json/.yaml/.yml files merged in name order) and -bin-dir.
      def self.load(config_path:, bin_dir:, token_requester: nil, service_account_reader: nil, sa_tokens: true, clock: nil)
        documents = config_files(config_path).map { |path| [path, parse_document(File.read(path), path)] }
        providers = []
        names = {}
        documents.each do |_path, document|
          Array(document["providers"]).each do |provider|
            name = provider.is_a?(Hash) ? provider["name"].to_s : ""
            raise ConfigError, "duplicate provider name #{name.inspect} found in configuration file(s)" if names[name]

            names[name] = true
            providers << provider
          end
        end
        errors = validate(providers, sa_tokens: sa_tokens)
        raise ConfigError, "failed to validate credential provider config: #{errors.join(", ")}" unless errors.empty?

        loaded = new(providers.map do |provider|
          binary = File.join(bin_dir.to_s, provider["name"])
          raise ConfigError, "plugin binary executable #{binary} did not exist" unless File.file?(binary) && File.executable?(binary)

          Provider.new(provider, binary: binary, token_requester: token_requester, service_account_reader: service_account_reader,
                                 sa_tokens: sa_tokens, clock: clock)
        end)
        loaded.config_hash = config_hash(documents.map(&:first))
        loaded
      end

      # readCredentialProviderConfig: sha256 over each file, in order, with
      # its length as a big-endian uint64 before it.
      def self.config_hash(paths)
        digest = Digest::SHA256.new
        paths.each do |path|
          data = File.binread(path)
          digest << [data.bytesize].pack("Q>") << data
        end
        "sha256:#{digest.hexdigest}"
      end

      def self.config_files(path)
        raise ConfigError, "credential provider config path is empty" if path.to_s.empty?
        raise ConfigError, "unable to access path #{path.inspect}" unless File.exist?(path)
        return [path] unless File.directory?(path)

        files = Dir.children(path).sort.filter_map do |entry|
          full = File.join(path, entry)
          full if File.file?(full) && %w[.json .yaml .yml].include?(File.extname(entry))
        end
        raise ConfigError, "no configuration files found in directory #{path.inspect}" if files.empty?

        files
      end

      def self.parse_document(text, path)
        document = Psych.safe_load(text, permitted_classes: [], aliases: false)
        raise ConfigError, "error decoding config #{path.inspect}: not a mapping" unless document.is_a?(Hash)

        group, version = document["apiVersion"].to_s.split("/", 2)
        unless document["kind"] == "CredentialProviderConfig"
          raise ConfigError, "error decoding config #{path.inspect}: failed to decode #{document["kind"].to_s.inspect} (wrong Kind)"
        end
        unless group == CONFIG_GROUP && CONFIG_VERSIONS.include?(version)
          raise ConfigError, "error decoding config #{path.inspect}: failed to decode CredentialProviderConfig, unexpected Group: #{group}"
        end

        document
      rescue Psych::Exception => error
        raise ConfigError, "error decoding config #{path.inspect}: #{error.message}"
      end

      # validateCredentialProviderConfig.
      def self.validate(providers, sa_tokens: true)
        errors = []
        errors << "providers: Required value: at least 1 item in plugins is required" if providers.empty?
        seen = {}
        providers.each do |provider|
          provider = {} unless provider.is_a?(Hash)
          name = provider["name"].to_s
          errors << %(providers.name: Invalid value: #{name.inspect}: provider name cannot contain '/') if name.include?("/")
          errors << %(providers.name: Invalid value: #{name.inspect}: provider name cannot contain spaces) if name.include?(" ")
          errors << %(providers.name: Invalid value: "#{name}": provider name cannot be '#{name}') if %w[. ..].include?(name)
          errors << %(providers.name: Duplicate value: #{name.inspect}) if seen[name]
          seen[name] = true
          api_version = provider["apiVersion"].to_s
          if api_version.empty?
            errors << "providers.apiVersion: Required value"
          elsif !API_VERSIONS.include?(api_version)
            errors << %(providers.apiVersion: Unsupported value: #{api_version.inspect}: supported values: #{API_VERSIONS.sort.map(&:inspect).join(", ")})
          end
          images = Array(provider["matchImages"])
          errors << "providers.matchImages: Required value: at least 1 item in matchImages is required" if images.empty?
          images.each do |image|
            parse_schemeless(image.to_s)
          rescue URI::Error => error
            errors << %(providers.matchImages: Invalid value: #{image.to_s.inspect}: match image is invalid: #{error.message})
          end
          duration = provider["defaultCacheDuration"]
          if duration.nil?
            errors << "providers.defaultCacheDuration: Required value"
          elsif (seconds = parse_duration(duration)).nil? || seconds.negative?
            errors << %(providers.defaultCacheDuration: Invalid value: #{duration.to_s.inspect}: must be greater than or equal to 0)
          end
          errors.concat(token_attribute_errors(provider, api_version, sa_tokens)) if provider.key?("tokenAttributes")
        end
        errors
      end

      def self.token_attribute_errors(provider, api_version, sa_tokens)
        path = "providers.tokenAttributes"
        attributes = provider["tokenAttributes"].is_a?(Hash) ? provider["tokenAttributes"] : {}
        errors = []
        unless sa_tokens
          errors << "#{path}: Forbidden: tokenAttributes is not supported when KubeletServiceAccountTokenForCredentialProviders feature gate is disabled"
        end
        errors << "#{path}.serviceAccountTokenAudience: Required value" if attributes["serviceAccountTokenAudience"].to_s.empty?
        errors << "#{path}.requireServiceAccount: Required value" if attributes["requireServiceAccount"].nil?
        unless api_version == "credentialprovider.kubelet.k8s.io/v1"
          errors << "#{path}: Forbidden: tokenAttributes is only supported for credentialprovider.kubelet.k8s.io/v1 API version"
        end
        required = Array(attributes["requiredServiceAccountAnnotationKeys"]).map(&:to_s)
        optional = Array(attributes["optionalServiceAccountAnnotationKeys"]).map(&:to_s)
        if attributes["requireServiceAccount"] == false && !required.empty?
          errors << "#{path}.requiredServiceAccountAnnotationKeys: Forbidden: requireServiceAccount cannot be false when " \
                    "requiredServiceAccountAnnotationKeys is set"
        end
        {"requiredServiceAccountAnnotationKeys" => required, "optionalServiceAccountAnnotationKeys" => optional}.each do |field, keys|
          keys.each_with_index do |key, index|
            errors << %(#{path}.#{field}: Invalid value: #{key.inspect}: must be a qualified name) unless qualified_name?(key.downcase)
            errors << %(#{path}.#{field}: Duplicate value: #{key.inspect}) if keys[0...index].include?(key)
          end
        end
        both = (required & optional).sort
        errors << %(#{path}: Invalid value: #{both.inspect}: annotation keys cannot be both required and optional) unless both.empty?
        cache_type = attributes["cacheType"].to_s
        if cache_type.empty?
          errors << "#{path}.cacheType: Required value: cacheType is required to be set when tokenAttributes is specified. " \
                    "Supported values are: #{CACHE_TYPES.join(", ")}"
        elsif !CACHE_TYPES.include?(cache_type)
          errors << %(#{path}.cacheType: Unsupported value: #{cache_type.inspect}: supported values: #{CACHE_TYPES.map(&:inspect).join(", ")})
        end
        errors
      end

      def self.qualified_name?(key)
        prefix, name = key.include?("/") ? key.split("/", 2) : [nil, key]
        if prefix && (prefix.empty? || prefix.length > 253 || !prefix.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/))
          return false
        end

        !name.to_s.empty? && name.length <= 63 && name.match?(/\A([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z/)
      end

      # metav1.Duration strings ("12h", "1m30s") or plain seconds.
      def self.parse_duration(value)
        return Float(value) if value.is_a?(Numeric)

        text = value.to_s.strip
        return 0.0 if text == "0"

        total = 0.0
        rest = text.dup
        units = {"h" => 3600.0, "m" => 60.0, "s" => 1.0, "ms" => 0.001, "us" => 0.000_001, "µs" => 0.000_001, "ns" => 0.000_000_001}
        negative = rest.start_with?("-")
        rest = rest.delete_prefix("-").delete_prefix("+")
        return nil if rest.empty?

        until rest.empty?
          match = rest.match(/\A(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/)
          return nil unless match

          total += match[1].to_f * units.fetch(match[2])
          rest = rest[match[0].length..]
        end
        negative ? -total : total
      end

      SchemelessURL = Struct.new(:host, :port, :path)

      # ParseSchemelessURL: url.Parse("https://" + value) -- host (globs
      # allowed), optional port, path.
      def self.parse_schemeless(value)
        text = value.to_s
        raise URI::InvalidURIError, "invalid control character in URL" if text.match?(/[\x00-\x1f\x7f ]/)
        raise URI::InvalidURIError, "invalid URL escape" if text.match?(/%(?!\h\h)/)

        authority, slash, rest = text.partition("/")
        path = slash.empty? ? "" : "/#{rest}"
        host = authority
        port = ""
        if (match = authority.match(/\A(.*):([^:\]]*)\z/)) && !authority.start_with?("[")
          host = match[1]
          port = match[2]
          raise URI::InvalidURIError, %(invalid port ":#{port}" after host) unless port.match?(/\A\d*\z/)
        end
        SchemelessURL.new(host, port, path)
      end

      # credentialprovider.URLsMatchStr: the same port, the same number of
      # host labels, each a filepath.Match glob, and a path prefix.
      def self.urls_match?(glob, target)
        glob_url = parse_schemeless(glob)
        target_url = parse_schemeless(target)
        return false unless glob_url.port == target_url.port

        glob_parts = glob_url.host.split(".", -1)
        target_parts = target_url.host.split(".", -1)
        return false unless glob_parts.length == target_parts.length
        return false unless target_url.path.start_with?(glob_url.path)

        glob_parts.zip(target_parts).all? { |pattern, part| File.fnmatch?(pattern, part, File::FNM_PATHNAME) }
      rescue URI::Error
        false
      end

      def initialize(providers)
        @providers = providers
      end

      attr_reader :providers
      attr_accessor :config_hash

      # registerMetrics + recordCredentialProviderConfigHash: the plugins'
      # errors and durations, and the config's hash as an info metric.
      def metrics=(registry)
        registry.register("kubelet_credential_provider_plugin_errors_total", type: :counter)
        registry.register("kubelet_credential_provider_plugin_duration", type: :histogram)
        registry.register("kubelet_credential_provider_config_info", type: :gauge)
        registry.set("kubelet_credential_provider_config_info", 1, {"hash" => @config_hash.to_s}) if @config_hash
        @providers.each { |provider| provider.metrics = registry if provider.respond_to?(:metrics=) }
      end

      def empty? = @providers.empty?

      # Every credential the providers give for +image+ on behalf of a Pod
      # (nil for node-level callers).
      def lookup(image, pod: nil)
        @providers.flat_map { |provider| provider.credentials_for(image, pod: pod) }
      end

      # One configured plugin.
      class Provider
        attr_reader :name
        attr_writer :metrics

        def initialize(config, binary:, token_requester:, service_account_reader:, sa_tokens:, clock: nil)
          @name = config["name"].to_s
          @api_version = config["apiVersion"].to_s
          @binary = binary
          @args = Array(config["args"]).map(&:to_s)
          @env = Array(config["env"]).to_h { |entry| [entry["name"].to_s, entry["value"].to_s] }
          @match_images = Array(config["matchImages"]).map(&:to_s)
          @default_cache = CredentialProviders.parse_duration(config["defaultCacheDuration"]) || 0.0
          attributes = config["tokenAttributes"]
          @token = if sa_tokens && attributes.is_a?(Hash) && !attributes["serviceAccountTokenAudience"].to_s.empty?
                     {audience: attributes["serviceAccountTokenAudience"].to_s, require: attributes["requireServiceAccount"] == true,
                      required: Array(attributes["requiredServiceAccountAnnotationKeys"]).map(&:to_s),
                      optional: Array(attributes["optionalServiceAccountAnnotationKeys"]).map(&:to_s),
                      cache_type: attributes["cacheType"].to_s}
                   end
          @token_requester = token_requester
          @service_account_reader = service_account_reader
          @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
          @cache = {}
          @inflight = {}
          @mutex = Mutex.new
          @last_purge = @clock.call
        end

        def matches?(image) = @match_images.any? { |glob| CredentialProviders.urls_match?(glob, image) }

        # perPodPluginProvider.provide: a failing plugin yields nothing (the
        # pull goes on with the other credentials), as upstream logs and
        # continues.
        def credentials_for(image, pod: nil)
          config, account = provide(image, pod)
          config.map do |registry, auth|
            Credential.new(registry: registry, username: auth["username"], password: auth["password"], service_account: account)
          end
        rescue PluginError, StandardError
          []
        end

        def provide(image, pod)
          return [{}, nil] unless matches?(image)

          token = nil
          annotations = {}
          account = nil
          sa_key = ""
          if @token
            namespace = pod&.dig("metadata", "namespace").to_s
            account_name = pod ? (pod.dig("spec", "serviceAccountName") || pod.dig("spec", "serviceAccount")).to_s : ""
            return [{}, nil] if account_name.empty? && @token[:require]

            unless account_name.empty?
              service_account = @service_account_reader&.call(namespace, account_name)
              raise PluginError, "failed to get service account: #{namespace}/#{account_name} not found" unless service_account

              present = service_account.dig("metadata", "annotations") || {}
              @token[:required].each do |key|
                return [{}, nil] unless present.key?(key) # requiredAnnotationNotFoundError

                annotations[key] = present[key].to_s
              end
              @token[:optional].each { |key| annotations[key] = present[key].to_s if present.key?(key) }
              uid = service_account.dig("metadata", "uid").to_s
              token = @token_requester.call(namespace, account_name, audience: @token[:audience], service_account_uid: uid,
                                                                     pod_name: pod.dig("metadata", "name").to_s, pod_uid: pod.dig("metadata", "uid").to_s)
              raise PluginError, "failed to get service account token" if token.to_s.empty?

              token_hash = "sha256:#{Digest::SHA256.hexdigest(token)}"
              parts = [namespace, account_name, uid, annotations.sort]
              parts += ["token", token_hash] if @token[:cache_type] == "Token"
              sa_key = JSON.generate(parts)
              account = {uid: uid, namespace: namespace, name: account_name}
            end
          end
          cached = cached(image, sa_key)
          return [cached, account] if cached

          flight_key = @token && token ? JSON.generate([image, "sha256:#{Digest::SHA256.hexdigest(token)}", annotations.sort]) : image
          response = single_flight(flight_key) { exec_plugin(image, token, annotations) }
          auth = response["auth"].is_a?(Hash) ? response["auth"] : {}
          if token && @token[:cache_type] != "Token" && auth.values.any? { |entry| entry.is_a?(Hash) && entry["password"] == token }
            raise PluginError, "credential provider plugin returned the service account token as the password which is not allowed " \
                               "when service account cache type is not set to 'Token'"
          end
          base = case response["cacheKeyType"]
                 when "Image" then image
                 when "Registry" then image.split("/").first
                 when "Global" then GLOBAL_CACHE_KEY
                 else raise PluginError, "credential provider plugin did not return a valid cacheKeyType: #{response["cacheKeyType"]}"
                 end
          config = auth.to_h do |pattern, entry|
            [pattern.to_s, {"username" => entry["username"].to_s, "password" => entry["password"].to_s}]
          end
          duration = response.key?("cacheDuration") && !response["cacheDuration"].nil? ? CredentialProviders.parse_duration(response["cacheDuration"]) : nil
          ttl = duration.nil? ? @default_cache : duration
          @mutex.synchronize { @cache[JSON.generate([base, sa_key])] = [config, @clock.call + ttl] } if ttl&.positive?
          [config, account]
        end

        private

        # getCachedCredentials: image, then registry, then global keys.
        def cached(image, sa_key)
          @mutex.synchronize do
            now = @clock.call
            if now - @last_purge > CACHE_PURGE_INTERVAL
              @cache.delete_if { |_key, (_config, expires)| expires <= now }
              @last_purge = now
            end
            [image, image.split("/").first, GLOBAL_CACHE_KEY].each do |base|
              entry = @cache[JSON.generate([base, sa_key])]
              return entry[0] if entry && entry[1] > now
            end
            nil
          end
        end

        def single_flight(key)
          flight, leader = @mutex.synchronize do
            if (existing = @inflight[key])
              [existing, false]
            else
              @inflight[key] = {mutex: Mutex.new, condition: ConditionVariable.new, done: false, value: nil, error: nil}
              [@inflight[key], true]
            end
          end
          unless leader
            flight[:mutex].synchronize { flight[:condition].wait(flight[:mutex]) until flight[:done] }
            raise flight[:error] if flight[:error]

            return flight[:value]
          end
          begin
            flight[:value] = yield
          rescue StandardError => error
            flight[:error] = error
            raise
          ensure
            @mutex.synchronize { @inflight.delete(key) }
            flight[:mutex].synchronize do
              flight[:done] = true
              flight[:condition].broadcast
            end
          end
        end

        # execPlugin.ExecPlugin.
        def exec_plugin(image, token, annotations)
          run_plugin(image, token, annotations)
        end

        def run_plugin(image, token, annotations)
          request = {"kind" => "CredentialProviderRequest", "apiVersion" => @api_version, "image" => image}
          request["serviceAccountToken"] = token if token
          request["serviceAccountAnnotations"] = annotations unless annotations.empty?
          env = ENV.to_h.merge(@env)
          stdout = stderr = status = nil
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            Open3.popen3(env, @binary, *@args, unsetenv_others: true) do |stdin, out, err, wait|
              stdin.write(JSON.generate(request))
              stdin.close
              readers = [Thread.new { out.read }, Thread.new { err.read }]
              unless wait.join(EXEC_TIMEOUT)
                begin
                  Process.kill("KILL", wait.pid)
                rescue StandardError
                  nil
                end
                plugin_failed
                raise PluginError, "error execing credential provider plugin #{@name} for image #{image}: context deadline exceeded"
              end
              stdout, stderr = readers.map(&:value)
              status = wait.value
            end
          rescue SystemCallError
            plugin_failed
            raise
          ensure
            # runPlugin: kubelet_credential_provider_plugin_duration.
            @metrics&.observe("kubelet_credential_provider_plugin_duration", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                              {"plugin_name" => @name})
          end
          unless status.success?
            plugin_failed
            raise PluginError, "error execing credential provider plugin #{@name} for image #{image}: #{status}: #{stderr}"
          end

          response = JSON.parse(stdout)
          unless response["apiVersion"] == @api_version
            raise PluginError, "apiVersion from credential plugin response did not match expected apiVersion:#{@api_version}, " \
                               "actual apiVersion:#{response["apiVersion"]}"
          end
          unless response["kind"] == "CredentialProviderResponse"
            raise PluginError, %(failed to decode CredentialProviderResponse, unexpected Kind: #{response["kind"].to_s.inspect})
          end

          response
        rescue JSON::ParserError
          raise PluginError, "error decoding credential provider plugin response from stdout"
        rescue SystemCallError => error
          raise PluginError, "error execing credential provider plugin #{@name} for image #{image}: #{error.message}"
        end

        def plugin_failed
          @metrics&.increment("kubelet_credential_provider_plugin_errors_total", {"plugin_name" => @name})
        rescue StandardError
          nil
        end
      end
    end
  end
end
