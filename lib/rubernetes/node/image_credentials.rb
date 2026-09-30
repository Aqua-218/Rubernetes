# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "uri"

require_relative "credential_providers"

module Rubernetes
  module Node
    # Registry credentials for a Pod's image pulls, resolved the way the
    # kubelet's credentialprovider keyring does it: the Pod's
    # `imagePullSecrets` plus the ServiceAccount's, each a
    # kubernetes.io/dockerconfigjson or kubernetes.io/dockercfg Secret, keyed
    # by registry and matched by URL prefix (longest match wins, docker.io
    # aliases collapse onto index.docker.io).
    class ImageCredentials
      # +source+: the Secret it came from ({uid:, namespace:, name:});
      # +auth_hash+: a digest of its auth config (TrackedAuthConfig
      # .AuthConfigHash), which KubeletEnsureSecretPulledImages compares.
      # +service_account+: set for a credential provider plugin's auth
      # obtained with the Pod's ServiceAccount token.
      Credential = Struct.new(:registry, :username, :password, :identity_token, :source, :auth_hash, :service_account,
                              keyword_init: true) do
        def to_h
          {username: username, password: password, identity_token: identity_token}.compact
        end

        # What pulled the image, for the pull records: a Secret, a
        # ServiceAccount, or nil (node-wide).
        def pull_secret
          return {service_account: service_account} if service_account
          return nil unless source

          source.merge(hash: auth_hash.to_s)
        end
      end

      DOCKER_HUB_ALIASES = %w[docker.io index.docker.io registry-1.docker.io https://index.docker.io/v1/].freeze
      DOCKERCONFIGJSON_TYPE = "kubernetes.io/dockerconfigjson"
      DOCKERCFG_TYPE = "kubernetes.io/dockercfg"

      class << self
        # Builds the keyring for a Pod: `reader` answers `get("secrets", name,
        # namespace:)` and `get("serviceaccounts", name, namespace:)`.
        def for_pod(pod, reader:, providers: nil)
          metadata = pod["metadata"] || pod[:metadata] || {}
          spec = pod["spec"] || pod[:spec] || {}
          namespace = (metadata["namespace"] || metadata[:namespace] || "default").to_s
          names = Array(spec["imagePullSecrets"] || spec[:imagePullSecrets]).filter_map do |ref|
            ref.is_a?(Hash) ? (ref["name"] || ref[:name]) : ref
          end
          account = (spec["serviceAccountName"] || spec[:serviceAccountName] || spec["serviceAccount"] || "default").to_s
          if reader && !account.empty?
            sa = safe_get(reader, "serviceaccounts", account, namespace)
            names += Array(sa && (sa["imagePullSecrets"] || sa[:imagePullSecrets])).filter_map do |ref|
              ref.is_a?(Hash) ? (ref["name"] || ref[:name]) : ref
            end
          end
          keyring = new(providers: providers, pod: pod)
          names.map(&:to_s).reject(&:empty?).uniq.each do |name|
            secret = reader && safe_get(reader, "secrets", name, namespace)
            keyring.add_secret(secret, namespace: namespace) if secret
          end
          keyring
        end

        private

        def safe_get(reader, plural, name, namespace)
          reader.get(plural, name, namespace: namespace)
        rescue StandardError
          nil
        end
      end

      # +providers+: the node's credential provider plugins
      # (CredentialProviders), asked per image on behalf of +pod+ after the
      # Pod's own Secrets, as the kubelet's keyring puts pull secrets before
      # the node keyring.
      def initialize(providers: nil, pod: nil)
        @entries = {}
        @all = Hash.new { |hash, key| hash[key] = [] }
        @providers = providers && !providers.empty? ? providers : nil
        @pod = pod
        @provided = {}
        @provided_mutex = Mutex.new
      end

      def empty?
        @entries.empty? && @providers.nil?
      end

      def registries
        @entries.keys
      end

      # Adds every auth entry of a docker config Secret.
      def add_secret(secret, namespace: nil)
        metadata = secret["metadata"] || secret[:metadata] || {}
        source = {uid: (metadata["uid"] || metadata[:uid]).to_s, namespace: (metadata["namespace"] || metadata[:namespace] || namespace).to_s,
                  name: (metadata["name"] || metadata[:name]).to_s}
        type = (secret["type"] || secret[:type]).to_s
        data = secret["data"] || secret[:data] || {}
        string_data = secret["stringData"] || secret[:stringData] || {}
        raw = case type
              when DOCKERCONFIGJSON_TYPE then decode(data[".dockerconfigjson"]) || string_data[".dockerconfigjson"]
              when DOCKERCFG_TYPE then decode(data[".dockercfg"]) || string_data[".dockercfg"]
              else decode(data[".dockerconfigjson"]) || decode(data[".dockercfg"])
              end
        return self if raw.nil? || raw.to_s.empty?

        document = JSON.parse(raw)
        auths = document.is_a?(Hash) && document.key?("auths") ? document["auths"] : document
        return self unless auths.is_a?(Hash)

        auths.each { |registry, entry| add_auth(registry, entry, source: source) }
        self
      rescue JSON::ParserError
        self
      end

      def add_auth(registry, entry, source: nil)
        return unless entry.is_a?(Hash)

        username = entry["username"]
        password = entry["password"]
        if (username.nil? || password.nil?) && entry["auth"]
          decoded = begin
            Base64.decode64(entry["auth"].to_s)
          rescue ArgumentError
            ""
          end
          user, pass = decoded.split(":", 2)
          username ||= user
          password ||= pass
        end
        key = normalize_registry(registry)
        auth_hash = Digest::SHA256.hexdigest(JSON.generate([key, username, password, entry["identitytoken"], entry["registrytoken"]]))
        credential = Credential.new(registry: key, username: username, password: password,
                                    identity_token: entry["identitytoken"], source: source, auth_hash: auth_hash)
        @entries[key] = credential
        @all[key] << credential
      end

      # Every Secret credential for the reference's registry (keyring.Lookup):
      # a Pod proves access to an image with any of them.
      def lookup_all(reference)
        path, host = registry_path(reference)
        @all.flat_map do |registry, credentials|
          path == registry || path.start_with?("#{registry}/") || host == registry ? credentials : []
        end
      end

      # The ServiceAccount a provider plugin used for +reference+, if any.
      def service_account_for(reference)
        provided(reference).find(&:service_account)&.service_account
      end

      # The credential for an image reference, or nil when no entry matches.
      def lookup(reference)
        # distribution/reference: the first component is a registry only
        # when it looks like a host (a dot, a port, or "localhost") and more
        # path follows; anything else is a Docker Hub repository.
        path, host = registry_path(reference)
        best = nil
        @entries.each do |registry, credential|
          next unless path == registry || path.start_with?("#{registry}/") || host == registry
          next if best && best.registry.length >= registry.length

          best = credential
        end
        best || provided(reference).first
      end

      alias credentials_for lookup

      private

      # The provider plugins' credentials whose auth pattern matches the
      # image (once per image and keyring).
      def provided(reference)
        return [] unless @providers

        @provided_mutex.synchronize do
          @provided[reference.to_s] ||= @providers.lookup(reference.to_s, pod: @pod).filter_map do |credential|
            next nil unless CredentialProviders.urls_match?(credential.registry, reference.to_s.sub(%r{\Ahttps?://}, ""))

            Credential.new(registry: credential.registry, username: credential.username, password: credential.password,
                           service_account: credential.service_account)
          end
        end
      end

      # [registry path, host] of an image reference, as lookup matches them.
      def registry_path(reference)
        image = reference.to_s.sub(%r{\Ahttps?://}, "")
        parts = image.split("/")
        first = parts.first.to_s
        if parts.length > 1 && (first.include?(".") || first.include?(":") || first == "localhost")
          host = first
          remainder = parts.drop(1).join("/")
        else
          host = "index.docker.io"
          remainder = image
        end
        host = "index.docker.io" if DOCKER_HUB_ALIASES.include?(host)
        [remainder.empty? ? host : "#{host}/#{remainder}", host]
      end

      def decode(value)
        return nil if value.nil?

        Base64.decode64(value.to_s)
      end

      def normalize_registry(value)
        registry = value.to_s.strip
        registry = registry.sub(%r{\Ahttps?://}, "")
        registry = registry.sub(%r{/v1/?\z}, "").sub(%r{/v2/?\z}, "")
        registry = registry.chomp("/")
        registry = "index.docker.io" if DOCKER_HUB_ALIASES.include?(registry) || registry.empty?
        registry
      end
    end
  end
end
