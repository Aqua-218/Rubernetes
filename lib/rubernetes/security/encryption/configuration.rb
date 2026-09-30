# frozen_string_literal: true

require "yaml"
require "socket"
require "base64"
require "json"
require "digest"
require "openssl"
require "securerandom"
require_relative "transformer"

module Rubernetes
  module Security
    module Encryption
      # The process-wide metrics sink the providers and stores record into
      # (the apiserver's registry) and the identity label upstream stamps on
      # the envelope series (sha256 of the API server's id).
      class << self
        attr_accessor :metrics, :apiserver_id

        def apiserver_id_hash
          "sha256:#{Digest::SHA256.hexdigest((apiserver_id || Socket.gethostname).to_s)}"
        end

        def observe(name, value, labels = {})
          metrics&.observe(name, value, labels)
        rescue StandardError
          nil
        end

        def increment(name, labels = {}, by: 1)
          metrics&.increment(name, labels, by: by)
        rescue StandardError
          nil
        end

        def set(name, value, labels = {})
          metrics&.set(name, value, labels)
        rescue StandardError
          nil
        end
      end

      # The identity provider: stored as is (prefix "").
      class IdentityProvider
        def name = "identity"
        def prefix = ""
        def key_ids = []
        def encrypt(plaintext, _associated_data) = plaintext
        def decrypt(envelope, _associated_data) = envelope
        def current_key?(_envelope) = true
      end

      # aescbc: AES-256-CBC with PKCS#7 padding and a random IV, the legacy
      # provider EncryptionConfiguration still accepts.
      class AESCBCProvider
        PREFIX = "k8s:enc:aescbc:v1:"

        def initialize(keys:)
          @keys = Array(keys).map { |key| AESGCMProvider::Key.new(key.fetch("name"), decode_secret(key.fetch("secret"))) }
          raise Error, "aescbc provider needs at least one key" if @keys.empty?
        end

        def name = "aescbc"
        def prefix = PREFIX
        def key_ids = @keys.map(&:name)

        def encrypt(plaintext, _associated_data)
          key = @keys.first
          cipher = OpenSSL::Cipher.new("aes-256-cbc").encrypt
          cipher.key = key.secret
          iv = cipher.random_iv
          "#{PREFIX}#{key.name}:#{Base64.strict_encode64(iv + cipher.update(plaintext) + cipher.final)}"
        end

        def decrypt(envelope, _associated_data)
          raise Error, "envelope is not an aescbc envelope" unless envelope.start_with?(PREFIX)

          key_name, payload = envelope.delete_prefix(PREFIX).split(":", 2)
          key = @keys.find { |candidate| candidate.name == key_name }
          raise Error, "no aescbc key named #{key_name.inspect}" unless key

          bytes = Base64.strict_decode64(payload.to_s)
          cipher = OpenSSL::Cipher.new("aes-256-cbc").decrypt
          cipher.key = key.secret
          cipher.iv = bytes.byteslice(0, 16)
          cipher.update(bytes.byteslice(16, bytes.bytesize - 16)) + cipher.final
        rescue OpenSSL::Cipher::CipherError, ArgumentError => error
          raise Error, "aescbc decryption failed: #{error.message}"
        end

        def current_key?(envelope)
          envelope.start_with?("#{PREFIX}#{@keys.first.name}:")
        end

        private

        def decode_secret(value)
          secret = Base64.strict_decode64(value.to_s)
          raise Error, "aescbc keys must be 32 bytes" unless secret.bytesize == 32

          secret
        rescue ArgumentError
          raise Error, "aescbc key secret is not valid base64"
        end
      end

      # apiserver.config.k8s.io/v1 EncryptionConfiguration: resource groups,
      # each with an ordered provider list (the first writes, all read).
      class Configuration
        API_VERSION = "apiserver.config.k8s.io/v1"
        Group = Struct.new(:names, :transformer, :matcher, keyword_init: true)

        attr_reader :groups, :hash, :path

        def self.load(path)
          bytes = File.binread(path)
          from_h(YAML.safe_load(bytes, aliases: false, permitted_classes: []), hash: Digest::SHA256.hexdigest(bytes), path: path)
        end

        def self.from_h(document, hash: nil, path: nil)
          raise Error, "encryption configuration must be a mapping" unless document.is_a?(Hash)
          unless document["apiVersion"] == API_VERSION && document["kind"] == "EncryptionConfiguration"
            raise Error, "encryption configuration must be #{API_VERSION} EncryptionConfiguration"
          end

          groups = Array(document["resources"]).map do |entry|
            names = Array(entry["resources"]).map(&:to_s)
            raise Error, "an encryption resource group needs resources" if names.empty?

            providers = Array(entry["providers"]).map { |provider| build_provider(provider) }
            raise Error, "an encryption resource group needs providers" if providers.empty?

            Group.new(names: names, transformer: Transformer.new(providers: providers), matcher: matcher_for(names))
          end
          new(groups, hash: hash || Digest::SHA256.hexdigest(JSON.generate(document)), path: path)
        end

        def self.build_provider(entry)
          raise Error, "each provider must be a mapping with one provider key" unless entry.is_a?(Hash) && entry.length == 1

          kind, options = entry.first
          options ||= {}
          case kind.to_s
          when "identity" then IdentityProvider.new
          when "aesgcm" then AESGCMProvider.new(keys: options.fetch("keys"))
          when "aescbc" then AESCBCProvider.new(keys: options.fetch("keys"))
          when "kms"
            raise Error, "only KMS v2 is supported (apiVersion: v2)" unless options.fetch("apiVersion", "v2").to_s == "v2"

            timeout = options["timeout"] ? go_duration_seconds(options["timeout"]) : 3
            KMSv2Provider.new(name: options.fetch("name"), endpoint: options.fetch("endpoint"), timeout: timeout,
                              cache_size: options.fetch("cachesize", 1000))
          when "secretbox" then raise Error, "the secretbox provider (XSalsa20-Poly1305) is not available in this build"
          else raise Error, "unknown encryption provider #{kind.inspect}"
          end
        end

        def self.go_duration_seconds(text)
          value = text.to_s
          return Float(value) if value.match?(/\A\d+(\.\d+)?\z/)

          total = 0.0
          value.scan(/(\d+(?:\.\d+)?)(ms|s|m|h)/) do |number, unit|
            total += Float(number) * {"ms" => 0.001, "s" => 1, "m" => 60, "h" => 3600}.fetch(unit)
          end
          total
        end

        # Resource names as the configuration spells them: "secrets" (core),
        # "deployments.apps", "*.apps" (every resource of a group), "*.*"
        # (everything), "*." (every core resource); matched against storage
        # keys "registry/<group>/<version>/<resource>/..." (core:
        # "registry/<version>/<resource>/...").
        def self.matcher_for(names)
          rules = names.map do |name|
            resource, group = name.split(".", 2)
            group = "" if group.nil?
            [resource, group]
          end
          lambda do |key|
            group, resource = key_group_resource(key)
            next false if resource.nil?

            rules.any? do |wanted_resource, wanted_group|
              (wanted_group == "*" || wanted_group == group) && (wanted_resource == "*" || wanted_resource == resource)
            end
          end
        end

        def self.key_group_resource(key)
          parts = key.to_s.split("/")
          return [nil, nil] unless parts.first == "registry" && parts.length >= 3

          if parts[1].match?(/\Av\d/)
            ["", parts[2]]
          else
            [(parts[1]).to_s, parts[3]]
          end
        end

        def initialize(groups, hash:, path: nil)
          @groups = groups
          @hash = hash
          @path = path
        end

        # The store behind every resource group, encrypted.
        def wrap(store)
          @groups.reverse.reduce(store) do |inner, group|
            EncryptedStore.new(inner, transformer: group.transformer, resources: group.names, key_matcher: group.matcher)
          end
        end

        # A reload swaps the transformers of a wrapped chain in place: every
        # EncryptedStore takes the transformer of the group with the same
        # names, so the new keys are used for the next writes and reads.
        def apply_to(wrapped)
          layer = wrapped
          while layer.is_a?(EncryptedStore)
            group = @groups.find { |candidate| candidate.names == layer.resources }
            layer.transformer = group.transformer if group
            layer = layer.store
          end
          wrapped
        end
      end

      # --encryption-provider-config-automatic-reload: the file is re-read
      # when it changes (polled once a minute) and the transformers swapped;
      # apiserver_encryption_config_controller_automatic_reloads_total{status}
      # and _last_timestamp_seconds count it, _last_config_info shows the
      # active file's hash.
      class ReloadController
        POLL_INTERVAL = 60.0

        def initialize(path:, wrapped:, interval: POLL_INTERVAL, logger: nil, clock: -> { Time.now.to_f })
          @path = path
          @wrapped = wrapped
          @interval = interval
          @logger = logger
          @clock = clock
          @mutex = Mutex.new
          @last_hash = nil
          @thread = nil
          @stop = false
        end

        def note_loaded(configuration)
          @last_hash = configuration.hash
          # A "Custom" collector upstream: registered here, not from the inventory.
          registry = Encryption.metrics
          if registry && !registry.registered?("apiserver_encryption_config_controller_last_config_info")
            registry.register("apiserver_encryption_config_controller_last_config_info", type: :gauge,
                                                                                         help: "Information about the last applied encryption configuration with hash as label, split by apiserver identity.")
          end
          Encryption.set("apiserver_encryption_config_controller_last_config_info", 1,
                         {"apiserver_id_hash" => Encryption.apiserver_id_hash, "hash" => "sha256:#{configuration.hash}"})
        end

        def check!
          bytes = File.binread(@path)
          hash = Digest::SHA256.hexdigest(bytes)
          return false if hash == @last_hash

          configuration = Configuration.load(@path)
          configuration.apply_to(@wrapped)
          previous = @last_hash
          note_loaded(configuration)
          if previous
            Encryption.metrics&.delete("apiserver_encryption_config_controller_last_config_info",
                                       {"apiserver_id_hash" => Encryption.apiserver_id_hash, "hash" => "sha256:#{previous}"})
          end
          record("success")
          @logger&.call(:info, "encryption.config.reloaded", hash: hash)
          true
        rescue StandardError => error
          record("failure")
          @logger&.call(:warn, "encryption.config.reload_failed", error: error.class.name, message: error.message.to_s[0, 300])
          false
        end

        def start
          @mutex.synchronize do
            return self if @thread&.alive?

            @stop = false
            @thread = Thread.new do
              Thread.current.name = "encryption-config-reload"
              until @mutex.synchronize { @stop }
                sleep(@interval)
                check! unless @mutex.synchronize { @stop }
              end
            end
          end
          self
        end

        def stop
          @mutex.synchronize { @stop = true }
          @thread&.join(1)
          self
        end

        private

        def record(status)
          labels = {"apiserver_id_hash" => Encryption.apiserver_id_hash, "status" => status}
          Encryption.increment("apiserver_encryption_config_controller_automatic_reloads_total", labels)
          Encryption.set("apiserver_encryption_config_controller_automatic_reload_last_timestamp_seconds", @clock.call, labels)
        end
      end
    end
  end
end
