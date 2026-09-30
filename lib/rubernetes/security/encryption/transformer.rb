# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"
require "securerandom"

require_relative "../identity"

module Rubernetes
  module Security
    module Encryption
      class Error < Security::Error; end

      # Envelope encryption at rest (spec 5.1.8).  Every object gets its own
      # data encryption key (DEK); the DEK is wrapped by the key encryption
      # key held by the provider.  Providers are tried in order for reads
      # (prefix routing), the first configured provider writes.  A failure to
      # encrypt raises and nothing is stored.
      class AESGCMProvider
        PREFIX = "k8s:enc:aesgcm:v1:"
        NONCE_BYTES = 12

        Key = Struct.new(:name, :secret)

        def initialize(keys:)
          @keys = Array(keys).map { |key| Key.new(key.fetch("name"), decode_secret(key.fetch("secret"))) }
          raise Error, "aesgcm provider needs at least one key" if @keys.empty?
        end

        def name
          "aesgcm"
        end

        def prefix
          PREFIX
        end

        def key_ids
          @keys.map(&:name)
        end

        # Returns "k8s:enc:aesgcm:v1:<keyname>:<base64(nonce||ciphertext||tag)>"
        def encrypt(plaintext, associated_data)
          key = @keys.first
          cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
          cipher.key = key.secret
          nonce = SecureRandom.random_bytes(NONCE_BYTES)
          cipher.iv = nonce
          cipher.auth_data = associated_data
          ciphertext = cipher.update(plaintext) + cipher.final
          "#{PREFIX}#{key.name}:#{Base64.strict_encode64(nonce + ciphertext + cipher.auth_tag)}"
        end

        def decrypt(envelope, associated_data)
          raise Error, "envelope is not an aesgcm envelope" unless envelope.start_with?(PREFIX)

          key_name, payload = envelope.delete_prefix(PREFIX).split(":", 2)
          key = @keys.find { |candidate| candidate.name == key_name }
          raise Error, "no aesgcm key named #{key_name.inspect}" if key.nil?

          bytes = Base64.strict_decode64(payload)
          nonce = bytes.byteslice(0, NONCE_BYTES)
          tag = bytes.byteslice(-16, 16)
          ciphertext = bytes.byteslice(NONCE_BYTES, bytes.bytesize - NONCE_BYTES - 16)
          cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
          cipher.key = key.secret
          cipher.iv = nonce
          cipher.auth_tag = tag
          cipher.auth_data = associated_data
          cipher.update(ciphertext) + cipher.final
        rescue OpenSSL::Cipher::CipherError, ArgumentError => error
          raise Error, "aesgcm decryption failed: #{error.message}"
        end

        def current_key?(envelope)
          envelope.start_with?("#{PREFIX}#{@keys.first.name}:")
        end

        private

        def decode_secret(value)
          secret = Base64.strict_decode64(value)
          raise Error, "aesgcm key must be 32 bytes (AES-256)" unless secret.bytesize == 32

          secret
        rescue ArgumentError
          raise Error, "aesgcm key must be base64"
        end
      end

      # Kubernetes KMS v2 (k8s.io/kms/apis/v2): Status, Encrypt, Decrypt over
      # gRPC on a Unix socket.  A per-object DEK is generated locally,
      # wrapped by the KMS, and stored alongside the ciphertext.
      class KMSv2Provider
        PREFIX = "k8s:enc:kms:v2:"

        def initialize(name:, endpoint:, client: nil, timeout: 3, cache_size: 1000)
          @name = name
          @endpoint = endpoint
          @client = client || GRPCClient.new(endpoint: endpoint, timeout: timeout)
          @dek_cache = {}
          @mutex = Mutex.new
          @cache_size = cache_size
          @last_miss_at = nil
        end

        attr_reader :name

        def prefix
          "#{PREFIX}#{@name}:"
        end

        def key_ids
          [status.fetch("key_id")]
        end

        def status
          @client.status
        end

        def encrypt(plaintext, associated_data)
          dek = SecureRandom.random_bytes(32)
          nonce = SecureRandom.random_bytes(12)
          cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
          cipher.key = dek
          cipher.iv = nonce
          cipher.auth_data = associated_data
          ciphertext = cipher.update(plaintext) + cipher.final
          wrapped = @client.encrypt(dek, uid: SecureRandom.uuid)
          envelope = {"encryptedDEK" => Base64.strict_encode64(wrapped.fetch("ciphertext")), "keyID" => wrapped.fetch("key_id"),
                      "annotations" => wrapped.fetch("annotations", {}), "nonce" => Base64.strict_encode64(nonce),
                      "ciphertext" => Base64.strict_encode64(ciphertext + cipher.auth_tag)}
          "#{prefix}#{Base64.strict_encode64(JSON.generate(envelope))}"
        end

        def decrypt(envelope, associated_data)
          raise Error, "envelope is not a kms v2 envelope for #{@name}" unless envelope.start_with?(prefix)

          document = JSON.parse(Base64.strict_decode64(envelope.delete_prefix(prefix)))
          wrapped = Base64.strict_decode64(document.fetch("encryptedDEK"))
          dek = @mutex.synchronize { @dek_cache[wrapped] }
          if dek.nil?
            dek = @client.decrypt(wrapped, uid: SecureRandom.uuid, key_id: document.fetch("keyID"), annotations: document.fetch("annotations", {}))
            @mutex.synchronize do
              @dek_cache[wrapped] = dek
              @dek_cache.shift while @dek_cache.length > @cache_size
            end
          end
          bytes = Base64.strict_decode64(document.fetch("ciphertext"))
          cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
          cipher.key = dek
          cipher.iv = Base64.strict_decode64(document.fetch("nonce"))
          cipher.auth_tag = bytes.byteslice(-16, 16)
          cipher.auth_data = associated_data
          cipher.update(bytes.byteslice(0, bytes.bytesize - 16)) + cipher.final
        rescue OpenSSL::Cipher::CipherError, ArgumentError, JSON::ParserError, KeyError => error
          raise Error, "kms v2 decryption failed: #{error.message}"
        end

        def current_key?(envelope)
          document = JSON.parse(Base64.strict_decode64(envelope.delete_prefix(prefix)))
          document["keyID"] == status.fetch("key_id")
        rescue StandardError
          false
        end

        # Minimal gRPC/HTTP2 client for the KMS v2 service over a Unix socket
        # using the `grpc` gem already required by the CSI client.
        class GRPCClient
          SERVICE = "v2.KeyManagementService"

          def initialize(endpoint:, timeout:)
            require "grpc"
            @endpoint = endpoint.sub(%r{\Aunix://}, "unix:")
            @timeout = timeout
            @stub = GRPC::ClientStub.new(@endpoint, :this_channel_is_insecure, timeout: timeout)
          end

          def status
            response = call("Status", encode_status_request)
            decode_status_response(response)
          end

          def encrypt(plaintext, uid:)
            response = call("Encrypt", encode_encrypt_request(plaintext, uid))
            decode_encrypt_response(response)
          end

          def decrypt(ciphertext, uid:, key_id:, annotations:)
            response = call("Decrypt", encode_decrypt_request(ciphertext, uid, key_id, annotations))
            decode_decrypt_response(response)
          end

          private

          def call(method, request_bytes)
            marshal = ->(value) { value }
            unmarshal = ->(value) { value }
            @stub.request_response("/#{SERVICE}/#{method}", request_bytes, marshal, unmarshal, deadline: Time.now + @timeout)
          rescue GRPC::BadStatus => error
            raise Error, "kms v2 #{method} failed: #{error.message}"
          end

          # Hand-rolled protobuf encoding for the four small messages.
          def varint(value)
            bytes = "".b
            loop do
              byte = value & 0x7f
              value >>= 7
              if value.zero?
                bytes << byte.chr
                break
              end
              bytes << (byte | 0x80).chr
            end
            bytes
          end

          def field(number, bytes)
            varint((number << 3) | 2) + varint(bytes.bytesize) + bytes
          end

          def encode_status_request = "".b
          def encode_encrypt_request(plaintext, uid) = field(1, plaintext) + field(2, uid)

          def encode_decrypt_request(ciphertext, uid, key_id, annotations)
            body = field(1, ciphertext) + field(2, uid) + field(3, key_id)
            annotations.each { |key, value| body << field(4, field(1, key) + field(2, Base64.strict_decode64(value.to_s))) }
            body
          end

          def parse(bytes)
            fields = Hash.new { |hash, key| hash[key] = [] }
            offset = 0
            while offset < bytes.bytesize
              tag, offset = read_varint(bytes, offset)
              number = tag >> 3
              wire = tag & 7
              case wire
              when 0
                value, offset = read_varint(bytes, offset)
                fields[number] << value
              when 2
                length, offset = read_varint(bytes, offset)
                fields[number] << bytes.byteslice(offset, length)
                offset += length
              else
                raise Error, "unsupported protobuf wire type #{wire}"
              end
            end
            fields
          end

          def read_varint(bytes, offset)
            value = 0
            shift = 0
            loop do
              byte = bytes.getbyte(offset)
              raise Error, "truncated protobuf" if byte.nil?

              offset += 1
              value |= (byte & 0x7f) << shift
              break if (byte & 0x80).zero?

              shift += 7
            end
            [value, offset]
          end

          def decode_status_response(bytes)
            fields = parse(bytes)
            {"version" => fields[1].first.to_s, "healthz" => fields[2].first.to_s, "key_id" => fields[3].first.to_s}
          end

          def decode_encrypt_response(bytes)
            fields = parse(bytes)
            annotations = fields[3].each_with_object({}) do |entry, hash|
              pair = parse(entry)
              hash[pair[1].first.to_s] = Base64.strict_encode64(pair[2].first.to_s)
            end
            {"ciphertext" => fields[1].first.to_s, "key_id" => fields[2].first.to_s, "annotations" => annotations}
          end

          def decode_decrypt_response(bytes)
            parse(bytes)[1].first.to_s
          end
        end
      end

      # Routes envelopes to providers and rewrites stale envelopes.
      class Transformer
        IDENTITY_PREFIX = "".freeze

        def initialize(providers:)
          @providers = Array(providers)
          raise Error, "encryption transformer needs at least one provider" if @providers.empty?
        end

        def writer
          @providers.first
        end

        def encrypt(plaintext, associated_data)
          writer.encrypt(plaintext, associated_data)
        end

        def decrypt(envelope, associated_data)
          provider = @providers.find { |candidate| envelope.start_with?(candidate.prefix) }
          raise Error, "no encryption provider matches the stored envelope" if provider.nil?

          [provider.decrypt(envelope, associated_data), provider.equal?(writer) && provider.current_key?(envelope)]
        end
      end

      # Store wrapper: encrypts configured resources before they reach the
      # durable store and decrypts them on the way out.  Object metadata stays
      # in the clear so keys, selectors and watch history work; every other
      # top-level field is sealed in one envelope bound to the storage key
      # (authenticated data), so a ciphertext moved between keys fails to
      # decrypt.
      class EncryptedStore
        ENVELOPE_KEY = "__encrypted__".freeze
        CLEAR_FIELDS = %w[apiVersion kind metadata].freeze

        def initialize(store, transformer:, resources:, key_matcher: nil)
          @store = store
          @transformer = transformer
          @resources = Array(resources).map(&:to_s)
          @key_matcher = key_matcher || ->(key) { @resources.any? { |resource| key.to_s.start_with?("registry/#{resource}/") || key.to_s.include?("/#{resource}/") } }
        end

        attr_reader :store

        def encrypted_key?(key)
          @key_matcher.call(key)
        end

        def create(key, object = nil, **options)
          @store.create(key, seal(key, object || options[:object] || options[:body]), **options.reject { |name, _| %i[object body].include?(name) })
              .then { |result| unseal(key, result) }
        end

        def update(key, object = nil, **options)
          @store.update(key, seal(key, object || options[:object] || options[:body]), **options.reject { |name, _| %i[object body].include?(name) })
                .then { |result| unseal(key, result) }
        end

        def guaranteed_update(key, **options, &block)
          result = @store.guaranteed_update(key, **options) do |current|
            candidate = block.call(unseal(key, current))
            candidate.nil? ? nil : seal(key, candidate)
          end
          unseal(key, result)
        end

        def get(key, **options)
          unseal(key, @store.get(key, **options))
        end

        def delete(key, **options)
          unseal(key, @store.delete(key, **options))
        end

        def list(prefix = "", **options)
          result = @store.list(prefix, **options)
          return result unless result.respond_to?(:items)

          items = result.items.map { |item| unseal(key_of(prefix, item), item) }
          Rubernetes::Storage::ListResult.new(items: items, resource_version: result.resource_version, continue_token: result.continue_token,
                                              remaining_item_count: result.remaining_item_count)
        end

        def watch(prefix = "", *positional, **options)
          stream = @store.watch(prefix, *positional, **options)
          DecryptingWatch.new(stream, self, prefix)
        end

        def method_missing(name, *arguments, **keywords, &block)
          return super unless @store.respond_to?(name)

          @store.public_send(name, *arguments, **keywords, &block)
        end

        def respond_to_missing?(name, include_private = false)
          @store.respond_to?(name, include_private) || super
        end

        def seal(key, object)
          return object unless object.is_a?(Hash) && encrypted_key?(key)
          return object if object.key?(ENVELOPE_KEY)

          clear = object.select { |field, _| CLEAR_FIELDS.include?(field) }
          sealed = object.reject { |field, _| CLEAR_FIELDS.include?(field) }
          clear.merge(ENVELOPE_KEY => @transformer.encrypt(JSON.generate(sealed), key.to_s))
        end

        def unseal(key, object)
          return object unless object.is_a?(Hash) && object.key?(ENVELOPE_KEY)

          plaintext, _current = @transformer.decrypt(object[ENVELOPE_KEY], key.to_s)
          restored = object.reject { |field, _| field == ENVELOPE_KEY }.merge(JSON.parse(plaintext))
          object.frozen? ? Rubernetes::Storage::MemoryStoreSupport.deep_freeze(restored) : restored
        end

        # Key rotation: rewrite objects sealed with a non-current key.
        def rewrite_stale!(prefix)
          rewritten = 0
          @store.list(prefix).items.each do |item|
            next unless item.is_a?(Hash) && item.key?(ENVELOPE_KEY)

            key = key_of(prefix, item)
            _plaintext, current = @transformer.decrypt(item[ENVELOPE_KEY], key)
            next if current

            @store.guaranteed_update(key, prec: item.dig("metadata", "resourceVersion")) { |stored| seal(key, unseal(key, stored)) }
            rewritten += 1
          end
          rewritten
        end

        def key_of(prefix, item)
          namespace = item.dig("metadata", "namespace")
          name = item.dig("metadata", "name")
          base = prefix.to_s.chomp("/")
          if namespace && !base.end_with?("/#{namespace}")
            "#{base}/#{namespace}/#{name}"
          elsif namespace.nil? && !base.end_with?("/_cluster")
            "#{base}/_cluster/#{name}"
          else
            "#{base}/#{name}"
          end
        end

        class DecryptingWatch
          include Enumerable

          def initialize(stream, store, prefix)
            @stream = stream
            @store = store
            @prefix = prefix
          end

          def next(timeout: nil)
            translate(timeout.nil? ? @stream.next : @stream.next(timeout: timeout))
          end

          def each(timeout: :default, &block)
            return enum_for(:each, timeout: timeout) unless block

            if timeout == :default
              @stream.each { |event| block.call(translate(event)) }
            else
              @stream.each(timeout: timeout) { |event| block.call(translate(event)) }
            end
            self
          end

          def to_a(timeout: :default)
            (timeout == :default ? @stream.to_a : @stream.to_a(timeout: timeout)).map { |event| translate(event) }
          end

          def each_json_line(timeout: :default, &block)
            each(timeout: timeout) { |event| block.call(JSON.generate(event.to_h)) }
          end

          def method_missing(name, *arguments, **keywords, &block)
            return super unless @stream.respond_to?(name)

            @stream.public_send(name, *arguments, **keywords, &block)
          end

          def respond_to_missing?(name, include_private = false)
            @stream.respond_to?(name, include_private) || super
          end

          private

          def translate(event)
            return event unless event.respond_to?(:object) && event.object.is_a?(Hash) && event.object.key?(ENVELOPE_KEY)

            key = event.respond_to?(:key) && event.key ? event.key : @store.key_of(@prefix, event.object)
            Rubernetes::Storage::Event.new(type: event.type, object: @store.unseal(key, event.object), revision: event.revision, key: key)
          end
        end
      end
    end
  end
end
