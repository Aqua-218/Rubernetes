# frozen_string_literal: true

require "json"
require "rbconfig"

require_relative "digest"
require_relative "errors"
require_relative "media_types"
require_relative "strict_json"

module Rubernetes
  module Image
    # Immutable descriptor from an OCI manifest or index.
    class Descriptor
      attr_reader :media_type, :digest, :size, :urls, :annotations, :platform

      def self.from_h(value, allow_platform: true)
        raise ManifestError, "descriptor must be a JSON object" unless value.is_a?(Hash)

        media_type = value["mediaType"] || value[:media_type]
        digest = value["digest"] || value[:digest]
        size = value.key?("size") ? value["size"] : value[:size]
        raise ManifestError, "descriptor mediaType is required" unless media_type.is_a?(String) && !media_type.empty?
        raise ManifestError, "descriptor digest is required" unless digest
        raise ManifestError, "descriptor size must be a non-negative integer" unless size.is_a?(Integer) && size >= 0

        platform = value["platform"] || value[:platform]
        raise ManifestError, "descriptor platform is invalid" if platform && (!allow_platform || !platform.is_a?(Hash))

        new(
          media_type: media_type,
          digest: Digest.parse(digest),
          size: size,
          urls: normalize_urls(value["urls"] || value[:urls]),
          annotations: normalize_hash(value["annotations"] || value[:annotations]),
          platform: platform && normalize_hash(platform)
        )
      rescue DigestError => error
        raise ManifestError.new(error.message, cause: error), cause: error
      end

      def self.normalize_urls(urls)
        return [].freeze if urls.nil?
        raise ManifestError, "descriptor urls must be an array" unless urls.is_a?(Array)

        normalized = urls.map do |url|
          raise ManifestError, "descriptor URL must be a string" unless url.is_a?(String) && !url.empty? && !url.match?(/[\r\n]/)

          url.freeze
        end
        normalized.freeze
      end
      private_class_method :normalize_urls

      def self.normalize_hash(value)
        return {}.freeze if value.nil?
        raise ManifestError, "descriptor metadata must be an object" unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, item), result|
          raise ManifestError, "descriptor metadata keys must be strings" unless key.is_a?(String)

          result[key.freeze] = item.is_a?(String) ? item.freeze : item
        end.freeze
      end
      private_class_method :normalize_hash

      def initialize(media_type:, digest:, size:, urls: [], annotations: {}, platform: nil)
        @media_type = media_type.to_s.freeze
        @digest = Digest.parse(digest)
        @size = Integer(size)
        raise ManifestError, "descriptor size must be non-negative" if @size.negative?

        @urls = urls.map { |url| url.to_s.freeze }.freeze
        @annotations = annotations.dup.freeze
        @platform = platform&.dup&.freeze
        freeze
      rescue ArgumentError, TypeError => error
        raise ManifestError.new("invalid image descriptor: #{error.message}", cause: error), cause: error
      end

      def digest_string
        digest.to_s
      end

      def to_h
        value = {"mediaType" => media_type, "digest" => digest.to_s, "size" => size}
        value["urls"] = urls unless urls.empty?
        value["annotations"] = annotations unless annotations.empty?
        value["platform"] = platform unless platform.nil?
        value.freeze
      end
    end

    # Platform matcher for manifest indexes. Unknown host architectures are not
    # silently mapped to a different architecture because that would run an
    # image with an unverified ABI.
    class Platform
      ARCHITECTURES = {
        "x86_64" => "amd64",
        "amd64" => "amd64",
        "aarch64" => "arm64",
        "arm64" => "arm64",
        "armv8" => "arm64",
        "arm" => "arm",
        "i686" => "386",
        "x86" => "386",
        "ppc64le" => "ppc64le",
        "s390x" => "s390x",
        "riscv64" => "riscv64"
      }.freeze
      OS_NAMES = {
        "linux" => "linux",
        "darwin" => "darwin",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        "mingw" => "windows",
        "mswin" => "windows"
      }.freeze

      attr_reader :os, :architecture, :variant

      def self.current
        host_os = RbConfig::CONFIG.fetch("host_os")
        os = OS_NAMES.find { |key, _value| host_os.include?(key) }&.last || "linux"
        architecture = ARCHITECTURES[RbConfig::CONFIG.fetch("host_cpu")] || RbConfig::CONFIG.fetch("host_cpu")
        new(os: os, architecture: architecture)
      end

      def self.coerce(value = nil, os: nil, architecture: nil, arch: nil, variant: nil)
        if value
          return value if value.is_a?(self)

          raise ManifestError, "platform must be a mapping" unless value.is_a?(Hash)

          os ||= value["os"] || value[:os]
          architecture ||= value["architecture"] || value[:architecture] || value["arch"] || value[:arch]
          variant ||= value["variant"] || value[:variant]

        end
        new(os: os || "linux", architecture: architecture || arch || "amd64", variant: variant)
      end

      def initialize(os:, architecture:, variant: nil)
        normalized_os = OS_NAMES[os.to_s] || os
        normalized_architecture = ARCHITECTURES[architecture.to_s] || architecture
        @os = normalize_component(normalized_os, "platform os")
        @architecture = normalize_component(normalized_architecture, "platform architecture")
        @variant = variant.nil? ? nil : normalize_component(variant, "platform variant")
        freeze
      end

      def matches?(descriptor_platform, require_variant: false)
        return false unless descriptor_platform.is_a?(Hash)

        descriptor_os = descriptor_platform["os"] || descriptor_platform[:os]
        descriptor_architecture = descriptor_platform["architecture"] || descriptor_platform[:architecture]
        descriptor_variant = descriptor_platform["variant"] || descriptor_platform[:variant]
        return false unless descriptor_os.to_s == os && descriptor_architecture.to_s == architecture
        return false if require_variant && variant && descriptor_variant.to_s != variant
        return false if variant && descriptor_variant && descriptor_variant.to_s != variant

        true
      end

      def to_h
        value = {"os" => os, "architecture" => architecture}
        value["variant"] = variant if variant
        value.freeze
      end

      private

      def normalize_component(value, name)
        text = value.to_s
        unless !text.empty? && text.bytesize <= 128 && !text.match?(/[\x00\r\n]/) && !text.match?(/\s/)
          raise ManifestError,
                "#{name} must be a non-empty string"
        end

        text.freeze
      end
    end

    # Immutable parsed OCI image manifest.
    class Manifest
      attr_reader :media_type, :schema_version, :config, :layers, :annotations, :raw, :digest, :index_digest

      def self.parse(value, expected_digest: nil, expected_size: nil, max_bytes: 8 * 1024 * 1024, index_digest: nil)
        raw = value.is_a?(String) ? value.b : JSON.generate(value).b
        raise LimitError, "manifest exceeds the configured byte limit" if raw.bytesize > Integer(max_bytes)

        parsed = value.is_a?(String) ? StrictJSON.parse(raw, max_bytes: max_bytes) : value
        raise ManifestError, "image manifest must be a JSON object" unless parsed.is_a?(Hash)

        actual_digest = Digest.from_bytes(raw)
        if expected_digest && actual_digest != Digest.parse(expected_digest)
          raise DigestMismatch, "image manifest digest does not match the descriptor"
        end
        raise ManifestError, "image manifest size does not match the descriptor" if expected_size && raw.bytesize != Integer(expected_size)

        media_type = parsed["mediaType"]
        raise ManifestError, "image manifest mediaType is unsupported" unless MediaTypes.manifest?(media_type)
        raise ManifestError, "image manifest schemaVersion must be 2" unless parsed["schemaVersion"] == 2

        config = Descriptor.from_h(parsed["config"], allow_platform: false)
        raise ManifestError, "image config mediaType is unsupported" unless MediaTypes.config?(config.media_type)

        layers = parsed["layers"]
        raise ManifestError, "image manifest layers must be an array" unless layers.is_a?(Array)

        normalized_layers = layers.map do |layer|
          descriptor = Descriptor.from_h(layer, allow_platform: false)
          raise ManifestError, "image layer mediaType is unsupported" unless MediaTypes.layer?(descriptor.media_type)

          descriptor
        end.freeze
        new(
          media_type: media_type,
          schema_version: 2,
          config: config,
          layers: normalized_layers,
          annotations: parsed["annotations"].is_a?(Hash) ? parsed["annotations"].dup.freeze : {}.freeze,
          raw: raw.freeze,
          digest: actual_digest,
          index_digest: index_digest
        )
      rescue StrictJSON::Error, JSON::ParserError, TypeError, ArgumentError => error
        raise ManifestError.new("image manifest is not valid JSON: #{error.message}", cause: error), cause: error
      end

      def initialize(media_type:, schema_version:, config:, layers:, annotations: {}, raw: nil, digest: nil, index_digest: nil)
        @media_type = media_type.to_s.freeze
        @schema_version = Integer(schema_version)
        @config = config
        @layers = layers.freeze
        @annotations = annotations.freeze
        @raw = raw&.b&.freeze
        @digest = digest && Digest.parse(digest)
        @index_digest = index_digest && Digest.parse(index_digest)
        freeze
      end

      def index?
        false
      end
    end

    # Immutable parsed OCI image index / Docker manifest list.
    class Index
      attr_reader :media_type, :schema_version, :manifests, :annotations, :raw, :digest

      def self.parse(value, expected_digest: nil, expected_size: nil, max_bytes: 8 * 1024 * 1024)
        raw = value.is_a?(String) ? value.b : JSON.generate(value).b
        raise LimitError, "image index exceeds the configured byte limit" if raw.bytesize > Integer(max_bytes)

        parsed = value.is_a?(String) ? StrictJSON.parse(raw, max_bytes: max_bytes) : value
        raise ManifestError, "image index must be a JSON object" unless parsed.is_a?(Hash)

        actual_digest = Digest.from_bytes(raw)
        if expected_digest && actual_digest != Digest.parse(expected_digest)
          raise DigestMismatch, "image index digest does not match the descriptor"
        end
        raise ManifestError, "image index size does not match the descriptor" if expected_size && raw.bytesize != Integer(expected_size)

        media_type = parsed["mediaType"]
        raise ManifestError, "image index mediaType is unsupported" unless MediaTypes.index?(media_type)
        raise ManifestError, "image index schemaVersion must be 2" unless parsed["schemaVersion"] == 2

        entries = parsed["manifests"]
        raise ManifestError, "image index manifests must be an array" unless entries.is_a?(Array) && !entries.empty?

        descriptors = entries.map do |entry|
          descriptor = Descriptor.from_h(entry)
          unless MediaTypes.manifest?(descriptor.media_type) || MediaTypes.index?(descriptor.media_type)
            raise ManifestError,
                  "index descriptor mediaType is unsupported"
          end
          raise ManifestError, "index descriptor platform is required" unless descriptor.platform

          descriptor
        end
        new(
          media_type: media_type,
          schema_version: 2,
          manifests: descriptors,
          annotations: parsed["annotations"].is_a?(Hash) ? parsed["annotations"].dup.freeze : {}.freeze,
          raw: raw.freeze,
          digest: actual_digest
        )
      rescue StrictJSON::Error, JSON::ParserError, TypeError, ArgumentError => error
        raise ManifestError.new("image index is not valid JSON: #{error.message}", cause: error), cause: error
      end

      def initialize(media_type:, schema_version:, manifests:, annotations: {}, raw: nil, digest: nil)
        @media_type = media_type.to_s.freeze
        @schema_version = Integer(schema_version)
        @manifests = manifests.freeze
        @annotations = annotations.freeze
        @raw = raw&.b&.freeze
        @digest = digest && Digest.parse(digest)
        freeze
      end

      def index?
        true
      end

      def select(platform = nil, os: nil, architecture: nil, arch: nil, variant: nil)
        target = Platform.coerce(platform, os: os, architecture: architecture, arch: arch, variant: variant)
        matches = manifests.select { |descriptor| target.matches?(descriptor.platform) }
        if matches.empty?
          raise ManifestError,
                "image index has no manifest for #{target.os}/#{target.architecture}#{"/#{target.variant}" if target.variant}"
        end
        raise ManifestError, "image index has multiple manifests for the requested platform" if matches.length > 1

        matches.first
      end
      alias select_for select
    end

    module ManifestDocument
      module_function

      def parse(value, expected_digest: nil, expected_size: nil, max_bytes: 8 * 1024 * 1024, index_digest: nil)
        raw = value.is_a?(String) ? value.b : JSON.generate(value).b
        parsed = StrictJSON.parse(raw, max_bytes: max_bytes)
        media_type = parsed.is_a?(Hash) ? parsed["mediaType"] : nil
        if MediaTypes.index?(media_type)
          Index.parse(raw, expected_digest: expected_digest, expected_size: expected_size, max_bytes: max_bytes)
        elsif MediaTypes.manifest?(media_type)
          Manifest.parse(raw, expected_digest: expected_digest, expected_size: expected_size, max_bytes: max_bytes,
                              index_digest: index_digest)
        else
          raise ManifestError, "image document mediaType is unsupported"
        end
      rescue StrictJSON::Error, JSON::ParserError, TypeError => error
        raise ManifestError.new("image document is not valid JSON: #{error.message}", cause: error), cause: error
      end
    end

    Document = ManifestDocument
  end
end
