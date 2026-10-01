# frozen_string_literal: true

module Rubernetes
  module Image
    # Parsed and normalized OCI image reference.
    class Reference
      TAG_PATTERN = /\A[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}\z/
      HOST_PATTERN = /\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::[0-9]{1,5})?\z/
      IPV6_HOST_PATTERN = /\A\[[0-9A-Fa-f:.]+\](?::[0-9]{1,5})?\z/
      COMPONENT_PATTERN = /\A[a-z0-9]+(?:[._-][a-z0-9]+)*\z/

      attr_reader :registry, :repository, :tag, :digest

      def self.parse(value, default_registry: "docker.io", default_tag: "latest")
        return value if value.is_a?(self)
        raise ReferenceError, "image reference must be a non-empty string" unless value.is_a?(String) && !value.empty?

        text = value.strip
        unless text == value && !text.match?(/\s/) && !text.include?("://")
          raise ReferenceError,
                "image reference contains whitespace or a URI scheme"
        end

        name_part, digest_part = text.split("@", 2)
        raise ReferenceError, "image reference contains an invalid digest suffix" if digest_part && (digest_part.empty? || digest_part.include?("@"))

        digest = digest_part && Digest.parse(digest_part)
        components = name_part.split("/", -1)
        first_component = components.first.to_s
        has_registry = components.length > 1 && (first_component.include?(".") || first_component.include?(":") || first_component.casecmp?("localhost"))
        registry = has_registry ? first_component : default_registry
        repository_with_tag = has_registry ? components.drop(1).join("/") : components.join("/")
        tag = nil
        final_component = repository_with_tag.to_s.split("/").last.to_s
        colon = final_component.rindex(":")
        if colon
          tag = final_component[(colon + 1)..]
          repository_with_tag = repository_with_tag[0...-(tag.bytesize + 1)]
        end
        if (registry.to_s.downcase == "docker.io") && !repository_with_tag.include?("/")
          repository_with_tag = "library/#{repository_with_tag}"
        end
        tag ||= default_tag unless digest

        validate_registry!(registry)
        validate_repository!(repository_with_tag)
        raise ReferenceError, "image tag is invalid" if tag && !TAG_PATTERN.match?(tag)
        raise ReferenceError, "image reference must include a tag or digest" if digest.nil? && tag.nil?

        new(registry: registry.downcase, repository: repository_with_tag, tag: tag, digest: digest)
      rescue DigestError => error
        raise ReferenceError.new(error.message, cause: error), cause: error
      end
      class << self
        alias resolve parse
      end

      def self.validate_registry!(registry)
        host = registry.to_s
        valid = HOST_PATTERN.match?(host) || IPV6_HOST_PATTERN.match?(host)
        raise ReferenceError, "image registry is invalid" unless valid

        port = if host.start_with?("[")
                 host[/\]:(\d+)\z/, 1]
               elsif host.count(":") == 1
                 host.split(":", 2).last
               end
        return unless port && port.to_i > 65_535

        raise ReferenceError, "image registry port is invalid"
      end
      private_class_method :validate_registry!

      def self.validate_repository!(repository)
        components = repository.to_s.split("/")
        raise ReferenceError, "image repository is empty" if components.empty? || components.any?(&:empty?)
        raise ReferenceError, "image repository is invalid" unless components.all? { |component| COMPONENT_PATTERN.match?(component) }
        raise ReferenceError, "image repository is too long" if repository.bytesize > 255
      end
      private_class_method :validate_repository!

      def initialize(registry:, repository:, tag: nil, digest: nil)
        self.class.send(:validate_registry!, registry)
        self.class.send(:validate_repository!, repository)
        raise ReferenceError, "image tag is invalid" if tag && !TAG_PATTERN.match?(tag.to_s)

        @registry = registry.to_s.downcase.freeze
        @repository = repository.to_s.freeze
        @tag = tag&.to_s&.freeze
        @digest = digest.nil? ? nil : Digest.parse(digest)
        raise ReferenceError, "image reference requires tag or digest" if @tag.nil? && @digest.nil?

        freeze
      end

      def digest?
        !digest.nil?
      end

      def locator
        digest? ? digest.to_s : tag
      end

      def with_digest(value)
        self.class.new(registry: registry, repository: repository, tag: nil, digest: Digest.parse(value))
      end

      def to_s
        value = "#{registry}/#{repository}"
        value = "#{value}:#{tag}" if tag
        value = "#{value}@#{digest}" if digest
        value
      end
      alias canonical to_s

      def ==(other)
        other.is_a?(self.class) && registry == other.registry && repository == other.repository && tag == other.tag && digest == other.digest
      end
      alias eql? ==

      def hash
        [registry, repository, tag, digest].hash
      end
    end

    OCIReference = Reference
  end
end
