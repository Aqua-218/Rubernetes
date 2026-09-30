# frozen_string_literal: true

require "json"
require "psych"
require "timeout"

require_relative "errors"
require_relative "../manifest"

module Rubernetes
  module Client
    # Reads JSON and safe YAML Kubernetes manifests without executing user code.
    class ManifestReader
      DEFAULT_MAX_BYTES = 16 * 1024 * 1024
      DEFAULT_MAX_RESOURCES = 10_000

      # JSON.parse normally overwrites an earlier member with the same name. Kubernetes
      # manifests must not silently change meaning based on parser order, so duplicate members
      # are rejected while the parser is constructing each object.
      class DuplicateKeyHash < Hash
        def []=(key, value)
          raise ManifestError, "duplicate JSON object key #{key.inspect}" if key?(key)

          super
        end
      end

      attr_reader :max_bytes, :max_resources

      def self.load(path, **)
        new(**).load(path)
      end

      def initialize(max_bytes: DEFAULT_MAX_BYTES, max_resources: DEFAULT_MAX_RESOURCES, sandbox: nil, allow_code: false,
                     environment: [], env: ENV)
        @max_bytes = self.class.__send__(:positive_integer, max_bytes, "max_bytes")
        @max_resources = self.class.__send__(:positive_integer, max_resources, "max_resources")
        @sandbox = sandbox
        @allow_code = !!allow_code
        @environment = Array(environment).freeze
        @env = env
      end

      # Returns one or more resource mappings in document order. A List object is expanded.
      def load(path)
        file_path = path.to_s
        raise ManifestError, "manifest path must be a non-empty string" if file_path.empty?
        return load_ruby(file_path) if File.extname(file_path).casecmp?(".rb")

        content = read_file(file_path)
        parse(content, filename: file_path)
      end

      # Reads a manifest from an IO or string. The string form is useful for raw CLI tests.
      def load_content(content, filename: "<memory>")
        raise ManifestError, "manifest content must be a String" unless content.is_a?(String)
        raise ManifestError, "manifest exceeds #{@max_bytes} bytes" if content.bytesize > @max_bytes

        parse(content, filename: filename)
      end

      private

      def load_ruby(path)
        unless @allow_code
          raise RubyManifestIsolationError,
                "Ruby manifest execution requires explicit --allow-code and an isolated child process"
        end
        unless @sandbox && @sandbox.respond_to?(:compile)
          raise RubyManifestIsolationError,
                "Ruby manifest execution requires an isolated child process; no sandbox runner is configured"
        end

        resources = @sandbox.compile(path, allow_code: true, environment: @environment, env: @env)
        normalize_sandbox_resources(resources, path)
      rescue ManifestError
        raise
      rescue Rubernetes::Manifest::Error, ArgumentError, IOError, SystemCallError, Timeout::Error, JSON::ParserError, RuntimeError => error
        raise RubyManifestIsolationError.new("isolated Ruby manifest failed for #{path}: #{error.message}", cause: error), cause: error
      end

      def normalize_sandbox_resources(resources, path)
        raise RubyManifestIsolationError, "isolated Ruby manifest must return an array: #{path}" unless resources.is_a?(Array)
        raise RubyManifestIsolationError, "isolated Ruby manifest exceeds #{@max_resources} resources" if resources.length > @max_resources

        resources.each { |resource| validate_resource_mapping(resource, path) }
        resources
      end

      def self.positive_integer(value, name)
        integer = Integer(value)
        raise ArgumentError, "#{name} must be positive" unless integer.positive?

        integer
      rescue ArgumentError, TypeError => error
        raise ArgumentError, "#{name} must be a positive integer: #{error.message}"
      end

      def read_file(path)
        content = if path == "-"
                    $stdin.read(@max_bytes + 1)
                  else
                    File.binread(path, @max_bytes + 1)
                  end
        raise ManifestError, "manifest exceeds #{@max_bytes} bytes: #{path}" if content.bytesize > @max_bytes

        content
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR => error
        raise ManifestError.new("cannot read manifest #{path}: #{error.message}", cause: error), cause: error
      end

      def parse(content, filename:)
        parsed = if json_file?(filename, content)
                   parse_json(content, filename)
                 else
                   parse_yaml_documents(content, filename)
                 end
        resources = parsed.flat_map { |document| normalize_document(document, filename) }
        raise ManifestError, "manifest contains no resources: #{filename}" if resources.empty?
        raise ManifestError, "manifest contains more than #{@max_resources} resources" if resources.length > @max_resources

        resources
      end

      def json_file?(filename, content)
        return true if File.extname(filename).casecmp?(".json")

        stripped = content.lstrip
        stripped.start_with?("{", "[")
      end

      def parse_json(content, filename)
        value = JSON.parse(content, object_class: DuplicateKeyHash, max_nesting: 512)
        [value]
      rescue JSON::ParserError => error
        raise ManifestError.new("cannot parse JSON manifest #{filename}: #{error.message}", cause: error), cause: error
      rescue ManifestError => error
        raise ManifestError.new("cannot parse JSON manifest #{filename}: #{error.message}", cause: error), cause: error
      end

      def parse_yaml_documents(content, filename)
        class_loader = Psych::ClassLoader::Restricted.new([], [])
        scanner = Psych::ScalarScanner.new(class_loader)
        visitor = Psych::Visitors::NoAliasRuby.new(scanner, class_loader)
        documents = []
        Psych.parse_stream(content, filename: filename) do |document|
          reject_duplicate_yaml_keys(document, filename)
          documents << visitor.accept(document)
        end
        documents
      rescue ManifestError
        raise
      rescue Psych::Exception => error
        raise ManifestError.new("cannot parse YAML manifest #{filename}: #{error.message}", cause: error), cause: error
      end

      def reject_duplicate_yaml_keys(node, filename)
        case node
        when Psych::Nodes::Document, Psych::Nodes::Sequence
          node.children.each { |child| reject_duplicate_yaml_keys(child, filename) }
        when Psych::Nodes::Mapping
          seen = {}
          node.children.each_slice(2) do |key_node, value_node|
            key = key_node.is_a?(Psych::Nodes::Scalar) ? key_node.value : nil
            raise ManifestError, "duplicate YAML mapping key #{key.inspect}: #{filename}" if key && seen.key?(key)

            seen[key] = true if key
            reject_duplicate_yaml_keys(key_node, filename)
            reject_duplicate_yaml_keys(value_node, filename)
          end
        end
      end

      def normalize_document(document, filename)
        case document
        when Array
          document.flat_map { |item| normalize_document(item, filename) }
        when Hash
          if document["kind"].to_s.end_with?("List") && document.key?("items")
            items = document["items"]
            raise ManifestError, "manifest List items must be an array: #{filename}" unless items.is_a?(Array)

            items.flat_map { |item| normalize_document(item, filename) }
          else
            validate_resource_mapping(document, filename)
            [document]
          end
        else
          raise ManifestError, "manifest document must be an object or array: #{filename}"
        end
      end

      def validate_resource_mapping(resource, filename)
        resource.each_key do |key|
          raise ManifestError, "manifest field names must be strings: #{filename}" unless key.is_a?(String)
        end
      end
    end

    ManifestLoader = ManifestReader
  end
end
