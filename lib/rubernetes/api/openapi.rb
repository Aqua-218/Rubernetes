# frozen_string_literal: true

require "digest"
require "json"
require "uri"
require_relative "crd/openapi_metadata"
require_relative "crd/openapi_routes"
require_relative "crd/openapi_v2_routes"
require_relative "crd/openapi_references"

module Rubernetes
  module API
    # Read-only access to generated OpenAPI documents.
    #
    # The repository maps only the Kubernetes OpenAPI endpoints to fixed
    # artifact names. It never follows a link supplied by a request and it
    # rejects symlinked path components before reading an artifact.
    class OpenAPIRepository
      DEFAULT_ROOT = File.expand_path("../../../generated/openapi", __dir__).freeze

      def initialize(root: DEFAULT_ROOT)
        @root = File.expand_path(root.to_s)
        @dynamic = {}
        @dynamic_index = {}
        @group_encodings = {}
        @dynamic_v2 = {}
        # One group/version can be served by several CustomResourceDefinitions
        # -- the conformance spec "works for multiple CRDs of same group and
        # version but different kinds" registers exactly that.  Keeping one
        # document per group/version meant the second CRD replaced the first
        # and only the last kind was ever published.
        @dynamic_owners = {}
        @mutex = Mutex.new
        # Bumped on every publish/withdraw.  The merged swagger document is
        # rebuilt only when it changes: with CustomResourceDefinitions present
        # every /openapi/v2 request used to deep-copy the 3 MB document.
        @generation = 0
        @merged = {}
        @static = {}
      end

      attr_reader :generation, :root

      def document_for(path)
        relative = relative_path(path)
        return nil if relative.nil?

        dynamic = @mutex.synchronize { @dynamic[relative] }
        return dynamic if dynamic

        if ["v3/index.json", "v2.json"].include?(relative)
          generation = @mutex.synchronize { @generation }
          cached = @mutex.synchronize { @merged[relative] }
          return cached.last if cached && cached.first == generation

          base = static_document(relative)
          merged = relative == "v2.json" ? v2_with_dynamic(base) : v3_index_with_dynamic(base)
          @mutex.synchronize { @merged[relative] = [generation, merged] }
          return merged
        end

        static_document(relative)
      end

      # An in-flight encoding may finish after the CRD is withdrawn. Its local
      # cache then falls out of scope with the request, along with the bytes.
      def encoded_group(path, document, format)
        relative = relative_path(path)
        cache = @mutex.synchronize do
          @group_encodings[relative] ||= {} if (@dynamic[relative] || @static[relative]).equal?(document)
        end
        return yield unless cache

        cached = @mutex.synchronize { cache[format] }
        return cached if cached

        encoded = yield
        @mutex.synchronize { cache[format] ||= encoded }
      end

      # The shipped documents never change while the server runs; each is
      # parsed once and the same (frozen) object is handed out, which also
      # lets the server keep its encoding and ETag.
      def static_document(relative)
        cached = @mutex.synchronize { @static[relative] if @static.key?(relative) }
        return cached if cached

        document = read_document(relative)
        return nil if document.nil?

        document = deep_freeze(document)
        @mutex.synchronize { @static[relative] = document }
      end

      # Publish or withdraw a dynamically served group/version document
      # (CustomResourceDefinitions, aggregated APIs).
      def publish(group:, version:, document:, owner: nil)
        key = "#{group}/#{version}"
        @mutex.synchronize do
          owners = (@dynamic_owners[key] ||= {})
          owners[owner.to_s.empty? ? key : owner.to_s] = document
          refresh_dynamic_locked(key, owners)
          @generation += 1
        end
      end

      def withdraw(group:, version:, owner: nil)
        key = "#{group}/#{version}"
        @mutex.synchronize do
          owners = @dynamic_owners[key]
          next if owners.nil?

          owner.to_s.empty? ? owners.clear : owners.delete(owner.to_s)
          @generation += 1
          if owners.empty?
            @dynamic_owners.delete(key)
            @dynamic.delete("v3/apis/#{key}.json")
            @group_encodings.delete("v3/apis/#{key}.json")
            @dynamic_index.delete("apis/#{key}")
            @dynamic_v2.delete(key)
          else
            refresh_dynamic_locked(key, owners)
          end
        end
      end

      # The document +owner+ published for a group/version, and whether any
      # owner serves the group/version (the CRD OpenAPI controllers'
      # specsByGVandName).
      def owner_document(group:, version:, owner:)
        @mutex.synchronize { @dynamic_owners["#{group}/#{version}"]&.[](owner.to_s) }
      end

      def group_version_published?(group:, version:)
        @mutex.synchronize { !@dynamic_owners["#{group}/#{version}"].to_h.empty? }
      end

      def dynamic_paths
        @mutex.synchronize { @dynamic.keys.map { |relative| relative.delete_suffix(".json").delete_prefix("v3/") } }
      end

      private

      # Every CRD that serves this group/version contributes its paths and
      # schemas to one document.
      def refresh_dynamic_locked(key, owners)
        documents = owners.values.grep(Hash)
        merged = documents.first ? JSON.parse(JSON.generate(documents.first)) : {}
        documents.drop(1).each do |document|
          merged["paths"] = (merged["paths"] || {}).merge(document["paths"] || {})
          schemas = (merged.dig("components", "schemas") || {}).merge(document.dig("components", "schemas") || {})
          merged["components"] = (merged["components"] || {}).merge("schemas" => schemas)
        end
        # kube-apiserver serves custom resources in the classic swagger
        # document too; the CustomResourcePublishOpenAPI specs poll
        # /openapi/v2 for the definition and its schema.  Only the CRD's own
        # schemas: v2.json already carries the shared meta definitions.
        components = merged["components"] ||= {}
        schemas = components["schemas"] || {}
        @dynamic_v2[key] = {schemas: schemas, paths: merged.fetch("paths", {})}
        components["schemas"] = schemas.transform_values { |schema| CRD::OpenAPIMetadata.with_embedded(schema, v2: false) }
        add_referenced_components(merged)
        CRD::OpenAPIRoutes.add_delete_options_gvks(merged) { @static["v2.json"] ||= deep_freeze(read_document("v2.json")) }
        bytes = JSON.generate(merged)
        hash = Digest::SHA512.hexdigest(bytes).upcase
        @group_encodings["v3/apis/#{key}.json"] = {json: [bytes, hash]}
        @dynamic_index["apis/#{key}"] = {"serverRelativeURL" => "/openapi/v3/apis/#{key}?hash=#{hash}"}
        @dynamic["v3/apis/#{key}.json"] = merged
      end

      # apiextensions-apiserver publishes a CRD document that resolves on its
      # own: ObjectMeta, ListMeta and everything they reference travel with
      # it.  Without them the metadata $ref dangled and `kubectl explain
      # <crd>.metadata` printed no FIELDS -- "[sig-api-machinery]
      # CustomResourcePublishOpenAPI works for CRD with validation schema"
      # looks for creationTimestamp there.
      def add_referenced_components(document)
        schemas = (document["components"] ||= {})["schemas"] ||= {}
        shared = shared_components
        pending = []
        document["paths"] = CRD::OpenAPIReferences.routes(document["paths"], pending) if document["paths"]
        schemas.transform_values! { |schema| CRD::OpenAPIReferences.v3(schema, pending) }
        until pending.empty?
          name = pending.pop
          next if schemas.key?(name) || !shared.key?(name)

          schemas[name] = CRD::OpenAPIReferences.v3(shared.fetch(name), pending)
        end
        document
      end

      def shared_components
        @shared_components ||= (@static["v3/api/v1.json"] || read_document("v3/api/v1.json") || {}).dig("components", "schemas") || {}
      end

      def relative_path(path)
        segments = path.to_s.split("/").reject(&:empty?).map do |segment|
          URI::RFC2396_PARSER.unescape(segment)
        end
        return nil unless segments.first == "openapi"

        segments = segments.drop(1)
        return "v2.json" if segments == ["v2"]
        return "v3/index.json" if segments == ["v3"]
        return "v3/api/#{segments[2]}.json" if segments.length == 3 && segments.first(2) == %w[v3 api]
        return "v3/apis/#{segments[2]}/#{segments[3]}.json" if segments.length == 4 && segments.first(2) == %w[v3 apis]
        return "v3/apis/#{segments[2]}.json" if segments.length == 3 && segments.first(2) == %w[v3 apis]
        return "v3/#{segments[1]}.json" if segments.length == 2 && %w[api apis version logs].include?(segments[1])
        return "v3/openid/v1/jwks.json" if segments == %w[v3 openid v1 jwks]
        return "v3/.well-known/openid-configuration.json" if segments == %w[v3 .well-known openid-configuration]

        nil
      rescue URI::InvalidURIError
        nil
      end

      def v2_with_dynamic(document)
        overlays = @mutex.synchronize { @dynamic_v2.values }
        return document if overlays.empty? || document.nil?

        definitions = document.fetch("definitions", {}).dup
        paths = document.fetch("paths", {}).dup
        routes = CRD::OpenAPIV2Routes.new(document.fetch("parameters", {}))
        overlays.each do |overlay|
          overlay[:schemas].each { |name, schema| definitions[name] = CRD::OpenAPIReferences.v2(v2_definition(schema)) }
          paths.merge!(routes.convert(overlay[:paths]))
        end
        document.merge("definitions" => definitions, "paths" => paths)
      end

      # apiextensions-apiserver/pkg/controller/openapi/builder buildKubeNative:
      # a custom resource whose ROOT schema preserves unknown fields is
      # published to swagger 2.0 as a bare `type: object`, with no properties
      # at all -- not even apiVersion/kind/metadata, because kubectl would then
      # reject every other field.  Only the group-version-kind marker survives.
      def v2_definition(schema)
        unless schema.is_a?(Hash) && schema["x-kubernetes-preserve-unknown-fields"] == true
          return CRD::OpenAPIMetadata.with_embedded(v2_structural(schema), v2: true)
        end

        bare = {"type" => "object"}
        %w[x-kubernetes-group-version-kind x-kubernetes-selectable-fields].each do |extension|
          bare[extension] = schema[extension] if schema.key?(extension)
        end
        bare
      end

      # apiextensions-apiserver/pkg/controller/openapi/v2 ToStructuralOpenAPIV2:
      # swagger 2.0 cannot express everything a CRD's structural schema can, and
      # kubectl validates client-side against exactly this document.  A schema
      # that keeps `properties` next to x-kubernetes-preserve-unknown-fields
      # makes kubectl reject every field the CRD deliberately allows -- which is
      # what "CustomResourcePublishOpenAPI works for CRD preserving unknown
      # fields in a nested object" checks.  The rules are applied top-down,
      # because a parent's `required` filtering reads its children's nullable
      # flag before the child clears it.
      def v2_structural(schema)
        return schema unless schema.is_a?(Hash)

        node = schema.dup
        %w[allOf oneOf anyOf not].each { |key| node.delete(key) }
        if node["nullable"] == true
          node.delete("type")
          node.delete("nullable")
          node.delete("items")
          node.delete("properties")
        end
        preserve = node["x-kubernetes-preserve-unknown-fields"] == true
        if preserve
          node.delete("items")
          node.delete("properties")
        end
        node.delete("type") if node["type"] == "array" && !node.key?("items")
        node.delete("type") if preserve && node["type"] == "object"
        node["required"] = v2_required(node) if node["required"].is_a?(Array)
        node.delete("required") if node["required"].is_a?(Array) && node["required"].empty?
        node["properties"] = node["properties"].transform_values { |value| v2_structural(value) } if node["properties"].is_a?(Hash)
        node["items"] = v2_structural(node["items"]) if node["items"].is_a?(Hash)
        node["additionalProperties"] = v2_structural(node["additionalProperties"]) if node["additionalProperties"].is_a?(Hash)
        node
      end

      # A nullable property loses its type in v2, and kubectl cannot require a
      # field it has no schema for, so the requirement goes with it.
      def v2_required(node)
        properties = node["properties"].is_a?(Hash) ? node["properties"] : {}
        additional = node["additionalProperties"]
        return [] if additional.is_a?(Hash) && additional["nullable"] == true

        node["required"].reject do |name|
          properties[name].is_a?(Hash) && properties[name]["nullable"] == true
        end
      end

      def v3_index_with_dynamic(index)
        @mutex.synchronize do
          return index if @dynamic_index.empty?

          {"paths" => (index || {}).fetch("paths", {}).merge(@dynamic_index)}
        end
      end

      def deep_freeze(value)
        case value
        when Hash then value.each_value { |child| deep_freeze(child) }
        when Array then value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end

      def read_document(relative)
        components = relative.split("/")
        return nil if components.empty? || components.any? { |component| unsafe_component?(component) }

        root_stat = File.lstat(@root)
        return nil unless root_stat.directory? && !root_stat.symlink?

        target = @root
        components.each do |component|
          target = File.join(target, component)
          stat = File.lstat(target)
          return nil if stat.symlink?
        end
        return nil unless File.file?(target)

        root_real = File.realpath(@root)
        target_real = File.realpath(target)
        return nil unless target_real == root_real || target_real.start_with?("#{root_real}#{File::SEPARATOR}")

        JSON.parse(File.binread(target_real))
      rescue Errno::ENOENT, Errno::EACCES, Errno::ELOOP, Errno::ENOTDIR, JSON::ParserError
        nil
      end

      def unsafe_component?(component)
        component.empty? || component == "." || component == ".." ||
          component.include?("/") || component.include?("\\") || component.include?("\0")
      end
    end
  end
end
