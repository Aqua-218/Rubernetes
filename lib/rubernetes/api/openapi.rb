# frozen_string_literal: true

require "json"
require "uri"

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

      attr_reader :generation

      attr_reader :root

      def document_for(path)
        relative = relative_path(path)
        return nil if relative.nil?

        dynamic = @mutex.synchronize { @dynamic[relative] }
        return dynamic if dynamic
        if relative == "v3/index.json" || relative == "v2.json"
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
        @mutex.synchronize { @dynamic.keys.map { |relative| relative.delete_suffix(".json").sub(%r{\Av3/}, "") } }
      end

      private

      # Every CRD that serves this group/version contributes its paths and
      # schemas to one document.
      def refresh_dynamic_locked(key, owners)
        documents = owners.values.select { |document| document.is_a?(Hash) }
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
        @dynamic_v2[key] = (merged.dig("components", "schemas") || {}).dup
        add_referenced_components(merged)
        @dynamic["v3/apis/#{key}.json"] = wrap_refs(merged)
      end

      # kube-openapi builder3/util WrapRefs: an OpenAPI v3 `$ref` may not carry
      # sibling keys, so a reference with a description (the CRD's `metadata`
      # property, "Standard object's metadata ...") is published as
      # `allOf: [{$ref}]` plus the siblings.  kubectl resolves a bare `$ref`
      # in place and drops the siblings, which made
      # `kubectl explain <crd>.metadata` print only ObjectMeta's own
      # description; "CustomResourcePublishOpenAPI works for CRD with
      # validation schema" matches on the property description.  swagger 2.0
      # keeps the sibling form, so this runs on the v3 document only.
      def wrap_refs(value)
        case value
        when Hash
          wrapped = value.each_with_object({}) { |(key, item), result| result[key] = wrap_refs(item) }
          if wrapped["$ref"].is_a?(String) && wrapped.size > 1
            reference = wrapped.delete("$ref")
            wrapped["allOf"] = [{"$ref" => reference}]
          end
          wrapped
        when Array then value.map { |item| wrap_refs(item) }
        else value
        end
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
        pending = collect_refs(document)
        until pending.empty?
          name = pending.shift
          next if schemas.key?(name) || !shared.key?(name)

          schemas[name] = JSON.parse(JSON.generate(shared.fetch(name)))
          pending.concat(collect_refs(schemas[name]))
        end
        document
      end

      def shared_components
        @shared_components ||= (read_document("v3/api/v1.json") || {}).dig("components", "schemas") || {}
      end

      def collect_refs(value, found = [])
        case value
        when Hash
          reference = value["$ref"]
          found << reference.delete_prefix("#/components/schemas/") if reference.is_a?(String) && reference.start_with?("#/components/schemas/")
          value.each_value { |child| collect_refs(child, found) }
        when Array
          value.each { |child| collect_refs(child, found) }
        end
        found
      end

      def relative_path(path)
        segments = path.to_s.split("/").reject(&:empty?).map do |segment|
          URI::RFC2396_PARSER.unescape(segment)
        end
        return nil unless segments.first == "openapi"

        segments = segments.drop(1)
        return "v2.json" if segments == ["v2"]
        return "v3/index.json" if segments == ["v3"]
        return "v3/api/#{segments[2]}.json" if segments.length == 3 && segments.first(2) == ["v3", "api"]
        return "v3/apis/#{segments[2]}/#{segments[3]}.json" if segments.length == 4 && segments.first(2) == ["v3", "apis"]
        return "v3/apis/#{segments[2]}.json" if segments.length == 3 && segments.first(2) == ["v3", "apis"]
        return "v3/#{segments[1]}.json" if segments.length == 2 && %w[api apis version logs].include?(segments[1])
        return "v3/openid/v1/jwks.json" if segments == %w[v3 openid v1 jwks]
        return "v3/.well-known/openid-configuration.json" if segments == %w[v3 .well-known openid-configuration]

        nil
      rescue URI::InvalidURIError
        nil
      end

      def v2_with_dynamic(document)
        overlay = @mutex.synchronize { @dynamic_v2.values.reduce({}) { |all, schemas| all.merge(schemas) } }
        return document if overlay.empty? || document.nil?

        document = JSON.parse(JSON.generate(document))
        definitions = document["definitions"].is_a?(Hash) ? document["definitions"] : {}
        overlay.each { |name, schema| definitions[name] = v2_schema(v2_definition(schema)) }
        document["definitions"] = definitions
        document
      end

      # apiextensions-apiserver/pkg/controller/openapi/builder buildKubeNative:
      # a custom resource whose ROOT schema preserves unknown fields is
      # published to swagger 2.0 as a bare `type: object`, with no properties
      # at all -- not even apiVersion/kind/metadata, because kubectl would then
      # reject every other field.  Only the group-version-kind marker survives.
      def v2_definition(schema)
        return v2_structural(schema) unless schema.is_a?(Hash) &&
                                            schema["x-kubernetes-preserve-unknown-fields"] == true

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
        if node["properties"].is_a?(Hash)
          node["properties"] = node["properties"].transform_values { |value| v2_structural(value) }
        end
        node["items"] = v2_structural(node["items"]) if node["items"].is_a?(Hash)
        if node["additionalProperties"].is_a?(Hash)
          node["additionalProperties"] = v2_structural(node["additionalProperties"])
        end
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

      # swagger 2.0 refers to #/definitions/..., OpenAPI v3 to
      # #/components/schemas/...; CRD schemas are otherwise identical.
      def v2_schema(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, item), result|
            result[key] = key == "$ref" && item.is_a?(String) ? item.sub("#/components/schemas/", "#/definitions/") : v2_schema(item)
          end
        when Array then value.map { |item| v2_schema(item) }
        else value
        end
      end

      def v3_index_with_dynamic(index)
        paths = dynamic_paths
        return index if paths.empty?

        index = index.nil? ? {"paths" => {}} : JSON.parse(JSON.generate(index))
        paths.each do |path|
          index["paths"][path] ||= {"serverRelativeURL" => "/openapi/v3/#{path}"}
        end
        index
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

        JSON.parse(File.binread(target_real), create_additions: false)
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
