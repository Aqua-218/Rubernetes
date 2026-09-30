# frozen_string_literal: true

# Pod source collection for the node agent.  API pods and local static pod
# manifests have different lifecycles, but the worker must see one stable
# desired object per namespace/name.  This class owns that merge and mirror
# reconciliation without starting a filesystem watcher or an API thread.

require "digest"
require "json"
require "yaml"

require_relative "registration"

module Rubernetes
  module Node
    class SourceManager
      Source = Data.define(:pod, :source, :key, :mirror) do
        def to_h
          {"pod" => pod, "source" => source, "key" => key, "mirror" => mirror}
        end
      end

      CONFIG_SOURCE_ANNOTATION = "kubernetes.io/config.source"
      CONFIG_MIRROR_ANNOTATION = "kubernetes.io/config.mirror"
      STATIC_SOURCES = %w[file http].freeze
      MANIFEST_EXTENSIONS = %w[.yaml .yml .json].freeze

      def initialize(node_name:, manifest_dir: nil, static_manifest_dir: nil, api_source: nil, api_client: nil, mirror_writer: nil, parser: nil,
                     clock: -> { Time.now.utc })
        @node_name = String(node_name)
        @manifest_dir = (manifest_dir || static_manifest_dir) && File.expand_path(manifest_dir || static_manifest_dir)
        @api_source = api_source || api_client
        @mirror_writer = mirror_writer
        @parser = parser || method(:parse_manifest)
        @clock = clock
        @api_pods = []
        @static_pods = []
        @mirrors = {}
      end

      attr_reader :node_name, :manifest_dir, :api_source, :mirror_writer

      def api_pods
        Support.deep_copy(@api_pods)
      end

      def static_pods
        Support.deep_copy(@static_pods)
      end

      def set_api_pods(pods)
        @api_pods = normalize_pod_list(pods).filter { |pod| pod_for_node?(pod) }
        @api_pods = @api_pods.map { |pod| Support.deep_copy(pod) }
      end

      alias replace_api_pods set_api_pods

      def apply_api_event(event)
        type = Support.value(event, "type").to_s.upcase
        object = Support.object_hash(Support.value(event, "object", event))
        current = @api_pods.to_h { |pod| [pod_key(pod), pod] }
        key = pod_key(object)
        case type
        when "DELETED"
          current.delete(key)
        when "ADDED", "MODIFIED"
          current[key] = object if pod_for_node?(object)
        else
          return merge
        end
        set_api_pods(current.values)
        merge
      end

      alias handle_api_event apply_api_event

      def watch(**)
        return nil unless @api_source.respond_to?(:watch)

        @api_source.watch(**)
      end

      def load_static(directory: @manifest_dir)
        return [] if directory.nil?

        directory = File.expand_path(directory)
        return [] unless Dir.exist?(directory)

        pods = []
        Dir.children(directory).sort.each do |entry|
          path = File.join(directory, entry)
          next unless MANIFEST_EXTENSIONS.include?(File.extname(entry).downcase)
          next unless File.file?(path) && !File.symlink?(path)

          parsed = invoke_parser(File.binread(path), path)
          normalize_pod_list(parsed).each do |pod|
            next unless pod_kind?(pod)

            pods << static_pod(pod, path: path)
          end
        end
        @static_pods = pods
        Support.deep_copy(pods)
      end

      alias read_static load_static

      def refresh(api_pods: nil, static_pods: nil, reconcile_mirrors: true)
        source_pods = if api_pods.nil?
                        read_api_source
                      else
                        set_api_pods(api_pods)
                      end
        local_pods = if static_pods.nil?
                       load_static
                     else
                       @static_pods = normalize_pod_list(static_pods).filter { |pod| pod_kind?(pod) }.map do |pod|
                         static_pod(pod, path: nil)
                       end
                     end
        reconcile_mirrors(local_pods) if reconcile_mirrors
        merge(api_pods: source_pods, static_pods: local_pods)
      end

      alias sync refresh

      def merge(api_pods: @api_pods, static_pods: @static_pods)
        api = normalize_pod_list(api_pods).filter { |pod| pod_for_node?(pod) }
        local = normalize_pod_list(static_pods).filter { |pod| pod_kind?(pod) }.map do |pod|
          annotations = Support.object_hash(Support.value(Support.metadata(pod), "annotations", {}))
          annotations.key?(CONFIG_MIRROR_ANNOTATION) ? Support.deep_copy(pod) : static_pod(pod, path: nil)
        end
        by_key = {}
        api.each do |pod|
          by_key[pod_key(pod)] = Source.new(pod: Support.deep_copy(pod), source: :api,
                                            key: pod_key(pod), mirror: mirror_pod?(pod))
        end
        local.each do |pod|
          key = pod_key(pod)
          existing = by_key[key]
          if existing.nil? || existing.mirror
            by_key[key] = Source.new(pod: merge_server_metadata(pod, existing&.pod), source: :static,
                                     key: key, mirror: true)
          end
        end
        by_key.values.sort_by(&:key).map(&:pod)
      end

      alias merged_pods merge

      def sources(api_pods: @api_pods, static_pods: @static_pods)
        merged = merge(api_pods: api_pods, static_pods: static_pods)
        merged.map do |pod|
          annotations = Support.object_hash(Support.value(Support.metadata(pod), "annotations", {}))
          source = annotations[CONFIG_SOURCE_ANNOTATION].to_s == "file" ? :static : :api
          Source.new(pod: pod, source: source, key: pod_key(pod), mirror: mirror_pod?(pod))
        end
      end

      def mirror_for(pod)
        static_pod(pod, path: nil)
      end

      alias mirror_pod_object mirror_for

      def mirror_pod?(pod)
        annotations = Support.object_hash(Support.value(Support.metadata(pod), "annotations", {}))
        annotations.key?(CONFIG_MIRROR_ANNOTATION)
      end

      def reconcile_mirrors(static_pods = @static_pods)
        desired = normalize_pod_list(static_pods).filter { |pod| pod_kind?(pod) }.to_h do |pod|
          mirror = mirror_for(pod)
          [pod_key(mirror), mirror]
        end
        if @mirror_writer
          desired.each do |key, mirror|
            namespace = Support.namespace(mirror, "default")
            name = Support.name(mirror).to_s
            existing = @mirrors[key]
            if existing
              invoke_writer(:update, mirror, namespace: namespace, name: name) ||
                invoke_writer(:upsert, mirror, namespace: namespace, name: name)
            else
              invoke_writer(:create, mirror, namespace: namespace, name: name) ||
                invoke_writer(:upsert, mirror, namespace: namespace, name: name)
            end
          end
          (@mirrors.keys - desired.keys).each do |key|
            old = @mirrors.fetch(key)
            invoke_writer(:delete, old, namespace: Support.namespace(old, "default"), name: Support.name(old).to_s)
          end
        end
        @mirrors = desired
        Support.deep_copy(desired.values)
      end

      def mirror_digest(pod)
        canonical_digest(pod)
      end

      private

      def read_api_source
        result = if @api_source.respond_to?(:call)
                   @api_source.call
                 elsif @api_source.respond_to?(:list)
                   @api_source.list
                 else
                   @api_pods
                 end
        set_api_pods(result)
        @api_pods
      end

      def normalize_pod_list(value)
        value = Support.value(value, "items", value) if !value.is_a?(Array) && !value.is_a?(Hash)
        value = Support.value(value, "items", []) if value.is_a?(Hash) && Support.present?(value, "items")
        value = [value] if value.is_a?(Hash) && pod_kind?(value)
        Array(value).filter_map do |item|
          object = Support.object_hash(item)
          object.empty? ? nil : object
        end
      end

      def pod_kind?(pod)
        kind = Support.value(pod, "kind")
        kind.nil? || kind.to_s == "Pod"
      end

      def pod_for_node?(pod)
        assigned = Support.value(Support.value(pod, "spec", {}), "nodeName")
        assigned.to_s == @node_name || mirror_pod?(pod)
      end

      def pod_key(pod)
        metadata = Support.metadata(pod)
        namespace = Support.value(metadata, "namespace", "default").to_s
        name = Support.value(metadata, "name") || Support.value(pod, "name")
        raise ArgumentError, "pod metadata.name is required" if name.to_s.empty?

        "#{namespace}/#{name}"
      end

      def static_pod(pod, path: nil)
        result = Support.object_hash(pod)
        result["apiVersion"] ||= "v1"
        result["kind"] = "Pod"
        spec = Support.object_hash(result["spec"])
        spec["nodeName"] ||= @node_name
        result["spec"] = spec
        metadata = Support.metadata(result)
        metadata["namespace"] ||= "default"
        annotations = Support.object_hash(metadata["annotations"])
        annotations[CONFIG_SOURCE_ANNOTATION] ||= "file"
        annotations[CONFIG_MIRROR_ANNOTATION] = canonical_digest(result.merge("metadata" => metadata.merge("annotations" => annotations)))
        metadata["annotations"] = annotations
        result["metadata"] = metadata
        result["metadata"]["annotations"]["kubernetes.io/config.path"] = path if path
        result
      end

      def merge_server_metadata(static_pod, api_pod)
        return static_pod unless api_pod

        static_metadata = Support.metadata(static_pod)
        api_metadata = Support.metadata(api_pod)
        %w[uid resourceVersion generation creationTimestamp managedFields deletionTimestamp].each do |field|
          static_metadata[field] = api_metadata[field] if api_metadata.key?(field)
        end
        static_pod.merge("metadata" => static_metadata)
      end

      def canonical_digest(pod)
        normalized = Support.object_hash(pod)
        metadata = Support.metadata(normalized)
        annotations = Support.object_hash(metadata["annotations"])
        annotations.delete(CONFIG_MIRROR_ANNOTATION)
        annotations.delete("kubernetes.io/config.path")
        metadata = metadata.reject do |key, _|
          %w[uid resourceVersion generation creationTimestamp managedFields deletionTimestamp].include?(key)
        end
        metadata["annotations"] = annotations unless annotations.empty?
        normalized["metadata"] = metadata
        Digest::SHA256.hexdigest(JSON.generate(canonical(normalized)))
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |key, output|
            original = value.keys.find { |candidate| candidate.to_s == key }
            output[key] = canonical(value.fetch(original))
          end
        when Array then value.map { |item| canonical(item) }
        else value
        end
      end

      def invoke_writer(method_name, pod, namespace:, name:)
        return false unless @mirror_writer.respond_to?(method_name)

        result = Support.invoke(@mirror_writer, method_name, resource: "v1/pods", namespace: namespace,
                                                             name: name, object: pod)
        result != false
      end

      def parse_manifest(content, path)
        extension = File.extname(path).downcase
        if extension == ".json"
          JSON.parse(content)
        else
          documents = YAML.parse_stream(content).children.map do |document|
            stream = Psych::Nodes::Stream.new
            stream.children << document
            YAML.safe_load(stream.to_yaml, aliases: false, permitted_classes: [], permitted_symbols: [])
          end
          documents.length == 1 ? documents.first : documents
        end
      rescue JSON::ParserError, Psych::Exception => error
        raise ArgumentError, "invalid static pod manifest #{path}: #{error.message}"
      end

      def invoke_parser(content, path)
        parameters = @parser.method(:call).parameters
        positional = parameters.any? { |kind, _| kind == :rest } ? 2 : parameters.count { |kind, _| %i[req opt].include?(kind) }
        @parser.call(*[content, path].first(positional))
      end
    end

    PodSourceManager = SourceManager unless const_defined?(:PodSourceManager, false)
  end
end
