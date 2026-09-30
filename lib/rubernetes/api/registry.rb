# frozen_string_literal: true

module Rubernetes
  module API
    # Group/version/kind identifier used by schema and discovery adapters.
    GVK = Struct.new(:group, :version, :kind, keyword_init: true) do
      def initialize(kind:, group: "", version: "v1")
        super(group: group.to_s, version: version.to_s, kind: kind.to_s)
        freeze
      end

      def api_version
        group.empty? ? version : "#{group}/#{version}"
      end

      def to_s
        "#{api_version}, Kind=#{kind}"
      end

      def to_h
        {group: group, version: version, kind: kind, api_version: api_version}
      end
    end

    # Group/version/resource identifier used by REST paths and storage keys.
    GVR = Struct.new(:group, :version, :resource, keyword_init: true) do
      def initialize(resource:, group: "", version: "v1")
        super(group: group.to_s, version: version.to_s, resource: resource.to_s)
        freeze
      end

      def group_version
        group.empty? ? version : "#{group}/#{version}"
      end

      def to_s
        "#{group_version}/#{resource}"
      end

      def to_h
        {group: group, version: version, resource: resource, group_version: group_version}
      end
    end

    # Immutable registry entry consumed by discovery, routing, and patch code.
    class Resource
      attr_reader :group, :version, :resource, :kind, :scope, :short_names,
                  :categories, :verbs, :list_kind, :singular_name, :merge_keys,
                  :patch_strategy, :storage_version_hash, :schema, :subresources,
                  :storage_version, :storage_group, :wire_converter, :converter, :printer_columns,
                  :selectable_fields, :custom

      # A subresource can be advertised under a group/version different from
      # its parent resource.  Kubernetes uses this for Scale: the endpoint is
      # routed below apps (or core) resources, while discovery identifies the
      # response as autoscaling/v1 Scale.  Keep the override on the immutable
      # registry entry so routing, discovery, and REST mapping use one source
      # of truth.
      Subresource = Struct.new(:resource, :kind, :verbs, :group, :version, keyword_init: true) do
        def initialize(resource:, kind: nil, verbs: [], group: nil, version: nil)
          group = group.nil? ? nil : group.to_s
          version = version.nil? ? nil : version.to_s
          group = nil if group && group.empty?
          version = nil if version && version.empty?
          super(resource: resource.to_s.freeze, kind: kind&.to_s&.freeze,
                verbs: Array(verbs).map(&:to_s).freeze,
                group: group&.freeze, version: version&.freeze)
          freeze
        end

        def to_h
          {resource: resource, kind: kind, verbs: verbs}.tap do |payload|
            payload[:group] = group if group
            payload[:version] = version if version
          end
        end

        def advertised_group(parent_group)
          return group if group
          return "autoscaling" if kind == "Scale" && parent_group.to_s.empty?
          return "policy" if kind == "Eviction" && parent_group.to_s.empty?
          return "authentication.k8s.io" if kind == "TokenRequest" && parent_group.to_s.empty?

          nil
        end

        def advertised_version(parent_group, _parent_version)
          return version if version
          return "v1" if kind == "Scale" && parent_group.to_s.empty?
          return "v1" if %w[Eviction TokenRequest].include?(kind) && parent_group.to_s.empty?

          nil
        end
      end

      def initialize(resource:, kind:, group: "", version: "v1", scope: :cluster,
                     short_names: [], categories: [], verbs: nil, list_kind: nil,
                     singular_name: nil, merge_keys: {}, patch_strategy: :merge,
                     storage_version_hash: nil, schema: nil, namespaced: nil, subresources: [],
                     storage_version: nil, storage_group: nil, wire_converter: nil, converter: nil,
                     printer_columns: [], selectable_fields: [], custom: false)
        # Dynamically served resources (CustomResourceDefinitions) share one
        # storage location across their served versions: objects are stored
        # under the storage version's GVR and converted on the way in and out.
        @storage_version = storage_version&.to_s&.freeze
        # An API group served over ANOTHER group's storage: events.k8s.io/v1
        # Events are the same objects as core/v1 Events, stored once in the
        # core shape and translated at the edge by wire_converter.
        @storage_group = storage_group&.to_s&.freeze
        @wire_converter = wire_converter
        @converter = converter
        @printer_columns = Array(printer_columns).freeze
        @selectable_fields = Array(selectable_fields).freeze
        @custom = custom == true
        @group = group.to_s.freeze
        @version = version.to_s.freeze
        @resource = resource.to_s.freeze
        @kind = kind.to_s.freeze
        @scope = normalize_scope(if namespaced.nil?
                                   scope
                                 else
                                   (namespaced ? :namespaced : :cluster)
                                 end)
        @short_names = Array(short_names).map(&:to_s).freeze
        @categories = Array(categories).map(&:to_s).freeze
        @verbs = (verbs || %w[get list watch create update patch delete deletecollection]).map(&:to_s).freeze
        @list_kind = (list_kind || "#{@kind}List").to_s.freeze
        @singular_name = (singular_name || singularize(@resource)).to_s.freeze
        @merge_keys = normalize_merge_keys(merge_keys).freeze
        @patch_strategy = patch_strategy.to_sym
        @storage_version_hash = storage_version_hash&.to_s&.freeze
        @schema = schema
        @subresources = normalize_subresources(subresources).freeze
        freeze
      end

      def gvk
        GVK.new(group: group, version: version, kind: kind)
      end

      def gvr
        GVR.new(group: group, version: version, resource: resource)
      end

      # A custom resource's storage key must NOT name a version.  etcd holds
      # one object per custom resource at /registry/<group>/<plural>/<ns>/<name>
      # whatever version it was written in (apiextensions-apiserver
      # customresource_handler.go builds its storage prefix from the CRD's
      # group and plural alone), and the apiserver converts whatever it finds
      # there to the version the client asked for.  Keying by the CRD's current
      # storage version instead made every existing object vanish the moment
      # the CRD's storage version moved: "[sig-api-machinery]
      # CustomResourceConversionWebhook should be able to convert a non
      # homogeneous list of CRs" patches the CRD from v1 to v2 and then lists
      # two objects, and the one written before the patch was no longer at any
      # key the server looked in.
      CUSTOM_STORAGE_VERSION = "__stored__"

      # GVR used for storage keys (differs from gvr for a resource served over
      # another group's storage).
      def storage_gvr
        return GVR.new(group: storage_group || group, version: CUSTOM_STORAGE_VERSION, resource: resource) if custom?

        GVR.new(group: storage_group || group, version: storage_version || version, resource: resource)
      end

      # True when reads and writes have to be translated between the served
      # shape and the stored one.
      def storage_alias?
        !@wire_converter.nil? && storage_gvr != gvr
      end

      def custom?
        @custom
      end

      def api_version
        gvk.api_version
      end

      def group_version
        gvr.group_version
      end

      def namespaced?
        scope == :namespaced
      end

      def cluster_scoped?
        !namespaced?
      end

      def subresource(name)
        @subresources.find { |entry| entry.resource == name.to_s }
      end

      def subresource_verbs(name)
        subresource(name)&.verbs || []
      end

      def to_h
        {
          group: group,
          version: version,
          resource: resource,
          kind: kind,
          scope: scope,
          namespaced: namespaced?,
          short_names: short_names,
          categories: categories,
          verbs: verbs,
          list_kind: list_kind,
          singular_name: singular_name,
          merge_keys: merge_keys,
          patch_strategy: patch_strategy,
          storage_version_hash: storage_version_hash,
          subresources: subresources.map(&:to_h),
          schema: schema
        }
      end

      private

      def normalize_scope(value)
        normalized = value.to_s.downcase
        return :namespaced if %w[namespaced namespace].include?(normalized)
        return :cluster if %w[cluster clusterscoped cluster-scoped].include?(normalized)

        raise ArgumentError, "resource scope must be :namespaced or :cluster"
      end

      def singularize(value)
        return "#{value[0..-4]}y" if value.end_with?("ies")
        return value[0..-2] if value.end_with?("ses")
        return value[0..-2] if value.end_with?("s")

        value
      end

      def normalize_merge_keys(value)
        return {} unless value.respond_to?(:each)

        value.each_with_object({}) do |(path, key), normalized|
          normalized[path.to_s] = key.to_s
        end
      end

      def normalize_subresources(value)
        entries =
          if value.is_a?(Hash)
            value.map do |name, descriptor|
              descriptor = descriptor.is_a?(Hash) ? descriptor.dup : {verbs: descriptor}
              descriptor[:resource] ||= descriptor["resource"] ||= name
              descriptor
            end
          else
            Array(value)
          end
        entries.map do |entry|
          if entry.is_a?(Subresource)
            if entry.kind == "Scale" && entry.group.nil? && @group == "apps"
              Subresource.new(resource: entry.resource, kind: entry.kind, verbs: entry.verbs,
                              group: "autoscaling", version: entry.version || "v1")
            else
              entry
            end
          elsif entry.is_a?(Hash)
            attributes = entry.transform_keys(&:to_sym)
            # The pinned API surface advertises apps and core Scale
            # subresources with an autoscaling/v1 response identity.  The
            # generated resource registry stores only the parent and child
            # names, so recover this well-known override only for apps (the
            # core discovery endpoint carries the override in its own
            # discovery response but does not add an autoscaling GVR).
            if attributes[:kind].to_s == "Scale" && attributes[:group].nil? && @group == "apps"
              attributes[:group] = "autoscaling"
              attributes[:version] ||= "v1"
            end
            Subresource.new(resource: attributes.fetch(:resource) { attributes.fetch(:name) },
                            kind: attributes[:kind], verbs: attributes.fetch(:verbs, []),
                            group: attributes[:group], version: attributes[:version])
          else
            Subresource.new(resource: entry)
          end
        end.uniq(&:resource)
      end
    end

    # Built-in registry with a small safe baseline. Schema generation can
    # replace it by injecting a complete registry into Server.new.
    class Registry
      DEFAULT_RESOURCES = [
        {group: "", version: "v1", resource: "configmaps", kind: "ConfigMap", scope: :namespaced,
         short_names: ["cm"]},
        {group: "", version: "v1", resource: "secrets", kind: "Secret", scope: :namespaced,
         short_names: ["secret"]},
        {group: "", version: "v1", resource: "pods", kind: "Pod", scope: :namespaced,
         short_names: ["po"],
         merge_keys: {"spec.containers" => "name", "spec.containers[*].env" => "name"},
         subresources: [
           {resource: "attach", kind: "PodAttachOptions", verbs: %w[create get]},
           {resource: "binding", kind: "Binding", verbs: ["create"]},
           {resource: "exec", kind: "PodExecOptions", verbs: %w[create get]},
           {resource: "log", kind: "Pod", verbs: ["get"]},
           {resource: "portforward", kind: "PodPortForwardOptions", verbs: %w[create get]},
           {resource: "proxy", kind: "PodProxyOptions", verbs: %w[create delete get head options patch update]},
           {resource: "resize", kind: "Pod", verbs: %w[get patch update]},
           {resource: "ephemeralcontainers", kind: "Pod", verbs: %w[get patch update]},
           {resource: "status", kind: "Pod", verbs: %w[get patch update]}
         ]},
        {group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster,
         short_names: ["ns"],
         subresources: [{resource: "finalize", kind: "Namespace", verbs: ["update"]},
                        {resource: "status", kind: "Namespace", verbs: %w[get patch update]}]}
      ].freeze

      class AlreadyRegistered < StandardError; end

      def initialize(resources: nil, defaults: true)
        @resources_by_gvr = {}
        @resources_by_gvk = {}
        source = if resources.nil? && defaults
                   DEFAULT_RESOURCES
                 elsif resources.is_a?(Hash)
                   resources.values
                 else
                   Array(resources)
                 end
        source.each { |entry| register(entry) }
      end

      Resource = Rubernetes::API::Resource
      GVK = Rubernetes::API::GVK
      GVR = Rubernetes::API::GVR

      def register(resource = nil, **attributes)
        entry = normalize(resource, attributes)
        gvr_key = key_for(entry.gvr)
        gvk_key = key_for(entry.gvk)
        if @resources_by_gvr.key?(gvr_key) || @resources_by_gvk.key?(gvk_key)
          raise AlreadyRegistered, "resource #{entry.group_version}/#{entry.resource} is already registered"
        end

        @resources_by_gvr[gvr_key] = entry
        @resources_by_gvk[gvk_key] = entry
        entry
      end

      alias add register

      # Remove a dynamically served resource (CustomResourceDefinition
      # deletion or served-version change).  Built-in resources are never
      # unregistered by the API server.
      def unregister(group:, version:, resource:)
        entry = @resources_by_gvr.delete(key_for(GVR.new(group: group, version: version, resource: resource)))
        return nil unless entry

        @resources_by_gvk.delete(key_for(entry.gvk))
        entry
      end

      def resources
        @resources_by_gvr.values.sort_by { |entry| [entry.group, entry.version, entry.resource] }
      end

      alias all resources

      def each(&)
        resources.each(&)
      end

      include Enumerable

      def groups
        resources.map(&:group).uniq.sort
      end

      def versions(group: "")
        resources.select { |entry| entry.group == group.to_s }.map(&:version).uniq.sort
      end

      def find_gvr(group:, version:, resource:)
        @resources_by_gvr[key_for(GVR.new(group: group, version: version, resource: resource))]
      end

      alias resource_for_gvr find_gvr
      alias lookup_gvr find_gvr

      def find_gvk(group:, version:, kind:)
        @resources_by_gvk[key_for(GVK.new(group: group, version: version, kind: kind))]
      end

      alias resource_for_gvk find_gvk
      alias lookup_gvk find_gvk

      # Resolve a parent resource for a cross-group subresource route.  The
      # URL remains rooted at the alias group/version (for example
      # autoscaling/v1/deployments/scale), but storage and mutation are owned
      # by the parent Resource registered under apps/v1.
      def find_subresource_parent(group:, version:, resource:, subresource:)
        resources.find do |entry|
          next false unless entry.resource == resource.to_s

          child = entry.subresource(subresource)
          child && child.advertised_group(entry.group).to_s == group.to_s &&
            child.advertised_version(entry.group, entry.version).to_s == version.to_s
        end
      end

      alias lookup_subresource_parent find_subresource_parent

      def [](identifier)
        case identifier
        when GVR then @resources_by_gvr[key_for(identifier)]
        when GVK then @resources_by_gvk[key_for(identifier)]
        else resources.find { |entry| entry.resource == identifier.to_s || entry.kind == identifier.to_s }
        end
      end

      private

      def normalize(resource, attributes)
        return Resource.new(**attributes) if resource.nil? && !attributes.key?(:gvr) && !attributes.key?(:gvk)
        return resource if resource.is_a?(Resource) && attributes.empty?

        values = resource_to_hash(resource).merge(stringify_keys(attributes))
        values = values.transform_keys(&:to_sym)
        values[:group] ||= values.delete(:api_group) || ""
        api_version = values.delete(:api_version)
        if api_version && (values[:version].nil? || values[:group].to_s.empty?)
          api_parts = api_version.to_s.split("/", 2)
          values[:group] = api_parts.length == 2 ? api_parts.first : ""
          values[:version] = api_parts.last
        end
        values[:version] ||= "v1"
        values[:resource] ||= values.delete(:name)
        gvr = values.delete(:gvr)
        gvk = values.delete(:gvk)
        values[:group] = gvr.group if gvr.respond_to?(:group) && values[:group].to_s.empty?
        values[:version] = gvr.version if gvr.respond_to?(:version) && values[:version].to_s == "v1"
        values[:resource] ||= gvr.resource if gvr.respond_to?(:resource)
        values[:kind] ||= gvk.kind if gvk.respond_to?(:kind)
        values[:kind] ||= infer_kind(values[:resource])
        values[:scope] ||= values.delete(:scope) || (values[:namespaced] ? :namespaced : :cluster)
        Resource.new(**values.slice(*Resource.instance_method(:initialize).parameters.filter_map do |kind, name|
          name if %i[key keyreq].include?(kind)
        end))
      end

      def resource_to_hash(resource)
        return resource.transform_keys(&:to_sym) if resource.is_a?(Hash)
        return resource.to_h.transform_keys(&:to_sym) if resource.respond_to?(:to_h)

        names = %i[group version resource kind scope namespaced short_names categories verbs list_kind
                   singular_name merge_keys patch_strategy storage_version_hash schema subresources]
        names.each_with_object({}) do |name, values|
          values[name] = resource.public_send(name) if resource.respond_to?(name)
        end
      end

      def stringify_keys(values)
        values.each_with_object({}) { |(key, value), normalized| normalized[key.to_sym] = value }
      end

      def infer_kind(resource)
        word = resource.to_s.delete_suffix("s")
        word.split(/[-_]/).map { |part| part[0].to_s.upcase + part[1..].to_s }.join
      end

      def key_for(identifier)
        case identifier
        when GVR
          [identifier.group, identifier.version, identifier.resource]
        when GVK
          [identifier.group, identifier.version, identifier.kind]
        else
          identifier.to_s
        end
      end
    end

    # Normalizes third-party/generated registries at the API boundary. The
    # server only relies on this adapter and therefore does not know schema
    # compiler implementation details.
    class RegistryAdapter
      def initialize(registry)
        @registry = registry
      end

      attr_reader :registry

      def resources
        entries = if @registry.respond_to?(:resources)
                    @registry.resources
                  elsif @registry.respond_to?(:all)
                    @registry.all
                  elsif @registry.respond_to?(:each)
                    result = []
                    @registry.each { |entry| result << entry }
                    result
                  else
                    []
                  end
        entries = entries.values if entries.is_a?(Hash)
        entries = entries.to_a if entries.respond_to?(:to_a) && !entries.is_a?(Array)
        Array(entries).filter_map { |entry| normalize(entry) }
      end

      def find_gvr(group:, version:, resource:)
        direct = call_lookup(:find_gvr, group: group, version: version, resource: resource) ||
                 call_lookup(:resource_for_gvr, group: group, version: version, resource: resource) ||
                 call_lookup(:lookup_gvr, group: group, version: version, resource: resource)
        normalize(direct) || resources.find do |entry|
          entry.group == group.to_s && entry.version == version.to_s &&
            (entry.resource == resource.to_s || entry.short_names.include?(resource.to_s))
        end
      end

      def find_gvk(group:, version:, kind:)
        direct = call_lookup(:find_gvk, group: group, version: version, kind: kind) ||
                 call_lookup(:resource_for_gvk, group: group, version: version, kind: kind) ||
                 call_lookup(:lookup_gvk, group: group, version: version, kind: kind)
        normalize(direct) || resources.find do |entry|
          entry.group == group.to_s && entry.version == version.to_s && entry.kind == kind.to_s
        end
      end

      def find_subresource_parent(group:, version:, resource:, subresource:)
        direct = call_lookup(
          :find_subresource_parent,
          group: group, version: version, resource: resource, subresource: subresource
        ) || call_lookup(
          :lookup_subresource_parent,
          group: group, version: version, resource: resource, subresource: subresource
        )
        normalized = normalize(direct)
        return normalized if normalized

        resources.find do |entry|
          next false unless entry.resource == resource.to_s

          child = entry.subresource(subresource)
          child && child.advertised_group(entry.group).to_s == group.to_s &&
            child.advertised_version(entry.group, entry.version).to_s == version.to_s
        end
      end

      private

      def call_lookup(method_name, **keywords)
        return nil unless @registry.respond_to?(method_name)

        method = @registry.method(method_name)
        if method.parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
          method.call(**keywords)
        else
          identifier = if keywords.key?(:kind)
                         GVK.new(group: keywords.fetch(:group), version: keywords.fetch(:version), kind: keywords.fetch(:kind))
                       else
                         GVR.new(group: keywords.fetch(:group), version: keywords.fetch(:version), resource: keywords.fetch(:resource))
                       end
          if method.arity == 1 || method.arity.negative?
            method.call(identifier)
          else
            method.call(*keywords.values_at(:group, :version, keywords.key?(:kind) ? :kind : :resource))
          end
        end
      rescue ArgumentError
        nil
      end

      def normalize(entry)
        return nil if entry.nil?
        return entry if entry.is_a?(Resource)

        original_schema = entry if entry.respond_to?(:validator) && entry.respond_to?(:defaulting)
        values = if entry.is_a?(Hash)
                   entry
                 elsif entry.respond_to?(:to_h)
                   entry.to_h
                 else
                   {}
                 end
        values = values.transform_keys(&:to_sym)
        values[:group] ||= values.delete(:api_group) || ""
        api_version = values.delete(:api_version)
        if api_version && (values[:version].nil? || values[:group].to_s.empty?)
          api_parts = api_version.to_s.split("/", 2)
          values[:group] = api_parts.length == 2 ? api_parts.first : ""
          values[:version] = api_parts.last
        end
        values[:version] ||= "v1"
        gvr = values[:gvr]
        gvk = values[:gvk]
        values[:group] = gvr.group if gvr.respond_to?(:group) && values[:group].to_s.empty?
        values[:version] = gvr.version if gvr.respond_to?(:version) && (values[:version].nil? || values[:version].to_s == "v1")
        values[:resource] ||= gvr.resource if gvr.respond_to?(:resource)
        values[:kind] ||= gvk.kind if gvk.respond_to?(:kind)
        values[:resource] ||= values.delete(:name)
        values[:kind] ||= values[:resource].to_s.delete_suffix("s").split(/[-_]/).map(&:capitalize).join
        values[:scope] ||= values[:namespaced] ? :namespaced : :cluster
        values[:schema] ||= original_schema if original_schema
        Resource.new(**values.slice(*Resource.instance_method(:initialize).parameters.filter_map do |kind, name|
          name if %i[key keyreq].include?(kind)
        end))
      rescue ArgumentError
        nil
      end
    end
  end
end
