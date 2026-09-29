# frozen_string_literal: true

require "json"
require "psych"
require "thread"
require "uri"

require_relative "errors"
require_relative "http_client"
require_relative "kubeconfig"
require_relative "manifest_reader"

module Rubernetes
  module Client
    # Kubernetes resource client built on the raw HTTP transport.
    class KubernetesClient
      RESOURCE_PLURALS = {
        "Pod" => "pods",
        "Service" => "services",
        "Deployment" => "deployments",
        "ReplicaSet" => "replicasets",
        "StatefulSet" => "statefulsets",
        "DaemonSet" => "daemonsets",
        "Job" => "jobs",
        "CronJob" => "cronjobs",
        "ConfigMap" => "configmaps",
        "Secret" => "secrets",
        "Namespace" => "namespaces",
        "Node" => "nodes",
        "ServiceAccount" => "serviceaccounts",
        "Role" => "roles",
        "RoleBinding" => "rolebindings",
        "ClusterRole" => "clusterroles",
        "ClusterRoleBinding" => "clusterrolebindings",
        "PersistentVolume" => "persistentvolumes",
        "PersistentVolumeClaim" => "persistentvolumeclaims",
        "StorageClass" => "storageclasses",
        "Ingress" => "ingresses",
        "Endpoints" => "endpoints",
        "EndpointSlice" => "endpointslices",
        "ResourceQuota" => "resourcequotas",
        "LimitRange" => "limitranges",
        "NetworkPolicy" => "networkpolicies",
        "HorizontalPodAutoscaler" => "horizontalpodautoscalers",
        "PodDisruptionBudget" => "poddisruptionbudgets",
        "PriorityClass" => "priorityclasses",
        "RuntimeClass" => "runtimeclasses",
        "MutatingWebhookConfiguration" => "mutatingwebhookconfigurations",
        "ValidatingWebhookConfiguration" => "validatingwebhookconfigurations"
      }.freeze

      # Last-resort scope table, used only when neither discovery nor a REST
      # mapper can describe the resource.  A hand-written list silently gets a
      # cluster-scoped resource wrong -- the request then goes to
      # /namespaces/<ctx>/<plural> and 404s -- so the generated schema registry
      # is the source of truth and this literal is only the fallback for a
      # tree where that file is absent.
      FALLBACK_CLUSTER_SCOPED_RESOURCES = %w[
        namespaces nodes clusterroles clusterrolebindings persistentvolumes storageclasses
        priorityclasses runtimeclasses mutatingwebhookconfigurations validatingwebhookconfigurations
      ].freeze

      GENERATED_REGISTRY_PATH = File.expand_path("../../../generated/schema/registry.json", __dir__).freeze

      def self.cluster_scoped_resources
        @cluster_scoped_resources ||= begin
          plurals = FALLBACK_CLUSTER_SCOPED_RESOURCES.dup
          if File.file?(GENERATED_REGISTRY_PATH)
            document = JSON.parse(File.binread(GENERATED_REGISTRY_PATH))
            Array(document["resources"]).each do |entry|
              plurals << entry["resource"].to_s if entry["scope"].to_s == "Cluster" && !entry["resource"].to_s.empty?
            end
          end
          plurals.uniq.freeze
        rescue JSON::ParserError, SystemCallError
          FALLBACK_CLUSTER_SCOPED_RESOURCES
        end
      end

      CORE_STATIC_KINDS = %w[
        Pod Service ConfigMap Secret Namespace Node ServiceAccount PersistentVolume
        PersistentVolumeClaim ResourceQuota LimitRange
      ].freeze

      PATCH_CONTENT_TYPES = {
        json: "application/json-patch+json",
        json_patch: "application/json-patch+json",
        merge: "application/merge-patch+json",
        merge_patch: "application/merge-patch+json",
        strategic: "application/strategic-merge-patch+json",
        strategic_merge: "application/strategic-merge-patch+json",
        apply: "application/apply-patch+yaml"
      }.freeze
      DEFAULT_WATCH_MAX_BYTES = 16 * 1024 * 1024
      DEFAULT_WATCH_MAX_EVENTS = 10_000
      WATCH_EVENT_TYPES = %w[ADDED MODIFIED DELETED BOOKMARK ERROR].freeze
      DEFAULT_WATCH_RECONNECTS = 8
      PINNED_VERSION_PRIORITY = {
        "admissionregistration.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "apps" => %w[v1],
        "authentication.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "authorization.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "autoscaling" => %w[v2 v1],
        "batch" => %w[v1 v1beta1],
        "certificates.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "coordination.k8s.io" => %w[v1 v1beta1 v1alpha2],
        "discovery.k8s.io" => %w[v1 v1beta1],
        "events.k8s.io" => %w[v1 v1beta1],
        "flowcontrol.apiserver.k8s.io" => %w[v1 v1beta3 v1beta2 v1beta1],
        "networking.k8s.io" => %w[v1 v1beta1],
        "node.k8s.io" => %w[v1 v1alpha1],
        "policy" => %w[v1 v1beta1],
        "rbac.authorization.k8s.io" => %w[v1 v1beta1],
        "resource.k8s.io" => %w[v1 v1beta2 v1beta1 v1alpha3],
        "scheduling.k8s.io" => %w[v1 v1alpha2],
        "storage.k8s.io" => %w[v1 v1beta1],
        "storagemigration.k8s.io" => %w[v1beta1],
        "internal.apiserver.k8s.io" => %w[v1alpha1],
        "apiregistration.k8s.io" => %w[v1 v1beta1],
        "auditregistration.k8s.io" => %w[v1alpha1],
        "metrics.k8s.io" => %w[v1beta1]
      }.transform_values(&:freeze).freeze

      # A RESTMapper descriptor assembled from APIResourceList discovery.  The
      # descriptor deliberately retains discovery verbs and subresource scope
      # instead of inferring them from a Kind's spelling.
      ResourceDescriptor = Struct.new(
        :group, :version, :resource, :kind, :namespaced, :verbs, :short_names,
        :singular_name, :list_kind, :subresource, keyword_init: true
      ) do
        def api_version
          group.to_s.empty? ? version.to_s : "#{group}/#{version}"
        end

        def subresource?
          !subresource.to_s.empty?
        end

        def key
          "#{api_version}/#{resource}"
        end
      end

      # The server ended the stream with 410 Expired: the resumption version
      # is older than what it retains.  Carries the status so a reflector's
      # gone_error? sees it as the 410 it is.
      class WatchReset < StandardError
        def status = 410
        def code = 410
      end

      attr_reader :rest_client, :context, :discovery_cache, :rest_mapper

      # The bearer token requests carry now (nil for certificate
      # credentials); a ServiceAccount context answers its current token.
      def bearer_token
        if @context.respond_to?(:bearer_token)
          @context.bearer_token
        elsif @context.is_a?(Hash)
          @context[:bearer_token] || @context["bearer_token"]
        end
      end

      def self.from_kubeconfig(path: nil, context: nil, env: ENV, **options)
        kubeconfig = Kubeconfig.load(path: path, env: env)
        resolved_context = kubeconfig.resolve(name: context)
        rest_client = HTTPClient.new(context: resolved_context, **options)
        new(rest_client: rest_client, context: resolved_context)
      end

      def initialize(
        rest_client: nil,
        context: nil,
        http_client: nil,
        server: nil,
        token: nil,
        namespace: nil,
        discovery_cache: nil,
        rest_mapper: nil,
        **http_options
      )
        @context = context || {
          server: server,
          bearer_token: token,
          namespace: namespace
        }
        @rest_client = rest_client || http_client
        @rest_client ||= HTTPClient.new(context: @context, **http_options) if context || server
        raise ArgumentError, "rest_client or context is required" unless @rest_client
        @discovery_mutex = Mutex.new
        @discovery_entries = {}
        @discovery_by_kind = {}
        @discovery_preferred = {}
        @discovery_loaded = false
        @rest_mapper = rest_mapper
        @discovery_cache = discovery_cache || {}
        seed_discovery_cache(@discovery_cache)
      end

      # Populate and cache the RESTMapper from the server's live discovery
      # endpoints.  Repeated calls are local and safe for concurrent clients.
      def discover!(force: false)
        return @discovery_cache unless force || !@discovery_loaded

        @discovery_mutex.synchronize do
          return @discovery_cache if @discovery_loaded && !force

          if force
            @discovery_entries.clear
            @discovery_by_kind.clear
            @discovery_preferred.clear
            @discovery_cache.clear
          end

          discover_core_versions!
          discover_api_groups!
          @discovery_loaded = true
          @discovery_cache
        end
      end

      def refresh_discovery!(force: true)
        discover!(force: force)
      end

      def invalidate_discovery!
        @discovery_mutex.synchronize do
          @discovery_loaded = false
          @discovery_entries.clear
          @discovery_by_kind.clear
          @discovery_preferred.clear
          @discovery_cache.clear
        end
        self
      end

      # Sends an arbitrary API request. The raw Response is preserved for callers that need
      # headers, status, or a watch stream; use get/create/etc. for decoded resource objects.
      def raw(method, path, body: nil, headers: {}, query: nil, raise_for_status: true)
        response = @rest_client.request(method, path, body: body, headers: headers, query: query)
        response = normalize_rest_response(response)
        if raise_for_status && !response.success?
          if @rest_client.respond_to?(:raise_for_status!)
            @rest_client.raise_for_status!(response, method, path)
          else
            raise APIError.new(
              "Kubernetes API request #{method} #{path} failed with HTTP #{response.status}",
              response: response
            )
          end
        end
        response
      end

      alias request raw

      # Fetches a collection or named resource and decodes its JSON response.
      def get(path_or_resource, name = nil, namespace: nil, api_version: "v1", query: nil,
              subresource: nil, return_response: false)
        path = resource_path(path_or_resource, name, namespace: namespace, api_version: api_version,
                             subresource: subresource, operation: name ? :get : :list)
        response = raw("GET", path, query: query)
        return response if return_response

        decode_response(response)
      end

      # Creates a resource from a manifest at the collection endpoint.
      def create(manifest_or_path, manifest = nil, namespace: nil, api_version: "v1", path: nil,
                 subresource: nil, return_response: false)
        resource = manifest || manifest_or_path
        resource_path_value = path || (manifest_or_path if manifest && manifest_or_path.to_s.start_with?("/"))
        resource_path_value ||= resource_path(resource, nil, namespace: namespace, api_version: api_version,
                                              use_manifest_name: !subresource.nil?, subresource: subresource,
                                              operation: :create)
        response = raw("POST", resource_path_value, body: encode_resource(resource), headers: json_headers)
        return response if return_response

        decode_response(response)
      end

      # Applies a manifest with Kubernetes server-side apply field ownership semantics.
      def apply(manifest, namespace: nil, field_manager: "rubernetes", force: false, path: nil,
                subresource: nil, return_response: false)
        resource = normalize_resource(manifest)
        name = resource.dig("metadata", "name")
        raise UsageError, "apply manifest metadata.name is required" if name.to_s.empty?
        target_path = path || resource_path(resource, name, namespace: namespace, api_version: resource["apiVersion"],
                                             subresource: subresource, operation: :patch)
        query = {"fieldManager" => field_manager}
        query["force"] = "true" if force
        response = raw(
          "PATCH",
          target_path,
          body: JSON.generate(resource),
          headers: {"Content-Type" => PATCH_CONTENT_TYPES.fetch(:apply), "Accept" => "application/json"},
          query: query
        )
        return response if return_response

        decode_response(response)
      end

      # Replaces a named resource (HTTP PUT): the ordinary authoritative update
      # client-go's Update sends.  The body's metadata.resourceVersion is the
      # optimistic-concurrency precondition; the server answers 409 when it
      # is stale and 404 when the object is gone -- an update never creates.
      def update(manifest, namespace: nil, path: nil, subresource: nil, return_response: false)
        resource = normalize_resource(manifest)
        name = resource.dig("metadata", "name")
        raise UsageError, "update manifest metadata.name is required" if name.to_s.empty?
        target_path = path || resource_path(resource, name, namespace: namespace, api_version: resource["apiVersion"],
                                             subresource: subresource, operation: :update)
        response = raw("PUT", target_path, body: encode_resource(resource), headers: json_headers)
        return response if return_response

        decode_response(response)
      end

      # Applies a JSON, merge, strategic, or server-side apply patch to a named resource.
      def patch(
        path_or_resource,
        patch_body = nil,
        type: :merge,
        namespace: nil,
        api_version: "v1",
        name: nil,
        path: nil,
        subresource: nil,
        return_response: false
      )
        resource = path_or_resource.is_a?(Hash) ? path_or_resource : nil
        target_path = path || if resource
                               resource_path(resource, name || resource.dig("metadata", "name"), namespace: namespace,
                                             api_version: api_version, subresource: subresource, operation: :patch)
                             else
                               resource_path(path_or_resource, name, namespace: namespace, api_version: api_version,
                                             subresource: subresource, operation: :patch)
                             end
        content_type = patch_content_type(type)
        response = raw(
          "PATCH",
          target_path,
          body: encode_patch_body(patch_body, content_type),
          headers: {"Content-Type" => content_type, "Accept" => "application/json"}
        )
        return response if return_response

        decode_response(response)
      end

      # Deletes a named resource and decodes any response body.
      # A DELETE carries its DeleteOptions in the body, the way client-go
      # sends them (gracePeriodSeconds, preconditions, propagationPolicy):
      # preconditions in particular have no query-parameter form, and without
      # them a delete by name can remove a REPLACEMENT object that has since
      # taken the name.
      def delete(path_or_resource, name = nil, namespace: nil, api_version: "v1", query: nil,
                 subresource: nil, return_response: false, options: nil)
        path = resource_path(path_or_resource, name, namespace: namespace, api_version: api_version,
                             subresource: subresource, operation: name ? :delete : :deletecollection)
        body = nil
        headers = {}
        unless options.nil?
          payload = options.respond_to?(:to_h) ? options.to_h : options
          document = {"apiVersion" => "v1", "kind" => "DeleteOptions"}.merge(
            payload.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
          )
          body = JSON.generate(document)
          headers["content-type"] = "application/json"
        end
        response = raw("DELETE", path, query: query, body: body, headers: headers)
        return response if return_response

        decode_response(response)
      end

      # Starts a watch request and returns its raw streaming response by default. Set
      # return_response to false to parse the bounded newline-delimited JSON event stream.
      def watch(path_or_resource, namespace: nil, api_version: "v1", query: {}, subresource: nil,
                return_response: true, max_bytes: DEFAULT_WATCH_MAX_BYTES, max_events: DEFAULT_WATCH_MAX_EVENTS,
                reconnect: true, max_reconnects: DEFAULT_WATCH_RECONNECTS)
        path = resource_path(path_or_resource, nil, namespace: namespace, api_version: api_version,
                             subresource: subresource, operation: :watch)
        unless query.respond_to?(:to_h)
          raise UsageError, "watch query must be a mapping"
        end

        if !return_response && reconnect && @rest_client.respond_to?(:stream)
          return collect_watch_events(path_or_resource, namespace: namespace, api_version: api_version,
                                      subresource: subresource, query: query, max_bytes: max_bytes,
                                      max_events: max_events, reconnect: reconnect,
                                      max_reconnects: max_reconnects)
        end
        watch_query = stringify_query(query).merge("watch" => "true")
        response = raw("GET", path, query: watch_query)
        return response if return_response

        parse_watch_stream(response.body, max_bytes: max_bytes, max_events: max_events)
      end

      # Fetches and parses a bounded watch stream into validated event mappings.
      def watch_events(path_or_resource, namespace: nil, api_version: "v1", query: {},
                       subresource: nil, max_bytes: DEFAULT_WATCH_MAX_BYTES,
                       max_events: DEFAULT_WATCH_MAX_EVENTS, reconnect: true,
                       max_reconnects: DEFAULT_WATCH_RECONNECTS)
        if @rest_client.respond_to?(:stream) && reconnect
          return collect_watch_events(path_or_resource, namespace: namespace, api_version: api_version,
                                      subresource: subresource, query: query, max_bytes: max_bytes,
                                      max_events: max_events, reconnect: reconnect,
                                      max_reconnects: max_reconnects)
        end
        watch(
          path_or_resource,
          namespace: namespace,
          api_version: api_version,
          subresource: subresource,
          query: query,
          return_response: false,
          max_bytes: max_bytes,
          max_events: max_events,
          reconnect: false,
          max_reconnects: 0
        )
      end

      # Yields validated watch events as the HTTP response arrives. This is the interface used by
      # the CLI so an unbounded watch does not wait for the server to close or buffer the entire
      # stream before producing output.
      def watch_each(path_or_resource, namespace: nil, api_version: "v1", query: {},
                     subresource: nil, max_bytes: DEFAULT_WATCH_MAX_BYTES,
                     max_events: DEFAULT_WATCH_MAX_EVENTS, reconnect: true,
                     max_reconnects: DEFAULT_WATCH_RECONNECTS, &block)
        unless block
          return enum_for(
            __method__,
            path_or_resource,
            namespace: namespace,
            api_version: api_version,
            query: query,
            subresource: subresource,
            max_bytes: max_bytes,
            max_events: max_events,
            reconnect: reconnect,
            max_reconnects: max_reconnects
          )
        end

        unless query.respond_to?(:to_h)
          raise UsageError, "watch query must be a mapping"
        end

        path = resource_path(path_or_resource, nil, namespace: namespace, api_version: api_version,
                             subresource: subresource, operation: :watch)
        watch_query = stringify_query(query).merge("watch" => "true")
        unless @rest_client.respond_to?(:stream)
          return watch_events(
            path_or_resource,
            namespace: namespace,
            api_version: api_version,
            query: query,
            subresource: subresource,
            max_bytes: max_bytes,
            max_events: max_events,
            reconnect: false,
            max_reconnects: 0
          ).each(&block)
        end

        stream_watch(path, watch_query, max_bytes: max_bytes, max_events: max_events,
                     reconnect: reconnect, max_reconnects: max_reconnects, &block)
      end

      # Close a transport-owned streaming watch during agent shutdown.  A
      # watch_each call without a block returns an Enumerator, which has no
      # close operation in Ruby 3.4; ownership therefore terminates at the
      # REST transport instead of leaving the response body blocked in read.
      def close
        return self unless @rest_client.respond_to?(:close)

        @rest_client.close
        self
      end

      private

      def resource_path(path_or_resource, name, namespace:, api_version:, use_manifest_name: true,
                        subresource: nil, operation: nil)
        manifest = nil
        if path_or_resource.is_a?(Hash)
          manifest = stringify_keys(path_or_resource)
          kind = manifest["kind"].to_s
          raise UsageError, "Kubernetes manifest kind is required" if kind.empty?
          api_version = manifest["apiVersion"] if api_version.to_s.empty? || api_version.to_s == "v1" && manifest["apiVersion"]
          namespace ||= manifest.dig("metadata", "namespace")
          name ||= manifest.dig("metadata", "name") if use_manifest_name
          path_or_resource = kind
        end
        path = path_or_resource.to_s
        if path.start_with?("/")
          absolute = path.sub(%r{/+\z}, "")
          absolute = "#{absolute}/#{escape_path(name)}" if name
          absolute = "#{absolute}/#{escape_path(subresource)}" if subresource
          return absolute
        end

        resource = path
        raise UsageError, "Kubernetes resource name is required" if resource.empty?
        version = api_version.to_s
        raise UsageError, "Kubernetes apiVersion is required" if version.empty?
        if version == "v1" && !resource.include?("/")
          version = discover_default_api_version(resource) || version
        end

        group, version_name = version.split("/", 2)
        if version_name.nil?
          group = ""
          version_name = version
          base = "/api/#{escape_path(version_name)}"
        else
          base = "/apis/#{escape_path(group)}/#{escape_path(version_name)}"
        end
        resource_name, embedded_subresource = resource.split("/", 2)
        subresource ||= embedded_subresource
        descriptor = rest_mapper_descriptor(resource, group: group, version: version_name)
        descriptor ||= static_descriptor(resource, group: group, version: version_name)
        descriptor ||= discover_descriptor(resource, group: group, version: version_name)
        resource_name = descriptor ? descriptor.resource : resource_name_for_kind(resource_name)
        namespaced = descriptor ? descriptor.namespaced : !self.class.cluster_scoped_resources.include?(resource_name)
        raise UsageError, "Kubernetes subresource name is required" if subresource && name.to_s.empty?
        validate_verb!(descriptor, operation, subresource)
        path_parts = [base]
        if namespaced
          selected_namespace = namespace || context_namespace
          if selected_namespace && selected_namespace != :all && !selected_namespace.to_s.empty?
            path_parts.concat(["namespaces", escape_path(selected_namespace)])
          end
        end
        path_parts << escape_path(resource_name)
        path_parts << escape_path(name) if name
        path_parts << escape_path(subresource) if subresource
        path_parts.join("/")
      end

      def rest_mapper_descriptor(value, group:, version:)
        if @rest_mapper
          api_version = api_version_for(group, version)
          candidate = if @rest_mapper.respond_to?(:resolve)
                        call_mapper(@rest_mapper.method(:resolve), value, api_version)
                      elsif @rest_mapper.respond_to?(:resource_for)
                        call_mapper(@rest_mapper.method(:resource_for), value, api_version)
                      elsif @rest_mapper.respond_to?(:call)
                        call_mapper(@rest_mapper.method(:call), value, api_version)
                      end
          normalized = normalize_descriptor(candidate, group: group, version: version)
          return normalized if normalized
        end

        lookup_discovery_descriptor(value, group: group, version: version)
      rescue ArgumentError, NoMethodError
        nil
      end

      def call_mapper(callable, value, api_version)
        parameters = callable.parameters
        return callable.call(value, api_version: api_version) if parameters.any? { |kind, name| kind == :keyrest || name == :api_version }
        return callable.call(value, api_version) if parameters.length >= 2

        callable.call(value)
      end

      def static_descriptor(value, group:, version:)
        resource_name, subresource = value.to_s.split("/", 2)
        kind = resource_name if RESOURCE_PLURALS.key?(resource_name)
        kind ||= RESOURCE_PLURALS.find { |_candidate, plural| plural == resource_name }&.first
        plural = kind ? RESOURCE_PLURALS.fetch(kind) : resource_name
        return nil unless kind || RESOURCE_PLURALS.value?(plural)
        return nil if group.to_s.empty? && version.to_s == "v1" && !CORE_STATIC_KINDS.include?(kind || resource_name)

        descriptor = ResourceDescriptor.new(
          group: group.to_s,
          version: version.to_s,
          resource: plural,
          kind: kind || resource_name,
          namespaced: !self.class.cluster_scoped_resources.include?(plural),
          verbs: %w[get list watch create update patch delete deletecollection],
          short_names: [],
          singular_name: plural.sub(/s\z/, ""),
          list_kind: "#{kind || resource_name}List",
          subresource: subresource
        )
        descriptor
      end

      def discover_default_api_version(value)
        static = static_descriptor(value, group: "", version: "v1")
        return "v1" if static

        resource_name = value.to_s.split("/", 2).first
        candidates = @discovery_entries.values.select do |descriptor|
          !descriptor.subresource? &&
            (descriptor.resource == resource_name || descriptor.kind == resource_name ||
             descriptor.short_names.include?(resource_name))
        end
        if candidates.empty?
          discover!
          candidates = @discovery_entries.values.select do |descriptor|
            !descriptor.subresource? &&
              (descriptor.resource == resource_name || descriptor.kind == resource_name ||
               descriptor.short_names.include?(resource_name))
          end
        end
        return nil if candidates.empty?

        candidates.group_by(&:group).sort_by(&:first).each do |group, entries|
          versions = entries.map(&:version).uniq
          preferred = pinned_discovery_versions(group, versions).first
          preferred ||= @discovery_preferred[group].to_s
          selected = entries.find { |entry| entry.version == preferred } || entries.sort_by(&:version).first
          return selected.api_version if selected
        end
        nil
      rescue APIError, TransportError, ConfigurationError, WatchStreamError
        nil
      end

      def discover_descriptor(value, group:, version:)
        discover!
        lookup_discovery_descriptor(value, group: group, version: version)
      rescue APIError, TransportError, ConfigurationError, WatchStreamError
        # Keep the historic static mapper usable for injected transports which
        # intentionally expose only the CRUD endpoint under test. A successful
        # discovery response, however, is authoritative and is handled by the
        # lookup above.
        nil
      end

      def lookup_discovery_descriptor(value, group:, version:)
        direct_key = "#{group}/#{version}/#{value}"
        direct = @discovery_entries[direct_key]
        return direct if direct

        resource_name, subresource = value.to_s.split("/", 2)
        key = "#{group}/#{version}/#{resource_name}"
        descriptor = @discovery_entries[key]
        unless descriptor
          descriptor = @discovery_by_kind[[group.to_s, version.to_s, resource_name.to_s]]
        end
        unless descriptor
          descriptor = @discovery_by_kind[[group.to_s, version.to_s, resource_name.to_s.downcase]]
        end
        return nil unless descriptor
        return descriptor unless subresource

        # The subresource entry is looked up directly under the canonical
        # plural.  Recursing here re-enters with the same string whenever the
        # requested name already *is* the plural ("pods/binding"), which
        # overflows the stack instead of answering.
        canonical = @discovery_entries["#{group}/#{version}/#{descriptor.resource}/#{subresource}"]
        canonical || descriptor.dup.tap { |copy| copy.subresource = subresource }
      end

      def normalize_descriptor(value, group:, version:)
        return value if value.is_a?(ResourceDescriptor)
        return nil unless value.respond_to?(:to_h) || value.is_a?(Hash)

        attributes = value.to_h
        attributes = attributes.transform_keys(&:to_s)
        descriptor = ResourceDescriptor.new(
          group: attributes["group"] || group,
          version: attributes["version"] || version,
          resource: attributes["resource"] || attributes["name"],
          kind: attributes["kind"] || attributes["kindName"],
          namespaced: attributes.key?("namespaced") ? attributes["namespaced"] : attributes["scope"].to_s.downcase == "namespaced",
          verbs: Array(attributes["verbs"]),
          short_names: Array(attributes["shortNames"] || attributes["short_names"]),
          singular_name: attributes["singularName"] || attributes["singular_name"],
          list_kind: attributes["listKind"] || attributes["list_kind"],
          subresource: attributes["subresource"]
        )
        return nil if descriptor.resource.to_s.empty? || descriptor.kind.to_s.empty?

        descriptor
      rescue KeyError, TypeError
        nil
      end

      def validate_verb!(descriptor, operation, subresource)
        return if descriptor.nil? || operation.nil?
        candidate = descriptor
        if subresource
          candidate = lookup_discovery_descriptor("#{descriptor.resource}/#{subresource}",
                                                  group: descriptor.group, version: descriptor.version) || descriptor
        end
        verbs = Array(candidate.verbs).map(&:to_s)
        return if verbs.empty? || verbs.include?(operation.to_s) || (operation == :patch && verbs.include?("update"))

        target = subresource ? "#{descriptor.resource}/#{subresource}" : descriptor.resource
        raise UsageError, "Kubernetes discovery does not allow #{operation} for #{target}"
      end

      def api_version_for(group, version)
        group.to_s.empty? ? version.to_s : "#{group}/#{version}"
      end

      def discover_core_versions!
        payload = decode_response(raw("GET", "/api"))
        versions = Array(payload.is_a?(Hash) ? payload["versions"] : payload)
        versions.each do |version|
          version = version.to_s
          next if version.empty?
          register_resource_list(group: "", version: version,
                                 payload: decode_response(raw("GET", "/api/#{escape_path(version)}")))
        end
      end

      def discover_api_groups!
        payload = decode_response(raw("GET", "/apis"))
        groups = payload.is_a?(Hash) ? Array(payload["groups"]) : []
        groups.each do |group_payload|
          next unless group_payload.is_a?(Hash)
          group = group_payload["name"].to_s
          next if group.empty?
          preferred = group_payload.dig("preferredVersion", "version").to_s
          @discovery_preferred[group] = preferred unless preferred.empty?
          versions = Array(group_payload["versions"]).filter_map do |entry|
            entry.is_a?(Hash) ? entry["version"].to_s : entry.to_s
          end.reject(&:empty?)
          versions = [preferred, *versions].compact.uniq unless preferred.empty?
          ordered = pinned_discovery_versions(group, versions)
          ordered.each do |version|
            register_resource_list(
              group: group,
              version: version,
              payload: decode_response(raw("GET", "/apis/#{escape_path(group)}/#{escape_path(version)}"))
            )
          end
        end
      end

      def pinned_discovery_versions(group, versions)
        priority = PINNED_VERSION_PRIORITY.fetch(group.to_s, [])
        available = versions.map(&:to_s).uniq
        priority.select { |version| available.include?(version) } + (available - priority).sort
      end

      def register_resource_list(group:, version:, payload:)
        return unless payload.is_a?(Hash)
        entries = Array(payload["resources"]).select { |entry| entry.is_a?(Hash) }
        # Base resources are registered first because subresources inherit
        # scope and identity defaults from their parent APIResource entry.
        entries.sort_by { |entry| entry["name"].to_s.include?("/") ? 1 : 0 }.each do |entry|
          name = entry["name"].to_s
          next if name.empty?
          base_name, subresource = name.split("/", 2)
          parent = @discovery_entries["#{group}/#{version}/#{base_name}"]
          # APIResourceList may advertise a subresource under a different
          # response group/version than its parent (apps/.../scale is served
          # as autoscaling/v1 Scale).  Preserve that identity in the REST
          # mapper while retaining the parent's scope and plural.
          entry_group = (entry["group"] || group).to_s
          entry_version = (entry["version"] || version).to_s
          descriptor = ResourceDescriptor.new(
            group: entry_group,
            version: entry_version,
            resource: base_name,
            kind: (subresource ? (entry["kind"] || parent&.kind) : entry["kind"]).to_s,
            namespaced: subresource ? !!parent&.namespaced : !!entry["namespaced"],
            verbs: Array(entry["verbs"]).map(&:to_s),
            short_names: subresource ? Array(parent&.short_names) : Array(entry["shortNames"]),
            singular_name: subresource ? parent&.singular_name : entry["singularName"],
            list_kind: parent&.list_kind || "#{entry["kind"]}List",
            subresource: subresource
          )
          next if descriptor.kind.to_s.empty?
          key = "#{entry_group}/#{entry_version}/#{name}"
          @discovery_entries[key] = descriptor
          @discovery_cache[key] = descriptor.to_h
          @discovery_by_kind[[group.to_s, version.to_s, descriptor.kind.to_s]] = descriptor unless subresource
          descriptor.short_names.each do |short_name|
            @discovery_by_kind[[group.to_s, version.to_s, short_name.to_s]] = descriptor unless subresource
          end
        end
      end

      def seed_discovery_cache(cache)
        return unless cache.respond_to?(:each)
        cache.each do |key, value|
          if value.is_a?(Hash) && value["resources"].is_a?(Array)
            group, version = key.to_s.split("/", 2)
            group = "" if version.nil?
            version ||= group
            register_resource_list(group: group, version: version, payload: value)
            next
          end
          parts = key.to_s.split("/")
          if parts.length == 2
            group, version, resource = "", parts[0], parts[1]
          else
            next unless parts.length >= 3
            group, version, resource = parts[-3], parts[-2], parts[-1]
          end
          descriptor = normalize_descriptor(value, group: group, version: version)
          next unless descriptor
          descriptor.resource ||= resource
          descriptor.group = group
          descriptor.version = version
          @discovery_entries["#{group}/#{version}/#{resource}"] = descriptor
          @discovery_by_kind[[group, version, descriptor.kind.to_s]] = descriptor if descriptor.kind
        end
      end

      def context_namespace
        return nil unless @context
        if @context.respond_to?(:namespace)
          @context.namespace
        elsif @context.is_a?(Hash)
          @context[:namespace] || @context["namespace"]
        end
      end

      def resource_name_for_kind(value)
        string = value.to_s
        RESOURCE_PLURALS[string] || begin
          normalized = string.downcase
          normalized.end_with?("s") ? normalized : "#{normalized}s"
        end
      end

      def escape_path(value)
        value.to_s.split("/").map { |segment| URI::RFC2396_PARSER.escape(segment) }.join("/")
      end

      def normalize_resource(value)
        return stringify_keys(value) if value.is_a?(Hash)
        if value.is_a?(String)
          parsed = JSON.parse(value)
          return parsed if parsed.is_a?(Hash)
        end
        raise UsageError, "Kubernetes manifest must be a mapping"
      rescue JSON::ParserError => error
        raise ManifestError.new("manifest is not valid JSON: #{error.message}", cause: error), cause: error
      end

      def encode_resource(resource)
        JSON.generate(normalize_resource(resource))
      rescue JSON::GeneratorError => error
        raise ManifestError.new("manifest cannot be encoded as JSON: #{error.message}", cause: error), cause: error
      end

      def encode_patch_body(body, content_type)
        return body if body.is_a?(String)
        JSON.generate(stringify_keys(body))
      rescue JSON::GeneratorError => error
        raise UsageError.new("patch cannot be encoded as JSON: #{error.message}", cause: error), cause: error
      end

      def patch_content_type(type)
        key = type.to_s.downcase.tr("-", "_").to_sym
        return type.to_s if type.to_s.include?("/")
        PATCH_CONTENT_TYPES.fetch(key) do
          raise UsageError, "unsupported patch type #{type.inspect}; choose #{PATCH_CONTENT_TYPES.keys.join(", ")}"
        end
      end

      def json_headers
        {"Content-Type" => "application/json", "Accept" => "application/json"}
      end

      def stringify_query(query)
        unless query.respond_to?(:to_h)
          raise UsageError, "watch query must be a mapping"
        end

        query.to_h.each_with_object({}) { |(key, value), normalized| normalized[key.to_s] = value }
      end

      def decode_response(response)
        return nil if response.body.nil? || response.body.empty?
        return response.json if response.respond_to?(:json)

        JSON.parse(response.body)
      rescue JSON::ParserError => error
        raise Error.new("Kubernetes API returned a non-JSON body: #{error.message}", cause: error), cause: error
      end

      def collect_watch_events(path_or_resource, namespace:, api_version:, subresource:, query:,
                               max_bytes:, max_events:, reconnect:, max_reconnects:)
        events = []
        watch_each(path_or_resource, namespace: namespace, api_version: api_version,
                   subresource: subresource, query: query, max_bytes: max_bytes,
                   max_events: max_events, reconnect: reconnect, max_reconnects: max_reconnects) do |event|
          events << event
        end
        events
      end

      def stream_watch(path, base_query, max_bytes:, max_events:, reconnect:, max_reconnects:)
        reconnect_limit = Integer(max_reconnects)
        raise UsageError, "watch max_reconnects must be non-negative" if reconnect_limit.negative?
        last_resource_version = base_query["resourceVersion"]&.to_s
        reconnect_count = 0

        loop do
          current_query = base_query.dup
          current_query["resourceVersion"] = last_resource_version if last_resource_version && !last_resource_version.empty?
          if reconnect_count.positive?
            # sendInitialEvents and resourceVersionMatch describe only the
            # initial watch-list handshake; a resumed ordinary watch carries
            # the bookmark/list resourceVersion directly.
            current_query.delete("sendInitialEvents")
            current_query.delete("resourceVersionMatch")
          end
          begin
            stream = @rest_client.stream("GET", path, query: current_query)
            body = normalize_stream_response(stream, path)
            parse_watch_stream(body, max_bytes: max_bytes, max_events: max_events) do |event|
              if expired_watch_event?(event)
                raise WatchReset, "watch resourceVersion expired"
              end
              event_resource_version = watch_resource_version(event)
              last_resource_version = event_resource_version if event_resource_version
              yield event
            end
            return nil
          rescue APIError => error
            # 410 Gone is the caller's to handle.  Every watcher here (the
            # informer's reflector, the node sync loop, the proxy, the DNS
            # resolver) answers a failed watch with a full list that replays
            # the current state.  Resuming here from a fresh list version
            # instead skipped every event between the expired version and
            # that list without telling anyone: an idle DaemonSet informer,
            # reconnecting after the store had compacted five minutes of
            # history, never heard of the DaemonSet created in between and no
            # daemon Pod was created for the five minutes the e2e allowed.
            # A WatchReset (410 as an ERROR event) propagates the same way.
            raise unless reconnect && reconnect_count < reconnect_limit
            raise if error.status.to_i == 410
            raise unless transport_disconnect?(error)

            reconnect_count += 1
          rescue TransportError, EOFError, IOError => error
            raise unless reconnect && reconnect_count < reconnect_limit

            reconnect_count += 1
          rescue WatchLimitError
            # The byte and event limits bound ONE connection, not the watch:
            # a Pod watch under a conformance run streams 16 MiB in minutes.
            # Every event's resourceVersion has been recorded, so the watch
            # resumes exactly where the oversized connection stopped, the way
            # a server-side timeout (timeoutSeconds) is resumed.  Raising
            # instead reached the controller manager's reflectors as
            # `informer.failed`, and the node's DNS Pod watch as
            # `dns.watch_error`, each followed by a backoff during which the
            # informer went stale.
            raise unless reconnect && reconnect_count < reconnect_limit

            reconnect_count += 1
          end
        end
      end

      def normalize_stream_response(response, path)
        return response unless response.respond_to?(:status) && response.respond_to?(:body)

        normalized = normalize_rest_response(response)
        return normalized.body if normalized.success?

        if @rest_client.respond_to?(:raise_for_status!)
          @rest_client.raise_for_status!(normalized, "GET", path)
        end
        raise APIError.new("Kubernetes watch request GET #{path} failed with HTTP #{normalized.status}",
                           response: normalized)
      end

      def expired_watch_event?(event)
        return false unless event["type"].to_s == "ERROR"
        object = event["object"]
        return false unless object.is_a?(Hash)

        object["code"].to_i == 410 || object["reason"].to_s == "Expired"
      end

      def watch_resource_version(event)
        metadata = event.dig("object", "metadata") if event.is_a?(Hash)
        value = metadata["resourceVersion"] if metadata.is_a?(Hash)
        value.to_s unless value.nil? || value.to_s.empty?
      end

      def transport_disconnect?(error)
        error.status.to_i >= 500
      end

      def parse_watch_stream(body, max_bytes:, max_events:, &consumer)
        byte_limit = positive_limit(max_bytes, "watch max_bytes")
        event_limit = positive_limit(max_events, "watch max_events")
        events = []
        buffer = +""
        total_bytes = 0
        line_number = 0
        event_count = 0

        each_body_chunk(body) do |chunk|
          unless chunk.is_a?(String)
            raise WatchStreamError, "watch stream chunks must be strings"
          end

          total_bytes += chunk.bytesize
          if total_bytes > byte_limit
            raise WatchLimitError, "watch stream exceeds #{byte_limit} bytes"
          end
          buffer << chunk

          while (newline_index = buffer.index("\n"))
            line = buffer.slice!(0, newline_index)
            buffer.slice!(0, 1)
            line_number += 1
            event = decode_watch_event(line, line_number)
            next if event.nil?

            raise WatchLimitError, "watch stream exceeds #{event_limit} events" if event_count >= event_limit
            event_count += 1
            consumer ? consumer.call(event) : events << event
          end
        end

        unless buffer.empty?
          line_number += 1
          event = decode_watch_event(buffer, line_number)
          if event
            raise WatchLimitError, "watch stream exceeds #{event_limit} events" if event_count >= event_limit
            consumer ? consumer.call(event) : events << event
          end
        end
        consumer ? nil : events
      end

      def each_body_chunk(body)
        return if body.nil?
        if body.is_a?(String)
          yield body
        elsif body.respond_to?(:each)
          body.each { |chunk| yield chunk }
        else
          raise WatchStreamError, "watch response body must be a string or enumerable stream"
        end
      end

      def decode_watch_event(line, line_number)
        stripped = line.strip
        return nil if stripped.empty?

        event = JSON.parse(
          stripped,
          object_class: ManifestReader::DuplicateKeyHash,
          create_additions: false,
          max_nesting: 512
        )
        unless event.is_a?(Hash)
          raise WatchStreamError, "watch stream line #{line_number} must be a JSON object"
        end

        event_type = event["type"]
        unless WATCH_EVENT_TYPES.include?(event_type)
          raise WatchStreamError, "watch stream line #{line_number} has an unsupported event type"
        end
        unless event["object"].is_a?(Hash)
          raise WatchStreamError, "watch stream line #{line_number} must contain an object mapping"
        end

        event
      rescue JSON::ParserError, ManifestError => error
        raise WatchStreamError.new("watch stream line #{line_number} is malformed: #{error.message}", cause: error), cause: error
      end

      def positive_limit(value, name)
        limit = Integer(value)
        raise UsageError, "#{name} must be positive" unless limit.positive?

        limit
      rescue ArgumentError, TypeError => error
        raise UsageError.new("#{name} must be a positive integer: #{error.message}", cause: error), cause: error
      end

      def normalize_rest_response(response)
        return response if response.respond_to?(:success?) && response.respond_to?(:body)
        if response.is_a?(Hash)
          return HTTPClient::Response.new(status: 200, headers: {"content-type" => "application/json"}, body: JSON.generate(response))
        end
        unless response.respond_to?(:status) && response.respond_to?(:body)
          raise TransportError, "REST client returned an invalid response object"
        end

        body = response.body.is_a?(String) ? response.body : JSON.generate(response.body)
        HTTPClient::Response.new(
          status: response.status,
          headers: response.respond_to?(:headers) ? response.headers : {},
          body: body
        )
      end

      def stringify_keys(value)
        case value
        when Hash
          value.to_h { |key, child| [key.to_s, stringify_keys(child)] }
        when Array
          value.map { |child| stringify_keys(child) }
        else
          value
        end
      end
    end

    APIClient = KubernetesClient
  end
end
