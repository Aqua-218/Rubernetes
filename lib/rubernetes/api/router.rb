# frozen_string_literal: true

require "uri"

module Rubernetes
  module API
    # Parses Kubernetes REST paths into stable route values. It performs no
    # storage or transport work, making it useful to HTTP and in-process tests.
    class Router
      PROXY_SUBRESOURCE = "proxy"

      Route = Struct.new(:kind, :operation, :group, :version, :resource, :namespace,
                         :name, :subresource, :collection, :path, :subresource_path, keyword_init: true) do
        def api_version
          group.to_s.empty? ? version.to_s : "#{group}/#{version}"
        end

        def discovery?
          %i[version api_versions api_groups resource_list health metrics].include?(kind)
        end

        def resource_route?
          kind == :resource
        end
      end

      def initialize(registry)
        @registry = registry.is_a?(RegistryAdapter) ? registry : RegistryAdapter.new(registry)
      end

      attr_reader :registry

      def route(request)
        path = request.respond_to?(:path) ? request.path.to_s : request.to_s
        segments = path.split("/").reject(&:empty?).map { |segment| URI::RFC2396_PARSER.unescape(segment) }
        return Route.new(kind: :root, operation: :root, path: path) if segments.empty?

        case segments
        in ["version"]
          return Route.new(kind: :version, operation: :get, path: path)
        in ["healthz"] | ["livez"] | ["readyz"] | ["healthz", *] | ["livez", *] | ["readyz", *]
          return Route.new(kind: :health, operation: :get, path: path)
        in ["metrics"] | ["metrics", *]
          return Route.new(kind: :metrics, operation: :get, path: path)
        in ["statusz"]
          return Route.new(kind: :statusz, operation: :get, path: path)
        in ["flagz"]
          return Route.new(kind: :flagz, operation: :get, path: path)
        in ["openapi", "v2"] | ["openapi", "v3"] | ["openapi", "v3", *]
          return Route.new(kind: :openapi, operation: :get, path: path)
        in [".well-known", "openid-configuration"] | ["openid", "v1", "jwks"]
          return Route.new(kind: :openid, operation: :get, path: path)
        in ["api"]
          return Route.new(kind: :api_versions, operation: :get, path: path)
        in ["apis"]
          return Route.new(kind: :api_groups, operation: :get, path: path)
        else
          # Continue below for API version and resource paths.
        end

        if segments.first == "api"
          parse_api_path(segments.drop(1), path, group: "")
        elsif segments.first == "apis"
          parse_apis_path(segments.drop(1), path)
        else
          Route.new(kind: :unknown, operation: :unknown, path: path)
        end
      rescue URI::InvalidURIError => error
        raise Status::BadRequest, "request path is malformed: #{error.message}"
      end

      private

      def parse_api_path(segments, path, group:)
        return Route.new(kind: :unknown, operation: :unknown, path: path) if segments.empty?

        version = segments.shift
        return Route.new(kind: :unknown, operation: :unknown, path: path) if version.nil? || version.empty?
        return Route.new(kind: :resource_list, operation: :get, group: group, version: version, path: path) if segments.empty?

        parse_resource_segments(segments, group: group, version: version, path: path)
      end

      def parse_apis_path(segments, path)
        return Route.new(kind: :api_groups, operation: :get, path: path) if segments.empty?

        group = segments.shift
        return Route.new(kind: :api_group, operation: :get, group: group, path: path) if segments.empty?

        version = segments.shift
        return Route.new(kind: :resource_list, operation: :get, group: group, version: version, path: path) if segments.empty?

        parse_resource_segments(segments, group: group, version: version, path: path)
      end

      def parse_resource_segments(segments, group:, version:, path:)
        namespace = nil
        # `namespaces` is itself a cluster-scoped resource. Treat it as the
        # namespace path marker only when another resource segment follows.
        if segments.first == "namespaces" && segments.length >= 3
          namespaced_resource = registry.find_gvr(group: group, version: version, resource: segments[2])
          # Cross-group subresources (notably autoscaling/v1 Scale) inherit
          # the parent resource's scope even though the parent is registered
          # under another API group.  Resolve that scope before consuming the
          # namespace marker; otherwise the alias URL is parsed as unknown.
          namespaced_resource ||= registry.find_subresource_parent(
            group: group, version: version, resource: segments[2],
            subresource: segments[-1]
          )
          if namespaced_resource&.namespaced?
            segments.shift
            namespace = segments.shift
            return Route.new(kind: :unknown, operation: :unknown, path: path) if namespace.nil?
          end
        end
        resource_name = segments.shift
        return Route.new(kind: :unknown, operation: :unknown, path: path) if resource_name.nil?

        resource = registry.find_gvr(group: group, version: version, resource: resource_name)
        name = segments.shift
        subresource = segments.shift
        # `proxy` forwards whatever path follows it to the target, so the
        # remaining segments belong to the proxied request, not to the route.
        subresource_path = nil
        if subresource == PROXY_SUBRESOURCE && !segments.empty?
          subresource_path = segments.join("/")
          segments = []
        end
        return Route.new(kind: :unknown, operation: :unknown, path: path) unless segments.empty?

        # The alias group exposes only the subresource route.  Do not make a
        # bare /autoscaling/v1/deployments collection accidentally resolve to
        # apps/v1; require the advertised child segment before accepting the
        # canonical parent resource.
        if subresource
          resource ||= registry.find_subresource_parent(
            group: group, version: version, resource: resource_name, subresource: subresource
          )
        end
        return Route.new(kind: :unknown, operation: :unknown, path: path) if resource.nil?
        return Route.new(kind: :unknown, operation: :unknown, path: path) if resource.cluster_scoped? && !namespace.nil?

        return Route.new(kind: :unknown, operation: :unknown, path: path) if subresource && resource.subresource(subresource).nil?

        collection = name.nil?
        operation = operation_for(collection: collection, subresource: subresource)
        Route.new(kind: :resource, operation: operation, group: group, version: version,
                  resource: resource, namespace: namespace, name: name,
                  subresource: subresource, collection: collection, path: path,
                  subresource_path: subresource_path)
      end

      def operation_for(collection:, subresource:)
        return :list if collection && subresource.nil?
        return :subresource if subresource

        :get
      end
    end
  end
end
