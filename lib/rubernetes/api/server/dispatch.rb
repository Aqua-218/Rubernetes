# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Routes a request to its handler: the non-resource endpoints, the streaming
      # subresource bridge, the virtual REST resources, and the verb handlers.
      module Dispatch
        private

        def dispatch(request, route)
          aggregated = aggregated_response(request, route)
          return aggregated if aggregated

          case route.kind
          when :version then json_response(version_payload)
          when :api_versions
            discovery_response(request, core_only: true)
          when :api_groups
            discovery_response(request, core_only: false)
          when :api_group then api_group_response(route)
          when :resource_list then resource_list_response(route)
          when :health then health_response(request, route.path)
          when :metrics then route.path == "/metrics/slis" ? slis_response : metrics_response
          when :statusz then zpage_response(:statusz, request)
          when :flagz then zpage_response(:flagz, request)
          when :openapi then openapi_response(request, route)
          when :openid then openid_response(request, route)
          when :resource then resource_response(request, route)
          else
            unknown_path_response(route)
          end
        end

        # Misses below an installed Kubernetes API group use its Status
        # serializer, including requests for an unserved version. Paths
        # outside those groups fall through to the generic HTTP mux.
        def unknown_path_response(route)
          segments = route.path.to_s.split("/").reject(&:empty?)
          group = case segments
                  in ["api", _, *] then ""
                  in ["apis", name, _, *] then name
                  else nil
                  end
          return discovery_not_found_response unless group && enabled_resources.any? { |resource| resource.group == group }

          error_response(Status::NotFound.new("the server could not find the requested resource", details: {}))
        end

        def resource_response(request, route)
          resource = route.resource
          raise Status::NotFound.new("the requested API path #{route.path.inspect} was not found") unless resource_enabled?(resource)

          storage_version_precondition!(request, route)
          api_verb = api_verb_for(request, route)
          return discovery_not_found_response if resource.custom? && resource.namespaced? && !route.namespace && !%w[list watch].include?(api_verb)

          allowed_verbs = route.subresource ? resource.subresource_verbs(route.subresource) : resource.verbs
          # A proxy subresource is a Connecter: upstream's ProxyREST accepts
          # every method (GET POST PUT PATCH DELETE HEAD OPTIONS) and relays it,
          # whatever discovery lists as verbs.  "[sig-network] Proxy version v1
          # A set of valid responses are returned for both pod and service
          # Proxy" sends OPTIONS.
          proxy = route.subresource.to_s == "proxy"
          unless proxy || (api_verb && (allowed_verbs.empty? || allowed_verbs.include?(api_verb)))
            if resource.custom?
              details = {"group" => resource.group, "kind" => resource.resource}
              raise Status::MethodNotAllowed.new("#{api_verb} is not supported on resources of kind \"#{resource.resource}.#{resource.group}\"",
                                                 details: details)
            end
            raise Status::MethodNotAllowed.new("the server does not allow this method on the requested resource", details: {})
          end

          return bridged_subresource_response(request, route) if @subresource_bridge&.handles?(route)

          validate_resource_accept!(request, route, api_verb) if request.header("accept") && !proxy

          virtual = virtual_resource_response(request, route)
          return virtual if virtual

          return watch_response(request, route) if api_verb == "watch"

          case request.method
          when "GET", "HEAD"
            route.collection ? list_response(request, route) : get_response(route)
          when "POST"
            create_response(request, route)
          when "PUT"
            require_member!(route)
            update_response(request, route)
          when "PATCH"
            require_member!(route)
            patch_response(request, route)
          when "DELETE"
            route.collection ? delete_collection_response(request, route) : delete_response(request, route)
          else
            raise Status::MethodNotAllowed.new("method #{request.method} is not supported for #{route.path}")
          end
        end

        def validate_resource_accept!(request, route, api_verb)
          validate_builtin_route_accept!(request, route)
          return if api_verb == "watch"
          return if !route.resource.custom? && %w[get list].include?(api_verb)

          Negotiation.negotiate_output(
            request.header("accept"),
            supported: response_media_types(route),
            table: table_supported?(route),
            protobuf: !route.resource.custom?
          )
        end

        def validate_builtin_route_accept!(request, route)
          return if route.resource.custom?

          produces = response_media_types(route)
          produces += Negotiation.stream_content_types(produces) if request.method == "GET" && (route.collection || route.operation == :watch)
          return if Negotiation.restful_route_accepts?(request.header("accept"), produces)

          raise Status::NotAcceptable.new("406: Not Acceptable\n\nAvailable representations: #{produces.join(", ")}", details: {})
        end

        # A Pod's exec, attach, portforward or log: authenticated, admitted as
        # a CONNECT, and handed to the bridge that reaches the node.
        def bridged_subresource_response(request, route)
          bridged_request = authenticate_request(request)
          pod = await_scheduled_pod(route, request)
          admit_streaming_subresource(bridged_request, route)
          record_pod_logs_usage(request) if route.subresource.to_s == "log"
          begin
            @subresource_bridge.call(bridged_request, route, pod: pod)
          rescue Status::Error => error
            best_effort { record_pod_logs_tls_failure(error) } if route.subresource.to_s == "log"
            # Streaming clients frequently crash on a log error rather than
            # reporting it, so the reason has to be recoverable from the
            # server's own log.
            warn("subresource.failed subresource=#{route.subresource} " \
                 "pod=#{route.namespace}/#{route.name} node=#{pod.dig("spec", "nodeName").inspect} " \
                 "error=#{error.class}: #{error.message}")
            raise
          end
        end

        # ---- virtual REST resources ------------------------------------------
        # These kinds are served by REST handlers rather than storage in
        # kube-apiserver: token/subject reviews, pod eviction, and component
        # status.  Each handler mirrors its upstream registry counterpart.
        def virtual_resource_response(request, route)
          resource = route.resource
          group = resource.group.to_s
          return eviction_response(request, route) if route.subresource == "eviction" && resource.resource == "pods" && group.empty?
          return binding_response(request, route) if route.subresource == "binding" && resource.resource == "pods" && group.empty?
          return proxy_response(request, route) if route.subresource == "proxy" && group.empty? && %w[pods services nodes].include?(resource.resource)
          if resource.resource == "componentstatuses" && group.empty? && route.subresource.nil?
            return %w[GET HEAD].include?(request.method) ? component_status_response(request, route) : nil
          end
          if route.subresource == "token" && resource.resource == "serviceaccounts" && group.empty?
            return request.method == "POST" ? token_request_response(request, route) : nil
          end
          return nil unless route.collection && route.subresource.nil?

          case [group, resource.resource]
          when ["", "bindings"]
            binding_response(request, route)
          when ["authentication.k8s.io", "tokenreviews"]
            request.method == "POST" ? token_review_response(request, route) : nil
          when ["authentication.k8s.io", "selfsubjectreviews"]
            request.method == "POST" ? self_subject_review_response(request, route) : nil
          when ["authorization.k8s.io", "selfsubjectrulesreviews"]
            request.method == "POST" ? self_subject_rules_review_response(request, route) : nil
          when ["authorization.k8s.io", "subjectaccessreviews"], ["authorization.k8s.io", "selfsubjectaccessreviews"],
               ["authorization.k8s.io", "localsubjectaccessreviews"]
            request.method == "POST" ? subject_access_review_response(request, route) : nil
          end
        end

        def subresource_object(route)
          namespace = storage_namespace(route, operation: :get)
          @store.get(resource: route.resource, namespace: namespace, name: route.name)
        rescue MemoryStore::NotFound
          raise missing_resource(route)
        end

        def api_verb_for(request, route)
          method = request.method
          return "watch" if route.watch_request?(request)
          return if route.operation == :watch && method != "GET"

          custom = route.resource.custom?
          return if !custom && route.resource.namespaced? && route.namespace.nil? && method != "GET"

          case method
          when "GET" then route.collection ? "list" : "get"
          when "HEAD" then (route.collection ? "list" : "get") if custom
          when "POST" then "create" if route.collection || route.subresource || custom
          when "PUT" then "update" if !route.collection || custom
          when "PATCH" then "patch" if !route.collection || custom
          when "DELETE" then route.collection ? "deletecollection" : "delete"
          end
        end

        def require_member!(route)
          raise Status::BadRequest.new("name must be provided") if route.name.nil?
        end

        POD_SCHEDULE_WAIT_SECONDS = Float(ENV.fetch("RUBERNETES_LOG_SCHEDULE_WAIT", "120"))

        # registry/core/pod/rest/log.go: kube_apiserver_pod_logs_insecure_backend_total
        # {usage} counts every pods/log request by how the kubelet is trusted
        # ("enforce_tls", or "skip_tls_allowed" when the caller asked for
        # insecureSkipTLSVerifyBackend), and _backend_tls_failure_total the
        # ones that failed on the kubelet's certificate.
        def record_pod_logs_usage(request)
          insecure = %w[1 true yes].include?(request.query_value("insecureSkipTLSVerifyBackend").to_s.downcase)
          @metrics&.increment("kube_apiserver_pod_logs_insecure_backend_total", {"usage" => insecure ? "skip_tls_allowed" : "enforce_tls"})
        end

        def record_pod_logs_tls_failure(error)
          message = error.message.to_s
          return unless message.match?(/certificate verify failed|SSL_connect|tls: |x509/i)

          @metrics&.increment("kube_apiserver_pod_logs_backend_tls_failure_total")
        end

        # A follow request is a long-lived stream, and clients open it as soon as
        # the pod exists.  The kubelet waits for the container in that case, so
        # the API server waits for the assignment that precedes it instead of
        # answering "not assigned to a node" for a pod that is about to be bound.
        def await_scheduled_pod(route, request)
          pod = subresource_object(route)
          return pod unless route.subresource.to_s == "log"

          # Not gated on `follow`: a client that asks for a pod's logs the moment
          # it is created is asking about a pod that is about to be bound, and
          # answering "not assigned to a node" is a race, not an answer.
          follow = %w[1 true yes].include?(request.query_value("follow").to_s.downcase)
          deadline = @clock.call.to_f + (follow ? POD_SCHEDULE_WAIT_SECONDS : 30.0)
          while pod.dig("spec", "nodeName").to_s.empty? && @clock.call.to_f < deadline
            sleep(0.5)
            pod = subresource_object(route)
          end
          pod
        end
      end
    end
  end
end
