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
            aggregated_discovery?(request) ? aggregated_discovery_response(core_only: true) : json_response(api_versions_payload)
          when :api_groups
            aggregated_discovery?(request) ? aggregated_discovery_response(core_only: false) : json_response(api_groups_payload)
          when :api_group then api_group_response(route)
          when :resource_list then resource_list_response(route)
          when :health then health_response(route.path)
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

        # kube-apiserver registers one go-restful web service per served
        # group/version; a miss inside one of them is rendered as a Status,
        # while every other path falls through to the generic HTTP mux and its
        # plain-text "404 page not found".
        def unknown_path_response(route)
          segments = route.path.to_s.split("/").reject(&:empty?)
          group_version = if segments.first == "api" && segments.length >= 2
                            ["", segments[1]]
                          elsif segments.first == "apis" && segments.length >= 3
                            [segments[1], segments[2]]
                          end
          return discovery_not_found_response if group_version.nil?

          served = enabled_resources.any? { |resource| resource.group == group_version[0] && resource.version == group_version[1] }
          return discovery_not_found_response unless served

          error_response(Status::NotFound.new("the server could not find the requested resource", details: {}))
        end

        def resource_response(request, route)
          resource = route.resource
          raise Status::NotFound.new("the requested API path #{route.path.inspect} was not found") unless resource_enabled?(resource)

          api_verb = api_verb_for(request, route)
          allowed_verbs = route.subresource ? resource.subresource_verbs(route.subresource) : resource.verbs
          # A proxy subresource is a Connecter: upstream's ProxyREST accepts
          # every method (GET POST PUT PATCH DELETE HEAD OPTIONS) and relays it,
          # whatever discovery lists as verbs.  "[sig-network] Proxy version v1
          # A set of valid responses are returned for both pod and service
          # Proxy" sends OPTIONS.
          proxy = route.subresource.to_s == "proxy"
          unless proxy || allowed_verbs.empty? || allowed_verbs.include?(api_verb)
            target = route.subresource ? "#{resource.resource}/#{route.subresource}" : resource.resource
            raise Status::MethodNotAllowed.new("verb #{request.method} is not supported for #{target}")
          end

          return bridged_subresource_response(request, route) if @subresource_bridge&.handles?(route)

          virtual = virtual_resource_response(request, route)
          return virtual if virtual

          return watch_response(request, route) if watch_request?(request)

          case request.method
          when "GET", "HEAD"
            route.collection ? list_response(request, route) : get_response(route)
          when "POST"
            require_collection!(route)
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
          raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                     details: resource_details(route))
        end

        def api_verb_for(request, route)
          method = request.method
          return "watch" if method == "GET" && watch_request?(request)
          return "list" if %w[GET HEAD].include?(method) && route.collection
          return "get" if %w[GET HEAD].include?(method)
          return "create" if method == "POST"
          return "update" if method == "PUT"
          return "patch" if method == "PATCH"
          return "deletecollection" if method == "DELETE" && route.collection
          return "delete" if method == "DELETE"

          method.downcase
        end

        def require_collection!(route)
          raise Status::Invalid.new("operation requires a resource collection") unless route.collection
        end

        def require_member!(route)
          raise Status::Invalid.new("operation requires a named resource") if route.collection || route.name.nil?
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
