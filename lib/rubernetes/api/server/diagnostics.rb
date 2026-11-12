# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The endpoints that report on the server itself: /healthz /livez /readyz,
      # /metrics and /metrics/slis, /statusz and /flagz, and the legacy
      # componentstatuses resource.
      module Diagnostics
        private

        COMPONENT_STATUS_SERVERS = [
          {"name" => "scheduler", "url" => "https://127.0.0.1:10259/healthz"},
          {"name" => "controller-manager", "url" => "https://127.0.0.1:10257/healthz"},
          {"name" => "etcd-0", "url" => nil}
        ].freeze

        # pkg/registry/core/componentstatus/rest.go: the fixed server inventory
        # of the legacy endpoint, probed the way kube-apiserver probes it.
        COMPONENT_STATUS_DEPRECATION_WARNING = "299 - \"v1 ComponentStatus is deprecated in v1.19+\""

        def component_status_response(_request, route)
          statuses = COMPONENT_STATUS_SERVERS.map { |server| component_status(server) }
          response = if route.collection
                       json_response({"kind" => "ComponentStatusList", "apiVersion" => "v1", "metadata" => {}, "items" => statuses})
                     else
                       status = statuses.find { |entry| entry.dig("metadata", "name") == route.name.to_s }
                       unless status
                         raise Status::NotFound.new("componentstatus #{route.name.to_s.inspect} not found",
                                                    details: {"name" => route.name.to_s, "kind" => "componentstatus"})
                       end
                       json_response({"kind" => "ComponentStatus", "apiVersion" => "v1"}.merge(status))
                     end
          # kube-apiserver marks the resource deprecated on every response.
          Response.new(status: response.status, headers: response.headers.merge("warning" => COMPONENT_STATUS_DEPRECATION_WARNING),
                       body: response.body)
        end

        def component_status(server)
          healthy, message, error = component_health(server)
          condition = {"type" => "Healthy", "status" => healthy ? "True" : "False", "message" => message}
          condition["error"] = error unless error.to_s.empty?
          {"metadata" => {"name" => server.fetch("name")}, "conditions" => [condition]}
        end

        def component_health(server)
          if @component_health_checker
            result = @component_health_checker.call(server)
            return result if result.is_a?(Array)
          end
          return [true, "ok", nil] if server.fetch("url").nil?

          uri = URI(server.fetch("url"))
          http = Security::Egress.http(uri, "cluster")
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http.open_timeout = 2
          http.read_timeout = 2
          response = http.start { |connection| connection.get(uri.request_uri) }
          body = response.body.to_s
          if response.code.to_i == 200 && body.strip == "ok"
            [true, "ok", nil]
          else
            [false, "HTTP probe failed with statuscode: #{response.code}", body]
          end
        rescue Errno::ECONNREFUSED
          [false, "Get #{uri.to_s.inspect}: dial tcp #{uri.host}:#{uri.port}: connect: connection refused", nil]
        rescue StandardError => error
          [false, "Get #{uri.to_s.inspect}: #{error.message}", nil]
        end

        # The top-level paths /statusz lists besides the API and discovery trees.
        STATUSZ_PATHS = %w[/flagz /healthz /livez /metrics /readyz /version].freeze

        def zpage_response(page, request)
          accept = request.header("accept")
          status, headers, body = if page == :statusz
                                    git = @version_info.fetch("gitVersion", "").to_s.delete_prefix("v")
                                    Observability::ZPages.statusz(
                                      component: "kube-apiserver", start_time: (@process_start ||= Observability::ZPages.process_start_time),
                                      binary_version: git, emulation_version: git.split(".").first(2).join("."), paths: STATUSZ_PATHS,
                                      accept: accept
                                    )
                                  else
                                    Observability::ZPages.flagz(component: "kube-apiserver", flags: @component_flags || {}, accept: accept)
                                  end
          Response.new(status: status, headers: headers.merge("cache-control" => "no-cache, private"), body: body)
        end

        # /metrics in the Prometheus text format every Kubernetes component
        # serves.  Requests are counted as they are answered, so the endpoint
        # reflects this process rather than a static document.
        def metrics_response
          body = @metrics ? @metrics.render : ""
          Response.new(status: 200,
                       headers: {"content-type" => Observability::Metrics::CONTENT_TYPE, "cache-control" => "no-cache, private"},
                       body: body)
        end

        # /metrics/slis: the health check SLIs (component-base slis.Registry).
        def slis_response
          Response.new(status: 200,
                       headers: {"content-type" => Observability::Metrics::CONTENT_TYPE, "cache-control" => "no-cache, private"},
                       body: health_slis.render)
        end

        HEALTH_SLIS_MUTEX = Mutex.new

        def health_slis
          @health_slis || HEALTH_SLIS_MUTEX.synchronize { @health_slis ||= Observability::HealthcheckSLIs.new }
        end

        # The checks the root health handlers run: the handler itself (ping),
        # and on /readyz the datastore (etcd-readiness).
        def observe_health_checks(path, ready)
          type = Observability::HealthcheckSLIs.type_for(path)
          return unless type

          health_slis.observe("ping", type, true)
          health_slis.observe("etcd-readiness", type, ready) if type == "readyz"
        end

        def health_response(path)
          observe_health_checks(path, path != "/readyz" || ready?)
          if path == "/readyz" && !ready?
            return Response.new(status: 500, headers: {"content-type" => "text/plain; charset=utf-8",
                                                       "cache-control" => "no-cache, private",
                                                       "x-content-type-options" => "nosniff"}, body: "not ready")
          end

          Response.new(status: 200, headers: {"content-type" => "text/plain; charset=utf-8",
                                              "cache-control" => "no-cache, private",
                                              "x-content-type-options" => "nosniff"}, body: "ok")
        end
      end
    end
  end
end
