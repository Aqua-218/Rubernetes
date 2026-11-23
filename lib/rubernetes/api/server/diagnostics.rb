# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The endpoints that report on the server itself: /healthz /livez /readyz,
      # /metrics and /metrics/slis, /statusz and /flagz, and the legacy
      # componentstatuses resource.
      module Diagnostics
        attr_accessor :startup_health

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
          cbor = feature_gate_enabled?("CBORServingAndStorage")
          status, headers, body = if page == :statusz
                                    git = @version_info.fetch("gitVersion", "").to_s.delete_prefix("v")
                                    Observability::ZPages.statusz(
                                      component: "kube-apiserver", start_time: (@process_start ||= Observability::ZPages.process_start_time),
                                      binary_version: git, emulation_version: git.split(".").first(2).join("."), paths: STATUSZ_PATHS,
                                      accept: accept, cbor: cbor
                                    )
                                  else
                                    Observability::ZPages.flagz(component: "kube-apiserver", flags: @component_flags || {}, accept: accept, cbor: cbor)
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

        HEALTH_HEADERS = {"content-type" => "text/plain; charset=utf-8", "cache-control" => "no-cache, private",
                          "x-content-type-options" => "nosniff"}.freeze

        def health_response(request, path)
          _, type, check = path.split("/", 3)
          checks = current_health_checks(type)
          return individual_health_check(check, checks) unless check.nil? || check.empty?

          excluded = request.query_values("exclude").uniq.sort
          failures = []
          lines = checks.map do |name, passed|
            next "[+]#{name} excluded: ok" if excluded.include?(name)

            health_slis.observe(name, type, passed)
            next "[+]#{name} ok" if passed

            failures << name
            "[-]#{name} failed: reason withheld"
          end
          unknown = excluded - checks.keys
          lines << "warn: some health checks cannot be excluded: no matches for #{unknown.map(&:inspect).join(",")}" unless unknown.empty?
          return Response.new(status: 500, headers: HEALTH_HEADERS, body: "#{lines.join("\n")}\n#{type} check failed\n") unless failures.empty?

          body = request.query.key?("verbose") ? "#{lines.join("\n")}\n#{type} check passed\n" : "ok"
          Response.new(status: 200, headers: HEALTH_HEADERS, body: body)
        end

        def current_health_checks(type)
          datastore = basic_datastore_ready?
          checks = {"ping" => true, "log" => @startup_health.nil? || @startup_health.log_healthy?, "etcd" => datastore}
          if @startup_health
            checks.merge!(@startup_health.checks(readyz: type == "readyz"))
            checks["poststarthook/storage-readiness"] = datastore if feature_gate_enabled?("WatchCacheInitializationPostStartHook")
          end
          checks["etcd-readiness"] = datastore && storage_version_registered? if type == "readyz"
          checks["storage-versions"] = storage_version_registered? if type == "healthz" && storage_version_reporting?
          checks
        end

        def individual_health_check(name, checks)
          return Response.new(status: 404, headers: HEALTH_HEADERS, body: "404 page not found\n") unless checks.key?(name)
          return Response.new(status: 200, headers: HEALTH_HEADERS, body: "ok") if checks.fetch(name)

          reason = name.start_with?("poststarthook/") ? "not finished" : "#{name} is not ready"
          Response.new(status: 500, headers: HEALTH_HEADERS, body: "internal server error: #{reason}\n")
        end
      end
    end
  end
end
