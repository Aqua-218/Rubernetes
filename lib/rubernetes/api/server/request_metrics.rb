# frozen_string_literal: true

require_relative "../peer_transport"

module Rubernetes
  module API
    class Server
      # What is recorded about a served request: the apiserver_request_* series,
      # the slow-request and trace log lines, and the metering of long-running
      # responses.
      module RequestMetrics
        # endpoints/metrics validConnectRequests: reported as CONNECT.
        CONNECT_SUBRESOURCES = %w[log exec portforward attach proxy].freeze

        APPLY_PATCH_TYPE = "application/apply-patch+yaml"

        private

        SLOW_REQUEST_SECONDS = 3.0

        # A request that took seconds is otherwise invisible: the client sees a
        # slow answer and the server logs nothing.  Watches are excluded, they
        # are long by design.
        def log_slow_request(request, route, response, started)
          return unless @logger && request && started
          return if route && (route.kind == :metrics || route.operation == :watch)

          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
          if (phases = Thread.current[REQUEST_PHASES_KEY])
            slowest_first = phases.sort_by { |_name, seconds| -seconds }.to_h.transform_values { |seconds| seconds.round(4) }
            @logger.info("request.trace", method: request.method, path: request.path.to_s[0, 200],
                                          status: response&.status, seconds: elapsed.round(4), phases: slowest_first)
          end
          return if elapsed < SLOW_REQUEST_SECONDS

          @logger.warn("request.slow", method: request.method, path: request.path.to_s[0, 200],
                                       status: response&.status, seconds: elapsed.round(3))
        end

        # One served request, counted the way kube-apiserver counts it.  The
        # metrics endpoint itself is not counted, so scraping cannot inflate
        # the very numbers it reports.
        def record_request_metric(request, route, response, started, webhook_seconds: 0.0, slow_log: true)
          # A watch or a followed log lasts as long as the client wants: its
          # duration is not a slow request.  A logger that fails does not cost
          # the request its metrics.
          best_effort { log_slow_request(request, route, response, started) } if slow_log
          return unless @metrics && request && response
          return if route && route.kind == :metrics

          size = response_body_size(response)
          dry_run = Array(request.query_values("dryRun")).sort.join(",")
          labels = request_metric_labels(request, route)
          if size.nil? && %w[GET LIST].include?(labels[:verb])
            metrics = @metrics
            endpoint = Observability::Metrics.request_labels(**labels)
            response.on_body_encoded { |bytes| metrics.response_size(endpoint, bytes) }
          end
          @metrics.record_request(**labels, code: response.status,
                                            duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                                            dry_run: dry_run, response_size: size, webhook_seconds: webhook_seconds)
          record_request_extras(request, route, labels)
        end

        # The bytes of a body that is already encoded; nil for one the
        # transport still has to encode (it reports the size then).
        def response_body_size(response)
          body = response.body
          size = if body.is_a?(String)
                   body.bytesize
                 else
                   (body.is_a?(Array) && body.all?(String) ? body.sum(&:bytesize) : nil)
                 end
          size || (response.encoded_body.bytesize if response.encoded_body.is_a?(String))
        end

        # The rest of MonitorRequest and the body read: the series
        # fieldValidationRequestLatencies creates (and never observes),
        # apiserver_selfrequest_total for the loopback user, and
        # apiserver_request_body_size_bytes for a body a handler read.
        def record_request_extras(request, route, labels)
          @metrics.touch("field_validation_request_duration_seconds", {"field_validation" => metric_field_validation(request)})
          endpoint = Observability::Metrics.request_labels(**labels)
          identity = request.identity
          user = identity.is_a?(Hash) ? (identity["username"] || identity[:username]) : nil
          @metrics.increment("apiserver_selfrequest_total", endpoint.slice("verb", "group", "resource", "subresource")) if user.to_s == "system:apiserver"
          verb = REQUEST_BODY_VERBS[request.method.to_s.upcase]
          verb = "delete_collection" if verb == "delete" && route&.name.nil?
          body = request.body
          return unless verb && route&.resource_route? && body.is_a?(String)
          return if verb.start_with?("delete") && body.empty?

          @metrics.observe("apiserver_request_body_size_bytes", body.bytesize,
                           {"group" => route.resource.group.to_s, "resource" => route.resource.resource.to_s, "verb" => verb})
        end

        REQUEST_BODY_VERBS = {"POST" => "create", "PUT" => "update", "PATCH" => "patch", "DELETE" => "delete"}.freeze

        # RecordRequestTermination: a request the server itself cut short
        # (priority and fairness rejected it, 429).
        def record_request_termination(request, route, code)
          return unless @metrics && request

          labels = Observability::Metrics.request_labels(**request_metric_labels(request, route))
          @metrics.increment("apiserver_request_terminations_total", labels.merge("code" => code.to_s))
        end

        # The endpoint labels MonitorRequest reports: CleanScope, and the verb
        # as CanonicalVerb + CleanVerb make it (LIST for a collection GET,
        # WATCH, APPLY for an apply patch, CONNECT for the streaming
        # subresources; anything else "other").
        def request_metric_labels(request, route)
          resource = route&.resource_route? ? route.resource : nil
          subresource = route&.subresource
          name = if resource
                   subresource ? "#{resource.resource}/#{subresource}" : resource.resource
                 else
                   (route&.kind || "unknown").to_s
                 end
          method = request.method.to_s.upcase
          scope = if resource && (route.name || method == "POST")
                    "resource"
                  elsif resource && route.namespace
                    "namespace"
                  elsif resource
                    "cluster"
                  else
                    ""
                  end
          verb = method
          verb = scope == "resource" || scope.empty? ? "GET" : "LIST" if %w[GET HEAD].include?(method)
          verb = "WATCH" if method == "GET" && route&.watch_request?(request)
          verb = "APPLY" if method == "PATCH" && request.header("content-type").to_s.split(";").first.to_s.strip == APPLY_PATCH_TYPE
          verb = "CONNECT" if resource && CONNECT_SUBRESOURCES.include?(subresource.to_s)
          verb = "other" unless %w[APPLY CONNECT CREATE DELETE DELETECOLLECTION GET LIST PATCH POST PROXY PUT UPDATE WATCH
                                   WATCHLIST].include?(verb)
          {verb: verb, resource: name, group: resource ? resource.group : "", version: resource ? resource.version : "", scope: scope}
        end

        # A watch or a streaming subresource whose stream (or upgraded
        # connection) outlives this call: the same response, metered until it
        # ends; nil for everything else.
        def long_running_response(request, route, response, started, webhook_seconds)
          return nil unless @metrics && request && route&.resource_route? && response.is_a?(Response)

          watch = request.method == "GET" && route&.watch_request?(request)
          return nil unless watch || LONG_RUNNING_SUBRESOURCES.include?(route.subresource.to_s)

          return nil unless streaming_body?(response) || response.upgrade?

          labels = Observability::Metrics.request_labels(**request_metric_labels(request, route))
          finish = lambda do
            best_effort { record_request_metric(request, route, response, started, webhook_seconds: webhook_seconds, slow_log: false) }
          end
          if response.upgrade?
            upgrade = response.upgrade
            metrics = @metrics
            metered = lambda do |*arguments|
              metrics.longrunning(labels, 1)
              begin
                upgrade.call(*arguments)
              ensure
                metrics.longrunning(labels, -1)
                finish.call
              end
            end
            metered.define_singleton_method(:close) { upgrade.close } if upgrade.is_a?(PeerTransport::UpgradeRelay) || upgrade.is_a?(WatchWebSocket)
            return Response.new(status: response.status, headers: response.headers, body: response.body, stream: response.stream?,
                                upgrade: metered, unbounded: response.unbounded?, encoded_body: response.encoded_body)
          end

          resource = route.resource
          events = if watch && resource && !response.body.is_a?(PeerTransport::Stream)
                     {"group" => resource.group.to_s, "version" => resource.version.to_s, "resource" => resource.resource.to_s}
                   end
          watch_list = if events && truthy?(query(request, "sendInitialEvents")) && feature_gate_enabled?("WatchList")
                         {labels: events.merge("scope" => labels["scope"]), started: started}
                       end
          body = LongRunningBody.new(response.body, metrics: @metrics, labels: labels, watch: events, finish: finish, watch_list: watch_list)
          Response.new(status: response.status, headers: response.headers, body: body, stream: true, unbounded: response.unbounded?,
                       encoded_body: response.encoded_body)
        end
      end
    end
  end
end
