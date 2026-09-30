# frozen_string_literal: true

require "json"
require_relative "../security/egress"
require "time"
require "net/http"
require "openssl"
require "uri"

require_relative "response"

module Rubernetes
  module API
    # API aggregation (apiregistration.k8s.io/v1 APIService): requests for a
    # group/version claimed by an APIService with a service reference are
    # proxied to the backend over mTLS with the front-proxy client
    # certificate; the caller identity is forwarded in X-Remote-* headers
    # (never the bearer token).  Discovery for the aggregated group/version
    # is fetched from the backend and merged into /apis.  Availability is
    # reported through the APIService status Available condition.
    class Aggregator
      GROUP = "apiregistration.k8s.io"
      RESOURCE = "apiservices"
      MAX_BODY_BYTES = 3 * 1024 * 1024
      TIMEOUT = 30
      IDENTITY_HEADERS = {"user" => "X-Remote-User", "uid" => "X-Remote-Uid", "groups" => "X-Remote-Group"}.freeze
      # The aggregator's own requests -- the availability check
      # (remote_available_controller: SetAuthProxyHeaders) and discovery
      # (handler_discovery) -- are made as system:kube-aggregator in
      # system:masters, through the front-proxy client certificate.
      AGGREGATOR_IDENTITY = {"X-Remote-User" => "system:kube-aggregator", "X-Remote-Group" => "system:masters"}.freeze

      Backend = Struct.new(:name, :group, :version, :priority, :service_namespace, :service_name, :port, :ca_bundle, :insecure, keyword_init: true)

      def initialize(client_certificate: nil, client_key: nil, service_resolver: nil, http_factory: nil, clock: -> { Time.now.utc })
        @client_certificate = client_certificate
        @client_key = client_key
        @service_resolver = service_resolver
        @http_factory = http_factory
        @clock = clock
        @backends = {}
        @availability = {}
        @mutex = Mutex.new
      end

      # kube-aggregator's proxy handler answers "service unavailable" for an
      # APIService whose Available condition is false (plain text, 503).
      def mark_available(name, available)
        @mutex.synchronize { @availability[name] = available }
      end

      def available_backend?(backend)
        @mutex.synchronize { @availability.fetch(backend.name, false) }
      end

      # kube-aggregator answers for an unavailable backend with a Status
      # (ServiceUnavailable, 503) that clients decode; a text body made
      # client-go report "the server rejected our request for an unknown
      # reason", which the Aggregator conformance spec treats as fatal
      # instead of waiting for the backend.
      def unavailable_response(message = "service unavailable")
        Response.new(status: 503, headers: {"content-type" => "application/json", "x-content-type-options" => "nosniff"},
                     body: Status.failure(message: message, code: 503, reason: "ServiceUnavailable"))
      end

      def sync(apiservice)
        name = apiservice.dig("metadata", "name")
        spec = apiservice["spec"] || {}
        service = spec["service"]
        @mutex.synchronize do
          if service.nil? || apiservice.dig("metadata", "deletionTimestamp")
            # Local APIServices (no service) describe built-in groups; nothing to proxy.
            @backends.delete(name)
            return nil
          end
          @backends[name] = Backend.new(name: name, group: spec["group"].to_s, version: spec["version"].to_s, priority: [spec["groupPriorityMinimum"].to_i, spec["versionPriority"].to_i],
                                        service_namespace: service["namespace"], service_name: service["name"], port: service["port"] || 443,
                                        ca_bundle: spec["caBundle"], insecure: spec["insecureSkipTLSVerify"] == true)
        end
      end

      def backend_names
        @mutex.synchronize { @backends.keys }
      end

      def remove(name)
        @mutex.synchronize do
          @backends.delete(name)
          @availability.delete(name)
        end
      end

      def backend_for(group, version)
        @mutex.synchronize { @backends.values.find { |backend| backend.group == group && backend.version == version } }
      end

      def groups
        @mutex.synchronize do
          @backends.values.group_by(&:group).map do |group, backends|
            versions = backends.sort_by { |backend| [-backend.priority[1], backend.version] }.map { |backend| {"groupVersion" => "#{group}/#{backend.version}", "version" => backend.version} }
            {"name" => group, "versions" => versions, "preferredVersion" => versions.first}
          end
        end
      end

      def claims?(group, version = nil)
        @mutex.synchronize { @backends.values.any? { |backend| backend.group == group && (version.nil? || backend.version == version) } }
      end

      # Proxy a request; returns an API::Response.
      def proxy(request, group:, version:)
        backend = backend_for(group, version)
        return nil if backend.nil?
        return unavailable_response unless available_backend?(backend)

        uri = URI.parse(resolve(backend))
        path = request.path
        query = request.query.is_a?(Hash) && !request.query.empty? ? URI.encode_www_form(request.query.flat_map { |key, value| Array(value).map { |item| [key, item] } }) : nil
        http = build_http(uri, backend)
        klass = {"GET" => Net::HTTP::Get, "POST" => Net::HTTP::Post, "PUT" => Net::HTTP::Put, "PATCH" => Net::HTTP::Patch, "DELETE" => Net::HTTP::Delete, "HEAD" => Net::HTTP::Head}.fetch(request.method) { return Response.new(status: 405, body: Status.failure(message: "method not allowed", code: 405, reason: "MethodNotAllowed")) }
        target = query ? "#{path}?#{query}" : path
        outbound = klass.new(target)
        forwarded_headers(request).each do |name, value|
          if value.is_a?(Array)
            outbound.delete(name)
            value.each { |item| outbound.add_field(name, item) }
          else
            outbound[name] = value
          end
        end
        if request.body && !request.body.empty?
          # k8s.io/apiserver negotiation.NegotiateInputSerializer defaults an
          # empty request Content-Type to application/json, and kube-apiserver
          # proxies the request verbatim (no Content-Type when the client sent
          # none).  Net::HTTP instead stamps a body with
          # application/x-www-form-urlencoded, which the backend rejects 415;
          # so a body with no forwarded Content-Type gets the same JSON
          # default the backend would have applied itself.
          outbound["content-type"] = "application/json" if outbound["content-type"].to_s.empty?
          outbound.body = request.body
        end
        raise Status::Error.new(message: "request body exceeds the aggregation limit", code: 413, reason: "RequestEntityTooLarge") if request.body && request.body.bytesize > MAX_BODY_BYTES

        response = http.request(outbound)
        record_x509(http)
        log_proxy(uri, target, request.method, response, sent_content_type: outbound["content-type"], body_bytes: outbound.body.to_s.bytesize)
        raise Status::Error.new(message: "aggregated API response exceeds the limit", code: 502, reason: "BadGateway") if response.body.to_s.bytesize > MAX_BODY_BYTES

        headers = {}
        %w[content-type cache-control warning].each { |name| headers[name] = response[name] if response[name] }
        body = response.body.to_s
        body = JSON.parse(body) if (headers["content-type"] || "").start_with?("application/json") && !body.empty?
        Response.new(status: response.code.to_i, headers: headers, body: body)
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::ProtocolError, Net::HTTPFatalError, OpenSSL::SSL::SSLError, SystemCallError, SocketError, IOError => error
        unavailable_response("Error trying to reach service: '#{error.message}'")
      rescue JSON::ParserError
        Response.new(status: 502, headers: {"content-type" => "application/json"},
                     body: Status.failure(message: "aggregated API returned invalid JSON", code: 502, reason: "BadGateway"))
      end

      # Aggregated discovery v2 items for every available APIService backend:
      # the backend's own resource list (APIResourceList) mapped into the
      # apidiscovery.k8s.io/v2 shape.  kube-apiserver includes aggregated
      # groups in /apis aggregated discovery, and the 1.36 dynamic client
      # reads only that document -- without this it cannot find an aggregated
      # resource ("could not find group version resource ... wardle/flunders").
      # kube-aggregator's x509 and discovery metrics, on the process-wide
      # registry (the apiserver's /metrics merges it): a backend serving
      # certificate without SANs or signed with SHA-1, counted per proxied
      # request; and every aggregated discovery document built.  The peer
      # aggregated discovery counters are for the peer proxy, which does not
      # exist here.
      def shared_metrics
        return nil unless defined?(Rubernetes::Observability::Metrics)

        Rubernetes::Observability::Metrics.global
      end

      def record_x509(http)
        registry = shared_metrics
        certificate = http.respond_to?(:peer_cert) ? http.peer_cert : nil
        return unless registry && certificate

        %w[apiserver_kube_aggregator_x509_missing_san_total apiserver_kube_aggregator_x509_insecure_sha1_total].each do |name|
          registry.register(name, type: :counter) unless registry.registered?(name)
        end
        registry.increment("apiserver_kube_aggregator_x509_missing_san_total") unless Rubernetes::Observability::Metrics.certificate_has_san?(certificate)
        registry.increment("apiserver_kube_aggregator_x509_insecure_sha1_total") if Rubernetes::Observability::Metrics.certificate_sha1?(certificate)
      rescue StandardError
        nil
      end

      def record_discovery_aggregation
        registry = shared_metrics
        return unless registry

        registry.register("aggregator_discovery_aggregation_count_total", type: :counter) unless registry.registered?("aggregator_discovery_aggregation_count_total")
        registry.increment("aggregator_discovery_aggregation_count_total")
      rescue StandardError
        nil
      end

      def discovery_items
        record_discovery_aggregation
        @mutex.synchronize { @backends.values.group_by(&:group) }.sort.map do |group, backends|
          versions = backends.sort_by { |backend| [-backend.priority[1], backend.version] }.filter_map do |backend|
            next nil unless @mutex.synchronize { @availability.fetch(backend.name, false) }

            list = resource_list(group, backend.version)
            resources = Array(list && list["resources"]).reject { |resource| resource["name"].to_s.include?("/") }.map do |resource|
              {"resource" => resource["name"].to_s,
               "responseKind" => {"group" => group, "version" => backend.version, "kind" => resource["kind"].to_s},
               "scope" => resource["namespaced"] ? "Namespaced" : "Cluster",
               "singularResource" => resource["singularName"].to_s,
               "verbs" => Array(resource["verbs"])}
            end
            {"version" => backend.version, "resources" => resources, "freshness" => list.nil? ? "Stale" : "Current"}
          end
          next nil if versions.empty?

          {"metadata" => {"name" => group, "creationTimestamp" => nil}, "versions" => versions}
        end.compact
      end

      # Discovery merged from the backend's /apis/<group>/<version>.
      def resource_list(group, version)
        backend = backend_for(group, version)
        return nil if backend.nil?

        uri = URI.parse(resolve(backend))
        http = build_http(uri, backend)
        response = http.get("/apis/#{group}/#{version}", {"accept" => "application/json"}.merge(AGGREGATOR_IDENTITY))
        return nil unless response.code.to_i == 200

        JSON.parse(response.body)
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::ProtocolError, Net::HTTPFatalError, OpenSSL::SSL::SSLError, SystemCallError, SocketError, IOError, JSON::ParserError
        nil
      end

      def available?(backend)
        uri = URI.parse(resolve(backend))
        response = build_http(uri, backend).get("/apis/#{backend.group}/#{backend.version}", {"accept" => "application/json"}.merge(AGGREGATOR_IDENTITY))
        response.code.to_i.between?(200, 299)
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::ProtocolError, Net::HTTPFatalError, OpenSSL::SSL::SSLError, SystemCallError, SocketError, IOError
        false
      end

      # Availability follows kube-aggregator's available controller: the
      # Service must exist and expose the port, an EndpointSlice must carry
      # a ready address for that port, and the backend must answer the
      # discovery request for the group/version.  `service` and
      # `endpoint_slices` are the objects currently in the store (nil / []
      # when absent); pass `skip_endpoint_checks: true` for an explicit
      # resolver that bypasses Service/EndpointSlice lookup.
      def availability_condition(backend, service: nil, endpoint_slices: [], skip_endpoint_checks: false)
        failure = skip_endpoint_checks ? nil : endpoint_failure(backend, service, endpoint_slices)
        if failure
          reason, message = failure
          return condition(false, reason, message)
        end
        target = "#{resolve(backend)}/apis/#{backend.group}/#{backend.version}"
        error = discovery_error(backend)
        return condition(true, "Passed", "all checks passed") if error.nil?

        condition(false, "FailedDiscoveryCheck", "failing or missing response from #{target}: #{error}")
      end

      def backends
        @mutex.synchronize { @backends.values.dup }
      end

      def backend(name)
        @mutex.synchronize { @backends[name] }
      end

      private

      def condition(available, reason, message)
        {"type" => "Available", "status" => available ? "True" : "False", "reason" => reason, "message" => message,
         "lastTransitionTime" => @clock.call.utc.iso8601}
      end

      def endpoint_failure(backend, service, endpoint_slices)
        reference = "service/#{backend.service_name} in #{backend.service_namespace.to_s.inspect}"
        return ["ServiceNotFound", "#{reference} is not present"] if service.nil?

        ports = Array(service.dig("spec", "ports"))
        port = ports.find { |entry| entry["port"].to_i == backend.port.to_i }
        return ["ServicePortError", "#{reference} is not listening on port #{backend.port}"] if port.nil?

        return ["EndpointsNotFound", "cannot find endpointslices for #{reference}"] if Array(endpoint_slices).empty?

        port_name = port["name"].to_s
        served = Array(endpoint_slices).any? do |slice|
          Array(slice["ports"]).any? { |entry| entry["name"].to_s == port_name } &&
            Array(slice["endpoints"]).any? { |endpoint| endpoint.dig("conditions", "ready") != false && !Array(endpoint["addresses"]).empty? }
        end
        return nil if served

        ["MissingEndpoints", "endpointslices for #{reference} have no addresses with port name #{port_name.inspect}"]
      end

      def discovery_error(backend)
        uri = URI.parse(resolve(backend))
        response = build_http(uri, backend).get("/apis/#{backend.group}/#{backend.version}", {"accept" => "application/json"}.merge(AGGREGATOR_IDENTITY))
        return nil if response.code.to_i.between?(200, 299)

        "bad status from #{uri}/apis/#{backend.group}/#{backend.version}: #{response.code}"
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::ProtocolError, Net::HTTPFatalError, OpenSSL::SSL::SSLError, SystemCallError, SocketError, IOError => error
        error.message
      end

      # kube-aggregator's ServiceResolver: the request goes to a ready
      # endpoint's address, but TLS is verified against the Service's DNS
      # name (`<name>.<namespace>.svc`), which is what the backend's
      # certificate carries.  Dialling the bare address failed with
      # `hostname "10.240.0.2" does not match the server certificate`.
      def resolve(backend)
        host = "#{backend.service_name}.#{backend.service_namespace}.svc"
        address = resolved_address(backend)
        port = address ? address[1] : backend.port
        "https://#{host}:#{port}"
      end

      def resolved_address(backend)
        resolved = @service_resolver&.call(backend.service_namespace, backend.service_name, backend.port)
        return [resolved[0].to_s, Integer(resolved[1])] if resolved.is_a?(Array) && resolved.length == 2
        return [URI.parse(resolved).hostname, URI.parse(resolved).port] if resolved.is_a?(String) && !resolved.empty?

        nil
      rescue StandardError
        nil
      end

      # kube-aggregator logs every proxied request; without it a backend's
      # answer (a plain 404 from the wrong port, say) is invisible.
      def log_proxy(uri, target, method, response, sent_content_type: nil, body_bytes: nil)
        line = {"timestamp" => Time.now.utc.iso8601(6), "level" => "info", "event" => "aggregator.proxy",
                "backend" => uri.to_s, "method" => method, "path" => target, "status" => response.code.to_s,
                "sent_content_type" => sent_content_type.to_s, "sent_body_bytes" => body_bytes,
                "content_type" => response["content-type"].to_s, "body" => response.body.to_s[0, 120]}
        $stderr.write(JSON.generate(line) << "\n")
      rescue StandardError
        nil
      end

      # transport.headerKeyEscaper: "%" -> "%25", "/" -> "%2F"
      # (headerrequest unescapes the same way on the far side).
      def escape_header_key(key)
        key.gsub("%", "%25").gsub("/", "%2F")
      end

      def backend_for_uri(_uri)
        nil
      end

      def build_http(uri, backend)
        return @http_factory.call(uri, backend) if @http_factory

        # Never route cluster-internal traffic through an environment proxy.
        # URI#hostname: an IPv6 literal without the brackets URI#host keeps.
        http = Net::HTTP.new(uri.hostname, uri.port, nil)
        address = resolved_address(backend)
        http.ipaddr = address[0] if address && address[0] != uri.hostname
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = TIMEOUT
        http.read_timeout = TIMEOUT
        if http.use_ssl?
          if backend.insecure
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          else
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            if backend.ca_bundle
              store = OpenSSL::X509::Store.new
              OpenSSL::X509::Certificate.load(backend.ca_bundle.unpack1("m0")).each { |certificate| store.add_cert(certificate) }
              http.cert_store = store
            end
          end
          http.cert = @client_certificate if @client_certificate
          http.key = @client_key if @client_key
        end
        http
      end

      # Only the verified identity travels to the backend; the original
      # Authorization header is dropped.
      def forwarded_headers(request)
        headers = {}
        %w[accept content-type accept-encoding user-agent].each do |name|
          value = request.header(name)
          headers[name] = value if value
        end
        identity = request.identity.is_a?(Hash) ? request.identity : {}
        headers["X-Remote-User"] = identity["username"].to_s
        headers["X-Remote-Uid"] = identity["uid"].to_s if identity["uid"]
        # client-go transport.SetAuthProxyHeaders: one X-Remote-Group header
        # per group, and extra keys percent-encoded -- a key such as
        # "authentication.kubernetes.io/pod-name" is not a legal header name
        # and the backend answered the raw form with a bare 400.
        groups = Array(identity["groups"]).map(&:to_s).reject(&:empty?)
        headers["X-Remote-Group"] = groups unless groups.empty?
        (identity["extra"] || {}).each do |key, values|
          headers["X-Remote-Extra-#{escape_header_key(key.to_s)}"] = Array(values).map(&:to_s)
        end
        headers["X-Forwarded-For"] = request.remote_address.to_s if request.respond_to?(:remote_address) && request.remote_address
        headers
      end
    end
  end
end
