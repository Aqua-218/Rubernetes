# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "uri"

require_relative "api"
require_relative "decode"
require_relative "storage"
require_relative "../security/identity"
require_relative "../security/authentication/request_context"
require_relative "../security/authentication/request_header"
require_relative "../security/authentication/x509"
require_relative "../security/authentication/webhook_token"
require_relative "../security/authorization/attributes"
require_relative "../security/authorization/webhook"
require_relative "../transport/http_server"
require_relative "../api/node_endpoint_resolver"

module Rubernetes
  module MetricsServer
    # sigs.k8s.io/metrics-server (v0.8.0) as a component: every
    # metric_resolution it scrapes each Node's /metrics/resource (the address
    # and port the node advertised, as kube-apiserver dials it), keeps the
    # last two points, and serves metrics.k8s.io/v1beta1 over HTTPS behind
    # the aggregator -- which is what `kubectl top` and the HPA's resource
    # metrics read.
    #
    # Authentication and authorization are delegated like any extension API
    # server: the front-proxy (request-header) CA and client CA come from
    # kube-system/extension-apiserver-authentication, a bearer token is
    # checked with a TokenReview, and every request is authorized with a
    # SubjectAccessReview.  /healthz, /livez and /readyz are always allowed.
    #
    # `register` creates what the upstream manifests install: the
    # kube-system/metrics-server Service with Endpoints pointing at this
    # process and the v1beta1.metrics.k8s.io APIService.
    class Server
      DEFAULT_PORT = 4443
      DEFAULT_RESOLUTION = 15.0
      DEFAULT_SCRAPE_TIMEOUT = 10.0
      MAX_DELAY_MS = 4_000
      DELAY_PER_SOURCE_MS = 8
      AUTH_CONFIGMAP = "/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication"
      ALWAYS_ALLOW = %w[/healthz /livez /readyz].freeze
      SERVICE_NAMESPACE = "kube-system"
      SERVICE_NAME = "metrics-server"
      APISERVICE_NAME = "v1beta1.metrics.k8s.io"
      # --kubelet-preferred-address-types default.
      DEFAULT_ADDRESS_TYPES = %w[Hostname InternalDNS InternalIP ExternalDNS ExternalIP].freeze

      attr_reader :storage, :api

      def initialize(client:, config: {}, logger: nil, clock: -> { Time.now.utc }, http_get: nil)
        @client = client
        @config = config.transform_keys(&:to_s)
        @logger = logger
        @clock = clock
        @http_get = http_get || method(:default_http_get)
        @resolution = Float(@config.fetch("metric_resolution_seconds", DEFAULT_RESOLUTION))
        @scrape_timeout = Float(@config.fetch("scrape_timeout_seconds", DEFAULT_SCRAPE_TIMEOUT))
        @scheme = @config.fetch("kubelet_scheme", "http").to_s
        @storage = Storage.new(metric_resolution: @resolution)
        @api = API.new(storage: @storage, lister: self, clock: @clock)
        @address_types = Array(@config.fetch("address_type_priority", DEFAULT_ADDRESS_TYPES)).map(&:to_s)
        @authenticators = []
        @mutex = Mutex.new
        @stopping = false
        @threads = []
      end

      # ------------------------------------------------------------ lifecycle

      def start
        refresh_authentication
        @http = Transport::HTTPServer.new(method(:call), host: @config.fetch("bind_address", "0.0.0.0").to_s,
                                                         port: Integer(@config.fetch("port", DEFAULT_PORT)), logger: @logger,
                                                         **tls_options)
        @http.start
        @threads << Thread.new { scrape_loop }.tap { |thread| thread.name = "metrics-server-scrape" }
        @threads << Thread.new { authentication_loop }.tap { |thread| thread.name = "metrics-server-authn" }
        register if @config["register"] == true
        self
      end

      def stop
        @mutex.synchronize { @stopping = true }
        @threads.each { |thread| thread.wakeup rescue nil }
        @threads.each { |thread| thread.join(2) }
        @http&.stop
        self
      end

      def port = @http&.port

      # One scrape of every node (scraper.Scrape) into the storage.
      def scrape_once
        nodes = nodes(label_selector: @config["node_selector"])
        delay_ms = [DELAY_PER_SOURCE_MS * nodes.length, MAX_DELAY_MS].min
        batches = nodes.map do |node|
          Thread.new do
            sleep(rand(delay_ms) / 1000.0) if delay_ms.positive? && @config.fetch("jitter", true)
            collect_node(node)
          end
        end.map(&:value)
        batch = Storage::Batch.empty
        batches.compact.each do |source|
          source.nodes.each { |name, point| batch.nodes[name] ||= point }
          source.pods.each { |key, containers| batch.pods[key] ||= containers }
        end
        @storage.store(batch)
        batch
      end

      # ------------------------------------------------------------- lister

      def nodes(label_selector: nil)
        list = @client.get("/api/v1/nodes", query: selector_query(label_selector))
        Array(list && list["items"])
      rescue StandardError => error
        log(:warn, "metrics_server.list_nodes_failed", error: error.message.to_s[0, 200])
        []
      end

      def node(name)
        @client.get("/api/v1/nodes/#{name}")
      rescue StandardError
        nil
      end

      def pods(namespace:, label_selector: nil)
        path = namespace ? "/api/v1/namespaces/#{namespace}/pods" : "/api/v1/pods"
        list = @client.get(path, query: selector_query(label_selector))
        Array(list && list["items"])
      end

      def pod(namespace, name)
        @client.get("/api/v1/namespaces/#{namespace}/pods/#{name}")
      rescue StandardError
        nil
      end

      # ------------------------------------------------------------ serving

      def call(request)
        path = request.path.to_s
        return health(path) if ALWAYS_ALLOW.include?(path)

        user = authenticate(request)
        return status(401, "Unauthorized", "Unauthorized") if user == :invalid

        attributes = authorization_attributes(user, request.method, path)
        decision = authorize(attributes)
        unless decision
          subject = attributes.resource ? %(#{attributes.resource}.#{API::GROUP} is forbidden) : %(forbidden: #{path})
          return status(403, "Forbidden", %(#{subject}: User "#{user.name}" cannot #{attributes.verb} resource "#{attributes.resource}" in API group "#{API::GROUP}"#{attributes.namespace.empty? ? " at the cluster scope" : %( in the namespace "#{attributes.namespace}")}))
        end

        query = request.query.transform_values { |value| value.is_a?(Array) ? value.first : value }
        code, headers, body = @api.call(request.method, path, query, accept: request.header("accept"))
        [code, headers, [body]]
      rescue StandardError => error
        log(:error, "metrics_server.request_failed", path: path, error: "#{error.class}: #{error.message}"[0, 300])
        status(500, "InternalError", "Internal error occurred: #{error.message}")
      end

      private

      def selector_query(selector)
        selector.to_s.empty? ? nil : {"labelSelector" => selector.to_s}
      end

      def collect_node(node)
        name = node.dig("metadata", "name").to_s
        address = node_address(node)
        return nil if address.nil?

        port = kubelet_port(node)
        path = node.dig("metadata", "annotations", "metrics.k8s.io/resource-metrics-path").to_s
        path = "/metrics/resource" if path.empty?
        requested = @clock.call
        host = address.include?(":") ? "[#{address}]" : address
        body = @http_get.call("#{@scheme}://#{host}:#{port}#{path}", @scrape_timeout)
        body && Decode.batch(body, default_time: requested, node_name: name)
      rescue StandardError => error
        log(:warn, "metrics_server.scrape_failed", node: name, error: "#{error.class}: #{error.message}"[0, 200])
        nil
      end

      # The address a node's agent listens on (the streaming address it
      # announced, as kube-apiserver dials it), else the first address of the
      # preferred types (utils.NewPriorityNodeAddressResolver).
      def node_address(node)
        announced = node.dig("metadata", "annotations", Rubernetes::API::NodeEndpointResolver::STREAMING_ADDRESS_ANNOTATION).to_s
        return announced unless announced.empty?

        addresses = Array(node.dig("status", "addresses"))
        @address_types.each do |type|
          entry = addresses.find { |candidate| candidate["type"] == type && !candidate["address"].to_s.empty? }
          return entry["address"].to_s if entry
        end
        nil
      end

      # useNodeStatusPort: status.daemonEndpoints.kubeletEndpoint.Port.
      def kubelet_port(node)
        endpoint = node.dig("status", "daemonEndpoints", "kubeletEndpoint") || {}
        port = (endpoint["Port"] || endpoint["port"]).to_i
        port.positive? ? port : Integer(@config.fetch("kubelet_port", Rubernetes::API::NodeEndpointResolver::DEFAULT_PORT))
      end

      def default_http_get(url, timeout)
        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = timeout
        http.read_timeout = timeout
        if uri.scheme == "https"
          http.use_ssl = true
          http.verify_mode = @config["kubelet_insecure_tls"] == true ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
        end
        headers = {"accept" => "text/plain"}
        token = @client.respond_to?(:bearer_token) ? @client.bearer_token : nil
        headers["authorization"] = "Bearer #{token}" if token && uri.scheme == "https"
        response = http.get(uri.request_uri, headers)
        raise "request failed, status: #{response.code}" unless response.code.to_i == 200

        response.body
      end

      def scrape_loop
        until @mutex.synchronize { @stopping }
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            scrape_once
          rescue StandardError => error
            log(:warn, "metrics_server.scrape_round_failed", error: error.message.to_s[0, 200])
          end
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
          sleep([@resolution - elapsed, 0.1].max)
        end
      end

      def authentication_loop
        until @mutex.synchronize { @stopping }
          sleep(60)
          refresh_authentication rescue nil
        end
      end

      # Delegating authentication (k8s.io/apiserver options.DelegatingAuthenticationOptions).
      def refresh_authentication
        data = (@client.get(AUTH_CONFIGMAP) || {})["data"] || {}
        authenticators = []
        front_proxy = certificates(data["requestheader-client-ca-file"])
        unless front_proxy.empty?
          authenticators << Security::Authentication::RequestHeader.new(
            ca_certificates: front_proxy, allowed_names: json_list(data["requestheader-allowed-names"]),
            username_headers: json_list(data["requestheader-username-headers"], ["X-Remote-User"]),
            uid_headers: json_list(data["requestheader-uid-headers"], ["X-Remote-Uid"]),
            group_headers: json_list(data["requestheader-group-headers"], ["X-Remote-Group"]),
            extra_header_prefixes: json_list(data["requestheader-extra-headers-prefix"], ["X-Remote-Extra-"]), clock: @clock
          )
        end
        client_ca = certificates(data["client-ca-file"])
        authenticators << Security::Authentication::X509.new(ca_certificates: client_ca, clock: @clock) unless client_ca.empty?
        authenticators << Security::Authentication::WebhookToken.new(transport: review_transport("/apis/authentication.k8s.io/v1/tokenreviews"),
                                                                    clock: @clock)
        @mutex.synchronize do
          @authenticators = authenticators
          @client_cas = front_proxy + client_ca
        end
      rescue StandardError => error
        log(:warn, "metrics_server.authentication_config_failed", error: error.message.to_s[0, 200])
      end

      def authenticate(request)
        context = Security::Authentication::RequestContext.new(headers: request.headers, client_certificate: request.client_certificate,
                                                                client_chain: request.client_chain, remote_address: request.remote_address,
                                                                path: request.path)
        authenticators = @mutex.synchronize { @authenticators }
        authenticators.each do |authenticator|
          result = authenticator.authenticate(context)
          return result.user if result
        rescue Security::AuthenticationError
          return :invalid
        end
        return :invalid if context.bearer_token

        Security::UserInfo.new(name: Security::UserInfo::ANONYMOUS_NAME, groups: [Security::UserInfo::ALL_UNAUTHENTICATED])
      end

      def authorization_attributes(user, method, path)
        resource = %r{\A/apis/#{Regexp.escape(API::GROUP_VERSION)}(?:/namespaces/([^/]+))?/(nodes|pods)(?:/([^/]+))?\z}.match(path)
        return Security::Authorization::Attributes.new(user: user, verb: method.downcase, path: path) unless resource

        Security::Authorization::Attributes.new(user: user, verb: resource[3] ? "get" : "list", namespace: resource[1],
                                                api_group: API::GROUP, api_version: API::VERSION, resource: resource[2], name: resource[3])
      end

      def authorize(attributes)
        @authorizer ||= Security::Authorization::Webhook.new(transport: review_transport("/apis/authorization.k8s.io/v1/subjectaccessreviews"),
                                                             clock: @clock)
        @authorizer.authorize(attributes).allowed?
      end

      def review_transport(path)
        lambda do |body|
          response = @client.raw("POST", path, body: body, headers: {"content-type" => "application/json"}, raise_for_status: false)
          [response.status, response.body]
        end
      end

      def health(path)
        return [200, {"content-type" => "text/plain"}, ["ok"]] unless path == "/readyz"
        return [200, {"content-type" => "text/plain"}, ["ok"]] if @storage.ready?

        [500, {"content-type" => "text/plain"}, ["[-]metric-storage-ready failed: not metrics to serve\n"]]
      end

      def status(code, reason, message)
        [code, {"content-type" => "application/json"},
         [JSON.generate({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Failure", "message" => message,
                         "reason" => reason, "code" => code})]]
      end

      def tls_options
        cert_file = @config.dig("tls", "cert_file")
        key_file = @config.dig("tls", "key_file")
        if cert_file && key_file
          certificate = OpenSSL::X509::Certificate.new(File.binread(cert_file))
          key = OpenSSL::PKey.read(File.binread(key_file))
        else
          certificate, key = self_signed
        end
        @serving_certificate = certificate
        {cert: certificate, key: key, request_client_certificates: true,
         client_ca_certificates: @mutex.synchronize { Array(@client_cas) }}
      end

      # --secure-port without --tls-cert-file: a self-signed serving
      # certificate for the Service's DNS names.
      def self_signed
        key = OpenSSL::PKey::EC.generate("prime256v1")
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = OpenSSL::BN.rand(64)
        certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/CN=#{SERVICE_NAME}.#{SERVICE_NAMESPACE}.svc")
        certificate.public_key = key
        certificate.not_before = @clock.call - 60
        certificate.not_after = @clock.call + (365 * 86_400)
        extensions = OpenSSL::X509::ExtensionFactory.new(certificate, certificate)
        names = ["DNS:#{SERVICE_NAME}", "DNS:#{SERVICE_NAME}.#{SERVICE_NAMESPACE}", "DNS:#{SERVICE_NAME}.#{SERVICE_NAMESPACE}.svc"]
        address = @config["advertise_address"].to_s
        names << "IP:#{address}" unless address.empty?
        certificate.add_extension(extensions.create_extension("subjectAltName", names.join(","), false))
        certificate.sign(key, OpenSSL::Digest.new("SHA256"))
        [certificate, key]
      end

      # The upstream manifests' Service, Endpoints and APIService, pointing
      # the aggregator at this process.
      def register
        address = @config["advertise_address"].to_s
        raise ArgumentError, "metrics_server.register needs advertise_address" if address.empty?

        port = self.port
        ensure_object("/api/v1/namespaces/#{SERVICE_NAMESPACE}/services", SERVICE_NAME,
                      {"apiVersion" => "v1", "kind" => "Service",
                       "metadata" => {"name" => SERVICE_NAME, "namespace" => SERVICE_NAMESPACE, "labels" => {"k8s-app" => "metrics-server"}},
                       "spec" => {"ports" => [{"name" => "https", "port" => 443, "protocol" => "TCP", "targetPort" => port}]}})
        ensure_object("/api/v1/namespaces/#{SERVICE_NAMESPACE}/endpoints", SERVICE_NAME,
                      {"apiVersion" => "v1", "kind" => "Endpoints",
                       "metadata" => {"name" => SERVICE_NAME, "namespace" => SERVICE_NAMESPACE, "labels" => {"k8s-app" => "metrics-server"}},
                       "subsets" => [{"addresses" => [{"ip" => address}], "ports" => [{"name" => "https", "port" => port, "protocol" => "TCP"}]}]},
                      replace: true)
        # system:aggregated-metrics-reader, aggregated into view/edit/admin.
        ensure_object("/apis/rbac.authorization.k8s.io/v1/clusterroles", "system:aggregated-metrics-reader",
                      {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => "ClusterRole",
                       "metadata" => {"name" => "system:aggregated-metrics-reader",
                                      "labels" => {"k8s-app" => "metrics-server", "rbac.authorization.k8s.io/aggregate-to-admin" => "true",
                                                   "rbac.authorization.k8s.io/aggregate-to-edit" => "true",
                                                   "rbac.authorization.k8s.io/aggregate-to-view" => "true"}},
                       "rules" => [{"apiGroups" => [API::GROUP], "resources" => %w[pods nodes], "verbs" => %w[get list watch]}]})
        ensure_object("/apis/apiregistration.k8s.io/v1/apiservices", APISERVICE_NAME,
                      {"apiVersion" => "apiregistration.k8s.io/v1", "kind" => "APIService",
                       "metadata" => {"name" => APISERVICE_NAME, "labels" => {"k8s-app" => "metrics-server"}},
                       "spec" => {"service" => {"name" => SERVICE_NAME, "namespace" => SERVICE_NAMESPACE, "port" => 443},
                                  "group" => API::GROUP, "version" => API::VERSION,
                                  "caBundle" => [@serving_certificate.to_pem].pack("m0"),
                                  "groupPriorityMinimum" => 100, "versionPriority" => 100}},
                      replace: true)
      rescue StandardError => error
        log(:warn, "metrics_server.register_failed", error: "#{error.class}: #{error.message}"[0, 300])
      end

      def ensure_object(collection, name, object, replace: false)
        existing = begin
          @client.get("#{collection}/#{name}")
        rescue StandardError
          nil
        end
        if existing.nil?
          @client.raw("POST", collection, body: JSON.generate(object), headers: {"content-type" => "application/json"})
        elsif replace
          object = object.merge("metadata" => object["metadata"].merge("resourceVersion" => existing.dig("metadata", "resourceVersion")))
          @client.raw("PUT", "#{collection}/#{name}", body: JSON.generate(object), headers: {"content-type" => "application/json"})
        end
      end

      def certificates(pem)
        pem.to_s.scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m).map { |block| OpenSSL::X509::Certificate.new(block) }
      end

      def json_list(text, default = [])
        return default if text.to_s.empty?

        Array(JSON.parse(text.to_s))
      rescue JSON::ParserError
        default
      end

      def log(level, event, **fields)
        @logger&.public_send(level, event, **fields)
      rescue StandardError
        nil
      end
    end
  end
end
