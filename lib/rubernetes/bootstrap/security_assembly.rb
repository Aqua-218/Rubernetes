# frozen_string_literal: true

require "json"
require "net/http"
require "uri"
require "openssl"
require "yaml"

require_relative "../security"

module Rubernetes
  module Bootstrap
    # Builds the API server security pipeline from the `security` section of
    # the process configuration.  Files are read here, once, so the pipeline
    # never touches the filesystem per request.  Bootstrap objects (RBAC
    # roles/bindings, API Priority and Fairness FlowSchemas / priority
    # levels, system namespaces) come from the pinned v1.36.2 corpus.
    class SecurityAssembly
      CORPUS_ROOT = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults", __dir__)
      BOOTSTRAP_ROOT = File.join(CORPUS_ROOT, "bootstrap")

      attr_reader :pipeline, :tls_options, :service_account_issuer, :feature_gates, :bootstrap_objects
      # What kube-apiserver publishes in kube-system/extension-apiserver-authentication
      # (ClusterAuthenticationTrust): the client CA and the request-header
      # (front-proxy) settings extension API servers authenticate with.
      attr_reader :authentication_info

      def initialize(config:, store:, key_for:, logger: nil, clock: -> { Time.now.utc }, resource_resolver: nil, service_resolver: nil,
                     scope_resolver: nil, type_resolver: nil, defaulter: nil, apiserver_id: nil)
        @defaulter = defaulter
        @apiserver_id = apiserver_id || Socket.gethostname
        @reload_controllers = []
        @service_resolver = service_resolver
        @scope_resolver = scope_resolver
        @type_resolver = type_resolver
        @config = config || {}
        @store = store
        @key_for = key_for
        @resource_resolver = resource_resolver
        @logger = logger
        @clock = clock
        @feature_gates = default_feature_gates.merge(@config.fetch("feature_gates", {}))
        @tls_options = {}
        @bootstrap_objects = []
        build!
      end

      # Security::ConfigReloadController for --authorization-config and
      # --authentication-config files (the service starts and stops them).
      attr_reader :reload_controllers
      # The ExternalJWTSigner when service account tokens are signed externally.
      attr_reader :external_jwt_signer
      # The node authorizer graph's feeder (started by the service once the store serves).
      attr_reader :node_graph_populator

      def self.default_feature_gates
        document = JSON.parse(File.read(File.join(CORPUS_ROOT, "features.json")))
        document.fetch("gates").transform_values { |gate| gate["default"] == true }
      end

      def default_feature_gates
        self.class.default_feature_gates
      end

      def self.bootstrap_documents
        %w[clusterroles clusterrolebindings roles rolebindings flowschemas prioritylevelconfigurations namespaces].each_with_object({}) do |name, documents|
          path = File.join(BOOTSTRAP_ROOT, "#{name}.json")
          next unless File.file?(path)

          documents[name] = JSON.parse(File.read(path)).fetch("items", [])
        end
      end

      private

      def build!
        authn = @config["authentication"] || {}
        authz = @config["authorization"] || {}
        authenticator = build_authenticator(authn)
        authorizer = build_authorizer(authz)
        @pipeline_authorizer = authorizer
        audit_policy, audit_backend = build_audit(@config["audit"])
        flow_control = build_flow_control(@config["flow_control"])
        admission = build_admission(@config["admission"])
        @pipeline = Security::Pipeline.new(authenticator: authenticator, authorizer: authorizer, flow_control: flow_control,
                                           audit_policy: audit_policy, audit_backend: audit_backend, admission: admission, clock: @clock,
                                           constrained_impersonation: @feature_gates.fetch("ConstrainedImpersonation", true) != false)
      end

      # ------------------------------------------------------------ authn

      def build_authenticator(authn)
        authenticators = []
        client_cas = []
        @authentication_info = {client_ca: [], request_header: nil}
        if authn["request_header"]
          rh = authn["request_header"]
          ca = load_certificates(rh.fetch("ca_file"))
          client_cas.concat(ca)
          @authentication_info[:request_header] = {
            ca: ca, allowed_names: Array(rh["allowed_names"]).map(&:to_s),
            username_headers: Array(rh["username_headers"] || ["X-Remote-User"]), uid_headers: Array(rh["uid_headers"] || ["X-Remote-Uid"]),
            group_headers: Array(rh["group_headers"] || ["X-Remote-Group"]), extra_header_prefixes: Array(rh["extra_header_prefixes"] || ["X-Remote-Extra-"])
          }
          authenticators << Security::Authentication::RequestHeader.new(
            ca_certificates: ca, allowed_names: Array(rh["allowed_names"]),
            username_headers: Array(rh["username_headers"] || ["X-Remote-User"]), group_headers: Array(rh["group_headers"] || ["X-Remote-Group"]),
            uid_headers: Array(rh["uid_headers"] || ["X-Remote-Uid"]), extra_header_prefixes: Array(rh["extra_header_prefixes"] || ["X-Remote-Extra-"]), clock: @clock
          )
        end
        if authn["client_ca_file"]
          ca = load_certificates(authn["client_ca_file"])
          client_cas.concat(ca)
          @authentication_info[:client_ca] = ca
          authenticators << Security::Authentication::X509.new(ca_certificates: ca, clock: @clock)
        end
        # --authentication-token-cache-ttl: bearer-token authenticators are
        # wrapped in tokencache with a 10 s success TTL (no failure caching).
        token_ttl = authn.fetch("token_success_cache_ttl", Security::Authentication::TokenCache::DEFAULT_SUCCESS_TTL)
        cache_token = ->(authenticator) { Security::Authentication::TokenCache.new(authenticator, success_ttl: token_ttl, clock: @monotonic_clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }) }
        authenticators << cache_token.call(Security::Authentication::StaticTokenFile.load(authn["token_file"])) if authn["token_file"]
        if authn["service_account"]
          sa = authn["service_account"]
          external_signer = nil
          max_expiration = sa["max_expiration_seconds"]
          if sa["signing_endpoint"]
            external_signer = Security::Authentication::ExternalJWTSigner.new(socket: sa["signing_endpoint"], issuer: sa.fetch("issuer"),
                                                                              allow_signing_with_non_oidc_keys: sa["allow_signing_with_non_oidc_keys"] == true,
                                                                              clock: @clock, logger: @logger)
            external_signer.start!
            @external_jwt_signer = external_signer
            signer_max = external_signer.max_token_expiration_seconds
            max_expiration = [max_expiration, signer_max.positive? ? signer_max : nil].compact.min
            signing_key = nil
            verification = []
          else
            signing_key = OpenSSL::PKey.read(File.binread(sa.fetch("signing_key_file")))
            verification = Array(sa["key_files"]).map { |path| OpenSSL::PKey.read(File.binread(path)) }
          end
          audiences = Array(sa["api_audiences"]).empty? ? [sa.fetch("issuer")] : Array(sa["api_audiences"])
          lookup = Security::Authentication::ServiceAccount::Lookup.new(
            service_account: ->(namespace, name) { read_object("serviceaccounts", namespace, name) },
            pod: ->(namespace, name) { read_object("pods", namespace, name) },
            secret: ->(namespace, name) { read_object("secrets", namespace, name) },
            node: ->(_namespace, name) { read_object("nodes", nil, name) }
          )
          @service_account_issuer = Security::Authentication::ServiceAccount.new(
            issuer: sa.fetch("issuer"), signing_key: signing_key, verification_keys: verification.empty? ? nil : verification,
            api_audiences: audiences, lookup: lookup, clock: @clock, max_expiration_seconds: max_expiration, external_signer: external_signer,
            secret_writer: ->(namespace, name, labels) { merge_labels("secrets", namespace, name, labels) }
          )
          authenticators << cache_token.call(@service_account_issuer)
        end
        if authn["bootstrap_tokens"] == true
          authenticators << cache_token.call(Security::Authentication::BootstrapToken.new(secret_reader: ->(namespace, name) { read_object("secrets", namespace, name) }, clock: @clock))
        end
        Array(authn["jwt"]).each do |jwt_config|
          authenticators << cache_token.call(Security::Authentication::JWTAuthenticator.new(config: jwt_config, cel: cel_evaluator, clock: @clock))
        end
        file_configuration = nil
        file_authenticators = []
        if authn["config_file"]
          file_bytes = File.binread(authn["config_file"])
          file_configuration = Security::Authentication::Configuration.from_bytes(file_bytes, disallowed_issuers: service_account_issuers(authn))
          file_authenticators = build_file_jwt_authenticators(file_configuration, cache_token)
          authenticators.concat(file_authenticators)
        end
        if authn["webhook"]
          hook = authn["webhook"]
          authenticators << Security::Authentication::WebhookToken.new(
            transport: https_transport(hook), api_audiences: Array((authn["service_account"] || {})["api_audiences"]),
            authenticated_ttl: hook.fetch("cache_authenticated_ttl", 120), unauthenticated_ttl: hook.fetch("cache_unauthenticated_ttl", 30), clock: @clock
          )
        end
        unless client_cas.empty?
          @tls_options[:request_client_certificates] = true
          @tls_options[:client_ca_certificates] = client_cas
        end
        anonymous = authn["anonymous"] || file_configuration&.anonymous || {"enabled" => true}
        union = Security::Authentication::Union.new(authenticators: authenticators,
                                                    anonymous: Security::Authentication::Union::Anonymous.new(enabled: anonymous["enabled"] != false, conditions: anonymous["conditions"]))
        if file_configuration
          original_anonymous = file_configuration.anonymous
          current = file_authenticators
          issuers = service_account_issuers(authn)
          @reload_controllers << Security::ConfigReloadController.new(
            kind: "authentication", path: authn["config_file"], apiserver_id: @apiserver_id, logger: @logger,
            initial_bytes: file_bytes, initial_config: file_configuration,
            load: lambda do |bytes|
              configuration = Security::Authentication::Configuration.from_bytes(bytes, disallowed_issuers: issuers)
              # The anonymous settings are read once; a change is refused (field.Forbidden).
              raise Security::Authentication::Configuration::InvalidError, "anonymous: Forbidden: changed from initial configuration file" unless configuration.anonymous == original_anonymous

              configuration
            end,
            apply: lambda do |configuration|
              replacement = build_file_jwt_authenticators(configuration, cache_token)
              union.replace(current, replacement)
              current = replacement
            end
          )
        end
        union
      end

      def service_account_issuers(authn)
        sa = authn["service_account"]
        sa ? [sa["issuer"].to_s] : []
      end

      def build_file_jwt_authenticators(configuration, cache_token)
        configuration.jwt.map do |jwt_config|
          cache_token.call(Security::Authentication::JWTAuthenticator.new(config: jwt_config, cel: cel_evaluator, clock: @clock))
        end
      end

      # ------------------------------------------------------------ authz

      def build_authorizer(authz)
        return build_authorizer_from_file(authz["config_file"]) if authz["config_file"]

        modes = Array(authz["modes"])
        modes = %w[Node RBAC] if modes.empty?
        authorizers = modes.map do |mode|
          case mode
          when "AlwaysAllow" then Security::Authorization::AlwaysAllow.new
          when "AlwaysDeny" then Security::Authorization::AlwaysDeny.new
          when "RBAC" then Security::Authorization::RBAC.new(source: rbac_source)
          when "Node" then Security::Authorization::Node.new(graph: node_graph, features: @feature_gates)
          when "ABAC" then Security::Authorization::ABAC.load(authz.fetch("abac_policy_file"))
          when "Webhook"
            hook = authz.fetch("webhook")
            Security::Authorization::Webhook.new(transport: https_transport(hook), authorized_ttl: hook.fetch("cache_authorized_ttl", 300),
                                                 unauthorized_ttl: hook.fetch("cache_unauthorized_ttl", 30), failure_policy: hook.fetch("failure_policy", "NoOpinion"), clock: @clock)
          else raise Config::Error, "unknown authorization mode #{mode}"
          end
        end
        Security::Authorization::Union.new(authorizers: authorizers)
      end

      # --authorization-config: the AuthorizationConfiguration file's
      # authorizer chain, reloaded when the file changes (webhooks may come
      # and go; the non-webhook types are fixed at startup).
      def build_authorizer_from_file(path)
        bytes = File.binread(path)
        configuration = Security::Authorization::Configuration.from_bytes(bytes, cel: cel_evaluator)
        union = Security::Authorization::Union.new(authorizers: configuration.build(authorizer_factory))
        fixed_types = configuration.non_webhook_types
        @reload_controllers << Security::ConfigReloadController.new(
          kind: "authorization", path: path, apiserver_id: @apiserver_id, logger: @logger,
          initial_bytes: bytes, initial_config: configuration,
          load: ->(data) { Security::Authorization::Configuration.from_bytes(data, cel: cel_evaluator, require_non_webhook_types: fixed_types) },
          apply: ->(new_configuration) { union.reload(new_configuration.build(authorizer_factory)) }
        )
        union
      end

      def authorizer_factory
        {
          "AlwaysAllow" => -> { Security::Authorization::AlwaysAllow.new },
          "AlwaysDeny" => -> { Security::Authorization::AlwaysDeny.new },
          "RBAC" => -> { Security::Authorization::RBAC.new(source: rbac_source) },
          "Node" => -> { Security::Authorization::Node.new(graph: node_graph, features: @feature_gates) },
          "ABAC" => ->(_entry) { Security::Authorization::ABAC.load((@config["authorization"] || {}).fetch("abac_policy_file")) },
          "Webhook" => lambda do |entry, match_conditions|
            hook = entry.webhook
            Security::Authorization::Webhook.new(transport: webhook_connection_transport(hook), authorized_ttl: hook.authorized_ttl,
                                                 unauthorized_ttl: hook.unauthorized_ttl, failure_policy: hook.failure_policy,
                                                 version: hook.subject_access_review_version, clock: @clock,
                                                 name: entry.name, match_conditions: match_conditions)
          end
        }
      end

      # connectionInfo: a kubeconfig's server and credentials, or the
      # in-cluster service account (the API server itself, when it runs as a
      # Pod).
      def webhook_connection_transport(hook)
        if hook.connection_type == "KubeConfigFile"
          kubeconfig_transport(hook.kubeconfig_file, timeout: hook.timeout)
        else
          host = ENV.fetch("KUBERNETES_SERVICE_HOST", "")
          port = ENV.fetch("KUBERNETES_SERVICE_PORT", "")
          token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
          raise Config::Error, "authorization webhook connectionInfo.type InClusterConfig: unable to load in-cluster configuration (KUBERNETES_SERVICE_HOST and the service account token must be present)" if host.empty? || port.empty? || !File.file?(token_file)

          address = host.include?(":") ? "[#{host}]" : host
          http_transport(url: "https://#{address}:#{port}/apis/authorization.k8s.io/v1/subjectaccessreviews",
                         ca_pem: File.binread("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"), token: File.read(token_file).strip, timeout: hook.timeout)
        end
      end

      def kubeconfig_transport(path, timeout: 30)
        require_relative "../client/kubeconfig"
        context = Client::Kubeconfig.load(path).resolve
        ca_pem = context.ca_data || (context.ca_file && File.binread(context.ca_file))
        cert_pem = context.client_certificate_data || (context.client_certificate_file && File.binread(context.client_certificate_file))
        key_pem = context.client_key_data || (context.client_key_file && File.binread(context.client_key_file))
        http_transport(url: context.server, ca_pem: ca_pem, cert_pem: cert_pem, key_pem: key_pem, token: context.bearer_token,
                       insecure: context.insecure_skip_tls_verify == true, timeout: timeout)
      end

      def http_transport(url:, ca_pem: nil, cert_pem: nil, key_pem: nil, token: nil, insecure: false, timeout: 30)
        ca = ca_pem ? ca_pem.to_s.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).map { |pem| OpenSSL::X509::Certificate.new(pem) } : []
        client_cert = cert_pem ? OpenSSL::X509::Certificate.new(cert_pem) : nil
        client_key = key_pem ? OpenSSL::PKey.read(key_pem) : nil
        lambda do |body|
          uri = URI.parse(url)
          http = Security::Egress.http(uri, "controlplane")
          http.use_ssl = uri.scheme == "https"
          http.open_timeout = [timeout.to_f, 10].min
          http.read_timeout = timeout.to_f
          if http.use_ssl?
            if insecure
              http.verify_mode = OpenSSL::SSL::VERIFY_NONE
            else
              store = OpenSSL::X509::Store.new
              ca.each { |certificate| store.add_cert(certificate) }
              http.cert_store = store unless ca.empty?
              http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            end
            http.cert = client_cert if client_cert
            http.key = client_key if client_key
          end
          headers = {"content-type" => "application/json", "accept" => "application/json"}
          headers["authorization"] = "Bearer #{token}" if token && !token.to_s.empty?
          path = uri.request_uri.to_s.empty? || uri.request_uri == "/" ? "/apis/authorization.k8s.io/v1/subjectaccessreviews" : uri.request_uri
          response = http.post(path, body, headers)
          [response.code.to_i, response.body]
        end
      end

      # The list work estimator's object counts and sizes per resource
      # ("pods", "deployments.apps"), from the store's registry prefixes.
      def store_object_stats
        store = @store
        return nil unless store.respond_to?(:object_counts) && store.respond_to?(:object_sizes)

        lambda do
          counts = store.object_counts
          sizes = store.object_sizes
          counts.each_with_object({}) do |(prefix, count), stats|
            parts = prefix.split("/")
            resource_key = parts.length == 3 ? parts[2] : "#{parts[3]}.#{parts[1]}"
            stats[resource_key] = [count, sizes[prefix].to_i]
          end
        end
      end

      def rbac_source
        Security::Authorization::StoreRBACSource.new(@store, key_for: ->(resource, namespace) { @key_for.call("rbac.authorization.k8s.io", "v1", resource, namespace, nil) })
      end

      # The node authorizer's graph: fed by the store's watches when the
      # store has them (the API server), read live otherwise (tests, tools).
      def node_graph
        return @node_graph if @node_graph
        if @store.respond_to?(:watch)
          graph = Security::Authorization::NodeGraph.new
          @node_graph_populator = Security::Authorization::NodeGraph::Populator.new(graph: graph, store: @store, logger: @logger)
          return @node_graph = graph
        end

        @node_graph = live_node_graph
      end

      # Started by the service once the store is serving.
      attr_reader :node_graph_populator

      def live_node_graph
        assembly = self
        graph = Object.new
        graph.define_singleton_method(:pods_on_node) do |node_name|
          assembly.send(:list_objects, "pods", nil).select { |pod| pod.dig("spec", "nodeName") == node_name }
        end
        graph.define_singleton_method(:persistent_volume_claim) { |namespace, name| assembly.send(:read_object, "persistentvolumeclaims", namespace, name) }
        graph.define_singleton_method(:persistent_volume) { |name| assembly.send(:read_object, "persistentvolumes", nil, name) }
        graph.define_singleton_method(:volume_attachment) do |name|
          assembly.send(:read_object, "volumeattachments", nil, name, group: "storage.k8s.io", version: "v1")
        end
        graph.define_singleton_method(:resource_slice) do |name|
          assembly.send(:read_object, "resourceslices", nil, name, group: "resource.k8s.io", version: "v1")
        end
        graph.define_singleton_method(:pod_certificate_request) do |namespace, name|
          assembly.send(:read_object, "podcertificaterequests", namespace, name, group: "certificates.k8s.io", version: "v1beta1")
        end
        graph
      end

      # ------------------------------------------------------------ audit / apf / admission

      def build_audit(audit)
        return [nil, nil] unless audit

        policy = Security::Audit::Policy.from_h(YAML.safe_load(File.read(audit.fetch("policy_file")), permitted_classes: [], aliases: false))
        backends = []
        backends << Security::Audit::LogBackend.new(path: audit["log_path"], max_queue: audit.fetch("max_queue", 10_000)) if audit["log_path"]
        if (webhook = audit["webhook"])
          token = webhook["token_file"] ? File.read(webhook["token_file"]).strip : webhook["token"]
          backends << Security::Audit::WebhookBackend.new(url: webhook.fetch("url"), mode: webhook.fetch("mode", "batch"),
                                                          ca_file: webhook["ca_file"], token: token,
                                                          timeout: webhook.fetch("timeout_seconds", 30),
                                                          batch_max_size: webhook.fetch("batch_max_size", Security::Audit::WebhookBackend::DEFAULT_BATCH_MAX_SIZE),
                                                          batch_max_wait: webhook.fetch("batch_max_wait_seconds", Security::Audit::WebhookBackend::DEFAULT_BATCH_MAX_WAIT))
        end
        backend = case backends.length
                  when 0 then Security::Audit::MemoryBackend.new
                  when 1 then backends.first
                  else Security::Audit::UnionBackend.new(*backends)
                  end
        [policy, backend]
      end

      # kube-apiserver enables API Priority and Fairness by default (the
      # bootstrap PriorityLevelConfigurations and FlowSchemas, which
      # install_bootstrap_objects already creates unless it is off);
      # security.flow_control.enabled: false is the off switch.
      def build_flow_control(apf)
        return nil if apf.is_a?(Hash) && apf["enabled"] == false

        documents = self.class.bootstrap_documents
        Security::FlowControl::Controller.new(
          flow_schemas: documents.fetch("flowschemas", []), priority_level_configurations: documents.fetch("prioritylevelconfigurations", []),
          read_seats: (apf || {}).fetch("read_seats", Security::FlowControl::Controller::DEFAULT_READ_SEATS),
          mutating_seats: (apf || {}).fetch("mutating_seats", Security::FlowControl::Controller::DEFAULT_MUTATING_SEATS),
          object_stats: store_object_stats
        )
      end

      def build_admission(admission)
        return nil unless defined?(Security::Admission::Registry)

        context = Security::Admission::Context.new(store: @store, key_for: @key_for, clock: @clock, feature_gates: @feature_gates,
                                                   authorizer: @pipeline_authorizer, resource_resolver: @resource_resolver,
                                                   scope_resolver: @scope_resolver, type_resolver: @type_resolver, defaulter: @defaulter,
                                                   cel: Security::CEL::Evaluator.new(library: Security::CEL::Library.new(authorizer: @pipeline_authorizer)))
        config = (admission&.fetch("config", nil) || {}).dup
        if @service_resolver
          %w[MutatingAdmissionWebhook ValidatingAdmissionWebhook].each do |plugin|
            config[plugin] = (config[plugin] || {}).merge("service_resolver" => @service_resolver)
          end
        end
        Security::Admission::Registry.default_chain(context: context, enable: Array(admission&.fetch("enable", nil)), disable: Array(admission&.fetch("disable", nil)),
                                                    config: config, feature_gates: @feature_gates)
      end

      # ------------------------------------------------------------ helpers

      def cel_evaluator
        return nil unless defined?(Security::CEL::Evaluator)

        Security::CEL::Evaluator.new
      end

      def https_transport(hook)
        url = hook.fetch("url")
        ca = hook["ca_file"] ? load_certificates(hook["ca_file"]) : []
        client_cert = hook["client_cert_file"] ? OpenSSL::X509::Certificate.new(File.binread(hook["client_cert_file"])) : nil
        client_key = hook["client_key_file"] ? OpenSSL::PKey.read(File.binread(hook["client_key_file"])) : nil
        lambda do |body|
          uri = URI.parse(url)
          # URI#hostname: an IPv6 literal without the brackets URI#host keeps.
          http = Security::Egress.http(uri, "controlplane")
          http.use_ssl = uri.scheme == "https"
          http.open_timeout = 10
          http.read_timeout = 30
          if http.use_ssl?
            store = OpenSSL::X509::Store.new
            ca.each { |certificate| store.add_cert(certificate) }
            http.cert_store = store unless ca.empty?
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            http.cert = client_cert if client_cert
            http.key = client_key if client_key
          end
          response = http.post(uri.request_uri, body, {"content-type" => "application/json", "accept" => "application/json"})
          [response.code.to_i, response.body]
        end
      end

      def load_certificates(path)
        OpenSSL::X509::Certificate.load(File.binread(path))
      end

      def read_object(resource, namespace, name, group: "", version: "v1")
        @store.get(@key_for.call(group, version, resource, namespace, name))
      rescue StandardError
        nil
      end

      # The legacy token tracker's label write (a merge of metadata.labels).
      def merge_labels(resource, namespace, name, labels)
        @store.guaranteed_update(@key_for.call("", "v1", resource, namespace, name)) do |current|
          next current if current.nil?

          copy = JSON.parse(JSON.generate(current))
          (copy["metadata"] ||= {})["labels"] = (copy["metadata"]["labels"] || {}).merge(labels)
          copy
        end
      rescue StandardError
        nil
      end

      def list_objects(resource, namespace)
        @store.list(@key_for.call("", "v1", resource, namespace, nil)).items
      rescue StandardError
        []
      end
    end
  end
end
