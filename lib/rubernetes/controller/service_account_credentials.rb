# frozen_string_literal: true

require_relative "../client"

module Rubernetes
  module Controller
    # kube-controller-manager --use-service-account-credentials
    # (k8s.io/controller-manager/pkg/clientbuilder DynamicControllerClientBuilder):
    # every controller talks to the API server as its own ServiceAccount in
    # kube-system, bound by the bootstrap policy to system:controller:<name>.
    # The controller manager's own identity (system:kube-controller-manager)
    # only creates those ServiceAccounts and requests their tokens; the shared
    # informers and the token controller keep using it.
    class ServiceAccountCredentials
      NAMESPACE = "kube-system"
      EXPIRATION_SECONDS = 3600
      # Refresh once this fraction of a token's lifetime has passed.
      REFRESH_FRACTION = 0.8

      # upstream cmd/kube-controller-manager: the client name each controller
      # asks its ClientBuilder for.  A controller not listed uses its own name
      # (ControllerContext.NewClient(controllerName)); nil keeps the
      # controller manager's own identity (rootClientBuilder).
      SERVICE_ACCOUNTS = {
        "serviceaccount-token-controller" => nil,
        "bootstrap-signer-controller" => "bootstrap-signer",
        "certificatesigningrequest-approving-controller" => "certificate-controller",
        "certificatesigningrequest-cleaner-controller" => "certificate-controller",
        "certificatesigningrequest-signing-controller" => "certificate-controller",
        "clusterrole-aggregation-controller" => "clusterrole-aggregation-controller",
        "cronjob-controller" => "cronjob-controller",
        "daemonset-controller" => "daemon-set-controller",
        "deployment-controller" => "deployment-controller",
        "disruption-controller" => "disruption-controller",
        "endpoints-controller" => "endpoint-controller",
        "endpointslice-controller" => "endpointslice-controller",
        "endpointslice-mirroring-controller" => "endpointslicemirroring-controller",
        "ephemeral-volume-controller" => "ephemeral-volume-controller",
        "garbage-collector-controller" => "generic-garbage-collector",
        "horizontal-pod-autoscaler-controller" => "horizontal-pod-autoscaler",
        "job-controller" => "job-controller",
        "kube-apiserver-serving-clustertrustbundle-publisher-controller" => "kube-apiserver-serving-clustertrustbundle-publisher",
        "legacy-serviceaccount-token-cleaner-controller" => "legacy-service-account-token-cleaner",
        "namespace-controller" => "namespace-controller",
        "node-ipam-controller" => "node-controller",
        "node-lifecycle-controller" => "node-controller",
        "taint-eviction-controller" => "node-controller",
        "persistent-volume-attach-detach-controller" => "attachdetach-controller",
        "persistentvolume-attach-detach-controller" => "attachdetach-controller",
        "persistentvolume-binder-controller" => "persistent-volume-binder",
        "persistentvolumeclaim-protection-controller" => "pvc-protection-controller",
        "persistent-volume-expander-controller" => "expand-controller",
        "persistentvolume-expander-controller" => "expand-controller",
        "persistent-volume-protection-controller" => "pv-protection-controller",
        "persistentvolume-protection-controller" => "pv-protection-controller",
        "podcertificaterequest-cleaner-controller" => "podcertificaterequestcleaner",
        "pod-garbage-collector-controller" => "pod-garbage-collector",
        "replicaset-controller" => "replicaset-controller",
        "replicationcontroller-controller" => "replication-controller",
        "resourceclaim-controller" => "resource-claim-controller",
        "resourcepoolstatusrequest-controller" => "resourcepoolstatusrequest-controller",
        "resourcequota-controller" => "resourcequota-controller",
        "root-ca-certificate-publisher-controller" => "root-ca-cert-publisher",
        "serviceaccount-controller" => "service-account-controller",
        "service-cidr-controller" => "service-cidrs-controller",
        "statefulset-controller" => "statefulset-controller",
        "storageversion-garbage-collector-controller" => "storage-version-garbage-collector",
        "token-cleaner-controller" => "token-cleaner",
        "ttl-after-finished-controller" => "ttl-after-finished-controller",
        "ttl-controller" => "ttl-controller",
        "volume-attributes-class-protection-controller" => "volumeattributesclass-protection-controller",
        "volumeattributesclass-protection-controller" => "volumeattributesclass-protection-controller"
      }.freeze

      def self.service_account_for(controller_name)
        name = controller_name.to_s
        SERVICE_ACCOUNTS.fetch(name, name)
      end

      # A kubeconfig context whose bearer token is the ServiceAccount's
      # current one; everything else (server, CA) is the root context's, and
      # no client certificate is presented.
      class TokenContext
        def initialize(root, source)
          @root = root
          @source = source
        end

        def name = "serviceaccount"
        def server = value(:server)
        def namespace = NAMESPACE
        def ca_file = value(:ca_file)
        def ca_data = value(:ca_data)
        def insecure_skip_tls_verify = value(:insecure_skip_tls_verify)
        def client_certificate_file = nil
        def client_certificate_data = nil
        def client_key_file = nil
        def client_key_data = nil
        def client_certificate = nil
        def client_key = nil
        def certificate_authority_file = ca_file
        def certificate_authority_data = ca_data
        def bearer_token = @source.call
        def token = bearer_token

        def to_h
          {name: name, server: server, namespace: namespace, ca_file: ca_file, ca_data: ca_data,
           insecure_skip_tls_verify: insecure_skip_tls_verify}
        end

        private

        def value(key)
          if @root.respond_to?(key)
            @root.public_send(key)
          elsif @root.is_a?(Hash)
            @root[key] || @root[key.to_s]
          end
        end
      end

      def initialize(root_client:, namespace: NAMESPACE, expiration_seconds: EXPIRATION_SECONDS,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, client_factory: nil)
        @root = root_client
        @namespace = namespace
        @expiration_seconds = Integer(expiration_seconds)
        @clock = clock
        # clientbuilder: rest.AddUserAgent(config, name) -- the default
        # user agent with "/<ServiceAccount>" appended.
        @client_factory = client_factory || lambda do |context, account|
          Client::KubernetesClient.new(context: context,
                                       user_agent: "#{Client::HTTPClient.default_user_agent}/#{account}")
        end
        @tokens = {}
        @clients = {}
        @mutex = Mutex.new
      end

      # The client for +controller_name+; the root client for a controller
      # that keeps the controller manager's identity.
      def client_for(controller_name)
        account = self.class.service_account_for(controller_name)
        return @root if account.nil?

        existing = @mutex.synchronize { @clients[account] }
        return existing if existing

        # Built outside the lock: a client reads its bearer token as it is
        # constructed, and #token takes the same lock (a recursive lock
        # raised ThreadError in every controller's reconcile).
        context = TokenContext.new(@root.context, -> { token(account) })
        client = @client_factory.arity == 1 ? @client_factory.call(context) : @client_factory.call(context, account)
        @mutex.synchronize { @clients[account] ||= client }
      end

      # The ServiceAccount's token, requested again once it is due.
      def token(account)
        entry = @mutex.synchronize { @tokens[account] }
        return entry[:token] if entry && @clock.call < entry[:refresh_at]

        issued = request_token(account)
        @mutex.synchronize { @tokens[account] = issued }
        issued[:token]
      end

      private

      def request_token(account)
        ensure_service_account(account)
        request = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest",
                   "spec" => {"expirationSeconds" => @expiration_seconds}}
        response = @root.create(request, namespace: @namespace, api_version: "v1",
                                         path: "/api/v1/namespaces/#{@namespace}/serviceaccounts/#{account}/token")
        token = response.to_h.dig("status", "token").to_s
        raise Client::Error, "TokenRequest for #{@namespace}/#{account} returned no token" if token.empty?

        {token: token, refresh_at: @clock.call + (@expiration_seconds * REFRESH_FRACTION)}
      end

      # getOrCreateServiceAccount.
      def ensure_service_account(account)
        @root.get("serviceaccounts", account, namespace: @namespace, api_version: "v1")
      rescue Client::APIError => error
        raise unless error.status == 404

        begin
          @root.create({"apiVersion" => "v1", "kind" => "ServiceAccount",
                        "metadata" => {"name" => account, "namespace" => @namespace}},
                       namespace: @namespace, api_version: "v1")
        rescue Client::APIError => create_error
          raise unless create_error.status == 409
        end
      end
    end
  end
end
