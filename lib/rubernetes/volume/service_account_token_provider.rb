# frozen_string_literal: true

module Rubernetes
  module Volume
    # Issues projected ServiceAccount tokens through the TokenRequest API, the
    # way the kubelet does: the node never signs a token itself, it asks the API
    # server for one bound to the pod and audience, and re-requests before the
    # token expires (Projection::TokenRotator drives the rotation).
    #
    # A projected `serviceAccountToken` source is unusable without this: the
    # backend refuses to fabricate a token, so a pod that mounts the default
    # projected volume cannot start.
    class ServiceAccountTokenProvider
      DEFAULT_TTL_SECONDS = 3600

      def initialize(client:, default_ttl: DEFAULT_TTL_SECONDS)
        @client = client
        @default_ttl = Integer(default_ttl)
      end

      # Called by Projection::TokenRotator.  `pod_uid` here is the pod's UID;
      # the namespace, name and service account come from the pod the volume
      # was normalised with, so they are carried on the request context.
      def issue(audience:, pod_uid:, ttl: nil, pod: nil)
        context = pod || @pod
        raise UnsupportedError, "service account token requires the owning pod" unless context

        namespace = Types.key(Types.key(context, "metadata", {}), "namespace", "default").to_s
        spec = Types.key(context, "spec", {})
        service_account = Types.key(spec, "serviceAccountName", Types.key(spec, "serviceAccount", "default")).to_s
        request = {
          "apiVersion" => "authentication.k8s.io/v1",
          "kind" => "TokenRequest",
          "spec" => {
            # No audience means the API server's configured default.
            "audiences" => audience.to_s.empty? ? [] : [audience.to_s],
            "expirationSeconds" => Integer(ttl || @default_ttl),
            "boundObjectRef" => {"kind" => "Pod", "apiVersion" => "v1",
                                 "name" => Types.key(Types.key(context, "metadata", {}), "name", "").to_s,
                                 "uid" => pod_uid.to_s}
          }
        }
        path = "/api/v1/namespaces/#{namespace}/serviceaccounts/#{service_account}/token"
        response = @client.create(request, namespace: namespace, api_version: "v1", path: path)
        status = Types.key(response.to_h, "status", {})
        {"token" => Types.key(status, "token"), "expiresAt" => Types.key(status, "expirationTimestamp")}
      end

      # The rotator issues per (audience, pod_uid); binding the pod for the
      # duration of one volume's preparation keeps that interface unchanged.
      def for_pod(pod)
        copy = self.class.new(client: @client, default_ttl: @default_ttl)
        copy.instance_variable_set(:@pod, pod)
        copy
      end
    end
  end
end
