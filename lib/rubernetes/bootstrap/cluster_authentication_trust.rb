# frozen_string_literal: true

require "json"
require "openssl"

require_relative "kubernetes_service_reconciler"

module Rubernetes
  module Bootstrap
    # kube-apiserver's ClusterAuthenticationTrust controller
    # (pkg/controlplane/controller/clusterauthenticationtrust, v1.36.2):
    # publishes kube-system/extension-apiserver-authentication, the client CA
    # and the request-header (front-proxy) configuration every extension API
    # server -- metrics-server, sample-apiserver -- authenticates the
    # aggregator's proxied requests with.  Nothing published it, so a
    # delegating extension server found no front-proxy CA to trust.
    #
    # Each server merges its own values into what is already there (several
    # API servers, possibly with different CAs, share one ConfigMap): header
    # lists are unioned in order, CA bundles are combined without duplicates
    # and without expired certificates.  It runs at start and every minute.
    class ClusterAuthenticationTrust
      NAMESPACE = "kube-system"
      NAME = "extension-apiserver-authentication"
      PATH = "/api/v1/namespaces/#{NAMESPACE}/configmaps"
      INTERVAL = 60.0
      IDENTITY = KubernetesServiceReconciler::IDENTITY

      def initialize(api_server:, authentication_info:, logger: nil, uid_headers: true, interval: INTERVAL, clock: -> { Time.now.utc })
        @api_server = api_server
        @info = authentication_info || {}
        @logger = logger
        @uid_headers = uid_headers
        @interval = Float(interval)
        @clock = clock
        @mutex = Mutex.new
        @stopping = false
        @thread = nil
      end

      def start
        @mutex.synchronize do
          return self if @thread&.alive?

          @stopping = false
          @thread = Thread.new { loop_forever }
          @thread.name = "apiserver-cluster-authentication-trust"
        end
        self
      end

      def stop
        @mutex.synchronize { @stopping = true }
        @thread&.wakeup rescue nil
        @thread&.join(2)
        self
      end

      # syncConfigMap: the ConfigMap's data after merging this server's info;
      # written only when it changed.
      def sync_once
        existing = get("#{PATH}/#{NAME}")
        data = desired_data(existing ? existing["data"] || {} : {})
        return data if existing && existing["data"] == data

        ensure_namespace
        if existing
          put("#{PATH}/#{NAME}", existing.merge("data" => data))
        else
          create(PATH, {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => NAME, "namespace" => NAMESPACE}, "data" => data})
        end
        data
      end

      # combinedClusterAuthenticationInfo + getConfigMapDataFor.
      def desired_data(current)
        data = {}
        client_ca = combine_certificates(parse_bundle(current["client-ca-file"]), Array(@info[:client_ca]))
        data["client-ca-file"] = encode(client_ca) unless client_ca.empty?
        header = @info[:request_header] || {}
        request_ca = combine_certificates(parse_bundle(current["requestheader-client-ca-file"]), Array(header[:ca]))
        return data if request_ca.empty?

        data["requestheader-username-headers"] = union(current["requestheader-username-headers"], header[:username_headers])
        uid = union(current["requestheader-uid-headers"], header[:uid_headers])
        data["requestheader-uid-headers"] = uid if @uid_headers && JSON.parse(uid).any?
        data["requestheader-group-headers"] = union(current["requestheader-group-headers"], header[:group_headers])
        data["requestheader-extra-headers-prefix"] = union(current["requestheader-extra-headers-prefix"], header[:extra_header_prefixes])
        data["requestheader-client-ca-file"] = encode(request_ca)
        data["requestheader-allowed-names"] = union(current["requestheader-allowed-names"], header[:allowed_names])
        data
      end

      private

      def loop_forever
        until @mutex.synchronize { @stopping }
          begin
            sync_once
          rescue StandardError => error
            @logger&.debug("cluster_authentication_trust.retry", error: "#{error.class}: #{error.message}")
          end
          sleep(@interval)
        end
      end

      # combineUniqueStringSlices over the stored JSON list and this server's.
      def union(stored, own)
        existing = stored.to_s.empty? ? [] : Array(JSON.parse(stored))
        values = []
        (existing + Array(own)).each { |value| values << value.to_s unless values.include?(value.to_s) }
        JSON.generate(values)
      rescue JSON::ParserError
        JSON.generate(Array(own).map(&:to_s).uniq)
      end

      def parse_bundle(pem)
        return [] if pem.to_s.empty?

        pem.to_s.scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m).map { |block| OpenSSL::X509::Certificate.new(block) }
      rescue OpenSSL::X509::CertificateError
        []
      end

      # combineCertLists: stored first, then this server's; expired ones are
      # dropped and each certificate appears once.
      def combine_certificates(stored, own)
        now = @clock.call
        result = []
        (stored + own).each do |certificate|
          next if certificate.not_after < now
          next if result.any? { |kept| kept.to_der == certificate.to_der }

          result << certificate
        end
        result
      end

      def encode(certificates) = certificates.map(&:to_pem).join

      def ensure_namespace
        return if get("/api/v1/namespaces/#{NAMESPACE}")

        create("/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => NAMESPACE}})
      end

      def request(method, path, object = nil)
        headers = object ? {"content-type" => "application/json"} : {}
        @api_server.call(API::Request.new(method: method, path: path, headers: headers, body: object && JSON.generate(object), identity: IDENTITY))
      end

      def get(path)
        response = request("GET", path)
        return nil if response.status == 404
        raise "GET #{path} -> #{response.status}" unless response.status == 200

        body(response)
      end

      def create(path, object)
        response = request("POST", path, object)
        raise "POST #{path} -> #{response.status}" unless [200, 201, 409].include?(response.status)

        body(response)
      end

      def put(path, object)
        response = request("PUT", path, object)
        raise "PUT #{path} -> #{response.status}" unless response.status == 200

        body(response)
      end

      def body(response)
        value = response.body
        value = JSON.parse(value) if value.is_a?(String) && !value.empty?
        value.is_a?(Hash) ? value : nil
      end
    end
  end
end
