# frozen_string_literal: true

require "digest"
require "ipaddr"
require "json"
require "securerandom"
require "socket"
require "time"
require_relative "../client"

module Rubernetes
  module Bootstrap
    # kube-apiserver's bootstrap controller for the `default/kubernetes`
    # Service: the Service itself (first address of the primary ServiceCIDR,
    # port 443 -> the API server's secure port) and its Endpoints /
    # EndpointSlice listing every live API server.
    #
    # Liveness of the other API servers follows the "lease" reconciler
    # design: each server renews a Lease in kube-system that carries its
    # endpoint; the Endpoints are the addresses of all leases renewed within
    # the grace window.  A server that stops renewing drops out on its own.
    class KubernetesServiceReconciler
      SERVICE_NAME = "kubernetes"
      SERVICE_NAMESPACE = "default"
      LEASE_NAMESPACE = "kube-system"
      LEASE_LABEL = "apiserver.kubernetes.io/identity"
      # APIServerIdentity (Beta on): the kube-apiserver identity Lease --
      # labelled apiserver.kubernetes.io/identity=kube-apiserver plus the
      # host, held by "<lease name>_<uuid>" for one process, an hour long,
      # expired ones garbage-collected hourly.
      LEASE_LABEL_VALUE = "kube-apiserver"
      LEGACY_LEASE_LABEL_VALUE = "rubernetes-apiserver"
      IDENTITY_LEASE_DURATION_SECONDS = 3600
      IDENTITY_LEASE_GC_PERIOD = 3600.0
      ENDPOINT_ANNOTATION = "rubernetes.io/endpoint"
      DEFAULT_INTERVAL = 10.0
      # An API server serves the kubernetes Endpoints while it renewed its
      # Lease within this window (the lease reconciler's TTL).
      LEASE_DURATION_SECONDS = 30
      SKIP_MIRROR_LABEL = "endpointslice.kubernetes.io/skip-mirror"
      MANAGED_BY_LABEL = "endpointslice.kubernetes.io/managed-by"

      attr_reader :endpoint, :service_ip, :secure_port

      def initialize(api_server:, logger:, advertise_address:, secure_port:, service_cidrs:, identity:,
                     interval: DEFAULT_INTERVAL, clock: -> { Time.now.utc })
        @api_server = api_server
        @logger = logger
        @advertise_address = advertise_address.to_s
        @secure_port = Integer(secure_port)
        @identity = identity.to_s
        @interval = Float(interval)
        @clock = clock
        cidr = IPAddr.new(String(Array(service_cidrs).first))
        @service_ip = IPAddr.new(cidr.to_i + 1, cidr.family).to_s
        @endpoint = "#{@advertise_address}:#{@secure_port}"
        @thread = nil
        @stopping = false
        @mutex = Mutex.new
        @holder = "#{lease_name}_#{SecureRandom.uuid}"
        @last_gc = nil
      end

      def start
        @mutex.synchronize do
          return self if @thread&.alive?

          @stopping = false
          @thread = Thread.new { loop_forever }
          @thread.name = "apiserver-kubernetes-service"
        end
        self
      end

      def stop
        @mutex.synchronize { @stopping = true }
        @thread&.join(2)
        self
      end

      # One reconciliation: Service, own Lease, Endpoints, EndpointSlice.
      def reconcile_once
        ensure_service
        renew_lease
        addresses = live_addresses
        ensure_endpoints(addresses)
        ensure_endpoint_slice(addresses)
        addresses
      end

      private

      def loop_forever
        until @mutex.synchronize { @stopping }
          begin
            reconcile_once
          rescue StandardError => error
            @logger.debug("kubernetes_service.reconcile_retry", error: "#{error.class}: #{error.message}")
          end
          sleep(@interval)
        end
      end

      def ensure_service
        existing = get("/api/v1/namespaces/#{SERVICE_NAMESPACE}/services/#{SERVICE_NAME}")
        return if existing

        create("/api/v1/namespaces/#{SERVICE_NAMESPACE}/services", {
                 "apiVersion" => "v1", "kind" => "Service",
                 "metadata" => {"name" => SERVICE_NAME, "namespace" => SERVICE_NAMESPACE,
                                "labels" => {"component" => "apiserver", "provider" => "kubernetes"}},
                 "spec" => {"clusterIP" => @service_ip, "type" => "ClusterIP", "sessionAffinity" => "None",
                            "ports" => [{"name" => "https", "protocol" => "TCP", "port" => 443, "targetPort" => @secure_port}]}
               })
      end

      # config.go APIServerID: "apiserver-" + base32(sha256(len-prefixed
      # hostname, len-prefixed "kube-apiserver"))[:16] lowercased.  Our API
      # servers share a host, so their own identity stands in for the
      # hostname and each keeps a Lease of its own.
      def lease_name = self.class.apiserver_id(@identity)

      # The API server ID (config.go): also the identity Lease's name.
      def self.apiserver_id(identity)
        data = [identity.to_s, "kube-apiserver"].map { |part| [part.bytesize].pack("n") + part.b }.join
        digest = Digest::SHA256.digest(data)[0, 16]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        "apiserver-#{digest.unpack1("B*").scan(/.{1,5}/).map { |chunk| alphabet[chunk.ljust(5, "0").to_i(2)] }.join.downcase}"
      end

      def renew_lease
        now = @clock.call.utc.iso8601(6)
        path = "/apis/coordination.k8s.io/v1/namespaces/#{LEASE_NAMESPACE}/leases/#{lease_name}"
        body = {
          "apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
          "metadata" => {"name" => lease_name, "namespace" => LEASE_NAMESPACE,
                         "labels" => {LEASE_LABEL => LEASE_LABEL_VALUE, "kubernetes.io/hostname" => hostname_label},
                         "annotations" => {ENDPOINT_ANNOTATION => @endpoint}},
          "spec" => {"holderIdentity" => @holder, "leaseDurationSeconds" => IDENTITY_LEASE_DURATION_SECONDS, "renewTime" => now}
        }
        existing = get(path)
        if existing
          # leasecontroller: the lease read, its renewTime moved on and the
          # identity labels reapplied (newLeasePostProcessFunc), written back
          # with an Update.
          metadata = existing["metadata"].merge(
            "labels" => (existing.dig("metadata", "labels") || {}).merge(body.dig("metadata", "labels")),
            "annotations" => (existing.dig("metadata", "annotations") || {}).merge(body.dig("metadata", "annotations"))
          )
          put(path, existing.merge("metadata" => metadata.except("managedFields"),
                                   "spec" => (existing["spec"] || {}).merge(body["spec"])))
        else
          create("/apis/coordination.k8s.io/v1/namespaces/#{LEASE_NAMESPACE}/leases", body)
        end
      end

      def hostname_label
        Socket.gethostname.to_s.downcase[0, 63]
      rescue StandardError
        ""
      end

      # Identity Leases of every API server (and, while servers are
      # upgraded, the ones written under the previous label).
      def identity_leases
        [LEASE_LABEL_VALUE, LEGACY_LEASE_LABEL_VALUE].flat_map do |value|
          list = get("/apis/coordination.k8s.io/v1/namespaces/#{LEASE_NAMESPACE}/leases?labelSelector=#{LEASE_LABEL}%3D#{value}") || {}
          Array(list["items"])
        end
      end

      # apiserverleasegc: identity Leases that expired are deleted.
      def collect_expired_leases(leases)
        now = @clock.call.utc
        return if @last_gc && now - @last_gc < IDENTITY_LEASE_GC_PERIOD

        @last_gc = now
        leases.each do |lease|
          renew = lease.dig("spec", "renewTime")
          duration = Integer(lease.dig("spec", "leaseDurationSeconds") || IDENTITY_LEASE_DURATION_SECONDS)
          next unless renew.nil? || now - Time.iso8601(renew.to_s) > duration

          name = lease.dig("metadata", "name")
          delete("/apis/coordination.k8s.io/v1/namespaces/#{LEASE_NAMESPACE}/leases/#{name}")
        rescue StandardError
          nil
        end
      end

      def live_addresses
        leases = identity_leases
        collect_expired_leases(leases)
        now = @clock.call.utc
        leases.filter_map do |lease|
          renew = lease.dig("spec", "renewTime")
          next if renew.nil? || (now - Time.iso8601(renew.to_s)) > LEASE_DURATION_SECONDS

          endpoint = lease.dig("metadata", "annotations", ENDPOINT_ANNOTATION).to_s
          next if endpoint.empty?

          host, port = split_endpoint(endpoint)
          {"ip" => host, "port" => port}
        end.uniq.sort_by { |entry| entry["ip"] }
      end

      def split_endpoint(endpoint)
        if endpoint.start_with?("[")
          host, port = endpoint[1..].split("]:", 2)
        else
          host, port = endpoint.rpartition(":").values_at(0, 2)
        end
        [host, Integer(port)]
      end

      # API servers on one host listen on different ports, so the subsets are
      # grouped by port the way the Endpoints schema requires.
      def ensure_endpoints(addresses)
        return if addresses.empty?

        subsets = addresses.group_by { |entry| entry.fetch("port") }.sort.map do |port, entries|
          {"addresses" => entries.map { |entry| {"ip" => entry.fetch("ip")} }.uniq,
           "ports" => [{"name" => "https", "port" => port, "protocol" => "TCP"}]}
        end
        desired = {
          "apiVersion" => "v1", "kind" => "Endpoints",
          "metadata" => {"name" => SERVICE_NAME, "namespace" => SERVICE_NAMESPACE, "labels" => {SKIP_MIRROR_LABEL => "true"}},
          "subsets" => subsets
        }
        path = "/api/v1/namespaces/#{SERVICE_NAMESPACE}/endpoints/#{SERVICE_NAME}"
        existing = get(path)
        if existing.nil?
          create("/api/v1/namespaces/#{SERVICE_NAMESPACE}/endpoints", desired)
        elsif existing["subsets"] != desired["subsets"] || (existing.dig("metadata", "labels") || {}) != desired.dig("metadata", "labels")
          # EndpointsAdapter.Update.
          metadata = existing["metadata"].except("managedFields").merge("labels" => desired.dig("metadata", "labels"))
          put(path, existing.merge("metadata" => metadata, "subsets" => desired["subsets"]))
        end
      end

      # One EndpointSlice per endpoint port (a slice carries a single port
      # list); the first keeps the Service's name, the rest are suffixed.
      def ensure_endpoint_slice(addresses)
        return if addresses.empty?

        wanted = {}
        addresses.group_by { |entry| entry.fetch("port") }.sort.each_with_index do |(port, entries), index|
          name = index.zero? ? SERVICE_NAME : "#{SERVICE_NAME}-#{port}"
          family = IPAddr.new(entries.first.fetch("ip")).ipv6? ? "IPv6" : "IPv4"
          # endpointSliceFromEndpoints labels the slice with the service name
          # only.  API servers sharing a host serve on different ports, and
          # each further port needs a slice of its own; those carry a
          # managed-by label so the ones no longer wanted can be found.
          labels = {"kubernetes.io/service-name" => SERVICE_NAME}
          labels[MANAGED_BY_LABEL] = "rubernetes-apiserver" unless index.zero?
          wanted[name] = {
            "apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
            "metadata" => {"name" => name, "namespace" => SERVICE_NAMESPACE, "labels" => labels},
            "addressType" => family,
            "endpoints" => entries.map { |entry| entry.fetch("ip") }.uniq.map { |ip| {"addresses" => [ip], "conditions" => {"ready" => true}} },
            "ports" => [{"name" => "https", "port" => port, "protocol" => "TCP"}]
          }
        end
        wanted.each do |name, desired|
          path = "/apis/discovery.k8s.io/v1/namespaces/#{SERVICE_NAMESPACE}/endpointslices/#{name}"
          existing = get(path)
          if existing.nil?
            create("/apis/discovery.k8s.io/v1/namespaces/#{SERVICE_NAMESPACE}/endpointslices", desired)
          elsif existing["addressType"] != desired["addressType"]
            # Required for a change of address type: delete and create.
            delete(path)
            create("/apis/discovery.k8s.io/v1/namespaces/#{SERVICE_NAMESPACE}/endpointslices", desired)
          elsif existing["endpoints"] != desired["endpoints"] || existing["ports"] != desired["ports"] ||
                (existing.dig("metadata", "labels") || {}) != desired.dig("metadata", "labels")
            metadata = desired["metadata"].merge("resourceVersion" => existing.dig("metadata", "resourceVersion"))
            put(path, desired.merge("metadata" => metadata))
          end
        end
        list = get("/apis/discovery.k8s.io/v1/namespaces/#{SERVICE_NAMESPACE}/endpointslices?labelSelector=#{MANAGED_BY_LABEL}%3Drubernetes-apiserver") || {}
        Array(list["items"]).each do |slice|
          name = slice.dig("metadata", "name")
          next if wanted.key?(name)

          delete("/apis/discovery.k8s.io/v1/namespaces/#{SERVICE_NAMESPACE}/endpointslices/#{name}")
        end
      end

      # ---------------------------------------------------------------- API access

      IDENTITY = {"username" => "system:apiserver", "groups" => ["system:masters"]}.freeze
      # The loopback client's user agent (rest.DefaultKubernetesUserAgent of
      # kube-apiserver), which names the field manager of these writes.
      HEADERS = {"user-agent" => Client::HTTPClient.default_user_agent(command: "kube-apiserver")}.freeze

      def get(path)
        response = @api_server.call(API::Request.new(method: "GET", path: path, headers: HEADERS, body: nil, identity: IDENTITY))
        return nil if response.status == 404
        raise "GET #{path} -> #{response.status}" unless response.status == 200

        body(response)
      end

      def create(path, object)
        response = @api_server.call(API::Request.new(method: "POST", path: path, headers: HEADERS.merge("content-type" => "application/json"),
                                                     body: JSON.generate(object), identity: IDENTITY))
        return body(response) if [200, 201, 409].include?(response.status)

        raise "POST #{path} -> #{response.status}: #{message(response)}"
      end

      def put(path, object)
        response = @api_server.call(API::Request.new(method: "PUT", path: path, headers: HEADERS.merge("content-type" => "application/json"),
                                                     body: JSON.generate(object), identity: IDENTITY))
        return body(response) if response.status == 200

        raise "PUT #{path} -> #{response.status}: #{message(response)}"
      end

      def delete(path)
        response = @api_server.call(API::Request.new(method: "DELETE", path: path, headers: HEADERS, body: nil, identity: IDENTITY))
        raise "DELETE #{path} -> #{response.status}" unless [200, 202, 404].include?(response.status)

        true
      end

      def body(response)
        value = response.body
        value = JSON.parse(value) if value.is_a?(String) && !value.empty?
        value.is_a?(Hash) ? value : nil
      end

      def message(response)
        value = body(response)
        value.is_a?(Hash) ? value["message"] : nil
      end
    end
  end
end
