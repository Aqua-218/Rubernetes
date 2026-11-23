# frozen_string_literal: true

module Rubernetes
  module Cluster
    # Node-local DNS listens on each provisioned worker's bridge gateway.
    # Publish those same listeners for clients that discover kube-dns by name.
    module DNSAddon
      private

      DNS_LABELS = {"k8s-app" => "kube-dns", "app.kubernetes.io/managed-by" => "rubernetes-cluster"}.freeze
      DNS_PORTS = [{"name" => "dns", "port" => 53, "protocol" => "UDP"},
                   {"name" => "dns-tcp", "port" => 53, "protocol" => "TCP"}].freeze

      def install_cluster_dns!(kubeconfig)
        client = api_client(kubeconfig)
        path = "/api/v1/namespaces/kube-system/services/kube-dns"
        response = client.raw("GET", path, raise_for_status: false)
        service = if response.status == 404
                    client.create(cluster_dns_service)
                  else
                    raise Error, "reading kube-dns returned HTTP #{response.status}" unless response.success?

                    JSON.parse(response.body)
                  end
        return unless service.dig("metadata", "labels", "app.kubernetes.io/managed-by") == DNS_LABELS.fetch("app.kubernetes.io/managed-by")

        families.each do |family|
          slice = cluster_dns_endpoints(family, service.dig("metadata", "uid"))
          client.apply(slice, field_manager: "rubernetes-cluster")
        end
      ensure
        client&.close
      end

      def cluster_dns_service
        {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "kube-dns", "namespace" => "kube-system", "labels" => DNS_LABELS},
         "spec" => {"ports" => DNS_PORTS, "ipFamilies" => families.map { |family| dns_address_type(family) },
                    "ipFamilyPolicy" => families.length == 2 ? "RequireDualStack" : "SingleStack", "internalTrafficPolicy" => "Local"}}
      end

      def cluster_dns_endpoints(family, uid)
        address_type = dns_address_type(family)
        labels = DNS_LABELS.merge("kubernetes.io/service-name" => "kube-dns", "endpointslice.kubernetes.io/managed-by" => "dns.rubernetes.io")
        owner = {"apiVersion" => "v1", "kind" => "Service", "name" => "kube-dns", "uid" => uid, "controller" => true}
        endpoints = worker_ids.each_with_index.map do |node, index|
          address = node_advertise_addresses(index).fetch(families.index(family))
          {"addresses" => [address], "nodeName" => node, "conditions" => {"ready" => true}}
        end
        {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
         "metadata" => {"name" => "rubernetes-kube-dns-#{family}", "namespace" => "kube-system", "labels" => labels, "ownerReferences" => [owner]},
         "addressType" => address_type, "ports" => DNS_PORTS, "endpoints" => endpoints}
      end

      def dns_address_type(family)
        family == "ipv4" ? "IPv4" : "IPv6"
      end
    end
  end
end
