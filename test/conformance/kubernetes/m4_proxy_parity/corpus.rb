# frozen_string_literal: true

# Shared Service/EndpointSlice corpus and isolated topology for the M4 proxy
# backend parity measurement.
#
# The probe (production process) and the external runner (traffic generator
# and kernel observer) both load this file so the rules compiled by the
# production proxy and the packets sent by the runner describe exactly the
# same cluster.  The runner derives every expected verdict from these
# definitions and the Kubernetes Service semantics alone; it never asks the
# production model what it intends to do.
require "digest"
require "json"

module M4ProxyParityCorpus
  NODE_NAME = "m4-node"
  OTHER_NODE_NAME = "m4-other-node"
  NAMESPACE = "default"
  CLUSTER_DOMAIN = "cluster.local"

  # Every address below is inside a private node network namespace created
  # by the probe; nothing here is routable from the host namespace.
  TOPOLOGY = {
    "node_interfaces" => {"client" => "pxc0", "backend" => "pxb0"},
    "pod_interface" => "eth0",
    "client" => {
      "ipv4" => "198.18.20.2", "ipv4_prefix" => 30, "ipv6" => "fd00:20::2", "ipv6_prefix" => 64,
      "gateway_ipv4" => "198.18.20.1", "gateway_ipv6" => "fd00:20::1"
    },
    "backend" => {
      "ipv4" => ["198.18.30.2", "198.18.30.3"], "ipv4_prefix" => 29,
      "ipv6" => ["fd00:30::2", "fd00:30::3"], "ipv6_prefix" => 64,
      "gateway_ipv4" => "198.18.30.1", "gateway_ipv6" => "fd00:30::1"
    },
    # The node masquerades external (NodePort/ExternalIP/LoadBalancer with
    # externalTrafficPolicy Cluster) traffic to its backend-facing addresses
    # so a masqueraded reply is routed straight back to the node.
    "node_addresses" => ["198.18.30.1", "fd00:30::1"],
    "node_port_addresses" => {"ipv4" => "198.18.20.1", "ipv6" => "fd00:20::1"},
    "routes" => {
      "client" => ["10.96.0.0/16", "203.0.113.0/24", "198.51.100.0/24", "198.18.30.0/29",
                   "fd00:96::/64", "2001:db8:ee::/64", "2001:db8:1b::/64", "fd00:30::/64"],
      "backend" => ["198.18.20.0/30", "10.96.0.0/16", "fd00:20::/64", "fd00:96::/64"]
    },
    "ports" => {"tcp" => 8080, "udp" => 8053, "sctp" => 8132},
    "dns" => {"address" => "198.18.20.1", "port" => 15_353},
    "health_check_node_port" => 30_999
  }.freeze

  SERVICE_PORTS = {"TCP" => 8080, "UDP" => 8053, "SCTP" => 8132}.freeze
  FRONT_PORTS = {"TCP" => 80, "UDP" => 53, "SCTP" => 132}.freeze

  module_function

  def endpoint(address, _protocol, node: NODE_NAME, ready: true, serving: nil, terminating: false, hostname: nil)
    serving = ready if serving.nil?
    {
      "addresses" => [address],
      "conditions" => {"ready" => ready, "serving" => serving, "terminating" => terminating},
      "nodeName" => node,
      "hostname" => hostname,
      "targetRef" => {"kind" => "Pod", "name" => "pod-#{address.tr(".:", "--")}", "uid" => "uid-#{address}"}
    }.compact
  end

  def slice(service, family, endpoints, protocol:, port: SERVICE_PORTS.fetch(protocol))
    {
      "apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
      "metadata" => {"name" => "#{service}-#{family.downcase}", "namespace" => NAMESPACE,
                     "labels" => {"kubernetes.io/service-name" => service}},
      "addressType" => family,
      "ports" => [{"name" => protocol.downcase, "port" => port, "protocol" => protocol}],
      "endpoints" => endpoints
    }
  end

  def service(name, protocol, spec)
    {
      "apiVersion" => "v1", "kind" => "Service",
      "metadata" => {"name" => name, "namespace" => NAMESPACE, "uid" => "uid-#{name}"},
      "spec" => {
        "ports" => [{"name" => protocol.downcase, "port" => FRONT_PORTS.fetch(protocol),
                     "targetPort" => SERVICE_PORTS.fetch(protocol), "protocol" => protocol}]
      }.merge(spec)
    }
  end

  def dual_stack(v4, v6)
    {"clusterIP" => v4, "clusterIPs" => [v4, v6], "ipFamilies" => %w[IPv4 IPv6]}
  end

  def both_backends(protocol, **)
    v4 = TOPOLOGY.dig("backend", "ipv4").map { |ip| endpoint(ip, protocol, **) }
    v6 = TOPOLOGY.dig("backend", "ipv6").map { |ip| endpoint(ip, protocol, **) }
    [v4, v6]
  end

  def objects
    services = []
    slices = []
    add = lambda do |name, protocol, spec, v4_endpoints, v6_endpoints, port: SERVICE_PORTS.fetch(protocol)|
      services << service(name, protocol, spec)
      slices << slice(name, "IPv4", v4_endpoints, protocol: protocol, port: port) if v4_endpoints
      slices << slice(name, "IPv6", v6_endpoints, protocol: protocol, port: port) if v6_endpoints
    end
    protocols = %w[TCP UDP SCTP]
    protocols.each_with_index do |protocol, index|
      v4, v6 = both_backends(protocol)
      add.call("clusterip-#{protocol.downcase}", protocol,
               {"type" => "ClusterIP"}.merge(dual_stack("10.96.0.#{10 + index}", "fd00:96::#{10 + index}")), v4, v6)
      add.call("nodeport-#{protocol.downcase}", protocol,
               {"type" => "NodePort"}.merge(dual_stack("10.96.0.#{20 + index}", "fd00:96::#{20 + index}"))
                 .merge("ports" => [{"name" => protocol.downcase, "port" => FRONT_PORTS.fetch(protocol),
                                     "targetPort" => SERVICE_PORTS.fetch(protocol), "protocol" => protocol,
                                     "nodePort" => 30_080 + index}]), v4, v6)
      add.call("externalip-#{protocol.downcase}", protocol,
               {"type" => "ClusterIP", "externalIPs" => ["203.0.113.#{10 + index}", "2001:db8:ee::#{10 + index}"]}
                 .merge(dual_stack("10.96.0.#{30 + index}", "fd00:96::#{30 + index}")), v4, v6)
      add.call("lb-#{protocol.downcase}", protocol,
               {"type" => "LoadBalancer", "loadBalancerIPs" => ["198.51.100.#{10 + index}", "2001:db8:1b::#{10 + index}"],
                "loadBalancerSourceRanges" => ["198.18.20.0/30", "fd00:20::/64"],
                "allocateLoadBalancerNodePorts" => false}
                 .merge(dual_stack("10.96.0.#{40 + index}", "fd00:96::#{40 + index}")), v4, v6)
      add.call("headless-#{protocol.downcase}", protocol,
               {"type" => "ClusterIP", "clusterIP" => "None", "clusterIPs" => ["None"]}, v4, v6)
    end
    # Reverse SNAT must restore an address distinct from every endpoint; a
    # single-endpoint Service makes the DNAT target deterministic.
    single_v4 = [endpoint(TOPOLOGY.dig("backend", "ipv4").first, "TCP")]
    single_v6 = [endpoint(TOPOLOGY.dig("backend", "ipv6").first, "TCP")]
    add.call("reverse-tcp", "TCP", {"type" => "ClusterIP"}.merge(dual_stack("10.96.0.50", "fd00:96::50")), single_v4, single_v6)
    add.call("affinity-tcp", "TCP",
             {"type" => "ClusterIP", "sessionAffinity" => "ClientIP",
              "sessionAffinityConfig" => {"clientIP" => {"timeoutSeconds" => 600}}}.merge(dual_stack("10.96.0.51", "fd00:96::51")),
             *both_backends("TCP"))
    local_v4 = [endpoint(TOPOLOGY.dig("backend", "ipv4")[0], "TCP", node: NODE_NAME),
                endpoint(TOPOLOGY.dig("backend", "ipv4")[1], "TCP", node: OTHER_NODE_NAME)]
    local_v6 = [endpoint(TOPOLOGY.dig("backend", "ipv6")[0], "TCP", node: NODE_NAME),
                endpoint(TOPOLOGY.dig("backend", "ipv6")[1], "TCP", node: OTHER_NODE_NAME)]
    add.call("itp-local-tcp", "TCP", {"type" => "ClusterIP", "internalTrafficPolicy" => "Local"}.merge(dual_stack("10.96.0.52", "fd00:96::52")),
             local_v4, local_v6)
    add.call("etp-local-tcp", "TCP",
             {"type" => "NodePort", "externalTrafficPolicy" => "Local",
              "ports" => [{"name" => "tcp", "port" => 80, "targetPort" => 8080, "protocol" => "TCP", "nodePort" => 30_090}]}
               .merge(dual_stack("10.96.0.53", "fd00:96::53")), local_v4, local_v6)
    terminating_v4 = [endpoint(TOPOLOGY.dig("backend", "ipv4")[0], "TCP", ready: false, serving: true, terminating: true),
                      endpoint(TOPOLOGY.dig("backend", "ipv4")[1], "TCP", ready: false, serving: false, terminating: true)]
    terminating_v6 = [endpoint(TOPOLOGY.dig("backend", "ipv6")[0], "TCP", ready: false, serving: true, terminating: true),
                      endpoint(TOPOLOGY.dig("backend", "ipv6")[1], "TCP", ready: false, serving: false, terminating: true)]
    add.call("terminating-tcp", "TCP", {"type" => "ClusterIP"}.merge(dual_stack("10.96.0.54", "fd00:96::54")),
             terminating_v4, terminating_v6)
    add.call("hcnp-tcp", "TCP",
             {"type" => "NodePort", "externalTrafficPolicy" => "Local",
              "healthCheckNodePort" => TOPOLOGY.fetch("health_check_node_port"),
              "ports" => [{"name" => "tcp", "port" => 80, "targetPort" => 8080, "protocol" => "TCP", "nodePort" => 30_091}]}
               .merge(dual_stack("10.96.0.55", "fd00:96::55")), local_v4, local_v6)
    services << {
      "apiVersion" => "v1", "kind" => "Service",
      "metadata" => {"name" => "ext-tcp", "namespace" => NAMESPACE, "uid" => "uid-ext-tcp"},
      "spec" => {"type" => "ExternalName", "externalName" => "clusterip-tcp.#{NAMESPACE}.svc.#{CLUSTER_DOMAIN}"}
    }
    {"services" => services, "endpoint_slices" => slices}
  end

  # Case inventory.  `kind` selects the runner action; the runner derives the
  # expected observable from the corpus objects and Kubernetes semantics.
  def cases
    list = []
    %w[ipv4 ipv6].each do |family|
      %w[tcp udp sctp].each do |protocol|
        list << {"id" => "#{family}_#{protocol}_cluster_ip", "kind" => "vip", "service" => "clusterip-#{protocol}",
                 "family" => family, "protocol" => protocol.upcase}
        list << {"id" => "#{family}_#{protocol}_node_port", "kind" => "node_port", "service" => "nodeport-#{protocol}",
                 "family" => family, "protocol" => protocol.upcase}
        list << {"id" => "#{family}_#{protocol}_external_ip", "kind" => "external_ip", "service" => "externalip-#{protocol}",
                 "family" => family, "protocol" => protocol.upcase}
        list << {"id" => "#{family}_#{protocol}_load_balancer", "kind" => "load_balancer", "service" => "lb-#{protocol}",
                 "family" => family, "protocol" => protocol.upcase}
        list << {"id" => "#{family}_#{protocol}_headless", "kind" => "headless", "service" => "headless-#{protocol}",
                 "family" => family, "protocol" => protocol.upcase}
      end
      list << {"id" => "#{family}_distinct_address_reverse", "kind" => "vip", "service" => "reverse-tcp",
               "family" => family, "protocol" => "TCP", "distinct_reverse" => true}
      list << {"id" => "#{family}_fragments", "kind" => "fragments", "service" => "clusterip-udp",
               "family" => family, "protocol" => "UDP"}
    end
    list << {"id" => "external_name_cname", "kind" => "dns_cname", "service" => "ext-tcp", "family" => "ipv4", "protocol" => "TCP",
             "target_service" => "clusterip-tcp"}
    list << {"id" => "health_check_node_port", "kind" => "health_check", "service" => "hcnp-tcp", "family" => "ipv4",
             "protocol" => "TCP"}
    list << {"id" => "session_affinity_client_ip", "kind" => "affinity", "service" => "affinity-tcp", "family" => "ipv4",
             "protocol" => "TCP", "connections" => 6}
    list << {"id" => "internal_traffic_policy_local", "kind" => "vip", "service" => "itp-local-tcp", "family" => "ipv4",
             "protocol" => "TCP", "local_only" => true}
    list << {"id" => "external_traffic_policy_local", "kind" => "node_port", "service" => "etp-local-tcp", "family" => "ipv4",
             "protocol" => "TCP", "local_only" => true}
    list << {"id" => "terminating_endpoints", "kind" => "vip", "service" => "terminating-tcp", "family" => "ipv4",
             "protocol" => "TCP", "terminating" => true}
    list << {"id" => "dual_stack_service", "kind" => "dual_stack", "service" => "clusterip-tcp", "family" => "dual",
             "protocol" => "TCP"}
    list.freeze
  end

  def case_ids
    cases.map { |entry| entry.fetch("id") }
  end

  def canonical(value)
    case value
    when Hash then value.map { |key, child| [key.to_s, canonical(child)] }.sort_by(&:first).to_h
    when Array then value.map { |child| canonical(child) }
    else value
    end
  end

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
  end

  def corpus_sha256
    digest(objects.merge("cases" => cases, "topology" => TOPOLOGY))
  end
end
