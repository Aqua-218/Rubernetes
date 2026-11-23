# frozen_string_literal: true

require "digest"
require "open3"

module Conformance
  # The real reference CNI plugins own each Pod interface and IPAM record in
  # this variant of the IPv4 native profile. The existing cluster launcher
  # still supplies API, DNS, routing and kube-proxy in the same topology.
  class ExternalCNIProfile < Rubernetes::Cluster::Provisioner
    PLUGINS = %w[bridge host-local loopback].freeze

    def initialize(cni_bin_dir:, descriptor:, **)
      @cni_bin_dir = File.realpath(cni_bin_dir)
      @cni_evidence = {"plugin" => "cni", "binaries" => PLUGINS.to_h { |name| [name, plugin_identity(name)] }, "node_configs" => {}}
      super(descriptor: descriptor.merge("network" => @cni_evidence), **)
      raise Rubernetes::Cluster::Error, "the external CNI K1 fixture uses the IPv4 native profile" unless families == ["ipv4"]
    end

    def write_agent_config(id, index, ...)
      path = super
      document = YAML.safe_load_file(path)
      agent = document.fetch("processes").fetch("rubernetes-agent")
      network = agent.fetch("network")
      conf_dir = File.join(root, "network", id, "cni")
      FileUtils.mkdir_p(conf_dir)
      gateway = node_advertise_addresses(index).fetch(0)
      subnet = "#{IPAddr.new(pod_cidr(index, "ipv4"))}/24"
      bridge = network.fetch("bridge_name")
      prepare_dns_address(bridge, gateway)
      config = {
        "cniVersion" => "1.0.0", "name" => "external-#{id}",
        "plugins" => [{"type" => "bridge", "bridge" => bridge, "isDefaultGateway" => true, "isGateway" => true,
                       "ipam" => {"type" => "host-local", "dataDir" => File.join(conf_dir, "ipam"),
                                  "ranges" => [[{"subnet" => subnet, "gateway" => gateway}]]}}]
      }
      conflist = File.join(conf_dir, "10-reference.conflist")
      File.write(conflist, "#{JSON.pretty_generate(config)}\n")
      network["plugin"] = "cni"
      network["cni"] = {"conf_dir" => conf_dir, "bin_dirs" => [@cni_bin_dir]}
      # The external bridge owns the Pod addresses. DNS binds to its gateway
      # before the first CNI ADD and ClusterFirst Pods use that address.
      (agent["dns"] ||= {}).merge!("bind_addresses" => [gateway], "cluster_dns" => [gateway])
      File.write(path, YAML.dump(document))
      @cni_evidence.fetch("node_configs")[id] = {"path" => conflist, "sha256" => Digest::SHA256.file(conflist).hexdigest}
      path
    end

    private

    def prepare_dns_address(bridge, address)
      system("ip", "link", "add", bridge, "type", "bridge", exception: true)
      system("ip", "addr", "add", "#{address}/24", "dev", bridge, exception: true)
      system("ip", "link", "set", bridge, "up", exception: true)
    end

    def plugin_identity(name)
      path = File.realpath(File.join(@cni_bin_dir, name))
      version, status = Open3.capture2e(path, "--version")
      unless status.success? && version.include?("CNI protocol versions supported:")
        raise Rubernetes::Cluster::Error, "could not identify the external #{name} CNI plugin"
      end

      {"path" => path, "version" => version.lines.first.strip, "sha256" => Digest::SHA256.file(path).hexdigest}
    end
  end
end
