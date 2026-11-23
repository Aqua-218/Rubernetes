# frozen_string_literal: true

require "fileutils"
require "ipaddr"
require "tempfile"

require_relative "status"
require_relative "pod_dns"
require_relative "pod_hostname"

module Rubernetes
  module Node
    # The Pod-level files kubelet manages on the host and bind-mounts into
    # every container: /etc/hosts (managed hosts file with hostAliases),
    # /etc/hostname and /etc/resolv.conf built from dnsPolicy/dnsConfig.
    class PodFiles
      class Error < StandardError; end

      include PodDNS

      MANAGED_HEADER = "# Kubernetes-managed hosts file.\n"

      def initialize(cluster_dns: [], cluster_domain: "cluster.local", resolv_conf: "/etc/resolv.conf",
                     node_hosts: "/etc/hosts")
        @cluster_dns = Array(cluster_dns).map(&:to_s).reject(&:empty?)
        @cluster_domain = cluster_domain.to_s.delete_suffix(".")
        @resolv_conf = resolv_conf
        @node_hosts = node_hosts
      end

      attr_reader :cluster_dns, :cluster_domain

      # Writes the files under `directory` and returns {container path =>
      # host path} for the container mounts.
      def write(pod, directory:, pod_ips: [], host_network: false, hostname: nil, dns_config: nil)
        object = Helpers.string_keys(pod)
        FileUtils.mkdir_p(directory)
        files = {}
        hosts_path = File.join(directory, "hosts")
        atomic_write(hosts_path, hosts_content(object, pod_ips: pod_ips, host_network: host_network, hostname: hostname))
        files["/etc/hosts"] = hosts_path
        hostname_path = File.join(directory, "hostname")
        atomic_write(hostname_path, "#{hostname || PodHostname.kernel_hostname(object, cluster_domain: @cluster_domain)}\n")
        files["/etc/hostname"] = hostname_path
        resolv_path = File.join(directory, "resolv.conf")
        config = dns_config || self.dns_config(object, host_network: host_network)
        atomic_write(resolv_path, format_resolv_conf(config))
        files["/etc/resolv.conf"] = resolv_path
        files
      end

      # kubelet managedHostsFileContent / nodeHostsFileContent.
      def hosts_content(pod, pod_ips:, host_network:, hostname: nil)
        spec = Helpers.key(pod, "spec", {})
        aliases = Array(Helpers.key(spec, "hostAliases", []))
        if host_network
          content = File.file?(@node_hosts) ? File.read(@node_hosts) : "127.0.0.1\tlocalhost\n"
          content = content.dup
          content << "\n" unless content.end_with?("\n")
          content << host_aliases_content(aliases)
          return content
        end

        # The short name and the domain (upstream managedHostsFileContent);
        # +hostname+, the UTS name, may be the FQDN.
        name = pod_hostname(pod)
        domain = pod_domain(pod)
        fqdn = domain.empty? ? name : "#{name}.#{domain}"
        content = +MANAGED_HEADER
        content << "127.0.0.1\tlocalhost\n"
        content << "::1\tlocalhost ip6-localhost ip6-loopback\n"
        content << "fe00::0\tip6-localnet\n"
        content << "fe00::0\tip6-mcastprefix\n"
        content << "fe00::1\tip6-allnodes\n"
        content << "fe00::2\tip6-allrouters\n"
        Array(pod_ips).each do |ip|
          entry = fqdn == name ? name : "#{fqdn}\t#{name}"
          content << "#{ip}\t#{entry}\n"
        end
        content << host_aliases_content(aliases)
        content
      end

      def host_aliases_content(aliases)
        return "" if aliases.empty?

        content = +"\n# Entries added by HostAliases.\n"
        aliases.each do |entry|
          item = Helpers.string_keys(entry)
          ip = Helpers.key(item, "ip", "").to_s
          hostnames = Array(Helpers.key(item, "hostnames", [])).map(&:to_s)
          next if ip.empty? || hostnames.empty?

          content << "#{ip}\t#{hostnames.join("\t")}\n"
        end
        content
      end

      def pod_hostname(pod) = PodHostname.generate(pod, cluster_domain: @cluster_domain).first

      # `<subdomain>.<namespace>.svc.<cluster domain>` when spec.subdomain is
      # set (none with hostnameOverride).
      def pod_domain(pod) = PodHostname.generate(pod, cluster_domain: @cluster_domain).last

      private

      def atomic_write(path, content)
        Tempfile.create(".#{File.basename(path)}", File.dirname(path)) do |file|
          file.write(content)
          file.chmod(0o644)
          file.flush
          File.rename(file.path, path)
        end
      rescue SystemCallError => error
        raise Error, "failed to write #{path}: #{error.message}"
      end
    end
  end
end
