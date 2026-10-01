# frozen_string_literal: true

require "fileutils"
require "ipaddr"

require_relative "status"
require_relative "pod_hostname"

module Rubernetes
  module Node
    # The Pod-level files kubelet manages on the host and bind-mounts into
    # every container: /etc/hosts (managed hosts file with hostAliases),
    # /etc/hostname and /etc/resolv.conf built from dnsPolicy/dnsConfig.
    class PodFiles
      class Error < StandardError; end

      DNS_POLICIES = %w[ClusterFirst ClusterFirstWithHostNet Default None].freeze
      # kubelet: resolv.conf limits (pkg/kubelet/network/dns)
      MAX_SEARCH_DOMAINS = 32
      MAX_SEARCH_CHARS = 2048
      MAX_NAMESERVERS = 3
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
      def write(pod, directory:, pod_ips: [], host_network: false, hostname: nil)
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
        atomic_write(resolv_path, resolv_conf_content(object, host_network: host_network))
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

      # pkg/kubelet/network/dns.GetPodDNS
      def resolv_conf_content(pod, host_network:)
        spec = Helpers.key(pod, "spec", {})
        policy = Helpers.key(spec, "dnsPolicy", "ClusterFirst").to_s
        raise Error, "unsupported dnsPolicy #{policy.inspect}" unless DNS_POLICIES.include?(policy)

        namespace = Helpers.key(Helpers.key(pod, "metadata", {}), "namespace", "default").to_s
        effective = policy
        effective = "Default" if policy == "ClusterFirst" && host_network
        nameservers, searches, options = case effective
                                         when "None" then [[], [], []]
                                         when "Default" then host_dns
                                         else cluster_dns_config(namespace)
                                         end
        config = Helpers.key(spec, "dnsConfig", nil)
        if config
          nameservers += Array(Helpers.key(config, "nameservers", [])).map(&:to_s)
          searches += Array(Helpers.key(config, "searches", [])).map(&:to_s)
          Array(Helpers.key(config, "options", [])).each do |option|
            item = Helpers.string_keys(option)
            name = Helpers.key(item, "name", "").to_s
            next if name.empty?

            value = Helpers.key(item, "value", nil)
            options.reject! { |existing| existing.split(":").first == name }
            options << (value.nil? ? name : "#{name}:#{value}")
          end
        end
        nameservers = nameservers.uniq
        searches = searches.uniq
        raise Error, "dnsPolicy None requires dnsConfig.nameservers" if nameservers.empty? && effective == "None"

        format_resolv_conf(nameservers, searches, options)
      end

      def cluster_dns_config(namespace)
        if @cluster_dns.empty?
          raise Error,
                "dnsPolicy ClusterFirst requires the node's cluster DNS address (rubernetes-agent.dns.cluster_dns)"
        end

        host_nameservers, host_searches, host_options = host_dns
        searches = ["#{namespace}.svc.#{@cluster_domain}", "svc.#{@cluster_domain}", @cluster_domain]
        searches += host_searches.reject { |domain| searches.include?(domain) }
        options = ["ndots:5"] + host_options.reject { |option| option.start_with?("ndots") }
        _ = host_nameservers
        [@cluster_dns.dup, searches, options]
      end

      RESOLVED_UPSTREAM_FILE = "/run/systemd/resolve/resolv.conf"

      # kubelet: with a systemd-resolved stub (127.0.0.53) in /etc/resolv.conf
      # the real upstream file is the one Pods must inherit.
      def host_dns
        source = @resolv_conf
        if File.file?(source)
          servers = File.foreach(source).filter_map do |line|
            f = line.sub(/[#;].*/, "").split
            f[1] if f.first == "nameserver"
          end
          source = RESOLVED_UPSTREAM_FILE if !servers.empty? && servers.all? do |server|
            server.start_with?("127.") || server == "::1"
          end && File.file?(RESOLVED_UPSTREAM_FILE)
        end
        return [[], [], []] unless File.file?(source)

        nameservers = []
        searches = []
        options = []
        File.foreach(source) do |line|
          fields = line.sub(/[#;].*/, "").split
          next if fields.empty?

          case fields.first
          when "nameserver" then nameservers << fields[1] if fields[1]
          when "search" then searches = fields[1..]
          when "domain" then searches = [fields[1]] if searches.empty? && fields[1]
          when "options" then options += fields[1..]
          end
        end
        # 127.0.0.53-style local stub resolvers are unreachable from a Pod
        # network namespace; kubelet expects --resolv-conf to point at a
        # reachable file and so do we, but a loopback-only host file would
        # otherwise produce a Pod that can resolve nothing.
        [nameservers, searches, options]
      rescue SystemCallError
        [[], [], []]
      end

      def format_resolv_conf(nameservers, searches, options)
        lines = nameservers.first(MAX_NAMESERVERS).map { |server| "nameserver #{server}" }
        trimmed = []
        total = 0
        searches.each do |domain|
          break if trimmed.length >= MAX_SEARCH_DOMAINS
          break if total + domain.length + 1 > MAX_SEARCH_CHARS

          trimmed << domain
          total += domain.length + 1
        end
        lines << "search #{trimmed.join(" ")}" unless trimmed.empty?
        lines << "options #{options.join(" ")}" unless options.empty?
        "#{lines.join("\n")}\n"
      end

      def pod_hostname(pod) = PodHostname.generate(pod, cluster_domain: @cluster_domain).first

      # `<subdomain>.<namespace>.svc.<cluster domain>` when spec.subdomain is
      # set (none with hostnameOverride).
      def pod_domain(pod) = PodHostname.generate(pod, cluster_domain: @cluster_domain).last

      private

      def atomic_write(path, content)
        temporary = "#{path}.tmp-#{Process.pid}"
        File.open(temporary, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |file|
          file.write(content)
          file.flush
        end
        File.rename(temporary, path)
      rescue SystemCallError => error
        raise Error, "failed to write #{path}: #{error.message}"
      end
    end
  end
end
