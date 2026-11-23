# frozen_string_literal: true

module Rubernetes
  module Node
    # The kubelet computes DNS once for RunPodSandbox and the managed resolv.conf.
    module PodDNS
      MAX_SEARCH_DOMAINS = 32
      MAX_SEARCH_CHARS = 2048
      MAX_NAMESERVERS = 3
      MAX_RESOLV_BYTES = 10 << 20
      RESOLVED_UPSTREAM_FILE = "/run/systemd/resolve/resolv.conf"
      MISSING_CLUSTER_DNS = 'kubelet does not have ClusterDNS IP configured and cannot create Pod using "ClusterFirst" ' \
                            'policy. Falling back to "Default" policy.'

      def dns_config(pod, host_network:, node_ips: [], &warning)
        spec = Helpers.key(pod, "spec", {})
        metadata = Helpers.key(pod, "metadata", {})
        config = base_dns(metadata, Helpers.key(spec, "dnsPolicy", "ClusterFirst"), host_network, node_ips, &warning)
        overrides = Helpers.key(spec, "dnsConfig", nil)
        if overrides
          config["servers"] = (config["servers"] + Array(Helpers.key(overrides, "nameservers", []))).uniq
          config["searches"] = (config["searches"] + Array(Helpers.key(overrides, "searches", []))).uniq
          options = config["options"].to_h do |item|
            name, _, value = item.partition(":")
            [name, value]
          end
          Array(Helpers.key(overrides, "options", [])).each do |option|
            options[Helpers.key(option, "name")] = Helpers.key(option, "value", nil).to_s
          end
          config["options"] = options.map { |name, value| value.empty? ? name : "#{name}:#{value}" }
        end
        limit_dns(config, &warning)
      end

      def resolv_conf_content(pod, host_network:, node_ips: [])
        format_resolv_conf(dns_config(pod, host_network: host_network, node_ips: node_ips))
      end

      private

      def base_dns(metadata, policy, host_network, node_ips, &warning)
        host = host_dns
        return {"servers" => [], "searches" => [], "options" => []} if policy == "None"

        unless policy == "Default" || (policy == "ClusterFirst" && host_network)
          namespace = Helpers.key(metadata, "namespace", "default")
          unless @cluster_dns.empty?
            searches = host["searches"]
            searches = (["#{namespace}.svc.#{@cluster_domain}", "svc.#{@cluster_domain}", @cluster_domain] + searches).uniq unless @cluster_domain.empty?
            return {"servers" => @cluster_dns.dup, "searches" => searches, "options" => ["ndots:5"]}
          end
          warning&.call("Node", "MissingClusterDNS", MISSING_CLUSTER_DNS)
          reference = "#{Helpers.key(metadata, "name")}_#{namespace}(#{Helpers.key(metadata, "uid")})"
          warning&.call("Pod", "MissingClusterDNS", "pod: #{reference.inspect}. #{MISSING_CLUSTER_DNS}")
        end
        if @resolv_conf == ""
          host["servers"] = node_ips.map { |ip| ip.include?(":") ? "::1" : "127.0.0.1" }
          host["servers"] << "127.0.0.1" if host["servers"].empty?
          host["searches"] = ["."]
        end
        host
      end

      def host_dns
        return {"servers" => [], "searches" => [], "options" => []} if @resolv_conf == ""

        config = read_resolver(@resolv_conf)
        # The default host path can point at systemd-resolved's node-local stub.
        # An explicitly selected resolver file is authoritative.
        servers = config["servers"]
        if @resolv_conf == "/etc/resolv.conf" && !servers.empty? && servers.all? { |ip| ip.start_with?("127.") || ip == "::1" } &&
           File.file?(RESOLVED_UPSTREAM_FILE)
          return read_resolver(RESOLVED_UPSTREAM_FILE)
        end

        config
      rescue SystemCallError => error
        raise PodFiles::Error, "could not read resolver configuration: #{error.message}"
      end

      def read_resolver(path)
        content = File.binread(path, MAX_RESOLV_BYTES + 1).to_s
        raise PodFiles::Error, "#{path} exceeds #{MAX_RESOLV_BYTES} bytes" if content.bytesize > MAX_RESOLV_BYTES

        servers = []
        searches = []
        options = {}
        content.each_line do |line|
          directive, *fields = line.split
          case directive
          when "nameserver"
            raise PodFiles::Error, "#{path}: nameserver list is empty" if fields.empty?

            servers << fields.first
          when "search"
            searches = fields.filter_map { |domain| domain.delete_suffix(".") unless domain == "." }
          when "options"
            fields.each { |option| options[option.partition(":").first] = option }
          end
        end
        {"servers" => servers, "searches" => searches, "options" => options.values}
      end

      def limit_dns(config, &warning)
        servers = config["servers"]
        if servers.size > MAX_NAMESERVERS
          config["servers"] = servers.first(MAX_NAMESERVERS)
          warning&.call("Pod", "DNSConfigForming", "Nameserver limits were exceeded, some nameservers have been omitted, " \
                                                   "the applied nameserver line is: #{config["servers"].join(" ")}")
        end
        searches = config["searches"]
        limited = searches.first(MAX_SEARCH_DOMAINS).reject { |s| s.bytesize > 253 }
        limited.pop while limited.join(" ").bytesize > MAX_SEARCH_CHARS
        if limited.size != searches.size
          config["searches"] = limited
          warning&.call("Pod", "DNSConfigForming", "Search Line limits were exceeded, some search paths have been omitted, " \
                                                   "the applied search line is: #{limited.join(" ")}")
        end
        config
      end

      def format_resolv_conf(config)
        lines = config.fetch("servers").map { |server| "nameserver #{server}" }
        searches = config.fetch("searches")
        options = config.fetch("options")
        lines << "search #{searches.join(" ")}" unless searches.empty?
        lines << "options #{options.join(" ")}" unless options.empty?
        "#{lines.join("\n")}\n"
      end
    end
  end
end
