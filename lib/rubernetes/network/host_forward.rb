# frozen_string_literal: true

require "open3"

module Rubernetes
  module Network
    # Permits forwarding for the cluster's Pod CIDRs on the host.
    #
    # A Pod network is only as good as the host's forwarding path.  Where
    # another Kubernetes, a container runtime or a firewall has set the
    # filter FORWARD policy to DROP -- which is the common case, and the case
    # on any host already running a cluster -- every packet between Pods on
    # different nodes is discarded.  Nothing reports it: the Pod is Running,
    # the route is present, and the connection simply times out.
    #
    # A verdict in another netfilter table cannot rescue such a packet: each
    # registered hook is consulted and a DROP anywhere wins.  The accept has
    # to live in the chain that drops, which is why every CNI implementation
    # installs this same pair of rules.  They are scoped to the cluster's own
    # Pod CIDRs, inserted at the head of the chain, and applied only when they
    # are not already there.
    class HostForward
      CHAIN = "FORWARD"

      Result = Struct.new(:installed, :already_present, :skipped, keyword_init: true)

      def initialize(runner: nil, logger: nil)
        @runner = runner || method(:run_command)
        @logger = logger
      end

      # `cidrs` are the cluster Pod CIDRs (v4 and v6 both welcome).
      BRIDGE_NETFILTER_SYSCTLS = %w[/proc/sys/net/bridge/bridge-nf-call-iptables /proc/sys/net/bridge/bridge-nf-call-ip6tables].freeze

      # kube-proxy requires br_netfilter: a Service reply from a Pod on the
      # same bridge is switched at L2 and never reaches the nat hooks, so the
      # DNAT is never reversed and the client sees a SYN-ACK from the Pod IP
      # (and resets).  Every CNI bridge plugin turns this on.
      def ensure_bridge_netfilter!
        system("modprobe", "br_netfilter", out: File::NULL, err: File::NULL) unless File.exist?(BRIDGE_NETFILTER_SYSCTLS.first)
        BRIDGE_NETFILTER_SYSCTLS.each do |path|
          next unless File.exist?(path)

          File.write(path, "1\n") unless File.read(path).strip == "1"
        end
        true
      rescue SystemCallError => error
        @logger&.warn("network.bridge_netfilter_failed", error: error.message) if @logger.respond_to?(:warn)
        false
      end

      NAT_CHAIN = "POSTROUTING"
      MASQUERADE_COMMENT = "rubernetes pod egress"

      def ensure!(cidrs)
        ensure_bridge_netfilter!
        installed = []
        present = []
        skipped = []
        list = Array(cidrs).map(&:to_s).reject(&:empty?).uniq
        list.each do |cidr|
          binary = cidr.include?(":") ? "ip6tables" : "iptables"
          %w[-s -d].each do |direction|
            arguments = [CHAIN, direction, cidr, "-j", "ACCEPT"]
            if invoke(binary, "-C", *arguments)
              present << [binary, direction, cidr]
            elsif invoke(binary, "-I", CHAIN, "1", direction, cidr, "-j", "ACCEPT")
              installed << [binary, direction, cidr]
            else
              # A host without the binary, or one that refuses the rule, is
              # reported rather than failing the node: a single-node cluster
              # forwards nothing and works regardless.
              skipped << [binary, direction, cidr]
            end
          end
          ensure_masquerade!(binary, cidr, list, installed, present, skipped)
        end
        log(installed, present, skipped)
        Result.new(installed: installed, already_present: present, skipped: skipped)
      end

      private

      # The bridge CNI plugin's ipMasq: traffic from the Pod CIDR to anything
      # outside the cluster leaves with the node's address.  Without it a Pod
      # reaches the host and other Pods but nothing beyond (its address is
      # not routable upstream), and an HTTPS call from a Pod to the internet
      # -- cert-manager registering an ACME account, 2026-10-01 -- times out
      # without a trace.  Cluster-internal and multicast destinations are
      # excluded, as the plugin does.
      def ensure_masquerade!(binary, cidr, cluster_cidrs, installed, present, skipped)
        rule = [NAT_CHAIN, "-s", cidr]
        cluster_cidrs.select { |other| other.include?(":") == cidr.include?(":") }.each { |other| rule += ["!", "-d", other] }
        unless cluster_cidrs.include?(cidr.include?(":") ? "ff00::/8" : "224.0.0.0/4")
          rule += ["!", "-d",
                   cidr.include?(":") ? "ff00::/8" : "224.0.0.0/4"]
        end
        rule += ["-m", "comment", "--comment", MASQUERADE_COMMENT, "-j", "MASQUERADE"]
        if invoke(binary, "-t", "nat", "-C", *rule)
          present << [binary, "masquerade", cidr]
        elsif invoke(binary, "-t", "nat", "-A", *rule)
          installed << [binary, "masquerade", cidr]
        else
          skipped << [binary, "masquerade", cidr]
        end
      end

      def invoke(binary, *)
        @runner.call(binary, *)
      end

      def run_command(binary, *)
        _out, _err, status = Open3.capture3(binary, *)
        status.success?
      rescue Errno::ENOENT, Errno::EACCES
        false
      end

      def log(installed, present, skipped)
        return unless @logger.respond_to?(:info)

        @logger.info("network.host_forward",
                     installed: installed.length, already_present: present.length, skipped: skipped.length)
      end
    end
  end
end
