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
      EGRESS_CHAIN = "RUBERNETES-POSTROUTING"
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
        end
        %w[iptables ip6tables].each do |binary|
          family = list.select { |cidr| cidr.include?(":") == (binary == "ip6tables") }
          next if family.empty?

          ensure_masquerade!(binary, family, installed, present, skipped)
        end
        log(installed, present, skipped)
        Result.new(installed: installed, already_present: present, skipped: skipped)
      end

      private

      # The bridge CNI plugin's ipMasq, in its shape: one chain per family
      # (iptables takes a single -d per rule, so each exclusion is a rule of
      # its own) that accepts cluster-internal and multicast destinations and
      # masquerades the rest, entered from POSTROUTING for each Pod CIDR.
      # Without it a Pod reaches the host and other Pods but nothing beyond
      # (its address is not routable upstream): cert-manager registering an
      # ACME account timed out without a trace (2026-10-01).
      def ensure_masquerade!(binary, cidrs, installed, present, skipped)
        nat = ["-t", "nat"]
        unless invoke(binary, *nat, "-S", EGRESS_CHAIN) || invoke(binary, *nat, "-N", EGRESS_CHAIN)
          cidrs.each { |cidr| skipped << [binary, "masquerade", cidr] }
          return
        end
        multicast = binary == "ip6tables" ? "ff00::/8" : "224.0.0.0/4"
        chain_rules = cidrs.map { |cidr| [EGRESS_CHAIN, "-d", cidr, "-j", "ACCEPT"] }
        chain_rules << [EGRESS_CHAIN, "-d", multicast, "-j", "ACCEPT"]
        chain_rules << [EGRESS_CHAIN, "-m", "comment", "--comment", MASQUERADE_COMMENT, "-j", "MASQUERADE"]
        chain_rules.each do |rule|
          next if invoke(binary, *nat, "-C", *rule)

          invoke(binary, *nat, "-A", *rule)
        end
        cidrs.each do |cidr|
          jump = [NAT_CHAIN, "-s", cidr, "-m", "comment", "--comment", MASQUERADE_COMMENT, "-j", EGRESS_CHAIN]
          if invoke(binary, *nat, "-C", *jump)
            present << [binary, "masquerade", cidr]
          elsif invoke(binary, *nat, "-A", *jump)
            installed << [binary, "masquerade", cidr]
          else
            skipped << [binary, "masquerade", cidr]
          end
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
