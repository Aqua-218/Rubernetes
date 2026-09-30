# frozen_string_literal: true

require "open3"

module Rubernetes
  module Network
    # containerPort.hostPort: the node must publish the container's port on the
    # node's own address.  The field was validated by the API server and used
    # by the scheduler's NodePorts filter, but nothing ever programmed the
    # mapping, so a Pod with a hostPort was scheduled and then unreachable --
    # "[sig-network] HostPort validates that there is no conflict between pods
    # with same hostPort but different hostIP and protocol" fails with
    # "Failed to connect to exposed host ports".
    #
    # kubelet's hostport manager installs, in the nat table:
    #   PREROUTING/OUTPUT -> KUBE-HOSTPORTS
    #   KUBE-HOSTPORTS: -p <proto> [-d <hostIP>] --dport <hostPort>
    #                   -j DNAT --to-destination <podIP>:<containerPort>
    # plus a hairpin MASQUERADE so a Pod reaching itself through the host port
    # gets a reply it accepts.  Every rule carries a comment naming the Pod, so
    # removal is exact and a restart cannot orphan another Pod's rule.
    class HostPort
      CHAIN = "KUBE-HOSTPORTS"
      HOOKS = %w[PREROUTING OUTPUT].freeze
      COMMENT_PREFIX = "rubernetes hostport"

      Mapping = Struct.new(:host_ip, :host_port, :container_port, :protocol, keyword_init: true)

      def initialize(runner: nil, logger: nil)
        @runner = runner || method(:run_command)
        @logger = logger
        @mutex = Mutex.new
      end

      # Every hostPort a Pod spec asks for, in the order kubelet would see them.
      def self.mappings_for(pod)
        spec = pod.is_a?(Hash) ? (pod["spec"] || pod[:spec] || {}) : {}
        containers = Array(spec["containers"] || spec[:containers]) +
                     Array(spec["initContainers"] || spec[:initContainers])
        containers.flat_map do |container|
          container = {} unless container.is_a?(Hash)
          Array(container["ports"] || container[:ports]).filter_map do |port|
            port = {} unless port.is_a?(Hash)
            host_port = port["hostPort"] || port[:hostPort]
            next nil if host_port.nil? || Integer(host_port).zero?

            container_port = port["containerPort"] || port[:containerPort] || host_port
            protocol = (port["protocol"] || port[:protocol] || "TCP").to_s.downcase
            next nil unless %w[tcp udp].include?(protocol)

            Mapping.new(host_ip: (port["hostIP"] || port[:hostIP]).to_s,
                        host_port: Integer(host_port),
                        container_port: Integer(container_port),
                        protocol: protocol)
          end
        end
      end

      def ensure!(pod_uid:, pod_ip:, pod:, family: :ipv4)
        mappings = self.class.mappings_for(pod)
        return [] if mappings.empty? || pod_ip.to_s.empty?

        binary = binary_for(family)
        @mutex.synchronize do
          ensure_chain!(binary)
          mappings.filter_map { |mapping| install(binary, pod_uid, pod_ip, mapping) }
        end
      end

      # Remove every rule tagged with this Pod, whatever it maps.
      def remove!(pod_uid:, family: :ipv4)
        binary = binary_for(family)
        comment = comment_for(pod_uid)
        removed = 0
        @mutex.synchronize do
          loop do
            rule = find_rule(binary, comment)
            break unless rule

            break unless invoke(binary, "-t", "nat", "-D", CHAIN, *rule)

            removed += 1
          end
        end
        removed
      end

      private

      def binary_for(family)
        family.to_s == "ipv6" ? "ip6tables" : "iptables"
      end

      def comment_for(pod_uid)
        "#{COMMENT_PREFIX} #{pod_uid}"
      end

      # The chain and its hooks are created once and left in place; a hook that
      # is already there must not be duplicated on every Pod.
      def ensure_chain!(binary)
        invoke(binary, "-t", "nat", "-N", CHAIN)
        HOOKS.each do |hook|
          arguments = [hook, "-m", "addrtype", "--dst-type", "LOCAL", "-j", CHAIN]
          next if invoke(binary, "-t", "nat", "-C", *arguments)

          invoke(binary, "-t", "nat", "-I", *arguments)
        end
      end

      def install(binary, pod_uid, pod_ip, mapping)
        rule = rule_arguments(pod_uid, pod_ip, mapping)
        return nil if invoke(binary, "-t", "nat", "-C", CHAIN, *rule)
        return nil unless invoke(binary, "-t", "nat", "-A", CHAIN, *rule)

        hairpin = hairpin_arguments(pod_uid, pod_ip, mapping)
        invoke(binary, "-t", "nat", "-A", CHAIN, *hairpin) unless invoke(binary, "-t", "nat", "-C", CHAIN, *hairpin)
        mapping
      end

      def rule_arguments(pod_uid, pod_ip, mapping)
        arguments = ["-p", mapping.protocol]
        arguments += ["-d", mapping.host_ip] unless mapping.host_ip.to_s.empty?
        arguments += ["--dport", mapping.host_port.to_s,
                      "-m", "comment", "--comment", comment_for(pod_uid),
                      "-j", "DNAT", "--to-destination", destination(pod_ip, mapping.container_port)]
        arguments
      end

      # A Pod that reaches its own published port must see the node, not
      # itself, as the source, or it drops the reply.
      def hairpin_arguments(pod_uid, pod_ip, mapping)
        ["-p", mapping.protocol, "-s", pod_ip.to_s, "-d", pod_ip.to_s,
         "--dport", mapping.container_port.to_s,
         "-m", "comment", "--comment", comment_for(pod_uid),
         "-j", "MASQUERADE"]
      end

      def destination(pod_ip, container_port)
        pod_ip.to_s.include?(":") ? "[#{pod_ip}]:#{container_port}" : "#{pod_ip}:#{container_port}"
      end

      # iptables has no "delete by comment", so the chain is listed and the
      # first rule carrying the comment is rebuilt into delete arguments.
      def find_rule(binary, comment)
        output = capture(binary, "-t", "nat", "-S", CHAIN)
        return nil if output.nil?

        line = output.lines.find { |candidate| candidate.include?(comment) && candidate.start_with?("-A #{CHAIN} ") }
        return nil unless line

        tokens = split_rule(line.strip.sub("-A #{CHAIN} ", ""))
        tokens.empty? ? nil : tokens
      end

      # iptables -S quotes the comment; split respecting those quotes.
      def split_rule(value)
        value.scan(/"[^"]*"|\S+/).map { |token| token.start_with?('"') ? token[1..-2] : token }
      end

      def invoke(binary, *)
        @runner.call(binary, *)
      end

      def capture(binary, *)
        out, _err, status = Open3.capture3(binary, *)
        status.success? ? out : nil
      rescue Errno::ENOENT, Errno::EACCES
        nil
      end

      def run_command(binary, *)
        _out, _err, status = Open3.capture3(binary, *)
        status.success?
      rescue Errno::ENOENT, Errno::EACCES
        false
      end
    end
  end
end
