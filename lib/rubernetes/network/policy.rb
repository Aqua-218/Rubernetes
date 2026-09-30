# frozen_string_literal: true

require "ipaddr"
require "socket"

require_relative "errors"
require_relative "support"

module Rubernetes
  module Network
    # Kubernetes label selector with the matchLabels/matchExpressions
    # semantics needed by NetworkPolicy.  Invalid operators are rejected
    # before an atomic policy revision can reach the dataplane.
    class Selector
      Requirement = Struct.new(:key, :operator, :values, keyword_init: true)

      OPERATORS = %w[In NotIn Exists DoesNotExist].freeze

      def initialize(value = {})
        hash = value.respond_to?(:to_h) ? value.to_h : value
        raise PolicyError, "selector must be an object" unless hash.is_a?(Hash)

        @requirements = []
        labels = Support.fetch(hash, "matchLabels", "match_labels", default: {})
        raise PolicyError, "matchLabels must be an object" unless labels.is_a?(Hash)

        labels.each { |key, label| @requirements << Requirement.new(key: valid_key(key), operator: "In", values: [String(label)]) }
        expressions = Support.fetch(hash, "matchExpressions", "match_expressions", default: [])
        raise PolicyError, "matchExpressions must be an array" unless expressions.is_a?(Array)

        expressions.each do |expression|
          entry = expression.respond_to?(:to_h) ? expression.to_h : expression
          operator = String(Support.fetch(entry, "operator"))
          raise PolicyError, "unsupported selector operator #{operator.inspect}" unless OPERATORS.include?(operator)

          key = valid_key(Support.fetch(entry, "key"))
          values = Array(Support.fetch(entry, "values", default: [])).map(&:to_s)
          raise PolicyError, "selector #{operator} requires at least one value" if %w[In NotIn].include?(operator) && values.empty?
          raise PolicyError, "selector #{operator} must not include values" if %w[Exists DoesNotExist].include?(operator) && !values.empty?

          @requirements << Requirement.new(key: key, operator: operator, values: values.freeze)
        end
        @requirements.freeze
      end

      def matches?(labels)
        value = labels.respond_to?(:to_h) ? labels.to_h : labels
        raise PolicyError, "labels must be an object" unless value.nil? || value.is_a?(Hash)

        values = (value || {}).transform_keys(&:to_s).transform_values(&:to_s)
        @requirements.all? do |requirement|
          present = values.key?(requirement.key)
          case requirement.operator
          when "In" then present && requirement.values.include?(values.fetch(requirement.key))
          when "NotIn" then !present || !requirement.values.include?(values.fetch(requirement.key))
          when "Exists" then present
          when "DoesNotExist" then !present
          else false
          end
        end
      end

      def empty?
        @requirements.empty?
      end

      def to_h
        {"requirements" => @requirements.map do |requirement|
          {"key" => requirement.key, "operator" => requirement.operator, "values" => requirement.values}
        end}
      end

      private

      def valid_key(value)
        key = Support.string(value, "selector key")
        raise PolicyError, "selector key is too long" if key.bytesize > 253
        unless key.match?(%r{\A[a-zA-Z0-9](?:[a-zA-Z0-9_.\-/]*[a-zA-Z0-9])?\z})
          raise PolicyError,
                "selector key contains invalid characters"
        end

        key
      end
    end

    class IPBlock
      attr_reader :cidr, :except

      def initialize(value)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        cidr_text = Support.fetch(hash, "cidr")
        network, prefix = Support.cidr(cidr_text, name: "ipBlock cidr")
        @cidr = "#{network}/#{prefix}"
        @network = network
        @prefix = prefix
        @except = Array(Support.fetch(hash, "except", default: [])).map do |entry|
          except_network, except_prefix = Support.cidr(entry, name: "ipBlock except")
          raise PolicyError, "ipBlock except family does not match cidr" unless except_network.ipv4? == network.ipv4?

          bits = network.ipv4? ? 32 : 128
          network_last = network.to_i + (1 << (bits - prefix)) - 1
          except_last = except_network.to_i + (1 << (bits - except_prefix)) - 1
          raise PolicyError, "ipBlock except must be inside cidr" unless except_network.to_i >= network.to_i && except_last <= network_last

          "#{except_network}/#{except_prefix}"
        end.freeze
      rescue KeyError, ValidationError => error
        raise PolicyError, "invalid ipBlock: #{error.message}"
      end

      def include?(address)
        value = Support.ip(address, name: "policy IP")
        return false unless @network.ipv4? == value.ipv4?

        bits = @network.ipv4? ? 32 : 128
        last = @network.to_i + (1 << (bits - @prefix)) - 1
        return false unless value.to_i.between?(@network.to_i, last)

        @except.none? do |entry|
          except_network, except_prefix = Support.cidr(entry, name: "ipBlock except")
          except_last = except_network.to_i + (1 << (bits - except_prefix)) - 1
          value.to_i.between?(except_network.to_i, except_last)
        end
      end

      def to_h
        {"cidr" => @cidr, "except" => @except}
      end
    end

    PolicyRule = Struct.new(:peers, :ports, keyword_init: true) do
      def to_h
        {"peers" => peers.map do |peer|
          {
            "pod_selector" => peer["pod_selector"]&.to_h,
            "namespace_selector" => peer["namespace_selector"]&.to_h,
            "ip_block" => peer["ip_block"]&.to_h,
            "all" => peer["all"]
          }.compact
        end, "ports" => ports}
      end
    end

    PolicyRecord = Struct.new(:name, :namespace, :pod_selector, :policy_types,
                              :ingress, :egress, :generation, :metadata,
                              keyword_init: true) do
      def to_h
        {"name" => name, "namespace" => namespace, "pod_selector" => pod_selector.to_h,
         "policy_types" => policy_types, "ingress" => ingress.map(&:to_h), "egress" => egress.map(&:to_h),
         "generation" => generation, "metadata" => metadata}
      end
    end

    PolicySnapshot = Struct.new(:revision, :policies, :entries, :created_at, keyword_init: true) do
      def to_h
        {"revision" => revision, "policies" => policies.map(&:to_h), "entries" => entries, "created_at" => created_at}
      end

      def freeze
        policies.freeze
        entries.freeze
        created_at.freeze if created_at.respond_to?(:freeze)
        super
      end
    end

    # NetworkPolicy evaluator and atomic map publisher.  A complete revision
    # is built off to the side and handed to the adapter in one swap call; the
    # current revision is not replaced if the adapter rejects the update.
    class PolicyEngine
      PROTOCOLS = %w[TCP UDP SCTP].freeze
      DIRECTIONS = %w[ingress egress].freeze

      def initialize(adapter: nil, clock: -> { Time.now.utc }, revision: 0, namespace_labels: nil,
                     pod_index: nil, **_options)
        @adapter = adapter
        @clock = clock
        @mutex = Mutex.new
        @revision = Support.integer(revision, "policy revision", min: 0)
        @policies = []
        @namespace_labels = normalize_namespace_labels(namespace_labels || {})
        @pod_index = pod_index
        @snapshot = PolicySnapshot.new(revision: @revision, policies: [].freeze, entries: {}.freeze,
                                       created_at: Support.now(@clock).iso8601(6)).freeze
      end

      attr_reader :adapter

      def revision
        @mutex.synchronize { @revision }
      end

      def snapshot
        @mutex.synchronize { @snapshot }
      end

      def policies
        @mutex.synchronize { Support.immutable(@policies.map(&:to_h)) }
      end

      def apply(policies, revision: nil, namespace_labels: nil, pod_index: nil, **_options)
        policy_values = policies.is_a?(Hash) || policies.respond_to?(:metadata) ? [policies] : Array(policies)
        candidate_policies = policy_values.map { |policy| normalize_policy(policy) }
        candidate_revision = revision.nil? ? @revision + 1 : Support.integer(revision, "policy revision", min: 1)
        @mutex.synchronize do
          if candidate_revision <= @revision
            raise PolicyRevisionError,
                  "policy revision #{candidate_revision} is not newer than #{@revision}"
          end

          labels = namespace_labels ? normalize_namespace_labels(namespace_labels) : @namespace_labels
          index = pod_index.nil? ? @pod_index : pod_index
          entries = compile_entries(candidate_policies, labels: labels, pod_index: index, revision: candidate_revision)
          candidate = PolicySnapshot.new(revision: candidate_revision, policies: candidate_policies.freeze,
                                         entries: Support.immutable(entries), created_at: Support.now(@clock).iso8601(6))
          publish!(candidate)
          @policies = candidate_policies
          @namespace_labels = labels
          @pod_index = index
          @revision = candidate_revision
          @snapshot = candidate.freeze
        end
      end

      alias replace apply
      alias update apply

      # Recompile the accepted policy set for a new concrete Pod inventory.
      # Node lifecycle uses this after a network add/delete; the adapter swap
      # must succeed before the new inventory becomes visible to callers.
      def sync_pods(pod_index, revision: nil)
        candidate_revision = revision.nil? ? @revision + 1 : Support.integer(revision, "policy revision", min: 1)
        @mutex.synchronize do
          if candidate_revision <= @revision
            raise PolicyRevisionError,
                  "policy revision #{candidate_revision} is not newer than #{@revision}"
          end

          entries = compile_entries(@policies, labels: @namespace_labels, pod_index: pod_index,
                                               revision: candidate_revision)
          candidate = PolicySnapshot.new(revision: candidate_revision, policies: @policies.dup.freeze,
                                         entries: Support.immutable(entries),
                                         created_at: Support.now(@clock).iso8601(6))
          if entries.dig("kernel", "pod_index_present") == false && @adapter.respond_to?(:detach)
            @adapter.detach
          else
            publish!(candidate)
          end
          @pod_index = pod_index
          @revision = candidate_revision
          @snapshot = candidate.freeze
        end
      end

      alias replace_pod_index sync_pods

      def add(policy, revision: nil, **)
        current = @mutex.synchronize { @policies.dup }
        apply(current + [policy], revision: revision, **)
      end

      def remove(name:, namespace: nil, revision: nil, **)
        target_name = String(name)
        target_namespace = namespace && String(namespace)
        remaining = @mutex.synchronize do
          @policies.reject { |policy| policy.name == target_name && (target_namespace.nil? || policy.namespace == target_namespace) }
        end
        apply(remaining, revision: revision, **)
      end

      def allowed?(source:, destination:, direction:, protocol: "TCP", port: nil, end_port: nil,
                   namespace_labels: nil, pod_index: nil, **_options)
        direction_name = normalize_direction(direction)
        protocol_name = normalize_protocol(protocol)
        source_hash = normalize_endpoint(source)
        destination_hash = normalize_endpoint(destination)
        target = direction_name == "ingress" ? destination_hash : source_hash
        peer = direction_name == "ingress" ? source_hash : destination_hash
        @mutex.synchronize do
          selected = @policies.select do |policy|
            policy.namespace == target.fetch("namespace") &&
              policy.pod_selector.matches?(target.fetch("labels"))
          end
          direction_selected = selected.any? { |policy| policy.policy_types.include?(direction_name) }
          return true unless direction_selected

          rules = selected.select { |policy| policy.policy_types.include?(direction_name) }.flat_map do |policy|
            policy_rules = direction_name == "ingress" ? policy.ingress : policy.egress
            policy_rules.map { |rule| [policy, rule] }
          end
          return false if rules.empty?

          rules.any? do |policy, rule|
            peer_match?(rule.peers, peer, policy_namespace: policy.namespace,
                                          namespace_labels: namespace_labels || @namespace_labels,
                                          pod_index: pod_index.nil? ? @pod_index : pod_index) &&
              port_match?(rule.ports, destination_hash, protocol_name, port, end_port)
          end
        end
      rescue KeyError, ValidationError => error
        raise PolicyError, "cannot evaluate network policy: #{error.message}"
      end

      alias permits? allowed?
      alias evaluate allowed?

      # Returns the identity set for a revision.  It is useful for differential
      # tests and lets an eBPF/nftables adapter inspect the exact atomic map.
      def identity_set(revision: nil)
        current = snapshot
        raise PolicyRevisionError, "unknown policy revision #{revision}" if revision && Integer(revision) != current.revision

        current.entries
      end

      private

      def publish!(snapshot)
        return true unless @adapter

        result = if @adapter.respond_to?(:atomic_swap)
                   @adapter.atomic_swap(snapshot.to_h)
                 elsif @adapter.respond_to?(:swap)
                   @adapter.swap(snapshot.to_h)
                 elsif @adapter.respond_to?(:replace)
                   @adapter.replace(snapshot.to_h)
                 elsif @adapter.respond_to?(:call)
                   @adapter.call(snapshot.to_h)
                 else
                   raise PolicyError, "policy adapter must respond to atomic_swap, swap, replace, or call"
                 end
        raise PolicyRevisionError, "atomic policy revision #{snapshot.revision} was rejected by the adapter" if result == false

        true
      rescue PolicyError
        raise
      rescue StandardError => error
        raise PolicyRevisionError, "atomic policy revision #{snapshot.revision} was rejected: #{error.message}"
      end

      def normalize_policy(policy)
        hash = policy.respond_to?(:to_h) ? policy.to_h : policy
        spec = Support.fetch(hash, "spec", default: hash)
        metadata = Support.fetch(hash, "metadata", default: {})
        namespace = Support.string(
          Support.fetch(metadata, "namespace", default: nil) || Support.fetch(spec, "namespace", default: "default"), "policy namespace"
        )
        name = Support.string(
          Support.fetch(metadata, "name",
                        default: nil) || Support.fetch(spec, "name", default: "policy-#{Support.digest(hash)[0, 12]}"), "policy name"
        )
        selector = Selector.new(Support.fetch(spec, "podSelector", "pod_selector", default: {}))
        policy_types = Array(Support.fetch(spec, "policyTypes", "policy_types", default: nil))
        policy_types = [] if policy_types.nil?
        ingress_rules = Array(Support.fetch(spec, "ingress", default: []))
        egress_rules = Array(Support.fetch(spec, "egress", default: []))
        if policy_types.empty?
          # Kubernetes defaults an omitted policyTypes field to Ingress, and
          # adds Egress when egress rules are present.
          policy_types = ["Ingress"]
          policy_types << "Egress" unless egress_rules.empty?
        end
        policy_types = policy_types.map { |type| normalize_direction(type) }
        raise PolicyError, "network policy must select ingress or egress" if policy_types.empty?

        PolicyRecord.new(name: name, namespace: namespace, pod_selector: selector,
                         policy_types: policy_types.freeze,
                         ingress: ingress_rules.map { |rule| normalize_rule(rule, direction: "ingress") }.freeze,
                         egress: egress_rules.map { |rule| normalize_rule(rule, direction: "egress") }.freeze,
                         generation: Support.fetch(metadata, "generation", default: 0), metadata: Support.immutable(metadata)).freeze
      rescue KeyError, ValidationError => error
        raise PolicyError, "invalid NetworkPolicy: #{error.message}"
      end

      def normalize_rule(rule, direction:)
        hash = rule.respond_to?(:to_h) ? rule.to_h : rule
        peer_key = direction == "ingress" ? "from" : "to"
        peers = Array(Support.fetch(hash, peer_key, default: [])).map { |peer| normalize_peer(peer) }.freeze
        ports = Array(Support.fetch(hash, "ports", default: [])).map { |port| normalize_port(port) }.freeze
        PolicyRule.new(peers: peers, ports: ports).freeze
      end

      def normalize_peer(peer)
        hash = peer.respond_to?(:to_h) ? peer.to_h : peer
        result = {}
        if (selector = Support.fetch(hash, "podSelector", "pod_selector", default: nil))
          result["pod_selector"] = Selector.new(selector)
        end
        if (selector = Support.fetch(hash, "namespaceSelector", "namespace_selector", default: nil))
          result["namespace_selector"] = Selector.new(selector)
        end
        if (block = Support.fetch(hash, "ipBlock", "ip_block", default: nil))
          raise PolicyError, "peer cannot combine ipBlock with selectors" if result.any?

          result["ip_block"] = IPBlock.new(block)
        end
        result["all"] = true if result.empty?
        result.freeze
      end

      def normalize_port(port)
        hash = port.respond_to?(:to_h) ? port.to_h : port
        protocol = normalize_protocol(Support.fetch(hash, "protocol", default: "TCP"))
        value = Support.fetch(hash, "port", default: nil)
        end_port = Support.fetch(hash, "endPort", "end_port", default: nil)
        raise PolicyError, "network policy port is required" if value.nil?
        raise PolicyError, "endPort requires a numeric port" if end_port && !numeric_port?(value)

        start = if numeric_port?(value)
                  Support.integer(value, "network policy port", min: 1,
                                                                max: 65_535)
                else
                  Support.string(value,
                                 "named network policy port")
                end
        finish = end_port.nil? ? nil : Support.integer(end_port, "network policy endPort", min: 1, max: 65_535)
        raise PolicyError, "endPort must be greater than or equal to port" if finish && start.is_a?(Integer) && finish < start

        {"protocol" => protocol, "port" => start, "end_port" => finish}.freeze
      end

      def compile_entries(policies, labels:, pod_index:, revision:)
        pods = normalize_pod_index(pod_index)
        entries = {"revision" => revision, "default_deny" => {"ingress" => [], "egress" => []}, "identities" => [],
                   "pods" => pods, "kernel" => compile_kernel_entries(policies, labels: labels, pods: pods)}
        policies.each do |policy|
          policy.policy_types.each do |type|
            entries.fetch("default_deny").fetch(type) << {"namespace" => policy.namespace, "selector" => policy.pod_selector.to_h}
          end
          entries.fetch("identities") << {"namespace" => policy.namespace, "name" => policy.name, "selector" => policy.pod_selector.to_h,
                                          "ingress" => policy.ingress.map(&:to_h), "egress" => policy.egress.map(&:to_h)}
        end
        entries["default_deny"].each_value(&:freeze)
        Support.canonical(entries)
      end

      # Compile the same normalized policies used by the Ruby evaluator into
      # concrete IP rules. The native adapters intentionally consume only this
      # representation; they never reinterpret Kubernetes selectors on their
      # own. A missing pod index therefore produces no selector allow rule and
      # cannot accidentally become an allow-all dataplane update.
      def compile_kernel_entries(policies, labels:, pods:)
        targets = []
        rules = []
        policies.each do |policy|
          selected_targets = pods.select do |pod|
            pod.fetch("namespace") == policy.namespace && policy.pod_selector.matches?(pod.fetch("labels"))
          end
          policy.policy_types.each do |direction|
            selected_targets.each do |target|
              target.fetch("ips").each do |address|
                targets << {"direction" => direction, "ip" => address,
                            "family" => Support.address_family(address)}
              end
              policy_rules = direction == "ingress" ? policy.ingress : policy.egress
              policy_rules.each do |rule|
                peer_specs = compile_peer_specs(rule.peers, policy_namespace: policy.namespace,
                                                            namespace_labels: labels, pods: pods)
                target.fetch("ips").each do |address|
                  family = Support.address_family(address)
                  family_peers = peer_specs.select do |peer_spec|
                    peer_family = compiled_peer_family(peer_spec)
                    peer_family.nil? || peer_family == family
                  end
                  port_specs = compile_port_specs(rule.ports, direction: direction, target: target,
                                                              peer_specs: family_peers, pods: pods)
                  family_peers.each do |peer_spec|
                    port_specs.each do |port_spec|
                      rules << {"direction" => direction, "target" => address,
                                "family" => Support.address_family(address), "peer" => peer_spec,
                                "protocol" => port_spec.fetch("protocol"), "port" => port_spec["port"],
                                "end_port" => port_spec["end_port"]}
                    end
                  end
                end
              end
            end
          end
        end
        {
          "targets" => unique_kernel_targets(targets),
          "rules" => unique_kernel_rules(rules),
          "pods" => pods,
          "pod_index_present" => !pods.empty?
        }
      end

      def compiled_peer_family(peer)
        return nil if peer.fetch("kind") == "all"
        return peer.fetch("family") if peer["family"]

        network, = Support.cidr(peer.fetch("cidr"), name: "compiled policy cidr")
        Support.address_family(network)
      end

      def compile_peer_specs(peers, policy_namespace:, namespace_labels:, pods:)
        return [{"kind" => "all"}] if peers.empty?

        peers.flat_map do |peer|
          next [{"kind" => "all"}] if peer["all"]

          if (block = peer["ip_block"])
            if block.except.empty?
              [{"kind" => "cidr", "cidr" => block.cidr}]
            else
              cidr_difference(block.cidr, block.except).map { |cidr| {"kind" => "cidr", "cidr" => cidr} }
            end
          else
            selected = pods.select do |pod|
              namespace_selector = peer["namespace_selector"]
              namespace_matches = if namespace_selector
                                    labels = namespace_labels[pod.fetch("namespace")]
                                    namespace_selector_matches?(namespace_selector, labels)
                                  else
                                    pod.fetch("namespace") == policy_namespace
                                  end
              namespace_matches && (!peer["pod_selector"] || peer.fetch("pod_selector").matches?(pod.fetch("labels")))
            end
            selected.flat_map do |pod|
              pod.fetch("ips").map do |address|
                {"kind" => "pod", "ip" => address, "family" => Support.address_family(address),
                 "ports" => pod.fetch("ports")}
              end
            end
          end
        end
      end

      def compile_port_specs(ports, direction:, target:, peer_specs:, pods: [])
        return [{"protocol" => nil, "port" => nil, "end_port" => nil}] if ports.empty?

        ports.flat_map do |port|
          if port.fetch("port").is_a?(Integer)
            [{"protocol" => port.fetch("protocol"), "port" => port.fetch("port"),
              "end_port" => port.fetch("end_port")}]
          else
            candidate_pods = if direction == "ingress"
                               [target]
                             elsif peer_specs.any? { |peer| peer.fetch("kind") == "all" }
                               # An omitted egress `to` selects every
                               # destination pod.  Named ports are resolved
                               # against each selected destination pod rather
                               # than being dropped because the wildcard
                               # peer has no single port map.
                               pods.select { |candidate| Array(candidate["ips"]).any? }
                             else
                               peer_specs.filter_map { |peer| peer["ports"] && peer }
                             end
            numbers = candidate_pods.flat_map do |candidate|
              ports_for = candidate.fetch("ports", {})
              value = ports_for[port.fetch("port").to_s]
              value.nil? ? [] : [Integer(value)]
            rescue ArgumentError, TypeError
              []
            end.uniq
            numbers.map { |number| {"protocol" => port.fetch("protocol"), "port" => number, "end_port" => nil} }
          end
        end
      end

      def unique_kernel_targets(targets)
        targets.uniq { |entry| entry.values_at("direction", "ip") }.sort_by { |entry| entry.values_at("direction", "ip") }
      end

      def unique_kernel_rules(rules)
        rules.uniq do |entry|
          [entry.fetch("direction"), entry.fetch("target"), entry.fetch("peer"), entry.fetch("protocol"),
           entry.fetch("port"), entry.fetch("end_port")]
        end.sort_by do |entry|
          [entry.fetch("direction"), entry.fetch("target"), JSON.generate(entry.fetch("peer")),
           entry.fetch("protocol").to_s, entry.fetch("port").to_i, entry.fetch("end_port").to_i]
        end
      end

      def cidr_difference(cidr, exclusions)
        network, prefix = Support.cidr(cidr, name: "ipBlock cidr")
        excluded = exclusions.map { |entry| Support.cidr(entry, name: "ipBlock except") }
        bits = network.ipv4? ? 32 : 128
        output = []
        subtract_cidr_node(network.to_i, prefix, bits, excluded, output)
        if bits == 32
          output.map { |base, length| "#{IPAddr.new(base, Socket::AF_INET)}/#{length}" }
        else
          output.map { |base, length| "#{IPAddr.new(base, Socket::AF_INET6)}/#{length}" }
        end
      end

      def subtract_cidr_node(base, prefix, bits, exclusions, output)
        span = 1 << (bits - prefix)
        last = base + span - 1
        overlap = exclusions.select do |network, excluded_prefix|
          excluded_base = network.to_i
          excluded_last = excluded_base + (1 << (bits - excluded_prefix)) - 1
          excluded_base <= last && excluded_last >= base
        end
        if overlap.empty?
          output << [base, prefix]
          return
        end
        covered = overlap.any? do |network, excluded_prefix|
          excluded_base = network.to_i
          excluded_last = excluded_base + (1 << (bits - excluded_prefix)) - 1
          excluded_base <= base && excluded_last >= last
        end
        return if covered

        raise PolicyError, "ipBlock except cannot be represented" if prefix >= bits

        child_span = 1 << (bits - prefix - 1)
        subtract_cidr_node(base, prefix + 1, bits, overlap, output)
        subtract_cidr_node(base + child_span, prefix + 1, bits, overlap, output)
      end

      def normalize_pod_index(value)
        candidates = case value
                     when nil then []
                     when Array then value
                     when Hash
                       if Support.fetch(value, "pods", default: nil)
                         Array(Support.fetch(value, "pods"))
                       elsif pod_hash?(value)
                         [value]
                       else
                         value.flat_map do |key, child|
                           Array(child).map do |entry|
                             entry_hash = entry.respond_to?(:to_h) ? entry.to_h : {}
                             namespace, name = key.to_s.split("/", 2)
                             entry_hash.merge("namespace" => entry_hash["namespace"] || namespace,
                                              "name" => entry_hash["name"] || name)
                           end
                         end
                       end
                     else
                       raise PolicyError, "pod index must be an array or object"
                     end
        candidates.filter_map { |pod| normalize_pod(pod) }.uniq do |pod|
          [pod.fetch("namespace"), pod.fetch("name"), pod.fetch("ips")]
        end.sort_by { |pod| [pod.fetch("namespace"), pod.fetch("name"), pod.fetch("ips").join(",")] }
      rescue KeyError, ValidationError => error
        raise PolicyError, "invalid pod index: #{error.message}"
      end

      def pod_hash?(value)
        %w[namespace namespace_name labels pod_labels ip ips addresses ports container_ports interface].any? do |key|
          value.key?(key) || value.key?(key.to_sym)
        end
      end

      def normalize_pod(value)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        raise PolicyError, "pod index entry must be an object" unless hash.is_a?(Hash)

        namespace = String(Support.fetch(hash, "namespace", "namespace_name", default: "default"))
        name = String(Support.fetch(hash, "name", "pod_name", "uid", default: Support.digest(hash)[0, 12]))
        labels = Support.fetch(hash, "labels", "pod_labels", default: {})
        labels = labels.to_h.transform_keys(&:to_s).transform_values(&:to_s)
        addresses = Array(Support.fetch(hash, "ips", "addresses", default: nil) ||
                          Support.fetch(hash, "ip", "address", default: nil)).compact
        ips = addresses.map { |address| Support.ip(address, name: "pod IP").to_s }.uniq
        ports = normalize_pod_ports(Support.fetch(hash, "ports", "container_ports", default: {}))
        interface = Support.fetch(hash, "interface", "veth", "veth_name", default: nil)
        {"namespace" => namespace, "name" => name, "labels" => labels, "ips" => ips,
         "ports" => ports, "interface" => interface && String(interface)}
      end

      def normalize_pod_ports(value)
        entries = if value.is_a?(Array)
                    value
                  elsif value.respond_to?(:to_h)
                    value.to_h.map { |name, number| {"name" => name, "port" => number} }
                  else
                    []
                  end
        entries.each_with_object({}) do |entry, result|
          hash = entry.respond_to?(:to_h) ? entry.to_h : {}
          name = Support.fetch(hash, "name", default: nil)
          number = Support.fetch(hash, "port", "containerPort", "targetPort", default: nil)
          next if name.nil? || number.nil?

          result[String(name)] = Support.integer(number, "pod port", min: 1, max: 65_535)
        end
      rescue ArgumentError, TypeError
        {}
      end

      def peer_match?(peers, peer, policy_namespace:, namespace_labels:, pod_index:)
        return true if peers.empty?

        peers.any? do |entry|
          if (block = entry["ip_block"])
            peer.fetch("ip", nil) && block.include?(peer.fetch("ip"))
          elsif entry["all"]
            true
          else
            namespace_selector = entry["namespace_selector"]
            namespace_ok = if namespace_selector
                             labels = namespace_labels[peer.fetch("namespace")]
                             namespace_selector_matches?(namespace_selector, labels)
                           else
                             peer.fetch("namespace") == policy_namespace
                           end
            pod_ok = !entry["pod_selector"] || entry.fetch("pod_selector").matches?(peer.fetch("labels"))
            namespace_ok && pod_ok
          end
        end
      end

      def namespace_selector_matches?(selector, labels)
        return true if selector.empty?
        return false if labels.nil?

        selector.matches?(labels)
      end

      def port_match?(ports, destination, protocol, port, _end_port)
        return true if ports.empty?

        destination_ports = normalize_destination_ports(destination.fetch("ports", {}))
        actual_port = if port.nil?
                        nil
                      elsif numeric_port?(port)
                        Integer(port)
                      else
                        destination_ports[port.to_s] || port.to_s
                      end
        ports.any? do |rule|
          next false unless rule.fetch("protocol") == protocol

          if rule.fetch("port").is_a?(Integer)
            next false if actual_port.nil? || !numeric_port?(actual_port)

            value = Integer(actual_port)
            upper = rule.fetch("end_port") || rule.fetch("port")
            next value.between?(rule.fetch("port"), upper)
          end
          named_value = destination_ports[rule.fetch("port")]
          next false if named_value.nil? || actual_port.nil?
          next false if actual_port && actual_port.to_i != named_value.to_i && actual_port.to_s != rule.fetch("port")

          true
        end
      end

      def normalize_destination_ports(value)
        hash = if value.is_a?(Array)
                 value
               else
                 (value.respond_to?(:to_h) ? value.to_h : value)
               end
        if hash.is_a?(Array)
          hash.each_with_object({}) do |entry, result|
            port = entry.respond_to?(:to_h) ? entry.to_h : entry
            name = Support.fetch(port, "name", default: nil)
            number = Support.fetch(port, "port", "containerPort", "targetPort", default: nil)
            result[String(name)] = Integer(number) if name && number
          end
        else
          hash.each_with_object({}) { |(name, number), result| result[String(name)] = Integer(number) }
        end
      rescue ArgumentError, TypeError
        {}
      end

      def normalize_endpoint(endpoint)
        hash = endpoint.respond_to?(:to_h) ? endpoint.to_h : endpoint
        labels = Support.fetch(hash, "labels", "pod_labels", default: {})
        namespace = String(Support.fetch(hash, "namespace", "namespace_name", default: "default"))
        ports = Support.fetch(hash, "ports", "container_ports", default: {})
        {"namespace" => namespace, "labels" => labels, "ip" => Support.fetch(hash, "ip", "address", default: nil),
         "ports" => ports, "name" => Support.fetch(hash, "name", "pod_name", default: nil)}
      end

      def normalize_namespace_labels(value)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        hash.each_with_object({}) do |(namespace, labels), result|
          result[String(namespace)] = labels.respond_to?(:to_h) ? labels.to_h.transform_keys(&:to_s) : {}
        end.freeze
      end

      def normalize_direction(value)
        value.to_s.downcase.then do |normalized|
          return "ingress" if %w[ingress in].include?(normalized)
          return "egress" if %w[egress out].include?(normalized)

          raise PolicyError, "unsupported NetworkPolicy direction #{value.inspect}"
        end
      end

      def normalize_protocol(value)
        protocol = String(value).upcase
        raise PolicyError, "unsupported NetworkPolicy protocol #{value.inspect}" unless PROTOCOLS.include?(protocol)

        protocol
      end

      def numeric_port?(value)
        value.is_a?(Integer) || value.to_s.match?(/\A\d+\z/)
      end
    end

    NetworkPolicy = PolicyRecord
    Policy = PolicyEngine
    NetworkPolicyEngine = PolicyEngine
    PolicyEvaluator = PolicyEngine
  end
end
