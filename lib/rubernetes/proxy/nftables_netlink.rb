# frozen_string_literal: true

require "digest"
require "ipaddr"
require "json"
require "socket"
require "time"
require_relative "model"

module Rubernetes
  module Proxy
    # Raised when the kernel rejects an nf_tables request or when a readback
    # cannot prove that the requested objects belong to this adapter.
    class NftablesNetlinkError < StandardError
      attr_reader :errno, :operation, :sequence

      def initialize(message, errno: nil, operation: nil, sequence: nil)
        super(message)
        @errno = errno
        @operation = operation
        @sequence = sequence
      end
    end

    # Direct NETLINK_NETFILTER adapter for the nftables proxy boundary.
    #
    # The adapter emits a complete Service datapath graph. Endpoint sets are
    # kept as explicit kernel objects for atomic membership updates, while
    # service rules use a deterministic Jenkins hash over the source address
    # to select one backend. ClientIP affinity uses a timeout map populated by
    # dynset at first packet and read back as part of the owned object graph.
    class NftablesNetlinkAdapter
      AF_UNSPEC = 0
      NFPROTO_INET = 1
      NFPROTO_IPV4 = 2
      NFPROTO_IPV6 = 10
      AF_NETLINK = 16
      NETLINK_NETFILTER = 12

      NLM_F_REQUEST = 0x01
      NLM_F_MULTI = 0x02
      NLM_F_ACK = 0x04
      NLM_F_ECHO = 0x08
      NLM_F_ROOT = 0x100
      NLM_F_MATCH = 0x200
      NLM_F_CREATE = 0x400
      NLM_F_EXCL = 0x200
      NLM_F_APPEND = 0x800
      NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

      NLMSG_NOOP = 1
      NLMSG_ERROR = 2
      NLMSG_DONE = 3
      NLMSG_MIN_TYPE = 0x10
      NFNL_MSG_BATCH_BEGIN = NLMSG_MIN_TYPE
      NFNL_MSG_BATCH_END = NLMSG_MIN_TYPE + 1
      NFNL_SUBSYS_NFTABLES = 10
      NFT_MSG_NEWTABLE = 0
      NFT_MSG_GETTABLE = 1
      NFT_MSG_DELTABLE = 2
      NFT_MSG_NEWCHAIN = 3
      NFT_MSG_GETCHAIN = 4
      NFT_MSG_DELCHAIN = 5
      NFT_MSG_NEWRULE = 6
      NFT_MSG_GETRULE = 7
      NFT_MSG_DELRULE = 8
      NFT_MSG_NEWSET = 9
      NFT_MSG_GETSET = 10
      NFT_MSG_DELSET = 11
      NFT_MSG_NEWSETELEM = 12
      NFT_MSG_GETSETELEM = 13
      NFT_MSG_DELSETELEM = 14

      # nftables object attributes from <linux/netfilter/nf_tables.h>.
      NFTA_TABLE_NAME = 1
      NFTA_TABLE_FLAGS = 2
      NFTA_TABLE_USERDATA = 6
      NFTA_CHAIN_TABLE = 1
      NFTA_CHAIN_HANDLE = 2
      NFTA_CHAIN_NAME = 3
      NFTA_CHAIN_HOOK = 4
      NFTA_CHAIN_POLICY = 5
      NFTA_CHAIN_TYPE = 7
      NFTA_CHAIN_USERDATA = 12
      NFTA_RULE_TABLE = 1
      NFTA_RULE_CHAIN = 2
      NFTA_RULE_HANDLE = 3
      NFTA_RULE_EXPRESSIONS = 4
      NFTA_RULE_POSITION = 6
      NFTA_RULE_USERDATA = 7
      NFTA_SET_TABLE = 1
      NFTA_SET_NAME = 2
      NFTA_SET_FLAGS = 3
      NFTA_SET_KEY_TYPE = 4
      NFTA_SET_KEY_LEN = 5
      NFTA_SET_DATA_TYPE = 6
      NFTA_SET_DATA_LEN = 7
      NFTA_SET_POLICY = 8
      NFTA_SET_ID = 10
      NFTA_SET_TIMEOUT = 11
      NFTA_SET_USERDATA = 13
      NFTA_SET_HANDLE = 16
      NFTA_SET_ELEM_LIST_TABLE = 1
      NFTA_SET_ELEM_LIST_SET = 2
      NFTA_SET_ELEM_LIST_ELEMENTS = 3
      NFTA_SET_ELEM_LIST_SET_ID = 4
      NFTA_SET_ELEM_KEY = 1
      NFTA_SET_ELEM_DATA = 2
      NFTA_SET_ELEM_FLAGS = 3
      NFTA_SET_ELEM_TIMEOUT = 4
      NFTA_SET_ELEM_EXPIRATION = 5
      NFTA_SET_ELEM_USERDATA = 6
      NFTA_DATA_VALUE = 1
      NFTA_DATA_VERDICT = 2

      # Nested expression attributes.
      NFTA_EXPR_NAME = 1
      NFTA_EXPR_DATA = 2
      NFTA_LIST_ELEM = 1
      NFTA_META_DREG = 1
      NFTA_META_KEY = 2
      NFTA_PAYLOAD_DREG = 1
      NFTA_PAYLOAD_BASE = 2
      NFTA_PAYLOAD_OFFSET = 3
      NFTA_PAYLOAD_LEN = 4
      NFTA_CMP_SREG = 1
      NFTA_CMP_OP = 2
      NFTA_CMP_DATA = 3
      NFTA_IMMEDIATE_DREG = 1
      NFTA_IMMEDIATE_DATA = 2
      NFTA_VERDICT_CODE = 1
      NFTA_VERDICT_CHAIN = 2
      NFTA_NAT_TYPE = 1
      NFTA_NAT_FAMILY = 2
      NFTA_NAT_REG_ADDR_MIN = 3
      NFTA_NAT_REG_PROTO_MIN = 5
      NFTA_NAT_FLAGS = 7

      # lookup, dynset, hash, and conntrack expression attributes from
      # <linux/netfilter/nf_tables.h>.
      NFTA_LOOKUP_SET = 1
      NFTA_LOOKUP_SREG = 2
      NFTA_LOOKUP_DREG = 3
      NFTA_LOOKUP_SET_ID = 4
      NFTA_DYNSET_SET_NAME = 1
      NFTA_DYNSET_SET_ID = 2
      NFTA_DYNSET_OP = 3
      NFTA_DYNSET_SREG_KEY = 4
      NFTA_DYNSET_SREG_DATA = 5
      NFTA_DYNSET_TIMEOUT = 6
      NFTA_DYNSET_FLAGS = 9
      NFTA_HASH_SREG = 1
      NFTA_HASH_DREG = 2
      NFTA_HASH_LEN = 3
      NFTA_HASH_MODULUS = 4
      NFTA_HASH_SEED = 5
      NFTA_HASH_OFFSET = 6
      NFTA_HASH_TYPE = 7
      NFTA_BITWISE_SREG = 1
      NFTA_BITWISE_DREG = 2
      NFTA_BITWISE_LEN = 3
      NFTA_BITWISE_MASK = 4
      NFTA_BITWISE_XOR = 5
      NFTA_BITWISE_OP = 6
      NFTA_CT_DREG = 1
      NFTA_CT_KEY = 2
      NFTA_CT_SREG = 4
      NFT_CT_MARK = 3
      # kube-proxy parity: a DNAT that must be masqueraded marks the
      # conntrack entry and POSTROUTING masquerades marked flows only, so a
      # ClusterIP flow to the same backend keeps its client source.
      MASQUERADE_CT_MARK = 0x4000

      NFT_SET_KEY_IPV4_ADDR = 7
      NFT_SET_KEY_IPV6_ADDR = 8
      # nftables' generic data-type id for a mark map value.  A map's
      # NFTA_SET_DATA_TYPE is a datatype id, not a register-width (0 is the
      # verdict datatype and is rejected for a mark-valued map).
      NFT_DATA_TYPE_MARK = 0x13
      NFT_META_NFPROTO = 15
      NFT_META_L4PROTO = 16
      NFT_PAYLOAD_NETWORK_HEADER = 1
      NFT_PAYLOAD_TRANSPORT_HEADER = 2
      NFT_CMP_EQ = 0
      NFT_CMP_NEQ = 1
      NFT_JUMP = -3
      NFT_NG_RANDOM = 1
      NFT_HASH_JENKINS = 0
      # numgen attributes (nf_tables.h): a random number generator expression,
      # which is how kube-proxy's nftables backend picks an endpoint when a
      # Service has no session affinity.
      NFTA_NG_DREG = 1
      NFTA_NG_MODULUS = 2
      NFTA_NG_TYPE = 3
      NFTA_NG_OFFSET = 4
      # A ClientIP miss inserts the first mapping.  UPDATE is rejected by
      # kernels when the source key is not already present; the hit rule
      # handles existing entries, so ADD is the correct first-packet op.
      NFT_DYNSET_OP_ADD = 0
      NFT_SET_MAP = 0x8
      NFT_SET_TIMEOUT = 0x10
      NFT_SET_EVAL = 0x20
      NFT_NAT_DNAT = 1
      NF_NAT_RANGE_PROTO_SPECIFIED = 0x2
      NF_INET_PRE_ROUTING = 0
      NF_INET_LOCAL_OUT = 3
      NF_INET_POST_ROUTING = 4
      NFT_ACCEPT = 1

      NLA_F_NESTED = 0x8000
      NLA_TYPE_MASK = 0x3fff
      NETLINK_HEADER_SIZE = 16
      NFGENMSG_SIZE = 4
      MAX_MESSAGE_BYTES = 1_048_576
      MAGIC = "rubernetes\0".b.freeze
      BASE_CHAIN_SPECS = {
        # TC/eBPF cannot reassemble at ingress.  nftables therefore rejects
        # fragments in a pre-defragmentation guard so both backends fail
        # closed with the same explicit contract.
        "fragment_guard" => {hook: NF_INET_PRE_ROUTING, priority: -450, type: "filter"},
        "prerouting" => {hook: NF_INET_PRE_ROUTING, priority: -100, type: "nat"},
        "output" => {hook: NF_INET_LOCAL_OUT, priority: -100, type: "nat"},
        "postrouting" => {hook: NF_INET_POST_ROUTING, priority: 100, type: "nat"}
      }.freeze

      SERVICE_SEMANTIC_MATRIX = {
        "multipleEndpointSelection" => true,
        "deterministicBackendHash" => true,
        "clientIPAffinityTimeout" => true,
        "internalTrafficPolicy" => true,
        "externalTrafficPolicy" => true,
        "masqueradeAndHairpin" => true,
        "nodePortExternalIPLoadBalancer" => true,
        "topologyHints" => true,
        "healthCheckNodePort" => true,
        "fragmentFailClosed" => true,
        "tcpUdpSctp" => true,
        "ipv4Ipv6DualStack" => true
      }.freeze

      # Kept as a compatibility constant for callers that display capability
      # gaps. A non-empty list means the adapter cannot claim production use.
      MISSING_SERVICE_CONTRACT = [].freeze

      Message = Struct.new(:type, :flags, :sequence, :pid, :payload, keyword_init: true) do
        def error_code
          return nil unless type == NftablesNetlinkAdapter::NLMSG_ERROR
          return nil if payload.bytesize < 4

          payload.unpack1("l<")
        end
      end

      attr_reader :table_name, :last_readback, :last_transaction, :missing_service_contract,
                  :service_semantic_matrix, :production_capability_error_detail

      def initialize(table_name: "rubernetes", timeout: 2.0, socket_factory: nil, transport: nil,
                     semantic_probe: nil)
        @table_name = validate_name(table_name, "table name")
        @timeout = Float(timeout)
        raise ArgumentError, "nftables netlink timeout must be positive and finite" unless @timeout.positive? && @timeout.finite?

        @socket_factory = socket_factory || method(:open_socket)
        @transport = transport
        @mutex = Mutex.new
        @sequence = 0
        @last_readback = nil
        @last_transaction = nil
        @missing_service_contract = MISSING_SERVICE_CONTRACT.dup.freeze
        @service_semantic_matrix = SERVICE_SEMANTIC_MATRIX.dup.freeze
        @production_probe_mutex = Mutex.new
        @production_capable = nil
        @production_capability_error_detail = nil
        @semantic_probe = semantic_probe
        raise ArgumentError, "semantic_probe must respond to call" if @semantic_probe && !@semantic_probe.respond_to?(:call)

        @semantic_verified = false
        @semantic_evidence_attested = false
      end

      def production_capable?
        return false unless missing_service_contract.empty? && service_semantic_matrix.values.all?
        return false if @transport
        return false unless @semantic_verified
        return false unless @semantic_evidence_attested
        return false unless @last_readback.is_a?(Hash) && @last_readback["verified"] == true

        @production_probe_mutex.synchronize do
          return @production_capable unless @production_capable.nil?

          begin
            @production_capable = live_kernel_capability_probe
            @production_capability_error_detail = "live NETLINK_NETFILTER owned-table probe failed" unless @production_capable
          rescue StandardError => error
            @production_capable = false
            @production_capability_error_detail = "live NETLINK_NETFILTER probe failed: #{error.message}"
          end
          @production_capable
        end
      end

      def test_adapter?
        false
      end

      # The adapter speaks NETLINK_NETFILTER directly; it can attach before
      # any packet proof exists.  Production capability is still established
      # only through verify_packet_semantics! after a verified readback.
      def mechanically_capable?
        @transport.nil?
      end

      def production_capability_error
        return "nftables adapter is production-capable" if production_capable?

        reasons = missing_service_contract.dup
        reasons << "transport-backed readback is not a live NETLINK_NETFILTER probe" if @transport
        reasons << "an external packet semantic probe and verified ruleset readback are required" unless @semantic_verified && @semantic_evidence_attested && @last_readback&.fetch(
          "verified", false
        )
        reasons << production_capability_error_detail if production_capability_error_detail
        reasons << "live NETLINK_NETFILTER owned-table readback probe is required" if reasons.empty?
        "nftables adapter is not production-capable: #{reasons.join("; ")}"
      end

      # Apply the complete desired object graph for a backend's current rules.
      # The graph is diffed against kernel readback and sent as one atomic
      # nfnetlink batch; no JSON or command-line protocol is involved.
      def send_messages(_messages, backend:, **_options)
        apply_backend(backend)
      end

      alias apply send_messages

      def attach(backend:, messages: [], **_options)
        result = apply_backend(backend)
        run_semantic_probe if @semantic_probe
        result.merge("attached" => true, "inputMessageCount" => Array(messages).length).freeze
      end

      def update(backend:, **_options)
        apply_backend(backend)
      end

      def verify_transaction(backend:, result:, **_options)
        return false unless result.is_a?(Hash)
        return false unless result["verified"] == true || result[:verified] == true

        readback(backend: backend).fetch("verified") == true
      end

      alias verify_attach verify_transaction
      alias verify_update verify_transaction

      # Readback is authoritative: true is returned only after GETTABLE,
      # GETCHAIN, GETSET/GETSETELEM and GETRULE have matched every owned object.
      def readback(backend:, **_options)
        desired = desired_objects(Array(backend.rules))
        actual = read_kernel_ruleset
        verification = verify_readback(actual, desired)
        @last_readback = actual.merge("verified" => verification).freeze
        @last_readback
      end

      def verify_packet_semantics!(evidence:)
        evidence = evidence.transform_keys(&:to_s) if evidence.respond_to?(:transform_keys)
        required = %w[executed packetTraceSha256 packetCount caseInventorySha256]
        missing = required.reject do |key|
          value = evidence.is_a?(Hash) && evidence[key]
          if key == "executed"
            value == true
          else
            (key == "packetCount" ? value.to_i.positive? : value.to_s.match?(/\A[0-9a-f]{64}\z/i))
          end
        end
        raise ArgumentError, "nftables packet semantics evidence is incomplete: #{missing.join(", ")}" unless missing.empty?
        raise "nftables ruleset readback must pass before packet proof" unless @last_readback&.fetch("verified", false)
        unless semantic_evidence_attested?(evidence)
          raise ArgumentError,
                "nftables packet semantics evidence must include external runner and packet capture provenance"
        end

        @semantic_verified = true
        @semantic_evidence_attested = true
        @production_capable = nil
        true
      end

      # Return an identity only after live table/rule readback and packet
      # semantics proof. Transport fixtures intentionally never qualify.
      def kernel_identity
        return nil unless production_capable?

        table = @last_readback.fetch("table")
        {
          "table" => table.slice("name", "marker"),
          "chains" => @last_readback.fetch("chains").map { |entry| entry.slice("name", "marker", "handle") },
          "sets" => @last_readback.fetch("sets").map { |entry| entry.slice("name", "marker", "handle", "key_len", "data_len") },
          "rules" => @last_readback.fetch("rules").map { |entry| entry.slice("chain", "marker", "handle") }
        }.freeze
      rescue StandardError
        nil
      end

      def detach(backend: nil, **_options)
        actual = if backend
                   read_kernel_ruleset
                 else
                   @last_readback || read_kernel_ruleset
                 end
        unless actual["table"]
          @semantic_verified = false
          @semantic_evidence_attested = false
          @production_capable = nil
          return true
        end

        ensure_owned_table!(actual)
        ensure_owned_objects!(actual)
        messages = destroy_messages(actual)
        transaction = send_transaction(messages)
        remaining = read_kernel_ruleset
        unless remaining["table"].nil?
          raise NftablesNetlinkError, "nftables detach readback still contains owned table #{@table_name.inspect}"
        end

        @last_transaction = transaction.freeze
        @last_readback = remaining.merge("verified" => true).freeze
        @semantic_verified = false
        @semantic_evidence_attested = false
        @production_capable = nil
        true
      end

      private

      # Capability is not inferred from the encoder or from a static feature
      # matrix.  Exercise the actual NETLINK_NETFILTER socket by creating a
      # uniquely owned probe table, reading it back, and removing it again.
      # The probe table is independent from the adapter's configured table so
      # capability checks cannot destroy a live Service ruleset.
      def live_kernel_capability_probe
        probe_name = "rk_probe_#{Process.pid}_#{Digest::SHA256.hexdigest("#{object_id}:#{@table_name}")[0, 12]}"
        probe = self.class.new(table_name: probe_name, timeout: @timeout, socket_factory: @socket_factory)
        created = false
        message = probe.send(:new_table_message)
        probe.send(:send_transaction, [message])
        created = true
        actual = probe.send(:read_kernel_ruleset)
        expected_marker = probe.send(:marker, "table", probe_name)
        table = actual["table"]
        verified = table.is_a?(Hash) && table["name"] == probe_name && table["marker"] == expected_marker
        raise NftablesNetlinkError, "owned nftables probe table readback did not match" unless verified

        true
      ensure
        if created && probe
          begin
            probe.detach
          rescue StandardError
            # A probe that cannot be cleaned up cannot prove a production
            # capability.  Surface failure through the caller's false result.
            raise
          end
        end
      end

      # Concurrent writers of the same owned table (several proxy instances on
      # one host, or a restart racing its predecessor) can both observe an
      # object as absent and then both create it; the loser sees EEXIST.  The
      # diff is recomputed from fresh kernel state and retried, so the
      # transaction converges instead of killing the process.  Ownership is
      # still enforced: a table that is not ours raises before any write.
      EEXIST_RETRIES = 3

      def apply_backend(backend)
        attempts = 0
        begin
          apply_backend_once(backend)
        rescue NftablesNetlinkError => error
          raise unless error.errno == Errno::EEXIST::Errno && attempts < EEXIST_RETRIES

          attempts += 1
          retry
        end
      end

      def apply_backend_once(backend)
        rules = Array(backend.rules).sort_by(&:key)
        desired = desired_objects(rules)
        current = read_kernel_ruleset
        ensure_owned_table!(current) if current["table"]
        ensure_owned_objects!(current)
        messages = lifecycle_messages(current, desired)
        transaction = send_transaction(messages)
        actual = read_kernel_ruleset
        verified = verify_readback(actual, desired)
        raise NftablesNetlinkError, "nftables transaction completed without matching kernel readback" unless verified

        result = {
          "verified" => true,
          "productionCapable" => production_capable?,
          "missingServiceContract" => missing_service_contract,
          "table" => @table_name,
          "transaction" => transaction,
          "readback" => actual
        }.freeze
        @last_transaction = transaction.freeze
        @last_readback = actual.merge("verified" => true).freeze
        result
      end

      def run_semantic_probe
        evidence = @semantic_probe.call(self)
        verify_packet_semantics!(evidence: evidence)
      rescue StandardError => error
        @semantic_verified = false
        @semantic_evidence_attested = false
        @production_capable = false
        raise NftablesNetlinkError, "nftables packet semantics probe failed: #{error.message}"
      end

      def semantic_evidence_attested?(evidence)
        return false unless evidence.is_a?(Hash)

        source = evidence["measurementSource"] || evidence["measurement_source"]
        trace = evidence["packetTraceSha256"] || evidence["packet_trace_sha256"]
        count = evidence["packetCount"] || evidence["packet_count"]
        inventory = evidence["caseInventorySha256"] || evidence["case_inventory_sha256"]
        return false unless source.is_a?(String) && !source.empty? && source != "model_only"
        return false unless trace.to_s.match?(/\A[0-9a-f]{64}\z/i) && count.to_i.positive?
        return false unless inventory.to_s.match?(/\A[0-9a-f]{64}\z/i)

        runner = evidence["runner"] || evidence["runnerProvenance"] || evidence["runner_provenance"]
        return false unless runner.is_a?(Hash)

        pid = runner["pid"] || runner["processId"] || runner["process_id"]
        started_at = runner["startedAt"] || runner["started_at"] || runner["startTime"] || runner["start_time"]
        runner_source = runner["source"] || runner["sourcePath"] || runner["source_path"]
        argv = runner["argv"] || runner["command"]
        stdout = runner["stdout"]
        stdout_digest = runner["stdoutSha256"] || runner["stdout_sha256"]
        return false unless pid.is_a?(Integer) && pid.positive?
        return false unless begin
          Time.iso8601(started_at.to_s)
          true
        rescue ArgumentError, TypeError
          false
        end
        return false unless runner_source.is_a?(String) && !runner_source.empty? && runner_source != "model"
        return false unless argv.is_a?(Array) && !argv.empty? && argv.all? { |arg| arg.is_a?(String) && !arg.empty? }
        return false unless stdout.is_a?(String) && stdout_digest.to_s.match?(/\A[0-9a-f]{64}\z/i)
        return false unless Digest::SHA256.hexdigest(stdout) == stdout_digest

        capture = evidence["packetCapture"] || evidence["packet_capture"] || evidence["pcap"]
        return false unless capture.is_a?(Hash)

        format = capture["format"] || capture["type"]
        digest = capture["sha256"] || capture["packetBytesSha256"] || capture["packet_bytes_sha256"] || capture["pcapSha256"] || capture["pcap_sha256"]
        capture_count = capture["packetCount"] || capture["packet_count"] || capture["count"]
        capture_source = capture["source"] || capture["sourcePath"] || capture["source_path"]
        return false unless %w[pcap packet_bytes raw].include?(format.to_s)
        return false unless digest.to_s.match?(/\A[0-9a-f]{64}\z/i) && capture_count.is_a?(Integer) && capture_count.positive?
        return false unless capture_source.is_a?(String) && !capture_source.empty? && capture_source != "model"

        # "bytes" is either the raw capture (verified against the digest) or
        # the capture size in bytes reported beside a digest of the file.
        bytes = capture["bytes"] || capture["packetBytes"] || capture["packet_bytes"]
        if bytes.is_a?(String)
          return false unless Digest::SHA256.hexdigest(bytes.b) == digest
        elsif bytes
          return false unless bytes.is_a?(Integer) && bytes.positive?
        end

        kernel = evidence["kernel"] || evidence["kernelIdentity"] || evidence["kernel_identity"] || evidence["kernelReadback"] || evidence["kernel_readback"]
        return false unless kernel.is_a?(Hash)

        table = kernel["table"] || kernel["tableIdentity"] || kernel["table_identity"]
        table_name = table.is_a?(Hash) ? table["name"] : table
        return false unless table_name.to_s == @table_name

        rules = kernel["rules"] || evidence["rules"]
        rules_digest = kernel["rulesDigest"] || kernel["rules_digest"] || evidence["rulesDigest"] || evidence["rules_digest"]
        return false unless rules.is_a?(Array) && rules_digest.to_s.match?(/\A[0-9a-f]{64}\z/i)
        return false unless rules_digest == canonical_digest(rules) && rules_digest == canonical_digest(@last_readback.fetch("rules"))

        true
      end

      def canonical_digest(value)
        Digest::SHA256.hexdigest(JSON.generate(ModelSupport.canonicalize(value)))
      end

      def desired_objects(rules)
        base_chains = BASE_CHAIN_SPECS.map do |name, spec|
          {
            "name" => name,
            "marker" => marker("chain", "base:#{name}"),
            "base" => true,
            "message" => new_chain_message(name: name, marker: marker("chain", "base:#{name}"), hook: spec)
          }
        end
        service_chains = []
        sets = []
        set_elements = []
        service_rules = []
        jump_rules = []
        next_set_id = 1

        rules.each do |rule|
          chain_name = service_chain_name(rule)
          chain_marker = marker("chain", "service:#{rule_identity(rule)}")
          service_chains << {
            "name" => chain_name,
            "marker" => chain_marker,
            "base" => false,
            "message" => new_chain_message(name: chain_name, marker: chain_marker)
          }
          endpoint_values = endpoints_for(rule)
          snat_endpoints = snat_endpoints_for(rule, endpoint_values)
          snat_chain = if snat_endpoints.empty?
                         nil
                       else
                         snat_name = snat_chain_name(rule)
                         service_chains << {
                           "name" => snat_name,
                           "marker" => marker("chain", "snat:#{rule_identity(rule)}"),
                           "base" => false,
                           "message" => new_chain_message(name: snat_name,
                                                          marker: marker("chain", "snat:#{rule_identity(rule)}"))
                         }
                         snat_name
                       end
          families = endpoint_families(rule, endpoint_values)
          families.each do |family|
            family_endpoints = endpoint_values.select { |endpoint| family_for_address(endpoint.fetch("address")) == family }
            set_name = endpoint_set_name(rule, family)
            set_marker = marker("set", "#{rule_identity(rule)}:#{family}")
            set_id = next_set_id
            next_set_id += 1
            sets << {
              "name" => set_name,
              "marker" => set_marker,
              "id" => set_id,
              "kind" => "endpoint",
              "family" => family,
              "flags" => 0,
              "key_type" => family == NFPROTO_IPV6 ? NFT_SET_KEY_IPV6_ADDR : NFT_SET_KEY_IPV4_ADDR,
              "key_len" => family == NFPROTO_IPV6 ? 16 : 4,
              "data_type" => nil,
              "data_len" => nil,
              "timeout" => nil,
              "message" => new_set_message(name: set_name, marker: set_marker, endpoints: family_endpoints,
                                           set_id: set_id, family: family)
            }
            # The set is keyed by address alone, so several backends of one
            # Service that share an address (three API servers on one host,
            # each on its own port) collapse into a single element; the port
            # distinction lives in the DNAT rules, not here.  Emitting one
            # element per endpoint would make the kernel reject the duplicate
            # key with EEXIST and take the whole transaction down.
            family_endpoints.uniq { |endpoint| endpoint.fetch("packed_address") }.each do |endpoint|
              endpoint_marker = marker("element", "#{rule_identity(rule)}:#{family}:#{endpoint.fetch("address")}")
              set_elements << {
                "set" => set_name,
                "set_id" => set_id,
                "marker" => endpoint_marker,
                "key" => endpoint.fetch("packed_address"),
                "message" => new_set_element_message(set_name: set_name, set_id: set_id, marker: endpoint_marker,
                                                     key: endpoint.fetch("packed_address"))
              }
            end

            affinity_set = nil
            if client_ip_affinity?(rule)
              affinity_set_name_value = affinity_set_name(rule, family)
              affinity_marker = marker("affinity", affinity_set_identity(rule, family))
              affinity_set_id = next_set_id
              next_set_id += 1
              affinity_set = {"name" => affinity_set_name_value, "id" => affinity_set_id,
                              "marker" => affinity_marker, "kind" => "affinity", "family" => family,
                              "flags" => NFT_SET_MAP | NFT_SET_TIMEOUT | NFT_SET_EVAL,
                              "key_type" => family == NFPROTO_IPV6 ? NFT_SET_KEY_IPV6_ADDR : NFT_SET_KEY_IPV4_ADDR,
                              "key_len" => family == NFPROTO_IPV6 ? 16 : 4,
                              "data_type" => NFT_DATA_TYPE_MARK,
                              "data_len" => 4,
                              "timeout" => Integer(rule.session_affinity_timeout_seconds) * 1000}
              sets << affinity_set.merge(
                "message" => new_set_message(name: affinity_set_name_value, marker: affinity_marker,
                                             endpoints: [], set_id: affinity_set_id, family: family,
                                             map: true, timeout_seconds: rule.session_affinity_timeout_seconds)
              )
            end

            destination_addresses = destination_addresses_for(rule, family)
            destination_addresses.each do |destination_address|
              service_rules.concat(service_rule_objects(rule, chain_name, family, family_endpoints,
                                                        affinity_set: affinity_set,
                                                        destination_address: destination_address))
              next unless snat_chain

              family_snat_endpoints = snat_endpoints.select do |endpoint|
                family_for_address(endpoint.fetch("address")) == family
              end
              snat_rule_objects(rule, snat_chain, family, family_snat_endpoints,
                                destination_address: destination_address).each do |object|
                service_rules << object unless service_rules.any? { |existing| existing["marker"] == object["marker"] }
              end
            end
          end
          %w[prerouting output].each do |base_name|
            jump_marker = marker("rule", "jump:#{base_name}:#{chain_name}")
            jump_rules << {
              "chain" => base_name,
              "marker" => jump_marker,
              "message" => new_jump_rule_message(base_name, chain_name, jump_marker)
            }
          end
          next unless snat_chain

          jump_marker = marker("rule", "jump:postrouting:#{snat_chain}")
          jump_rules << {
            "chain" => "postrouting",
            "marker" => jump_marker,
            "message" => new_jump_rule_message("postrouting", snat_chain, jump_marker)
          }
        end

        fragment_rules = fragment_guard_rule_objects
        {
          "table" => {"name" => @table_name, "marker" => marker("table", @table_name),
                      "message" => new_table_message},
          "chains" => (base_chains + service_chains).freeze,
          "sets" => sets.freeze,
          "set_elements" => set_elements.freeze,
          "rules" => (fragment_rules + service_rules + jump_rules).freeze
        }.freeze
      end

      def lifecycle_messages(current, desired)
        messages = []
        current_rules = current.fetch("rules")
        desired_rules = desired.fetch("rules")
        desired_rule_markers = desired_rules.map { |item| item.fetch("marker") }
        current_rules.each do |item|
          messages << delete_rule_message(item) unless desired_rule_markers.include?(item.fetch("marker"))
        end

        current_elements = current.fetch("set_elements")
        desired_elements = desired.fetch("set_elements")
        desired_element_markers = desired_elements.map { |item| item.fetch("marker") }
        affinity_set_names = affinity_set_names(current.fetch("sets"))
        current_elements.each do |item|
          # ClientIP mappings are live kernel state.  They intentionally have
          # no adapter userdata marker and must survive an ordinary rule or
          # endpoint refresh until their kernel timeout expires.
          next if affinity_set_names.include?(item["set"]) && !marker_owned?(item["marker"])

          messages << delete_set_element_message(item) unless desired_element_markers.include?(item.fetch("marker"))
        end

        current_sets = current.fetch("sets")
        desired_sets = desired.fetch("sets")
        desired_set_markers = desired_sets.map { |item| item.fetch("marker") }
        current_sets.each do |item|
          messages << delete_set_message(item) unless desired_set_markers.include?(item.fetch("marker"))
        end

        current_chains = current.fetch("chains")
        desired_chains = desired.fetch("chains")
        desired_chain_markers = desired_chains.map { |item| item.fetch("marker") }
        current_chains.reverse_each do |item|
          messages << delete_chain_message(item) unless desired_chain_markers.include?(item.fetch("marker"))
        end

        messages << desired.fetch("table").fetch("message") unless current["table"]
        current_chain_markers = current_chains.map { |item| item.fetch("marker") }
        desired_chains.each do |item|
          messages << item.fetch("message") unless current_chain_markers.include?(item.fetch("marker"))
        end
        current_set_markers = current_sets.map { |item| item.fetch("marker") }
        desired_sets.each do |item|
          messages << item.fetch("message") unless current_set_markers.include?(item.fetch("marker"))
        end
        current_element_markers = current_elements.map { |item| item.fetch("marker") }
        desired_elements.each do |item|
          messages << item.fetch("message") unless current_element_markers.include?(item.fetch("marker"))
        end
        current_rule_markers = current_rules.map { |item| item.fetch("marker") }
        desired_rules.each do |item|
          messages << item.fetch("message") unless current_rule_markers.include?(item.fetch("marker"))
        end
        messages
      end

      def destroy_messages(current)
        messages = current.fetch("rules").map { |item| delete_rule_message(item) }
        messages.concat(current.fetch("set_elements").map { |item| delete_set_element_message(item) })
        messages.concat(current.fetch("sets").map { |item| delete_set_message(item) })
        messages.concat(current.fetch("chains").reverse_each.map { |item| delete_chain_message(item) })
        messages << {type: NFT_MSG_DELTABLE, flags: NLM_F_REQUEST | NLM_F_ACK,
                     family: NFPROTO_INET, attributes: [attribute(NFTA_TABLE_NAME, cstring(@table_name))].join}
        messages
      end

      def new_table_message
        {type: NFT_MSG_NEWTABLE, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
         family: NFPROTO_INET,
         attributes: attributes(attribute(NFTA_TABLE_NAME, cstring(@table_name)),
                                attribute(NFTA_TABLE_FLAGS, u32(0)),
                                attribute(NFTA_TABLE_USERDATA, marker("table", @table_name)))}
      end

      def new_chain_message(name:, marker:, hook: nil)
        values = [attribute(NFTA_CHAIN_TABLE, cstring(@table_name)), attribute(NFTA_CHAIN_NAME, cstring(name)),
                  attribute(NFTA_CHAIN_USERDATA, marker)]
        if hook
          hook_attrs = attributes(attribute(1, u32(hook.fetch(:hook))), attribute(2, u32(hook.fetch(:priority))))
          values << attribute(NFTA_CHAIN_HOOK, hook_attrs, nested: true)
          values << attribute(NFTA_CHAIN_POLICY, u32(NFT_ACCEPT))
          values << attribute(NFTA_CHAIN_TYPE, cstring(hook.fetch(:type, "nat")))
        end
        {type: NFT_MSG_NEWCHAIN, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
         family: NFPROTO_INET, attributes: attributes(*values)}
      end

      def new_set_message(name:, marker:, endpoints:, set_id:, family: nil, map: false, timeout_seconds: nil)
        family ||= endpoints.empty? ? NFPROTO_IPV4 : family_for_address(endpoints.first.fetch("address"))
        key_type = family == NFPROTO_IPV6 ? NFT_SET_KEY_IPV6_ADDR : NFT_SET_KEY_IPV4_ADDR
        key_len = family == NFPROTO_IPV6 ? 16 : 4
        flags = map ? NFT_SET_MAP | NFT_SET_TIMEOUT | NFT_SET_EVAL : 0
        set_attributes = [attribute(NFTA_SET_TABLE, cstring(@table_name)), attribute(NFTA_SET_NAME, cstring(name)),
                          attribute(NFTA_SET_FLAGS, u32(flags)), attribute(NFTA_SET_KEY_TYPE, u32(key_type)),
                          attribute(NFTA_SET_KEY_LEN, u32(key_len)), attribute(NFTA_SET_ID, u32(set_id))]
        if map
          set_attributes << attribute(NFTA_SET_DATA_TYPE, u32(NFT_DATA_TYPE_MARK))
          set_attributes << attribute(NFTA_SET_DATA_LEN, u32(4))
          set_attributes << attribute(NFTA_SET_TIMEOUT, u64(Integer(timeout_seconds) * 1000))
        end
        set_attributes << attribute(NFTA_SET_USERDATA, marker)
        {type: NFT_MSG_NEWSET, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
         family: NFPROTO_INET,
         attributes: attributes(*set_attributes)}
      end

      def new_set_element_message(set_name:, set_id:, marker:, key:, data: nil, timeout_seconds: nil)
        key_data = attribute(NFTA_DATA_VALUE, key)
        element = attribute(NFTA_SET_ELEM_KEY, key_data, nested: true)
        element += attribute(NFTA_SET_ELEM_DATA, attribute(NFTA_DATA_VALUE, data), nested: true) if data
        element += attribute(NFTA_SET_ELEM_TIMEOUT, u64(Integer(timeout_seconds) * 1000)) if timeout_seconds
        element += attribute(NFTA_SET_ELEM_USERDATA, marker)
        {type: NFT_MSG_NEWSETELEM, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
         family: NFPROTO_INET,
         attributes: attributes(attribute(NFTA_SET_ELEM_LIST_TABLE, cstring(@table_name)),
                                attribute(NFTA_SET_ELEM_LIST_SET, cstring(set_name)),
                                attribute(NFTA_SET_ELEM_LIST_SET_ID, u32(set_id)),
                                attribute(NFTA_SET_ELEM_LIST_ELEMENTS,
                                          attribute(NFTA_LIST_ELEM, element, nested: true), nested: true))}
      end

      def new_jump_rule_message(chain_name, target_chain, marker)
        verdict = attributes(attribute(NFTA_VERDICT_CODE, u32(NFT_JUMP)),
                             attribute(NFTA_VERDICT_CHAIN, cstring(target_chain)))
        immediate_data = attribute(NFTA_DATA_VERDICT, verdict, nested: true)
        immediate = expression("immediate", attributes(attribute(NFTA_IMMEDIATE_DREG, u32(0)),
                                                       attribute(NFTA_IMMEDIATE_DATA, immediate_data, nested: true)))
        new_rule_message(chain_name: chain_name, marker: marker, expressions: [immediate])
      end

      def service_rule_objects(rule, chain_name, family, endpoints, affinity_set:, destination_address:)
        return [health_check_rule_object(rule, chain_name, family, endpoints, destination_address)] if rule.health_check
        return [] if endpoints.empty?

        objects = []
        source_ranges_for(rule, family).each do |source_range|
          endpoints.each_with_index do |backend, index|
            source_range_id = source_range ? source_range_identity(source_range) : nil
            endpoint_marker = marker("rule",
                                     "service:#{rule_identity(rule)}:#{family}:#{destination_address}:#{source_range_id}:#{backend.fetch("address")}:#{backend.fetch("port")}", rule_digest(rule))
            if hairpin_for?(rule, backend)
              hairpin_marker = marker("rule",
                                      "hairpin:#{rule_identity(rule)}:#{family}:#{destination_address}:#{source_range_id}:#{backend.fetch("address")}", rule_digest(rule))
              hairpin_expressions = service_match_expressions(rule, family: family, destination_address: destination_address,
                                                                    source_range: source_range) +
                                    source_address_expression(family, address: backend.fetch("address")) +
                                    nat_expressions(rule, backend)
              objects << {
                "chain" => chain_name,
                "marker" => hairpin_marker,
                "message" => new_rule_message(chain_name: chain_name, marker: hairpin_marker,
                                              expressions: hairpin_expressions)
              }
            end
            if affinity_set
              hit_expressions = service_match_expressions(rule, family: family, destination_address: destination_address,
                                                                source_range: source_range) +
                                source_address_expression(family) +
                                lookup_expressions(affinity_set.fetch("name"), affinity_set.fetch("id")) +
                                [compare_expression(1, index)] + nat_expressions(rule, backend)
              hit_marker = marker("rule", "affinity-hit:#{endpoint_marker}", rule_digest(rule))
              objects << {
                "chain" => chain_name,
                "marker" => hit_marker,
                "message" => new_rule_message(chain_name: chain_name, marker: hit_marker,
                                              expressions: hit_expressions)
              }
              miss_expressions = service_match_expressions(rule, family: family, destination_address: destination_address,
                                                                 source_range: source_range) +
                                 source_address_expression(family) +
                                 source_hash_expression(family, endpoints.length, rule) +
                                 [compare_expression(1, index)] +
                                 dynset_expression(affinity_set.fetch("name"), rule.session_affinity_timeout_seconds,
                                                   affinity_set.fetch("id")) +
                                 nat_expressions(rule, backend)
              miss_marker = marker("rule", "affinity-miss:#{endpoint_marker}", rule_digest(rule))
              objects << {
                "chain" => chain_name,
                "marker" => miss_marker,
                "message" => new_rule_message(chain_name: chain_name, marker: miss_marker,
                                              expressions: miss_expressions)
              }
            else
              expressions = service_match_expressions(rule, family: family, destination_address: destination_address,
                                                            source_range: source_range) +
                            source_address_expression(family) + source_port_expression(family) +
                            source_hash_expression(family, endpoints.length, rule, include_port: true) +
                            [compare_expression(1, index)] +
                            nat_expressions(rule, backend)
              objects << {
                "chain" => chain_name,
                "marker" => endpoint_marker,
                "message" => new_rule_message(chain_name: chain_name, marker: endpoint_marker, expressions: expressions)
              }
            end
          end
        end
        objects
      end

      def health_check_rule_object(rule, chain_name, family, _endpoints, destination_address)
        marker_value = marker("rule", "health:#{rule_identity(rule)}:#{family}:#{destination_address}", rule_digest(rule))
        # The healthCheckNodePort belongs to the node-local responder.  Keep
        # the packet local; a health rule must never DNAT it to a Pod.
        expressions = service_match_expressions(rule, family: family, destination_address: destination_address) + [accept_expression]
        {"chain" => chain_name, "marker" => marker_value, "action" => "node_local_responder", "dnat" => false,
         "message" => new_rule_message(chain_name: chain_name, marker: marker_value, expressions: expressions)}
      end

      def fragment_guard_rule_objects
        [
          {"chain" => "fragment_guard", "marker" => marker("rule", "fragment:ipv4:drop"), "action" => "drop_fragment",
           "message" => new_rule_message(chain_name: "fragment_guard", marker: marker("rule", "fragment:ipv4:drop"),
                                         expressions: ipv4_fragment_expressions + [reject_expression])},
          {"chain" => "fragment_guard", "marker" => marker("rule", "fragment:ipv6:drop"), "action" => "drop_fragment",
           "message" => new_rule_message(chain_name: "fragment_guard", marker: marker("rule", "fragment:ipv6:drop"),
                                         expressions: ipv6_fragment_expressions + [reject_expression])}
        ]
      end

      # The guard chain lives in the inet family, so every rule must select
      # its IP version first: the IPv4 fragment-offset test applied to an
      # IPv6 header (payload length + next header bytes) rejected all IPv6.
      def nfproto_expressions(family)
        [expression("meta", attributes(attribute(NFTA_META_DREG, u32(1)),
                                       attribute(NFTA_META_KEY, u32(NFT_META_NFPROTO)))),
         compare_expression(1, family)]
      end

      def ipv4_fragment_expressions
        payload = expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(1)),
                                                   attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_NETWORK_HEADER)),
                                                   attribute(NFTA_PAYLOAD_OFFSET, u32(6)),
                                                   attribute(NFTA_PAYLOAD_LEN, u32(2))))
        bitwise = expression("bitwise", attributes(attribute(NFTA_BITWISE_SREG, u32(1)),
                                                   attribute(NFTA_BITWISE_DREG, u32(1)),
                                                   attribute(NFTA_BITWISE_LEN, u32(2)),
                                                   attribute(NFTA_BITWISE_MASK, attribute(NFTA_DATA_VALUE, "\x3f\xff".b, nested: true)),
                                                   attribute(NFTA_BITWISE_XOR, attribute(NFTA_DATA_VALUE, "\0\0".b), nested: true)))
        nfproto_expressions(NFPROTO_IPV4) + [payload, bitwise, compare_not_equal_expression(1, "\0\0".b)]
      end

      # meta l4proto reports the upper-layer protocol behind the extension
      # chain, so a first fragment looks like plain UDP there.  The fragment
      # extension header itself is what identifies fragmented IPv6.
      NFTA_EXTHDR_DREG = 1
      NFTA_EXTHDR_TYPE = 2
      NFTA_EXTHDR_OFFSET = 3
      NFTA_EXTHDR_LEN = 4
      NFTA_EXTHDR_FLAGS = 5
      NFTA_EXTHDR_OP = 6
      NFT_EXTHDR_F_PRESENT = 1
      NFT_EXTHDR_OP_IPV6 = 0
      IPPROTO_FRAGMENT = 44

      def ipv6_fragment_expressions
        nfproto_expressions(NFPROTO_IPV6) +
          [expression("exthdr", attributes(attribute(NFTA_EXTHDR_DREG, u32(1)),
                                           attribute(NFTA_EXTHDR_TYPE, [IPPROTO_FRAGMENT].pack("C")),
                                           attribute(NFTA_EXTHDR_OFFSET, u32(0)),
                                           attribute(NFTA_EXTHDR_LEN, u32(1)),
                                           attribute(NFTA_EXTHDR_FLAGS, u32(NFT_EXTHDR_F_PRESENT)),
                                           attribute(NFTA_EXTHDR_OP, u32(NFT_EXTHDR_OP_IPV6)))),
           compare_expression(1, "\x01".b)]
      end

      def accept_expression
        verdict = attributes(attribute(NFTA_VERDICT_CODE, u32(NFT_ACCEPT)))
        immediate_data = attribute(NFTA_DATA_VERDICT, verdict, nested: true)
        expression("immediate", attributes(attribute(NFTA_IMMEDIATE_DREG, u32(0)),
                                           attribute(NFTA_IMMEDIATE_DATA, immediate_data, nested: true)))
      end

      def snat_rule_objects(rule, chain_name, family, endpoints, destination_address:)
        if masquerade_for?(rule)
          # External traffic policy Cluster: the Service chain marked the
          # conntrack entry at DNAT time; masquerade exactly those flows.
          marker_value = marker("rule", "snat:#{rule_identity(rule)}:#{family}:ctmark", rule_digest(rule))
          expressions = nfproto_expressions(family) + ct_mark_match_expressions + [masquerade_expression]
          return [{"chain" => chain_name, "marker" => marker_value,
                   "message" => new_rule_message(chain_name: chain_name, marker: marker_value, expressions: expressions)}]
        end
        endpoints.each_with_index.map do |backend, index|
          marker_value = marker("rule",
                                "snat:#{rule_identity(rule)}:#{family}:#{destination_address}:#{backend.fetch("address")}:#{index}", rule_digest(rule))
          # Without an external masquerade policy the SNAT chain exists only
          # for hairpin traffic: a Pod reaching itself through the Service.
          # Every other client keeps its source address (kube-proxy parity).
          expressions = snat_match_expressions(rule, family, backend, hairpin_only: true) + [masquerade_expression]
          {"chain" => chain_name, "marker" => marker_value,
           "message" => new_rule_message(chain_name: chain_name, marker: marker_value, expressions: expressions)}
        end
      end

      def snat_match_expressions(rule, family, backend, hairpin_only: false)
        expressions = [expression("meta", attributes(attribute(NFTA_META_DREG, u32(1)),
                                                     attribute(NFTA_META_KEY, u32(NFT_META_NFPROTO)))),
                       compare_expression(1, family)]
        expressions.concat(source_address_expression(family, address: backend.fetch("address"))) if hairpin_only
        expressions += [
          expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(1)),
                                           attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_NETWORK_HEADER)),
                                           attribute(NFTA_PAYLOAD_OFFSET, u32(family == NFPROTO_IPV6 ? 24 : 16)),
                                           attribute(NFTA_PAYLOAD_LEN, u32(family == NFPROTO_IPV6 ? 16 : 4)))),
          compare_expression(1, IPAddr.new(backend.fetch("address")).hton),
          expression("meta", attributes(attribute(NFTA_META_DREG, u32(1)),
                                        attribute(NFTA_META_KEY, u32(NFT_META_L4PROTO)))),
          compare_expression(1, protocol_number(rule.protocol)),
          expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(1)),
                                           attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_TRANSPORT_HEADER)),
                                           attribute(NFTA_PAYLOAD_OFFSET, u32(2)),
                                           attribute(NFTA_PAYLOAD_LEN, u32(2))))
        ]
        expressions << compare_expression(1, [backend.fetch("port")].pack("n"))
        expressions
      end

      def new_rule_message(chain_name:, marker:, expressions:)
        expression_list = expressions.map { |item| attribute(NFTA_LIST_ELEM, item, nested: true) }.join
        {type: NFT_MSG_NEWRULE, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
         family: NFPROTO_INET,
         attributes: attributes(attribute(NFTA_RULE_TABLE, cstring(@table_name)),
                                attribute(NFTA_RULE_CHAIN, cstring(chain_name)),
                                attribute(NFTA_RULE_EXPRESSIONS, expression_list, nested: true),
                                attribute(NFTA_RULE_USERDATA, marker))}
      end

      def source_address_expression(family, address: nil)
        payload_offset = family == NFPROTO_IPV6 ? 8 : 12
        payload_length = family == NFPROTO_IPV6 ? 16 : 4
        expressions = [expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(2)),
                                                        attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_NETWORK_HEADER)),
                                                        attribute(NFTA_PAYLOAD_OFFSET, u32(payload_offset)),
                                                        attribute(NFTA_PAYLOAD_LEN, u32(payload_length))))]
        expressions << compare_expression(2, IPAddr.new(address).hton) if address
        expressions
      end

      # How one backend is chosen out of several.
      #
      # The graph has one rule per endpoint and every rule re-evaluates the
      # selector, so the selector must give the SAME answer to every rule for a
      # given connection -- `numgen random` does not (measured: almost a third
      # of packets matched no rule and every ClusterIP became intermittently
      # unreachable).
      #
      # It must also NOT give the same answer to every connection from one
      # client unless the Service asked for that.  Hashing the source address
      # alone did exactly that: every Service behaved as `sessionAffinity:
      # ClientIP`, and "[sig-network] Services should be able to switch session
      # affinity" -- which turns affinity off and requires requests to spread --
      # failed with "Affinity shouldn't hold but did".  Hashing the source
      # address AND source port is constant within a connection (a NAT rule only
      # ever sees its first packet) and differs between connections, which is
      # the spread kube-proxy gets from `numgen random` in its vmap.  ClientIP
      # affinity keeps the address-only hash alongside its timeout set.
      def source_hash_expression(family, modulus, _rule, include_port: false)
        length = family == NFPROTO_IPV6 ? 16 : 4
        length += 4 if include_port
        seed = 0
        [expression("hash", attributes(attribute(NFTA_HASH_SREG, u32(2)), attribute(NFTA_HASH_DREG, u32(1)),
                                       attribute(NFTA_HASH_LEN, u32(length)), attribute(NFTA_HASH_MODULUS, u32(modulus)),
                                       attribute(NFTA_HASH_SEED, u32(seed)), attribute(NFTA_HASH_OFFSET, u32(0)),
                                       attribute(NFTA_HASH_TYPE, u32(NFT_HASH_JENKINS))))]
      end

      # NFT_REG32_05 (IPv4) / NFT_REG32_08 (IPv6) is the 4-byte word right after
      # the source address in NFT_REG_2, so the hash reads address . port as one
      # contiguous key.  The transport header's first two bytes are the source
      # port for TCP, UDP and SCTP alike; the kernel zero-pads the word.
      NFT_REG32_05 = 13
      NFT_REG32_08 = 16

      def source_port_expression(family)
        register = family == NFPROTO_IPV6 ? NFT_REG32_08 : NFT_REG32_05
        [expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(register)),
                                          attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_TRANSPORT_HEADER)),
                                          attribute(NFTA_PAYLOAD_OFFSET, u32(0)),
                                          attribute(NFTA_PAYLOAD_LEN, u32(2))))]
      end

      def lookup_expressions(set_name, set_id = nil)
        values = [attribute(NFTA_LOOKUP_SET, cstring(set_name)),
                  attribute(NFTA_LOOKUP_SREG, u32(2)),
                  attribute(NFTA_LOOKUP_DREG, u32(1))]
        values << attribute(NFTA_LOOKUP_SET_ID, u32(set_id)) if set_id
        [expression("lookup", attributes(*values))]
      end

      def dynset_expression(set_name, _timeout_seconds, set_id = nil)
        values = [attribute(NFTA_DYNSET_SET_NAME, cstring(set_name)),
                  attribute(NFTA_DYNSET_OP, u32(NFT_DYNSET_OP_ADD)),
                  attribute(NFTA_DYNSET_SREG_KEY, u32(2)),
                  attribute(NFTA_DYNSET_SREG_DATA, u32(1))]
        values.insert(1, attribute(NFTA_DYNSET_SET_ID, u32(set_id))) if set_id
        # The map's default timeout is authoritative.  Supplying a second
        # timeout is rejected by older kernels for dynamic maps.
        [expression("dynset", attributes(*values))]
      end

      def masquerade_expression
        expression("masq", nil)
      end

      def reject_expression
        expression("reject", attributes(attribute(1, u32(2)), attribute(2, u8(0))))
      end

      def delete_rule_message(item)
        {type: NFT_MSG_DELRULE, flags: NLM_F_REQUEST | NLM_F_ACK, family: NFPROTO_INET,
         attributes: attributes(attribute(NFTA_RULE_TABLE, cstring(@table_name)),
                                attribute(NFTA_RULE_CHAIN, cstring(item.fetch("chain"))),
                                attribute(NFTA_RULE_HANDLE, u64(item.fetch("handle"))))}
      end

      def delete_set_element_message(item)
        key_data = attribute(NFTA_DATA_VALUE, item.fetch("key"))
        element = attribute(NFTA_SET_ELEM_KEY, key_data, nested: true)
        list_attributes = [attribute(NFTA_SET_ELEM_LIST_TABLE, cstring(@table_name)),
                           attribute(NFTA_SET_ELEM_LIST_SET, cstring(item.fetch("set")))]
        list_attributes << attribute(NFTA_SET_ELEM_LIST_SET_ID, u32(item.fetch("set_id"))) if item["set_id"]
        {type: NFT_MSG_DELSETELEM, flags: NLM_F_REQUEST | NLM_F_ACK, family: NFPROTO_INET,
         attributes: attributes(*list_attributes,
                                attribute(NFTA_SET_ELEM_LIST_ELEMENTS,
                                          attribute(NFTA_LIST_ELEM, element, nested: true), nested: true))}
      end

      def delete_set_message(item)
        {type: NFT_MSG_DELSET, flags: NLM_F_REQUEST | NLM_F_ACK, family: NFPROTO_INET,
         attributes: attributes(attribute(NFTA_SET_TABLE, cstring(@table_name)),
                                attribute(NFTA_SET_NAME, cstring(item.fetch("name"))))}
      end

      def delete_chain_message(item)
        {type: NFT_MSG_DELCHAIN, flags: NLM_F_REQUEST | NLM_F_ACK, family: NFPROTO_INET,
         attributes: attributes(attribute(NFTA_CHAIN_TABLE, cstring(@table_name)),
                                attribute(NFTA_CHAIN_NAME, cstring(item.fetch("name"))))}
      end

      def service_match_expressions(rule, family:, destination_address:, source_range: nil)
        expressions = []
        expressions << expression("meta", attributes(attribute(NFTA_META_DREG, u32(1)),
                                                     attribute(NFTA_META_KEY, u32(NFT_META_NFPROTO))))
        expressions << compare_expression(1, family)
        if destination_address
          payload_offset = family == NFPROTO_IPV6 ? 24 : 16
          payload_length = family == NFPROTO_IPV6 ? 16 : 4
          expressions << expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(1)),
                                                          attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_NETWORK_HEADER)),
                                                          attribute(NFTA_PAYLOAD_OFFSET, u32(payload_offset)),
                                                          attribute(NFTA_PAYLOAD_LEN, u32(payload_length))))
          expressions << compare_expression(1, IPAddr.new(destination_address).hton)
        end
        expressions.concat(source_range_expression(family, source_range)) if source_range
        protocol = protocol_number(rule.protocol)
        expressions << expression("meta", attributes(attribute(NFTA_META_DREG, u32(1)),
                                                     attribute(NFTA_META_KEY, u32(NFT_META_L4PROTO))))
        # nft_data scalar values are host-order register bytes. Passing the
        # integer (rather than the NLA_U32 encoding) keeps l4proto as TCP /
        # UDP / SCTP in the kernel expression.
        expressions << compare_expression(1, protocol)
        expressions << expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(1)),
                                                        attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_TRANSPORT_HEADER)),
                                                        attribute(NFTA_PAYLOAD_OFFSET, u32(2)),
                                                        attribute(NFTA_PAYLOAD_LEN, u32(2))))
        expressions << compare_expression(1, [service_port(rule)].pack("n"))
        expressions
      end

      def source_ranges_for(rule, family)
        return [nil] unless rule.kind.to_s == "LoadBalancer"

        metadata = rule.metadata.is_a?(Hash) ? rule.metadata : {}
        ranges = Array(metadata["loadBalancerSourceRanges"] || metadata[:loadBalancerSourceRanges])
        return [nil] if ranges.empty?

        ranges.filter_map do |value|
          range = IPAddr.new(value.to_s)
          range if family_for_address(range.to_s) == family
        rescue ArgumentError
          nil
        end
      end

      def source_range_expression(family, range)
        ip = range.is_a?(IPAddr) ? range : IPAddr.new(range.to_s)
        length = family == NFPROTO_IPV6 ? 16 : 4
        mask = IPAddr.new(ip.netmask).hton
        network = ip.mask(ip.prefix).hton
        bitwise = expression("bitwise", attributes(
          attribute(NFTA_BITWISE_SREG, u32(2)),
          attribute(NFTA_BITWISE_DREG, u32(2)),
          attribute(NFTA_BITWISE_LEN, u32(length)),
          attribute(NFTA_BITWISE_MASK, attribute(NFTA_DATA_VALUE, mask), nested: true),
          attribute(NFTA_BITWISE_XOR, attribute(NFTA_DATA_VALUE, "\0".b * length), nested: true)
        ))
        source_address_expression(family) + [bitwise, compare_expression(2, network)]
      end

      def source_range_identity(range)
        "#{range}/#{range.prefix}"
      end

      def nat_expressions(rule, backend)
        masquerade_for?(rule) ? ct_mark_set_expressions + dnat_expressions(backend) : dnat_expressions(backend)
      end

      def ct_mark_set_expressions
        [expression("immediate", attributes(attribute(NFTA_IMMEDIATE_DREG, u32(1)),
                                            attribute(NFTA_IMMEDIATE_DATA,
                                                      attribute(NFTA_DATA_VALUE, [MASQUERADE_CT_MARK].pack("L")), nested: true))),
         expression("ct", attributes(attribute(NFTA_CT_KEY, u32(NFT_CT_MARK)), attribute(NFTA_CT_SREG, u32(1))))]
      end

      def ct_mark_match_expressions
        [expression("ct", attributes(attribute(NFTA_CT_KEY, u32(NFT_CT_MARK)), attribute(NFTA_CT_DREG, u32(1)))),
         expression("bitwise", attributes(attribute(NFTA_BITWISE_SREG, u32(1)),
                                          attribute(NFTA_BITWISE_DREG, u32(1)),
                                          attribute(NFTA_BITWISE_LEN, u32(4)),
                                          attribute(NFTA_BITWISE_MASK, attribute(NFTA_DATA_VALUE, [MASQUERADE_CT_MARK].pack("L")),
                                                    nested: true),
                                          attribute(NFTA_BITWISE_XOR, attribute(NFTA_DATA_VALUE, "\0\0\0\0".b), nested: true))),
         compare_expression(1, [MASQUERADE_CT_MARK].pack("L"))]
      end

      def dnat_expressions(backend)
        address = IPAddr.new(backend.fetch("address"))
        family = family_for_address(address.to_s)
        address_reg = address.hton
        # nft_data register slots are four bytes on the wire. The protocol
        # value occupies the first two bytes, followed by register padding;
        # this is the byte order required by the kernel NAT expression.
        # The NAT proto registers are 16-bit loads; a wider immediate is
        # accepted by the kernel but misreported by nft(8) as a 32-bit port.
        port_reg = [Integer(backend.fetch("port"))].pack("n")
        [expression("immediate", attributes(attribute(NFTA_IMMEDIATE_DREG, u32(1)),
                                            attribute(NFTA_IMMEDIATE_DATA,
                                                      attribute(NFTA_DATA_VALUE, address_reg), nested: true))),
         expression("immediate", attributes(attribute(NFTA_IMMEDIATE_DREG, u32(2)),
                                            attribute(NFTA_IMMEDIATE_DATA,
                                                      attribute(NFTA_DATA_VALUE, port_reg), nested: true))),
         expression("nat", attributes(attribute(NFTA_NAT_TYPE, u32(NFT_NAT_DNAT)),
                                      attribute(NFTA_NAT_FAMILY, u32(family)),
                                      attribute(NFTA_NAT_REG_ADDR_MIN, u32(1)),
                                      attribute(NFTA_NAT_REG_PROTO_MIN, u32(2)),
                                      attribute(NFTA_NAT_FLAGS, u32(NF_NAT_RANGE_PROTO_SPECIFIED))))]
      end

      def compare_expression(register, value)
        value = data_u32(value) if value.is_a?(Integer)
        data = attribute(NFTA_DATA_VALUE, value)
        expression("cmp", attributes(attribute(NFTA_CMP_SREG, u32(register)), attribute(NFTA_CMP_OP, u32(NFT_CMP_EQ)),
                                     attribute(NFTA_CMP_DATA, data, nested: true)))
      end

      def compare_not_equal_expression(register, value)
        data = attribute(NFTA_DATA_VALUE, value)
        expression("cmp", attributes(attribute(NFTA_CMP_SREG, u32(register)), attribute(NFTA_CMP_OP, u32(NFT_CMP_NEQ)),
                                     attribute(NFTA_CMP_DATA, data, nested: true)))
      end

      def expression(name, data)
        body = attribute(NFTA_EXPR_NAME, cstring(name))
        body += attribute(NFTA_EXPR_DATA, data, nested: true) unless data.nil? || data.empty?
        body
      end

      def desired_endpoint(address, port, backend: nil, rule: nil)
        ip = IPAddr.new(address.to_s)
        normalized_port = normalize_port(port, "endpoint port")
        local_node = rule && rule.metadata.is_a?(Hash) ? rule.metadata["node"] || rule.metadata[:node] : nil
        endpoint_hints = if backend.respond_to?(:hints)
                           Array(backend.hints).map(&:to_s)
                         else
                           Array(backend.is_a?(Hash) && (backend["hints"] || backend[:hints])).map(&:to_s)
                         end
        node_name = if backend.respond_to?(:node_name)
                      backend.node_name
                    elsif backend.is_a?(Hash)
                      backend["nodeName"] || backend[:nodeName] || backend["node_name"] || backend[:node_name]
                    end
        healthy = backend.respond_to?(:healthy?) ? backend.healthy? : true
        serving = backend.respond_to?(:serving?) ? backend.serving? : healthy
        terminating = backend.respond_to?(:terminating?) ? backend.terminating? : false
        {"address" => ip.to_s, "port" => normalized_port, "packed_address" => ip.hton,
         "node" => node_name.to_s, "local" => !local_node.to_s.empty? && node_name.to_s == local_node.to_s,
         "healthy" => healthy, "serving" => serving, "terminating" => terminating,
         "hints" => endpoint_hints.freeze}
      rescue ArgumentError, TypeError => error
        raise NftablesNetlinkError, "invalid nftables backend endpoint #{address.inspect}:#{port.inspect}: #{error.message}"
      end

      def service_port(rule)
        normalize_port(rule.node_port || rule.port, "service port")
      end

      def normalize_port(value, label)
        port = Integer(value)
        raise NftablesNetlinkError, "#{label} must be between 1 and 65535" unless port.between?(1, 65_535)

        port
      rescue ArgumentError, TypeError => error
        raise NftablesNetlinkError, "#{label} is invalid: #{error.message}"
      end

      def endpoints_for(rule)
        endpoints = Array(rule.backends).map do |backend|
          address = backend.respond_to?(:address) ? backend.address : backend.to_h.fetch("address")
          port = backend.respond_to?(:port) ? backend.port : backend.to_h.fetch("port")
          desired_endpoint(address, port, backend: backend, rule: rule)
        end.sort_by { |endpoint| [endpoint.fetch("address"), endpoint.fetch("port")] }
        endpoints = if rule.health_check
                      local_node = rule.metadata.is_a?(Hash) ? (rule.metadata["node"] || rule.metadata[:node]) : nil
                      candidates = local_node.to_s.empty? ? endpoints : endpoints.select { |endpoint| endpoint.fetch("local") }
                      candidates.select { |endpoint| endpoint.fetch("healthy") }
                    else
                      apply_policy_and_health(rule, endpoints)
                    end
        apply_topology_hints(rule, endpoints)
      end

      def apply_policy_and_health(rule, endpoints)
        policy = external_rule?(rule) ? rule.external_traffic_policy : rule.internal_traffic_policy
        local_node = rule.metadata.is_a?(Hash) ? (rule.metadata["node"] || rule.metadata[:node]) : nil
        endpoints = endpoints.select { |endpoint| endpoint.fetch("local") } if policy.to_s == "Local" && !local_node.to_s.empty?
        metadata = rule.metadata.is_a?(Hash) ? rule.metadata : {}
        if metadata["publishNotReadyAddresses"]
          non_terminating = endpoints.reject { |endpoint| endpoint.fetch("terminating") }
          return non_terminating unless non_terminating.empty?

          return endpoints.select { |endpoint| endpoint.fetch("terminating") && endpoint.fetch("serving") }
        end

        healthy = endpoints.select { |endpoint| endpoint.fetch("healthy") }
        return healthy unless healthy.empty?

        endpoints.select { |endpoint| endpoint.fetch("terminating") && endpoint.fetch("serving") }
      end

      def apply_topology_hints(rule, endpoints)
        metadata = rule.metadata.is_a?(Hash) ? rule.metadata : {}
        return endpoints if metadata.key?("topologyAwareHints") && !metadata["topologyAwareHints"]

        zone = metadata["zone"] || metadata[:zone]
        return endpoints if zone.to_s.empty? || rule.internal_traffic_policy.to_s == "Local"
        return endpoints unless endpoints.all? { |endpoint| !endpoint.fetch("hints").empty? }

        hinted = endpoints.select { |endpoint| endpoint.fetch("hints").include?(zone.to_s) }
        hinted.empty? ? endpoints : hinted
      end

      def external_rule?(rule)
        %w[NodePort LoadBalancer ExternalIP].include?(rule.kind.to_s)
      end

      def client_ip_affinity?(rule)
        rule.session_affinity.to_s == "ClientIP"
      end

      def masquerade_for?(rule)
        external_rule?(rule) && rule.external_traffic_policy.to_s == "Cluster"
      end

      def snat_endpoints_for(rule, endpoints)
        endpoints.select { |endpoint| masquerade_for?(rule) || hairpin_for?(rule, endpoint) }
      end

      def hairpin_for?(rule, endpoint)
        return false unless rule.virtual_ip
        return false unless endpoint.fetch("local")

        true
      end

      def endpoint_families(rule, endpoints)
        return [family_for_address(rule.virtual_ip)] if rule.virtual_ip

        families = endpoints.map { |endpoint| family_for_address(endpoint.fetch("address")) }.uniq
        families.empty? ? [NFPROTO_IPV4] : families.sort
      end

      def destination_addresses_for(rule, family)
        return [rule.virtual_ip] if rule.virtual_ip

        metadata = rule.metadata.is_a?(Hash) ? rule.metadata : {}
        addresses = Array(metadata["nodeAddresses"] || metadata[:nodeAddresses] || metadata["node_addresses"] || metadata[:node_addresses])
          .filter_map do |address|
            canonical = IPAddr.new(address.to_s).to_s
            family_for_address(canonical) == family ? canonical : nil
        rescue ArgumentError
          nil
          end.uniq
        addresses.empty? ? [nil] : addresses
      end

      def family_for_address(address)
        IPAddr.new(address.to_s).ipv6? ? NFPROTO_IPV6 : NFPROTO_IPV4
      end

      def protocol_number(protocol)
        {"TCP" => 6, "UDP" => 17, "SCTP" => 132}.fetch(protocol.to_s.upcase) do
          raise NftablesNetlinkError, "unsupported nftables service protocol #{protocol.inspect}"
        end
      end

      def service_chain_name(rule)
        "svc_#{Digest::SHA256.hexdigest(rule_identity(rule))[0, 24]}"
      end

      def endpoint_set_name(rule, family = nil)
        suffix = family == NFPROTO_IPV6 ? "6" : "4"
        "ep_#{Digest::SHA256.hexdigest(rule_identity(rule))[0, 20]}_#{suffix}"
      end

      def affinity_set_name(rule, family)
        suffix = family == NFPROTO_IPV6 ? "6" : "4"
        "aff_#{Digest::SHA256.hexdigest(rule_identity(rule))[0, 16]}_#{affinity_backend_digest(rule)}_#{suffix}"
      end

      def affinity_set_identity(rule, family)
        "#{rule_identity(rule)}:#{family}:#{affinity_backend_digest(rule)}"
      end

      def affinity_backend_digest(rule)
        Digest::SHA256.hexdigest(rule_digest(rule))[0, 12]
      end

      def snat_chain_name(rule)
        "snat_#{Digest::SHA256.hexdigest(rule_identity(rule))[0, 20]}"
      end

      def rule_identity(rule)
        Array(rule.key).join("\0")
      end

      def rule_digest(rule)
        Digest::SHA256.digest(JSON.generate(rule.to_h))
      end

      def marker(kind, identity, semantic = "")
        MAGIC + kind.to_s + "\0" + Digest::SHA256.digest(identity.to_s) + Digest::SHA256.digest(semantic.to_s)
      end

      def marker_kind(value)
        bytes = String(value).b
        return nil unless bytes.start_with?(MAGIC)

        rest = bytes.byteslice(MAGIC.bytesize..)
        rest&.split("\0", 2)&.first
      end

      def marker_owned?(value)
        !marker_kind(value).nil?
      end

      def verify_readback(actual, desired)
        return false unless actual["table"]
        return false unless actual["table"]["name"] == desired["table"]["name"]
        return false unless actual["table"]["marker"] == desired["table"]["marker"]

        same_objects?(actual.fetch("chains"), desired.fetch("chains"), %w[name marker]) &&
          same_objects?(actual.fetch("sets"), desired.fetch("sets"),
                        %w[name marker flags key_type key_len data_type data_len timeout]) &&
          same_objects?(readback_static_elements(actual), desired.fetch("set_elements"), %w[set key marker]) &&
          same_objects?(actual.fetch("rules"), desired.fetch("rules"), %w[chain marker])
      rescue KeyError, TypeError
        false
      end

      def readback_static_elements(actual)
        affinity_sets = affinity_set_names(actual.fetch("sets"))
        actual.fetch("set_elements").reject do |item|
          affinity_sets.include?(item["set"]) && !marker_owned?(item["marker"])
        end
      end

      def affinity_set_names(sets)
        Array(sets).filter_map do |item|
          item.fetch("name") if marker_kind(item["marker"]) == "affinity"
        end
      end

      def same_objects?(actual, desired, fields)
        actual.map { |item| fields.map { |field| item.fetch(field) } }.sort ==
          desired.map { |item| fields.map { |field| item.fetch(field) } }.sort
      end

      def ensure_owned_table!(actual)
        table = actual["table"]
        return unless table
        return if table.is_a?(Hash) && table["marker"] == marker("table", @table_name)

        raise NftablesNetlinkError, "refusing to modify nftables table #{@table_name.inspect} without an owned userdata marker"
      end

      def ensure_owned_objects!(actual)
        %w[chains sets rules].each do |key|
          foreign = actual.fetch(key).find { |item| !item.is_a?(Hash) || !marker_owned?(item["marker"]) }
          next unless foreign

          raise NftablesNetlinkError,
                "refusing to modify unmarked nftables #{key.delete_suffix('s')} in owned table #{@table_name.inspect}"
        end
        affinity_sets = affinity_set_names(actual.fetch("sets"))
        foreign_element = actual.fetch("set_elements").find do |item|
          !marker_owned?(item["marker"]) && !affinity_sets.include?(item["set"])
        end
        return unless foreign_element

        raise NftablesNetlinkError,
              "refusing to modify unmarked nftables set element in owned table #{@table_name.inspect}"
      end

      def read_kernel_ruleset
        if @transport.respond_to?(:readback)
          return normalize_transport_readback(@transport.readback(table_name: @table_name, family: NFPROTO_INET))
        end

        table_entries = dump(NFT_MSG_GETTABLE)
        table = table_entries.find { |entry| entry.fetch("name") == @table_name }
        return empty_readback unless table

        chain_entries = dump(NFT_MSG_GETCHAIN,
                             attributes: attribute(NFTA_CHAIN_TABLE, cstring(@table_name)))
          .select { |entry| entry.fetch("table") == @table_name }
        set_entries = dump(NFT_MSG_GETSET,
                           attributes: attribute(NFTA_SET_TABLE, cstring(@table_name)))
          .select { |entry| entry.fetch("table") == @table_name }
        rule_entries = dump(NFT_MSG_GETRULE,
                            attributes: attribute(NFTA_RULE_TABLE, cstring(@table_name)))
          .select { |entry| entry.fetch("table") == @table_name }
        element_entries = set_entries.flat_map do |set|
          dump(NFT_MSG_GETSETELEM,
               attributes: attributes(attribute(NFTA_SET_ELEM_LIST_TABLE, cstring(@table_name)),
                                      attribute(NFTA_SET_ELEM_LIST_SET, cstring(set.fetch("name")))))
        end.select { |entry| entry.fetch("table") == @table_name && entry["key"] }
        {
          "table" => table,
          "chains" => chain_entries,
          "sets" => set_entries,
          "set_elements" => element_entries,
          "rules" => rule_entries
        }
      rescue NftablesNetlinkError => error
        return empty_readback if error.errno == Errno::ENOENT::Errno

        raise
      end

      def empty_readback
        {"table" => nil, "chains" => [], "sets" => [], "set_elements" => [], "rules" => []}
      end

      def normalize_transport_readback(value)
        value = empty_readback unless value.is_a?(Hash)
        value.transform_keys(&:to_s).merge("chains" => Array(value["chains"] || value[:chains]),
                                           "sets" => Array(value["sets"] || value[:sets]),
                                           "set_elements" => Array(value["set_elements"] || value[:set_elements]),
                                           "rules" => Array(value["rules"] || value[:rules]))
      end

      def dump(type, attributes: "")
        if @transport.respond_to?(:dump)
          value = @transport.dump(type: type, family: NFPROTO_INET, attributes: attributes)
          return Array(value).map { |entry| normalize_readback_entry(entry, type) }
        end
        sequence = next_sequence
        request = netlink_message(nft_message_type(type), NLM_F_REQUEST | NLM_F_DUMP, sequence,
                                  nfgen_payload(NFPROTO_INET) + attributes.to_s)
        with_socket do |socket|
          send_bytes(socket, request, operation: "nftables dump")
          receive_dump(socket, sequence: sequence, type: type)
        end
      end

      def normalize_readback_entry(entry, type)
        return entry if entry.is_a?(Hash) && entry.key?("marker")

        if entry.is_a?(Hash)
          hash = entry.transform_keys(&:to_s)
          hash["marker"] ||= hash["userdata"]
          hash["type"] ||= type
          return hash
        end
        raise NftablesNetlinkError, "transport returned an invalid nftables readback entry"
      end

      def receive_dump(socket, sequence:, type:)
        entries = []
        deadline = monotonic_now + @timeout
        loop do
          buffer = receive_bytes(socket, deadline: deadline, operation: "nftables dump")
          messages = parse_messages(buffer)
          messages.each do |message|
            next unless message.sequence == sequence

            raise_kernel_error!(message, operation: "nftables dump") if message.type == NLMSG_ERROR
            next if message.type == NLMSG_DONE
            next unless message.type == nft_message_type(dump_reply_type(type))

            decoded = decode_readback_entry(message.payload, type)
            if decoded.is_a?(Array)
              entries.concat(decoded)
            else
              entries << decoded
            end
          end
          break if messages.any? { |message| message.sequence == sequence && message.type == NLMSG_DONE }
        end
        entries
      end

      def decode_readback_entry(payload, type)
        attrs = decode_attributes(payload.byteslice(NFGENMSG_SIZE..).to_s)
        case type
        when NFT_MSG_GETTABLE
          {"name" => string_value(attrs, NFTA_TABLE_NAME), "marker" => value(attrs, NFTA_TABLE_USERDATA)}
        when NFT_MSG_GETCHAIN
          {"table" => string_value(attrs, NFTA_CHAIN_TABLE),
           "name" => string_value(attrs, NFTA_CHAIN_NAME), "marker" => value(attrs, NFTA_CHAIN_USERDATA),
           "handle" => uint64_value(attrs, NFTA_CHAIN_HANDLE)}
        when NFT_MSG_GETSET
          {"table" => string_value(attrs, NFTA_SET_TABLE),
           "name" => string_value(attrs, NFTA_SET_NAME), "marker" => value(attrs, NFTA_SET_USERDATA),
           "handle" => uint64_value(attrs, NFTA_SET_HANDLE),
           "flags" => uint32_value(attrs, NFTA_SET_FLAGS) || 0,
           "key_type" => uint32_value(attrs, NFTA_SET_KEY_TYPE),
           "key_len" => uint32_value(attrs, NFTA_SET_KEY_LEN),
           "data_type" => uint32_value(attrs, NFTA_SET_DATA_TYPE),
           "data_len" => uint32_value(attrs, NFTA_SET_DATA_LEN),
           "timeout" => uint64_value(attrs, NFTA_SET_TIMEOUT)}
        when NFT_MSG_GETRULE
          {"table" => string_value(attrs, NFTA_RULE_TABLE),
           "chain" => string_value(attrs, NFTA_RULE_CHAIN), "marker" => value(attrs, NFTA_RULE_USERDATA),
           "handle" => uint64_value(attrs, NFTA_RULE_HANDLE)}
        when NFT_MSG_GETSETELEM
          decode_set_element_entries(attrs)
        else
          raise NftablesNetlinkError, "unsupported nftables readback type #{type}"
        end
      end

      def dump_reply_type(type)
        {
          NFT_MSG_GETTABLE => NFT_MSG_NEWTABLE,
          NFT_MSG_GETCHAIN => NFT_MSG_NEWCHAIN,
          NFT_MSG_GETRULE => NFT_MSG_NEWRULE,
          NFT_MSG_GETSET => NFT_MSG_NEWSET,
          NFT_MSG_GETSETELEM => NFT_MSG_NEWSETELEM
        }.fetch(type)
      end

      def decode_set_element_entries(attrs)
        list = nested_value(attrs, NFTA_SET_ELEM_LIST_ELEMENTS)
        set_name = string_value(attrs, NFTA_SET_ELEM_LIST_SET)
        set_id = uint32_value(attrs, NFTA_SET_ELEM_LIST_SET_ID)
        decode_attributes(list).filter_map do |list_entry|
          next unless list_entry.fetch("type") == NFTA_LIST_ELEM

          element_attrs = decode_attributes(list_entry.fetch("value"))
          key_data = nested_value(element_attrs, NFTA_SET_ELEM_KEY)
          key_attrs = decode_attributes(key_data)
          data_data = nested_value(element_attrs, NFTA_SET_ELEM_DATA)
          data_attrs = decode_attributes(data_data) unless data_data.empty?
          {"table" => string_value(attrs, NFTA_SET_ELEM_LIST_TABLE), "set" => set_name, "set_id" => set_id,
           "marker" => value(element_attrs, NFTA_SET_ELEM_USERDATA),
           "key" => value(key_attrs, NFTA_DATA_VALUE),
           "data" => data_attrs && value(data_attrs, NFTA_DATA_VALUE),
           "flags" => uint32_value(element_attrs, NFTA_SET_ELEM_FLAGS),
           "timeout" => uint64_value(element_attrs, NFTA_SET_ELEM_TIMEOUT),
           "expiration" => uint64_value(element_attrs, NFTA_SET_ELEM_EXPIRATION)}
        end
      end

      def send_transaction(messages)
        return {"messageCount" => 0, "acknowledgedSequences" => [], "bytes" => 0} if messages.empty?

        if @transport.respond_to?(:send_transaction)
          result = @transport.send_transaction(messages: messages, family: NFPROTO_INET)
          raise NftablesNetlinkError, "transport did not return a transaction acknowledgment" unless result

          return result
        end

        command_sequences = []
        sequence = next_sequence
        body = netlink_message(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0, nfgen_payload(AF_UNSPEC, NFNL_SUBSYS_NFTABLES))
        messages.each do |message|
          message_sequence = next_sequence
          command_sequences << message_sequence
          body << netlink_message(nft_message_type(message.fetch(:type)), message.fetch(:flags), message_sequence,
                                  nfgen_payload(message.fetch(:family, NFPROTO_INET)) + message.fetch(:attributes).to_s)
        end
        body << netlink_message(NFNL_MSG_BATCH_END, NLM_F_REQUEST, sequence, nfgen_payload(AF_UNSPEC, NFNL_SUBSYS_NFTABLES))
        raise NftablesNetlinkError, "nftables transaction exceeds #{MAX_MESSAGE_BYTES} bytes" if body.bytesize > MAX_MESSAGE_BYTES

        with_socket do |socket|
          send_bytes(socket, body, operation: "nftables transaction")
          acknowledgements = receive_acknowledgements(socket, sequences: command_sequences)
          {"messageCount" => messages.length, "acknowledgedSequences" => acknowledgements,
           "bytes" => body.bytesize}
        end
      end

      def receive_acknowledgements(socket, sequences:)
        pending = sequences.to_h { |sequence| [sequence, false] }
        deadline = monotonic_now + @timeout
        while pending.values.any?(&:!)
          buffer = receive_bytes(socket, deadline: deadline, operation: "nftables ACK")
          parse_messages(buffer).each do |message|
            next unless pending.key?(message.sequence)

            if message.type == NLMSG_ERROR
              raise_kernel_error!(message, operation: "nftables transaction")
              pending[message.sequence] = true
            end
          end
        end
        pending.keys.freeze
      end

      def raise_kernel_error!(message, operation:)
        code = message.error_code
        unless code.is_a?(Integer)
          raise NftablesNetlinkError.new("kernel returned a malformed #{operation} error message",
                                         operation: operation, sequence: message.sequence)
        end
        return if code.zero?

        errno = code.abs
        detail = errno_message(message)
        raise NftablesNetlinkError.new("kernel rejected #{operation}: errno #{errno}#{detail && ": #{detail}"}",
                                       errno: errno, operation: operation, sequence: message.sequence)
      end

      def errno_message(message)
        return nil if message.payload.bytesize <= 20

        attrs = decode_attributes(message.payload.byteslice(20..).to_s)
        value(attrs, 1)&.delete_suffix("\0")
      rescue NftablesNetlinkError
        nil
      end

      def with_socket
        socket = @socket_factory.call
        socket.bind([AF_NETLINK, 0, 0, 0].pack("S<S<L<L<")) if socket.respond_to?(:bind)
        configure_receive_path(socket)
        yield socket
      rescue NftablesNetlinkError
        raise
      rescue SystemCallError => error
        raise NftablesNetlinkError.new("nftables netlink I/O failed: #{error.message}", errno: error.errno,
                                                                                        operation: "netlink")
      ensure
        socket&.close if socket.respond_to?(:close)
      end

      # A transaction batch asks for one ACK per message; a large Service
      # rule set therefore answers with hundreds of NLMSG_ERROR records at
      # once.  The default receive buffer overflows (ENOBUFS on recvfrom) and
      # the batch outcome would be unknowable.  NETLINK_NO_ENOBUFS keeps the
      # kernel from poisoning the socket and the forced receive buffer holds
      # the whole ACK burst; a fixture socket without setsockopt is left alone.
      SOL_NETLINK = 270
      NETLINK_NO_ENOBUFS = 5
      SO_RCVBUFFORCE = 33
      RECEIVE_BUFFER_BYTES = 8 * 1024 * 1024

      def configure_receive_path(socket)
        return unless socket.respond_to?(:setsockopt)

        begin
          socket.setsockopt(SOL_NETLINK, NETLINK_NO_ENOBUFS, [1].pack("l"))
        rescue SystemCallError, IOError, TypeError, NoMethodError
          nil
        end
        begin
          socket.setsockopt(Socket::SOL_SOCKET, SO_RCVBUFFORCE, RECEIVE_BUFFER_BYTES)
        rescue SystemCallError, IOError, TypeError, NoMethodError
          begin
            socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, RECEIVE_BUFFER_BYTES)
          rescue SystemCallError, IOError, TypeError, NoMethodError
            nil
          end
        end
      end

      # SO_SNDBUFFORCE from <asm-generic/socket.h>; it lets a CAP_NET_ADMIN
      # process exceed net.core.wmem_max, which nft(8) also does for large
      # batches.  Plain SO_SNDBUF is the unprivileged fallback.
      SO_SNDBUFFORCE = 32
      NETLINK_SKB_OVERHEAD = 32

      def send_bytes(socket, bytes, operation:)
        ensure_send_buffer(socket, bytes.bytesize) if socket.respond_to?(:setsockopt)
        written = socket.send(bytes, 0)
        return if written == bytes.bytesize

        raise NftablesNetlinkError, "#{operation} was short-written (#{written}/#{bytes.bytesize} bytes)"
      rescue SystemCallError => error
        raise NftablesNetlinkError.new("#{operation} failed: #{error.message}", errno: error.errno, operation: operation)
      end

      # netlink_sendmsg rejects one datagram larger than sk_sndbuf - 32 with
      # EMSGSIZE, and a complete nftables batch must be one datagram so the
      # kernel applies it atomically.  Grow the buffer before sending.
      def ensure_send_buffer(socket, length)
        required = Integer(length) + NETLINK_SKB_OVERHEAD
        current = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF).int
        return if current >= required * 2

        begin
          socket.setsockopt(Socket::SOL_SOCKET, SO_SNDBUFFORCE, required * 2)
        rescue SystemCallError
          socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, required * 2)
        end
      rescue SystemCallError, IOError, TypeError, NoMethodError
        # A fixture socket without setsockopt/getsockopt keeps its default;
        # the kernel send below still reports EMSGSIZE if it was too small.
        nil
      end

      def receive_bytes(socket, deadline:, operation:)
        remaining = deadline - monotonic_now
        raise NftablesNetlinkError.new("#{operation} timed out", errno: Errno::ETIMEDOUT::Errno, operation: operation) if remaining <= 0

        ready = IO.select([socket], nil, nil, remaining)
        raise NftablesNetlinkError.new("#{operation} timed out", errno: Errno::ETIMEDOUT::Errno, operation: operation) unless ready

        socket.recv(MAX_MESSAGE_BYTES)
      rescue SystemCallError => error
        raise NftablesNetlinkError.new("#{operation} receive failed: #{error.message}", errno: error.errno, operation: operation)
      end

      def parse_messages(bytes)
        buffer = String(bytes).b
        offset = 0
        messages = []
        while offset + NETLINK_HEADER_SIZE <= buffer.bytesize
          length, type, flags, sequence, pid = buffer.byteslice(offset, NETLINK_HEADER_SIZE).unpack("L<S<S<L<L<")
          if length < NETLINK_HEADER_SIZE || offset + length > buffer.bytesize
            raise NftablesNetlinkError,
                  "nftables netlink message has invalid length #{length}"
          end

          payload = buffer.byteslice(offset + NETLINK_HEADER_SIZE, length - NETLINK_HEADER_SIZE).to_s.freeze
          messages << Message.new(type: type, flags: flags, sequence: sequence, pid: pid, payload: payload)
          offset += align(length)
        end
        raise NftablesNetlinkError, "nftables netlink message stream is truncated" unless offset == buffer.bytesize

        messages
      end

      def netlink_message(type, flags, sequence, payload)
        payload = String(payload).b
        length = NETLINK_HEADER_SIZE + payload.bytesize
        [length, Integer(type), Integer(flags), Integer(sequence), 0].pack("L<S<S<L<L<") + payload + ("\0" * (align(length) - length))
      end

      def nft_message_type(type)
        (NFNL_SUBSYS_NFTABLES << 8) | Integer(type)
      end

      def nfgen_payload(family, resource_id = 0)
        [Integer(family), 0, Integer(resource_id)].pack("CCn")
      end

      def attribute(type, body, nested: false)
        value = String(body).b
        attribute_type = Integer(type) | (nested ? NLA_F_NESTED : 0)
        length = 4 + value.bytesize
        raise NftablesNetlinkError, "nftables attribute is too large" if length > 0xffff

        [length, attribute_type].pack("S<S<") + value + ("\0" * (align(length) - length))
      end

      def attributes(*values)
        values.compact.join
      end

      def cstring(value)
        "#{String(value).delete("\0")}\0".b
      end

      def u32(value)
        [Integer(value) & 0xffff_ffff].pack("L>")
      end

      def u8(value)
        [Integer(value) & 0xff].pack("C")
      end

      def u64(value)
        [Integer(value) & 0xffff_ffff_ffff_ffff].pack("Q>")
      end

      # nft_data values are register bytes; the kernel represents scalar
      # register values in host order while NLA_U32/NLA_U64 attributes use
      # network order. Keep this distinct from u32/u64 to avoid silently
      # changing expression semantics when encoding attributes.
      def data_u32(value)
        [Integer(value) & 0xffff_ffff].pack("L<")
      end

      def align(length)
        (Integer(length) + 3) & ~3
      end

      def decode_attributes(bytes)
        buffer = String(bytes).b
        offset = 0
        values = []
        while offset + 4 <= buffer.bytesize
          length, type = buffer.byteslice(offset, 4).unpack("S<S<")
          raise NftablesNetlinkError, "nftables attribute has invalid length #{length}" if length < 4 || offset + length > buffer.bytesize

          values << {"type" => type & NLA_TYPE_MASK, "nested" => type.anybits?(NLA_F_NESTED),
                     "value" => buffer.byteslice(offset + 4, length - 4).to_s}
          offset += align(length)
        end
        raise NftablesNetlinkError, "nftables attribute stream is truncated" unless offset == buffer.bytesize

        values
      end

      def value(attrs, type)
        attrs.reverse_each do |entry|
          return entry.fetch("value") if entry.fetch("type") == type
        end
        nil
      end

      def nested_value(attrs, type)
        value(attrs, type).to_s
      end

      def string_value(attrs, type)
        value(attrs, type)&.delete_suffix("\0")
      end

      def uint64_value(attrs, type)
        body = value(attrs, type)
        body && body.bytesize >= 8 ? body.unpack1("Q>") : nil
      end

      def uint32_value(attrs, type)
        body = value(attrs, type)
        body && body.bytesize >= 4 ? body.unpack1("L>") : nil
      end

      def normalize_name(value, label)
        validate_name(value, label)
      end

      def validate_name(value, label)
        name = String(value)
        raise ArgumentError, "#{label} must not be empty" if name.empty?
        raise ArgumentError, "#{label} must not contain NUL" if name.include?("\0")
        raise ArgumentError, "#{label} exceeds nftables name limit" if name.bytesize >= 256

        name.freeze
      end

      def open_socket
        Socket.new(Socket::AF_NETLINK, Socket::SOCK_RAW, NETLINK_NETFILTER)
      end

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def next_sequence
        @mutex.synchronize do
          @sequence = (@sequence + 1) & 0xffff_ffff
          @sequence = 1 if @sequence.zero?
          @sequence
        end
      end
    end

    NativeNftablesAdapter = NftablesNetlinkAdapter unless const_defined?(:NativeNftablesAdapter, false)
  end
end
