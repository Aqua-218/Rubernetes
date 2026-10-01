# frozen_string_literal: true

require "json"
require "digest"
require "time"

require_relative "ebpf_program"

module Rubernetes
  module Proxy
    BackendStatus = Struct.new(:backend, :state, :reason, :checked_at, :error, keyword_init: true) do
      def initialize(**attributes)
        super
        freeze
      end

      def healthy?
        state.to_s == "ready"
      end

      def to_h
        {"backend" => backend.to_s, "state" => state.to_s, "reason" => reason.to_s,
         "checkedAt" => checked_at, "error" => error&.to_s}.compact
      end
    end

    ConnectionMeasurement = Struct.new(:from_backend, :to_backend, :started_at, :switched_at,
                                       :active_connections, :lost_connections, :duration_ms,
                                       :reason, :measurement_source, :runner_identity,
                                       :runner_digest, :raw_observation_digest, keyword_init: true) do
      def initialize(**attributes)
        super
        freeze
      end

      def connection_loss?
        lost_connections.to_i.positive?
      end

      def to_h
        {
          "fromBackend" => from_backend.to_s,
          "toBackend" => to_backend.to_s,
          "startedAt" => started_at,
          "switchedAt" => switched_at,
          "activeConnections" => active_connections.to_i,
          "lostConnections" => lost_connections.to_i,
          "durationMs" => duration_ms.to_f,
          "reason" => reason.to_s,
          "measurementSource" => measurement_source&.to_s,
          "runnerIdentity" => runner_identity&.to_s,
          "runnerDigest" => runner_digest&.to_s,
          "rawObservationDigest" => raw_observation_digest&.to_s
        }.compact
      end
    end

    # Shared rule application and packet lookup for both concrete backends.
    class Backend
      attr_reader :name, :revision, :last_diff, :attach_state, :last_error

      def initialize(name:, clock: -> { Time.now.utc }, syscall_adapter: nil, test_adapter: false)
        @name = name.to_s.freeze
        @clock = clock
        @syscall_adapter = syscall_adapter
        @test_adapter = !!test_adapter
        @mutex = Mutex.new
        @apply_mutex = Mutex.new
        @rules = {}
        @revision = 0
        @last_diff = RuleDiff.new
        @attach_state = :detached
        @last_error = nil
      end

      def backend_name
        name
      end

      alias type backend_name

      def ready?
        @mutex.synchronize { @attach_state == :attached || @attach_state == :ready }
      end

      # A concrete kernel backend is available only when its adapter declares
      # the boundary it implements and exposes a verification/readback hook.
      # Merely generating a JSON program or netlink payload is never enough to
      # advertise a usable datapath.
      def available?
        adapter_contract_available?
      end

      # A backend that can be attached now: its adapter is a real kernel
      # adapter (or an explicit test adapter) exposing the attach/verify
      # contract.  `available?` additionally requires the post-attach packet
      # proof; AutoBackend selects and attaches on attachability and reports
      # availability once the proof exists.
      def attachable?
        adapter_contract_available?(phase: :attach)
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      # Expose the same production boundary used by the adapter contract.
      # Parity evidence must name two real kernel-backed adapters; a rule
      # snapshot from MemoryBackend (or another model-only Backend) is not a
      # valid input even when a caller supplies plausible-looking evidence.
      def production_capable?
        adapter_contract_available? && adapter_authorized?
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def status
        state, error = @mutex.synchronize { [@attach_state, @last_error] }
        normalized_state = case state
                           when :attached, :ready then "ready"
                           when :failed then "failed"
                           when :attaching then "attaching"
                           else attachable? ? "unattached" : "unavailable"
                           end
        reason = case normalized_state
                 when "ready" then "attach verified"
                 when "attaching" then "attach in progress"
                 when "failed" then error&.message || "attach failed"
                 when "unattached" then "attach pending"
                 else "production-capable kernel adapter unavailable"
                 end
        BackendStatus.new(backend: name, state: normalized_state, reason: reason,
                          checked_at: @clock.call, error: error)
      end

      def rules
        @mutex.synchronize { @rules.values.sort_by(&:key).freeze }
      end

      def rule_map
        @mutex.synchronize { @rules.dup.freeze }
      end

      def digest
        Digest::SHA256.hexdigest(JSON.generate(ModelSupport.canonicalize(rules.map(&:to_h))))
      end

      def semantic_snapshot
        ModelSupport.canonicalize(rules.map(&:to_h)).freeze
      end

      # Concrete production adapters expose identities read from the live
      # kernel. Model and fixture adapters intentionally return nil.
      def kernel_identity
        return nil unless @syscall_adapter.respond_to?(:kernel_identity)

        @syscall_adapter.kernel_identity
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        nil
      end

      def semantics_equal?(other)
        other.respond_to?(:semantic_snapshot) && semantic_snapshot == other.semantic_snapshot
      end

      def apply(compiled_or_diff)
        if compiled_or_diff.is_a?(RuleDiff)
          apply_diff(compiled_or_diff)
        elsif compiled_or_diff.respond_to?(:rule_map)
          apply_compiled(compiled_or_diff)
        else
          current = RuleSet.new
          current.apply(rules, revision: @revision)
          current.apply(compiled_or_diff)
          apply_diff(current.last_diff)
        end
      end

      alias apply_rules apply

      def apply_compiled(compiled)
        incoming = compiled.rule_map
        @mutex.synchronize do
          compiled_revision = Integer(compiled.revision)
          raise StaleRevisionError, "compiled rule revision #{compiled_revision} is older than #{@revision}" if compiled_revision < @revision

          old_rules = @rules
          added = incoming.keys.reject { |key| old_rules.key?(key) }.map { |key| incoming.fetch(key) }
          deleted = old_rules.keys.reject { |key| incoming.key?(key) }.map { |key| old_rules.fetch(key) }
          updated = incoming.keys.filter_map do |key|
            old_rule = old_rules[key]
            new_rule = incoming[key]
            old_rule && new_rule != old_rule ? [old_rule, new_rule] : nil
          end
          diff = RuleDiff.new(added: added, updated: updated, deleted: deleted,
                              from_revision: @revision, to_revision: compiled.revision)
          apply_diff_locked(diff)
          @revision = compiled.revision
          @last_diff = diff
          diff
        end
      end

      def apply_diff(diff)
        normalized = diff.is_a?(RuleDiff) ? diff : RuleDiff.new(**diff)
        @mutex.synchronize { apply_diff_locked(normalized) }
        normalized
      end

      def attach(hook: :tc, **)
        @apply_mutex.synchronize do
          set_attach_state(:attaching)
          ensure_adapter_contract!(phase: :attach)
          operation_result = perform_attach(hook: hook, **)
          verify_adapter_effect!(phase: :attach, operation_result: operation_result,
                                 expected: expected_attach(hook: hook, **), hook: hook, **)
          @mutex.synchronize do
            @attach_state = :attached
            @last_error = nil
          end
        end
        true
      rescue BackendError => error
        fail_attach_state(error)
        raise
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError => error
        wrapped = BackendError.new("#{name} attach failed: #{error.message}")
        fail_attach_state(wrapped)
        raise wrapped
      end

      def detach(**)
        @apply_mutex.synchronize do
          @syscall_adapter.detach(backend: self, **) if @syscall_adapter.respond_to?(:detach)
          @mutex.synchronize do
            @attach_state = :detached
            @last_error = nil
          end
        end
        true
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError => error
        wrapped = error.is_a?(BackendError) ? error : BackendError.new("#{name} detach failed: #{error.message}")
        @mutex.synchronize { @last_error = wrapped }
        raise wrapped
      end

      def route(packet)
        normalized = packet.is_a?(Packet) ? packet : Packet.new(packet)
        candidates = @mutex.synchronize do
          @rules.values.select do |rule|
            rule.protocol == normalized.protocol &&
              (rule.virtual_ip.nil? || rule.virtual_ip == normalized.destination_ip) &&
              (rule.port == normalized.destination_port || rule.node_port == normalized.destination_port)
          end
        end
        candidates.min_by(&:key)
      end

      protected

      def adapter_contract_available?(phase: :strict)
        return false unless adapter_authorized?(phase: phase)
        return false unless adapter_operation_groups.all? do |group|
          Array(group).any? { |method_name| @syscall_adapter.respond_to?(method_name) }
        end

        adapter_verification_methods(:attach).any? { |method_name| @syscall_adapter.respond_to?(method_name) }
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def adapter_operation_groups
        [[:attach]]
      end

      def adapter_verification_methods(phase)
        case phase.to_sym
        when :transaction
          %i[verify_transaction verify_update verify_attach verify readback]
        when :update
          %i[verify_update verify_transaction verify readback]
        else
          %i[verify_attach verify_transaction verify readback]
        end
      end

      # A real kernel adapter can only *become* production-capable by
      # attaching and then receiving packet-semantics proof; requiring
      # production_capable? before the first attach would make a live
      # datapath unreachable.  The attach phase therefore accepts a
      # mechanically capable non-test adapter, while every other phase and
      # the production_capable? predicate keep the strict post-proof gate.
      def adapter_authorized?(phase: :strict)
        adapter = @syscall_adapter
        return false unless adapter

        if adapter.respond_to?(:production_capable?)
          return true if adapter.production_capable? == true
          return true if phase == :attach && adapter.respond_to?(:mechanically_capable?) &&
                         adapter.mechanically_capable? == true &&
                         !(adapter.respond_to?(:test_adapter?) && adapter.test_adapter? == true)

          return false
        end

        @test_adapter && adapter.respond_to?(:test_adapter?) && adapter.test_adapter? == true
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def ensure_adapter_contract!(phase: :attach)
        return true if adapter_contract_available?(phase: :attach)

        adapter = @syscall_adapter
        raise BackendError, "#{name} #{phase} requires a production-capable kernel adapter" if adapter.nil?
        unless adapter_authorized?(phase: :attach)
          raise BackendError, "#{name} #{phase} requires an adapter that declares production_capable?; " \
                              "use an explicit test_adapter: true only with a test_adapter? adapter"
        end

        missing_operations = adapter_operation_groups.filter_map do |group|
          next if Array(group).any? { |method_name| adapter.respond_to?(method_name) }

          Array(group).join(" or ")
        end
        raise BackendError, "#{name} #{phase} adapter is missing required operation: #{missing_operations.join(", ")}" unless missing_operations.empty?

        raise BackendError, "#{name} #{phase} adapter must expose verified attach/transaction readback"
      end

      def perform_attach(hook:, **)
        @syscall_adapter.attach(hook: hook, backend: self, **)
      end

      def expected_attach(hook:, **_options)
        {hook: hook}.freeze
      end

      def verify_adapter_effect!(phase:, operation_result:, expected:, hook:, **context)
        method_name = adapter_verification_methods(phase).find { |candidate| @syscall_adapter.respond_to?(candidate) }
        raise BackendError, "#{name} #{phase} adapter must expose verification or readback" unless method_name

        verification = @syscall_adapter.public_send(
          method_name,
          backend: self,
          result: operation_result,
          expected: expected,
          hook: hook,
          phase: phase,
          **context
        )
        return true if verified_result?(verification)

        raise BackendError, "#{name} #{phase} adapter did not verify the kernel effect"
      end

      def verified_result?(value)
        return value if [true, false].include?(value)
        return false if value.nil?
        return !!value.verified? if value.respond_to?(:verified?)
        return !!value.success? if value.respond_to?(:success?)

        if value.is_a?(Hash)
          %i[verified attached committed applied success].each do |key|
            return !!value[key] if value.key?(key)

            string_key = key.to_s
            return !!value[string_key] if value.key?(string_key)
          end
        end
        false
      end

      def set_attach_state(state)
        @mutex.synchronize { @attach_state = state.to_sym }
      end

      def fail_attach_state(error)
        @mutex.synchronize do
          @attach_state = :failed
          @last_error = error
        end
      end

      def apply_diff_locked(diff)
        raise StaleRevisionError, "rule diff starts at revision #{diff.from_revision}, expected #{@revision}" if diff.from_revision != @revision

        next_rules = @rules.dup
        diff.added.each { |rule| next_rules[rule.key] = rule }
        diff.updated.each { |_old_rule, new_rule| next_rules[new_rule.key] = new_rule }
        diff.deleted.each { |rule| next_rules.delete(rule.is_a?(Rule) ? rule.key : rule) }
        @rules = next_rules.freeze
        @revision = diff.to_revision
        @last_diff = diff
      end

      # Capture the in-memory commit point before a concrete backend talks to
      # the kernel adapter.  Adapters are allowed to fail after partially
      # processing a diff, so a failed publication must not leave the model
      # ahead of the datapath.
      def backend_state_snapshot
        @mutex.synchronize do
          {rules: @rules, revision: @revision, last_diff: @last_diff}.freeze
        end
      end

      def restore_backend_state(snapshot)
        @mutex.synchronize do
          @rules = snapshot.fetch(:rules)
          @revision = snapshot.fetch(:revision)
          @last_diff = snapshot.fetch(:last_diff)
        end
      end

      def inverse_diff(diff)
        RuleDiff.new(
          added: diff.deleted,
          updated: diff.updated.map { |old_rule, new_rule| [new_rule, old_rule] },
          deleted: diff.added,
          from_revision: diff.to_revision,
          to_revision: diff.from_revision
        )
      end
    end

    class MemoryBackend < Backend
      def initialize(**)
        super(name: "memory", **)
        @attach_state = :ready
      end

      def available?
        true
      end

      def attach(**_options)
        @mutex.synchronize do
          @attach_state = :ready
          @last_error = nil
        end
        true
      end
    end

    # Stable eBPF program and map layout generator.  The generated program is
    # intentionally represented as instruction records so a Linux adapter can
    # encode it for bpf(2) without embedding platform-dependent ABI code here.
    class EBPFBackend < Backend
      DEFAULT_HOOK = :tc
      MAP_LAYOUT = {
        "service_rules" => {"type" => "hash", "key_size" => 40,
                            "value_size" => EBPFProgram::WireFormat::SERVICE_VALUE_SIZE, "max_entries" => 65_536},
        "backends" => {"type" => "array_of_structs", "key_size" => EBPFProgram::WireFormat::BACKEND_KEY_SIZE,
                       "value_size" => EBPFProgram::WireFormat::BACKEND_VALUE_SIZE, "max_entries" => 1_000_000},
        "conntrack" => {"type" => "lru_hash", "key_size" => EBPFProgram::WireFormat::CONNTRACK_KEY_SIZE,
                        "value_size" => EBPFProgram::WireFormat::CONNTRACK_VALUE_SIZE, "max_entries" => 1_000_000},
        "client_ip_affinity" => {"type" => "lru_hash", "key_size" => EBPFProgram::WireFormat::AFFINITY_KEY_SIZE,
                                 "value_size" => EBPFProgram::WireFormat::AFFINITY_VALUE_SIZE, "max_entries" => 1_000_000},
        "source_ranges" => {"type" => "lpm_trie", "key_size" => EBPFProgram::WireFormat::SOURCE_RANGE_KEY_SIZE,
                            "value_size" => EBPFProgram::WireFormat::SOURCE_RANGE_VALUE_SIZE, "max_entries" => 65_536},
        "sctp_crc32c" => {"type" => "array", "key_size" => 4,
                          "value_size" => 4, "max_entries" => 256},
        "snat" => {"type" => "lru_hash", "key_size" => EBPFProgram::WireFormat::SNAT_KEY_SIZE,
                   "value_size" => EBPFProgram::WireFormat::SNAT_VALUE_SIZE, "max_entries" => 1_000_000}
      }.freeze

      def initialize(capability: false, verifier_probe: nil, capability_probe: nil, **)
        super(name: "ebpf", **)
        @capability = capability
        @verifier_probe = verifier_probe || capability_probe
        @program = nil
        @map_layout = MAP_LAYOUT
        @last_verifier_probe = nil
      end

      attr_reader :program, :map_layout

      # The most recent real verifier probe result (nil until available? or
      # attach asked the adapter to load the program).  Node status records it
      # so the selected datapath is traceable to a kernel decision.
      attr_reader :last_verifier_probe

      class InstructionEncoder
        def encode(instructions)
          JSON.generate(Array(instructions)).b
        end
      end

      def instruction_encoder
        @instruction_encoder ||= InstructionEncoder.new
      end

      def available?
        return false unless adapter_contract_available?

        verifier_available?
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def attachable?
        return false unless adapter_contract_available?(phase: :attach)

        verifier_available?
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      alias capability? available?

      def probe
        available?
      end

      def attach(hook: DEFAULT_HOOK, **options)
        begin
          ensure_adapter_contract!(phase: :attach)
        rescue BackendError => error
          fail_attach_state(error)
          raise
        end

        unless verifier_available?
          error = BackendError.new("eBPF attach failed: verifier probe failed")
          fail_attach_state(error)
          raise error
        end

        super
      end

      def generate_program(rules: self.rules, hook: DEFAULT_HOOK)
        ordered_rules = Array(rules).sort_by(&:key)
        @program = [
          {"op" => "load_skb_metadata", "hook" => hook.to_s},
          {"op" => "lookup_service_rule", "map" => "service_rules"},
          {"op" => "lookup_conntrack", "map" => "conntrack"},
          {"op" => "select_backend_rendezvous", "map" => "backends", "deterministic" => true},
          {"op" => "rewrite_destination", "checksum" => "incremental"},
          {"op" => "tail_call_or_pass"}
        ] + ordered_rules.map { |rule| {"op" => "rule", "key" => rule.key, "backendCount" => rule.backends.length} }
        @program.freeze
      end

      def apply_diff(diff)
        @apply_mutex.synchronize do
          previous = backend_state_snapshot
          result = nil
          begin
            result = super
            generate_program
            publish_program_diff(result) if attached?
            result
          rescue StandardError => error
            rollback_error = rollback_program_update(previous, result)
            restore_backend_state(previous)
            raise BackendError, "eBPF rule update failed: #{error.message}; rollback failed: #{rollback_error.message}" if rollback_error

            raise
          end
        end
      end

      def apply_compiled(compiled)
        @apply_mutex.synchronize do
          previous = backend_state_snapshot
          result = nil
          begin
            result = super
            generate_program
            publish_program_diff(result) if attached?
            result
          rescue StandardError => error
            rollback_error = rollback_program_update(previous, result)
            restore_backend_state(previous)
            raise BackendError, "eBPF rule update failed: #{error.message}; rollback failed: #{rollback_error.message}" if rollback_error

            raise
          end
        end
      end

      def instruction_bytes
        instruction_encoder.encode(program || generate_program)
      end

      def map_layout_json
        JSON.generate(map_layout)
      end

      protected

      def adapter_operation_groups
        [[:attach], %i[update apply_diff]]
      end

      # Auto selection must be driven by the kernel verifier, not by a flag.
      # An injected probe wins; otherwise a real adapter is asked to load the
      # compiled datapath (LinuxEBPFAdapter#verifier_probe) and the result is
      # recorded.  The legacy `capability:` flag remains only for adapters
      # that expose no verifier probe at all (model/test fixtures); the
      # production adapter always answers through the kernel.
      def verifier_available?
        return !!@verifier_probe.call if @verifier_probe

        adapter = @syscall_adapter
        if adapter.respond_to?(:verifier_probe) && !(adapter.respond_to?(:test_adapter?) && adapter.test_adapter? == true)
          @last_verifier_probe = adapter.verifier_probe
          return @last_verifier_probe.is_a?(Hash) && @last_verifier_probe["accepted"] == true
        end

        !!@capability
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError => error
        @last_verifier_probe = {"accepted" => false, "error" => "#{error.class}: #{error.message}"}.freeze
        false
      end

      def perform_attach(hook:, **)
        attach_program = program || generate_program(hook: hook)
        @syscall_adapter.attach(hook: hook, backend: self, program: attach_program,
                                map_layout: map_layout, **)
      end

      def expected_attach(hook:, **_options)
        {hook: hook, program: program, map_layout: map_layout}.freeze
      end

      def backend_state_snapshot
        super.merge(program: @program).freeze
      end

      def restore_backend_state(snapshot)
        super
        @program = snapshot[:program]
      end

      private

      def attached?
        @mutex.synchronize { @attach_state == :attached }
      end

      def publish_program_diff(diff)
        ensure_adapter_contract!(phase: :update)
        operation_result = if @syscall_adapter.respond_to?(:update)
                             @syscall_adapter.update(backend: self, diff: diff, program: program)
                           elsif @syscall_adapter.respond_to?(:apply_diff)
                             @syscall_adapter.apply_diff(diff, backend: self, program: program)
                           end
        verify_adapter_effect!(phase: :update, operation_result: operation_result,
                               expected: {diff: diff, program: program}.freeze, hook: DEFAULT_HOOK)
      rescue ArgumentError, IOError, SystemCallError, RuntimeError, TypeError => error
        raise BackendError, "eBPF rule update failed: #{error.message}"
      end

      def rollback_program_update(previous, diff)
        return nil unless diff && attached? && @syscall_adapter

        previous_program = previous[:program]
        previous_program ||= generate_program(rules: previous.fetch(:rules).values)
        inverse = inverse_diff(diff)
        operation_result = if @syscall_adapter.respond_to?(:update)
                             @syscall_adapter.update(backend: self, diff: inverse, program: previous_program)
                           elsif @syscall_adapter.respond_to?(:apply_diff)
                             @syscall_adapter.apply_diff(inverse, backend: self, program: previous_program)
                           end
        verify_adapter_effect!(phase: :update, operation_result: operation_result,
                               expected: {diff: inverse, program: previous_program}.freeze, hook: DEFAULT_HOOK)
        nil
      rescue StandardError => error
        error
      ensure
        @program = previous[:program] if previous
      end
    end

    BPFBackend = EBPFBackend
    EbpfBackend = EBPFBackend

    # Minimal netlink encoder for nftables rule updates.  The same Rule objects
    # are used as eBPF input, and messages are deterministic for reproducible
    # differential tests.
    class NftablesBackend < Backend
      def initialize(netlink_adapter: nil, **)
        super(name: "nftables", syscall_adapter: netlink_adapter || default_netlink_adapter, **)
        @messages = [].freeze
      end

      attr_reader :messages

      class NetlinkEncoder
        def encode(messages)
          JSON.generate(Array(messages)).b
        end
      end

      # The native adapter is the default production datapath.  Its
      # production-capability matrix and post-transaction readback remain the
      # authority for whether this backend can be used on the current kernel.
      def default_netlink_adapter
        return nil unless defined?(NftablesNetlinkAdapter)

        NftablesNetlinkAdapter.new
      end

      def netlink_encoder
        @netlink_encoder ||= NetlinkEncoder.new
      end

      def encode_messages(diff: @last_diff)
        @messages = messages_for(diff)
      end

      def apply_diff(diff)
        @apply_mutex.synchronize do
          previous = backend_state_snapshot
          result = nil
          begin
            result = super
            encode_messages(diff: diff)
            transmit_messages if attached?
            result
          rescue StandardError => error
            rollback_error = rollback_message_update(previous, result)
            restore_backend_state(previous)
            if rollback_error
              raise BackendError,
                    "nftables rule update failed: #{error.message}; rollback failed: #{rollback_error.message}"
            end

            raise
          end
        end
      end

      def apply_compiled(compiled)
        @apply_mutex.synchronize do
          previous = backend_state_snapshot
          result = nil
          begin
            result = super
            encode_messages(diff: result)
            transmit_messages if attached?
            result
          rescue StandardError => error
            rollback_error = rollback_message_update(previous, result)
            restore_backend_state(previous)
            if rollback_error
              raise BackendError,
                    "nftables rule update failed: #{error.message}; rollback failed: #{rollback_error.message}"
            end

            raise
          end
        end
      end

      def netlink_payload
        netlink_encoder.encode(messages)
      end

      protected

      def adapter_operation_groups
        [%i[attach send_messages apply]]
      end

      def perform_attach(hook:, **)
        if @syscall_adapter.respond_to?(:attach)
          @syscall_adapter.attach(messages: messages, hook: hook, backend: self, **)
        elsif @syscall_adapter.respond_to?(:send_messages)
          @syscall_adapter.send_messages(messages, hook: hook, backend: self, **)
        elsif @syscall_adapter.respond_to?(:apply)
          @syscall_adapter.apply(messages, hook: hook, backend: self, **)
        end
      end

      def expected_attach(hook:, **_options)
        {hook: hook, messages: messages}.freeze
      end

      def backend_state_snapshot
        super.merge(messages: @messages).freeze
      end

      def restore_backend_state(snapshot)
        super
        @messages = snapshot[:messages]
      end

      private

      def attached?
        @mutex.synchronize { @attach_state == :attached }
      end

      def transmit_messages(messages = @messages)
        ensure_adapter_contract!(phase: :transaction)
        operation_result = if @syscall_adapter.respond_to?(:send_messages)
                             @syscall_adapter.send_messages(messages, hook: :netdev, backend: self)
                           elsif @syscall_adapter.respond_to?(:apply)
                             @syscall_adapter.apply(messages, hook: :netdev, backend: self)
                           elsif @syscall_adapter.respond_to?(:attach)
                             @syscall_adapter.attach(messages: messages, hook: :netdev, backend: self)
                           end
        verify_adapter_effect!(phase: :transaction, operation_result: operation_result,
                               expected: messages, hook: :netdev, messages: messages)
        operation_result
      rescue ArgumentError, IOError, SystemCallError, RuntimeError, TypeError => error
        raise BackendError, "nftables rule update failed: #{error.message}"
      end

      def messages_for(diff)
        additions = diff.added.map { |rule| encode_rule("add", rule) }
        updates = diff.updated.map { |_old_rule, rule| encode_rule("replace", rule) }
        deletions = diff.deleted.map { |rule| encode_rule("delete", rule) }
        (additions + updates + deletions).sort_by { |message| [message["operation"], message["key"].to_s] }.freeze
      end

      def rollback_message_update(_previous, diff)
        return nil unless diff && attached? && @syscall_adapter

        transmit_messages(messages_for(inverse_diff(diff)))
        nil
      rescue StandardError => error
        error
      end

      def encode_rule(operation, rule)
        {
          "operation" => operation,
          "family" => if rule.virtual_ip.nil?
                        "inet"
                      else
                        (rule.virtual_ip.include?(":") ? "ip6" : "ip")
                      end,
          "table" => "rubernetes",
          "chain" => "service_#{Digest::SHA256.hexdigest(rule.service_key)[0, 12]}",
          "key" => rule.key,
          "destination" => rule.virtual_ip,
          "port" => rule.port,
          "nodePort" => rule.node_port,
          "protocol" => rule.protocol,
          "backends" => rule.backend_ids
        }.compact
      end
    end

    NFTablesBackend = NftablesBackend
    NftBackend = NftablesBackend

    # Differential parity helper used by the M4 corpus.  It compares the
    # observable Service rules, never implementation-specific instruction or
    # netlink bytes.
    class BackendParity
      REQUIRED_CASE_IDS = %w[
        ipv4_tcp_cluster_ip ipv4_udp_cluster_ip ipv4_sctp_cluster_ip
        ipv6_tcp_cluster_ip ipv6_udp_cluster_ip ipv6_sctp_cluster_ip
        ipv4_tcp_node_port ipv4_udp_node_port ipv4_sctp_node_port
        ipv6_tcp_node_port ipv6_udp_node_port ipv6_sctp_node_port
        ipv4_tcp_external_ip ipv4_udp_external_ip ipv4_sctp_external_ip
        ipv6_tcp_external_ip ipv6_udp_external_ip ipv6_sctp_external_ip
        ipv4_tcp_load_balancer ipv4_udp_load_balancer ipv4_sctp_load_balancer
        ipv6_tcp_load_balancer ipv6_udp_load_balancer ipv6_sctp_load_balancer
        ipv4_tcp_headless ipv4_udp_headless ipv4_sctp_headless
        ipv6_tcp_headless ipv6_udp_headless ipv6_sctp_headless
        external_name_cname
        ipv4_distinct_address_reverse ipv6_distinct_address_reverse
        health_check_node_port ipv4_fragments ipv6_fragments
        session_affinity_client_ip internal_traffic_policy_local external_traffic_policy_local
        terminating_endpoints dual_stack_service
      ].freeze

      def self.compare(left, right)
        left_snapshot = left.semantic_snapshot
        right_snapshot = right.semantic_snapshot
        {
          "passed" => left_snapshot == right_snapshot,
          "observableSemanticsEqual" => left_snapshot == right_snapshot,
          # A Ruby rule snapshot cannot prove that either kernel datapath
          # accepted a packet or that its owned objects are still installed.
          # Keep this result explicitly model-only so callers cannot use it as
          # a production M4 parity verdict.
          "measurementSource" => "model_only",
          "productionCapable" => false,
          "productionVerified" => false,
          "leftDigest" => left.digest,
          "rightDigest" => right.digest,
          # Carry the canonical model inputs alongside their digests. A
          # readback that merely self-hashes a fabricated rule list must not
          # satisfy the parity boundary.
          "leftRules" => left_snapshot,
          "rightRules" => right_snapshot,
          "comparisonDigest" => Digest::SHA256.hexdigest(JSON.generate([left_snapshot, right_snapshot]))
        }.freeze
      end

      # A production parity result requires independent packet-corpus and
      # kernel-readback evidence for both backends.  The ordinary .compare
      # method remains useful for model debugging but never upgrades itself.
      def self.production_compare(left, right, packet_corpus:, kernel_readback:)
        model = compare(left, right)
        evidence_errors = []
        evidence_errors << "left backend is not a production-capable external adapter" unless production_backend?(left)
        evidence_errors << "right backend is not a production-capable external adapter" unless production_backend?(right)
        if !external_packet_corpus?(packet_corpus, left_digest: model.fetch("leftDigest"),
                                                   right_digest: model.fetch("rightDigest"), errors: evidence_errors) && evidence_errors.empty?
          evidence_errors << "packet corpus provenance is incomplete"
        end
        if !external_kernel_readback?(kernel_readback, left_digest: model.fetch("leftDigest"),
                                                       right_digest: model.fetch("rightDigest"),
                                                       expected_rules: {"ebpf" => model.fetch("leftRules"),
                                                                        "nftables" => model.fetch("rightRules")},
                                                       errors: evidence_errors) && evidence_errors.empty?
          evidence_errors << "kernel readback provenance is incomplete"
        end
        unless evidence_errors.empty?
          return model.merge(
            "passed" => false,
            "observableSemanticsEqual" => false,
            "measurementSource" => "external_evidence_missing",
            "evidenceErrors" => evidence_errors.uniq.freeze
          ).freeze
        end
        if !shared_execution_provenance?(packet_corpus, kernel_readback, errors: evidence_errors) && evidence_errors.empty?
          evidence_errors << "packet and kernel evidence do not share one immutable runner execution"
        end
        if !shared_case_binding?(packet_corpus, kernel_readback, errors: evidence_errors) && evidence_errors.empty?
          evidence_errors << "packet and kernel evidence do not share the required case inventory"
        end
        unless evidence_errors.empty?
          return model.merge(
            "passed" => false,
            "observableSemanticsEqual" => false,
            "measurementSource" => "external_evidence_missing",
            "evidenceErrors" => evidence_errors.uniq.freeze
          ).freeze
        end

        model.merge(
          "measurementSource" => "external_packet_corpus_and_kernel_readback",
          "productionCapable" => model.fetch("passed") == true,
          "productionVerified" => model.fetch("passed"),
          "evidenceErrors" => [].freeze
        ).freeze
      end

      def self.production_backend?(backend)
        return false if defined?(MemoryBackend) && backend.is_a?(MemoryBackend)

        return false unless backend.is_a?(EBPFBackend) || backend.is_a?(NftablesBackend)
        return false unless backend.respond_to?(:production_capable?) && backend.production_capable? == true
        return false unless backend.respond_to?(:digest) && backend.respond_to?(:semantic_snapshot)

        adapter = backend.instance_variable_get(:@syscall_adapter)
        return false unless adapter

        concrete = if defined?(LinuxEBPFAdapter) && backend.is_a?(EBPFBackend)
                     adapter.instance_of?(LinuxEBPFAdapter)
                   elsif defined?(NftablesNetlinkAdapter) && backend.is_a?(NftablesBackend)
                     adapter.instance_of?(NftablesNetlinkAdapter)
                   else
                     false
                   end
        return false unless concrete

        identity = backend.kernel_identity
        identity.is_a?(Hash) && !identity.empty?
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def self.external_packet_corpus?(value, left_digest: nil, right_digest: nil, errors: nil)
        failures = errors || []
        unless value.is_a?(Hash)
          failures << "packet corpus must be a hash"
          return false
        end
        measurement_source = evidence_value(value, "measurementSource", "measurement_source")
        failures << "packet corpus measurement source is not external" if measurement_source.to_s.empty? || measurement_source.to_s == "model_only"
        failures << "packet corpus must report executed=true" unless evidence_value(value, "executed") == true
        validate_runner_provenance(value, "packet corpus", failures)
        validate_input_binding(value, "packet corpus", left_digest, right_digest, failures)

        raw_trace = evidence_value(value, "rawPacketTrace", "raw_packet_trace")
        trace = evidence_value(value, "packetTraceSha256", "packet_trace_sha256")
        if raw_trace.nil?
          failures << "packet corpus raw packet trace is required"
        elsif !valid_digest?(trace) || trace != canonical_trace_digest(raw_trace)
          failures << "packet corpus packet trace digest does not match canonical raw trace"
        end

        validate_packet_capture(value, "packet corpus", failures)

        cases = evidence_value(value, "cases", "comparisons")
        inventory = evidence_value(value, "caseInventory", "case_inventory")
        validate_case_binding(cases, inventory, trace, failures)
        validate_case_inventory_digest(value, inventory, failures)
        failures.empty?
      end

      def self.external_kernel_readback?(value, left_digest: nil, right_digest: nil, expected_rules: nil, errors: nil)
        failures = errors || []
        unless value.is_a?(Hash)
          failures << "kernel readback must be a hash"
          return false
        end
        measurement_source = evidence_value(value, "measurementSource", "measurement_source")
        failures << "kernel readback measurement source is not external" if measurement_source.to_s.empty? || measurement_source.to_s == "model_only"
        validate_runner_provenance(value, "kernel readback", failures)
        validate_input_binding(value, "kernel readback", left_digest, right_digest, failures)
        failures << "kernel readback packet trace is required" unless valid_digest?(evidence_value(value, "packetTraceSha256",
                                                                                                   "packet_trace_sha256"))
        failures << "kernel readback case inventory digest is required" unless valid_digest?(evidence_value(value, "caseInventorySha256",
                                                                                                            "case_inventory_sha256"))
        backends = %w[ebpf nftables].to_h do |name|
          [name, value[name] || value[name.to_sym]]
        end
        backends.each do |name, entry|
          validate_kernel_backend_readback(entry, name, name == "ebpf" ? left_digest : right_digest,
                                           expected_rules: expected_rules && expected_rules[name], failures: failures)
        end
        failures.empty?
      end

      def self.evidence_value(value, *keys)
        keys.each do |key|
          return value[key] if value.key?(key)

          symbol = key.to_sym
          return value[symbol] if value.key?(symbol)
        end
        nil
      end

      def self.valid_digest?(value)
        value.to_s.match?(/\A[0-9a-f]{64}\z/i)
      end

      def self.positive_integer?(value)
        value.is_a?(Integer) && value.positive?
      end

      # BPF_OBJ_GET_INFO_BY_FD exposes the verifier tag as eight kernel bytes,
      # rendered by the native adapter as exactly sixteen hexadecimal chars.
      # It is not a SHA-256 evidence digest and must not be self-supplied.
      def self.valid_bpf_tag?(value)
        value.is_a?(String) && value.match?(/\A[0-9a-f]{16}\z/i)
      end

      def self.canonical_trace_digest(value)
        canonical = value.is_a?(String) ? value.b : JSON.generate(ModelSupport.canonicalize(value))
        Digest::SHA256.hexdigest(canonical)
      end

      def self.validate_runner_provenance(value, label, failures)
        identity = evidence_value(value, "runnerIdentity", "runner_identity")
        digest = evidence_value(value, "runnerDigest", "runner_digest", "runnerSha256", "runner_sha256")
        mode = evidence_value(value, "mode", "runnerMode", "runner_mode")
        failures << "#{label} runner identity is required" unless identity.is_a?(String) && !identity.empty?
        failures << "#{label} runner digest is invalid" unless valid_digest?(digest)
        failures << "#{label} execution mode must identify an isolated external runner" unless mode.is_a?(String) && !mode.empty? && mode.to_s != "model"
        runner = evidence_value(value, "runner", "runnerProvenance", "runner_provenance")
        if runner.is_a?(Hash)
          pid = evidence_value(runner, "pid", "processId", "process_id")
          started_at = evidence_value(runner, "startedAt", "started_at", "startTime", "start_time")
          source = evidence_value(runner, "source", "sourcePath", "source_path")
          argv = evidence_value(runner, "argv", "command")
          stdout = evidence_value(runner, "stdout", "stdoutBytes", "stdout_bytes")
          stdout_digest = evidence_value(runner, "stdoutSha256", "stdout_sha256")
          failures << "#{label} runner PID is invalid" unless pid.is_a?(Integer) && pid.positive?
          failures << "#{label} runner start-time is invalid" unless iso8601_value?(started_at)
          failures << "#{label} runner source is required" unless source.is_a?(String) && !source.empty? && source != "model"
          failures << "#{label} runner argv is required" unless argv.is_a?(Array) && !argv.empty? && argv.all? do |arg|
            arg.is_a?(String) && !arg.empty?
          end
          failures << "#{label} runner stdout is required" unless stdout.is_a?(String)
          failures << "#{label} runner stdout digest is invalid" unless valid_digest?(stdout_digest)
          if stdout
            stdout_bytes = stdout.is_a?(String) ? stdout.b : JSON.generate(ModelSupport.canonicalize(stdout))
            failures << "#{label} runner stdout digest does not match" unless stdout_digest == Digest::SHA256.hexdigest(stdout_bytes)
          end
        else
          failures << "#{label} runner PID/start-time/source/argv/stdout provenance is required"
        end
        execution = evidence_value(value, "executionIdentity", "execution_identity")
        execution_digest = evidence_value(value, "executionIdentitySha256", "execution_identity_sha256")
        if execution.is_a?(Hash) && !execution.empty?
          execution_identity = evidence_value(execution, "runnerIdentity", "runner_identity")
          execution_runner_digest = evidence_value(execution, "runnerDigest", "runner_digest")
          execution_mode = evidence_value(execution, "mode", "runnerMode", "runner_mode")
          failures << "#{label} execution identity runner does not match" unless execution_identity == identity
          failures << "#{label} execution identity digest does not match" unless execution_runner_digest == digest
          failures << "#{label} execution identity mode does not match" unless execution_mode == mode
          unless valid_digest?(execution_digest) && execution_digest == canonical_trace_digest(execution)
            failures << "#{label} execution identity digest is invalid"
          end
        else
          failures << "#{label} immutable execution identity is required"
        end
      end

      def self.validate_packet_capture(value, label, failures)
        capture = evidence_value(value, "packetCapture", "packet_capture", "pcap")
        capture = value if capture.nil? && (value.key?("packetBytesSha256") || value.key?(:packet_bytes_sha256))
        unless capture.is_a?(Hash)
          failures << "#{label} packet bytes/PCAP provenance is required"
          return
        end
        format = evidence_value(capture, "format", "type")
        digest = evidence_value(capture, "sha256", "packetBytesSha256", "packet_bytes_sha256", "pcapSha256", "pcap_sha256")
        count = evidence_value(capture, "packetCount", "packet_count", "count")
        source = evidence_value(capture, "source", "sourcePath", "source_path")
        failures << "#{label} packet capture format is invalid" unless %w[pcap packet_bytes raw].include?(format.to_s)
        failures << "#{label} packet capture sha256 is invalid" unless valid_digest?(digest)
        failures << "#{label} packet capture count must be positive" unless count.is_a?(Integer) && count.positive?
        failures << "#{label} packet capture source is required" unless source.is_a?(String) && !source.empty? && source != "model"
        bytes = evidence_value(capture, "bytes", "packetBytes", "packet_bytes")
        # "bytes" is either the raw capture (checked against its digest) or
        # the capture size reported beside a digest of the capture file.
        if bytes.is_a?(String)
          failures << "#{label} packet capture bytes digest does not match" unless Digest::SHA256.hexdigest(bytes.b) == digest
        elsif bytes
          failures << "#{label} packet capture bytes must be raw bytes or a positive size" unless bytes.is_a?(Integer) && bytes.positive?
        end
      end

      def self.iso8601_value?(value)
        Time.iso8601(value.to_s)
        true
      rescue ArgumentError, TypeError
        false
      end

      def self.validate_input_binding(value, label, left_digest, right_digest, failures)
        binding = evidence_value(value, "inputBinding", "input_binding")
        unless binding.is_a?(Hash)
          failures << "#{label} input binding is required"
          return
        end
        bound_left = evidence_value(binding, "leftDigest", "left_digest", "ebpfDigest", "ebpf_digest")
        bound_right = evidence_value(binding, "rightDigest", "right_digest", "nftablesDigest", "nftables_digest")
        failures << "#{label} input binding left digest does not match" unless bound_left == left_digest
        failures << "#{label} input binding right digest does not match" unless bound_right == right_digest
        binding_digest = evidence_value(value, "inputBindingSha256", "input_binding_sha256")
        return if valid_digest?(binding_digest) && binding_digest == canonical_trace_digest(binding)

        failures << "#{label} immutable input binding digest is invalid"
      end

      def self.validate_case_binding(cases, inventory, trace, failures)
        unless cases.is_a?(Array) && !cases.empty?
          failures << "packet corpus cases are required"
          return
        end
        unless inventory.is_a?(Array) && !inventory.empty?
          failures << "packet corpus case inventory is required"
          return
        end
        case_id = lambda do |entry|
          entry.is_a?(Hash) ? evidence_value(entry, "id", "case", "caseId", "case_id") : entry.to_s
        end
        case_ids = cases.map(&case_id).map(&:to_s)
        inventory_ids = inventory.map(&case_id).map(&:to_s)
        failures << "packet corpus case inventory does not bind cases" unless case_ids.sort == inventory_ids.sort && case_ids.uniq.length == case_ids.length
        failures << "packet corpus required case inventory is incomplete" unless case_ids.sort == REQUIRED_CASE_IDS.sort
        failures << "packet corpus case count is not #{REQUIRED_CASE_IDS.length}" unless case_ids.length == REQUIRED_CASE_IDS.length
        cases.each do |entry|
          unless entry.is_a?(Hash) && evidence_value(entry, "passed") == true
            failures << "packet corpus case did not pass"
            next
          end
          expected = evidence_value(entry, "expected")
          actual = evidence_value(entry, "actual")
          failures << "packet corpus case expected/actual mismatch" unless !expected.nil? && !actual.nil? &&
                                                                           ModelSupport.canonicalize(expected) == ModelSupport.canonicalize(actual)
          expected_digest = evidence_value(entry, "expectedSha256", "expected_sha256")
          actual_digest = evidence_value(entry, "actualSha256", "actual_sha256")
          unless valid_digest?(expected_digest) && expected_digest == canonical_trace_digest(expected)
            failures << "packet corpus case expected digest is invalid"
          end
          failures << "packet corpus case actual digest is invalid" unless valid_digest?(actual_digest) && actual_digest == canonical_trace_digest(actual)
          case_trace = evidence_value(entry, "packetTraceSha256", "packet_trace_sha256")
          failures << "packet corpus case trace is not bound to raw trace" unless case_trace == trace
        end
      end

      def self.validate_case_inventory_digest(value, inventory, failures)
        digest = evidence_value(value, "caseInventorySha256", "case_inventory_sha256")
        return if inventory.is_a?(Array) && valid_digest?(digest) && digest == canonical_trace_digest(inventory)

        failures << "packet corpus case inventory digest is invalid"
      end

      def self.shared_execution_provenance?(packet_corpus, kernel_readback, errors: nil)
        failures = errors || []
        packet = evidence_value(packet_corpus, "executionIdentitySha256", "execution_identity_sha256")
        kernel = evidence_value(kernel_readback, "executionIdentitySha256", "execution_identity_sha256")
        failures << "packet/kernel execution identity digest differs" unless valid_digest?(packet) && packet == kernel
        packet_runner = evidence_value(packet_corpus, "runnerDigest", "runner_digest")
        kernel_runner = evidence_value(kernel_readback, "runnerDigest", "runner_digest")
        failures << "packet/kernel runner digest differs" unless valid_digest?(packet_runner) && packet_runner == kernel_runner
        packet_provenance = evidence_value(packet_corpus, "runner", "runnerProvenance", "runner_provenance")
        kernel_provenance = evidence_value(kernel_readback, "runner", "runnerProvenance", "runner_provenance")
        if packet_provenance.is_a?(Hash) && kernel_provenance.is_a?(Hash)
          provenance_keys = %w[pid processId process_id startedAt started_at startTime start_time source sourcePath source_path argv
                               command stdout stdoutSha256 stdout_sha256]
          provenance_keys.each do |key|
            packet_value = evidence_value(packet_provenance, key)
            kernel_value = evidence_value(kernel_provenance, key)
            failures << "packet/kernel runner #{key} differs" unless packet_value == kernel_value
          end
        else
          failures << "packet/kernel runner PID/start/source/argv/stdout provenance differs"
        end
        failures.empty?
      end

      def self.shared_case_binding?(packet_corpus, kernel_readback, errors: nil)
        failures = errors || []
        packet_trace = evidence_value(packet_corpus, "packetTraceSha256", "packet_trace_sha256")
        kernel_trace = evidence_value(kernel_readback, "packetTraceSha256", "packet_trace_sha256")
        packet_inventory = evidence_value(packet_corpus, "caseInventorySha256", "case_inventory_sha256")
        kernel_inventory = evidence_value(kernel_readback, "caseInventorySha256", "case_inventory_sha256")
        failures << "packet/kernel raw packet trace digest differs" unless valid_digest?(packet_trace) && packet_trace == kernel_trace
        failures << "packet/kernel case inventory digest differs" unless valid_digest?(packet_inventory) && packet_inventory == kernel_inventory
        failures.empty?
      end

      def self.validate_kernel_backend_readback(entry, name, expected_digest, failures:, expected_rules: nil)
        unless entry.is_a?(Hash)
          failures << "#{name} kernel readback entry is required"
          return
        end
        failures << "#{name} kernel readback did not report readback=true" unless evidence_value(entry, "readback") == true
        rules = evidence_value(entry, "rules")
        unless rules.is_a?(Array) && !rules.empty? && rules.all? { |rule| rule.is_a?(Hash) && !rule.empty? }
          failures << "#{name} kernel readback rules are not concrete"
        end
        identity = evidence_value(entry, "identity", "kernelIdentity", "kernel_identity")
        identity_digest = evidence_value(entry, "identityDigest", "identity_digest")
        failures << "#{name} kernel identity is required" unless identity.is_a?(Hash) && !identity.empty?
        failures << "#{name} kernel identity digest is invalid" unless valid_digest?(identity_digest) && identity_digest == canonical_trace_digest(identity)
        rules_digest = evidence_value(entry, "rulesDigest", "rules_digest", "ruleDigest", "rule_digest")
        failures << "#{name} kernel rules digest does not match readback" unless valid_digest?(rules_digest) && rules_digest == canonical_trace_digest(rules)
        if expected_rules
          unless ModelSupport.canonicalize(rules) == ModelSupport.canonicalize(expected_rules)
            failures << "#{name} kernel rules do not match the canonical model snapshot"
          end
          unless canonical_trace_digest(expected_rules) == canonical_trace_digest(rules)
            failures << "#{name} kernel rules digest does not match the canonical model snapshot"
          end
        end
        input_digest = evidence_value(entry, "inputDigest", "input_digest", "ruleInputDigest", "rule_input_digest")
        failures << "#{name} kernel readback is not bound to backend input" unless input_digest == expected_digest
        model_digest = evidence_value(entry, "rulesModelDigest", "rules_model_digest", "modelDigest", "model_digest")
        expected_model_digest = expected_rules ? canonical_trace_digest(expected_rules) : expected_digest
        unless model_digest == expected_model_digest && expected_model_digest == expected_digest
          failures << "#{name} kernel rules are not bound to the model digest"
        end
        case name
        when "ebpf"
          program = evidence_value(entry, "program", "programIdentity", "program_identity")
          maps = evidence_value(entry, "maps", "mapIdentity", "map_identity")
          filters = evidence_value(entry, "filters", "tcFilters", "tc_filters")
          failures << "ebpf program verifier identity is required" unless program.is_a?(Hash) && positive_integer?(evidence_value(program,
                                                                                                                                  "id")) &&
                                                                          valid_bpf_tag?(evidence_value(
                                                                            program, "tag"
                                                                          ))
          failures << "ebpf map readback identity is required" unless maps.is_a?(Array) && !maps.empty? && maps.all? do |map|
            map.is_a?(Hash) && positive_integer?(evidence_value(map, "id"))
          end
          failures << "ebpf TC filter readback identity is required" unless filters.is_a?(Array) && !filters.empty? && filters.all? do |filter|
            positive_integer?(evidence_value(filter, "ifindex")) && positive_integer?(evidence_value(filter, "programId", "program_id"))
          end
        when "nftables"
          table = evidence_value(entry, "table", "tableIdentity", "table_identity")
          chains = evidence_value(entry, "chains")
          sets = evidence_value(entry, "sets")
          failures << "nftables table readback identity is required" unless table.is_a?(Hash) && evidence_value(table, "name").to_s != ""
          failures << "nftables chain readback identity is required" unless chains.is_a?(Array) && !chains.empty?
          failures << "nftables set readback identity is required" unless sets.is_a?(Array) && !sets.empty?
        end
      end

      def initialize(left:, right:)
        @left = left
        @right = right
      end

      def compare
        self.class.compare(@left, @right)
      end

      def production_compare(packet_corpus:, kernel_readback:)
        self.class.production_compare(@left, @right,
                                      packet_corpus: packet_corpus,
                                      kernel_readback: kernel_readback)
      end

      alias call compare

      def parity?
        compare.fetch("passed")
      end

      def production_parity?(packet_corpus:, kernel_readback:)
        production_compare(packet_corpus: packet_corpus, kernel_readback: kernel_readback).fetch("productionVerified")
      end
    end

    class CapabilityProbe
      def initialize(verifier: nil, bpf: nil)
        @verifier = verifier
        @bpf = bpf
      end

      def ebpf
        return !!@verifier.call if @verifier
        # attachable? runs the adapter's real verifier probe for a backend
        # that has not attached yet; available? is the stricter post-proof
        # predicate and is used when the backend exposes nothing else.
        return !!@bpf.attachable? if @bpf.respond_to?(:attachable?)
        return !!@bpf.available? if @bpf.respond_to?(:available?)

        false
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      alias ebpf? ebpf
    end

    # Auto backend chooses eBPF only after a verifier probe and records the
    # choice so node status can expose the actual datapath in use.
    class AutoBackend
      attr_reader :ebpf, :nftables, :connection_probe, :connection_tracker

      def initialize(ebpf: EBPFBackend.new, nftables: NftablesBackend.new,
                     capability_probe: nil, node_status: nil, clock: -> { Time.now.utc },
                     connection_tracker: nil, connection_probe: nil)
        @ebpf = ebpf
        @nftables = nftables
        @capability_probe = if capability_probe.respond_to?(:call)
                              CapabilityProbe.new(verifier: capability_probe)
                            else
                              capability_probe || CapabilityProbe.new(bpf: @ebpf)
                            end
        @node_status = node_status
        @clock = clock
        @connection_tracker = connection_tracker
        @connection_probe = connection_probe
        @mutex = Mutex.new
        @measurements = []
        @measurements_mutex = Mutex.new
        @status_mutex = Mutex.new
        @selected = nil
        @status = nil
        @last_error = nil
        select_backend
      end

      def name
        current.name
      end

      alias backend_name name

      def current
        @mutex.synchronize { @selected || @nftables }
      end

      alias backend current

      def selected_backend
        current.name
      end

      alias selected selected_backend

      def available?
        backend_available?(current)
      end

      def ready?
        backend_ready?(current)
      end

      def rules
        current.rules
      end

      def rule_map
        current.rule_map
      end

      def revision
        current.revision
      end

      def digest
        current.digest
      end

      def last_diff
        current.last_diff
      end

      def status
        @status_mutex.synchronize { @status }
      end

      def measurements
        @measurements_mutex.synchronize { @measurements.dup.freeze }
      end

      def last_error
        @status_mutex.synchronize { @last_error }
      end

      def apply(value)
        current.apply(value)
      rescue StaleRevisionError
        raise
      rescue BackendError => error
        @status_mutex.synchronize { @last_error = error }
        switch!(reason: "#{current.name} apply failed: #{error.message}")
        current.apply(value)
      end

      alias apply_rules apply

      def apply_diff(diff)
        apply(diff)
      end

      def attach(**)
        backend = current
        backend.attach(**)
        ensure_backend_ready!(backend)
        publish_status("ready", "#{backend.name} attach verified")
        true
      rescue BackendError => error
        @status_mutex.synchronize { @last_error = error }
        fallback = current.equal?(@ebpf) ? @nftables : @ebpf
        if !fallback.equal?(current) && backend_attachable?(fallback)
          begin
            return switch!(target: fallback, reason: "#{current.name} attach failed: #{error.message}")
          rescue BackendError => switch_error
            # Keep the original attach failure visible: the fallback switch
            # error alone would hide why the selected datapath never came up.
            error = BackendError.new("#{switch_error.message}; original #{current.name} attach failure: #{error.message}")
          end
        end
        publish_status("failed", "#{current.name} attach failed", error)
        raise error
      end

      def detach(**)
        current.detach(**)
      end

      def switch!(target: nil, reason: "manual switch")
        target_backend = if target.nil?
                           current.equal?(@ebpf) ? @nftables : @ebpf
                         else
                           resolve_backend(target)
                         end
        raise BackendError, "target backend #{target_backend.name} is unavailable" unless backend_attachable?(target_backend)

        started_at = @clock.call
        from_backend = current
        raise BackendError, "cannot switch to the currently selected backend" if target_backend.equal?(from_backend)

        measurement_context = capture_connection_context(from_backend, target_backend, started_at)
        target_attached = false
        old_detach_attempted = false
        old_detached = false
        switch_committed = false
        begin
          # Prepare and verify the target while the old datapath remains live.
          target_backend.apply(RuleSetSnapshot.new(rules: from_backend.rules, revision: from_backend.revision))
          target_attached = true
          target_backend.attach
          ensure_backend_ready!(target_backend)

          # The selected backend is the in-process commit point.  No caller
          # can observe a half-selected datapath between target verification
          # and the old backend teardown.
          @mutex.synchronize { @selected = target_backend }

          old_detach_attempted = true
          from_backend.detach
          old_detached = true

          observation = measure_connection_switch(measurement_context, from_backend, target_backend)
          active_connections = observation.fetch(:active_connections)
          lost_connections = observation.fetch(:lost_connections)
          measurement_source = observation.fetch(:measurement_source)
          switch_committed = true
        rescue StandardError => error
          unless switch_committed
            begin
              rollback_switch!(from_backend, target_backend, target_attached: target_attached,
                                                             old_detached: old_detached, old_detach_attempted: old_detach_attempted)
            rescue StandardError => rollback_error
              error = BackendError.new("#{error.message}; backend switch rollback failed: #{rollback_error.message}")
            end
          end
          raise error
        end
        switched_at = @clock.call
        measurement = ConnectionMeasurement.new(
          from_backend: from_backend.name, to_backend: target_backend.name,
          started_at: started_at, switched_at: switched_at,
          active_connections: active_connections, lost_connections: lost_connections,
          duration_ms: ((switched_at.to_f - started_at.to_f) * 1000.0), reason: reason,
          measurement_source: measurement_source,
          runner_identity: observation[:runner_identity], runner_digest: observation[:runner_digest],
          raw_observation_digest: observation[:raw_observation_digest]
        )
        @measurements_mutex.synchronize { @measurements << measurement }
        publish_status("ready", reason)
        measurement
      rescue ArgumentError, BackendError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError => error
        publish_status("failed", reason, error)
        raise BackendError, "backend switch failed: #{error.message}"
      end

      alias switch switch!

      def switch_to(target = nil, reason: "manual switch")
        switch!(target: target, reason: reason)
      end

      def connection_loss_measurements
        measurements
      end

      def probe
        if @capability_probe.respond_to?(:ebpf?)
          @capability_probe.ebpf?
        elsif @capability_probe.respond_to?(:ebpf)
          @capability_probe.ebpf
        elsif @capability_probe.respond_to?(:call)
          !!@capability_probe.call
        else
          false
        end
      end

      def backend_status
        status
      end

      private

      RuleSetSnapshot = Struct.new(:rules, :revision, keyword_init: true) do
        def rule_map
          rules.to_h { |rule| [rule.key, rule] }
        end
      end

      def select_backend
        probe_result = probe
        if probe_result && backend_attachable?(@ebpf)
          @selected = @ebpf
          publish_selection_status("eBPF verifier probe succeeded#{verifier_probe_summary}; attach pending")
        elsif backend_attachable?(@nftables)
          @selected = @nftables
          reason = if probe_result
                     "eBPF verifier probe succeeded but adapter is unavailable; nftables selected"
                   else
                     "eBPF verifier probe failed; nftables selected"
                   end
          publish_selection_status(reason)
        else
          @selected = @nftables
          reason = if probe_result
                     "eBPF verifier probe succeeded but no production-capable proxy adapter is available"
                   else
                     "no production-capable proxy adapter is available"
                   end
          publish_status("unavailable", reason)
        end
      rescue ArgumentError, BackendError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError => error
        @selected = @nftables
        if backend_available?(@nftables)
          publish_selection_status("eBPF probe raised; nftables selected", error)
        else
          publish_status("unavailable", "eBPF probe raised and nftables adapter is unavailable", error)
        end
      end

      # Summarize the kernel verifier decision behind an eBPF selection so
      # node status names the accepted program rather than a boolean.
      def verifier_probe_summary
        result = @ebpf.respond_to?(:last_verifier_probe) ? @ebpf.last_verifier_probe : nil
        return "" unless result.is_a?(Hash) && result["accepted"] == true

        " (kernel #{result["kernelRelease"]}, program id #{result["programId"]}, tag #{result["programTag"]}, " \
          "#{result["instructionCount"]} insns, verifier log sha256 #{result["verifierLogSha256"].to_s[0, 16]})"
      rescue StandardError
        ""
      end

      def resolve_backend(target)
        return target if target.respond_to?(:apply)

        case target.to_s.downcase
        when "ebpf", "bpf" then @ebpf
        when "nftables", "nft" then @nftables
        else raise BackendError, "unknown backend #{target.inspect}"
        end
      end

      def publish_status(state, reason, error = nil)
        snapshot = BackendStatus.new(backend: selected_backend, state: state, reason: reason,
                                     checked_at: @clock.call, error: error)
        @status_mutex.synchronize do
          @status = snapshot
          @last_error = error if error
        end
        if @node_status.respond_to?(:record_proxy_backend)
          @node_status.record_proxy_backend(snapshot.to_h)
        elsif @node_status.respond_to?(:update_proxy_backend)
          @node_status.update_proxy_backend(snapshot.to_h)
        end
      end

      def publish_selection_status(reason, error = nil)
        state = if backend_ready?(current)
                  "ready"
                elsif backend_attachable?(current)
                  "unattached"
                else
                  "unavailable"
                end
        publish_status(state, reason, error)
      end

      def backend_available?(backend)
        return false unless backend
        return !!backend.available? if backend.respond_to?(:available?)

        false
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def backend_attachable?(backend)
        return false unless backend
        return !!backend.attachable? if backend.respond_to?(:attachable?)

        backend_available?(backend)
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def backend_ready?(backend)
        backend.respond_to?(:ready?) && backend.ready? == true
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def ensure_backend_ready!(backend)
        return true if backend_ready?(backend)

        raise BackendError, "#{backend.name} attach returned without a verified ready state"
      end

      def backend_identity(backend)
        backend.respond_to?(:identity) ? backend.identity.to_s : backend.to_s
      end

      def test_adapter_mode?
        [@ebpf, @nftables].all? do |backend|
          adapter = backend.instance_variable_get(:@syscall_adapter)
          adapter.respond_to?(:test_adapter?) && adapter.test_adapter? == true
        end
      rescue StandardError
        false
      end

      def capture_connection_context(from_backend, target_backend, started_at)
        return {started_at: started_at, source: :test_adapter}.freeze if test_adapter_mode?

        observer = external_connection_observer
        unless connection_probe_available?
          raise BackendError,
                "connection-loss measurement requires an external connection tracker or probe"
        end

        snapshot = if observer.respond_to?(:before_switch)
                     observer.before_switch(from_backend: from_backend, to_backend: target_backend)
                   elsif observer.respond_to?(:snapshot)
                     observer.snapshot
                   end
        before = normalize_external_snapshot(snapshot, label: "before-switch")
        {
          started_at: started_at, before: before, source: :external_probe,
          runner_identity: external_probe_identity(observer), runner_digest: external_probe_digest(observer)
        }.freeze
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError => error
        raise BackendError, "external connection probe could not capture pre-switch state: #{error.message}"
      end

      def connection_probe_available?
        observer = external_connection_observer
        return false unless observer

        external_probe_authorized?(observer) &&
          (observer.respond_to?(:measure_switch) || observer.respond_to?(:measure) ||
           observer.respond_to?(:probe) || observer.respond_to?(:snapshot) || observer.respond_to?(:before_switch))
      end

      def measure_connection_switch(context, from_backend, target_backend)
        return model_connection_observation(target_backend) if context.fetch(:source) == :test_adapter

        probe = external_connection_observer
        after = if probe.respond_to?(:after_switch)
                  probe.after_switch(from_backend: from_backend, to_backend: target_backend)
                elsif probe.respond_to?(:snapshot)
                  probe.snapshot
                end
        after = normalize_external_snapshot(after, label: "after-switch")
        before_ids = context.fetch(:before).fetch(:connection_ids)
        after_ids = after.fetch(:connection_ids)
        raise BackendError, "external connection probe changed connection IDs during backend switch" unless before_ids == after_ids

        arguments = {
          from_backend: from_backend.name,
          to_backend: target_backend.name,
          before: context[:before],
          after: after,
          started_at: context[:started_at],
          switched_at: @clock.call
        }.freeze
        raw = if probe.respond_to?(:measure_switch)
                probe.measure_switch(**arguments)
              elsif probe.respond_to?(:measure)
                probe.measure(**arguments)
              elsif probe.respond_to?(:probe)
                probe.probe(**arguments)
              end
        normalize_external_observation(raw, context: context, after: after, probe: probe)
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError => error
        raise BackendError, "external connection probe did not produce a verified measurement: #{error.message}"
      end

      def normalize_external_snapshot(value, label:)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        raise BackendError, "external #{label} observation is missing" unless hash.is_a?(Hash)

        ids = hash[:connection_ids] || hash["connection_ids"] || hash[:connectionIDs] || hash["connectionIDs"]
        ids = Array(ids).map(&:to_s).reject(&:empty?).uniq.sort
        raise BackendError, "external #{label} observation must report connection IDs" if ids.empty?

        raw_digest = hash[:raw_observation_digest] || hash["raw_observation_digest"] ||
                     hash[:rawObservationDigest] || hash["rawObservationDigest"]
        canonical = hash.reject do |key, _value|
          %w[rawObservationDigest raw_observation_digest].include?(key.to_s)
        end
        unless valid_probe_digest?(raw_digest) && raw_digest == BackendParity.canonical_trace_digest(canonical)
          raise BackendError,
                "external #{label} observation raw digest is invalid"
        end

        {raw: canonical.freeze, connection_ids: ids.freeze, raw_observation_digest: raw_digest}.freeze
      end

      def normalize_external_observation(value, context:, after:, probe:)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        raise BackendError, "external connection probe returned no observation" unless hash.is_a?(Hash)

        active = hash[:active_connections] || hash["active_connections"] || hash["activeConnections"]
        lost = hash[:lost_connections] || hash["lost_connections"] || hash["lostConnections"]
        raise BackendError, "external connection probe must report active_connections and lost_connections" if active.nil? || lost.nil?

        active = Integer(active)
        lost = Integer(lost)
        raise BackendError, "external connection probe returned negative counts" if active.negative? || lost.negative?
        raise BackendError, "external connection probe reported more lost than active connections" if lost > active

        runner_identity = hash[:runner_identity] || hash["runner_identity"] || hash[:runnerIdentity] || hash["runnerIdentity"]
        runner_digest = hash[:runner_digest] || hash["runner_digest"] || hash[:runnerDigest] || hash["runnerDigest"]
        unless runner_identity == context.fetch(:runner_identity)
          raise BackendError,
                "external connection probe runner identity is required"
        end
        raise BackendError, "external connection probe runner digest is invalid" unless runner_digest == context.fetch(:runner_digest)

        raw = hash[:raw_observation] || hash["raw_observation"] || hash[:rawObservation] || hash["rawObservation"]
        raw_digest = hash[:raw_observation_digest] || hash["raw_observation_digest"] || hash[:rawObservationDigest] || hash["rawObservationDigest"]
        if raw.nil?
          raw = {"before" => context.fetch(:before).fetch(:raw), "after" => after.fetch(:raw),
                 "activeConnections" => active, "lostConnections" => lost}
        end
        unless valid_probe_digest?(raw_digest) && raw_digest == BackendParity.canonical_trace_digest(raw)
          raise BackendError,
                "external connection probe raw observation digest is invalid"
        end

        observed_ids = hash[:connection_ids] || hash["connection_ids"] || hash[:connectionIDs] || hash["connectionIDs"]
        observed_ids = Array(observed_ids).map(&:to_s).reject(&:empty?).uniq.sort
        unless observed_ids == context.fetch(:before).fetch(:connection_ids)
          raise BackendError,
                "external connection probe must bind connection IDs"
        end

        {active_connections: active, lost_connections: lost, measurement_source: "external_probe",
         runner_identity: runner_identity, runner_digest: runner_digest,
         raw_observation_digest: raw_digest}.freeze
      end

      def external_connection_observer
        return @connection_probe if @connection_probe && external_probe_authorized?(@connection_probe)

        tracker = @connection_tracker
        return nil unless tracker

        externally_authorized = if tracker.respond_to?(:external?)
                                  tracker.external? == true
                                elsif tracker.respond_to?(:production_capable?)
                                  tracker.production_capable? == true
                                else
                                  false
                                end
        externally_authorized ? tracker : nil
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        nil
      end

      def external_probe_authorized?(probe)
        return false unless probe

        externally_authorized = if probe.respond_to?(:external?)
                                  probe.external? == true
                                elsif probe.respond_to?(:production_capable?)
                                  probe.production_capable? == true
                                else
                                  false
                                end
        externally_authorized && valid_probe_identity?(probe)
      rescue ArgumentError, IOError, NoMethodError, RuntimeError, SystemCallError, TypeError
        false
      end

      def external_probe_identity(probe)
        identity = if probe.respond_to?(:runner_identity)
                     probe.runner_identity
                   elsif probe.respond_to?(:runnerIdentity)
                     probe.runnerIdentity
                   end
        raise BackendError, "external connection probe runner identity is required" unless identity.is_a?(String) && !identity.empty?

        identity
      end

      def external_probe_digest(probe)
        digest = if probe.respond_to?(:runner_digest)
                   probe.runner_digest
                 elsif probe.respond_to?(:runnerDigest)
                   probe.runnerDigest
                 end
        raise BackendError, "external connection probe runner digest is invalid" unless valid_probe_digest?(digest)

        digest
      end

      def valid_probe_identity?(probe)
        external_probe_identity(probe)
        external_probe_digest(probe)
        true
      rescue BackendError
        false
      end

      def valid_probe_digest?(value)
        value.to_s.match?(/\A[0-9a-f]{64}\z/i)
      end

      def model_connection_observation(target_backend)
        tracker = @connection_tracker
        old_connections = tracker.respond_to?(:connections) ? tracker.connections : []
        active = tracker.respond_to?(:size) ? tracker.size.to_i : old_connections.length
        lost = old_connections.count do |connection|
          target_backend.rules.none? do |rule|
            rule.backends.any? { |backend| backend_identity(backend) == backend_identity(connection.backend) }
          end
        end
        {active_connections: active, lost_connections: lost, measurement_source: "test_model"}.freeze
      end

      def rollback_switch!(from_backend, target_backend, target_attached:, old_detached:, old_detach_attempted:)
        rollback_errors = []
        @mutex.synchronize { @selected = from_backend }
        if target_attached
          begin
            target_backend.detach
          rescue StandardError => error
            rollback_errors << "target detach: #{error.message}"
          end
        end
        if old_detached || old_detach_attempted || !backend_ready?(from_backend)
          begin
            from_backend.attach
            ensure_backend_ready!(from_backend)
          rescue StandardError => error
            rollback_errors << "old backend restore: #{error.message}"
          end
        end
        raise BackendError, rollback_errors.join("; ") unless rollback_errors.empty?

        true
      end
    end
  end
end
