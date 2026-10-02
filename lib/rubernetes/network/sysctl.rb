# frozen_string_literal: true

require_relative "durable_state"
require_relative "errors"
require_relative "support"

module Rubernetes
  module Network
    # Node-scoped forwarding sysctls are shared infrastructure, just like the
    # bridge.  This manager journals the original bytes before the first
    # write, owns only the exact value it installed, and restores it when the
    # final Pod reference is released.
    class SysctlManager
      STATIC_TARGETS = {
        "net/ipv4/ip_forward" => "1",
        "net/ipv6/conf/all/forwarding" => "1",
        "net/ipv6/conf/default/forwarding" => "1",
        "net/ipv4/conf/all/rp_filter" => "0",
        "net/ipv4/conf/default/rp_filter" => "0",
        # kube-proxy requires bridged Pod traffic to traverse netfilter: a
        # Service reply from a Pod on the same bridge is switched at L2 and,
        # without br_netfilter, never has its DNAT reversed (the client sees
        # a SYN-ACK from the Pod IP and resets).  Every CNI bridge plugin
        # sets these to 1.
        "net/bridge/bridge-nf-call-iptables" => "1",
        "net/bridge/bridge-nf-call-ip6tables" => "1",
        "net/bridge/bridge-nf-call-arptables" => "0"
      }.freeze

      BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"

      def self.current_boot_id
        File.binread(BOOT_ID_PATH).strip
      rescue SystemCallError, IOError
        nil
      end

      def initialize(state_path:, root: "/proc/sys", journal: nil, fsync: true, boot_id: self.class.current_boot_id)
        @root = File.expand_path(String(root))
        @journal = journal
        @boot_id = boot_id
        @store = DurableState.new(state_path, default: default_state, fsync: fsync)
        @state = normalize_state(@store.read)
        @mutex = Mutex.new
        discard_previous_boot!
      end

      # `operation_id` is the sandbox's network operation: the records this
      # call journals are filed under it so the ownership ledger retires them
      # with the operation (OwnershipLedger forgets finished operations and
      # rewrites the journal without their records).  Journaled under the
      # manager's own id, ~1300 of one worker's 1642 post-round records were
      # these acquire/release pairs, which the ledger had to keep for ever.
      # The state file, not the journal, is what recovery reads.
      def acquire(owner:, bridge:, operation_id: nil)
        owner_id = Support.identifier(owner, "sysctl owner")
        bridge_name = interface_name(bridge)
        @mutex.synchronize do
          if @state.fetch("state") == "active"
            verify_active!(bridge_name)
            owners = (@state.fetch("owners") + [owner_id]).uniq.sort
            persist!(@state.merge("owners" => owners), "network_sysctl_reference_acquired", operation_id: operation_id)
            return snapshot
          end

          entries = target_entries(bridge_name).map do |path, target|
            {"path" => path, "original" => read_exact(path), "target" => target}
          end
          pending = {"version" => 1, "state" => "applying", "owners" => [owner_id],
                     "bridge" => bridge_name, "netns_inode" => File.stat(Netlink::THREAD_NAMESPACE_PATH).ino,
                     "entries" => entries}
          persist!(pending, "network_sysctl_apply_started", operation_id: operation_id)
          written = []
          begin
            entries.each do |entry|
              write_exact(entry.fetch("path"), entry.fetch("target"))
              written << entry
            end
            persist!(pending.merge("state" => "active"), "network_sysctl_apply_committed", operation_id: operation_id)
            snapshot
          rescue StandardError => error
            rollback_errors = restore_entries(written.reverse)
            persist!(default_state.merge("last_error" => error.message,
                                         "rollback_errors" => rollback_errors),
                     "network_sysctl_apply_rolled_back", operation_id: operation_id)
            detail = rollback_errors.empty? ? "" : "; rollback: #{rollback_errors.join("; ")}"
            raise EffectError, "network sysctl bootstrap failed: #{error.message}#{detail}"
          end
        end
      end

      def release(owner:, operation_id: nil)
        owner_id = Support.identifier(owner, "sysctl owner")
        @mutex.synchronize do
          return false if @state.fetch("state") == "inactive"

          owners = @state.fetch("owners").reject { |entry| entry == owner_id }
          unless owners.empty?
            persist!(@state.merge("owners" => owners), "network_sysctl_reference_released", operation_id: operation_id)
            return true
          end

          persist!(@state.merge("state" => "rolling_back", "owners" => []),
                   "network_sysctl_rollback_started", operation_id: operation_id)
          errors = restore_entries(@state.fetch("entries").reverse)
          unless errors.empty?
            persist!(@state.merge("state" => "unknown", "owners" => []),
                     "network_sysctl_rollback_failed", operation_id: operation_id)
            raise OwnershipError, "network sysctl rollback lost ownership: #{errors.join("; ")}"
          end
          persist!(default_state, "network_sysctl_rollback_committed", operation_id: operation_id)
          true
        end
      end

      # Crash recovery is fail-closed.  An active journal may reassert only a
      # value still equal to either our target or the original captured value;
      # any third-party value proves that ownership has been lost.
      def recover
        @mutex.synchronize do
          return snapshot if @state.fetch("state") == "inactive"

          @state.fetch("entries").each do |entry|
            current = read_exact(entry.fetch("path"))
            unless [entry.fetch("original"), entry.fetch("target")].include?(current)
              raise OwnershipError, "network sysctl #{entry.fetch("path")} changed outside its journal"
            end

            write_exact(entry.fetch("path"), entry.fetch("target")) unless current == entry.fetch("target")
          end
          persist!(@state.merge("state" => "active"), "network_sysctl_recovered")
          snapshot
        end
      end

      def shutdown
        owners = @mutex.synchronize { @state.fetch("owners").dup }
        owners.each { |owner| release(owner: owner) }
        true
      end

      def snapshot
        Support.immutable(@state.merge("refcount" => @state.fetch("owners").length))
      end

      private

      def default_state
        {"version" => 1, "state" => "inactive", "owners" => [], "bridge" => nil,
         "netns_inode" => nil, "entries" => []}
      end

      def normalize_state(value)
        default_state.merge(Support.canonical(value || {}))
      end

      def target_entries(bridge)
        dynamic = {
          "net/ipv4/conf/#{bridge}/rp_filter" => "0",
          "net/ipv6/conf/#{bridge}/forwarding" => "1"
        }
        STATIC_TARGETS.merge(dynamic).to_h do |relative, target|
          path = File.join(@root, relative)
          raise OwnershipError, "required network sysctl is unavailable: #{path}" unless File.file?(path) && !File.symlink?(path)

          [path, target]
        end
      end

      def verify_active!(bridge)
        raise OwnershipError, "network sysctl bridge changed while referenced" unless @state.fetch("bridge") == bridge
        raise OwnershipError, "network namespace changed while sysctls are referenced" unless
          @state.fetch("netns_inode") == File.stat(Netlink::THREAD_NAMESPACE_PATH).ino

        @state.fetch("entries").each do |entry|
          current = read_exact(entry.fetch("path"))
          raise OwnershipError, "network sysctl #{entry.fetch("path")} changed while owned" unless current == entry.fetch("target")
        end
      end

      def restore_entries(entries)
        Array(entries).filter_map do |entry|
          path = entry.fetch("path")
          current = read_exact(path)
          if current == entry.fetch("target")
            write_exact(path, entry.fetch("original"))
            nil
          else
            "#{path} expected owned value #{entry.fetch("target").inspect}, got #{current.inspect}"
          end
        rescue StandardError => error
          "#{path}: #{error.class}: #{error.message}"
        end
      end

      def read_exact(path)
        File.binread(path).strip
      rescue SystemCallError, IOError => error
        raise OwnershipError, "cannot read network sysctl #{path}: #{error.message}"
      end

      def write_exact(path, value)
        flags = File::WRONLY | File::TRUNC
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        File.open(path, flags) do |file|
          file.write("#{value}\n")
          file.flush
        end
        actual = read_exact(path)
        raise EffectError, "network sysctl #{path} read back #{actual.inspect}, expected #{value.inspect}" unless actual == value

        actual
      rescue SystemCallError, IOError => error
        raise EffectError, "cannot write network sysctl #{path}: #{error.message}"
      end

      JOURNAL_OPERATION_ID = "network:sysctl"

      def persist!(state, event, operation_id: nil)
        @store.replace(state)
        @state = Support.copy(state)
        append_journal(event, {"state" => @state.fetch("state"), "owners" => @state.fetch("owners"),
                               "bridge" => @state["bridge"], "netns_inode" => @state["netns_inode"]},
                       operation_id: operation_id)
      end

      def append_journal(event, payload, operation_id: nil)
        return unless @journal

        parameters = @journal.method(:append).parameters
        if parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :operation_id }
          @journal.append(operation_id: operation_id.nil? ? JOURNAL_OPERATION_ID : String(operation_id), event: event, payload: payload)
        else
          @journal.append(event: event, payload: payload)
        end
      end

      def interface_name(value)
        name = Support.string(value, "bridge name")
        raise ValidationError, "invalid bridge name" unless name.match?(/\A[a-zA-Z0-9_.-]+\z/) && name.bytesize < Netlink::IFNAMSIZ

        name
      end
    end
  end
end
