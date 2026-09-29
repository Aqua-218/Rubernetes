# frozen_string_literal: true

# Linux capability set manipulation for the workload bootstrap.  The default
# bounding set and the add/drop merge follow the Kubernetes v1.36.2 CRI
# defaults (the containerd/OCI default capability list); this class only
# turns a resolved set into capget/capset/prctl calls and exposes the same
# numbers for external verification through /proc/<pid>/status.

require "fiddle"
require_relative "error"
require_relative "security"

module Rubernetes
  module Platform
    module Linux
      class Capabilities
        class Error < StandardError; end

        # Values from include/uapi/linux/capability.h.
        LINUX_CAPABILITY_VERSION_3 = 0x2008_0522
        LINUX_CAPABILITY_U32S_3 = 2
        # Values from include/uapi/linux/prctl.h.
        PR_SET_KEEPCAPS = 8
        PR_CAPBSET_READ = 23
        PR_CAPBSET_DROP = 24
        PR_CAP_AMBIENT = 47
        PR_CAP_AMBIENT_IS_SET = 1
        PR_CAP_AMBIENT_RAISE = 2
        PR_CAP_AMBIENT_LOWER = 3
        PR_CAP_AMBIENT_CLEAR_ALL = 4

        # Capability numbers from include/uapi/linux/capability.h, including
        # the three that postdate Security::CAPABILITIES.
        NUMBERS = Security::CAPABILITIES.merge(
          "PERFMON" => 38,
          "BPF" => 39,
          "CHECKPOINT_RESTORE" => 40
        ).freeze

        # Default bounding/effective/permitted set granted by kubelet through
        # the CRI (containerd default capabilities, Kubernetes v1.36.2).
        DEFAULT_SET = %w[
          CHOWN DAC_OVERRIDE FSETID FOWNER MKNOD NET_RAW SETGID SETUID SETFCAP
          SETPCAP NET_BIND_SERVICE SYS_CHROOT KILL AUDIT_WRITE
        ].freeze

        CAPGET = Fiddle::Function.new(Fiddle::Handle::DEFAULT["capget"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
        CAPSET = Fiddle::Function.new(Fiddle::Handle::DEFAULT["capset"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
        PRCTL = Fiddle::Function.new(Fiddle::Handle::DEFAULT["prctl"], [Fiddle::TYPE_LONG] * 5, Fiddle::TYPE_INT)

        Sets = Data.define(:effective, :permitted, :inheritable) do
          def to_h
            {"effective" => format("%016x", effective), "permitted" => format("%016x", permitted), "inheritable" => format("%016x", inheritable)}
          end
        end

        # The kernel's highest capability is read once by the constructing
        # (agent-side) process; the workload child reuses it because its
        # /proc view may already be restricted when capabilities are applied.
        def initialize(last_cap: self.class.last_cap)
          @last_cap = Integer(last_cap)
        end

        attr_reader :last_cap

        def self.normalize_name(value)
          key = String(value).upcase.sub(/\ACAP_/, "")
          Security::CAPABILITY_ALIASES.fetch("CAP_#{key}", key)
        end

        def self.mask(names)
          Array(names).reduce(0) do |mask, name|
            normalized = normalize_name(name)
            bit = NUMBERS.fetch(normalized) { raise Error, "unknown Linux capability #{name.inspect}" }
            mask | (1 << bit)
          end
        end

        def self.names(mask)
          NUMBERS.select { |_name, bit| (Integer(mask) & (1 << bit)).positive? }.keys.sort
        end

        # Highest capability the running kernel knows, read from the kernel
        # rather than assumed from headers so bounding-set drops cover every
        # bit the kernel would otherwise leave enabled.
        def self.last_cap
          Integer(File.read("/proc/sys/kernel/cap_last_cap").strip)
        end

        def self.full_mask(last_cap = self.last_cap)
          (1 << (Integer(last_cap) + 1)) - 1
        end

        # Merge Kubernetes securityContext.capabilities onto the default set.
        # `ALL` is honored in both directions exactly as containerd does:
        # drop ALL clears the default set before additions are applied.
        def self.resolve(add: [], drop: [], privileged: false, last_cap: self.last_cap)
          return full_mask(last_cap) if privileged

          names = DEFAULT_SET.dup
          drops = Array(drop).map { |name| normalize_name(name) }
          adds = Array(add).map { |name| normalize_name(name) }
          names = [] if drops.include?("ALL")
          names -= drops
          if adds.include?("ALL")
            return full_mask(last_cap)
          end

          adds.each { |name| names << name unless names.include?(name) }
          mask(names) & full_mask(last_cap)
        end

        def self.read_status(pid = "self")
          values = File.read("/proc/#{pid}/status").lines.each_with_object({}) do |line, result|
            key, raw = line.split(":", 2)
            next unless raw

            result[key] = raw.strip
          end
          {
            "CapInh" => values.fetch("CapInh").to_i(16),
            "CapPrm" => values.fetch("CapPrm").to_i(16),
            "CapEff" => values.fetch("CapEff").to_i(16),
            "CapBnd" => values.fetch("CapBnd").to_i(16),
            "CapAmb" => values.fetch("CapAmb").to_i(16),
            "NoNewPrivs" => Integer(values.fetch("NoNewPrivs", "0")),
            "Seccomp" => Integer(values.fetch("Seccomp", "0"))
          }
        end

        def capget
          header = Fiddle::Pointer[[LINUX_CAPABILITY_VERSION_3, 0].pack("L<2")]
          data = Fiddle::Pointer.malloc(4 * 3 * LINUX_CAPABILITY_U32S_3, Fiddle::RUBY_FREE)
          result = CAPGET.call(header, data)
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "capget", resource_id: "security:capabilities") if result == -1

          words = data[0, 4 * 3 * LINUX_CAPABILITY_U32S_3].unpack("L<6")
          Sets.new(
            effective: words[0] | (words[3] << 32),
            permitted: words[1] | (words[4] << 32),
            inheritable: words[2] | (words[5] << 32)
          )
        end

        def capset(effective:, permitted:, inheritable:)
          header = Fiddle::Pointer[[LINUX_CAPABILITY_VERSION_3, 0].pack("L<2")]
          data = Fiddle::Pointer[[
            effective & 0xffff_ffff, permitted & 0xffff_ffff, inheritable & 0xffff_ffff,
            (effective >> 32) & 0xffff_ffff, (permitted >> 32) & 0xffff_ffff, (inheritable >> 32) & 0xffff_ffff
          ].pack("L<6")]
          result = CAPSET.call(header, data)
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "capset", resource_id: "security:capabilities") if result == -1

          true
        end

        def keep_caps(enabled)
          prctl(PR_SET_KEEPCAPS, enabled ? 1 : 0, 0, 0, 0, operation: "prctl(PR_SET_KEEPCAPS)")
        end

        def bounding_set_drop(bit)
          prctl(PR_CAPBSET_DROP, Integer(bit), 0, 0, 0, operation: "prctl(PR_CAPBSET_DROP, #{bit})")
        end

        def bounding_set_has?(bit)
          result = PRCTL.call(PR_CAPBSET_READ, Integer(bit), 0, 0, 0)
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "prctl(PR_CAPBSET_READ)", resource_id: "security:capabilities") if result == -1

          result == 1
        end

        def ambient_clear_all
          prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, operation: "prctl(PR_CAP_AMBIENT, CLEAR_ALL)")
        end

        # Apply the resolved set.  Ordering matters (R-1.6):
        # 1. raise effective to the current permitted set so CAP_SETPCAP is
        #    usable even after a KEEPCAPS setuid cleared the effective set;
        # 2. drop every capability outside the target from the bounding set
        #    while CAP_SETPCAP is still effective;
        # 3. set effective/permitted to the target, inheritable and ambient
        #    to empty (containerd stopped populating inheritable after
        #    CVE-2022-24769), so a non-root exec cannot regain capabilities;
        # 4. clear KEEPCAPS so the setting does not leak into the workload.
        def apply(target_mask, last_cap: @last_cap)
          target = Integer(target_mask)
          current = capget
          capset(effective: current.permitted, permitted: current.permitted, inheritable: 0)
          (0..Integer(last_cap)).each do |bit|
            next unless (target & (1 << bit)).zero?
            next unless bounding_set_has?(bit)

            bounding_set_drop(bit)
          end
          missing = target & ~current.permitted
          unless missing.zero?
            raise Error, "capabilities #{self.class.names(missing).join(", ")} are not in the permitted set"
          end
          ambient_clear_all
          capset(effective: target, permitted: target, inheritable: 0)
          keep_caps(false)
          verify!(target, last_cap: last_cap)
        end

        def verify!(target, last_cap: @last_cap)
          status = self.class.read_status
          full = self.class.full_mask(last_cap)
          observed = {
            "CapBnd" => status.fetch("CapBnd") & full,
            "CapEff" => status.fetch("CapEff") & full,
            "CapPrm" => status.fetch("CapPrm") & full,
            "CapInh" => status.fetch("CapInh") & full,
            "CapAmb" => status.fetch("CapAmb") & full
          }
          expected = {"CapBnd" => target, "CapEff" => target, "CapPrm" => target, "CapInh" => 0, "CapAmb" => 0}
          mismatch = expected.reject { |key, value| observed.fetch(key) == value }
          unless mismatch.empty?
            detail = mismatch.map { |key, value| "#{key} expected=#{format("%016x", value)} actual=#{format("%016x", observed.fetch(key))}" }
            raise Error, "capability readback mismatch: #{detail.join("; ")}"
          end
          observed
        end

        private

        def prctl(option, arg2, arg3, arg4, arg5, operation:)
          result = PRCTL.call(option, arg2, arg3, arg4, arg5)
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: operation, resource_id: "security:capabilities") if result == -1

          true
        end
      end
    end
  end
end
