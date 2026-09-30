# frozen_string_literal: true

# Linux security policy preparation.  The adapter discovers kernel capabilities
# and executes an already validated, dependency-ordered plan; it does not make
# scheduling or admission decisions.  Low-level actions are injectable so the
# same plan can be checked at L0/L1 without changing policy code.

require "rbconfig"
require_relative "abi_manifest"
require_relative "syscall"
require_relative "seccomp_profile"

module Rubernetes
  module Platform
    module Linux
      class Security
        class Error < StandardError; end
        class Unsupported < Error; end
        class InvalidContext < Error; end
        class DependencyCycle < Error; end

        CAPABILITIES = {
          "AUDIT_CONTROL" => 30,
          "AUDIT_READ" => 37,
          "AUDIT_WRITE" => 29,
          "BLOCK_SUSPEND" => 36,
          "CHOWN" => 0,
          "DAC_OVERRIDE" => 1,
          "DAC_READ_SEARCH" => 2,
          "FOWNER" => 3,
          "FSETID" => 4,
          "IPC_LOCK" => 14,
          "IPC_OWNER" => 15,
          "KILL" => 5,
          "LEASE" => 28,
          "LINUX_IMMUTABLE" => 9,
          "MAC_ADMIN" => 33,
          "MAC_OVERRIDE" => 32,
          "MKNOD" => 27,
          "NET_ADMIN" => 12,
          "NET_BIND_SERVICE" => 10,
          "NET_BROADCAST" => 11,
          "NET_RAW" => 13,
          "SETFCAP" => 31,
          "SETGID" => 6,
          "SETPCAP" => 8,
          "SETUID" => 7,
          "SYS_ADMIN" => 21,
          "SYS_BOOT" => 22,
          "SYS_CHROOT" => 18,
          "SYS_MODULE" => 16,
          "SYS_NICE" => 23,
          "SYS_PACCT" => 20,
          "SYS_PTRACE" => 19,
          "SYS_RAWIO" => 17,
          "SYS_RESOURCE" => 24,
          "SYS_TIME" => 25,
          "SYS_TTY_CONFIG" => 26,
          "SYSLOG" => 34,
          "WAKE_ALARM" => 35
        }.freeze
        CAPABILITY_ALIASES = {
          "CAP_CHOWN" => "CHOWN", "CAP_DAC_OVERRIDE" => "DAC_OVERRIDE", "CAP_DAC_READ_SEARCH" => "DAC_READ_SEARCH",
          "CAP_FOWNER" => "FOWNER", "CAP_FSETID" => "FSETID", "CAP_KILL" => "KILL", "CAP_SETGID" => "SETGID",
          "CAP_SETUID" => "SETUID", "CAP_SETPCAP" => "SETPCAP", "CAP_NET_BIND_SERVICE" => "NET_BIND_SERVICE",
          "CAP_NET_RAW" => "NET_RAW", "CAP_SYS_CHROOT" => "SYS_CHROOT", "CAP_MKNOD" => "MKNOD",
          "CAP_AUDIT_WRITE" => "AUDIT_WRITE", "CAP_SETFCAP" => "SETFCAP", "CAP_SYS_ADMIN" => "SYS_ADMIN"
        }.freeze
        ARCHITECTURES = {
          "x86_64" => 0xC000_003E,
          "amd64" => 0xC000_003E,
          "aarch64" => 0xC000_00B7,
          "arm64" => 0xC000_00B7
        }.freeze
        SECCOMP_ACTIONS = {kill: 0x8000_0000, errno: 0x0005_0000, allow: 0x7FFF_0000}.freeze
        # Default bounding set kubelet grants through the CRI (containerd's
        # default capabilities); Capabilities::DEFAULT_SET mirrors it.
        CRI_DEFAULT_CAPABILITIES = %w[
          CHOWN DAC_OVERRIDE FSETID FOWNER MKNOD NET_RAW SETGID SETUID SETFCAP
          SETPCAP NET_BIND_SERVICE SYS_CHROOT KILL AUDIT_WRITE
        ].freeze
        STEP_DEPENDENCIES = {
          namespace: [],
          mount: [:namespace],
          groups: [:mount],
          identity: [:groups],
          capabilities: [:identity],
          securebits: [:capabilities],
          no_new_privs: [:securebits],
          lsm: [:no_new_privs],
          rlimit: [:lsm],
          seccomp: %i[no_new_privs capabilities rlimit],
          close_fds: [:seccomp],
          execveat: [:close_fds]
        }.freeze

        Probe = Data.define(:architecture, :capabilities, :no_new_privs, :seccomp, :landlock, :details) do
          def capability?(name)
            capabilities.fetch(normalize_name(name), false)
          end

          def available?(feature)
            case feature.to_sym
            when :no_new_privs then no_new_privs || details.fetch("no_new_privs_supported", false)
            when :seccomp then seccomp
            when :landlock then landlock
            else capabilities.fetch(feature.to_s.upcase, false)
            end
          end

          def to_h
            {
              "architecture" => architecture,
              "capabilities" => capabilities,
              "no_new_privs" => no_new_privs,
              "seccomp" => seccomp,
              "landlock" => landlock,
              "details" => details
            }
          end

          private

          def normalize_name(name)
            value = String(name).upcase.delete_prefix('CAP_')
            CAPABILITY_ALIASES.fetch("CAP_#{value}", value)
          end
        end

        Context = Data.define(
          :run_as_user, :run_as_group, :supplemental_groups, :fs_group, :capabilities,
          :privileged, :allow_privilege_escalation, :seccomp, :landlock,
          :apparmor, :selinux, :proc_mount, :read_only_root_filesystem,
          :rlimits, :namespace, :fd_allowlist
        ) do
          def self.from(value)
            return value if value.is_a?(self)

            input = value.respond_to?(:to_h) ? value.to_h : {}
            capabilities = input[:capabilities] || input["capabilities"] || {}
            capabilities = {add: capabilities, drop: []} if capabilities.is_a?(Array)
            new(
              run_as_user: fetch(input, :run_as_user, :runAsUser),
              run_as_group: fetch(input, :run_as_group, :runAsGroup),
              supplemental_groups: Array(fetch(input, :supplemental_groups, :supplementalGroups)).map { |item| Integer(item) },
              fs_group: fetch(input, :fs_group, :fsGroup),
              capabilities: {
                add: Array(fetch(capabilities, :add)).map { |item| String(item) },
                drop: Array(fetch(capabilities, :drop)).map { |item| String(item) }
              },
              privileged: Boolean(fetch(input, :privileged, default: false)),
              allow_privilege_escalation: fetch(input, :allow_privilege_escalation, :allowPrivilegeEscalation),
              seccomp: fetch(input, :seccomp, :seccomp_profile, :seccompProfile, default: "RuntimeDefault"),
              landlock: fetch(input, :landlock, default: nil),
              apparmor: fetch(input, :apparmor, :appArmorProfile),
              selinux: fetch(input, :selinux, :seLinuxOptions),
              proc_mount: fetch(input, :proc_mount, :procMount, default: "Default"),
              read_only_root_filesystem: Boolean(fetch(input, :read_only_root_filesystem, :readOnlyRootFilesystem, default: false)),
              rlimits: (fetch(input, :rlimits, default: {}) || {}).to_h,
              namespace: fetch(input, :namespace, default: {}),
              fd_allowlist: Array(fetch(input, :fd_allowlist, :fdAllowlist, default: [0, 1, 2])).map { |item| Integer(item) }
            )
          rescue ArgumentError, TypeError => error
            raise InvalidContext, "invalid security context: #{error.message}"
          end

          def privileged?
            privileged == true
          end

          def no_new_privs_required?
            allow_privilege_escalation == false || seccomp_name != "Unconfined" || landlock
          end

          def seccomp_name
            value = seccomp.respond_to?(:to_h) ? seccomp.to_h : seccomp
            value.is_a?(Hash) ? String(value[:type] || value["type"] || "RuntimeDefault") : String(value || "RuntimeDefault")
          end

          # `seccompProfile.localhostProfile`, relative to the node's seccomp
          # profile root.
          def seccomp_localhost_profile
            value = seccomp.respond_to?(:to_h) ? seccomp.to_h : seccomp
            return nil unless value.is_a?(Hash)

            profile = value[:localhostProfile] || value["localhostProfile"] || value[:localhost_profile] || value["localhost_profile"]
            profile.nil? ? nil : String(profile)
          end

          # The capability names the workload will hold (the CRI default set
          # plus/minus the Pod's add/drop, everything when privileged); the
          # RuntimeDefault seccomp profile is evaluated for this set.
          def effective_capability_names
            return CAPABILITIES.keys.map { |name| "CAP_#{name}" } if privileged?

            adds = Array(capabilities[:add] || capabilities["add"]).map { |name| String(name).upcase.delete_prefix('CAP_') }
            drops = Array(capabilities[:drop] || capabilities["drop"]).map { |name| String(name).upcase.delete_prefix('CAP_') }
            names = CRI_DEFAULT_CAPABILITIES.dup
            names = [] if drops.include?("ALL")
            names -= drops
            return CAPABILITIES.keys.map { |name| "CAP_#{name}" } if adds.include?("ALL")

            adds.each { |name| names << name unless names.include?(name) }
            names.map { |name| "CAP_#{name}" }
          end

          def landlock_required?
            !landlock.nil?
          end

          def self.fetch(input, *keys, default: nil)
            keys.each do |key|
              return input[key] if input.key?(key)

              string = key.to_s
              return input[string] if input.key?(string)
            end
            default
          end

          def self.Boolean(value)
            return value if [true, false].include?(value)

            return false if value.nil?

            raise ArgumentError, "boolean field must be true or false"
          end
        end

        Step = Data.define(:name, :dependencies)
        Plan = Data.define(:context, :steps, :seccomp_program, :probe) do
          def step_names
            steps.map(&:name)
          end

          def to_h
            {
              "steps" => step_names.map(&:to_s),
              "seccomp" => seccomp_program&.to_h,
              "probe" => probe.to_h
            }
          end
        end

        Instruction = Data.define(:code, :jt, :jf, :k) do
          def to_h
            {"code" => code, "jt" => jt, "jf" => jf, "k" => k}
          end
        end
        SeccompProgram = Data.define(:architecture, :action, :instructions, :allowed_syscalls, :profile) do
          def initialize(architecture:, action:, instructions:, allowed_syscalls:, profile: nil)
            super
          end

          def to_h
            {
              "architecture" => architecture,
              "action" => action,
              "instructions" => instructions.map(&:to_h),
              "allowed_syscalls" => allowed_syscalls,
              "profile" => profile.respond_to?(:name) ? profile.name : nil,
              "rule_count" => profile.respond_to?(:rules) ? profile.rules.length : nil
            }.compact
          end
        end

        # Compiles a seccomp profile (Seccomp::Profile) into classic BPF.
        #
        # Program shape: the architecture check comes first (a mismatch is a
        # kill, so a foreign-ABI filter can never turn into allow-all), then
        # the syscall number is loaded and the profile's rules are matched in
        # order.  A rule without argument conditions is a chain of JEQ on the
        # syscall numbers straight to its return; a rule with conditions
        # jumps into a block that checks each 64-bit argument as two 32-bit
        # words and falls through to the next rule on the first failed check.
        # Unmatched calls receive the profile's default action.
        #
        # Syscall numbers come from the architecture's ABI manifest, never
        # from the host process; a rule naming a syscall the architecture does
        # not have is skipped, which is libseccomp's behaviour too.
        class SeccompCompiler
          AUDIT_ARCH_OFFSET = 4
          SYSCALL_OFFSET = 0
          ARGS_OFFSET = 16
          BPF_LD_W_ABS = 0x20
          BPF_JMP_JA = 0x05
          BPF_JMP_JEQ_K = 0x15
          BPF_JMP_JGT_K = 0x25
          BPF_JMP_JGE_K = 0x35
          BPF_ALU_AND_K = 0x54
          BPF_RET_K = 0x06
          MAX_JUMP = 255
          # Names per JEQ chain so every jump stays within the 8-bit offset.
          CHUNK = 128
          RETURN_VALUES = {
            allow: 0x7FFF_0000, errno: 0x0005_0000, kill: 0x8000_0000, kill_process: 0x8010_0000,
            trap: 0x0003_0000, log: 0x7FFC_0000, trace: 0x7FF0_0000, notify: 0x7FC0_0000
          }.freeze
          # The legacy hand-written allow-list is kept only as the shape of the
          # `allowlist:` compatibility path; RuntimeDefault comes from
          # Seccomp::RuntimeDefault.
          DEFAULT_ALLOW = Seccomp::RuntimeDefault::ALLOW
          DEFAULT_SYSCALL_NUMBERS = {
            "brk" => 12, "clock_nanosleep" => 230, "close" => 3, "dup2" => 33, "execve" => 59, "execveat" => 322,
            "exit" => 60, "exit_group" => 231, "fstat" => 5, "futex" => 202, "getcwd" => 79,
            "getdents64" => 217, "getpid" => 39, "getppid" => 110, "getrandom" => 318,
            "ioctl" => 16, "lseek" => 8, "mmap" => 9, "mprotect" => 10, "munmap" => 11,
            "nanosleep" => 35, "openat" => 257, "pipe2" => 293, "poll" => 7, "ppoll" => 271,
            "prctl" => 157, "read" => 0, "rt_sigaction" => 13, "rt_sigprocmask" => 14,
            "rt_sigreturn" => 15, "sched_yield" => 24, "set_tid_address" => 218, "setgid" => 106,
            "setgroups" => 116, "setuid" => 105, "sigaltstack" => 131, "statx" => 332,
            "tgkill" => 234, "uname" => 63, "wait4" => 61, "write" => 1
          }.freeze

          Pending = Struct.new(:code, :jt, :jf, :k)

          # A tiny label-resolving assembler for the forward-only jumps
          # classic BPF allows.
          class Assembler
            def initialize
              @instructions = []
              @labels = {}
            end

            def emit(code, jt: 0, jf: 0, k: 0)
              @instructions << Pending.new(code, jt, jf, k)
              self
            end

            def label(name)
              raise Unsupported, "seccomp label #{name.inspect} defined twice" if @labels.key?(name)

              @labels[name] = @instructions.length
              name
            end

            def resolve
              @instructions.each_with_index.map do |pending, index|
                jt = offset(pending.jt, index)
                jf = offset(pending.jf, index)
                k = pending.code == BPF_JMP_JA ? offset(pending.k, index) : pending.k
                Instruction.new(code: pending.code, jt: jt, jf: jf, k: k)
              end.freeze
            end

            private

            def offset(target, index)
              return Integer(target) unless target.is_a?(Symbol)

              position = @labels.fetch(target) { raise Unsupported, "seccomp label #{target.inspect} is undefined" }
              delta = position - (index + 1)
              raise Unsupported, "seccomp jump to #{target} is backwards" if delta.negative?
              raise Unsupported, "seccomp jump to #{target} exceeds #{MAX_JUMP} instructions" if delta > MAX_JUMP && target != :__ja__

              delta
            end
          end

          def initialize(architecture: nil, syscall_numbers: {}, allowlist: nil, manifest: nil)
            @architecture = normalize_architecture(architecture)
            @manifest = manifest || ABIManifest.load(architecture: @architecture)
            defaults = if @manifest.respond_to?(:seccomp_syscalls)
                         @manifest.seccomp_syscalls
                       else
                         @architecture == "aarch64" ? {} : DEFAULT_SYSCALL_NUMBERS
                       end
            @syscall_numbers = defaults.merge(syscall_numbers.transform_keys(&:to_s)).transform_values { |value| Integer(value) }
            names = allowlist.nil? ? nil : Array(allowlist).map(&:to_s)
            names -= ["arch_prctl"] if names && @architecture == "aarch64"
            @allowlist = names&.uniq&.sort&.freeze
          end

          attr_reader :architecture, :syscall_numbers

          def allowlist
            @allowlist || DEFAULT_ALLOW
          end

          # `profile` is a Seccomp::Profile; without one the RuntimeDefault
          # profile for `capabilities` (or, when the compiler was built with
          # an explicit `allowlist:`, a plain allow-list) is compiled.
          def compile(profile: nil, capabilities: nil, action: :errno, errno: Errno::EPERM::Errno)
            action = action.to_sym
            raise ArgumentError, "unsupported seccomp action #{action.inspect}" unless %i[errno kill].include?(action)

            profile ||= if @allowlist
                          missing = @allowlist.reject { |name| @syscall_numbers.key?(name) }
                          raise Unsupported, "syscall numbers are missing for #{missing.join(", ")}" unless missing.empty?

                          Seccomp::Profile.new(default_action: action, default_errno: Integer(errno),
                                               rules: [Seccomp::Rule.new(names: @allowlist, action: :allow, errno_ret: nil, args: [].freeze)],
                                               architectures: [@architecture], name: "allowlist")
                        else
                          Seccomp::Profile.runtime_default(architecture: @architecture,
                                                           capabilities: capabilities || CRI_DEFAULT_CAPABILITIES)
                        end
            unless profile.architectures.empty? || profile.architectures.include?(@architecture)
              raise Unsupported, "seccomp profile does not list architecture #{@architecture}"
            end

            assembler = Assembler.new
            assembler.emit(BPF_LD_W_ABS, k: AUDIT_ARCH_OFFSET)
            assembler.emit(BPF_JMP_JEQ_K, jt: 1, jf: 0, k: ARCHITECTURES.fetch(@architecture))
            assembler.emit(BPF_RET_K, k: RETURN_VALUES.fetch(:kill))
            assembler.emit(BPF_LD_W_ABS, k: SYSCALL_OFFSET)
            allowed = []
            profile.rules.each_with_index do |rule, rule_index|
              numbers = rule.names.filter_map { |name| @syscall_numbers[name] && [name, @syscall_numbers[name]] }
              next if numbers.empty?

              allowed.concat(numbers.map(&:first)) if rule.action == :allow && rule.args.empty?
              numbers.each_slice(CHUNK).with_index do |chunk, chunk_index|
                hit = :"rule#{rule_index}_#{chunk_index}_hit"
                skip = :"rule#{rule_index}_#{chunk_index}_next"
                chunk.each { |(_name, number)| assembler.emit(BPF_JMP_JEQ_K, jt: hit, jf: 0, k: number) }
                assembler.emit(BPF_JMP_JA, k: skip)
                assembler.label(hit)
                rule.args.each_with_index do |arg, arg_index|
                  emit_condition(assembler, arg, pass: :"rule#{rule_index}_#{chunk_index}_arg#{arg_index}_ok", fail: skip)
                end
                assembler.emit(BPF_RET_K, k: return_value(rule.action, rule.errno_ret || profile.default_errno))
                assembler.label(skip)
              end
            end
            deny = return_value(profile.default_action, profile.default_errno)
            assembler.emit(BPF_RET_K, k: deny)
            instructions = assembler.resolve
            raise Unsupported, "seccomp program exceeds BPF_MAXINSNS (#{instructions.length})" if instructions.length > 4096

            SeccompProgram.new(architecture: @architecture, action: profile.default_action == :kill ? :kill : :errno,
                               instructions: instructions, allowed_syscalls: allowed.uniq.sort.freeze,
                               profile: profile)
          end

          private

          def return_value(action, errno)
            base = RETURN_VALUES.fetch(action.to_sym) { raise Unsupported, "unsupported seccomp action #{action.inspect}" }
            return base | (Integer(errno) & 0xFFFF) if action.to_sym == :errno

            base
          end

          # One 64-bit argument comparison as two 32-bit word checks.  Every
          # failing branch jumps to `fail` (the next rule); every satisfied
          # condition reaches `pass`, right after the block.
          def emit_condition(assembler, arg, pass:, fail:)
            low = ARGS_OFFSET + (8 * arg.index)
            high = low + 4
            value_low = arg.value & 0xFFFF_FFFF
            value_high = (arg.value >> 32) & 0xFFFF_FFFF
            case arg.op
            when "SCMP_CMP_EQ"
              assembler.emit(BPF_LD_W_ABS, k: high)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: fail, k: value_high)
              assembler.emit(BPF_LD_W_ABS, k: low)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: fail, k: value_low)
            when "SCMP_CMP_NE"
              assembler.emit(BPF_LD_W_ABS, k: high)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: pass, k: value_high)
              assembler.emit(BPF_LD_W_ABS, k: low)
              assembler.emit(BPF_JMP_JEQ_K, jt: fail, jf: 0, k: value_low)
            when "SCMP_CMP_MASKED_EQ"
              expected_low = arg.value_two & 0xFFFF_FFFF
              expected_high = (arg.value_two >> 32) & 0xFFFF_FFFF
              assembler.emit(BPF_LD_W_ABS, k: high)
              assembler.emit(BPF_ALU_AND_K, k: value_high)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: fail, k: expected_high)
              assembler.emit(BPF_LD_W_ABS, k: low)
              assembler.emit(BPF_ALU_AND_K, k: value_low)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: fail, k: expected_low)
            when "SCMP_CMP_GT"
              assembler.emit(BPF_LD_W_ABS, k: high)
              assembler.emit(BPF_JMP_JGT_K, jt: pass, jf: 0, k: value_high)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: fail, k: value_high)
              assembler.emit(BPF_LD_W_ABS, k: low)
              assembler.emit(BPF_JMP_JGT_K, jt: 0, jf: fail, k: value_low)
            when "SCMP_CMP_GE"
              assembler.emit(BPF_LD_W_ABS, k: high)
              assembler.emit(BPF_JMP_JGT_K, jt: pass, jf: 0, k: value_high)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: fail, k: value_high)
              assembler.emit(BPF_LD_W_ABS, k: low)
              assembler.emit(BPF_JMP_JGE_K, jt: 0, jf: fail, k: value_low)
            when "SCMP_CMP_LT"
              assembler.emit(BPF_LD_W_ABS, k: high)
              assembler.emit(BPF_JMP_JGT_K, jt: fail, jf: 0, k: value_high)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: pass, k: value_high)
              assembler.emit(BPF_LD_W_ABS, k: low)
              assembler.emit(BPF_JMP_JGE_K, jt: fail, jf: 0, k: value_low)
            when "SCMP_CMP_LE"
              assembler.emit(BPF_LD_W_ABS, k: high)
              assembler.emit(BPF_JMP_JGT_K, jt: fail, jf: 0, k: value_high)
              assembler.emit(BPF_JMP_JEQ_K, jt: 0, jf: pass, k: value_high)
              assembler.emit(BPF_LD_W_ABS, k: low)
              assembler.emit(BPF_JMP_JGT_K, jt: fail, jf: 0, k: value_low)
            else
              raise Unsupported, "unsupported seccomp argument operator #{arg.op}"
            end
            assembler.label(pass)
          end

          def normalize_architecture(value)
            value ||= RbConfig::CONFIG.fetch("host_cpu")
            key = String(value).downcase
            if ARCHITECTURES.key?(key)
              if key == "amd64"
                "x86_64"
              else
                key == "arm64" ? "aarch64" : key
              end
            else
              raise(Unsupported,
                    "unsupported seccomp architecture #{value.inspect}")
            end
          end
        end

        # Discovers current process capability state.  The adapter hook is
        # intentionally small: production may use procfs/syscalls while tests
        # can provide exact capability matrices and failure cases.
        class CapabilityProbe
          def initialize(adapter: nil, proc_status: "/proc/self/status", architecture: nil)
            @adapter = adapter
            @proc_status = proc_status
            @architecture = architecture
          end

          def call
            return normalize(@adapter.call) if @adapter.respond_to?(:call)
            return normalize(@adapter.probe) if @adapter.respond_to?(:probe)

            status = File.file?(@proc_status) ? File.read(@proc_status) : ""
            values = parse_status(status)
            capabilities = CAPABILITIES.keys.to_h do |name|
                             [name, bit_set?(values.fetch("CapBnd", 0), CAPABILITIES.fetch(name))]
                           end
            Probe.new(
              architecture: normalize_architecture(@architecture),
              capabilities: capabilities.freeze,
              no_new_privs: values.fetch("NoNewPrivs", 0) == 1,
              seccomp: seccomp_supported?,
              landlock: landlock_supported?,
              details: values.merge(
                "no_new_privs_supported" => no_new_privs_supported?,
                "seccomp_supported" => seccomp_supported?,
                "landlock_supported" => landlock_supported?
              ).freeze
            )
          rescue SystemCallError => error
            Probe.new(architecture: normalize_architecture(@architecture), capabilities: {}, no_new_privs: false, seccomp: false,
                      landlock: false, details: {"error" => "#{error.class}: #{error.message}"}.freeze)
          end

          alias probe call

          private

          def normalize(value)
            return value if value.is_a?(Probe)

            input = value.respond_to?(:to_h) ? value.to_h : {}
            Probe.new(
              architecture: String(input[:architecture] || input["architecture"] || normalize_architecture(@architecture)),
              capabilities: (input[:capabilities] || input["capabilities"] || {}).to_h.transform_keys do |key|
                String(key).upcase.delete_prefix('CAP_')
              end.freeze,
              no_new_privs: input.key?(:no_new_privs) ? input[:no_new_privs] : input.fetch("no_new_privs", false),
              seccomp: input.key?(:seccomp) ? input[:seccomp] : input.fetch("seccomp", false),
              landlock: input.key?(:landlock) ? input[:landlock] : input.fetch("landlock", false),
              details: (input[:details] || input.fetch("details", {})).freeze
            )
          end

          def parse_status(status)
            status.lines.each_with_object({}) do |line, values|
              key, raw = line.split(":", 2)
              next unless raw

              token = raw.strip
              values[key] =
                token.match?(/\A[0-9a-fA-F]+\z/) && key.start_with?("Cap") ? token.to_i(16) : Integer(token, exception: false) || token
            end
          end

          def bit_set?(value, bit)
            Integer(value).anybits?((1 << bit))
          end

          def normalize_architecture(value)
            key = String(value || RbConfig::CONFIG.fetch("host_cpu")).downcase
            return "x86_64" if %w[x86_64 amd64].include?(key)
            return "aarch64" if %w[aarch64 arm64].include?(key)

            raise Unsupported, "unsupported Linux architecture #{value.inspect}"
          end

          def no_new_privs_supported?
            result = Syscall.call(prctl_number, 39, 0, 0, 0, 0)
            result.value >= 0
          rescue StandardError
            false
          end

          def seccomp_supported?
            result = Syscall.call(prctl_number, 21, 0, 0, 0, 0)
            result.value >= 0
          rescue StandardError
            false
          end

          def landlock_supported?
            result = Syscall.call(444, 0, 0, 1)
            result.value >= 0
          rescue StandardError
            false
          end

          def prctl_number
            157
          end
        end

        class RecordingAdapter
          attr_reader :calls

          def initialize
            @calls = []
          end

          def call(name, **arguments)
            @calls << [name.to_sym, arguments.freeze]
            true
          end

          def apply(step:, context:, program: nil)
            call(step, context: context, program: program)
          end
        end

        def initialize(capability_probe: CapabilityProbe.new, adapter: RecordingAdapter.new, seccomp_compiler: nil,
                       seccomp_root: nil)
          @capability_probe = capability_probe
          @adapter = adapter
          @seccomp_compiler = seccomp_compiler
          @seccomp_root = seccomp_root && File.expand_path(String(seccomp_root))
        end

        attr_reader :capability_probe, :adapter, :seccomp_root

        # The seccomp program for a context: none for Unconfined and for a
        # privileged container (kubelet runs those unconfined), the
        # RuntimeDefault profile evaluated for the effective capabilities, or
        # a Localhost profile read from the node's profile root.  A Localhost
        # profile that cannot be read fails the container rather than
        # silently falling back to a weaker filter.
        def seccomp_program_for(context, compiler: nil)
          return nil if context.seccomp_name == "Unconfined" || context.privileged?

          compiler ||= @seccomp_compiler || SeccompCompiler.new
          capabilities = context.effective_capability_names
          profile = if context.seccomp_name == "Localhost"
                      load_localhost_profile(context.seccomp_localhost_profile, capabilities: capabilities,
                                                                                architecture: compiler.architecture)
                    else
                      Seccomp::Profile.runtime_default(architecture: compiler.architecture, capabilities: capabilities)
                    end
          compiler.compile(profile: profile, capabilities: capabilities)
        end

        def load_localhost_profile(relative, capabilities:, architecture:)
          raise InvalidContext, "seccomp Localhost profile requires localhostProfile" if relative.nil? || relative.empty?
          raise Unsupported, "seccomp Localhost profiles require a configured seccomp_root" if @seccomp_root.nil?

          components = relative.split("/")
          if relative.start_with?("/") || relative.include?("\0") || components.include?("..") || components.include?(".")
            raise InvalidContext, "seccomp localhostProfile #{relative.inspect} must be a relative path without traversal"
          end

          path = File.join(@seccomp_root, relative)
          raise InvalidContext, "seccomp Localhost profile #{relative.inspect} was not found under #{@seccomp_root}" unless File.file?(path)

          Seccomp::Profile.from_oci(File.read(path), capabilities: capabilities, architecture: architecture, name: "Localhost:#{relative}")
        rescue Seccomp::ProfileError => error
          raise InvalidContext, "seccomp Localhost profile #{relative.inspect}: #{error.message}"
        end

        def probe
          @capability_probe.respond_to?(:call) ? @capability_probe.call : @capability_probe.probe
        end

        def context(value)
          Context.from(value)
        end

        def validate(value, probe: self.probe)
          context = Context.from(value)
          validate_context!(context, probe)
          context
        end

        def plan(value, probe: self.probe)
          context = validate(value, probe: probe)
          program = seccomp_program_for(context)
          steps = topological_steps
          Plan.new(context: context, steps: steps.freeze, seccomp_program: program, probe: probe)
        end

        def apply(value, probe: self.probe)
          planned = value.is_a?(Plan) ? value : plan(value, probe: probe)
          planned.steps.each do |step|
            invoke(step.name, context: planned.context, program: planned.seccomp_program)
          end
          planned
        end

        private

        def validate_context!(context, probe)
          if context.privileged? && context.allow_privilege_escalation == false
            raise InvalidContext, "privileged security context cannot disable privilege escalation"
          end

          validate_id(context.run_as_user, "run_as_user") if context.run_as_user
          validate_id(context.run_as_group, "run_as_group") if context.run_as_group
          context.supplemental_groups.each { |group| validate_id(group, "supplemental_groups") }
          context.capabilities.values.flatten.each do |name|
            normalized = normalize_capability(name)
            # ALL is the Kubernetes wildcard (drop everything / add everything).
            next if normalized == "ALL"
            raise InvalidContext, "unknown Linux capability #{name.inspect}" unless CAPABILITIES.key?(normalized)
            next if context.privileged?
            raise Unsupported, "capability #{normalized} is not in the host bounding set" unless probe.capability?(normalized)
          end
          if context.no_new_privs_required? && !probe.available?(:no_new_privs) && !context.privileged?
            raise Unsupported, "security context requires no_new_privs, but the kernel capability is unavailable"
          end
          unless %w[RuntimeDefault Unconfined Localhost].include?(context.seccomp_name)
            raise InvalidContext, "seccomp profile must be RuntimeDefault, Unconfined, or Localhost"
          end
          if context.seccomp_name != "Unconfined" && !probe.available?(:seccomp)
            raise Unsupported, "seccomp is required by the security context but unavailable"
          end
          if context.landlock_required? && !probe.available?(:landlock)
            raise Unsupported, "Landlock is required by the security context but unavailable"
          end

          context
        end

        def validate_id(value, name)
          integer = Integer(value)
          raise InvalidContext, "#{name} must be between 0 and 4294967295" unless integer.between?(0, 4_294_967_295)
        rescue ArgumentError, TypeError
          raise InvalidContext, "#{name} must be an integer"
        end

        def normalize_capability(value)
          key = String(value).upcase
          CAPABILITY_ALIASES.fetch(key, key.delete_prefix('CAP_'))
        end

        def topological_steps
          pending = STEP_DEPENDENCIES.transform_values(&:dup)
          output = []
          until pending.empty?
            ready = pending.select { |_name, dependencies| dependencies.empty? }.keys.sort
            raise DependencyCycle, "security step dependency graph contains a cycle" if ready.empty?

            ready.each do |name|
              output << Step.new(name: name, dependencies: STEP_DEPENDENCIES.fetch(name).freeze)
              pending.delete(name)
            end
            pending.each_value { |dependencies| dependencies.reject! { |dependency| ready.include?(dependency) } }
          end
          output
        end

        def invoke(name, context:, program:)
          if @adapter.respond_to?(:apply)
            @adapter.apply(step: name, context: context, program: program)
          elsif @adapter.respond_to?(name)
            @adapter.public_send(name, context)
          elsif @adapter.respond_to?(:call)
            @adapter.call(name, context: context, program: program)
          else
            raise Unsupported, "security adapter cannot apply #{name}"
          end
        end
      end

      SecurityContext = Security::Context unless const_defined?(:SecurityContext, false)
      CapabilityProbe = Security::CapabilityProbe unless const_defined?(:CapabilityProbe, false)
      SeccompCompiler = Security::SeccompCompiler unless const_defined?(:SeccompCompiler, false)
    end
  end
end
