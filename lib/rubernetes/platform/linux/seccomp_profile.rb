# frozen_string_literal: true

require "json"

module Rubernetes
  module Platform
    module Linux
      # seccomp profiles in the OCI runtime-spec shape (the format kubelet's
      # `Localhost` profiles use) and the RuntimeDefault profile, which is
      # containerd's default: an allow-list of syscalls, argument-conditioned
      # rules for `clone`/`personality`, and capability-gated groups (CAP_SYS_ADMIN
      # unlocks mount/setns/…).  A profile is data; SeccompCompiler turns it
      # into classic BPF and Seccomp::Interpreter evaluates that BPF so the
      # compiler can be checked against the profile's own semantics.
      module Seccomp
        class Error < StandardError; end
        class ProfileError < Error; end

        ACTIONS = {
          "SCMP_ACT_ALLOW" => :allow, "SCMP_ACT_ERRNO" => :errno, "SCMP_ACT_KILL" => :kill,
          "SCMP_ACT_KILL_THREAD" => :kill, "SCMP_ACT_KILL_PROCESS" => :kill_process,
          "SCMP_ACT_TRAP" => :trap, "SCMP_ACT_LOG" => :log, "SCMP_ACT_TRACE" => :trace, "SCMP_ACT_NOTIFY" => :notify
        }.freeze
        OPERATORS = %w[SCMP_CMP_NE SCMP_CMP_LT SCMP_CMP_LE SCMP_CMP_EQ SCMP_CMP_GE SCMP_CMP_GT SCMP_CMP_MASKED_EQ].freeze
        OCI_ARCHITECTURES = {
          "SCMP_ARCH_X86_64" => "x86_64", "SCMP_ARCH_AARCH64" => "aarch64",
          "SCMP_ARCH_X86" => "i386", "SCMP_ARCH_X32" => "x32", "SCMP_ARCH_ARM" => "arm"
        }.freeze
        ENOSYS = 38
        EPERM = 1

        # One argument condition of a rule.
        Arg = Data.define(:index, :value, :value_two, :op) do
          def self.from(hash)
            input = hash.to_h.transform_keys(&:to_s)
            op = String(input.fetch("op"))
            raise ProfileError, "unsupported seccomp argument operator #{op.inspect}" unless OPERATORS.include?(op)

            index = Integer(input.fetch("index"))
            raise ProfileError, "seccomp argument index must be 0..5" unless index.between?(0, 5)

            new(index: index, value: Integer(input.fetch("value", 0)),
                value_two: Integer(input.fetch("valueTwo", input.fetch("value_two", 0))), op: op)
          end

          def to_h
            {"index" => index, "value" => value, "valueTwo" => value_two, "op" => op}
          end

          # The semantics the compiled BPF must reproduce.
          def match?(argument)
            actual = Integer(argument) & 0xFFFF_FFFF_FFFF_FFFF
            case op
            when "SCMP_CMP_EQ" then actual == value
            when "SCMP_CMP_NE" then actual != value
            when "SCMP_CMP_LT" then actual < value
            when "SCMP_CMP_LE" then actual <= value
            when "SCMP_CMP_GT" then actual > value
            when "SCMP_CMP_GE" then actual >= value
            when "SCMP_CMP_MASKED_EQ" then (actual & value) == value_two
            end
          end
        end

        # A rule: the named syscalls receive `action` when every argument
        # condition holds (an empty condition list always holds).
        Rule = Data.define(:names, :action, :errno_ret, :args) do
          def self.from(hash)
            input = hash.to_h.transform_keys(&:to_s)
            names = Array(input.fetch("names")).map { |name| String(name) }
            raise ProfileError, "seccomp rule requires at least one syscall name" if names.empty?

            action = ACTIONS.fetch(String(input.fetch("action"))) do
              raise ProfileError, "unsupported seccomp action #{input["action"].inspect}"
            end
            errno = input["errnoRet"] || input["errno_ret"]
            new(names: names.freeze, action: action, errno_ret: errno.nil? ? nil : Integer(errno),
                args: Array(input["args"]).map { |arg| Arg.from(arg) }.freeze)
          end

          def to_h
            {"names" => names, "action" => action.to_s, "errnoRet" => errno_ret, "args" => args.map(&:to_h)}.compact
          end

          def match?(arguments)
            args.all? { |arg| arg.match?(Array(arguments)[arg.index] || 0) }
          end
        end

        class Profile
          attr_reader :default_action, :default_errno, :architectures, :rules, :name

          def initialize(default_action:, rules:, architectures: [], default_errno: EPERM, name: nil)
            @default_action = default_action
            @default_errno = Integer(default_errno)
            @architectures = Array(architectures).map(&:to_s).freeze
            @rules = Array(rules).freeze
            @name = name
            freeze
          end

          # OCI runtime-spec `linux.seccomp` document (also the file format of
          # a kubelet Localhost profile).  Rules carrying `excludes`/`includes`
          # in the Docker extension form are resolved against the given
          # capabilities and architecture.
          def self.from_oci(document, capabilities: [], architecture: nil, name: nil)
            input = document.is_a?(String) ? JSON.parse(document) : document.to_h
            input = input.transform_keys(&:to_s)
            default_action = ACTIONS.fetch(String(input.fetch("defaultAction"))) do
              raise ProfileError, "unsupported default seccomp action #{input["defaultAction"].inspect}"
            end
            caps = Array(capabilities).map { |cap| normalize_capability(cap) }
            architectures = Array(input["architectures"]).map { |arch| OCI_ARCHITECTURES.fetch(String(arch), String(arch)) }
            rules = Array(input["syscalls"]).filter_map do |entry|
              rule = entry.to_h.transform_keys(&:to_s)
              next unless applies?(rule["includes"], caps, architecture, include: true)
              next unless applies?(rule["excludes"], caps, architecture, include: false)

              names = Array(rule["names"])
              names = [rule["name"]] if names.empty? && rule["name"]
              Rule.from(rule.merge("names" => names))
            end
            new(default_action: default_action, rules: rules, architectures: architectures,
                default_errno: input.fetch("defaultErrnoRet", EPERM), name: name)
          rescue JSON::ParserError => error
            raise ProfileError, "seccomp profile is not valid JSON: #{error.message}"
          rescue KeyError => error
            raise ProfileError, "seccomp profile is missing #{error.key.inspect}"
          end

          def self.applies?(filter, capabilities, architecture, include:)
            return true if filter.nil? || filter.to_h.empty?

            hash = filter.to_h.transform_keys(&:to_s)
            caps = Array(hash["caps"]).map { |cap| normalize_capability(cap) }
            arches = Array(hash["arches"]).map(&:to_s)
            matched = (!caps.empty? && (caps & capabilities).any?) ||
                      (!arches.empty? && architecture && arches.include?(oci_arch_name(architecture)))
            include ? matched || (caps.empty? && arches.empty?) : !matched
          end

          def self.normalize_capability(name)
            value = String(name).upcase
            value.start_with?("CAP_") ? value : "CAP_#{value}"
          end

          def self.oci_arch_name(architecture)
            {"x86_64" => "amd64", "aarch64" => "arm64"}.fetch(architecture.to_s, architecture.to_s)
          end

          # The RuntimeDefault profile for one container: containerd's
          # default seccomp profile evaluated for the container's effective
          # capability set.
          def self.runtime_default(architecture:, capabilities: [])
            RuntimeDefault.build(architecture: architecture, capabilities: capabilities)
          end

          def to_h
            {"defaultAction" => default_action.to_s, "defaultErrnoRet" => default_errno,
             "architectures" => architectures, "syscalls" => rules.map(&:to_h)}
          end

          # Reference semantics: the action the profile assigns to a call.
          # Rules are matched in order, the first matching rule wins.
          def evaluate(name, arguments = [])
            rules.each do |rule|
              next unless rule.names.include?(String(name))
              next unless rule.match?(arguments)

              return [rule.action, rule.action == :errno ? (rule.errno_ret || default_errno) : nil]
            end
            [default_action, default_action == :errno ? default_errno : nil]
          end
        end

        # containerd/pkg/seccomp/seccomp_default.go (the Docker default
        # profile) as data.
        module RuntimeDefault
          ALLOW = %w[
            accept accept4 access adjtimex alarm bind brk cachestat capget capset chdir chmod chown chown32
            clock_adjtime clock_adjtime64 clock_getres clock_getres_time64 clock_gettime clock_gettime64
            clock_nanosleep clock_nanosleep_time64 close close_range connect copy_file_range creat dup dup2 dup3
            epoll_create epoll_create1 epoll_ctl epoll_ctl_old epoll_pwait epoll_pwait2 epoll_wait epoll_wait_old
            eventfd eventfd2 execve execveat exit exit_group faccessat faccessat2 fadvise64 fadvise64_64 fallocate
            fanotify_mark fchdir fchmod fchmodat fchmodat2 fchown fchown32 fchownat fcntl fcntl64 fdatasync
            fgetxattr flistxattr flock fork fremovexattr fsetxattr fstat fstat64 fstatat64 fstatfs fstatfs64 fsync
            ftruncate ftruncate64 futex futex_requeue futex_time64 futex_wait futex_waitv futex_wake futimesat
            getcpu getcwd getdents getdents64 getegid getegid32 geteuid geteuid32 getgid getgid32 getgroups
            getgroups32 getitimer getpeername getpgid getpgrp getpid getppid getpriority getrandom getresgid
            getresgid32 getresuid getresuid32 getrlimit get_robust_list getrusage getsid getsockname getsockopt
            get_thread_area gettid gettimeofday getuid getuid32 getxattr inotify_add_watch inotify_init
            inotify_init1 inotify_rm_watch io_cancel ioctl io_destroy io_getevents io_pgetevents
            io_pgetevents_time64 ioprio_get ioprio_set io_setup io_submit io_uring_enter io_uring_register
            io_uring_setup ipc kill landlock_add_rule landlock_create_ruleset landlock_restrict_self lchown
            lchown32 lgetxattr link linkat listen listxattr llistxattr _llseek lremovexattr lseek lsetxattr lstat
            lstat64 madvise map_shadow_stack membarrier memfd_create memfd_secret mincore mkdir mkdirat mknod
            mknodat mlock mlock2 mlockall mmap mmap2 mprotect mq_getsetattr mq_notify mq_open mq_timedreceive
            mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink mremap msgctl msgget msgrcv msgsnd
            msync munlock munlockall munmap name_to_handle_at nanosleep newfstatat _newselect open openat openat2
            pause pidfd_open pidfd_send_signal pipe pipe2 pkey_alloc pkey_free pkey_mprotect poll ppoll
            ppoll_time64 prctl pread64 preadv preadv2 prlimit64 process_mrelease pselect6 pselect6_time64 ptrace
            pwrite64 pwritev pwritev2 read readahead readlink readlinkat readv recv recvfrom recvmmsg
            recvmmsg_time64 recvmsg remap_file_pages removexattr rename renameat renameat2 restart_syscall rmdir
            rseq rt_sigaction rt_sigpending rt_sigprocmask rt_sigqueueinfo rt_sigreturn rt_sigsuspend
            rt_sigtimedwait rt_sigtimedwait_time64 rt_tgsigqueueinfo sched_getaffinity sched_getattr
            sched_getparam sched_get_priority_max sched_get_priority_min sched_getscheduler
            sched_rr_get_interval sched_rr_get_interval_time64 sched_setaffinity sched_setattr sched_setparam
            sched_setscheduler sched_yield seccomp select semctl semget semop semtimedop semtimedop_time64 send
            sendfile sendfile64 sendmmsg sendmsg sendto setfsgid setfsgid32 setfsuid setfsuid32 setgid setgid32
            setgroups setgroups32 setitimer setpgid setpriority setregid setregid32 setresgid setresgid32
            setresuid setresuid32 setreuid setreuid32 setrlimit set_robust_list setsid setsockopt
            set_thread_area set_tid_address setuid setuid32 setxattr shmat shmctl shmdt shmget shutdown
            sigaltstack signalfd signalfd4 sigprocmask sigreturn socket socketcall socketpair splice stat stat64
            statfs statfs64 statmount statx symlink symlinkat sync sync_file_range syncfs sysinfo tee tgkill
            time timer_create timer_delete timer_getoverrun timer_gettime timer_gettime64 timer_settime
            timer_settime64 timerfd_create timerfd_gettime timerfd_gettime64 timerfd_settime timerfd_settime64
            times tkill truncate truncate64 ugetrlimit umask uname unlink unlinkat utime utimensat
            utimensat_time64 utimes vfork vmsplice wait4 waitid waitpid write writev
          ].freeze
          ARCH_ALLOW = {
            "x86_64" => %w[arch_prctl modify_ldt],
            "aarch64" => %w[],
            "arm" => %w[arm_fadvise64_64 arm_sync_file_range sync_file_range2 breakpoint cacheflush set_tls]
          }.freeze
          # personality(2) values Docker accepts: PER_LINUX, PER_LINUX32,
          # UNAME26, PER_LINUX32|UNAME26 and the query value.
          PERSONALITY_VALUES = [0x0, 0x8, 0x20000, 0x20008, 0xffffffff].freeze
          # clone flags that create namespaces: without CAP_SYS_ADMIN a
          # clone(2) asking for any of them is refused.
          CLONE_NAMESPACE_FLAGS = 0x7E02_0000
          CAPABILITY_GROUPS = {
            "CAP_DAC_READ_SEARCH" => %w[open_by_handle_at],
            "CAP_SYS_ADMIN" => %w[bpf clone clone3 fanotify_init fsconfig fsmount fsopen fspick lookup_dcookie mount
                                  mount_setattr move_mount open_tree perf_event_open quotactl quotactl_fd setdomainname
                                  sethostname setns syslog umount umount2 unshare],
            "CAP_SYS_BOOT" => %w[reboot],
            "CAP_SYS_CHROOT" => %w[chroot],
            "CAP_SYS_MODULE" => %w[delete_module init_module finit_module],
            "CAP_SYS_PACCT" => %w[acct],
            "CAP_SYS_PTRACE" => %w[kcmp pidfd_getfd process_vm_readv process_vm_writev ptrace],
            "CAP_SYS_RAWIO" => %w[iopl ioperm],
            "CAP_SYS_TIME" => %w[settimeofday stime clock_settime clock_settime64],
            "CAP_SYS_TTY_CONFIG" => %w[vhangup],
            "CAP_SYS_NICE" => %w[get_mempolicy mbind set_mempolicy],
            "CAP_SYSLOG" => %w[syslog],
            "CAP_BPF" => %w[bpf],
            "CAP_PERFMON" => %w[perf_event_open]
          }.freeze

          module_function

          def build(architecture:, capabilities: [])
            arch = architecture.to_s
            caps = Array(capabilities).map { |cap| Profile.normalize_capability(cap) }
            rules = []
            rules << Rule.new(names: (ALLOW + ARCH_ALLOW.fetch(arch, [])).uniq.sort.freeze, action: :allow, errno_ret: nil, args: [].freeze)
            PERSONALITY_VALUES.each do |value|
              rules << Rule.new(names: %w[personality].freeze, action: :allow, errno_ret: nil,
                                args: [Arg.new(index: 0, value: value, value_two: 0, op: "SCMP_CMP_EQ")].freeze)
            end
            if caps.include?("CAP_SYS_ADMIN")
              rules << Rule.new(names: CAPABILITY_GROUPS.fetch("CAP_SYS_ADMIN").freeze, action: :allow, errno_ret: nil, args: [].freeze)
            else
              rules << Rule.new(names: %w[clone].freeze, action: :allow, errno_ret: nil,
                                args: [Arg.new(index: 0, value: CLONE_NAMESPACE_FLAGS, value_two: 0, op: "SCMP_CMP_MASKED_EQ")].freeze)
              # glibc probes clone3 and falls back to clone on ENOSYS; EPERM
              # would make posix_spawn fail instead.
              rules << Rule.new(names: %w[clone3].freeze, action: :errno, errno_ret: ENOSYS, args: [].freeze)
            end
            CAPABILITY_GROUPS.each do |capability, names|
              next if capability == "CAP_SYS_ADMIN"
              next unless caps.include?(capability)

              rules << Rule.new(names: names.freeze, action: :allow, errno_ret: nil, args: [].freeze)
            end
            Profile.new(default_action: :errno, default_errno: EPERM, rules: rules, architectures: [arch], name: "RuntimeDefault")
          end
        end

        # Evaluates a classic-BPF seccomp program on one syscall record the
        # way the kernel would: the profile's semantics are checked against
        # this interpreter in tests, and it is the executable counterpart of
        # the Lean model of the compiler.
        module Interpreter
          BPF_LD_W_ABS = 0x20
          BPF_JMP_JA = 0x05
          BPF_JMP_JEQ_K = 0x15
          BPF_JMP_JGT_K = 0x25
          BPF_JMP_JGE_K = 0x35
          BPF_JMP_JSET_K = 0x45
          BPF_ALU_AND_K = 0x54
          BPF_RET_K = 0x06
          MAX_STEPS = 4096

          module_function

          # `record` = {"nr" =>, "arch" =>, "args" => [6 × u64]}; returns the
          # raw seccomp return value (SECCOMP_RET_* | data).
          def run(instructions, record)
            data = seccomp_data(record)
            accumulator = 0
            pc = 0
            steps = 0
            while pc < instructions.length
              steps += 1
              raise Error, "seccomp program did not terminate" if steps > MAX_STEPS

              instruction = instructions[pc]
              code, jt, jf, k = if instruction.respond_to?(:code)
                                  [instruction.code, instruction.jt, instruction.jf,
                                   instruction.k]
                                else
                                  instruction.values_at("code", "jt", "jf", "k")
                                end
              case code
              when BPF_LD_W_ABS
                raise Error, "seccomp load offset #{k} is not word aligned" unless (k % 4).zero? && k.between?(0, 60)

                accumulator = data.fetch(k)
                pc += 1
              when BPF_ALU_AND_K
                accumulator &= k
                pc += 1
              when BPF_JMP_JA
                pc += 1 + k
              when BPF_JMP_JEQ_K
                pc += 1 + (accumulator == k ? jt : jf)
              when BPF_JMP_JGT_K
                pc += 1 + (accumulator > k ? jt : jf)
              when BPF_JMP_JGE_K
                pc += 1 + (accumulator >= k ? jt : jf)
              when BPF_JMP_JSET_K
                pc += 1 + ((accumulator & k) == 0 ? jf : jt)
              when BPF_RET_K
                return k
              else
                raise Error, "unsupported seccomp BPF opcode 0x#{code.to_s(16)}"
              end
            end
            raise Error, "seccomp program fell off the end"
          end

          # The (action, errno) pair a raw return value means.
          def decode(value)
            action = value & 0xFFFF_0000
            data = value & 0xFFFF
            case action
            when 0x7FFF_0000 then [:allow, nil]
            when 0x0005_0000 then [:errno, data]
            when 0x8000_0000 then [:kill, nil]
            when 0x8010_0000 then [:kill_process, nil]
            when 0x0003_0000 then [:trap, nil]
            when 0x7FFC_0000 then [:log, nil]
            when 0x7FF0_0000 then [:trace, data]
            when 0x7FC0_0000 then [:notify, nil]
            else raise Error, "unknown seccomp return 0x#{value.to_s(16)}"
            end
          end

          # struct seccomp_data laid out as 32-bit little-endian words by
          # byte offset: nr @0, arch @4, instruction_pointer @8/@12, args
          # @16 + 8*i (low word first).
          def seccomp_data(record)
            input = record.to_h.transform_keys(&:to_s)
            words = {0 => Integer(input.fetch("nr")) & 0xFFFF_FFFF, 4 => Integer(input.fetch("arch")) & 0xFFFF_FFFF, 8 => 0, 12 => 0}
            args = Array(input.fetch("args", []))
            6.times do |index|
              value = Integer(args[index] || 0) & 0xFFFF_FFFF_FFFF_FFFF
              words[16 + (8 * index)] = value & 0xFFFF_FFFF
              words[20 + (8 * index)] = value >> 32
            end
            words
          end
        end
      end
    end
  end
end
