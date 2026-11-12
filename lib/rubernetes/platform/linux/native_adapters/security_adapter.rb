# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Applies the security plan in the child that will exec.  The parent
        # only compiles/validates the plan; a failed child application never
        # releases the workload gate.
        class SecurityAdapter
          include CapabilityContract

          # Values from include/uapi/linux/prctl.h.
          PR_SET_SECUREBITS = 28
          PR_GET_SECUREBITS = 27
          PR_SET_NO_NEW_PRIVS = 38
          PR_GET_NO_NEW_PRIVS = 39
          PR_GET_SECCOMP = 21
          PR_SET_SECCOMP = 22
          # Value from include/uapi/linux/seccomp.h.
          SECCOMP_MODE_FILTER = 2
          # Values from include/uapi/linux/mount.h.
          MS_RDONLY = Mount::MS_RDONLY
          MS_NOSUID = Mount::MS_NOSUID
          MS_NODEV = Mount::MS_NODEV
          MS_NOEXEC = Mount::MS_NOEXEC
          MS_REMOUNT = Mount::MS_REMOUNT
          MS_BIND = Mount::MS_BIND
          MS_REC = Mount::MS_REC
          MS_PRIVATE = Mount::MS_PRIVATE
          MS_SLAVE = Mount::MS_SLAVE
          MS_SHARED = Mount::MS_SHARED
          MS_STRICTATIME = PivotRoot::MS_STRICTATIME
          # Pod volumeMount.mountPropagation values (pkg/apis/core/types.go)
          # mapped to the propagation flag applied to the bind target.
          MOUNT_PROPAGATION = {
            "None" => MS_PRIVATE, "HostToContainer" => MS_SLAVE, "Bidirectional" => MS_SHARED
          }.freeze
          MAX_SYMLINK_FOLLOWS = 40
          # kubelet defaults (pkg/securitycontext/util.go) applied unless
          # procMount is Unmasked or the container is privileged.
          DEFAULT_MASKED_PATHS = %w[
            /proc/asound /proc/acpi /proc/interrupts /proc/kcore /proc/keys /proc/latency_stats
            /proc/timer_list /proc/timer_stats /proc/sched_debug /proc/scsi /sys/firmware
            /sys/devices/virtual/powercap
          ].freeze
          DEFAULT_READONLY_PATHS = %w[/proc/bus /proc/fs /proc/irq /proc/sys /proc/sysrq-trigger].freeze
          # Minimal device set kubelet/CRI provides to every container.
          ROOTFS_DEVICES = %w[null zero full random urandom tty].freeze
          DEVICE_SYMLINKS = {
            "fd" => "/proc/self/fd", "stdin" => "/proc/self/fd/0", "stdout" => "/proc/self/fd/1",
            "stderr" => "/proc/self/fd/2", "ptmx" => "pts/ptmx"
          }.freeze
          PIVOT_OLD = "dev/.pivot-old"

          CLOSE = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["close"], [Fiddle::TYPE_INT], Fiddle::TYPE_INT
          )
          FCNTL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["fcntl"], [Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_INT
          )
          # Values from include/uapi/asm-generic/fcntl.h.
          F_GETFD = 1
          FD_CLOEXEC = 1
          PRCTL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["prctl"], [Fiddle::TYPE_LONG] * 5, Fiddle::TYPE_INT
          )
          SETRESUID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["setresuid"], [Fiddle::TYPE_UINT] * 3, Fiddle::TYPE_INT
          )
          SETRESGID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["setresgid"], [Fiddle::TYPE_UINT] * 3, Fiddle::TYPE_INT
          )
          GETRESUID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["getresuid"], [Fiddle::TYPE_VOIDP] * 3, Fiddle::TYPE_INT
          )
          GETRESGID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["getresgid"], [Fiddle::TYPE_VOIDP] * 3, Fiddle::TYPE_INT
          )

          Rootfs = Data.define(:root_mount_id, :mount_count, :old_root_mount_ids, :old_root_unreachable, :mountinfo_sha256,
                               :rootfs_read_only) do
            def to_h
              {
                "root_mount_id" => root_mount_id, "mount_count" => mount_count,
                "old_root_mount_ids" => old_root_mount_ids, "old_root_unreachable" => old_root_unreachable,
                "mountinfo_sha256" => mountinfo_sha256, "rootfs_read_only" => rootfs_read_only
              }
            end
          end

          def initialize(landlock: Landlock.new, landlock_roots: [], mount: Mount.new, pivot: PivotRoot.new, setns: Setns.new,
                         capabilities: Capabilities.new)
            @landlock = landlock
            @landlock_roots = Array(landlock_roots).map { |path| File.expand_path(String(path)) }.freeze
            @mount = mount
            @pivot = pivot
            @setns = setns
            @capabilities = capabilities
            @rootfs_report = nil
            @capability_report = nil
            @user_namespace_joined = false
          end

          attr_reader :landlock_roots, :rootfs_report, :capability_report

          def native_capabilities
            {
              security_application: true,
              no_new_privs: prctl_probe(PR_GET_NO_NEW_PRIVS),
              seccomp: prctl_probe(PR_GET_SECCOMP),
              landlock: @landlock.probe.available?
            }.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:security_application), "security application adapter is unavailable")
            require_capability!(native_capabilities.fetch(:no_new_privs), "no_new_privs cannot be queried")
            require_capability!(native_capabilities.fetch(:seccomp), "seccomp cannot be queried")
            true
          end

          def apply(step:, context:, program: nil)
            case step.to_sym
            when :namespace, :mount
              true
            when :groups
              apply_groups(context)
            when :identity
              apply_identity(context)
            when :capabilities
              apply_capabilities(context)
            when :securebits
              apply_securebits
            when :no_new_privs
              apply_no_new_privs
            when :lsm
              apply_landlock(context)
            when :rlimit
              apply_rlimits(context)
            when :seccomp
              apply_seccomp(program)
            when :close_fds
              close_unlisted_fds(context)
            when :execveat
              true
            else
              raise Unsupported, "unsupported security step #{step.inspect}"
            end
          end

          private

          def apply_prctl(option, argument, resource_id:)
            result = PRCTL.call(option, argument, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(#{option})", resource_id: resource_id) if result == -1

            true
          end

          def prctl_probe(option)
            PRCTL.call(option, 0, 0, 0, 0) != -1
          end
        end
      end
    end
  end
end
