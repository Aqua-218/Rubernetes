# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # The security plan's steps, applied one by one in the process that will
        # exec the workload.
        class SecurityAdapter
          # Join the holder's user namespace after every privileged mount
          # operation is complete (R-1.6): the mount namespace stays owned by
          # the initial user namespace, so the workload cannot alter it even
          # with CAP_SYS_ADMIN inside the Pod's user namespace.
          def join_user_namespace(descriptor)
            return true unless descriptor

            @setns.setns(fd: descriptor, name: :user, resource_id: "workload:user")
            descriptor.close unless descriptor.closed?
            @user_namespace_joined = true
            true
          end

          private

          def apply_groups(context)
            groups = Array(context.supplemental_groups)
            groups << Integer(context.fs_group) if context.fs_group
            return true if groups.empty?

            Process.groups = groups.uniq
            true
          rescue SystemCallError => error
            raise EffectError, "supplemental group setup failed: #{error.message}"
          end

          # KEEPCAPS keeps the permitted set across a setuid so the capability
          # step can still drop the bounding set (which needs CAP_SETPCAP)
          # before it installs the final sets.  After a user-namespace join the
          # credentials are still the host kuid; setresuid(0) inside the
          # namespace is what maps the workload onto the Pod's own range, so
          # the default identity becomes explicit there.
          def apply_identity(context)
            uid = context.run_as_user && Integer(context.run_as_user)
            gid = context.run_as_group && Integer(context.run_as_group)
            if @user_namespace_joined
              uid ||= 0
              gid ||= 0
            end
            return true if uid.nil? && gid.nil?

            fix_stdio_ownership(uid, gid)
            @capabilities.keep_caps(true)
            change_ids(SETRESGID, gid, "setresgid") if gid
            change_ids(SETRESUID, uid, "setresuid") if uid
            observed_uid = read_ids(GETRESUID, "getresuid")
            observed_gid = read_ids(GETRESGID, "getresgid")
            raise EffectError, "uid readback mismatch: expected #{uid} got #{observed_uid.inspect}" if uid && observed_uid != [uid, uid,
                                                                                                                               uid]
            raise EffectError, "gid readback mismatch: expected #{gid} got #{observed_gid.inspect}" if gid && observed_gid != [gid, gid,
                                                                                                                               gid]

            true
          end

          # runc fixStdioPermissions: the workload's stdio pipes are created by
          # the runtime as root, so a non-root process could not re-open its own
          # /dev/stderr (nginx: "could not open error log file ... Permission
          # denied").  Ownership of a root-owned pipe or terminal moves to the
          # container user before the switch; regular files and sockets are
          # left alone, and EINVAL/EPERM (user namespaces) are ignored as in runc.
          def fix_stdio_ownership(uid, gid)
            return if uid.nil?

            (0..2).each do |fd|
              io = File.for_fd(fd, autoclose: false)
              stat = io.stat
              next unless (stat.pipe? || stat.chardev?) && stat.uid.zero?

              begin
                io.chown(uid, gid || -1)
              rescue Errno::EINVAL, Errno::EPERM
                next
              end
            rescue SystemCallError, IOError
              next
            end
          end

          def change_ids(function, value, operation)
            result = function.call(value, value, value)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: operation, resource_id: "security:identity") if result == -1

            true
          end

          def read_ids(function, operation)
            storage = Array.new(3) { Fiddle::Pointer.malloc(4, Fiddle::RUBY_FREE) }
            result = function.call(*storage)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: operation, resource_id: "security:identity") if result == -1

            storage.map { |pointer| pointer[0, 4].unpack1("L<") }
          end

          def apply_capabilities(context)
            target = Capabilities.resolve(
              add: Array(context.capabilities.fetch(:add)),
              drop: Array(context.capabilities.fetch(:drop)),
              privileged: context.privileged?,
              last_cap: @capabilities.last_cap
            )
            @capability_report = @capabilities.apply(target).merge("target" => target)
            true
          rescue Capabilities::Error, KeyError => error
            raise EffectError, "capability setup failed: #{error.message}"
          end

          # securebits default to zero; only a change needs CAP_SETPCAP, which
          # the capability step may already have dropped.  Reading first keeps
          # the step a no-op in the default case instead of failing spuriously.
          def apply_securebits
            current = PRCTL.call(PR_GET_SECUREBITS, 0, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(PR_GET_SECUREBITS)", resource_id: "security:securebits") if current == -1
            return true if current.zero?

            apply_prctl(PR_SET_SECUREBITS, 0, resource_id: "security:securebits")
          end

          def apply_no_new_privs
            apply_prctl(PR_SET_NO_NEW_PRIVS, 1, resource_id: "security:no_new_privs")
            result = PRCTL.call(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
            errno = Fiddle.last_error
            if result == -1
              raise Linux::Error.new(errno: errno, operation: "prctl(PR_GET_NO_NEW_PRIVS)",
                                     resource_id: "security:no_new_privs")
            end
            raise EffectError, "no_new_privs was not enabled" unless result == 1

            true
          end

          def apply_landlock(context)
            return true unless context.landlock_required?
            raise Unsupported, "Landlock roots are not configured" if @landlock_roots.empty?

            rights = Landlock::ACCESS_FS_EXECUTE | Landlock::ACCESS_FS_READ_FILE | Landlock::ACCESS_FS_READ_DIR
            ruleset = @landlock.create_ruleset(handled_access_fs: rights, identity: "security:landlock")
            openat2 = Openat2.new(root: "/", strict: true)
            relative_paths = @landlock_roots.map { |path| path.delete_prefix("/") }.reject(&:empty?)
            # Roots are configured for the image family, not for one image; a
            # root absent from this rootfs contributes no rule.  With no
            # present root the policy would deny every read and exec, which is
            # a configuration error rather than a sandbox, so it fails closed.
            # A symlinked root (/lib64 -> usr/lib64 on merged-usr images) is
            # covered by the directory it points to; openat2 resolves rule
            # paths with RESOLVE_NO_SYMLINKS, so only real directories count.
            present_paths = relative_paths.select do |path|
              absolute = File.join("/", path)
              File.directory?(absolute) && !File.symlink?(absolute)
            end
            raise Unsupported, "no configured Landlock root exists in the rootfs" if present_paths.empty?

            @landlock.apply(ruleset, paths: present_paths, openat2: openat2, read_only: true, resource_id: "security:landlock")
            true
          end

          def apply_rlimits(context)
            context.rlimits.each do |name, limits|
              resource = name.is_a?(Integer) ? name : Process.const_get("RLIMIT_#{String(name).upcase}")
              values = limits.is_a?(Array) ? limits : [limits, limits]
              Process.setrlimit(resource, Integer(values.fetch(0)), Integer(values.fetch(1)))
            end
            true
          rescue NameError, ArgumentError, SystemCallError => error
            raise EffectError, "rlimit setup failed: #{error.message}"
          end

          def apply_seccomp(program)
            return true unless program

            expected = case RbConfig::CONFIG.fetch("host_cpu").downcase
                       when "x86_64", "amd64" then "x86_64"
                       when "aarch64", "arm64" then "aarch64"
                       else raise Unsupported, "unsupported seccomp host architecture"
                       end
            raise Unsupported, "seccomp architecture mismatch" unless program.architecture == expected

            instructions = program.instructions.map do |instruction|
              [instruction.code, instruction.jt, instruction.jf, instruction.k].pack("S<CCL<")
            end.join
            filter = Fiddle::Pointer[instructions]
            fprog = Fiddle::Pointer[[program.instructions.length].pack("S<") + ("\0" * 6) + [filter.to_i].pack("Q<")]
            result = PRCTL.call(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog.to_i, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(PR_SET_SECCOMP)", resource_id: "security:seccomp") if result == -1

            true
          end

          def close_unlisted_fds(context)
            allowlist = Array(context.fd_allowlist).map { |fd| Integer(fd) }
            directory = @fd_directory || Dir.open("/proc/self/fd")
            @fd_directory = nil
            entries = directory.children
            allowlist << directory.fileno
            entries.each do |entry|
              fd = Integer(entry, exception: false)
              next unless fd
              next if allowlist.include?(fd)

              descriptor_flags = FCNTL.call(fd, F_GETFD)
              descriptor_errno = Fiddle.last_error
              if descriptor_flags == -1
                next if descriptor_errno == Errno::EBADF::Errno

                raise Linux::Error.new(errno: descriptor_errno, operation: "fcntl(F_GETFD)", resource_id: "security:fd:#{fd}")
              end
              # Ruby's runtime descriptors (timer/wakeup pipes and loaded
              # extension handles) are close-on-exec.  Leave those alone:
              # closing them before exec destabilizes MRI, while the kernel
              # will close them atomically during exec.
              next unless descriptor_flags.nobits?(FD_CLOEXEC)

              result = CLOSE.call(fd)
              errno = Fiddle.last_error
              next if result.zero? || errno == Errno::EBADF::Errno

              raise Linux::Error.new(errno: errno, operation: "close", resource_id: "security:fd:#{fd}")
            end
            true
          rescue SystemCallError => error
            raise EffectError, "fd close failed: #{error.message}"
          ensure
            begin
              directory&.close
            rescue IOError
              nil
            end
          end
        end
      end
    end
  end
end
