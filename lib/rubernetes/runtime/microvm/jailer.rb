# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"

require_relative "errors"
require_relative "../../platform/linux/pidfd"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Launches Firecracker through its jailer (spec/node/runtime.md
      # 5.8.11): dedicated unprivileged UID/GID, private PID, mount and
      # network namespaces, cgroup v2 limits, the built-in default-deny
      # seccomp filter, and a chroot whose inputs (kernel, rootfs device
      # node, drives) are placed by the host before exec and are not
      # writable by the jailed user.  The VMM is tracked by pidfd and
      # start time, never by numeric PID alone.
      class Jailer
        JAIL_INPUT_MODE = 0o600
        Instance = Struct.new(:id, :jailer_pid, :vmm_pid, :vmm_start_time, :pidfd, :chroot, :api_socket, :uid, :gid, :cgroup_path,
                              :netns_path, :launched_at, keyword_init: true) do
          def identity
            "microvm:#{id}:#{vmm_pid}:#{vmm_start_time}"
          end

          def to_h
            {"id" => id, "jailer_pid" => jailer_pid, "vmm_pid" => vmm_pid, "vmm_start_time" => vmm_start_time, "chroot" => chroot,
             "api_socket" => api_socket, "uid" => uid, "gid" => gid, "cgroup_path" => cgroup_path, "netns_path" => netns_path, "identity" => identity}
          end

          def host_path(jail_path)
            File.join(chroot, jail_path.delete_prefix("/"))
          end
        end

        def initialize(artifacts:, chroot_base:, cgroup_root: "/sys/fs/cgroup", parent_cgroup: "rubernetes/microvm", pidfd: nil,
                       logger: nil)
          @artifacts = artifacts
          @chroot_base = File.expand_path(chroot_base)
          @cgroup_root = cgroup_root
          @parent_cgroup = parent_cgroup
          @pidfd = pidfd || Platform::Linux::Pidfd.new
          @logger = logger
        end

        attr_reader :chroot_base, :parent_cgroup

        def exec_name
          File.basename(@artifacts.path(:firecracker))
        end

        # The chroot the jailer will use for +id+ (jailer derives it from the
        # exec file name and the id).
        def chroot_for(id)
          File.join(@chroot_base, exec_name, id, "root")
        end

        # Prepares the jail root before launch: installs the verified inputs
        # (kernel, snapshot files, drive files, block device nodes), creates
        # the vhost-vsock node the jailer does not provide, and gives the
        # jailed user ownership of its directories.  +inputs+ maps a jail
        # path to a host path or to {"path" =>, "writable" => true}.
        # Read-only inputs are hard-linked without touching their inode's
        # owner or mode, so a pinned artifact is never re-owned by a jail;
        # writable inputs are unique per VM and are owned by the jailed user.
        def prepare(id:, uid:, gid:, inputs: {})
          validate_id!(id)
          root = chroot_for(id)
          raise JailerError, "jail root #{root} already exists" if File.exist?(root)

          %w[. dev run drives snapshot].each do |directory|
            path = File.join(root, directory)
            FileUtils.mkdir_p(path, mode: 0o700)
            File.chown(uid, gid, path)
          end
          vhost = File.join(root, "dev", "vhost-vsock")
          major, minor = File.stat("/dev/vhost-vsock").then { |stat| [stat.rdev_major, stat.rdev_minor] }
          mknod(vhost, major, minor)
          File.chown(uid, gid, vhost)
          File.chmod(0o600, vhost)
          inputs.each do |jail_path, value|
            host_path = value.is_a?(Hash) ? value.fetch("path") : value
            writable = value.is_a?(Hash) && value["writable"] == true
            install_input(root, jail_path, host_path, uid, gid, writable: writable)
          end
          root
        end

        def install_input(root, jail_path, host_path, uid, gid, writable: false)
          target = File.join(root, jail_path.delete_prefix("/"))
          FileUtils.mkdir_p(File.dirname(target), mode: 0o700)
          File.chown(uid, gid, File.dirname(target))
          if File.blockdev?(host_path)
            stat = File.stat(host_path)
            mknod(target, stat.rdev_major, stat.rdev_minor, block: true)
            File.chown(uid, gid, target)
            File.chmod(writable ? 0o600 : 0o400, target)
          elsif writable
            begin
              File.link(host_path, target)
            rescue SystemCallError
              FileUtils.cp(host_path, target)
            end
            File.chown(uid, gid, target)
            File.chmod(0o600, target)
          else
            stat = File.stat(host_path)
            raise JailerError, "read-only input #{host_path} is writable by group/other" unless stat.mode.nobits?(0o022)
            unless stat.mode.allbits?(0o004) || acl_grants_read?(
              host_path, uid
            )
              raise JailerError,
                    "read-only input #{host_path} is not readable by uid #{uid}"
            end

            begin
              File.link(host_path, target)
            rescue SystemCallError
              FileUtils.cp(host_path, target)
              File.chmod(0o644, target)
            end
          end
          target
        end

        def launch(id:, uid:, gid:, netns_path:, cgroup_limits: {}, firecracker_args: [], log_path: nil)
          validate_id!(id)
          root = chroot_for(id)
          raise JailerError, "jail root #{root} is not prepared" unless File.directory?(root)
          raise JailerError, "network namespace #{netns_path} does not exist" unless File.exist?(netns_path)

          arguments = [@artifacts.path(:jailer), "--id", id, "--exec-file", @artifacts.path(:firecracker), "--uid", uid.to_s, "--gid", gid.to_s,
                       "--chroot-base-dir", @chroot_base, "--netns", netns_path, "--cgroup-version", "2", "--parent-cgroup", @parent_cgroup, "--new-pid-ns"]
          cgroup_limits.each { |file, value| arguments.push("--cgroup", "#{file}=#{value}") }
          arguments.push("--", "--api-sock", "/run/firecracker.socket", *firecracker_args)
          log = log_path ? File.open(log_path, "a") : File.open(File::NULL, "w")
          launched_at = Time.now.utc
          jailer_pid = Process.spawn(*arguments, in: File::NULL, out: log, err: log, close_others: true)
          log.close
          vmm_pid = wait_for_pid_file(root, jailer_pid)
          # With --new-pid-ns the jailer parent exits once Firecracker runs;
          # reap it in the background so it never lingers as a zombie.
          Process.detach(jailer_pid)
          fd = @pidfd.open(pid: vmm_pid)
          start_time = process_start_time(vmm_pid)
          verify_confinement!(vmm_pid, uid)
          wait_for_api_socket(File.join(root, "run", "firecracker.socket"), vmm_pid)
          Instance.new(id: id, jailer_pid: jailer_pid, vmm_pid: vmm_pid, vmm_start_time: start_time, pidfd: fd, chroot: root,
                       api_socket: File.join(root, "run", "firecracker.socket"), uid: uid, gid: gid,
                       cgroup_path: File.join(@cgroup_root, @parent_cgroup, id), netns_path: netns_path, launched_at: launched_at.iso8601(6))
        rescue StandardError => error
          kill_pid(jailer_pid) if jailer_pid
          raise error.is_a?(JailerError) ? error : JailerError.new("jailer launch failed: #{error.class}: #{error.message}")
        end

        # Confinement is verified from the kernel's view of the VMM process,
        # not from the jailer's exit status.
        # Confinement is verified from the kernel's view of the VMM process,
        # not from the jailer's exit status.  Identity, capabilities and the
        # private PID namespace hold from exec; the seccomp filter and
        # no_new_privs are installed by Firecracker when the VM starts, so
        # verify_seccomp! runs after InstanceStart / snapshot load.
        def verify_confinement!(pid, uid, timeout: 5.0)
          # The jailer writes the PID file before the child has switched
          # UID and exec'd Firecracker; wait for the kernel to show the
          # jailed identity (or the child to die).
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          status = nil
          loop do
            status = File.read("/proc/#{pid}/status")
            uids = status[/^Uid:\s+(.+)$/, 1].to_s.split.map(&:to_i)
            break if uids.uniq == [uid] && status[/^Name:\s+(.+)$/, 1].to_s.start_with?("firecracker")
            if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
              raise JailerError,
                    "VMM did not drop to uid #{uid} within #{timeout}s (uid #{uids.inspect})"
            end

            sleep 0.005
          end
          uids = status[/^Uid:\s+(.+)$/, 1].to_s.split.map(&:to_i)
          raise JailerError, "VMM runs as uid #{uids.inspect}, expected #{uid}" unless uids.uniq == [uid]

          %w[CapPrm CapEff CapAmb].each do |name|
            value = status[/^#{name}:\s+([0-9a-f]+)/, 1]
            raise JailerError, "VMM keeps capabilities #{name}=#{value}" unless value.nil? || value.to_i(16).zero?
          end
          nspid = status[/^NSpid:\s+(.+)$/, 1].to_s.split
          raise JailerError, "VMM is not in a private PID namespace" unless nspid.length >= 2 && nspid.last == "1"

          true
        end

        def verify_seccomp!(instance, timeout: 5.0)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          status = nil
          loop do
            status = File.read("/proc/#{instance.vmm_pid}/status")
            break if status[/^Seccomp:\s+(\d)/, 1] == "2" && status[/^NoNewPrivs:\s+(\d)/, 1] == "1"
            if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
              raise JailerError,
                    "VMM is not under seccomp filter mode with no_new_privs"
            end

            sleep 0.01
          end
          true
        end

        def confinement_report(instance)
          status = File.read("/proc/#{instance.vmm_pid}/status")
          {"uid" => status[/^Uid:\s+(.+)$/, 1].to_s.split.map(&:to_i).uniq, "cap_eff" => status[/^CapEff:\s+([0-9a-f]+)/, 1],
           "seccomp" => status[/^Seccomp:\s+(\d)/, 1], "no_new_privs" => status[/^NoNewPrivs:\s+(\d)/, 1],
           "nspid" => status[/^NSpid:\s+(.+)$/, 1].to_s.split, "cgroup" => File.read("/proc/#{instance.vmm_pid}/cgroup").strip,
           "root_inode" => File.stat("/proc/#{instance.vmm_pid}/root").ino, "chroot_inode" => File.stat(instance.chroot).ino,
           "mount_namespace" => File.readlink("/proc/#{instance.vmm_pid}/ns/mnt"), "host_mount_namespace" => File.readlink("/proc/self/ns/mnt"),
           "network_namespace" => File.readlink("/proc/#{instance.vmm_pid}/ns/net"), "host_network_namespace" => File.readlink("/proc/self/ns/net"),
           "open_files" => Dir.children("/proc/#{instance.vmm_pid}/fd").length}
        rescue SystemCallError => error
          {"error" => error.message}
        end

        def alive?(instance)
          return false unless File.exist?("/proc/#{instance.vmm_pid}")

          process_start_time(instance.vmm_pid) == instance.vmm_start_time
        rescue SystemCallError
          false
        end

        # Sends SIGKILL through the pidfd (never through a reused PID) and
        # waits for the exit.
        def kill(instance, timeout: 10.0)
          @pidfd.send_signal(pidfd: instance.pidfd, signal: Signal.list.fetch("KILL")) if alive?(instance)
          kill_pid(instance.jailer_pid)
          wait_exit(instance, timeout: timeout)
        end

        def wait_exit(instance, timeout: 10.0)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          while alive?(instance)
            if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
              raise JailerError,
                    "VMM #{instance.vmm_pid} did not exit within #{timeout}s"
            end

            sleep 0.02
          end
          reap(instance.jailer_pid)
          true
        end

        def remove_jail(id)
          validate_id!(id)
          directory = File.join(@chroot_base, exec_name, id)
          return false unless File.exist?(directory)

          FileUtils.rm_rf(directory)
          true
        end

        def cgroup_populated?(instance)
          events = File.join(instance.cgroup_path, "cgroup.events")
          return false unless File.file?(events)

          File.read(events).match?(/^populated 1$/)
        end

        def remove_cgroup(instance)
          return false unless File.directory?(instance.cgroup_path)
          raise JailerError, "cgroup #{instance.cgroup_path} is still populated" if cgroup_populated?(instance)

          Dir.rmdir(instance.cgroup_path)
          true
        end

        def list_jails
          directory = File.join(@chroot_base, exec_name)
          return [] unless File.directory?(directory)

          Dir.children(directory).sort
        end

        private

        def wait_for_pid_file(root, jailer_pid, timeout: 10.0)
          path = File.join(root, "#{exec_name}.pid")
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          loop do
            if File.file?(path)
              content = File.read(path).strip
              return Integer(content) if content.match?(/\A\d+\z/) && File.exist?("/proc/#{content}")
            end
            _pid, status = Process.waitpid2(jailer_pid, Process::WNOHANG)
            raise JailerError, "jailer exited before Firecracker started (status #{status.exitstatus.inspect})" if status
            if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
              raise JailerError,
                    "Firecracker did not report its PID within #{timeout}s"
            end

            sleep 0.01
          end
        end

        def wait_for_api_socket(path, pid, timeout: 10.0)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          until File.socket?(path)
            raise JailerError, "Firecracker exited before opening its API socket" unless File.exist?("/proc/#{pid}")
            if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
              raise JailerError,
                    "Firecracker did not open #{path} within #{timeout}s"
            end

            sleep 0.005
          end
          true
        end

        def process_start_time(pid)
          stat = File.read("/proc/#{pid}/stat")
          Integer(stat[(stat.rindex(")") + 2)..].split[19])
        end

        def kill_pid(pid)
          Process.kill("KILL", pid)
        rescue Errno::ESRCH, Errno::EPERM
          nil
        end

        def reap(pid)
          Process.waitpid(pid, Process::WNOHANG)
        rescue Errno::ECHILD
          nil
        end

        def mknod(path, major, minor, block: false)
          type = block ? "b" : "c"
          system("mknod", path, type, major.to_s, minor.to_s) || raise(JailerError, "mknod #{path} failed")
        end

        # Shared read-only inputs (image disks) grant each VM's UID read
        # access through a POSIX ACL instead of being world-readable.
        def acl_grants_read?(path, uid)
          output, status = Open3.capture2("getfacl", "--omit-header", "--numeric", "--absolute-names", path)
          return false unless status.success?

          output.lines.any? { |line| line.strip.match?(/\Auser:#{Integer(uid)}:r/) } && output.lines.none? do |line|
            line.strip.match?(/\Amask::-/)
          end
        rescue SystemCallError
          false
        end

        def validate_id!(id)
          raise JailerError, "invalid jail id #{id.inspect}" unless id.is_a?(String) && id.match?(/\A[a-zA-Z0-9_-]{1,64}\z/)
        end
      end
    end
  end
end
