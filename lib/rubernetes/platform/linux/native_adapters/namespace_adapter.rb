# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Creates a namespace holder outside the workload process.  The holder
        # is the stable namespace owner and the Pod's PID 1 (§5.8.6); workload
        # processes join its network/UTS/IPC/user namespaces and copy its
        # mount namespace before they build their own rootfs.
        class NamespaceAdapter
          include CapabilityContract
          include ProcessIdentity

          CLONE_NEWNS = Setns::CLONE_NEWNS
          CLONE_NEWUTS = Setns::CLONE_NEWUTS
          CLONE_NEWIPC = Setns::CLONE_NEWIPC
          CLONE_NEWUSER = Setns::CLONE_NEWUSER
          CLONE_NEWPID = Setns::CLONE_NEWPID
          CLONE_NEWNET = Setns::CLONE_NEWNET
          CLONE_NEWCGROUP = Setns::CLONE_NEWCGROUP
          # Values from include/uapi/linux/prctl.h.
          PR_SET_PDEATHSIG = 1
          # Values from include/uapi/linux/sockios.h and linux/if.h.
          SIOCGIFFLAGS = 0x8913
          SIOCSIFFLAGS = 0x8914
          IFF_UP = 0x1
          IFREQ_SIZE = 40
          IFNAMSIZ = 16
          SIGKILL = Signal.list.fetch("KILL")
          SIGTERM = Signal.list.fetch("TERM")
          HELPER_TIMEOUT = 30.0

          Handle = Data.define(:id, :identity, :pid, :pidfd, :supervisor_pid, :namespaces, :plan,
                               :start_time, :namespace_links, :creation_method, :clone_flags, :user_mapping, :commit_channel) do
            def to_h
              {
                "id" => id,
                "identity" => identity,
                "pid" => pid,
                "pidfd" => pidfd,
                "supervisor_pid" => supervisor_pid,
                "namespaces" => namespaces.map(&:to_s),
                "start_time" => start_time,
                "namespace_links" => namespace_links,
                "creation_method" => creation_method,
                "clone_flags" => clone_flags,
                "user_mapping" => user_mapping,
                "plan" => plan.to_h
              }
            end
          end

          PRCTL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["prctl"], [Fiddle::TYPE_LONG] * 5, Fiddle::TYPE_INT
          )
          SETHOSTNAME = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["sethostname"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_INT
          )

          NAMESPACE_TYPES = Setns::NAMESPACE_TYPES

          def initialize(pidfd: Pidfd.new, mount: Mount.new, proc_root: "/proc", clone3: Clone3.new, setns: Setns.new,
                         supervisor_cgroup_root: nil)
            @pidfd = pidfd
            @mount = mount
            @proc_root = File.expand_path(String(proc_root))
            @clone3 = clone3
            @setns = setns
            @supervisor_cgroup = File.join(File.expand_path(supervisor_cgroup_root), "rubernetes-supervisors") if supervisor_cgroup_root
            @handles = {}
            @mutex = Mutex.new
          end

          attr_reader :handles, :supervisor_cgroup

          def native_capabilities
            {
              namespace: namespace_probe,
              namespace_setns: true,
              namespace_pidfd: true,
              namespace_clone3: true,
              namespace_user: user_namespaces_available?
            }.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:namespace), "Linux namespace descriptors are unavailable")
            require_capability!(native_capabilities.fetch(:namespace_setns), "setns(2)/unshare(2) are unavailable")
            require_capability!(native_capabilities.fetch(:namespace_pidfd), "pidfd adapter is unavailable")
            require_capability!(native_capabilities.fetch(:namespace_clone3), "clone3 namespace creation is unavailable")
            true
          end

          # Raw clone3 executes a small Ruby setup branch in the child. MRI
          # cannot safely resume that branch after clone3 from a process that
          # has other Ruby threads (the child inherits a held VM lock). Route
          # threaded callers through a single-threaded supervisor process;
          # the supervisor owns the clone3 child until the pidfd is closed.
          def create(plan:, id:, identity:, durable: false)
            if @clone3.instance_of?(Clone3) && (durable || Thread.list.count(&:alive?) > 1)
              return create_through_exec_supervisor(plan: plan, id: id, identity: identity, durable: durable)
            end

            create_direct(plan: plan, id: id, identity: identity)
          end

          def destroy(handle:, id:, identity:)
            value = handle.is_a?(Handle) ? handle : @mutex.synchronize { @handles[handle_id(handle)] }
            # Already destroyed by an earlier attempt: nothing left to release.
            return true if value.nil?
            raise EffectError, "namespace identity mismatch for #{id}" unless value.identity == String(identity)

            # Ownership of the pidfd is taken exactly once.  Teardown is
            # retried until it succeeds, and a retry holding the same Handle
            # used to close value.pidfd AGAIN -- by then the kernel had handed
            # that descriptor number to something else, usually glibc's netlink
            # socket, which answers EBADF by aborting the whole process
            # ("Unexpected error 9 on netlink descriptor 67"): the node agent
            # died mid-run and took every Pod on the node with it.
            owned = @mutex.synchronize { @handles.delete(value.id) }
            return true if owned.nil?

            value = owned
            if (channel = value.commit_channel)
              [channel.writer, channel.reader].reject(&:closed?).each(&:close)
            end
            begin
              @pidfd.send_signal(pidfd: value.pidfd, signal: SIGTERM, resource_id: value.identity)
              wait_for_exit(value.pidfd, timeout: 2.0, resource_id: value.identity)
            rescue Linux::Error => error
              raise unless [Errno::ESRCH::Errno, Errno::ECHILD::Errno].include?(error.errno)
            end
            begin
              @pidfd.send_signal(pidfd: value.pidfd, signal: SIGKILL, resource_id: value.identity)
              wait_for_exit(value.pidfd, timeout: 2.0, resource_id: value.identity)
            rescue Linux::Error => error
              raise unless [Errno::ESRCH::Errno, Errno::ECHILD::Errno, Errno::EPIPE::Errno].include?(error.errno)
            ensure
              close_fd(value.pidfd)
              reap_supervisor(value.supervisor_pid)
            end
            true
          end

          # The overlay cleanup path may run after this adapter has destroyed
          # the holder.  Keep that distinction local to the adapter so an
          # externally killed holder still fails the normal mount readback.
          def destroyed?(handle)
            return false unless handle.is_a?(Handle)

            unregistered = @mutex.synchronize { !@handles.key?(handle.id) }
            unregistered && !File.exist?("/proc/#{Integer(handle.pid)}")
          rescue ArgumentError, TypeError
            false
          end

          def lookup(value)
            id = handle_id(value)
            @mutex.synchronize { @handles.fetch(id) { raise EffectError, "unknown namespace #{id}" } }
          end

          # Reopen a namespace holder discovered after an agent restart.  The
          # old pidfd is process-local and is deliberately ignored; the PID,
          # start time, and namespace links are checked before a new pidfd is
          # acquired.  Identity mismatch is fatal and never triggers cleanup.
          def adopt(id:, identity:, plan:, metadata:)
            value = metadata.to_h.transform_keys(&:to_s)
            pid = Integer(value.fetch("pid"))
            expected_start = Integer(value.fetch("start_time"))
            actual_start, links = kernel_identity(pid, Array(plan.namespaces))
            raise EffectError, "namespace holder start time changed during adoption" unless actual_start == expected_start

            expected_links = value["namespace_links"] || {}
            raise EffectError, "namespace holder namespace identity changed during adoption" unless expected_links.empty? || expected_links == links

            pidfd = @pidfd.open(pid: pid, resource_id: String(identity))
            handle = Handle.new(id: String(id).freeze, identity: String(identity).freeze, pid: pid,
                                pidfd: pidfd, supervisor_pid: value["supervisor_pid"],
                                namespaces: Array(plan.namespaces).map(&:to_sym).freeze, plan: plan,
                                start_time: actual_start, namespace_links: links.freeze,
                                creation_method: value.fetch("creation_method", "clone3"),
                                clone_flags: Integer(value.fetch("clone_flags", Clone3::CLONE_PIDFD)),
                                user_mapping: value["user_mapping"], commit_channel: nil)
            @mutex.synchronize do
              existing = @handles[handle.id]
              return existing if existing

              @handles[handle.id] = handle
            end
            handle
          rescue KeyError, ArgumentError, TypeError, SystemCallError => error
            raise EffectError, "namespace adoption failed: #{error.message}"
          end

          def resources
            @mutex.synchronize { @handles.values.map(&:to_h).freeze }
          end

          # Open verified descriptors for the holder namespaces.  The link
          # text recorded at creation is compared against the live link so a
          # recycled PID can never be entered.
          def open_namespace_descriptors(handle, only: nil)
            value = handle.is_a?(Handle) ? handle : lookup(handle)
            selected = (only ? Array(only).map(&:to_sym) : value.namespaces) & value.namespaces
            selected.to_h do |name|
              [name, @setns.open_namespace(pid: value.pid, name: name,
                                           expected_link: value.namespace_links[name.to_s],
                                           resource_id: "#{value.identity}:#{name}")]
            end
          end

          private

          def namespace_probe
            required = NAMESPACE_TYPES.values.map { |_flag, name| File.join(@proc_root, "self", "ns", name) }
            required.all? { |path| File.stat(path).file? || File.stat(path).ftype == "file" }
          rescue SystemCallError
            false
          end

          def user_namespaces_available?
            Integer(File.read("/proc/sys/user/max_user_namespaces").strip).positive?
          rescue SystemCallError, ArgumentError
            false
          end

          # A holder is named by its handle or by its id.
          def handle_id(value)
            value.is_a?(Handle) ? value.id : String(value)
          end

          def register(handle)
            @mutex.synchronize { @handles[handle.id] = handle }
            handle
          end

          def wait_for_exit(pidfd, timeout:, resource_id:)
            @pidfd.wait(pidfd: pidfd, timeout: timeout, resource_id: resource_id)
          end

          def terminate_process(pid)
            return unless pid

            Process.kill(SIGKILL, Integer(pid))
            Process.wait(Integer(pid), Process::WNOHANG)
          rescue Errno::ESRCH, Errno::ECHILD
            nil
          end

          def reap_supervisor(pid)
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2.0
            loop do
              result = Process.wait(Integer(pid), Process::WNOHANG)
              return true if result
              break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

              sleep 0.01
            end
            Process.kill(SIGKILL, Integer(pid))
            Process.wait(Integer(pid))
            true
          rescue Errno::ECHILD, Errno::ESRCH
            true
          end

          def close_fd(fd)
            IO.for_fd(Integer(fd)).close
          rescue IOError, Errno::EBADF
            nil
          end

          # Numeric PIDs and pidfds are process-local handles.  Persist the
          # kernel start time and namespace inode links alongside them so a
          # restarted agent can prove that a discovered holder is the same
          # process before it is ever signalled or cleaned up.
          def kernel_identity(pid, namespaces)
            stat = File.read("/proc/#{Integer(pid)}/stat")
            start_time = Integer(stat[(stat.rindex(")") + 1)..].split.fetch(19))
            links = Array(namespaces).to_h do |name|
              proc_name = NAMESPACE_TYPES.fetch(name).fetch(1)
              [name.to_s, File.readlink("/proc/#{Integer(pid)}/ns/#{proc_name}")]
            end
            [start_time, links.freeze]
          rescue SystemCallError, ArgumentError, IndexError => error
            raise EffectError, "namespace holder identity could not be read: #{error.message}"
          end
        end
      end
    end
  end
end
