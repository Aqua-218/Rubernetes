# frozen_string_literal: true

# Production Linux effects used by Native host profiles.  These adapters are
# deliberately separate from the runtime policy/state machine: they own only
# kernel-facing operations and expose a read-only capability preflight.  A
# failed preflight or effect is fatal; no adapter silently falls back to a
# recording implementation.
#
# No adapter shells out to nsenter(1), unshare(1), or any other external
# binary.  Namespace transitions are direct setns(2)/unshare(2) calls made by
# a freshly created, single-threaded clone3 child (spec/node/runtime.md
# §5.8.6, §5.8.10), and the workload bootstrap runs in that child until it
# execveat(2)s the verified executable.

require "digest"
# Digest::SHA256 autoloads on first use; the workload bootstrap first uses it
# after the pivot into the container root, where the library is not there.
require "digest/sha2"
require "fileutils"
require "fiddle"
require "io/console"
require "pty"
require "json"
require "openssl"
require "rbconfig"
require "socket"

require_relative "capabilities"
require_relative "cgroup_v2"
require_relative "clone3"
require_relative "landlock"
require_relative "mount"
require_relative "openat2"
require_relative "pidfd"
require_relative "pivot_root"
require_relative "security"
require_relative "setns"
require_relative "userns"

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        class Unsupported < StandardError; end
        class EffectError < StandardError; end

        module CapabilityContract
          def native_capabilities
            @native_capabilities ||= capabilities_snapshot
          end

          private

          def capabilities_snapshot
            {}.freeze
          end

          def require_capability!(value, message)
            raise Unsupported, message unless value

            true
          end
        end

        # Shared low-level helpers for processes that must prove their own
        # identity across a PID namespace boundary.
        module ProcessIdentity
          module_function

          def process_start_time(pid, proc_root: "/proc")
            stat = File.read(File.join(proc_root, Integer(pid).to_s, "stat"))
            suffix = stat[(stat.rindex(")") + 1)..]
            Integer(suffix.split.fetch(19))
          rescue SystemCallError, ArgumentError, IndexError
            raise Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "procfs(start_time)", resource_id: "process:#{pid}")
          end

          # NSpid lists the PID in every namespace from the outermost (host)
          # to the innermost.  The host PID is the only value the agent can
          # correlate with a pidfd and with cgroup.procs.
          def host_pid_from_status(status)
            line = String(status).lines.find { |entry| entry.start_with?("NSpid:") }
            line ? line.split.drop(1).first.to_i : 0
          end

          def kernel_process_id
            File.basename(File.readlink("/proc/self")).to_i
          rescue SystemCallError
            Process.pid
          end
        end

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
                               :start_time, :namespace_links, :creation_method, :clone_flags, :user_mapping) do
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
                "plan" => plan.respond_to?(:to_h) ? plan.to_h : plan
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

          def initialize(pidfd: Pidfd.new, mount: Mount.new, proc_root: "/proc", clone3: Clone3.new, setns: Setns.new)
            @pidfd = pidfd
            @mount = mount
            @proc_root = File.expand_path(String(proc_root))
            @clone3 = clone3
            @setns = setns
            @handles = {}
            @mutex = Mutex.new
          end

          attr_reader :handles

          def native_capabilities
            {
              namespace: namespace_probe,
              namespace_setns: @setns.respond_to?(:setns) && @setns.respond_to?(:unshare),
              namespace_pidfd: @pidfd.respond_to?(:open),
              namespace_clone3: @clone3.respond_to?(:call),
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
          def create(plan:, id:, identity:)
            return create_through_exec_supervisor(plan: plan, id: id, identity: identity) if Thread.list.count(&:alive?) > 1 && @clone3.instance_of?(Clone3)

            create_direct(plan: plan, id: id, identity: identity)
          end

          NAMESPACE_EXEC_SUPERVISOR_SOURCE = <<~'RUBY'
            require "json"
            require "rubernetes/platform/linux/native_adapters"

            begin
              # The payload arrives as the argument, or (for a pre-spawned
              # idle supervisor) as one line on stdin once a sandbox needs it.
              payload_text = ARGV.empty? ? STDIN.gets : ARGV.fetch(0)
              exit!(0) if payload_text.nil?
              payload = JSON.parse(payload_text)
              parent_pid = Integer(payload.fetch("parent_pid"))
              parent_start_time = Integer(payload.fetch("parent_start_time"))
              plan_class = Struct.new(:namespaces, :user_mapping, :hostname, keyword_init: true)
              plan = plan_class.new(
                namespaces: Array(payload.fetch("namespaces")).map(&:to_sym),
                user_mapping: payload["user_mapping"],
                hostname: payload["hostname"]
              )
              adapter = Rubernetes::Platform::Linux::NativeAdapters::NamespaceAdapter.new
              adapter.send(:set_parent_death_signal,
                            expected_parent_pid: parent_pid,
                            expected_parent_start_time: parent_start_time)
              handle = adapter.send(:create_direct,
                                    plan: plan,
                                    id: payload.fetch("id"),
                                    identity: payload.fetch("identity"))
              STDOUT.write(JSON.generate(
                "ok" => true,
                "pid" => handle.pid,
                "start_time" => handle.start_time,
                "namespace_links" => handle.namespace_links,
                "namespaces" => handle.namespaces.map(&:to_s),
                "clone_flags" => handle.clone_flags,
                "user_mapping" => handle.user_mapping
              ) << "\n")
              STDOUT.flush
              pidfd = adapter.instance_variable_get(:@pidfd)
              sleep 0.01 while pidfd.alive?(pidfd: handle.pidfd)
              Process.wait(handle.pid)
              exit!(0)
            rescue StandardError => error
              STDOUT.write(JSON.generate("ok" => false, "error" => "#{error.class}: #{error.message}") << "\n")
              STDOUT.flush
              exit!(127)
            end
          RUBY

          # Idle exec supervisors started ahead of time (a microVM guest
          # pre-spawns them before the base snapshot so a restored VM never
          # pays the Ruby start-up of the holder).  Each entry is
          # [pid, stdin_writer, stdout_reader].
          POOL_MUTEX = Mutex.new
          @supervisor_pool = []

          class << self
            def prespawn_exec_supervisors(count, ruby_library_root: nil)
              root = ruby_library_root || new.send(:ruby_library_root)
              count.times do
                reader, writer = IO.pipe
                input_reader, input_writer = IO.pipe
                pid = Process.spawn(
                  RbConfig.ruby, "--disable-gems", "-I", root, "-e", NAMESPACE_EXEC_SUPERVISOR_SOURCE,
                  in: input_reader, out: writer, err: $stderr
                )
                writer.close
                input_reader.close
                POOL_MUTEX.synchronize { @supervisor_pool << [pid, input_writer, reader] }
              end
              @supervisor_pool.length
            end

            def take_exec_supervisor
              POOL_MUTEX.synchronize do
                until @supervisor_pool.empty?
                  entry = @supervisor_pool.shift
                  begin
                    Process.waitpid(entry[0], Process::WNOHANG).nil? ? (return entry) : next
                  rescue Errno::ECHILD
                    next
                  end
                end
                nil
              end
            end

            def exec_supervisor_pool_size
              POOL_MUTEX.synchronize { @supervisor_pool.length }
            end
          end

          def create_through_exec_supervisor(plan:, id:, identity:)
            parent_pid = Process.pid
            payload = JSON.generate(
              "parent_pid" => parent_pid,
              "parent_start_time" => process_start_time(parent_pid),
              "id" => String(id),
              "identity" => String(identity),
              "namespaces" => Array(plan.namespaces).map(&:to_s),
              "user_mapping" => plan.user_mapping,
              "hostname" => plan.hostname
            )
            pooled = self.class.take_exec_supervisor
            if pooled
              supervisor_pid, input_writer, reader = pooled
              input_writer.write(payload + "\n")
              input_writer.close
            else
              reader, writer = IO.pipe
              # The exec supervisor needs only the platform layer and the JSON
              # default gem; skipping RubyGems initialization removes most of
              # its startup cost (a microVM guest runs it on one vCPU).
              supervisor_pid = Process.spawn(
                RbConfig.ruby, "--disable-gems", "-I", ruby_library_root, "-e", NAMESPACE_EXEC_SUPERVISOR_SOURCE,
                payload, out: writer, err: $stderr
              )
              writer.close
            end
            raise EffectError, "namespace exec supervisor did not report readiness" unless reader.wait_readable(10)

            response = JSON.parse(reader.gets.to_s)
            unless response["ok"] == true
              raise EffectError, response["error"].to_s.empty? ? "namespace exec supervisor failed" : response["error"]
            end

            pid = Integer(response.fetch("pid"))
            pidfd = @pidfd.open(pid: pid, resource_id: String(identity))
            handle = Handle.new(
              id: String(id).freeze,
              identity: String(identity).freeze,
              pid: pid,
              pidfd: pidfd,
              supervisor_pid: supervisor_pid,
              namespaces: Array(response.fetch("namespaces")).map(&:to_sym).freeze,
              plan: plan,
              start_time: Integer(response.fetch("start_time")),
              namespace_links: response.fetch("namespace_links").freeze,
              creation_method: "clone3",
              clone_flags: Integer(response.fetch("clone_flags")),
              user_mapping: response["user_mapping"]
            )
            @mutex.synchronize { @handles[handle.id] = handle }
            handle
          rescue JSON::ParserError, KeyError, ArgumentError, TypeError, SystemCallError => error
            terminate_process(supervisor_pid) if supervisor_pid
            raise EffectError, "namespace exec supervisor failed: #{error.message}"
          ensure
            reader&.close unless reader&.closed?
            writer&.close unless writer&.closed?
          end

          # Holder creation.  Ordering inside the child (R-1.6):
          # 1. PR_SET_PDEATHSIG so an agent crash never strands a PID 1;
          # 2. loopback, propagation, and hostname while the child still holds
          #    full capabilities over the freshly created namespaces (they are
          #    owned by the initial user namespace on purpose: mounts copied
          #    from them by workloads are not MNT_LOCKED, so the workload can
          #    later perform a regular umount of its old root);
          # 3. unshare(CLONE_NEWUSER) last, then wait for the parent to write
          #    setgroups=deny/uid_map/gid_map (user_namespaces(7) only allows a
          #    65,536-wide map from a writer in the parent namespace).
          def create_direct(plan:, id:, identity:)
            namespaces = normalize_namespaces(plan)
            validate_plan_namespaces!(namespaces)
            validate_native_capabilities!
            user_mapping = normalize_user_mapping(plan)
            if user_mapping && !namespaces.include?(:user)
              raise EffectError,
                    "user namespace mapping requires the :user namespace in the plan"
            end
            raise EffectError, "the :user namespace requires a uid/gid mapping" if namespaces.include?(:user) && user_mapping.nil?

            reader, writer = IO.pipe
            map_reader, map_writer = IO.pipe
            agent_pid = Process.pid
            agent_start_time = process_start_time(agent_pid)
            clone_flags = (namespaces - [:user]).sum { |name| NAMESPACE_TYPES.fetch(name).fetch(0) } | Clone3::CLONE_PIDFD
            clone_result = @clone3.call(
              args: Clone3::Args.new(flags: clone_flags),
              resource_id: String(identity)
            )
            if clone_result.child?
              reader.close
              map_writer.close
              begin
                set_parent_death_signal(expected_parent_pid: agent_pid,
                                        expected_parent_start_time: agent_start_time,
                                        pid_namespace_pid1: namespaces.include?(:pid))
                configure_loopback if namespaces.include?(:network)
                # Only a holder that owns a mount namespace may change
                # propagation: a plan without :mount (a PID-only holder) still
                # shares the agent's -- the host's -- mount namespace, and the
                # recursive slave/private landed on the host root, stripping
                # every shared peer group (the agents' Pod roots included).
                make_mounts_slave if namespaces.include?(:mount)
                configure_hostname(plan)
                if user_mapping
                  @setns.unshare(flags: CLONE_NEWUSER, resource_id: "#{identity}:user")
                  writer.write("U")
                  writer.flush
                  acknowledgement = map_reader.read(1)
                  raise EffectError, "user namespace mapping was not acknowledged" unless acknowledgement == "M"
                end
                map_reader.close
                send_ready(writer, kernel_process_id)
                hold_until_signal
              rescue StandardError => error
                send_failure(writer, error)
                exit!(127)
              ensure
                writer.close unless writer.closed?
              end
              exit!(0)
            end
            supervisor_pid = clone_result.pid
            writer.close
            map_reader.close
            first = reader.read(1)
            if first == "U"
              UserNamespace.write_mappings(pid: supervisor_pid, mapping: user_mapping, proc_root: @proc_root)
              map_writer.write("M")
              map_writer.flush
              first = reader.read(1)
            end
            map_writer.close
            payload = first.to_s + reader.read(8).to_s
            reader.close
            unless payload.bytesize == 9 && payload.getbyte(0) == "R".ord
              terminate_process(supervisor_pid)
              raise EffectError, decode_failure(payload)
            end

            pid = supervisor_pid
            pidfd = clone_result.pidfd
            raise EffectError, "clone3 did not return a namespace pidfd" unless pidfd

            start_time, namespace_links = kernel_identity(pid, namespaces)
            handle = Handle.new(
              id: String(id).freeze,
              identity: String(identity).freeze,
              pid: pid,
              pidfd: pidfd,
              supervisor_pid: supervisor_pid,
              namespaces: namespaces.freeze,
              plan: plan,
              start_time: start_time,
              namespace_links: namespace_links.freeze,
              creation_method: "clone3",
              clone_flags: clone_flags,
              user_mapping: user_mapping&.to_h
            )
            @mutex.synchronize { @handles[handle.id] = handle }
            handle
          rescue SystemCallError, UserNamespace::Error => error
            terminate_process(supervisor_pid) if supervisor_pid
            close_fd(clone_result.pidfd) if clone_result&.pidfd
            raise EffectError, "namespace creation failed: #{error.message}"
          rescue StandardError
            terminate_process(supervisor_pid) if supervisor_pid
            close_fd(clone_result.pidfd) if clone_result&.pidfd
            raise
          ensure
            reader&.close unless reader&.closed?
            writer&.close unless writer&.closed?
            map_reader&.close unless map_reader&.closed?
            map_writer&.close unless map_writer&.closed?
          end

          def destroy(handle:, id:, identity:)
            value = if handle.is_a?(Handle)
                      handle
                    else
                      @mutex.synchronize { @handles[String(handle.respond_to?(:id) ? handle.id : handle)] }
                    end
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
            id = value.respond_to?(:id) ? value.id : String(value)
            @mutex.synchronize { @handles.fetch(String(id)) { raise EffectError, "unknown namespace #{id}" } }
          end

          # Reopen a namespace holder discovered after an agent restart.  The
          # old pidfd is process-local and is deliberately ignored; the PID,
          # start time, and namespace links are checked before a new pidfd is
          # acquired.  Identity mismatch is fatal and never triggers cleanup.
          def adopt(id:, identity:, plan:, metadata:)
            value = metadata.respond_to?(:to_h) ? metadata.to_h.transform_keys(&:to_s) : {}
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
                                user_mapping: value["user_mapping"])
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

          # Run a Ruby block inside the holder's namespaces and return its
          # JSON-serializable result.  The block runs in a fresh clone3 child
          # (single task, so setns(2) on a mount namespace is legal) created
          # from a forked, single-Ruby-thread intermediary; the caller's own
          # namespaces are never changed, even when the block raises.
          def within_namespaces(handle, only: [:mount], timeout: HELPER_TIMEOUT)
            value = handle.is_a?(Handle) ? handle : lookup(handle)
            descriptors = open_namespace_descriptors(value, only: only)
            reader, writer = IO.pipe
            helper_pid = Process.fork do
              reader.close
              begin
                clone_result = @clone3.call(args: Clone3::Args.new(flags: Clone3::CLONE_PIDFD),
                                            resource_id: "#{value.identity}:helper")
                if clone_result.child?
                  begin
                    # Ordered join: the user namespace first when present so
                    # the mount namespace join is authorized by it, then the
                    # remaining namespaces.
                    ordered = descriptors.keys.sort_by { |name| name == :user ? 0 : 1 }
                    ordered.each do |name|
                      @setns.setns(fd: descriptors.fetch(name), name: name, resource_id: "#{value.identity}:#{name}")
                    end
                    descriptors.each_value(&:close)
                    result = yield
                    writer.write(JSON.generate("ok" => true, "value" => result))
                    writer.flush
                    exit!(0)
                  rescue StandardError => error
                    writer.write(JSON.generate("ok" => false, "error" => "#{error.class}: #{error.message}",
                                               "errno" => (error.respond_to?(:errno) ? error.errno : nil)))
                    writer.flush
                    exit!(127)
                  end
                end
                writer.close
                wait = @pidfd.wait(pidfd: clone_result.pidfd, timeout: timeout, resource_id: "#{value.identity}:helper")
                unless wait
                  @pidfd.send_signal(pidfd: clone_result.pidfd, signal: SIGKILL, resource_id: "#{value.identity}:helper")
                  @pidfd.wait(pidfd: clone_result.pidfd, timeout: 5.0, resource_id: "#{value.identity}:helper")
                  exit!(124)
                end
                exit!(wait.exit_status || (128 + wait.term_signal.to_i))
              rescue StandardError
                exit!(125)
              end
            end
            writer.close
            descriptors.each_value(&:close)
            payload = reader.read
            reader.close
            _pid, status = Process.waitpid2(helper_pid)
            document = payload.to_s.empty? ? nil : JSON.parse(payload)
            raise EffectError, "namespace helper timed out" if status.exitstatus == 124
            unless status.success? && document && document["ok"] == true
              raise EffectError,
                    "namespace helper failed: #{document ? document["error"] : "exit #{status.exitstatus || (128 + status.termsig.to_i)}"}"
            end

            document["value"]
          rescue JSON::ParserError, Errno::ECHILD => error
            raise EffectError, "namespace helper returned an invalid result: #{error.message}"
          ensure
            reader&.close unless reader&.closed?
            writer&.close unless writer&.closed?
            descriptors&.each_value { |io| io.close unless io.closed? }
          end

          # Run a mount-only operation in the holder mount namespace.
          def with_mount_namespace(handle, &)
            within_namespaces(handle, only: [:mount], &)
            true
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

          def ruby_library_root
            @ruby_library_root ||= begin
              load_path = $LOAD_PATH.find { |path| File.file?(File.join(path, "rubernetes", "platform", "linux.rb")) }
              load_path || File.expand_path("../../..", __dir__)
            end
          end

          def normalize_namespaces(plan)
            values = plan.respond_to?(:namespaces) ? plan.namespaces : []
            Array(values).map { |name| String(name).downcase.to_sym }.uniq
          end

          def normalize_user_mapping(plan)
            mapping = plan.respond_to?(:user_mapping) ? plan.user_mapping : nil
            return nil unless mapping

            value = mapping.respond_to?(:to_h) ? mapping.to_h.transform_keys(&:to_s) : {}
            UserNamespace::Mapping.new(
              uid_base: Integer(value.fetch("uid_base")),
              gid_base: Integer(value.fetch("gid_base")),
              size: Integer(value.fetch("size"))
            )
          rescue KeyError, ArgumentError, TypeError => error
            raise EffectError, "invalid user namespace mapping: #{error.message}"
          end

          def validate_plan_namespaces!(namespaces)
            unknown = namespaces - NAMESPACE_TYPES.keys
            raise ArgumentError, "unsupported namespace #{unknown.first.inspect}" unless unknown.empty?
          end

          def set_parent_death_signal(expected_parent_pid: nil, expected_parent_start_time: nil, pid_namespace_pid1: false)
            result = PRCTL.call(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "namespace") if result == -1

            parent_changed = if pid_namespace_pid1
                               expected_parent_pid && expected_parent_start_time &&
                                 process_start_time(expected_parent_pid) != Integer(expected_parent_start_time)
                             else
                               expected_parent_pid && Process.ppid != Integer(expected_parent_pid)
                             end
            parent_changed ||= expected_parent_start_time && process_start_time(expected_parent_pid) != Integer(expected_parent_start_time)
            raise Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "namespace") if parent_changed

            true
          end

          # A freshly-created network namespace has a loopback device, but it
          # starts administratively DOWN.  Bring it up with the kernel ioctl
          # API so Pod-local listeners and port-forwarding work without a
          # dependency on a host `ip` binary inside the namespace.
          def configure_loopback
            request = "lo".b.ljust(IFNAMSIZ, "\0").ljust(IFREQ_SIZE, "\0")
            socket = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
            socket.ioctl(SIOCGIFFLAGS, request)
            flags = request.byteslice(IFNAMSIZ, 2).unpack1("s!")
            request[IFNAMSIZ, 2] = [flags | IFF_UP].pack("s!")
            socket.ioctl(SIOCSIFFLAGS, request)
            true
          rescue SystemCallError, IOError => error
            raise EffectError, "failed to configure loopback: #{error.message}"
          ensure
            socket&.close unless socket&.closed?
          end

          # The holder's mount namespace is a slave of the host's peer groups
          # (runc's default for a container root, see build_rootfs): nothing
          # mounted here reaches the host, but host-side mounts made under a
          # shared mount keep arriving.  The Pod directory is such a mount
          # (Node::PodVolumes makes it a shared self-bind), so a subPath the
          # kubelet binds when a container STARTS -- into an emptyDir an
          # earlier init container filled, GitLab's rails-secrets/secrets.yml
          # -- is visible to that container.  A private namespace only ever
          # saw the mounts that existed when the sandbox was created.
          def make_mounts_slave
            @mount.make_slave(target: "/", recursive: true, resource_id: "namespace:mount-propagation")
          end

          def configure_hostname(plan)
            hostname = plan.respond_to?(:hostname) ? plan.hostname : nil
            return true if hostname.nil? || String(hostname).empty?

            value = String(hostname)
            raise ArgumentError, "hostname must not contain NUL" if value.include?("\0")

            pointer = Fiddle::Pointer["#{value}\0"]
            result = SETHOSTNAME.call(pointer, value.bytesize)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "sethostname", resource_id: "namespace:hostname") if result == -1

            true
          end

          def hold_until_signal
            stopping = false
            trap("TERM") { stopping = true }
            trap("INT") { stopping = true }
            loop do
              begin
                loop do
                  reaped = Process.waitpid(-1, Process::WNOHANG)
                  break unless reaped
                end
              rescue Errno::ECHILD
                nil
              end
              break if stopping

              sleep 0.05
            end
          end

          def send_ready(writer, pid)
            writer.write("R" + [Integer(pid)].pack("Q<"))
            writer.flush
          end

          def send_failure(writer, error)
            errno = error.respond_to?(:errno) && error.errno ? Integer(error.errno) : Errno::EINVAL::Errno
            writer.write("E" + [errno].pack("l<"))
            writer.flush
          rescue IOError
            nil
          end

          def decode_failure(payload)
            return "namespace holder exited before reporting readiness" unless payload && payload.bytesize >= 5
            return "namespace holder failed with errno #{payload.byteslice(1, 4).unpack1("l<")}" unless payload.getbyte(0) == "R".ord

            "namespace holder returned an invalid readiness message"
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

        # OverlayFS preparation creates only a private workspace in the
        # configured root.  The actual mount is performed inside the holder
        # mount namespace by a short-lived clone3 helper, so the agent's mount
        # namespace is never modified.  Per-container /proc, /sys, and /dev
        # are built later by the workload bootstrap in the container's own
        # mount namespace (§5.8.7 step 3); the shared holder mount carries
        # only the verified image layers plus the empty mountpoint
        # directories a read-only image may lack.
        class OverlayFilesystemAdapter
          include CapabilityContract

          MS_RDONLY = Mount::MS_RDONLY
          MS_BIND = Mount::MS_BIND
          RUNTIME_LOWER_DIRECTORIES = %w[proc sys dev].freeze

          def initialize(root:, namespace_adapter:, mount: Mount.new)
            @root = File.expand_path(String(root))
            @namespace_adapter = namespace_adapter
            @mount = mount
            @workspaces = {}
            @mutex = Mutex.new
          end

          attr_reader :root

          def native_capabilities
            {
              filesystem: mount_functions_available?,
              overlayfs: overlay_filesystem_available? && existing_parent_directory?
            }.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:filesystem), "mount(2) is unavailable")
            require_capability!(native_capabilities.fetch(:overlayfs), "the configured sandbox root parent is unavailable")
            true
          end

          # `owner` is the Pod's mapped root (uid, gid) when hostUsers=false:
          # the merged root directory takes the upper directory's owner and
          # mode, so an unmapped host-root 0700 root would be untraversable
          # from inside the user namespace.
          def prepare(workspace:, lowerdirs:, read_only: false, owner: nil)
            validate_native_capabilities!
            paths = Array(lowerdirs).map { |path| validate_lowerdir(path) }
            base = File.join(@root, String(workspace.id))
            validate_workspace_component!(workspace.id)
            FileUtils.mkdir_p(base, mode: 0o700)
            # The base directory is traversed only by the agent-side helper;
            # the merged root below it must stay world-searchable like an
            # image root (0755) so a non-root workload can resolve paths.
            File.chmod(0o711, base)
            runtime_lower = prepare_runtime_lower(base)
            # The runtime layer is the lowest layer: image content always
            # wins, and it only contributes the empty proc/sys/dev mountpoints.
            paths.push(runtime_lower)
            [workspace.root, workspace.upper].compact.each do |path|
              FileUtils.mkdir_p(path, mode: 0o755)
              File.chmod(0o755, path)
              File.chown(Integer(owner.fetch(0)), Integer(owner.fetch(1)), path) if owner
            end
            if workspace.work
              FileUtils.mkdir_p(workspace.work, mode: 0o700)
              File.chmod(0o700, workspace.work)
            end
            @mutex.synchronize do
              @workspaces[workspace.identity] = {
                "workspace" => workspace,
                "lowerdirs" => paths.freeze,
                "read_only" => read_only == true,
                "runtime_lower" => runtime_lower,
                "namespace" => nil,
                "mounted" => false,
                "mount_identity" => nil
              }
            end
            workspace
          rescue SystemCallError => error
            raise EffectError, "workspace preparation failed: #{error.message}"
          end

          def activate(workspace = nil, namespace:, **options)
            workspace ||= options.fetch(:workspace)
            metadata = metadata_for(workspace)
            return true if metadata.fetch("mounted") || metadata.fetch("lowerdirs").empty?

            namespace_handle = namespace.respond_to?(:adapter_handle) ? namespace.adapter_handle : namespace
            mount_data = ["lowerdir=#{metadata.fetch("lowerdirs").join(":")}"]
            # A read-only root is still writable while the container is being
            # built: bind mounts (the service account token under /var/run,
            # /etc/hosts, volumes) need their mountpoints created in it, which
            # a lower-only overlay refused with EROFS so the container never
            # started.  runc does the same -- mounts first, then the root is
            # remounted read-only (SecurityAdapter#pivot_into), which is what
            # the workload sees.
            if workspace.upper && workspace.work
              mount_data << "upperdir=#{workspace.upper}"
              mount_data << "workdir=#{workspace.work}"
            end
            mount = @mount
            flags = workspace.upper && workspace.work ? 0 : MS_RDONLY
            data = mount_data.join(",")
            identity = workspace.identity
            root = workspace.root
            @namespace_adapter.with_mount_namespace(namespace_handle) do
              # Slave, not private: the overlay stays inside the holder either
              # way, but private would cut the Pod root off from the host's
              # later binds (NamespaceAdapter#make_mounts_slave).
              mount.make_slave(target: "/", recursive: true, resource_id: identity)
              mount.mount(source: "overlay", target: root, filesystem: "overlay", flags: flags, data: data, resource_id: identity)
              true
            end
            mount_identity = mount_readback(namespace_handle, workspace.root)
            @mutex.synchronize do
              metadata["namespace"] = namespace_handle
              metadata["mounted"] = true
              metadata["mount_identity"] = mount_identity.freeze
            end
            true
          end

          # Re-register an already-mounted workspace after process restart.
          # Mount-table readback is mandatory; no path-only adoption is
          # allowed because a reused directory could belong to another Pod.
          def adopt(workspace:, namespace:, metadata: {})
            namespace_handle = namespace.respond_to?(:adapter_handle) ? namespace.adapter_handle : namespace
            expected_mounted = metadata["mounted"]
            expected_mounted = metadata[:mounted] if expected_mounted.nil? && metadata.respond_to?(:key?) && metadata.key?(:mounted)
            if expected_mounted == false
              raise EffectError, "unexpected mount at #{workspace.root} during workspace adoption" if mount_present?(namespace_handle,
                                                                                                                     workspace.root)

              mount_identity = nil
            else
              mount_identity = mount_readback(namespace_handle, workspace.root)
              expected_identity = metadata["mount_identity"] || metadata[:mount_identity]
              if expected_identity && !same_mount_identity?(mount_identity, expected_identity)
                raise EffectError, "overlay mount identity changed during adoption for #{workspace.identity}"
              end
            end
            @mutex.synchronize do
              @workspaces[workspace.identity] = {
                "workspace" => workspace,
                "lowerdirs" => Array(metadata["lowerdirs"] || metadata[:lowerdirs]).freeze,
                "read_only" => metadata["read_only"] == true || metadata[:read_only] == true,
                "runtime_lower" => metadata["runtime_lower"] || metadata[:runtime_lower],
                "namespace" => namespace_handle,
                "mounted" => expected_mounted != false,
                "mount_identity" => mount_identity&.freeze
              }
            end
            workspace
          end

          def cleanup(workspace = nil, **options)
            workspace ||= options.fetch(:workspace)
            metadata = begin
              metadata_for(workspace)
            rescue EffectError
              return cleanup_orphan_workspace(workspace)
            end
            if metadata.fetch("mounted")
              namespace_handle = metadata.fetch("namespace")
              # Native rollback destroys the namespace before releasing the
              # workspace.  Once its holder is gone, the namespace-scoped
              # mounts have already been released and their mountinfo cannot
              # be read back; retain strict identity checks while the holder
              # is alive and only skip that impossible readback in this case.
              cleanup_mounted_workspace(workspace, metadata, namespace_handle) unless namespace_holder_gone?(namespace_handle)
            end
            FileUtils.rm_rf(File.join(@root, String(workspace.id)))
            @mutex.synchronize { @workspaces.delete(workspace.identity) }
            true
          rescue SystemCallError => error
            raise EffectError, "workspace cleanup failed: #{error.message}"
          end

          # A workspace a dead operation left before this process started (the
          # ledger, not this adapter, knows it).  Its overlay lived in the
          # Pod's mount namespace, which went with its holder; what is left is
          # the directory, removed only when it is exactly this adapter's
          # <root>/<id> and nothing is mounted on it in this namespace.
          def cleanup_orphan_workspace(workspace)
            id = String(workspace.id)
            validate_workspace_component!(id)
            directory = File.join(@root, id)
            # Only <root>/<id> is ever removed; the recorded root must be it,
            # inside it, or "/" (a sandbox that runs on the host root).
            recorded = File.expand_path(String(workspace.root))
            unless recorded == "/" || recorded == directory || recorded.start_with?("#{directory}/")
              raise EffectError, "unknown workspace #{workspace.identity}"
            end

            mounted = File.readlines("/proc/self/mountinfo", chomp: true).any? do |line|
              point = unescape_mountinfo(line.split.fetch(4, ""))
              point == directory || point.start_with?("#{directory}/")
            end
            raise EffectError, "orphan workspace #{workspace.identity} is still mounted" if mounted

            FileUtils.rm_rf(directory)
            true
          end

          def resources
            @mutex.synchronize do
              @workspaces.values.map do |metadata|
                workspace = metadata.fetch("workspace")
                workspace.to_h.merge(
                  "metadata" => {
                    "managed_by" => "rubernetes-native",
                    "mounted" => metadata.fetch("mounted"),
                    "lowerdirs" => metadata.fetch("lowerdirs"),
                    "runtime_lower" => metadata.fetch("runtime_lower"),
                    "mount_identity" => metadata.fetch("mount_identity")
                  }
                )
              end.freeze
            end
          end

          private

          # The overlay is released with a regular umount: a lazily detached
          # mount would stay alive behind any descriptor and defeat the
          # "no child mounts" release precondition of §5.8.4.
          def cleanup_mounted_workspace(workspace, metadata, namespace_handle)
            current_identity = begin
              mount_readback(namespace_handle, workspace.root)
            rescue EffectError
              # The holder can exit between the liveness check in #cleanup and
              # this readback.  Its mount namespace -- and therefore every
              # mount inside it -- is gone with it, which is exactly the state
              # cleanup is trying to reach, so reading /proc/<pid>/mountinfo
              # failing for a holder that has since vanished is success, not a
              # cleanup failure.  Observed as
              # "overlay mount readback failed: Invalid argument @ rb_sysopen -
              # /proc/<pid>/mountinfo" on roughly one in three 1000-cycle
              # ledger probe runs.  Strictness is retained while the holder is
              # alive: the raise is re-raised in that case.
              raise unless namespace_holder_vanished?(namespace_handle)

              return true
            end
            unless same_mount_identity?(current_identity, metadata.fetch("mount_identity"))
              raise EffectError, "overlay mount identity changed before cleanup for #{workspace.identity}"
            end

            mount = @mount
            root = workspace.root
            identity = workspace.identity
            begin
              @namespace_adapter.with_mount_namespace(namespace_handle) do
                mount.unmount(target: root, flags: 0, resource_id: identity)
                true
              end
            rescue EffectError, Linux::Error => error
              # umount2 ENOENT (the target is gone) or EINVAL (nothing is
              # mounted there any more): a concurrent or earlier cleanup got
              # there first -- the state this one is trying to reach.  A
              # runtime restart that hit this died with RecoveryRequired.
              raise unless error.message.match?(/umount2/) && error.message.match?(/No such file or directory|Invalid argument/)
            end
            raise EffectError, "overlay mount remained after cleanup for #{workspace.identity}" if mount_present?(namespace_handle,
                                                                                                                  workspace.root)
          end

          def namespace_holder_gone?(namespace_handle)
            return false unless @namespace_adapter.respond_to?(:destroyed?)

            @namespace_adapter.destroyed?(namespace_handle) == true
          end

          # True when the namespace holder is no longer a live process.  Asked
          # only after a readback failed, to tell "the holder exited under us"
          # (cleanup already achieved) from "the mount table is unreadable for
          # some other reason" (a real failure).
          def namespace_holder_vanished?(namespace_handle)
            return true if namespace_holder_gone?(namespace_handle)

            pid = namespace_handle.respond_to?(:pid) ? namespace_handle.pid : nil
            return true if pid.nil?

            !File.exist?("/proc/#{Integer(pid)}/mountinfo")
          rescue SystemCallError, ArgumentError, TypeError
            true
          end

          def prepare_runtime_lower(base)
            root = File.join(base, "runtime-lower")
            FileUtils.mkdir_p(root, mode: 0o755)
            File.chmod(0o755, root)
            RUNTIME_LOWER_DIRECTORIES.each do |name|
              directory = File.join(root, name)
              FileUtils.mkdir_p(directory, mode: 0o755)
              stat = File.lstat(directory)
              raise EffectError, "runtime rootfs mountpoint is not a directory: #{directory}" unless stat.directory?
            end
            root
          rescue SystemCallError => error
            raise EffectError, "runtime rootfs mountpoint preparation failed: #{error.message}"
          end

          def mount_functions_available?
            @mount.respond_to?(:mount) && @mount.respond_to?(:unmount) && @mount.respond_to?(:make_private)
          end

          def existing_parent_directory?
            path = File.dirname(@root)
            path = File.dirname(path) until File.directory?(path) || path == File.dirname(path)
            File.directory?(path)
          end

          def overlay_filesystem_available?
            File.foreach("/proc/filesystems").any? { |line| line.split.last == "overlay" }
          rescue SystemCallError
            false
          end

          # A successful mount(2) return only proves that the syscall was
          # accepted.  Read the target namespace's mount table and require an
          # OverlayFS entry for the exact target before recording ownership.
          def mount_readback(namespace_handle, target)
            pid = namespace_handle.respond_to?(:pid) ? namespace_handle.pid : nil
            raise EffectError, "overlay mount readback requires a namespace holder pid" unless pid

            line = mountinfo_for(pid, target)
            raise EffectError, "overlay mount was not observed at #{target}" unless line

            separator = line.split(" - ", 2)
            filesystem = separator.fetch(1, "").split.first
            raise EffectError, "mount at #{target} is not OverlayFS" unless filesystem == "overlay"

            fields = separator.fetch(0).split
            {
              "mount_id" => Integer(fields.fetch(0)),
              "parent_id" => Integer(fields.fetch(1)),
              "root" => unescape_mountinfo(fields.fetch(3)),
              "mountpoint" => unescape_mountinfo(fields.fetch(4)),
              "filesystem" => filesystem,
              "super_options" => separator.fetch(1).split(" ", 3).fetch(2, "")
            }.freeze
          rescue KeyError, ArgumentError => error
            raise EffectError, "overlay mount readback was malformed: #{error.message}"
          rescue SystemCallError => error
            raise EffectError, "overlay mount readback failed: #{error.message}"
          end

          def mount_present?(namespace_handle, target)
            pid = namespace_handle.respond_to?(:pid) ? namespace_handle.pid : nil
            pid && !mountinfo_for(pid, target).nil?
          rescue SystemCallError
            false
          end

          def mountinfo_for(pid, target)
            escaped = String(target).gsub("\\", "\\134").gsub(" ", "\\040").gsub("\t", "\\011")
            File.readlines("/proc/#{Integer(pid)}/mountinfo", chomp: true).find do |line|
              line.split.fetch(4, nil) == escaped
            end
          end

          def unescape_mountinfo(value)
            String(value).gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
          end

          def same_mount_identity?(left, right)
            left.is_a?(Hash) && right.is_a?(Hash) &&
              left["mount_id"].to_i == right["mount_id"].to_i &&
              left["mountpoint"].to_s == right["mountpoint"].to_s &&
              left["filesystem"].to_s == right["filesystem"].to_s
          end

          def metadata_for(workspace)
            identity = workspace.respond_to?(:identity) ? workspace.identity : String(workspace)
            @mutex.synchronize { @workspaces.fetch(identity) { raise EffectError, "unknown workspace #{identity}" } }
          end

          def validate_workspace_component!(value)
            component = String(value)
            raise ArgumentError, "workspace id is invalid" unless component.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/)
          end

          def validate_lowerdir(value)
            path = File.expand_path(String(value))
            raise ArgumentError, "overlay lowerdir must be absolute" unless path.start_with?("/")
            raise ArgumentError, "overlay lowerdir contains an unsafe separator" if path.include?(":") || path.include?("\0")
            raise EffectError, "overlay lowerdir is not a directory" unless File.directory?(path) && !File.symlink?(path)

            real = File.realpath(path)
            raise EffectError, "overlay lowerdir changed during validation" unless real == path

            real
          rescue Errno::ENOENT => error
            raise EffectError, "overlay lowerdir is unavailable: #{error.message}"
          end
        end

        # CgroupV2 already contains path and value validation.  This wrapper
        # adds the host-profile capability contract and keeps the production
        # adapter distinguishable from FakeCgroup/RecordingAdapter.
        class CgroupAdapter
          include CapabilityContract

          def initialize(root:, adapter: CgroupV2::FileAdapter.new)
            @root = File.expand_path(String(root))
            @delegate = CgroupV2.new(root: root, adapter: adapter)
          end

          def native_capabilities
            {cgroup_v2: cgroup_mount_available?}.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:cgroup_v2), "cgroup v2 is unavailable")
            true
          end

          def available?
            @delegate.available?
          end

          def create(**arguments) = @delegate.create(**arguments)
          def configure(handle, limits) = @delegate.configure(handle, limits)
          def configure_pod(handle, limits) = @delegate.configure_pod(handle, limits)
          def limits_readback(handle, **) = @delegate.limits_readback(handle, **)
          def pod_limits_readback(handle, **) = @delegate.pod_limits_readback(handle, **)
          def oom_kill_count(handle) = @delegate.oom_kill_count(handle)
          def attach(handle, pid:) = @delegate.attach(handle, pid: pid)
          def open_procs(handle) = @delegate.open_procs(handle)
          def kill(handle) = @delegate.kill(handle)
          def remove(handle, force: false) = @delegate.remove(handle, force: force)
          def stats(handle) = @delegate.stats(handle)
          # cpu.stat / memory.stat / memory.current / pids.current of a
          # container cgroup, or of the Pod cgroup above it (pod: true).
          # Runtime::Native#pod_usage feeds /stats/summary, /metrics/resource
          # and metrics.k8s.io from this; without it every Pod's CPU and
          # memory were simply absent from all three.
          def usage(handle, pod: false) = @delegate.usage(handle, pod: pod)
          def events(handle) = @delegate.events(handle)
          def resources = @delegate.resources
          def lookup(value) = @delegate.lookup(value)

          private

          def cgroup_mount_available?
            return true if @delegate.probe.available?

            mount_root = @root
            mount_root = File.dirname(mount_root) until File.directory?(mount_root) || mount_root == File.dirname(mount_root)
            controllers_path = File.join(mount_root, "cgroup.controllers")
            return false unless File.file?(controllers_path)

            controllers = File.read(controllers_path).split
            %w[cpu memory pids].all? { |name| controllers.include?(name) }
          rescue SystemCallError
            false
          end
        end

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

          # §5.8.7 in the container's private mount namespace:
          # 1. MS_PRIVATE|MS_REC propagation;
          # 2. the verified OverlayFS (already mounted by the holder) is the
          #    new root; 3. /proc, /sys, /dev, devpts, shm, mqueue, cgroup2;
          # 4. maskedPaths/readonlyPaths and read-only rootfs;
          # 5. pivot_root, then a regular umount of the old root tree with a
          #    mount-ID proof that nothing from it remains; 6. cwd and the
          #    executable are re-validated inside the new root by the caller.
          def build_rootfs(rootfs, context:, cwd: nil, mounts: [])
            path = File.expand_path(String(rootfs))
            raise EffectError, "workload rootfs must be absolute" unless path.start_with?("/")
            raise EffectError, "workload rootfs contains NUL" if path.include?("\0")

            # The whole view becomes a slave of the host peer groups (runc's
            # default): host-side mounts keep propagating in, which is what a
            # HostToContainer volume relies on, and nothing made here reaches
            # the host.  The container root itself is then made recursively
            # private (§5.8.7 step 1) so the workload's own mounts never leave.
            @mount.make_slave(target: "/", recursive: true, resource_id: "workload:mount-propagation")
            stat = File.stat(path)
            raise EffectError, "workload rootfs is not a directory" unless stat.directory?

            before = @pivot.read_mountinfo
            overlay = before.select { |entry| entry.mountpoint == path }.max_by(&:index)
            if overlay.nil?
              # A verified rootfs handed over as a plain directory (an
              # already-unpacked image tree) becomes its own mount point in
              # this private mount namespace, which is what pivot_root(2)
              # requires; the bind is recursive so nothing beneath it is
              # hidden from the identity proof below.
              @mount.mount(source: path, target: path, filesystem: nil, flags: MS_BIND | MS_REC,
                           resource_id: "workload:rootfs-bind")
              before = @pivot.read_mountinfo
              overlay = before.select { |entry| entry.mountpoint == path }.max_by(&:index)
              raise EffectError, "workload rootfs bind mount is not visible: #{path}" unless overlay
            elsif overlay.filesystem != "overlay"
              raise EffectError, "workload rootfs mount is not OverlayFS"
            end
            @mount.make_private(target: path, recursive: true, resource_id: "workload:rootfs-propagation")

            privileged = context.privileged?
            mount_proc(path)
            mount_sys(path, privileged: privileged)
            mount_dev(path, privileged: privileged)
            apply_bind_mounts(path, mounts, context)
            apply_masked_paths(path, context) unless privileged
            apply_readonly_paths(path, context) unless privileged
            pivot_into(path, overlay: overlay, before: before, read_only: context.read_only_root_filesystem == true)
            target_cwd = cwd.nil? || String(cwd).empty? ? "/" : String(cwd)
            raise EffectError, "workload cwd must be absolute" unless target_cwd.start_with?("/")
            raise EffectError, "workload cwd contains NUL" if target_cwd.include?("\0")

            Dir.chdir(target_cwd)
            @rootfs_report
          rescue SystemCallError => error
            raise EffectError, "workload rootfs construction failed: #{error.message}"
          end

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

          DEFAULT_EXEC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

          # Resolve a bare program name on PATH.  This runs after pivot_root, so
          # the lookup happens in the container's own filesystem -- the only
          # place it can be done correctly, and the reason the host-side layers
          # pass the name through untouched.
          def resolve_executable(path, search_path = nil)
            value = String(path)
            return value if value.include?("/")

            search = (search_path.to_s.empty? ? DEFAULT_EXEC_PATH : search_path.to_s).split(":")
            resolved = search.filter_map do |directory|
              next if directory.empty?

              candidate = File.join(directory, value)
              candidate if File.file?(candidate) && File.executable?(candidate)
            end.first
            raise EffectError, "exec: #{value.inspect}: executable file not found in $PATH" unless resolved

            resolved
          end

          def validate_executable!(path)
            value = String(path)
            unless value.start_with?("/") && File.file?(value) && File.executable?(value)
              raise EffectError, "workload executable is unavailable: #{value.inspect}"
            end

            true
          rescue SystemCallError => error
            raise EffectError, "workload executable validation failed: #{error.message}"
          end

          # Open the executable inside the new root and hash the bytes that
          # will be executed.  The descriptor, not the pathname, is what
          # execveat(2) later runs.
          # The descriptor directory is opened right after the rootfs exists
          # and before Landlock restricts reads outside the allowed roots; the
          # close step later enumerates it through this descriptor.
          def prepare_fd_directory
            @fd_directory = Dir.open("/proc/self/fd")
            true
          rescue SystemCallError => error
            raise EffectError, "cannot open the descriptor directory: #{error.message}"
          end

          def open_executable(path, search_path = nil)
            path = resolve_executable(path, search_path)
            validate_executable!(path)
            io = File.open(path, File::RDONLY)
            digest = Digest::SHA256.new
            script = nil
            while (chunk = io.read(1024 * 1024))
              script = chunk.start_with?("#!") if script.nil?
              digest.update(chunk)
            end
            io.rewind
            # A "#!" script cannot run through the descriptor: execveat(2) with
            # AT_EMPTY_PATH starts the interpreter on /dev/fd/N, which is ENOENT
            # once the close-on-exec descriptor is gone and, kept open, makes $0
            # "/dev/fd/N" instead of the script path runc would pass.  Scripts
            # are therefore executed by their resolved pathname inside the new
            # root (see WorkloadBootstrap#exec_workload); ELF binaries keep the
            # verified-descriptor exec.  Every image entrypoint that is a shell
            # script (Gitea's init containers, "command: [/script.sh]") failed
            # with ENOENT before this.
            [io, digest.hexdigest, {path: path, script: script == true}]
          rescue SystemCallError => error
            raise EffectError, "workload executable could not be opened: #{error.message}"
          end

          private

          def mount_proc(root)
            target = ensure_directory(File.join(root, "proc"))
            @mount.mount(source: "proc", target: target, filesystem: "proc",
                         flags: MS_NOSUID | MS_NODEV | MS_NOEXEC, resource_id: "workload:proc")
          end

          def mount_sys(root, privileged:)
            target = ensure_directory(File.join(root, "sys"))
            flags = MS_NOSUID | MS_NODEV | MS_NOEXEC
            flags |= MS_RDONLY unless privileged
            @mount.mount(source: "sysfs", target: target, filesystem: "sysfs", flags: flags, resource_id: "workload:sys")
            cgroup_target = File.join(target, "fs", "cgroup")
            return unless File.directory?(cgroup_target)

            # The cgroup namespace was unshared after cgroup placement, so
            # this mount is rooted at the container's own cgroup.
            @mount.mount(source: "cgroup2", target: cgroup_target, filesystem: "cgroup2",
                         flags: MS_NOSUID | MS_NODEV | MS_NOEXEC | (privileged ? 0 : MS_RDONLY),
                         resource_id: "workload:cgroup2")
          end

          # /dev is a nodev tmpfs: a node the workload mknods there (the
          # device cgroup lets every container mknod) cannot be opened.  The
          # device nodes it does get are bind mounts, and a bind carries its
          # source mount's flags, so /dev/null and friends still open.
          def mount_dev(root, privileged: false)
            target = ensure_directory(File.join(root, "dev"))
            @mount.mount(source: "tmpfs", target: target, filesystem: "tmpfs",
                         flags: MS_NOSUID | MS_NODEV | MS_STRICTATIME, data: "mode=755,size=65536k", resource_id: "workload:dev")
            ROOTFS_DEVICES.each do |name|
              source = File.join("/dev", name)
              raise EffectError, "required host device is unavailable: #{source}" unless File.stat(source).chardev?

              device = File.join(target, name)
              File.open(device, File::WRONLY | File::CREAT | File::EXCL, 0o666) {}
              @mount.mount(source: source, target: device, filesystem: nil, flags: MS_BIND, resource_id: "workload:dev:#{name}")
            end
            mount_host_devices(target, "/dev") if privileged
            DEVICE_SYMLINKS.each { |name, link_target| File.symlink(link_target, File.join(target, name)) }
            pts = ensure_directory(File.join(target, "pts"))
            @mount.mount(source: "devpts", target: pts, filesystem: "devpts", flags: MS_NOSUID | MS_NOEXEC,
                         data: "newinstance,ptmxmode=0666,mode=0620,gid=5", resource_id: "workload:devpts")
            shm = ensure_directory(File.join(target, "shm"))
            @mount.mount(source: "shm", target: shm, filesystem: "tmpfs", flags: MS_NOSUID | MS_NODEV | MS_NOEXEC,
                         data: "mode=1777,size=65536k", resource_id: "workload:shm")
            mqueue = ensure_directory(File.join(target, "mqueue"))
            @mount.mount(source: "mqueue", target: mqueue, filesystem: "mqueue", flags: MS_NOSUID | MS_NODEV | MS_NOEXEC,
                         resource_id: "workload:mqueue")
          end

          # Directories containerd's HostDevices walk leaves out.
          HOST_DEVICE_SKIPPED_DIRECTORIES = %w[pts shm fd mqueue .lxc .lxd-mounts .udev].freeze

          # A privileged container gets every host device node (containerd
          # WithPrivileged -> WithAllDevices, the device cgroup allows all).
          # Nodes already provided (the standard set) and the names that are
          # symlinks in a container /dev stay as they are; sockets, fifos and
          # dangling symlinks are not devices.  Bind mounts rather than
          # mknod because the tmpfs is nodev.
          def mount_host_devices(target, source)
            Dir.children(source).sort.each do |name|
              host = File.join(source, name)
              if File.directory?(host) && !File.symlink?(host)
                next if HOST_DEVICE_SKIPPED_DIRECTORIES.include?(name)

                mount_host_devices(ensure_directory(File.join(target, name)), host)
                next
              end
              next if name == "console" || DEVICE_SYMLINKS.key?(name)

              stat = begin
                File.stat(host)
              rescue Errno::ENOENT, Errno::ELOOP, Errno::EACCES
                next
              end
              next unless stat.chardev? || stat.blockdev?

              device = File.join(target, name)
              next if File.exist?(device) || File.symlink?(device)

              File.open(device, File::WRONLY | File::CREAT | File::EXCL, stat.mode & 0o777) {}
              @mount.mount(source: host, target: device, filesystem: nil, flags: MS_BIND,
                           resource_id: "workload:dev:#{host.delete_prefix("/dev/")}")
            end
          end

          # Volume, projection and per-container files (termination log,
          # /etc/hosts, /etc/resolv.conf) enter the rootfs as bind mounts of
          # host paths.  The destination is resolved the way securejoin does:
          # symlinks inside the image are followed relative to the new root
          # and can never point outside it.
          def apply_bind_mounts(root, mounts, context)
            Array(mounts).each_with_index do |mount, index|
              spec = mount.respond_to?(:to_h) ? mount.to_h.transform_keys(&:to_s) : {}
              source = String(spec.fetch("source") { spec.fetch("host_path") })
              destination = String(spec.fetch("destination") { spec.fetch("container_path") })
              raise EffectError, "bind mount #{index} source must be absolute" unless source.start_with?("/")
              raise EffectError, "bind mount #{index} destination must be absolute" unless destination.start_with?("/")
              raise EffectError, "bind mount #{index} path contains NUL" if source.include?("\0") || destination.include?("\0")

              source_stat = File.stat(source)
              target = secure_join(root, destination)
              if source_stat.directory?
                ensure_directory_tree(root, target)
              else
                ensure_directory_tree(root, File.dirname(target))
                File.open(target, File::WRONLY | File::CREAT, 0o644) {} unless File.exist?(target)
                raise EffectError, "bind mount #{index} destination is a directory but the source is a file" if File.directory?(target)
              end
              readonly = spec["readonly"] == true || spec["read_only"] == true
              propagation = spec["propagation"] || spec["mount_propagation"] || "None"
              flag = MOUNT_PROPAGATION.fetch(String(propagation)) do
                raise EffectError, "bind mount #{index} has unknown propagation #{propagation.inspect}"
              end
              if flag == MS_SHARED && !context.privileged?
                raise EffectError, "bind mount #{index}: Bidirectional mount propagation requires a privileged container"
              end

              @mount.mount(source: source, target: target, filesystem: nil, flags: MS_BIND | MS_REC,
                           resource_id: "workload:bind:#{destination}")
              if readonly
                @mount.mount(source: nil, target: target, filesystem: nil,
                             flags: MS_BIND | MS_REMOUNT | MS_RDONLY | (source_stat.directory? ? MS_REC : 0),
                             resource_id: "workload:bind-ro:#{destination}")
                # A remount is never recursive (MS_REC is ignored there): the
                # submounts of a read-only volume stay writable unless the
                # mount asks for recursiveReadOnly, which mount_setattr(2)
                # with AT_RECURSIVE applies to the whole tree.
                recursive_readonly(target, spec["recursive_readonly"], destination)
              end
              @mount.set_propagation(target: target, propagation: flag, recursive: true,
                                     resource_id: "workload:bind-propagation:#{destination}")
            end
            true
          rescue SystemCallError => error
            raise EffectError, "bind mount construction failed: #{error.message}"
          end

          # v1.VolumeMount.recursiveReadOnly: Enabled must succeed, IfPossible
          # falls back to the plain read-only bind where the kernel cannot.
          def recursive_readonly(target, mode, destination)
            return if mode.nil? || mode.to_s == "Disabled"

            @mount.mount_setattr(dirfd: Mount::AT_FDCWD, path: target, flags: Mount::AT_RECURSIVE,
                                 attr_set: Mount::MOUNT_ATTR_RDONLY, resource_id: "workload:bind-rro:#{destination}")
          rescue Linux::Error => error
            if mode.to_s == "Enabled"
              raise EffectError,
                    "volume at #{destination} requested recursive read-only mode, but it is not supported: #{error.message}"
            end
          end

          # Resolve `destination` beneath `root`, following symlinks that the
          # image may contain (e.g. /tmp -> /var/tmp) relative to the root.
          # The result is lexically and physically inside the root; an escape
          # is refused rather than clamped.
          def secure_join(root, destination)
            components = destination.split("/").reject(&:empty?)
            resolved = []
            follows = 0
            until components.empty?
              component = components.shift
              case component
              when "." then next
              when ".."
                resolved.pop
                next
              end
              candidate = File.join(root, *resolved, component)
              if File.symlink?(candidate)
                follows += 1
                raise EffectError, "too many symlinks resolving #{destination}" if follows > MAX_SYMLINK_FOLLOWS

                link = File.readlink(candidate)
                link_components = link.split("/").reject(&:empty?)
                resolved = [] if link.start_with?("/")
                components = link_components + components
                next
              end
              resolved << component
            end
            path = File.join(root, *resolved)
            unless path == root || path.start_with?("#{root}/")
              raise EffectError,
                    "bind mount destination escapes the rootfs: #{destination}"
            end

            path
          end

          def ensure_directory_tree(root, path)
            relative = path.delete_prefix(root).split("/").reject(&:empty?)
            current = root
            relative.each do |component|
              current = File.join(current, component)
              next if File.directory?(current) && !File.symlink?(current)
              raise EffectError, "rootfs mountpoint component is a symlink: #{current}" if File.symlink?(current)

              Dir.mkdir(current, 0o755)
            end
            path
          end

          def apply_masked_paths(root, context)
            return if context.proc_mount.to_s == "Unmasked"

            DEFAULT_MASKED_PATHS.each do |relative|
              target = File.join(root, relative)
              next unless File.exist?(target)

              if File.directory?(target)
                @mount.mount(source: "tmpfs", target: target, filesystem: "tmpfs", flags: MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                             data: "mode=755", resource_id: "workload:mask:#{relative}")
              else
                @mount.mount(source: "/dev/null", target: target, filesystem: nil, flags: MS_BIND, resource_id: "workload:mask:#{relative}")
              end
            end
          end

          def apply_readonly_paths(root, context)
            return if context.proc_mount.to_s == "Unmasked"

            DEFAULT_READONLY_PATHS.each do |relative|
              target = File.join(root, relative)
              next unless File.exist?(target)

              @mount.mount(source: target, target: target, filesystem: nil, flags: MS_BIND | MS_REC, resource_id: "workload:ro:#{relative}")
              # A bind remount must repeat the locked flags of the underlying
              # mount (nosuid/nodev/noexec on proc) or the kernel rejects it.
              @mount.mount(source: nil, target: target, filesystem: nil,
                           flags: MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                           resource_id: "workload:ro-remount:#{relative}")
            end
          end

          def pivot_into(root, overlay:, before:, read_only:)
            Dir.chdir(root)
            put_old = File.join(root, PIVOT_OLD)
            Dir.mkdir(put_old, 0o700)
            # Everything not beneath the new root belongs to the old root
            # tree and must be gone after the pivot.
            old_ids = before.reject { |entry| entry.mountpoint == root || entry.mountpoint.start_with?("#{root}/") }.map(&:id)
            @pivot.pivot_root(new_root: ".", put_old: PIVOT_OLD, resource_id: "workload:pivot_root")
            Dir.chdir("/")
            @pivot.detach_tree("/#{PIVOT_OLD}", old_mount_ids: old_ids, resource_id: "workload:old-root")
            Dir.rmdir("/#{PIVOT_OLD}")
            if read_only
              @mount.mount(source: nil, target: "/", filesystem: nil, flags: MS_BIND | MS_REMOUNT | MS_RDONLY,
                           resource_id: "workload:rootfs-readonly")
            end
            after_raw = File.binread("/proc/self/mountinfo")
            after = PivotRoot.parse_mountinfo(after_raw)
            root_entry = after.select { |entry| entry.mountpoint == "/" }.max_by(&:index)
            unless root_entry && root_entry.filesystem == overlay.filesystem
              raise EffectError,
                    "pivot_root did not install the workload root"
            end
            raise EffectError, "root mount identity changed across pivot_root" unless root_entry.id == overlay.id

            # detach_tree proved the old root unreachable (nothing left under
            # the put-old directory, no descriptor on a detached mount).
            # Intersecting ids with the pre-pivot list is not a proof: ids are
            # recycled while the rootfs is built, and a new-root mount holding
            # a recycled id failed ~10 container starts a round.
            remaining = after.select { |entry| entry.mountpoint == "/#{PIVOT_OLD}" || entry.mountpoint.start_with?("/#{PIVOT_OLD}/") }
            raise EffectError, "old root mounts remain reachable: #{remaining.map(&:mountpoint).join(", ")}" unless remaining.empty?

            leaked = after.reject { |entry| entry.mountpoint.start_with?("/") }
            raise EffectError, "mount table contains entries outside the new root" unless leaked.empty?

            @rootfs_report = Rootfs.new(
              root_mount_id: root_entry.id, mount_count: after.length, old_root_mount_ids: old_ids.sort,
              old_root_unreachable: true, mountinfo_sha256: Digest::SHA256.hexdigest(after_raw),
              rootfs_read_only: read_only
            )
          end

          def ensure_directory(path)
            Dir.mkdir(path, 0o755) unless File.directory?(path)
            raise EffectError, "rootfs mountpoint is a symlink: #{path}" if File.symlink?(path)

            path
          end

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

          def apply_prctl(option, argument, resource_id:)
            result = PRCTL.call(option, argument, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(#{option})", resource_id: resource_id) if result == -1

            true
          end

          def prctl_probe(option)
            result = PRCTL.call(option, 0, 0, 0, 0)
            result != -1
          rescue StandardError
            false
          end
        end

        # Gate-aware clone3 workload adapter. A small Ruby management wrapper
        # owns pipes and wait/reap duties, but the production workload itself
        # is always created with clone3(CLONE_PIDFD) and runs the trusted
        # bootstrap in-process until execveat(2).  Fork is never reported as
        # workload creation capability.
        class ProcessGateAdapter
          include CapabilityContract
          include ProcessIdentity

          # Values from include/uapi/linux/prctl.h.
          PR_SET_PDEATHSIG = 1
          PR_SET_CHILD_SUBREAPER = 36
          SIGKILL = Signal.list.fetch("KILL")
          DUP2 = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["dup2"], [Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_INT
          )
          GETPPID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["getppid"], [], Fiddle::TYPE_INT
          )
          IMMEDIATE_EXIT = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["_exit"], [Fiddle::TYPE_INT], Fiddle::TYPE_VOID
          )
          PRCTL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["prctl"], [Fiddle::TYPE_LONG] * 5, Fiddle::TYPE_INT
          )
          # Namespaces a workload joins from the holder, in join order.  The
          # user namespace is joined last by the bootstrap after the rootfs is
          # built (see SecurityAdapter#join_user_namespace).
          HOLDER_JOIN_ORDER = %i[mount network uts ipc].freeze
          CONTAINER_JOIN_ORDER = %i[mount network uts ipc cgroup].freeze

          SETSID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["setsid"], [], Fiddle::TYPE_INT
          )
          IOCTL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["ioctl"], [Fiddle::TYPE_INT, Fiddle::TYPE_ULONG, Fiddle::TYPE_INT], Fiddle::TYPE_INT
          )
          TIOCSCTTY = 0x540E
          # Values from include/uapi/linux/ptrace.h.
          PTRACE_TRACEME = 0
          PTRACE_CONT = 7
          PTRACE_DETACH = 17
          SIGTRAP = Signal.list.fetch("TRAP")
          PTRACE = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["ptrace"], [Fiddle::TYPE_LONG, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
            Fiddle::TYPE_LONG
          )

          # The write side of a pty session.  Closing a terminal's input has
          # no pipe-like EOF: the equivalent the workload understands is an
          # end-of-transmission character, which is what a client's stdin
          # close turns into (the master itself stays open for reading).
          class PtyInput
            EOT = "\x04".b

            def initialize(master)
              @master = master
              @closed = false
            end

            def write(value)
              raise IOError, "pty input is closed" if @closed

              @master.write(value)
              @master.flush
              value.to_s.bytesize
            end

            def write_nonblock(value, exception: true)
              @master.write_nonblock(value, exception: exception)
            end

            def close_write
              return self if @closed

              @closed = true
              begin
                @master.write(EOT)
                @master.flush
              rescue IOError, SystemCallError
                nil
              end
              self
            end

            alias close close_write

            def closed?
              @closed
            end

            def to_io
              @master
            end
          end

          class Gate
            def initialize(writer:, status_reader:, identity_reader:, hook_reply: nil, hook_handler: nil)
              @writer = writer
              @status_reader = status_reader
              @identity_reader = identity_reader
              @hook_reply = hook_reply
              @hook_handler = hook_handler
              @released = false
              @workload_pid = nil
              @workload_start_time = nil
              @workload_executable_digest = nil
              @workload_security = nil
            end

            attr_reader :workload_pid, :workload_start_time, :workload_executable_digest, :workload_security

            def release
              raise EffectError, "process gate was already released" if @released

              @released = true
              @writer.write("1")
              @writer.close
              marker = @status_reader.read(1)
              # "H": the bootstrap entered the container namespaces and waits
              # for the runtime-namespace hooks (prestart, createRuntime).
              while marker == "H" && @hook_reply
                answer_hook_request
                marker = @status_reader.read(1)
              end
              if marker == "R"
                # The trusted bootstrap reads the outermost NSpid and its
                # start time before any namespace transition and sends both
                # only after all security steps succeed. The clone identity
                # pipe is an independent proof from the clone3 parent; require
                # the two cross-boundary identities to agree before accepting
                # either.
                host_identity = @status_reader.read(16).to_s
                executable_identity = @status_reader.read(64).to_s
                length_field = @status_reader.read(4).to_s
                clone_identity = @identity_reader.read(8).to_s
                unless host_identity.bytesize == 16 && clone_identity.bytesize == 8 && length_field.bytesize == 4 &&
                       executable_identity.match?(/\A[0-9a-f]{64}\z/)
                  raise EffectError, "workload readiness omitted its process identity"
                end

                metadata_length = length_field.unpack1("L<")
                raise EffectError, "workload readiness metadata is too large" if metadata_length > 1024 * 1024

                metadata_raw = @status_reader.read(metadata_length).to_s
                raise EffectError, "workload readiness metadata was truncated" unless metadata_raw.bytesize == metadata_length

                exec_failure = @status_reader.read.to_s
                raise EffectError, "workload exec failed after security readiness: #{exec_failure}" unless exec_failure.empty?

                host_pid, host_start_time = host_identity.unpack("Q<2")
                clone_pid = clone_identity.unpack1("Q<")
                unless host_pid.positive? && host_start_time.positive? && clone_pid == host_pid
                  raise EffectError, "workload readiness identities do not agree"
                end

                metadata = JSON.parse(metadata_raw)
                raise EffectError, "workload readiness metadata must be an object" unless metadata.is_a?(Hash)

                # A short-lived command can exit between the bootstrap write
                # and this read. When it is still live, verify the procfs
                # start time; when it has already exited, retain the
                # bootstrap's cross-boundary identity instead of scanning
                # /proc and risking PID reuse.
                verify_live_or_adopt_identity(host_pid, host_start_time)
                @workload_pid = host_pid
                @workload_start_time = host_start_time
                @workload_executable_digest = "sha256:#{executable_identity}"
                @workload_security = metadata.freeze
                return true
              end

              detail = @status_reader.read.to_s
              detail = "#{marker}#{detail}" unless marker == "E"
              raise EffectError, "workload security setup failed before exec#{": #{detail}" unless detail.empty?}"
            rescue JSON::ParserError => error
              raise EffectError, "workload readiness metadata is invalid: #{error.message}"
            ensure
              @writer.close unless @writer.closed?
              @status_reader.close unless @status_reader.closed?
              @identity_reader.close unless @identity_reader.closed?
              @hook_reply.close if @hook_reply && !@hook_reply.closed?
            end

            private

            def answer_hook_request
              length = @status_reader.read(4).to_s
              raise EffectError, "workload hook request was truncated" unless length.bytesize == 4

              size = length.unpack1("L<")
              raise EffectError, "workload hook request is too large" if size > 65_536

              request = JSON.parse(@status_reader.read(size).to_s)
              begin
                @hook_handler&.call(Integer(request.fetch("pid")))
                @hook_reply.write("0")
              rescue StandardError => error
                message = error.message.to_s.b
                @hook_reply.write("E" + [message.bytesize].pack("L<") + message)
              end
              @hook_reply.flush
            end

            def verify_live_or_adopt_identity(pid, expected_start_time)
              stat_path = "/proc/#{Integer(pid)}/stat"
              return true unless File.file?(stat_path)

              begin
                observed = ProcessIdentity.process_start_time(pid)
              rescue Linux::Error
                # The process exited after the existence check. The
                # bootstrap/clone identity pair is still authoritative.
                return true unless File.file?(stat_path)

                raise
              end
              raise EffectError, "workload process identity changed" unless observed == Integer(expected_start_time)

              true
            end
          end

          def initialize(namespace_adapter:, security: nil, clone3: Clone3.new, setns: Setns.new)
            @namespace_adapter = namespace_adapter
            @security = security
            @clone3 = clone3
            @setns = setns
            @pidfd = Pidfd.new
          end

          attr_writer :security

          def security_applied_in_child?
            true
          end

          # OCI hooks run at their stage: the in-container ones in the
          # bootstrap, the runtime-namespace ones through the gate.
          def runs_container_hooks? = true

          def native_capabilities
            {
              process_gate: @clone3.respond_to?(:call) && File.directory?("/proc/self/fd"),
              clone3: @clone3.respond_to?(:call),
              clone_pidfd: true,
              pdeathsig: true,
              subreaper: true,
              child_exec: true
            }.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:process_gate), "clone3/process gate is unavailable")
            require_capability!(native_capabilities.fetch(:clone3), "clone3 process creation is unavailable")
            require_capability!(native_capabilities.fetch(:clone_pidfd), "CLONE_PIDFD process ownership is unavailable")
            require_capability!(native_capabilities.fetch(:pdeathsig), "parent-death signal is unavailable")
            require_capability!(native_capabilities.fetch(:subreaper), "child subreaper is unavailable")
            true
          end

          # `join_process` (exec/attach) names a live container process whose
          # namespaces the new process enters instead of building a rootfs.
          # Workload children can be moved into their cgroup at their execve
          # (+cgroup_procs+, see NamespaceConnector#spawn_stream).
          def join_cgroup_at_exec? = true

          def spawn(command:, env: {}, cwd: nil, rootfs: nil, gate: true, security_plan: nil,
                    namespace: nil, cgroup: nil, tty: false, join_process: nil, mounts: [], stdin: false,
                    cgroup_procs: nil, container_hooks: nil, **_options)
            validate_native_capabilities!
            bind_mounts = Array(mounts).map { |mount| mount.respond_to?(:to_h) ? mount.to_h.transform_keys(&:to_s) : {} }
            raise EffectError, "bind mounts require a rootfs" if !bind_mounts.empty? && rootfs.nil?
            raise EffectError, "production process adapter requires a security plan" unless security_plan
            raise EffectError, "production process adapter has no security applier" unless @security

            bootstrap_security = bootstrap_security_adapter
            raise EffectError, "production process adapter has no rootfs/security transition helper" unless bootstrap_security

            gate_reader, gate_writer = IO.pipe
            status_reader, status_writer = IO.pipe
            identity_reader, identity_writer = IO.pipe
            hook_reply_reader, hook_reply_writer = container_hooks ? IO.pipe : [nil, nil]
            # Without `stdin: true` a container's stdin is /dev/null, as the
            # CRI gives it.  A pipe nobody ever writes to left `sh` -- busybox's
            # default command, the init container of "[sig-node] Pods Extended
            # pod generation should start at 1" -- blocked in read(2) for ever
            # instead of exiting at EOF, and the Pod never left Pending.
            if stdin || tty
              stdin_reader, stdin_writer = IO.pipe
            else
              stdin_reader = File.open(File::NULL, File::RDONLY)
              stdin_writer = nil
            end
            stdout_reader, stdout_writer = IO.pipe
            stderr_reader, stderr_writer = IO.pipe
            # A tty session (kubectl exec -it) gets a real pseudo-terminal:
            # the workload's stdio is the pty slave and its controlling
            # terminal, the caller reads and writes the master.  Pipes with a
            # tty flag would leave isatty(3) false and job control off.
            pty_master = nil
            pty_slave = nil
            if tty
              pty_master, pty_slave = PTY.open
              pty_master.sync = true
              pty_slave.nonblock = false
            end
            # Ruby opens pipes O_NONBLOCK for its own scheduler; the flag lives
            # on the open file description the child inherits, so a workload
            # would see EAGAIN on a full stdout or an empty stdin.  The
            # child's ends are made blocking; the agent's ends keep the flag.
            [stdin_reader, stdout_writer, stderr_writer].each { |io| io.nonblock = false }
            namespace_handle = namespace&.adapter_handle
            join = normalize_join(join_process)
            plan_namespaces = namespace_handle ? Array(namespace_handle.namespaces) : []
            # A rootfs is only ever mounted in a private copy of a mount
            # namespace: the holder's when the sandbox has one, otherwise a
            # fresh unshare(CLONE_NEWNS) by the single-threaded child.  The
            # agent's own mount table is never modified either way.
            private_mount_namespace = join.nil? && (!rootfs.nil? || (namespace_handle && plan_namespaces.include?(:mount)))
            shared_pid = namespace_handle && namespace_handle.plan.respond_to?(:shared) && Array(namespace_handle.plan.shared).include?(:pid)
            workload_clone_flags = Clone3::CLONE_PIDFD
            # A private PID namespace per container is the §5.8.6 default;
            # shareProcessNamespace and exec/attach join an existing one via
            # setns(2) in the wrapper before clone3 instead.
            workload_clone_flags |= Clone3::CLONE_NEWPID if plan_namespaces.include?(:pid) && !shared_pid && join.nil?
            agent_pid = Process.pid
            agent_start_time = process_start_time(agent_pid)
            command_words = Array(command).map { |item| String(item) }
            environment = env.to_h.each_with_object({}) { |(key, value), result| result[String(key)] = value.nil? ? nil : String(value) }
            # The wrapper and the workload child it clones are copies of the
            # agent and only wait or exec, but they are charged to the
            # container's memory cgroup once attached.  A Ruby GC marks every
            # heap page, and in a fork each marked page is a copy-on-write
            # copy: a GC in an exec helper charged ~400 MB to a 20Mi
            # container and memory.oom.group killed the container ("Pod
            # InPlace Resize" OOMKilled c1/c3).  GC is disabled in the child
            # before anything else, and spawn returns -- so the caller can
            # attach the cgroup -- only after that has finished.
            child_pid = fork_without_gc do
              Process.setsid
              gate_writer.close
              status_reader.close
              identity_reader.close
              hook_reply_writer&.close
              stdin_writer&.close
              stdout_reader.close
              stderr_reader.close
              # This wrapper lives as long as its workload, and fork gave it a
              # copy of EVERY descriptor the agent had open: the pipes of every
              # other container's stdio and of every exec in flight.  A pipe
              # whose write end sits in a long-lived wrapper never reaches EOF
              # for its reader, so "kubectl exec ss-2 -- mv ..." -- whose
              # pipes were created 5 s before ss-2's own wrapper forked --
              # hung for 24 h, until the suite timed out.  Close what is not
              # ours before waiting on the gate.
              close_inherited_descriptors(keep: [gate_reader, status_writer, identity_writer, stdin_reader,
                                                 stdout_writer, stderr_writer, pty_master, pty_slave, cgroup_procs,
                                                 hook_reply_reader].compact)
              namespace_descriptors = {}
              begin
                set_parent_death_signal(expected_parent_pid: agent_pid, expected_parent_start_time: agent_start_time)
                set_child_subreaper
                gate_reader.read(1) if gate
                gate_reader.close
                # Namespace descriptors are opened and verified in the wrapper
                # so the raw clone3 child only performs setns(2) on descriptors
                # whose identity has already been checked.
                if join
                  namespace_descriptors = open_process_namespaces(join)
                elsif namespace_handle
                  wanted = HOLDER_JOIN_ORDER + [:user] + (shared_pid ? [:pid] : [])
                  namespace_descriptors = @namespace_adapter.open_namespace_descriptors(namespace_handle, only: wanted)
                end
                # PID namespace membership is inherited only by children, so
                # the wrapper joins it (when sharing) before clone3.
                if namespace_descriptors[:pid]
                  @setns.setns(fd: namespace_descriptors[:pid], name: :pid, resource_id: "process:workload:pid")
                  namespace_descriptors[:pid].close
                  namespace_descriptors.delete(:pid)
                end
                wrapper_pid = kernel_process_id
                child_security_plan = security_plan.with(
                  context: security_plan.context.with(
                    fd_allowlist: security_plan.context.fd_allowlist +
                      [status_writer.fileno, stdin_reader.fileno, stdout_writer.fileno, stderr_writer.fileno] +
                      (pty_slave ? [pty_slave.fileno] : [])
                  )
                )
                status_writer.close_on_exec = false
                bootstrap = WorkloadBootstrap.new(
                  security: bootstrap_security, setns: @setns,
                  command: command_words, env: environment, cwd: cwd, rootfs: rootfs && String(rootfs),
                  plan: child_security_plan, namespace_descriptors: namespace_descriptors,
                  build_rootfs: !rootfs.nil? && join.nil?, unshare_mount: private_mount_namespace,
                  unshare_cgroup: join.nil? && plan_namespaces.include?(:cgroup),
                  mounts: bind_mounts,
                  status_writer: status_writer,
                  stdio: pty_slave ? [pty_slave.fileno] * 3 : [stdin_reader.fileno, stdout_writer.fileno, stderr_writer.fileno],
                  controlling_tty: !pty_slave.nil?,
                  trace_exec: !cgroup_procs.nil?,
                  hooks: container_hooks ? container_hooks["hooks"] : nil,
                  hook_state: container_hooks ? container_hooks["state"] : nil,
                  hook_reply: hook_reply_reader, clone3: @clone3
                )
                workload_clone = @clone3.call(
                  args: Clone3::Args.new(flags: workload_clone_flags),
                  resource_id: "process:workload"
                )
                if workload_clone.child?
                  bootstrap.run(expected_parent_pid: wrapper_pid)
                  IMMEDIATE_EXIT.call(127)
                end
                namespace_descriptors.each_value { |io| io.close unless io.closed? }
                hook_reply_reader&.close
                workload_pid = workload_clone.pid
                identity_writer.write([workload_pid].pack("Q<"))
                identity_writer.flush
                identity_writer.close
                # Only the workload child may hold the readiness writer.  If
                # the wrapper retains a copy, Gate#release blocks until the
                # workload exits instead of returning immediately after exec.
                status_writer.close
                stdin_reader.close
                stdout_writer.close
                reaped = cgroup_procs ? join_cgroup_at_exec_stop(workload_pid, cgroup_procs) : nil
                if reaped
                  IO.for_fd(workload_clone.pidfd).close if workload_clone.pidfd
                  exit_code = reaped.exitstatus || (128 + reaped.termsig.to_i)
                else
                  status = @pidfd.wait(
                    pidfd: workload_clone.pidfd,
                    timeout: nil,
                    resource_id: "process:workload"
                  )
                  IO.for_fd(workload_clone.pidfd).close if workload_clone.pidfd
                  # The workload's exit code is the wrapper's exit code; nothing
                  # is written to the container's stderr (a kubelet never adds
                  # its own lines to a container's log or an exec's output).
                  exit_code = status&.exit_status || (128 + status&.term_signal.to_i)
                end
                stderr_writer.close
                exit!(exit_code)
              rescue StandardError => error
                begin
                  status_writer.write("E#{error.class}: #{error.message}")
                  status_writer.flush
                rescue IOError
                  nil
                end
                begin
                  stderr_writer.write("rubernetes process wrapper failed: #{error.class}: #{error.message}\n")
                  stderr_writer.flush
                rescue IOError
                  nil
                end
                exit!(127)
              ensure
                gate_reader.close unless gate_reader.closed?
                status_writer.close unless status_writer.closed?
                stdin_reader.close unless stdin_reader.closed?
                stdout_writer.close unless stdout_writer.closed?
                stderr_writer.close unless stderr_writer.closed?
                identity_writer.close unless identity_writer.closed?
              end
            end
            gate_reader.close
            status_writer.close
            identity_writer.close
            stdin_reader.close
            stdout_writer.close
            stderr_writer.close
            hook_reply_reader&.close
            result = {pid: child_pid, pidfd: nil,
                      workload_creation_method: "clone3", workload_clone_flags: workload_clone_flags,
                      gate: Gate.new(writer: gate_writer, status_reader: status_reader, identity_reader: identity_reader,
                                     hook_reply: hook_reply_writer, hook_handler: container_hooks && container_hooks["runtime"]),
                      stdin: stdin_writer, stdout: stdout_reader,
                      stderr: stderr_reader, cgroup: cgroup}
            if pty_master
              pty_slave.close
              stdin_writer&.close
              stdout_reader.close
              result = result.merge(stdin: PtyInput.new(pty_master), stdout: pty_master, pty: pty_master,
                                    resize: ->(width, height) { pty_master.winsize = [Integer(height), Integer(width)] })
            end
            result
          rescue SystemCallError => error
            [gate_reader, gate_writer, status_reader, status_writer, identity_reader, identity_writer,
             stdin_reader, stdin_writer, stdout_reader, stdout_writer, stderr_reader, stderr_writer,
             pty_master, pty_slave, hook_reply_reader, hook_reply_writer].compact.each do |io|
              io.close unless io.closed?
            rescue IOError
              nil
            end
            raise EffectError, "process spawn failed: #{error.message}"
          end

          def release_gate(gate)
            gate.release
          end

          # The workload traced itself (PTRACE_TRACEME) before its security
          # steps, so its successful execve stops it with SIGTRAP: the old
          # address space -- the fork of this agent -- is already gone, and
          # not one instruction of the new program has run.  Move it into the
          # container's cgroup now and let it go.  Tearing that address space
          # down inside the cgroup is what made every exec under a small CPU
          # limit take seconds; runc's small init process never has one to
          # tear down.  Other signals that stop the tracee before its execve
          # are passed on.  Returns the Process::Status when the workload
          # exited instead (a failed exec), nil once it runs in the cgroup.
          def join_cgroup_at_exec_stop(pid, cgroup_procs)
            loop do
              _, status = Process.waitpid2(pid)
              return status unless status.stopped?

              signal = status.stopsig
              unless signal == SIGTRAP
                PTRACE.call(PTRACE_CONT, pid, nil, signal)
                next
              end
              begin
                cgroup_procs.syswrite(pid.to_s)
              rescue SystemCallError
                # Never let the command run outside the container's cgroup.
                Process.kill(SIGKILL, pid)
                PTRACE.call(PTRACE_DETACH, pid, nil, nil)
                _, status = Process.waitpid2(pid)
                return status
              ensure
                cgroup_procs.close unless cgroup_procs.closed?
              end
              PTRACE.call(PTRACE_DETACH, pid, nil, nil)
              return nil
            end
          end

          # Fork a child that disables GC first, and return only once it has
          # (see #spawn): GC.disable finishes a GC already in progress, and
          # any page that touches must be charged before the caller moves the
          # child into a container's cgroup, not after.
          def fork_without_gc(&)
            reader, writer = IO.pipe
            pid = Process.fork do
              GC.disable
              reader.close
              writer.write("g")
              writer.close
              yield
            end
            writer.close
            reader.read(1)
            pid
          ensure
            reader&.close unless reader.nil? || reader.closed?
            writer&.close unless writer.nil? || writer.closed?
          end

          def wait(pid:, timeout: nil)
            deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout))
            loop do
              result = Process.waitpid2(Integer(pid), Process::WNOHANG)
              return result && result.last if result
              return nil if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

              sleep 0.01
            end
          rescue Errno::ECHILD
            nil
          end

          # signal() names exactly one process.  Sending to the negated pid
          # instead reaches every member of that process group -- including
          # this agent whenever the workload never got its own session -- so
          # the two are separate methods, never aliases of each other.
          def signal(pid:, signal:)
            Process.kill(Integer(signal), Integer(pid))
            true
          end

          def signal_group(pid:, signal:)
            Process.kill(Integer(signal), -Integer(pid))
            true
          end

          private

          def normalize_join(value)
            return nil if value.nil?

            hash = value.respond_to?(:to_h) ? value.to_h.transform_keys(&:to_s) : {}
            pid = Integer(hash.fetch("pid") { hash.fetch("workload_pid") })
            start_time = Integer(hash.fetch("start_time") { hash.fetch("workload_start_time") })
            {"pid" => pid, "start_time" => start_time}
          rescue KeyError, ArgumentError, TypeError => error
            raise EffectError, "join_process requires pid and start_time: #{error.message}"
          end

          # Open the namespaces of a live container process.  The start time is
          # checked before and after the descriptors are opened so a recycled
          # PID cannot be joined.
          def open_process_namespaces(join)
            pid = join.fetch("pid")
            expected = join.fetch("start_time")
            raise EffectError, "container process identity changed before exec" unless process_start_time(pid) == expected

            descriptors = (CONTAINER_JOIN_ORDER + %i[user pid]).each_with_object({}) do |name, result|
              link = File.readlink("/proc/#{pid}/ns/#{Setns::NAMESPACE_TYPES.fetch(name).fetch(1)}")
              # The user namespace is only joined when it differs from ours.
              next if name == :user && link == File.readlink("/proc/self/ns/user")

              result[name] = @setns.open_namespace(pid: pid, name: name, expected_link: link, resource_id: "process:join:#{name}")
            end
            raise EffectError, "container process identity changed while joining" unless process_start_time(pid) == expected

            descriptors
          rescue SystemCallError => error
            raise EffectError, "container namespaces could not be opened: #{error.message}"
          end

          def bootstrap_security_adapter
            return @security if @security.respond_to?(:build_rootfs)
            return @security.adapter if @security.respond_to?(:adapter) && @security.adapter.respond_to?(:build_rootfs)

            nil
          end

          # Close every pipe, socket and anonymous inode (pidfd, eventfd,
          # epoll) this forked child inherited except the ones it was handed.
          # Regular files and devices are left alone: they cannot hold a
          # reader hostage and the log file is among them.
          INHERITED_CLOSE_KINDS = %w[pipe: socket: anon_inode:].freeze

          def close_inherited_descriptors(keep: [])
            keep_fds = Array(keep).compact.filter_map { |io| io.fileno if io.respond_to?(:fileno) && !io.closed? }
            Dir.children("/proc/self/fd").each do |entry|
              fd = Integer(entry, exception: false)
              next if fd.nil? || fd <= 2 || keep_fds.include?(fd)

              target = begin
                File.readlink("/proc/self/fd/#{fd}")
              rescue SystemCallError
                next
              end
              next unless INHERITED_CLOSE_KINDS.any? { |kind| target.start_with?(kind) }

              begin
                IO.for_fd(fd).close
              rescue SystemCallError, IOError, ArgumentError
                nil
              end
            end
          rescue SystemCallError
            nil
          end

          def set_parent_death_signal(expected_parent_pid: nil, expected_parent_start_time: nil)
            result = PRCTL.call(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "process") if result == -1

            if expected_parent_pid && kernel_parent_id != Integer(expected_parent_pid)
              raise Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "process")
            end
            if expected_parent_start_time && process_start_time(expected_parent_pid) != Integer(expected_parent_start_time)
              raise Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "process")
            end

            true
          end

          def set_child_subreaper
            result = PRCTL.call(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(PR_SET_CHILD_SUBREAPER)", resource_id: "process") if result == -1
          end

          def kernel_parent_id
            line = File.read("/proc/self/status").lines.find { |entry| entry.start_with?("PPid:") }
            value = line ? line.split.last.to_i : 0
            value.zero? ? Process.ppid : value
          rescue SystemCallError
            Process.ppid
          end
        end

        # One OCI hook run from the workload bootstrap, in whatever
        # namespaces and root the bootstrap is in at that stage.  The
        # bootstrap is a raw clone3 child with none of the interpreter's
        # threads, so the hook is started the same way (clone3 without flags,
        # then execve(2)) and waited for with waitpid(2)/usleep(3) directly:
        # Ruby's sleep never returned there.  The hook gets the state on stdin,
        # its output is kept for the error, and nothing else of the
        # bootstrap's descriptors (the readiness pipe above all) survives
        # into it.
        class ContainerHook
          OUTPUT_LIMIT = 4096
          CLOSE_RANGE_SYSCALL = 436
          EXECVE = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["execve"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT
          )
          SYSCALL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["syscall"], [Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG],
            Fiddle::TYPE_LONG
          )
          WAITPID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["waitpid"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT
          )
          USLEEP = Fiddle::Function.new(Fiddle::Handle::DEFAULT["usleep"], [Fiddle::TYPE_INT], Fiddle::TYPE_INT)
          KILL = Fiddle::Function.new(Fiddle::Handle::DEFAULT["kill"], [Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
          WNOHANG = 1
          Status = Data.define(:exitstatus, :termsig) do
            def success? = exitstatus&.zero? == true
          end

          def initialize(clone3:)
            @clone3 = clone3 || Clone3.new
          end

          def run(hook, state, stage:, index:)
            path = String(hook.fetch("path"))
            args = Array(hook["args"]).map(&:to_s)
            args = [path] if args.empty?
            @retained = []
            path_pointer = c_string(path)
            argv = pointer_vector(args.map { |value| c_string(value) })
            envp = pointer_vector(Array(hook["env"]).map { |value| c_string(value) })
            input_reader, input_writer = IO.pipe
            output_reader, output_writer = IO.pipe
            [input_reader, output_writer].each { |io| io.nonblock = false }
            child = @clone3.call(args: Clone3::Args.new(flags: 0), resource_id: "workload:hook")
            if child.child?
              ProcessGateAdapter::PRCTL.call(ProcessGateAdapter::PR_SET_PDEATHSIG, ProcessGateAdapter::SIGKILL, 0, 0, 0)
              ProcessGateAdapter::IMMEDIATE_EXIT.call(127) if ProcessGateAdapter::DUP2.call(input_reader.fileno, 0) == -1
              ProcessGateAdapter::IMMEDIATE_EXIT.call(127) if ProcessGateAdapter::DUP2.call(output_writer.fileno, 1) == -1
              ProcessGateAdapter::IMMEDIATE_EXIT.call(127) if ProcessGateAdapter::DUP2.call(output_writer.fileno, 2) == -1
              SYSCALL.call(CLOSE_RANGE_SYSCALL, 3, 0xFFFF_FFFF, 0)
              EXECVE.call(path_pointer, argv, envp)
              ProcessGateAdapter::IMMEDIATE_EXIT.call(127)
            end
            input_reader.close
            output_writer.close
            begin
              input_writer.write(state)
            rescue Errno::EPIPE
              nil
            ensure
              input_writer.close
            end
            wait(child.pid, output_reader, hook, stage: stage, index: index, path: path)
          ensure
            [input_reader, input_writer, output_reader, output_writer].each do |io|
              io.close if io && !io.closed?
            end
          end

          private

          def wait(pid, reader, hook, stage:, index:, path:)
            timeout = hook["timeout"]
            deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + Integer(timeout))
            output = +""
            loop do
              unless reader.closed?
                begin
                  chunk = reader.read_nonblock(4096)
                  output << chunk if output.bytesize < OUTPUT_LIMIT
                rescue IO::WaitReadable
                  nil
                rescue EOFError
                  reader.close
                end
              end
              status = reap(pid, WNOHANG)
              if status
                unless status.success?
                  raise EffectError,
                        "error running #{stage} hook ##{index}: #{path}: #{describe(status)}#{detail(output)}"
                end

                return true
              end
              if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
                KILL.call(pid, ProcessGateAdapter::SIGKILL)
                reap(pid, 0)
                raise EffectError, "error running #{stage} hook ##{index}: #{path} did not finish in #{timeout}s#{detail(output)}"
              end
              USLEEP.call(5_000)
            end
          end

          def reap(pid, options)
            storage = Fiddle::Pointer.malloc(4, Fiddle::RUBY_FREE)
            loop do
              result = WAITPID.call(pid, storage, options)
              return nil if result.zero?
              if result == -1 && Fiddle.last_error != Errno::EINTR::Errno
                raise EffectError, "waitpid on hook #{pid} failed: #{Fiddle.last_error}"
              end
              next if result == -1

              raw = storage[0, 4].unpack1("l")
              signal = raw & 0x7f
              return signal.zero? ? Status.new(exitstatus: (raw >> 8) & 0xff, termsig: nil) : Status.new(exitstatus: nil, termsig: signal)
            end
          end

          def describe(status)
            return "exec failed" if status.exitstatus == 127

            status.exitstatus ? "exit status #{status.exitstatus}" : "signal #{status.termsig}"
          end

          def detail(output)
            text = output.byteslice(0, OUTPUT_LIMIT).to_s.scrub.strip
            text.empty? ? "" : ", output: #{text}"
          end

          def c_string(value)
            text = String(value)
            raise EffectError, "hook argument contains NUL" if text.include?("\0")

            pointer = Fiddle::Pointer["#{text}\0"]
            @retained << pointer
            pointer
          end

          def pointer_vector(pointers)
            width = Fiddle::SIZEOF_VOIDP
            vector = Fiddle::Pointer.malloc((pointers.length + 1) * width, Fiddle::RUBY_FREE)
            pointers.each_with_index do |pointer, index|
              vector[index * width, width] = [pointer.to_i].pack(width == 8 ? "Q" : "L")
            end
            vector[pointers.length * width, width] = "\0" * width
            @retained << vector
            vector
          end
        end

        # The trusted bootstrap that runs inside the raw clone3 child.  The
        # child is single-threaded (a fresh task with its own fs_struct), which
        # is what makes setns(2)/unshare(2) on a mount namespace legal, and it
        # still maps the agent's Ruby image through the agent's mount
        # namespace: after unshare(CLONE_NEWNS) none of its executable
        # mappings pin the new namespace's copy of the old root, so that root
        # can be unmounted with a regular umount(2).
        class WorkloadBootstrap
          include ProcessIdentity

          # Values from include/uapi/linux/prctl.h.
          PR_SET_PDEATHSIG = 1
          SIGKILL = Signal.list.fetch("KILL")
          PRCTL = ProcessGateAdapter::PRCTL
          DUP2 = ProcessGateAdapter::DUP2
          GETPPID = ProcessGateAdapter::GETPPID
          IMMEDIATE_EXIT = ProcessGateAdapter::IMMEDIATE_EXIT
          SETSID = ProcessGateAdapter::SETSID
          IOCTL = ProcessGateAdapter::IOCTL
          TIOCSCTTY = ProcessGateAdapter::TIOCSCTTY

          def initialize(security:, setns:, command:, env:, cwd:, rootfs:, plan:, namespace_descriptors:,
                         build_rootfs:, unshare_mount:, unshare_cgroup:, status_writer:, stdio:, mounts: [],
                         controlling_tty: false, trace_exec: false, hooks: nil, hook_state: nil, hook_reply: nil, clone3: nil)
            @hooks = hooks || {}
            @hook_state = hook_state
            @hook_reply = hook_reply
            @clone3 = clone3
            @security = security
            @trace_exec = trace_exec
            @controlling_tty = controlling_tty
            @setns = setns
            @command = command
            @env = env
            @cwd = cwd
            @rootfs = rootfs
            @mounts = Array(mounts)
            @plan = plan
            @descriptors = namespace_descriptors
            @build_rootfs = build_rootfs
            @unshare_mount = unshare_mount
            @unshare_cgroup = unshare_cgroup
            @status = status_writer
            @stdio = stdio
            @pivot = PivotRoot.new
          end

          # Never returns: execveat(2) replaces the process, and every failure
          # path reports through the status pipe and _exit(2)s.
          def run(expected_parent_pid:)
            result = PRCTL.call(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)
            # Traced by the wrapper, which moves this process into the
            # container's cgroup at the stop after execve (before any seccomp
            # profile could refuse ptrace).
            IMMEDIATE_EXIT.call(127) if @trace_exec && ProcessGateAdapter::PTRACE.call(ProcessGateAdapter::PTRACE_TRACEME, 0, nil,
                                                                                       nil) == -1
            parent_pid = GETPPID.call
            # A PID-namespace init cannot see its parent in the outer
            # namespace and getppid(2) therefore returns zero. PR_SET_PDEATHSIG
            # still tracks that real parent across the namespace boundary.
            visible_parent = parent_pid == Integer(expected_parent_pid) || parent_pid.zero?
            IMMEDIATE_EXIT.call(127) if result == -1 || !visible_parent
            @stdio.each_with_index do |source, target|
              IMMEDIATE_EXIT.call(127) if DUP2.call(source, target) == -1
            end
            if @controlling_tty
              # A new session whose controlling terminal is the pty on fd 0,
              # so shells get job control and SIGHUP on hangup.
              SETSID.call
              IMMEDIATE_EXIT.call(127) if IOCTL.call(0, TIOCSCTTY, 0) == -1
            end
            begin
              # Host identity is captured before any namespace transition:
              # verified image roots have no /proc, and the parent needs a
              # cross-namespace process identity for pidfd and cgroup checks.
              host_pid = host_pid_from_status(File.read("/proc/self/status"))
              host_pid = kernel_process_id if host_pid.zero?
              @host_pid = host_pid
              host_start_time = self_start_time
              context = @plan.context
              program = @plan.seccomp_program
              executable = nil
              digest = nil
              # A plan without a mount step still execs a verified descriptor:
              # when a rootfs was requested the filesystem transition happens
              # here (a security plan without steps is the Unconfined case),
              # and the executable is opened before any step can restrict the
              # filesystem view.
              unless @plan.steps.any? { |step| step.name.to_sym == :mount }
                if @build_rootfs
                  enter_namespaces unless @plan.steps.any? { |step| step.name.to_sym == :namespace }
                  create_stage
                  build_filesystem(context)
                  start_stage
                end
                executable, digest, @executable_info = @security.open_executable(@command.fetch(0), @env["PATH"])
                @security.prepare_fd_directory
              end
              @plan.steps.each do |step|
                # Hooks run before the process gives up any privilege.
                start_stage unless %i[namespace mount].include?(step.name.to_sym)
                case step.name.to_sym
                when :namespace
                  enter_namespaces
                when :mount
                  create_stage
                  build_filesystem(context)
                  start_stage
                  executable, digest, @executable_info = @security.open_executable(@command.fetch(0), @env["PATH"])
                  @security.prepare_fd_directory
                when :lsm
                  # procfs descriptors are opened before Landlock removes the
                  # right to open them; a seq_file re-read from offset zero
                  # still reports the final state at readiness time.
                  open_readiness_sources
                  @security.apply(step: step.name, context: context, program: program)
                else
                  @security.apply(step: step.name,
                                  context: context.with(fd_allowlist: context.fd_allowlist + [executable&.fileno].compact), program: program)
                end
              end
              # A plan that neither builds a root nor mounts still runs its
              # hooks before the user process.
              start_stage
              metadata = readiness_metadata
              payload = JSON.generate(metadata)
              @status.write("R" + [host_pid, host_start_time].pack("Q<2") + digest + [payload.bytesize].pack("L<") + payload)
              @status.flush
              # Keep the readiness pipe open until the final exec succeeds.
              # close-on-exec gives the parent an EOF on success; when exec
              # fails, the rescue path can still append an error marker.
              @status.close_on_exec = true
              argv = pointer_vector(@command.map { |value| c_string(value) })
              envp = pointer_vector(@env.reject do |_key, value|
                value.nil?
              end.sort_by { |key, _| key }.map { |key, value| c_string("#{key}=#{value}") })
              error = if @executable_info&.fetch(:script)
                        @pivot.execveat_path(path: @executable_info.fetch(:path), argv: argv, envp: envp, resource_id: "workload:execveat")
                      else
                        @pivot.execveat(fd: executable.fileno, argv: argv, envp: envp, resource_id: "workload:execveat")
                      end
              raise error
            # ScriptError too: a LoadError that escaped left this raw clone3
            # child in the interpreter's exit path, parked on a futex for ever
            # with the readiness pipe open, and the gate release waiting on it.
            rescue StandardError, ScriptError => error
              begin
                location = Array(error.backtrace).first(3).join(" <- ")
                @status.write("E#{error.class}: #{error.message} [#{location}]")
                @status.flush
              rescue StandardError
                nil
              end
              IMMEDIATE_EXIT.call(127)
            end
          end

          private

          # OCI "create": the container namespaces exist and the root is not
          # pivoted yet.  prestart/createRuntime run in the runtime namespace
          # (the agent, through the gate), then createContainer here.
          def create_stage
            return if @create_stage_done

            @create_stage_done = true
            request_runtime_hooks if @hook_reply
            run_container_hooks("createContainer")
          end

          # OCI "start": inside the container's root, before the user process.
          def start_stage
            return if @start_stage_done

            create_stage
            @start_stage_done = true
            run_container_hooks("startContainer")
            @hook_reply&.close
            @hook_reply = nil
          end

          def request_runtime_hooks
            payload = JSON.generate("pid" => @host_pid)
            @status.write("H" + [payload.bytesize].pack("L<") + payload)
            @status.flush
            answer = @hook_reply.read(1)
            return true if answer == "0"

            if answer == "E"
              size = @hook_reply.read(4).to_s.unpack1("L<").to_i
              raise EffectError, @hook_reply.read(size).to_s
            end
            raise EffectError, "the runtime did not answer the hook request"
          end

          def run_container_hooks(stage)
            Array(@hooks[stage]).each_with_index do |hook, index|
              state = (@hook_state || {}).merge("status" => stage == "startContainer" ? "created" : "creating", "pid" => @host_pid)
              ContainerHook.new(clone3: @clone3).run(hook, JSON.generate(state), stage: stage, index: index)
            end
          end

          # Join order (R-1.6): mount first so the rootfs mount is visible,
          # then the shared Pod namespaces, then a private copy of the mount
          # namespace for this container, then a private cgroup namespace
          # rooted at the cgroup the wrapper was attached to.
          def enter_namespaces
            ProcessGateAdapter::CONTAINER_JOIN_ORDER.each do |name|
              descriptor = @descriptors[name]
              next unless descriptor

              @setns.setns(fd: descriptor, name: name, resource_id: "workload:#{name}")
              descriptor.close
            end
            @setns.unshare(flags: Setns::CLONE_NEWNS, resource_id: "workload:mount-namespace") if @unshare_mount
            @setns.unshare(flags: Setns::CLONE_NEWCGROUP, resource_id: "workload:cgroup-namespace") if @unshare_cgroup
            true
          end

          def build_filesystem(context)
            if @build_rootfs
              @security.build_rootfs(@rootfs, context: context, cwd: @cwd, mounts: @mounts)
            elsif @cwd && !String(@cwd).empty?
              Dir.chdir(String(@cwd))
            end
            @security.join_user_namespace(@descriptors[:user])
            true
          end

          def open_readiness_sources
            @readiness_sources ||= %w[status uid_map cgroup].to_h do |name|
              [name, File.open("/proc/self/#{name}", File::RDONLY)]
            end
          rescue SystemCallError => error
            raise EffectError, "cannot open readiness sources: #{error.message}"
          end

          def readiness_metadata
            open_readiness_sources
            status_text = reread(@readiness_sources.fetch("status"))
            values = status_text.lines.each_with_object({}) do |line, result|
              key, raw = line.split(":", 2)
              result[key] = raw.strip if raw
            end
            links = Setns::NAMESPACE_TYPES.to_h do |name, (_flag, proc_name)|
              [name.to_s, File.readlink("/proc/self/ns/#{proc_name}")]
            end
            {
              "rootfs" => @security.rootfs_report&.to_h,
              "capabilities" => @security.capability_report,
              "status" => {
                "CapBnd" => values["CapBnd"], "CapEff" => values["CapEff"], "CapPrm" => values["CapPrm"],
                "CapInh" => values["CapInh"], "CapAmb" => values["CapAmb"],
                "NoNewPrivs" => Integer(values.fetch("NoNewPrivs", "0")),
                "Seccomp" => Integer(values.fetch("Seccomp", "0")),
                "Uid" => values["Uid"], "Gid" => values["Gid"]
              },
              "namespaces" => links,
              "uid_map" => reread(@readiness_sources.fetch("uid_map")).strip,
              "cgroup" => reread(@readiness_sources.fetch("cgroup")).strip
            }
          end

          def reread(io)
            io.rewind
            io.read.to_s
          end

          # /proc/self/stat is read through whichever proc mount is visible;
          # before any namespace transition that is the host's, so the start
          # time is the one the parent can verify from outside.
          def self_start_time
            stat = File.read("/proc/self/stat")
            Integer(stat[(stat.rindex(")") + 1)..].split.fetch(19))
          end

          def c_string(value)
            text = String(value)
            raise EffectError, "exec argument contains NUL" if text.include?("\0")

            Fiddle::Pointer["#{text}\0"]
          end

          def pointer_vector(pointers)
            width = Fiddle::SIZEOF_VOIDP
            vector = Fiddle::Pointer.malloc((pointers.length + 1) * width, Fiddle::RUBY_FREE)
            pointers.each_with_index do |pointer, index|
              vector[index * width, width] = [pointer.to_i].pack(width == 8 ? "Q" : "L")
            end
            vector[pointers.length * width, width] = "\0" * width
            @retained = (@retained || []) + pointers + [vector]
            vector
          end
        end

        # Executes trusted stream helpers in an existing Pod.  Exec joins the
        # live container's namespaces (§5.8.10) and reapplies the container
        # security plan; port-forward and probes join only the holder's network
        # namespace with a host-owned static helper or an in-process socket.
        class NamespaceConnector
          include CapabilityContract

          BUSYBOX_CANDIDATES = %w[/usr/bin/busybox /bin/busybox].freeze

          def initialize(process_adapter:, cgroup_adapter:, namespace_adapter: nil)
            @process = process_adapter
            @cgroup = cgroup_adapter
            @namespace_adapter = namespace_adapter
          end

          def native_capabilities
            process_capabilities = @process.respond_to?(:native_capabilities) ? @process.native_capabilities.to_h : {}
            process_ready = process_capabilities[:process_gate] == true && process_capabilities[:child_exec] == true
            {
              namespace_exec_streams: process_ready,
              namespace_port_forward: process_ready && !busybox_path.nil?,
              namespace_probe: !@namespace_adapter.nil? && @namespace_adapter.respond_to?(:within_namespaces)
            }.freeze
          end

          def validate_native_capabilities!
            capabilities = native_capabilities
            require_capability!(capabilities.fetch(:namespace_exec_streams), "namespace exec stream helper is unavailable")
            require_capability!(capabilities.fetch(:namespace_port_forward), "static namespace port-forward helper is unavailable")
            true
          end

          def exec(sandbox:, container:, command:, tty: false, **_options)
            process = container.process
            join = if process && process.respond_to?(:workload_pid) && process.workload_pid && process.workload_start_time
                     {"pid" => process.workload_pid, "start_time" => process.workload_start_time}
                   end
            raise EffectError, "exec requires a live container process to join" unless join

            # CRI exec (runc exec) runs the command with the container's own
            # process environment.  Spawning it with an empty one left every
            # exec -- kubectl exec and exec probes alike -- without the Pod's
            # env vars, PATH included: the Job pod failure policy spec's
            # readiness probe `cat /data/foo-$JOB_COMPLETION_INDEX` read
            # /data/foo- and never succeeded, so its Pods never became Ready.
            spawn_stream(
              sandbox: sandbox,
              container: container,
              command: Array(command),
              cwd: container.spec["cwd"],
              rootfs: nil,
              tty: tty,
              join_process: join,
              env: container.spec["env"] || {}
            )
          end

          def port_forward(sandbox:, container:, ports:, timeout:, **_options)
            validate_native_capabilities!
            values = Array(ports).map { |port| Integer(port) }
            raise EffectError, "port-forward requires between 1 and 128 ports" unless values.length.between?(1, 128)

            timeout_seconds = Float(timeout)
            raise EffectError, "port-forward timeout must be positive" unless timeout_seconds.positive?

            streams = values.map do |port|
              spawn_stream(
                sandbox: sandbox,
                container: container,
                command: [
                  busybox_path,
                  "sh",
                  "-c",
                  "i=0; while [ $i -lt 50 ]; do #{busybox_path} nc -w 1 127.0.0.1 #{port} && exit $?; " \
                  "i=$((i+1)); #{busybox_path} sleep 0.02; done; exit 111"
                ],
                cwd: nil,
                rootfs: nil,
                tty: false
              )
            end
            multiplexed = PortForwardMultiplexer.new(streams)
            {stdin: multiplexed, stdout: multiplexed, stderr: nil, status: multiplexed.status}.freeze
          end

          # HTTP GET inside the Pod network namespace.  The request is a plain
          # HTTP/1.1 exchange on a blocking socket with an IO.select deadline;
          # no Timeout thread is created in the namespace helper child.
          def http_get(sandbox:, container:, definition:, timeout: 1.0, **_options)
            raise EffectError, "HTTP probe requires a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            host = String(definition["host"] || "127.0.0.1")
            port = Integer(definition["port"] || 80)
            path = String(definition["path"] || "/")
            path = "/#{path}" unless path.start_with?("/")
            headers = Array(definition["httpHeaders"]).each_with_object({}) do |header, result|
              item = header.respond_to?(:to_h) ? header.to_h.transform_keys(&:to_s) : {}
              result[String(item["name"])] = String(item["value"]) unless item["name"].to_s.empty?
            end
            # v1.HTTPGetAction.scheme selects HTTP or HTTPS.  kubelet's HTTPS
            # prober does not verify the server certificate -- the endpoint is
            # the container's own, and a Pod that serves its readiness over
            # TLS (every admission webhook does) is never ready without this.
            tls = String(definition["scheme"] || definition[:scheme]).casecmp("HTTPS").zero?
            deadline = Float(timeout)
            result = @namespace_adapter.within_namespaces(handle, only: [:network], timeout: deadline + 5.0) do
              NamespaceConnector.blocking_http_get(host, port, path, headers, deadline, tls: tls)
            end
            {"status" => Integer(result.fetch("status")), "success" => Integer(result.fetch("status")).between?(200, 399),
             "message" => "HTTP #{result.fetch("status")}", "body_bytes" => Integer(result.fetch("body_bytes"))}.freeze
          end

          # Namespaced sysctls (net.* in the network namespace, kernel.shm*/
          # msg*/sem and fs.mqueue.* in the IPC namespace) are written to
          # /proc/sys by a helper joined to the sandbox's namespaces; /proc/sys
          # reflects the writer's own namespaces.
          def grpc_check(sandbox:, container:, definition:, timeout: 1.0, **_options)
            raise EffectError, "gRPC probe requires a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            host = String(definition["host"] || "127.0.0.1")
            port = Integer(definition["port"] || 0)
            raise EffectError, "gRPC probe port is required" unless port.positive?

            service = String(definition["service"] || "")
            deadline = Float(timeout)
            # The helper is a fresh fork, so the grpc gem is loaded and
            # initialised there and never in the agent itself.
            result = @namespace_adapter.within_namespaces(handle, only: [:network], timeout: deadline + 5.0) do
              NamespaceConnector.blocking_grpc_check(host, port, service, deadline)
            end
            {"success" => result.fetch("success") == true, "message" => String(result.fetch("message"))}.freeze
          end

          # net.JoinHostPort: an IPv6 literal is bracketed.
          def self.host_port(host, port)
            host = host.to_s
            host = "[#{host}]" if host.include?(":") && !host.start_with?("[")
            "#{host}:#{port}"
          end

          def self.blocking_grpc_check(host, port, service, timeout)
            require "grpc"
            require "grpc/health/v1/health_services_pb"
            stub = ::Grpc::Health::V1::Health::Stub.new(host_port(host, port), :this_channel_is_insecure, timeout: timeout)
            request = ::Grpc::Health::V1::HealthCheckRequest.new(service: service.to_s)
            response = stub.check(request, deadline: Time.now + timeout)
            status = response.status.to_s
            {"success" => status == "SERVING", "message" => "gRPC health check status: #{status}"}
          rescue ::GRPC::DeadlineExceeded
            {"success" => false, "message" => "gRPC probe timed out after #{timeout}s"}
          rescue ::GRPC::BadStatus => error
            {"success" => false, "message" => "gRPC probe failed: #{error.message}"}
          rescue LoadError => error
            {"success" => false, "message" => "gRPC probe unavailable: #{error.message}"}
          end

          SYSCTL_NAMESPACES = {"net" => :network, "kernel" => :ipc, "fs" => :ipc}.freeze

          def apply_sysctls(sandbox:, sysctls:, **_options)
            raise EffectError, "sysctls require a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            entries = Array(sysctls).map do |entry|
              name = String(entry["name"] || entry[:name]).tr("/", ".")
              raise EffectError, "invalid sysctl name #{name.inspect}" unless name.match?(/\A[a-z0-9_.-]+\z/i) && !name.include?("..")

              family = name.split(".").first
              namespace = SYSCTL_NAMESPACES[family]
              raise EffectError, "sysctl #{name.inspect} is not namespaced" unless namespace

              [name, String(entry["value"] || entry[:value]), namespace]
            end
            entries.group_by(&:last).each do |namespace, group|
              @namespace_adapter.within_namespaces(handle, only: [namespace], timeout: 10.0) do
                group.map do |name, value, _|
                  path = File.join("/proc/sys", name.tr(".", "/"))
                  File.write(path, value)
                  name
                end
              end
            end
            entries.map { |name, value, _| "#{name}=#{value}" }
          end

          def tcp_socket(sandbox:, container:, definition:, timeout: 1.0, **_options)
            raise EffectError, "TCP probe requires a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            host = String(definition["host"] || "127.0.0.1")
            port = Integer(definition["port"])
            deadline = Float(timeout)
            result = @namespace_adapter.within_namespaces(handle, only: [:network], timeout: deadline + 5.0) do
              NamespaceConnector.blocking_tcp_connect(host, port, deadline)
            end
            {"success" => result.fetch("connected") == true, "message" => result.fetch("message")}.freeze
          end

          def self.blocking_tcp_connect(host, port, timeout)
            # The socket family follows the address: an IPv6 Pod IP needs an
            # AF_INET6 socket (AF_INET refused every IPv6 probe with EAFNOSUPPORT).
            info = Addrinfo.ip(host.to_s.delete_prefix("[").delete_suffix("]"))
            address = Socket.sockaddr_in(Integer(port), info.ip_address)
            socket = Socket.new(info.afamily, Socket::SOCK_STREAM, 0)
            begin
              socket.connect_nonblock(address, exception: false)
              ready = IO.select(nil, [socket], nil, timeout)
              return {"connected" => false, "message" => "connect timed out"} unless ready

              error = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int
              return {"connected" => false, "message" => SystemCallError.new(error).message} unless error.zero?

              {"connected" => true, "message" => "connected"}
            ensure
              socket.close
            end
          rescue SystemCallError => error
            {"connected" => false, "message" => error.message}
          end

          def self.blocking_http_get(host, port, path, headers, timeout, tls: false)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            remaining = -> { timeout - (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) }
            connect = blocking_tcp_connect(host, port, timeout)
            raise EffectError, "HTTP probe connect failed: #{connect.fetch("message")}" unless connect.fetch("connected")

            transport = TCPSocket.new(host.to_s.delete_prefix("[").delete_suffix("]"), Integer(port))
            socket = tls ? start_probe_tls(transport, host) : transport
            begin
              request = ["GET #{path} HTTP/1.1", "Host: #{host_port(host, port)}", "User-Agent: rubernetes-probe/1", "Connection: close"]
              headers.each { |name, value| request << "#{name}: #{value}" }
              socket.write(request.join("\r\n") + "\r\n\r\n")
              buffer = "".b
              loop do
                wait = remaining.call
                raise EffectError, "HTTP probe timed out" if wait <= 0
                break unless socket.wait_readable(wait)

                begin
                  chunk = socket.read_nonblock(16 * 1024, exception: false)
                rescue EOFError
                  break
                end
                break if chunk.nil?
                next if chunk == :wait_readable

                buffer << chunk
                break if buffer.bytesize > 1024 * 1024
                break if buffer.include?("\r\n\r\n".b) && buffer.start_with?("HTTP/".b) && buffer.bytesize >= 12
              end
              status = buffer[%r{\AHTTP/1\.[01] (\d{3})}, 1]
              raise EffectError, "HTTP probe received no status line" unless status

              {"status" => Integer(status), "body_bytes" => buffer.bytesize}
            ensure
              socket.close
              transport.close unless transport.closed?
            end
          end

          # kubelet's HTTPS prober sets InsecureSkipVerify: the probe targets
          # the container's own endpoint, whose certificate is routinely
          # self-signed and issued for a name the probe does not use.
          def self.start_probe_tls(transport, host)
            context = OpenSSL::SSL::SSLContext.new
            context.verify_mode = OpenSSL::SSL::VERIFY_NONE
            ssl = OpenSSL::SSL::SSLSocket.new(transport, context)
            # SNI carries a name, never an IP literal (Go's tls sends none for one).
            name = host.to_s.delete_prefix("[").delete_suffix("]")
            ssl.hostname = name unless name.empty? || name.match?(/\A[\d.]+\z/) || name.include?(":")
            ssl.sync_close = false
            ssl.connect
            ssl
          end

          # Kubernetes port-forward assigns two channels to each requested
          # port: 2*n carries data and 2*n+1 carries errors.
          class PortForwardMultiplexer
            def initialize(streams)
              @streams = Array(streams).freeze
              @readers = @streams.flat_map.with_index do |stream, index|
                [[stream.fetch(:stdout), index * 2], [stream.fetch(:stderr), (index * 2) + 1]]
              end.reject { |reader, _channel| reader.nil? }
              @buffer = "".b
              @closed = false
            end

            attr_reader :streams

            def status
              @streams.map { |stream| stream.fetch(:status) }.freeze
            end

            def write(value)
              bytes = String(value).b
              raise EffectError, "port-forward channel frame is empty" if bytes.empty?

              channel = bytes.getbyte(0)
              raise EffectError, "port-forward data channel must be even" unless channel.even?

              stream = @streams.fetch(channel / 2) { raise EffectError, "unknown port-forward channel #{channel}" }
              payload = bytes.byteslice(1, bytes.bytesize - 1) || "".b
              stream.fetch(:stdin).write(payload) unless payload.empty?
              bytes.bytesize
            end

            def read(length = nil)
              requested = length && Integer(length)
              return consume(requested) unless @buffer.empty?

              loop do
                return nil if @readers.empty?

                ready = IO.select(@readers.map(&:first), nil, nil)&.first || []
                ready.each do |reader|
                  pair = @readers.find { |candidate, _channel| candidate.equal?(reader) }
                  next unless pair

                  chunk = reader.read_nonblock(16 * 1024)
                  @buffer << pair.fetch(1).chr.b << chunk.b
                  return consume(requested)
                rescue IOError
                  @readers.delete(pair)
                rescue IO::WaitReadable
                  next
                end
              end
            end

            def close_write
              @streams.each do |stream|
                input = stream.fetch(:stdin)
                input.close unless input.closed?
              rescue IOError
                nil
              end
              self
            end

            def close
              return self if @closed

              @closed = true
              @streams.each do |stream|
                %i[stdin stdout stderr].filter_map { |key| stream[key] }.each do |io|
                  io.close unless io.closed?
                rescue IOError
                  nil
                end
              end
              self
            end

            def closed? = @closed

            private

            def consume(length)
              size = length ? [length, @buffer.bytesize].min : @buffer.bytesize
              value = @buffer.byteslice(0, size)
              @buffer = @buffer.byteslice(size, @buffer.bytesize - size) || "".b
              value
            end
          end

          private

          def spawn_stream(sandbox:, container:, command:, cwd:, rootfs:, tty:, join_process: nil, env: {})
            # The helper that execs the command is a fork of this agent, and
            # everything it does before execve -- closing inherited
            # descriptors, entering namespaces, the security steps, each
            # copy-on-write fault on the agent's heap -- used to run inside
            # the container's cgroup, attached right after fork.  Under a
            # small CPU limit (10m: 1 ms per 100 ms) that alone took 5-15 s
            # per exec ("Pod InPlace Resize" execs cat on cgroup files a
            # dozen times per spec).  runc exec does the same setup in a few
            # milliseconds.  Here the workload is moved into the cgroup at the
            # stop that follows its execve (see ProcessGateAdapter#spawn,
            # +cgroup_procs+), through a cgroup.procs descriptor opened now.
            procs = if container.cgroup && @cgroup.respond_to?(:open_procs) && @process.respond_to?(:join_cgroup_at_exec?) &&
                       @process.join_cgroup_at_exec?
                      @cgroup.open_procs(container.cgroup)
                    end
            process = @process.spawn(
              command: command,
              env: env,
              cwd: cwd,
              rootfs: rootfs,
              namespace: sandbox.namespace,
              cgroup: container.cgroup,
              security_plan: container.security_plan,
              tty: tty,
              # An exec/attach session always owns its input pipe; the
              # /dev/null default is for the container's own process.
              stdin: true,
              join_process: join_process,
              cgroup_procs: procs
            )
            procs&.close
            @cgroup.attach(container.cgroup, pid: process.fetch(:pid)) if container.cgroup && procs.nil?
            @process.release_gate(process.fetch(:gate))
            status = Queue.new
            Thread.new do
              result = @process.wait(pid: process.fetch(:pid), timeout: nil)
              status << result
            rescue StandardError => error
              status << error
            end
            wrapper_pid = process.fetch(:pid)
            workload_pid = process.fetch(:gate).workload_pid
            terminate = lambda do |signal = Signal.list.fetch("KILL")|
              [workload_pid, wrapper_pid].compact.uniq.each do |target|
                @process.signal(pid: target, signal: signal)
              rescue StandardError
                nil
              end
              true
            end
            {
              stdin: process.fetch(:stdin),
              stdout: process.fetch(:stdout),
              stderr: tty ? nil : process.fetch(:stderr),
              status: status,
              resize: process[:resize],
              terminate: terminate,
              pid: workload_pid
            }.freeze
          rescue StandardError
            begin
              @process.signal(pid: process.fetch(:pid), signal: Signal.list.fetch("KILL")) if process
              @process.wait(pid: process.fetch(:pid), timeout: 1.0) if process
            rescue StandardError
              nil
            end
            raise
          end

          def busybox_path
            @busybox_path ||= BUSYBOX_CANDIDATES.find do |path|
              File.executable?(path) && File.binread(path, 4) == "\x7FELF".b
            rescue SystemCallError
              false
            end
          end
        end

        class PidfdAdapter
          include CapabilityContract

          def initialize(delegate: Pidfd.new)
            @delegate = delegate
          end

          def native_capabilities
            {pidfd: pidfd_probe}.freeze
          end

          def validate_native_capabilities!
            fd = @delegate.open(pid: Process.pid, resource_id: "pidfd:preflight")
            IO.for_fd(fd).close
            true
          rescue StandardError => error
            raise Unsupported, "pidfd preflight failed: #{error.message}"
          end

          def open(**arguments) = @delegate.open(**arguments)
          def send_signal(**arguments) = @delegate.send_signal(**arguments)
          def wait(**arguments) = @delegate.wait(**arguments)
          def close(pidfd:) = IO.for_fd(Integer(pidfd)).close

          def alive?(pidfd:)
            @delegate.wait(pidfd: pidfd, timeout: 0, resource_id: "pidfd:#{pidfd}").nil?
          rescue Linux::Error => error
            raise unless error.errno == Errno::ECHILD::Errno

            false
          end

          private

          def pidfd_probe
            fd = @delegate.open(pid: Process.pid, resource_id: "pidfd:probe")
            IO.for_fd(fd).close
            true
          rescue StandardError
            false
          end
        end

        module_function

        def for_profile(profile:, sandbox_root:, cgroup_root:, architecture: nil, landlock_roots: [])
          namespace = NamespaceAdapter.new
          filesystem = OverlayFilesystemAdapter.new(root: sandbox_root, namespace_adapter: namespace)
          cgroup = CgroupAdapter.new(root: cgroup_root)
          security = SecurityAdapter.new(landlock_roots: landlock_roots)
          process = ProcessGateAdapter.new(namespace_adapter: namespace)
          streams = NamespaceConnector.new(process_adapter: process, cgroup_adapter: cgroup, namespace_adapter: namespace)
          pidfd = PidfdAdapter.new
          probe = Security::CapabilityProbe.new(architecture: architecture)
          {
            namespace_adapter: namespace,
            filesystem_adapter: filesystem,
            cgroup_adapter: cgroup,
            security_adapter: security,
            security_probe: probe,
            process_adapter: process,
            pidfd_adapter: pidfd,
            exec_adapter: streams,
            port_forward_adapter: streams,
            http_probe_adapter: streams,
            tcp_probe_adapter: streams,
            sysctl_adapter: streams
          }.freeze
        end
      end

      NativeAdapters = NativeAdapters unless const_defined?(:NativeAdapters, false)
    end
  end
end
