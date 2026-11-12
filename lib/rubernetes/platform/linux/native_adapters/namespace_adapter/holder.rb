# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Creation of the namespace holder: the clone3 child that owns the Pod's
        # namespaces, and the agent's side of the readiness handshake with it.
        class NamespaceAdapter
          # The two pipes of the creation handshake.  On `writer` the holder
          # reports "U" (user namespace unshared, write my maps), then "R" + pid
          # (ready) or "E" + errno; on `map_writer` the agent answers "U" with "M".
          HolderPipes = Struct.new(:reader, :writer, :map_reader, :map_writer) do
            def self.open
              reader, writer = IO.pipe
              new(reader, writer, *IO.pipe)
            rescue SystemCallError
              [reader, writer].each { |io| io&.close }
              raise
            end

            def close
              each { |io| io.close unless io.closed? }
            end
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
            namespaces, user_mapping = holder_plan(plan)
            clone_flags = (namespaces - [:user]).sum { |name| NAMESPACE_TYPES.fetch(name).fetch(0) } | Clone3::CLONE_PIDFD
            pipes = HolderPipes.open
            agent_pid = Process.pid
            agent = {pid: agent_pid, start_time: process_start_time(agent_pid)}
            clone_result = @clone3.call(args: Clone3::Args.new(flags: clone_flags), resource_id: String(identity))
            run_holder(plan, namespaces, user_mapping, identity, agent, pipes) if clone_result.child?
            await_holder(clone_result.pid, pipes, user_mapping)
            raise EffectError, "clone3 did not return a namespace pidfd" unless clone_result.pidfd

            start_time, namespace_links = kernel_identity(clone_result.pid, namespaces)
            register(Handle.new(
              id: String(id).freeze, identity: String(identity).freeze, pid: clone_result.pid, pidfd: clone_result.pidfd,
              supervisor_pid: clone_result.pid, namespaces: namespaces.freeze, plan: plan, start_time: start_time,
              namespace_links: namespace_links.freeze, creation_method: "clone3", clone_flags: clone_flags,
              user_mapping: user_mapping&.to_h
            ))
          rescue SystemCallError, UserNamespace::Error => error
            abandon_holder(clone_result)
            raise EffectError, "namespace creation failed: #{error.message}"
          rescue StandardError
            abandon_holder(clone_result)
            raise
          ensure
            pipes&.close
          end

          private

          # The namespaces and the uid/gid mapping a plan asks for, validated.
          def holder_plan(plan)
            namespaces = normalize_namespaces(plan)
            validate_plan_namespaces!(namespaces)
            validate_native_capabilities!
            user_mapping = normalize_user_mapping(plan)
            raise EffectError, "user namespace mapping requires the :user namespace in the plan" if user_mapping && !namespaces.include?(:user)
            raise EffectError, "the :user namespace requires a uid/gid mapping" if namespaces.include?(:user) && user_mapping.nil?

            [namespaces, user_mapping]
          end

          # The holder itself, in the clone3 child.  Never returns: it reports
          # readiness or its failure on the pipe, then holds the namespaces until
          # it is signalled.
          def run_holder(plan, namespaces, user_mapping, identity, agent, pipes)
            pipes.reader.close
            pipes.map_writer.close
            begin
              set_parent_death_signal(expected_parent_pid: agent.fetch(:pid),
                                      expected_parent_start_time: agent.fetch(:start_time),
                                      pid_namespace_pid1: namespaces.include?(:pid))
              configure_loopback if namespaces.include?(:network)
              # Only a holder that owns a mount namespace may change
              # propagation: a plan without :mount (a PID-only holder) still
              # shares the agent's -- the host's -- mount namespace, and the
              # recursive slave/private landed on the host root, stripping
              # every shared peer group (the agents' Pod roots included).
              make_mounts_slave if namespaces.include?(:mount)
              configure_hostname(plan)
              unshare_user_namespace(identity, pipes) if user_mapping
              pipes.map_reader.close
              send_ready(pipes.writer, kernel_process_id)
              hold_until_signal
            rescue StandardError => error
              send_failure(pipes.writer, error)
              exit!(127)
            ensure
              pipes.writer.close unless pipes.writer.closed?
            end
            exit!(0)
          end

          # In the holder: leave the initial user namespace and wait until the
          # agent has written the maps.
          def unshare_user_namespace(identity, pipes)
            @setns.unshare(flags: CLONE_NEWUSER, resource_id: "#{identity}:user")
            pipes.writer.write("U")
            pipes.writer.flush
            acknowledgement = pipes.map_reader.read(1)
            raise EffectError, "user namespace mapping was not acknowledged" unless acknowledgement == "M"
          end

          # In the agent: write the uid/gid maps when the holder asks for them,
          # then require its readiness message.
          def await_holder(pid, pipes, user_mapping)
            pipes.writer.close
            pipes.map_reader.close
            first = pipes.reader.read(1)
            if first == "U"
              UserNamespace.write_mappings(pid: pid, mapping: user_mapping, proc_root: @proc_root)
              pipes.map_writer.write("M")
              pipes.map_writer.flush
              first = pipes.reader.read(1)
            end
            pipes.map_writer.close
            payload = first.to_s + pipes.reader.read(8).to_s
            pipes.reader.close
            return if payload.bytesize == 9 && payload.getbyte(0) == "R".ord

            terminate_process(pid)
            raise EffectError, decode_failure(payload)
          end

          # A creation that failed after clone3 leaves no holder and no pidfd.
          def abandon_holder(clone_result)
            return unless clone_result

            terminate_process(clone_result.pid)
            close_fd(clone_result.pidfd) if clone_result.pidfd
          end

          def normalize_namespaces(plan)
            Array(plan.namespaces).map { |name| String(name).downcase.to_sym }.uniq
          end

          def normalize_user_mapping(plan)
            mapping = plan.user_mapping
            return nil unless mapping

            value = mapping.to_h.transform_keys(&:to_s)
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
            hostname = plan.hostname
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
            errno = Integer(NativeAdapters.errno_of(error) || Errno::EINVAL::Errno)
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
        end
      end
    end
  end
end
