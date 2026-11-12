# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
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
            bind_to_wrapper(expected_parent_pid)
            install_stdio
            begin
              # Host identity is captured before any namespace transition:
              # verified image roots have no /proc, and the parent needs a
              # cross-namespace process identity for pidfd and cgroup checks.
              @host_pid = host_pid_from_status(File.read("/proc/self/status"))
              @host_pid = kernel_process_id if @host_pid.zero?
              host_start_time = self_start_time
              apply_security_plan
              # A plan that neither builds a root nor mounts still runs its
              # hooks before the user process.
              start_stage
              announce_readiness(host_start_time)
              raise exec_workload
            # ScriptError too: a LoadError that escaped left this raw clone3
            # child in the interpreter's exit path, parked on a futex for ever
            # with the readiness pipe open, and the gate release waiting on it.
            rescue StandardError, ScriptError => error
              report_failure(error)
            end
          end

          private

          # The first instructions of the clone3 child.  Nothing here can report
          # a failure yet, so a failure is an immediate _exit(2).
          def bind_to_wrapper(expected_parent_pid)
            result = PRCTL.call(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)
            # Traced by the wrapper, which moves this process into the
            # container's cgroup at the stop after execve (before any seccomp
            # profile could refuse ptrace).
            IMMEDIATE_EXIT.call(127) if @trace_exec && ProcessGateAdapter::PTRACE.call(ProcessGateAdapter::PTRACE_TRACEME, 0, nil, nil) == -1
            parent_pid = GETPPID.call
            # A PID-namespace init cannot see its parent in the outer
            # namespace and getppid(2) therefore returns zero. PR_SET_PDEATHSIG
            # still tracks that real parent across the namespace boundary.
            visible_parent = parent_pid == Integer(expected_parent_pid) || parent_pid.zero?
            IMMEDIATE_EXIT.call(127) if result == -1 || !visible_parent
          end

          def install_stdio
            @stdio.each_with_index do |source, target|
              IMMEDIATE_EXIT.call(127) if DUP2.call(source, target) == -1
            end
            return unless @controlling_tty

            # A new session whose controlling terminal is the pty on fd 0,
            # so shells get job control and SIGHUP on hangup.
            SETSID.call
            IMMEDIATE_EXIT.call(127) if IOCTL.call(0, TIOCSCTTY, 0) == -1
          end

          def apply_security_plan
            context = @plan.context
            # A plan without a mount step still execs a verified descriptor:
            # when a rootfs was requested the filesystem transition happens
            # here (a security plan without steps is the Unconfined case),
            # and the executable is opened before any step can restrict the
            # filesystem view.
            prepare_without_mount_step(context) unless plan_step?(:mount)
            @plan.steps.each { |step| apply_step(step, context) }
          end

          def plan_step?(name)
            @plan.steps.any? { |step| step.name.to_sym == name }
          end

          def prepare_without_mount_step(context)
            if @build_rootfs
              enter_namespaces unless plan_step?(:namespace)
              enter_root(context)
            end
            open_workload_executable
          end

          def apply_step(step, context)
            name = step.name.to_sym
            # Hooks run before the process gives up any privilege.
            start_stage unless %i[namespace mount].include?(name)
            case name
            when :namespace
              enter_namespaces
            when :mount
              enter_root(context)
              open_workload_executable
            when :lsm
              # procfs descriptors are opened before Landlock removes the
              # right to open them; a seq_file re-read from offset zero
              # still reports the final state at readiness time.
              open_readiness_sources
              @security.apply(step: step.name, context: context, program: @plan.seccomp_program)
            else
              @security.apply(step: step.name,
                              context: context.with(fd_allowlist: context.fd_allowlist + [@executable&.fileno].compact),
                              program: @plan.seccomp_program)
            end
          end

          # The filesystem transition, with the OCI stages on either side of it.
          def enter_root(context)
            create_stage
            build_filesystem(context)
            start_stage
          end

          def open_workload_executable
            @executable, @executable_digest, @executable_info = @security.open_executable(@command.fetch(0), @env["PATH"])
            @security.prepare_fd_directory
          end

          def announce_readiness(host_start_time)
            payload = JSON.generate(readiness_metadata)
            @status.write("R" + [@host_pid, host_start_time].pack("Q<2") + @executable_digest + [payload.bytesize].pack("L<") + payload)
            @status.flush
            # Keep the readiness pipe open until the final exec succeeds.
            # close-on-exec gives the parent an EOF on success; when exec
            # fails, the rescue path can still append an error marker.
            @status.close_on_exec = true
          end

          # execveat(2) comes back only when it failed, with the error to raise.
          # A "#!" script runs by its path (SecurityAdapter#open_executable).
          def exec_workload
            argv = pointer_vector(@command.map { |value| c_string(value) })
            envp = pointer_vector(@env.compact.sort_by { |key, _| key }.map { |key, value| c_string("#{key}=#{value}") })
            if @executable_info&.fetch(:script)
              @pivot.execveat_path(path: @executable_info.fetch(:path), argv: argv, envp: envp, resource_id: "workload:execveat")
            else
              @pivot.execveat(fd: @executable.fileno, argv: argv, envp: envp, resource_id: "workload:execveat")
            end
          end

          # The process ends here whether or not the report could be written.
          def report_failure(error)
            location = Array(error.backtrace).first(3).join(" <- ")
            @status.write("E#{error.class}: #{error.message} [#{location}]")
            @status.flush
          ensure
            IMMEDIATE_EXIT.call(127)
          end

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
      end
    end
  end
end
