# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Holder creation for a threaded caller: a single-threaded supervisor
        # process, started on demand or taken from a pre-spawned pool, runs
        # #create_direct and owns the holder.
        class NamespaceAdapter
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
              pidfds = adapter.instance_variable_get(:@pidfd)
              # PDEATHSIG targets the native thread that spawned this process.
              # Pod workers may retire while their Pod and the agent live on.
              agent_process = IO.for_fd(pidfds.open(pid: parent_pid), autoclose: false)
              unless adapter.send(:process_start_time, parent_pid) == parent_start_time && !agent_process.wait_readable(0)
                raise "agent process disappeared before namespace setup"
              end
              # The holder inherits this runtime-owned service cgroup so a
              # systemd signal to the kubelet unit never reaches the runtime.
              # Until commit the agent pidfd below still guards both processes.
              if (cgroup = payload["supervisor_cgroup"])
                File.open(File.join(cgroup, "cgroup.procs"), File::WRONLY | File::NOFOLLOW) { |file| file.write(Process.pid.to_s) }
              end
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
              holder_process = IO.for_fd(handle.pidfd, autoclose: false)
              durable = false
              if payload["durable"]
                ready = IO.select([agent_process, holder_process, STDIN]).first
                if ready.include?(STDIN) && !ready.include?(agent_process) && STDIN.read(1) == "C"
                  durable = true
                  begin
                    STDOUT.write("C")
                    STDOUT.flush
                  rescue Errno::EPIPE
                    # The marker was sent only after the durable commit.
                    durable = true
                  end
                end
              end
              if !durable && IO.select([agent_process, holder_process]).first == [agent_process]
                begin
                  pidfds.send_signal(pidfd: handle.pidfd, signal: Signal.list.fetch("KILL"), resource_id: handle.identity)
                rescue Rubernetes::Platform::Linux::Error => error
                  raise unless error.errno == Errno::ESRCH::Errno
                end
              end
              STDIN.close
              STDOUT.close
              Process.wait(handle.pid)
              exit!(0)
            rescue StandardError => error
              unless STDOUT.closed?
                STDOUT.write(JSON.generate("ok" => false, "error" => "#{error.class}: #{error.message}") << "\n")
                STDOUT.flush
              end
              exit!(127)
            end
          RUBY

          # Idle exec supervisors started ahead of time (a microVM guest
          # pre-spawns them before the base snapshot so a restored VM never
          # pays the Ruby start-up of the holder).  Each entry is
          # [pid, stdin_writer, stdout_reader].
          POOL_MUTEX = Mutex.new
          CommitChannel = Struct.new(:writer, :reader, :committed)
          @supervisor_pool = []

          class << self
            def prespawn_exec_supervisors(count, ruby_library_root: nil)
              root = ruby_library_root || new.send(:ruby_library_root)
              count.times do
                reader, writer = IO.pipe
                input_reader, input_writer = IO.pipe
                pid = Process.spawn(
                  RbConfig.ruby, "--disable-gems", "-I", root, "-e", NAMESPACE_EXEC_SUPERVISOR_SOURCE,
                  in: input_reader, out: writer, err: File::NULL
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

          def create_through_exec_supervisor(plan:, id:, identity:, durable:)
            payload = exec_supervisor_payload(plan, id, identity, durable)
            pooled = self.class.take_exec_supervisor
            if pooled
              supervisor_pid, input_writer, reader = pooled
              input_writer.write(payload + "\n")
            else
              reader, writer = IO.pipe
              input_reader, input_writer = IO.pipe if durable
              # The exec supervisor needs only the platform layer and the JSON
              # default gem; skipping RubyGems initialization removes most of
              # its startup cost (a microVM guest runs it on one vCPU).
              supervisor_pid = Process.spawn(
                RbConfig.ruby, "--disable-gems", "-I", ruby_library_root, "-e", NAMESPACE_EXEC_SUPERVISOR_SOURCE,
                payload, in: input_reader || File::NULL, out: writer, err: File::NULL
              )
              writer.close
              input_reader&.close
            end
            raise EffectError, "namespace exec supervisor did not report readiness" unless reader.wait_readable(10)

            response = JSON.parse(reader.gets.to_s)
            unless response["ok"] == true
              raise EffectError, response["error"].to_s.empty? ? "namespace exec supervisor failed" : response["error"]
            end

            channel = CommitChannel.new(input_writer, reader, false) if durable
            handle = register(supervised_handle(response, plan, id, identity, supervisor_pid, channel))
            input_writer = reader = nil if channel
            handle
          rescue JSON::ParserError, KeyError, ArgumentError, TypeError, SystemCallError, EffectError => error
            terminate_process(supervisor_pid) if supervisor_pid
            raise EffectError, "namespace exec supervisor failed: #{error.message}"
          ensure
            reader&.close unless reader&.closed?
            writer&.close unless writer&.closed?
            input_writer&.close unless input_writer&.closed?
            input_reader&.close unless input_reader&.closed?
          end

          def commit(handle)
            channel = handle.commit_channel
            return true unless channel

            writer = channel.writer
            reader = channel.reader
            return channel.committed if writer.closed?

            writer.write("C")
            channel.committed = reader.wait_readable(5) && reader.read(1) == "C"
          rescue Errno::EPIPE, IOError
            false
          ensure
            [writer, reader].compact.reject(&:closed?).each(&:close)
          end

          private

          def exec_supervisor_payload(plan, id, identity, durable)
            parent_pid = Process.pid
            JSON.generate(
              "parent_pid" => parent_pid,
              "parent_start_time" => process_start_time(parent_pid),
              "id" => String(id),
              "identity" => String(identity),
              "durable" => durable,
              "supervisor_cgroup" => durable ? prepare_supervisor_cgroup : nil,
              "namespaces" => Array(plan.namespaces).map(&:to_s),
              "user_mapping" => plan.user_mapping,
              "hostname" => plan.hostname
            )
          end

          def prepare_supervisor_cgroup
            return unless @supervisor_cgroup

            Dir.mkdir(@supervisor_cgroup)
            @supervisor_cgroup
          rescue Errno::EEXIST
            @supervisor_cgroup
          end

          # The agent's handle for a holder its supervisor reported: the pidfd is
          # opened here, everything else is what the supervisor read back.
          def supervised_handle(response, plan, id, identity, supervisor_pid, channel)
            pid = Integer(response.fetch("pid"))
            Handle.new(
              id: String(id).freeze,
              identity: String(identity).freeze,
              pid: pid,
              pidfd: @pidfd.open(pid: pid, resource_id: String(identity)),
              supervisor_pid: supervisor_pid,
              namespaces: Array(response.fetch("namespaces")).map(&:to_sym).freeze,
              plan: plan,
              start_time: Integer(response.fetch("start_time")),
              namespace_links: response.fetch("namespace_links").freeze,
              creation_method: "clone3",
              clone_flags: Integer(response.fetch("clone_flags")),
              user_mapping: response["user_mapping"], commit_channel: channel
            )
          end

          def ruby_library_root
            @ruby_library_root ||= begin
              load_path = $LOAD_PATH.find { |path| File.file?(File.join(path, "rubernetes", "platform", "linux.rb")) }
              load_path || File.expand_path("../../..", __dir__)
            end
          end
        end
      end
    end
  end
end
