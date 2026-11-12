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
            payload = exec_supervisor_payload(plan, id, identity)
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

            register(supervised_handle(response, plan, id, identity, supervisor_pid))
          rescue JSON::ParserError, KeyError, ArgumentError, TypeError, SystemCallError => error
            terminate_process(supervisor_pid) if supervisor_pid
            raise EffectError, "namespace exec supervisor failed: #{error.message}"
          ensure
            reader&.close unless reader&.closed?
            writer&.close unless writer&.closed?
          end

          private

          def exec_supervisor_payload(plan, id, identity)
            parent_pid = Process.pid
            JSON.generate(
              "parent_pid" => parent_pid,
              "parent_start_time" => process_start_time(parent_pid),
              "id" => String(id),
              "identity" => String(identity),
              "namespaces" => Array(plan.namespaces).map(&:to_s),
              "user_mapping" => plan.user_mapping,
              "hostname" => plan.hostname
            )
          end

          # The agent's handle for a holder its supervisor reported: the pidfd is
          # opened here, everything else is what the supervisor read back.
          def supervised_handle(response, plan, id, identity, supervisor_pid)
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
              user_mapping: response["user_mapping"]
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
