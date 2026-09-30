# frozen_string_literal: true

require "fileutils"
require "json"

module Rubernetes
  module Runtime
    class Native
      # OCI runtime-spec config.md "POSIX-platform Hooks", as CDI
      # containerEdits carry them ({hookName, path, args, env, timeout}).
      #
      # Stages and where they run (runc's behaviour):
      #   prestart, createRuntime -- the runtime namespace, once the container
      #     namespaces exist and before the root is pivoted;
      #   createContainer -- the container namespaces, before the root is
      #     pivoted (the path resolves in the runtime's filesystem view);
      #   startContainer -- the container namespaces and root, before the
      #     user process is executed;
      #   poststart -- the runtime namespace, after the user process started;
      #   poststop -- the runtime namespace, when the container is deleted.
      #
      # Each hook reads the container state on stdin.  A failing hook before
      # the user process runs fails the container; poststart and poststop
      # failures are only reported.
      module Hooks
        STAGES = %w[prestart createRuntime createContainer startContainer poststart poststop].freeze
        RUNTIME_CREATE = %w[prestart createRuntime].freeze
        IN_CONTAINER = %w[createContainer startContainer].freeze
        # The state status each stage sees (runc).
        STATUS = {"prestart" => "creating", "createRuntime" => "creating", "createContainer" => "creating",
                  "startContainer" => "created", "poststart" => "running", "poststop" => "stopped"}.freeze
        OCI_VERSION = "1.2.0"
        OUTPUT_LIMIT = 4096

        class Error < StandardError; end

        module_function

        # CDI Hook#Validate: a known hook name, a non-empty path, and
        # environment entries in NAME=value form.  Returns
        # {stage => [{"path", "args", "env", "timeout"}]}, stages in order.
        def normalize(hooks)
          grouped = Hash.new { |hash, key| hash[key] = [] }
          Array(hooks).each do |hook|
            raise Error, "invalid hook #{hook.inspect}" unless hook.is_a?(Hash)

            stage = (hook["hookName"] || hook[:hookName]).to_s
            raise Error, "invalid hook name #{stage.dump}" unless STAGES.include?(stage)

            path = (hook["path"] || hook[:path]).to_s
            raise Error, "invalid hook #{stage.dump} with empty path" if path.empty?
            raise Error, "invalid hook #{stage.dump}: path #{path.dump} is not absolute" unless path.start_with?("/")

            env = Array(hook["env"] || hook[:env]).map(&:to_s)
            env.each do |entry|
              unless entry.match?(/\A[^=\0]+=/)
                raise Error,
                      "invalid hook #{stage.dump}: environment variable #{entry.dump} is not NAME=value"
              end
            end
            args = Array(hook["args"] || hook[:args]).map(&:to_s)
            raise Error, "invalid hook #{stage.dump}: argument contains NUL" if (args + env + [path]).any? { |value| value.include?("\0") }

            timeout = hook["timeout"] || hook[:timeout]
            unless timeout.nil?
              timeout = Integer(timeout, exception: false)
              raise Error, "invalid hook #{stage.dump}: timeout must be a positive number of seconds" if timeout.nil? || timeout <= 0
            end
            grouped[stage] << {"path" => path, "args" => args, "env" => env, "timeout" => timeout}
          end
          STAGES.each_with_object({}) { |stage, result| result[stage] = grouped[stage] if grouped.key?(stage) }
        end

        # The OCI state (runtime.md "State").
        def state(id:, status:, pid:, bundle:, annotations: {})
          value = {"ociVersion" => OCI_VERSION, "id" => id.to_s, "status" => status.to_s, "bundle" => bundle.to_s,
                   "annotations" => annotations || {}}
          value["pid"] = Integer(pid) if pid && status.to_s != "stopped"
          value
        end

        # The bundle a hook finds through state.bundle: config.json with the
        # container's root, process and mounts (hooks such as nvidia-cdi-hook
        # read the root path from it).
        def write_bundle(directory, root:, process:, mounts:, annotations:, hooks:)
          FileUtils.mkdir_p(directory, mode: 0o700)
          config = {
            "ociVersion" => OCI_VERSION,
            "root" => {"path" => root.to_s},
            "process" => process,
            "mounts" => Array(mounts).map do |mount|
              {"destination" => mount["destination"].to_s, "type" => "bind", "source" => mount["source"].to_s,
               "options" => ["rbind", mount["readonly"] ? "ro" : "rw"]}
            end,
            "annotations" => annotations || {},
            "hooks" => hooks.transform_values { |list| list.map { |hook| hook.reject { |_key, value| value.nil? || value == [] } } }
          }
          path = File.join(directory, "config.json")
          File.write("#{path}.tmp", JSON.pretty_generate(config), perm: 0o600)
          File.rename("#{path}.tmp", path)
          directory
        end

        # Runs +hook+ in the calling process's namespaces with +state+ on
        # stdin.  args[0] is argv[0] (the OCI hook args include it); the
        # environment is exactly the hook's.
        def run(hook, state, stage:, index:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          argv = hook["args"].empty? ? [hook["path"]] : hook["args"]
          env = hook["env"].to_h { |entry| entry.split("=", 2) }
          input_reader, input_writer = IO.pipe
          output_reader, output_writer = IO.pipe
          begin
            pid = Process.spawn(env, [hook["path"], argv.first], *argv.drop(1), unsetenv_others: true, pgroup: true,
                                                                                in: input_reader, out: output_writer, err: output_writer, close_others: true, chdir: "/")
          rescue SystemCallError => error
            raise Error, "error running #{stage} hook ##{index}: #{error.message}"
          ensure
            input_reader.close
            output_writer.close
          end
          begin
            input_writer.write(JSON.generate(state))
          rescue Errno::EPIPE
            nil
          ensure
            input_writer.close
          end
          deadline = hook["timeout"] && (clock.call + hook["timeout"])
          output = +""
          status = nil
          until status
            ready = output_reader.closed? ? nil : IO.select([output_reader], nil, nil, 0.05)
            if ready
              begin
                chunk = output_reader.read_nonblock(4096)
                output << chunk if output.bytesize < OUTPUT_LIMIT
              rescue IO::WaitReadable
                nil
              rescue EOFError
                output_reader.close
              end
            end
            _, status = Process.waitpid2(pid, Process::WNOHANG)
            next if status

            sleep 0.01 if output_reader.closed?
            next unless deadline && clock.call >= deadline

            kill_group(pid)
            Process.waitpid2(pid)
            raise Error, "error running #{stage} hook ##{index}: #{hook["path"]} did not finish in #{hook["timeout"]}s#{detail(output)}"
          end
          drain(output_reader, output)
          unless status.success?
            code = status.exitstatus ? "exit status #{status.exitstatus}" : "signal #{status.termsig}"
            raise Error, "error running #{stage} hook ##{index}: #{hook["path"]}: #{code}#{detail(output)}"
          end
          true
        ensure
          output_reader.close if output_reader && !output_reader.closed?
        end

        # What the hook wrote before it exited; a descendant that kept the
        # pipe open is not waited for.
        def drain(reader, output)
          output << reader.read_nonblock(4096) until reader.closed? || output.bytesize >= OUTPUT_LIMIT
        rescue IO::WaitReadable, EOFError, IOError
          nil
        end

        def kill_group(pid)
          Process.kill(:KILL, -pid)
        rescue Errno::ESRCH, Errno::EPERM
          begin
            Process.kill(:KILL, pid)
          rescue Errno::ESRCH
            nil
          end
        end

        def detail(output)
          text = output.byteslice(0, OUTPUT_LIMIT).to_s.scrub.strip
          text.empty? ? "" : ", output: #{text}"
        end
      end
    end
  end
end
