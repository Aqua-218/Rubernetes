# frozen_string_literal: true

# Process and log lifecycle adapter for Native containers.  Pidfds are the
# stable process identity whenever the host provides them; numeric PIDs are
# retained only as an invocation parameter and never as ownership identity.

require "fileutils"
require "digest"
require "securerandom"
require "tmpdir"
require "time"

module Rubernetes
  module Platform
    module Linux
      class ProcessSupervisor
        class Error < StandardError; end
        class InvalidSpec < Error; end
        class Timeout < Error; end
        class Unsupported < Error; end

        MAX_RETAINED_LOGS = 4096

        Handle = Data.define(
          :id, :pid, :pidfd, :workload_pid, :workload_pidfd, :workload_start_time,
          :workload_executable_digest, :workload_creation_method, :workload_clone_flags,
          :workload_security,
          :command, :started_at, :gate, :stdin, :stdout, :stderr,
          :stdout_log, :stderr_log, :combined_log, :state, :exit_status, :term_signal, :cgroup
        ) do
          def running?
            state == :running
          end

          def stopped?
            state == :stopped
          end

          def to_h
            {
              "id" => id,
              "pid" => pid,
              "pidfd" => pidfd,
              "workload_pid" => workload_pid,
              "workload_pidfd" => workload_pidfd,
              "workload_start_time" => workload_start_time,
              "workload_executable_digest" => workload_executable_digest,
              "workload_creation_method" => workload_creation_method,
              "workload_clone_flags" => workload_clone_flags,
              "workload_security" => workload_security,
              "command" => command,
              "started_at" => started_at&.utc&.iso8601(6),
              "state" => state.to_s,
              "exit_status" => exit_status,
              "term_signal" => term_signal,
              "cgroup" => cgroup
            }
          end
        end
        WaitResult = Data.define(:exit_status, :term_signal, :code) do
          def to_h
            {"exit_status" => exit_status, "term_signal" => term_signal, "code" => code}
          end
        end
        Stats = Data.define(:process, :cgroup, :memory_events, :timestamp) do
          def to_h
            {
              "process" => process,
              "cgroup" => cgroup,
              "memory_events" => memory_events,
              "timestamp" => timestamp.utc.iso8601(6)
            }
          end
        end

        class LogRotator
          DEFAULT_MAX_BYTES = 10 * 1024 * 1024
          DEFAULT_MAX_FILES = 5

          def initialize(path:, max_bytes: DEFAULT_MAX_BYTES, max_files: DEFAULT_MAX_FILES, adapter: nil)
            @path = File.expand_path(String(path))
            @max_bytes = Integer(max_bytes)
            @max_files = Integer(max_files)
            raise ArgumentError, "max_bytes must be positive" unless @max_bytes.positive?
            raise ArgumentError, "max_files must be between 1 and 64" unless @max_files.between?(1, 64)

            @adapter = adapter
            @mutex = Mutex.new
            @clock = -> { Time.now.utc }
            # [absolute byte offset, time] of every append, oldest first.  The
            # CRI log format timestamps each line so the kubelet can answer
            # sinceTime/sinceSeconds; the file here holds raw bytes, so the
            # time of each write lives beside it instead.
            @written = 0
            @index = []
            FileUtils.mkdir_p(File.dirname(@path)) unless @adapter
          end

          MAX_INDEX_ENTRIES = 16_384

          attr_writer :clock

          attr_reader :path, :max_bytes, :max_files

          def append(bytes)
            payload = String(bytes).b
            return 0 if payload.empty?

            @mutex.synchronize do
              record_append_time(payload.bytesize)
              written = 0
              until payload.empty?
                current_size = size
                available = @max_bytes - current_size
                rotate_unlocked! if available <= 0
                chunk_size = [payload.bytesize, [available, @max_bytes].max].min
                chunk = payload.byteslice(0, chunk_size)
                write(chunk)
                written += chunk.bytesize
                payload = payload.byteslice(chunk.bytesize, payload.bytesize - chunk.bytesize) || "".b
                rotate_unlocked! if size >= @max_bytes && !payload.empty?
              end
              written
            end
          end

          def read(follow: false, since: nil, tail: nil, stop: nil, tick: nil, timestamps: false)
            snapshot = nil
            value = @mutex.synchronize do
              contents = (0...@max_files).to_a.reverse_each.filter_map do |index|
                file = index.zero? ? @path : "#{@path}.#{index}"
                next unless exists?(file)

                read_file(file)
              end.join
              snapshot = exists?(@path) ? read_file(@path) : "".b
              base = @written - contents.bytesize
              offset = since_offset(since, contents.bytesize)
              if offset
                contents = contents.byteslice(offset, contents.bytesize) || "".b
                base += offset
              end
              contents = stamp_lines(contents, base) if timestamps
              if tail
                lines = contents.lines
                contents = lines.last(Integer(tail)).join
              end
              contents
            end
            return value unless follow

            follow_from(value, snapshot, stop: stop, tick: tick, timestamps: timestamps)
          end

          # PodLogOptions.timestamps: every line starts with the RFC 3339
          # time it was written, as the CRI log format records it.
          def stamp_lines(contents, base)
            offset = base
            contents.lines.map do |line|
              stamped = "#{written_at(offset).utc.iso8601(9)} ".b + line
              offset += line.bytesize
              stamped
            end.join.b
          end

          def written_at(offset)
            entry = @index.reverse_each.find { |start, _at| start <= offset }
            entry ? entry[1] : (@index.first&.last || @clock.call)
          end

          # A followed log ends when `stop` reports the writer gone (after a
          # final read), the way `kubectl logs -f` returns once the container
          # exits; `tick` runs before every poll so the owner can drain the
          # process pipes into the file.  `value` is what the caller sees
          # first (possibly tailed or offset); `snapshot` is the current file
          # deltas are measured against.
          # A followed log whose reader goes away must end.  Returning a bare
          # Enumerator gave the stream no lifecycle: `stop` only reports the
          # WRITER (the container) gone, so an idle log being followed by a
          # client that has disconnected polled at 10Hz for the life of the
          # process.  Node::Service::Stream#close_endpoint closes a source
          # that answers #close, which is how the transport ends a stream when
          # the peer disconnects -- a bare Enumerator silently ignored it.
          class FollowStream
            include Enumerable

            def initialize(initial, snapshot, rotator, stop: nil, tick: nil, timestamps: false)
              @initial = initial
              @snapshot = snapshot
              @rotator = rotator
              @stop = stop
              @tick = tick
              @timestamps = timestamps
              @line_start = initial.nil? || initial.empty? || initial.end_with?("\n")
              @mutex = Mutex.new
              @closed = false
            end

            def each
              return to_enum(:each) unless block_given?

              yield @initial unless @initial.nil? || @initial.empty?
              value = @snapshot
              loop do
                break if closed?

                @tick&.call
                finished = @stop&.call
                next_value = @rotator.contents
                if next_value.bytesize > value.bytesize
                  delta = next_value.byteslice(value.bytesize, next_value.bytesize - value.bytesize)
                  yield stamp(delta)
                  value = next_value
                elsif next_value.bytesize < value.bytesize
                  # Rotated underneath us: continue from the new file.
                  yield stamp(next_value) unless next_value.empty?
                  value = next_value
                end
                break if finished
                break if closed?

                sleep 0.1
              end
              self
            end

            # A followed delta is stamped when it is observed, at most one
            # poll (100 ms) after it was written; a line split across polls is
            # stamped once, where it starts.
            def stamp(chunk)
              return chunk unless @timestamps

              now = "#{Time.now.utc.iso8601(9)} ".b
              chunk.b.lines.map do |line|
                stamped = @line_start ? now + line : line
                @line_start = line.end_with?("\n")
                stamped
              end.join.b
            end

            def closed?
              @mutex.synchronize { @closed }
            end

            def close
              @mutex.synchronize { @closed = true }
              self
            end
          end

          def follow_from(initial, snapshot, stop: nil, tick: nil, timestamps: false)
            FollowStream.new(initial, snapshot, self, stop: stop, tick: tick, timestamps: timestamps)
          end

          # The current contents of the live log file, for a follower.
          def contents
            @mutex.synchronize { read_file(@path) }
          end

          def bytesize
            @mutex.synchronize { size }
          end

          def rotate!
            @mutex.synchronize { rotate_unlocked! }
            true
          end

          private

          def size
            return Integer(@adapter.size(@path)) if @adapter&.respond_to?(:size)
            return File.size(@path) if File.exist?(@path)

            0
          end

          def exists?(path)
            @adapter ? @adapter.exists?(path) : File.exist?(path)
          end

          def record_append_time(bytes)
            now = @clock.call
            last = @index.last
            @index << [@written, now] unless last && last[1] == now
            @index.shift while @index.length > MAX_INDEX_ENTRIES
            @written += bytes
          end

          # An Integer is a byte offset (the runtime resuming its own stream);
          # a Time or timestamp string is sinceTime: the log from the first
          # write at or after it.  Bytes older than the index -- written before
          # this process, or evicted from it -- predate any time asked for.
          def since_offset(since, available)
            case since
            when nil then nil
            when Integer then since
            else
              time = since.is_a?(Time) ? since : Time.iso8601(since.to_s)
              base = @written - available
              entry = @index.find { |_offset, at| at >= time }
              return available if entry.nil?

              (entry[0] - base).clamp(0, available)
            end
          rescue ArgumentError
            raise Error, "since must be a byte offset or an RFC 3339 time: #{since.inspect}"
          end

          def read_file(path)
            return String(@adapter.read(path)).b if @adapter
            File.binread(path)
          rescue Errno::ENOENT
            "".b
          end

          def write(payload)
            if @adapter
              @adapter.append(@path, payload)
            else
              File.open(@path, File::WRONLY | File::CREAT | File::APPEND, 0o600) { |file| file.write(payload) }
            end
          end

          def rotate_unlocked!
            if @adapter
              @adapter.rotate(path: @path, max_files: @max_files)
              return true
            end

            (@max_files - 1).downto(1) do |index|
              source = index == 1 ? @path : "#{@path}.#{index - 1}"
              destination = "#{@path}.#{index}"
              File.delete(destination) if File.exist?(destination)
              File.rename(source, destination) if File.exist?(source)
            end
            File.open(@path, File::WRONLY | File::CREAT | File::TRUNC, 0o600) { |file| file.flush; file.fsync }
          end
        end

        class ForkAdapter
          def spawn(command:, env: {}, cwd: nil, gate: true, stdin: false, tty: false, **_options)
            gate_reader, gate_writer = IO.pipe
            # stdin is /dev/null unless the container asked for one (CRI
            # semantics): an open pipe nobody writes to keeps `sh` waiting
            # for input for ever instead of exiting at EOF.
            if stdin || tty
              stdin_reader, stdin_writer = IO.pipe
            else
              stdin_reader = File.open(File::NULL, File::RDONLY)
              stdin_writer = nil
            end
            stdout_reader, stdout_writer = IO.pipe
            stderr_reader, stderr_writer = IO.pipe
            child_pid = Process.fork do
              # Between fork and exec this child still runs the supervisor's
              # Ruby signal handlers.  A workload stopped while it waits on the
              # gate must die, not run the agent's shutdown path.
              %w[INT TERM HUP QUIT].each do |name|
                begin
                  Signal.trap(name, "DEFAULT")
                rescue ArgumentError
                  nil
                end
              end
              gate_writer.close
              stdin_writer&.close
              stdout_reader.close
              stderr_reader.close
              gate_reader.read(1) if gate
              gate_reader.close
              # The workload leads its own process group, as runc does.  Sharing
              # the supervisor's group means any group-directed signal aimed at
              # the container also reaches the node agent that owns it.
              begin
                Process.setsid
              rescue SystemCallError
                nil
              end
              exec_options = {in: stdin_reader, out: stdout_writer, err: stderr_writer}
              exec_options[:chdir] = cwd if cwd
              Process.exec(env, *command, **exec_options)
            rescue SystemCallError
              exit!(127)
            ensure
              stdin_reader&.close
              stdout_writer&.close
              stderr_writer&.close
            end
            gate_reader.close
            stdin_reader.close
            stdout_writer.close
            stderr_writer.close
            {pid: child_pid, pidfd: nil, gate: gate_writer, stdin: stdin_writer, stdout: stdout_reader, stderr: stderr_reader}
          rescue SystemCallError => error
            [gate_reader, gate_writer, stdin_reader, stdin_writer, stdout_reader, stdout_writer,
             stderr_reader, stderr_writer].compact.each(&:close)
            raise Error, "failed to spawn process: #{error.message}"
          end

          def release_gate(gate)
            gate.write("1")
            gate.close
            true
          end

          def wait(pid:, timeout: nil)
            deadline = timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout)
            loop do
              result = Process.waitpid2(pid, Process::WNOHANG)
              return result && result.last if result
              if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
                return nil
              end
              sleep 0.01
            end
          rescue Errno::ECHILD
            nil
          end

          def signal(pid:, signal:)
            Process.kill(signal, pid)
            true
          end
        end

        def initialize(process_adapter: ForkAdapter.new, pidfd_adapter: nil, cgroup: nil, stats_reader: nil,
                       log_directory: Dir.tmpdir, max_log_bytes: LogRotator::DEFAULT_MAX_BYTES,
                       max_log_files: LogRotator::DEFAULT_MAX_FILES, clock: -> { Time.now.utc })
          @process_adapter = process_adapter
          @pidfd_adapter = pidfd_adapter
          @cgroup = cgroup
          @stats_reader = stats_reader || method(:default_stats)
          @log_directory = File.expand_path(String(log_directory))
          @max_log_bytes = Integer(max_log_bytes)
          @max_log_files = Integer(max_log_files)
          @clock = clock
          @mutex = Mutex.new
          @handles = {}
          @closed_logs = {}
        end

        attr_reader :handles

        # Production gate adapters apply the security plan in the child after
        # namespace entry and before exec.  Pure adapters return false and
        # retain the deterministic parent-side contract used by unit tests.
        def security_applied_in_child?
          @process_adapter.respond_to?(:security_applied_in_child?) && @process_adapter.security_applied_in_child?
        end

        # OCI hooks at their stages inside the container (see
        # ProcessGateAdapter#runs_container_hooks?).
        def runs_container_hooks?
          @process_adapter.respond_to?(:runs_container_hooks?) && @process_adapter.runs_container_hooks?
        end

        # Exposes only handles owned by this supervisor.  The Native runtime
        # adds workload identity and liveness metadata before presenting this
        # inventory to startup reconciliation.
        def resources
          @mutex.synchronize { @handles.values.map(&:to_h).freeze }
        end

        def spawn(command:, env: {}, cwd: nil, security_plan: nil, resource_id: nil, gate: true, id: nil, **options)
          normalized = normalize_command(command)
          normalized_env = normalize_environment(env)
          normalized_cwd = cwd && File.expand_path(String(cwd))
          process = call_spawn(normalized, normalized_env, normalized_cwd, gate, security_plan, options)
          pid = Integer(fetch_value(process, :pid))
          pidfd = fetch_value(process, :pidfd)
          pidfd ||= open_pidfd(pid, resource_id || "process:#{pid}") if @pidfd_adapter
          handle_id = String(id || resource_id || "process-#{Process.pid}-#{SecureRandom.hex(8)}")
          log_root = File.join(@log_directory, handle_id)
          handle = Handle.new(
            id: handle_id.freeze,
            pid: pid,
            pidfd: pidfd && Integer(pidfd),
            workload_pid: fetch_value(process, :workload_pid),
            workload_pidfd: fetch_value(process, :workload_pidfd),
            workload_start_time: fetch_value(process, :workload_start_time),
            workload_executable_digest: fetch_value(process, :workload_executable_digest),
            workload_creation_method: fetch_value(process, :workload_creation_method),
            workload_clone_flags: fetch_value(process, :workload_clone_flags),
            workload_security: fetch_value(process, :workload_security),
            command: normalized.freeze,
            started_at: @clock.call.utc,
            gate: fetch_value(process, :gate),
            stdin: fetch_value(process, :stdin),
            stdout: fetch_value(process, :stdout),
            stderr: fetch_value(process, :stderr),
            stdout_log: LogRotator.new(path: File.join(log_root, "stdout.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
            stderr_log: LogRotator.new(path: File.join(log_root, "stderr.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
            # What `kubectl logs` returns.  A container's log is BOTH streams:
            # the CRI writes one file per container and tags each line with the
            # stream it came from (kubelet ReadLogs parses that tag), and the
            # Pod log API has no way to ask for only one of them.  Keeping them
            # apart and serving stdout alone meant every diagnostic a workload
            # writes to stderr was invisible -- "[sig-node] Security Context
            # should run the container as unprivileged" reads the log for the
            # "Operation not permitted" that `ip link add` prints to stderr,
            # and read an empty log.
            combined_log: LogRotator.new(path: File.join(log_root, "container.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
            state: :created,
            exit_status: nil,
            term_signal: nil,
            cgroup: fetch_value(process, :cgroup)
          )
          @mutex.synchronize { @handles[handle.id] = handle }
          handle
        rescue ArgumentError, TypeError => error
          raise InvalidSpec, "invalid process specification: #{error.message}"
        end

        alias create spawn

        def release_gate(handle)
          current = lookup(handle)
          gate = current.gate
          if gate && @process_adapter.respond_to?(:release_gate)
            @process_adapter.release_gate(gate)
          elsif gate.respond_to?(:write)
            gate.write("1")
            gate.close if gate.respond_to?(:close)
          end
          workload_pid = fetch_value(gate, :workload_pid)
          workload_start_time = fetch_value(gate, :workload_start_time)
          workload_executable_digest = fetch_value(gate, :workload_executable_digest)
          workload_executable_digest ||= executable_digest(workload_pid) if workload_pid
          workload_security = fetch_value(gate, :workload_security)
          workload_pidfd = current.workload_pidfd
          if workload_pid && workload_pidfd.nil? && @pidfd_adapter
            workload_pidfd = open_live_workload_pidfd(
              workload_pid,
              workload_start_time,
              "process:#{current.id}:workload"
            )
          end
          update(current, state: :running, workload_pid: workload_pid || current.workload_pid,
                 workload_pidfd: workload_pidfd, workload_start_time: workload_start_time || current.workload_start_time,
                 workload_executable_digest: workload_executable_digest || current.workload_executable_digest,
                 workload_security: workload_security || current.workload_security)
        end

        # Re-adopt a live process discovered during startup reconciliation.
        # The caller must supply the durable start time and workload PID; a
        # numeric PID alone is never sufficient because it may have been
        # reused after the agent crashed.
        def adopt(metadata:, cgroup: nil)
          value = metadata.respond_to?(:to_h) ? metadata.to_h.transform_keys(&:to_s) : {}
          id = String(value.fetch("id") { raise Error, "process adoption requires an id" })
          pid = Integer(value.fetch("pid") { value.fetch("workload_pid") })
          workload_pid = Integer(value.fetch("workload_pid", pid))
          expected_start = value["workload_start_time"] || value["start_time"]
          raise Error, "process #{id} adoption requires a start time" if expected_start.nil?
          actual_start = process_start_time(workload_pid)
          raise Error, "process #{id} start time changed during adoption" unless actual_start == Integer(expected_start)
          expected_digest = value["workload_executable_digest"] || value["executable_digest"]
          raise Error, "process #{id} adoption requires an executable digest" if expected_digest.nil?
          actual_digest = executable_digest(workload_pid)
          raise Error, "process #{id} executable identity changed during adoption" unless actual_digest == String(expected_digest).downcase

          pidfd = @pidfd_adapter ? open_pidfd(pid, "process:adopt:#{id}") : value["pidfd"]
          workload_pidfd = if @pidfd_adapter && workload_pid != pid
            open_pidfd(workload_pid, "process:adopt:#{id}:workload")
          else
            pidfd
          end
          log_root = File.join(@log_directory, id)
          handle = Handle.new(
            id: id.freeze,
            pid: pid,
            pidfd: pidfd && Integer(pidfd),
            workload_pid: workload_pid,
            workload_pidfd: workload_pidfd && Integer(workload_pidfd),
            workload_start_time: actual_start,
            workload_executable_digest: actual_digest,
            workload_creation_method: value["workload_creation_method"],
            workload_clone_flags: value["workload_clone_flags"],
            workload_security: value["workload_security"],
            command: Array(value["command"]).map(&:to_s).freeze,
            started_at: value["started_at"] && Time.iso8601(String(value["started_at"])).utc,
            gate: nil,
            stdin: nil,
            stdout: nil,
            stderr: nil,
            stdout_log: LogRotator.new(path: File.join(log_root, "stdout.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
            stderr_log: LogRotator.new(path: File.join(log_root, "stderr.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
            # Spawned handles gained the interleaved container.log; an adopted
            # one (after an agent restart) was never given it, so Handle.new
            # raised "missing keyword: :combined_log" and the restarted agent
            # could not adopt a single running container -- recovery failed
            # closed on every restart.
            combined_log: LogRotator.new(path: File.join(log_root, "container.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
            state: value["state"].to_s == "stopped" ? :stopped : :running,
            exit_status: value["exit_status"],
            term_signal: value["term_signal"],
            cgroup: cgroup
          )
          @mutex.synchronize do
            existing = @handles[id]
            return existing if existing

            @handles[id] = handle
          end
          handle
        rescue ArgumentError, TypeError, SystemCallError => error
          raise Error, "process adoption failed: #{error.message}"
        end

        alias start release_gate
        alias start_process release_gate

        def wait(handle, timeout: nil, resource_id: nil)
          current = lookup(handle)
          drain_logs(current)
          result = if current.pidfd && @pidfd_adapter
            @pidfd_adapter.wait(pidfd: current.pidfd, timeout: timeout, resource_id: resource_id || "process:#{current.id}")
          elsif @process_adapter.respond_to?(:wait)
            @process_adapter.wait(pid: current.pid, timeout: timeout)
          else
            raise Unsupported, "process adapter cannot wait for #{current.id}"
          end
          return nil unless result

          normalized = normalize_wait_result(result)
          if normalized.exit_status.nil? && normalized.term_signal.nil?
            raise Error, "process wait returned no exit confirmation for #{current.id}"
          end
          update(current, state: :stopped, exit_status: normalized.exit_status, term_signal: normalized.term_signal)
          normalized
        end

        def stop(handle, timeout: 5.0, signal: Signal.list.fetch("TERM"), resource_id: nil)
          current = lookup(handle)
          send_signal(current, signal, resource_id || "process:#{current.id}") if current.running? || current.state == :created
          result = wait(current, timeout: timeout, resource_id: resource_id)
          return result if result

          send_signal(current, Signal.list.fetch("KILL"), resource_id || "process:#{current.id}")
          result = wait(current, timeout: 5.0, resource_id: resource_id)
          raise Timeout, "process #{current.id} did not exit after SIGKILL" unless result

          result
        end

        alias stop_process stop

        def close(handle)
          id = handle.respond_to?(:id) ? String(handle.id) : String(handle)
          current = @mutex.synchronize { @handles.delete(id) }
          return true unless current

          drain_logs(current)
          @mutex.synchronize do
            @closed_logs[id] = {stdout: current.stdout_log, stderr: current.stderr_log,
                                combined: current.combined_log}
            @closed_logs.shift while @closed_logs.length > MAX_RETAINED_LOGS
          end
          [current.gate, current.stdin, current.stdout, current.stderr].compact.each do |io|
            next unless io.respond_to?(:close)

            io.close unless io.respond_to?(:closed?) && io.closed?
          rescue IOError
            nil
          end
          if current.pidfd && @pidfd_adapter
            if @pidfd_adapter.respond_to?(:close)
              @pidfd_adapter.close(pidfd: current.pidfd)
            else
              IO.for_fd(current.pidfd).close
            end
          end
          if current.workload_pidfd && @pidfd_adapter
            if @pidfd_adapter.respond_to?(:close)
              @pidfd_adapter.close(pidfd: current.workload_pidfd)
            else
              IO.for_fd(current.workload_pidfd).close
            end
          end
          true
        rescue Errno::EBADF
          true
        end

        # Logs outlive the process: a container that already exited (and whose
        # supervisor handle was closed after wait) must still serve its
        # captured stdout/stderr, exactly as `kubectl logs` does for a
        # terminated container.  The retained record holds only the log
        # readers; every process resource was released by close.
        def logs(handle, follow: false, since: nil, tail: nil, stream: :stdout, timestamps: false)
          id = handle.respond_to?(:id) ? String(handle.id) : String(handle)
          current = @mutex.synchronize { @handles[id] }
          if current
            drain_logs(current)
            log = log_for(current, stream)
            return log.read(follow: false, since: since, tail: tail, timestamps: timestamps) if follow && !current.running?

            return log.read(follow: follow, since: since, tail: tail, timestamps: timestamps,
                            tick: -> { drain_logs(@mutex.synchronize { @handles[id] } || current) },
                            stop: -> { !(@mutex.synchronize { @handles[id] })&.running? })
          end
          retained = @mutex.synchronize { @closed_logs.fetch(id) { raise Error, "unknown process handle #{id}" } }
          log = case stream.to_sym
                when :stderr then retained.fetch(:stderr)
                when :stdout then retained.fetch(:stdout)
                else retained[:combined] || retained.fetch(:stdout)
                end
          log.read(follow: false, since: since, tail: tail, timestamps: timestamps)
        end

        # :all -- both streams, which is what a container's log is -- unless
        # the caller asks for one by name.
        def log_for(handle, stream)
          case stream.to_sym
          when :stderr then handle.stderr_log
          when :stdout then handle.stdout_log
          else handle.combined_log || handle.stdout_log
          end
        end

        def stats(handle, resource_id: nil)
          current = lookup(handle)
          drain_logs(current)
          process_stats = @stats_reader.call(current.pid)
          cgroup_stats = @cgroup ? @cgroup.stats(current.cgroup) : {}
          events = @cgroup ? @cgroup.events(current.cgroup) : {}
          Stats.new(process: normalize_hash(process_stats), cgroup: normalize_stats(cgroup_stats), memory_events: events, timestamp: @clock.call.utc)
        rescue SystemCallError => error
          raise Error, "failed to collect process stats #{resource_id || current.id}: #{error.message}"
        end

        def alive?(handle)
          current = lookup(handle)
          return false if current.stopped?
          if current.pidfd && @pidfd_adapter
            if @pidfd_adapter.respond_to?(:alive?)
              alive = @pidfd_adapter.alive?(pidfd: current.pidfd)
              unless alive
                # A negative liveness result is only terminal after the same
                # pidfd yields an exit status; never infer exit from a stale
                # numeric PID.
                result = wait(current, timeout: 0, resource_id: "process:#{current.id}")
                raise Error, "pidfd reported an exit without a wait confirmation for #{current.id}" unless result
              end
              return !!alive
            end
            result = wait(current, timeout: 0, resource_id: "process:#{current.id}")
            return true unless result

            return false
          end

          Process.kill(0, current.pid)
          true
        rescue Errno::ESRCH
          false
        end

        private

        def lookup(value)
          id = value.respond_to?(:id) ? value.id : String(value)
          @mutex.synchronize { @handles.fetch(String(id)) { raise Error, "unknown process handle #{id}" } }
        end

        def update(handle, **changes)
          next_handle = handle.with(**changes)
          @mutex.synchronize { @handles[handle.id] = next_handle }
          next_handle
        end

        def normalize_command(command)
          values = Array(command).map { |argument| String(argument) }
          raise InvalidSpec, "command must contain an executable and at most 4096 arguments" unless values.length.between?(1, 4096)
          raise InvalidSpec, "command executable must not be empty" if values.first.empty?
          raise InvalidSpec, "command arguments must not contain NUL" if values.any? { |argument| argument.include?("\0") }

          # A bare program name is resolved on PATH by exec in the child, after
          # the namespace and root have been entered, so the lookup happens in
          # the container's filesystem.  Requiring an absolute path here instead
          # rejects the ordinary `command: ["sh", "-c", ...]` that images and the
          # conformance suite rely on, and the host has no view of the container
          # rootfs to resolve it in.
          values
        end

        def normalize_environment(environment)
          environment.to_h.each_with_object({}) do |(key, value), output|
            name = String(key)
            raise InvalidSpec, "environment variable name is invalid" unless name.match?(/\A[^=\0]+\z/)
            output[name] = String(value)
          end
        end

        def call_spawn(command, environment, cwd, gate, security_plan, options)
          kwargs = options.merge(command: command, env: environment, cwd: cwd, gate: gate, security_plan: security_plan)
          if @process_adapter.respond_to?(:spawn)
            @process_adapter.spawn(**kwargs)
          elsif @process_adapter.respond_to?(:call)
            @process_adapter.call(**kwargs)
          else
            raise Unsupported, "process adapter does not expose spawn"
          end
        end

        def fetch_value(value, key)
          return value.public_send(key) if value.respond_to?(key)
          return value.fetch(key) if value.respond_to?(:fetch) && value.key?(key)
          return value.fetch(key.to_s) if value.respond_to?(:fetch) && value.key?(key.to_s)

          nil
        end

        def open_pidfd(pid, resource_id)
          @pidfd_adapter.open(pid: pid, resource_id: resource_id)
        rescue NoMethodError
          raise Unsupported, "pidfd adapter must expose open"
        end

        # The trusted process gate records pid+starttime before exec. Very
        # short exec/port-forward helpers can exit before this supervisor gets
        # a second pidfd_open opportunity. Never attach to a reused numeric
        # PID: open only while the recorded identity is still live, and treat
        # ESRCH after an exact start-time check as a completed short process.
        # The wrapper process remains pidfd-owned and publishes the exit
        # status, so accepting nil here does not lose lifecycle ownership.
        def open_live_workload_pidfd(pid, expected_start_time, resource_id)
          return open_pidfd(pid, resource_id) if expected_start_time.nil?

          expected = Integer(expected_start_time)
          observed = current_process_start_time(pid)
          return nil unless observed == expected

          open_pidfd(pid, resource_id)
        rescue StandardError => error
          raise unless process_disappeared_error?(error)

          observed = current_process_start_time(pid)
          return nil unless observed == expected

          raise
        end

        def current_process_start_time(pid)
          process_start_time(pid)
        rescue Errno::ENOENT, Errno::ESRCH
          nil
        end

        # pidfd_open(2) reports a pid whose task has already been released as
        # EINVAL (pidfd_prepare: no PIDTYPE_TGID task) when another reference
        # still pins the struct pid, and as ESRCH once that reference is gone.
        # Both are the same "short workload already exited" race; the caller
        # re-checks the recorded start time before accepting either.
        def process_disappeared_error?(error)
          error.respond_to?(:errno) &&
            [Errno::ENOENT::Errno, Errno::ESRCH::Errno, Errno::EINVAL::Errno].include?(Integer(error.errno))
        rescue ArgumentError, TypeError
          false
        end

        # A pidfd names exactly one process and survives pid reuse, so it is
        # tried first.  Signalling a *group* derived from a recorded pid is the
        # dangerous path: if the workload shares a process group with the
        # supervisor -- or the pid has been recycled -- stopping a container
        # signals the node agent itself, which is precisely how a conformance
        # run used to take its own node down.
        #
        # A container's process is its workload, not the wrapper that forked
        # it and waits for it: runc signals the container's init, and so does
        # this.  The wrapper is a fork of the agent that still carries the
        # agent's Ruby signal handlers, so a SIGTERM aimed at it was swallowed
        # and every stop sat out the whole grace period before SIGKILL --
        # deleting any Pod took terminationGracePeriodSeconds (30 s) where
        # kubelet takes the workload's own shutdown time.  The wrapper exits
        # with its workload, so a catchable signal goes to the workload alone;
        # SIGKILL also reaches the wrapper, and a workload already gone falls
        # back to the wrapper.
        def send_signal(handle, signal, resource_id)
          if handle.workload_pidfd && @pidfd_adapter
            begin
              @pidfd_adapter.send_signal(pidfd: handle.workload_pidfd, signal: Integer(signal), resource_id: "#{resource_id}:workload")
              return true unless Integer(signal) == Signal.list.fetch("KILL")
            rescue StandardError => error
              raise unless process_disappeared_error?(error)
            end
          end
          if handle.pidfd && @pidfd_adapter
            @pidfd_adapter.send_signal(pidfd: handle.pidfd, signal: Integer(signal), resource_id: resource_id)
          elsif @process_adapter.respond_to?(:signal)
            @process_adapter.signal(pid: handle.pid, signal: Integer(signal))
          elsif @process_adapter.respond_to?(:signal_group)
            # Last resort only: a group derived from a recorded pid can include
            # this supervisor, and after pid reuse can be someone else entirely.
            @process_adapter.signal_group(pid: handle.pid, signal: Integer(signal))
          else
            raise Unsupported, "process adapter cannot signal #{handle.id}"
          end
        end

        def normalize_wait_result(value)
          return value if value.is_a?(WaitResult)
          if value.respond_to?(:exit_status)
            return WaitResult.new(exit_status: value.exit_status, term_signal: value.term_signal, code: value.respond_to?(:code) ? value.code : nil)
          end
          if value.is_a?(Process::Status)
            return WaitResult.new(exit_status: value.exited? ? value.exitstatus : nil, term_signal: value.signaled? ? value.termsig : nil, code: value.to_i)
          end
          hash = value.respond_to?(:to_h) ? value.to_h : {}
          WaitResult.new(
            exit_status: hash[:exit_status] || hash["exit_status"],
            term_signal: hash[:term_signal] || hash["term_signal"],
            code: hash[:code] || hash["code"]
          )
        end

        def drain_logs(handle)
          {
            stdout: handle.stdout_log,
            stderr: handle.stderr_log
          }.each do |stream, log|
            io = stream == :stdout ? handle.stdout : handle.stderr
            next unless io

            loop do
              chunk = io.read_nonblock(16 * 1024)
              log.append(chunk)
              # The combined log is written in drain order, which is the order
              # the two streams actually arrived in -- the interleaving a
              # reader of the container's log expects.
              handle.combined_log&.append(chunk)
            rescue IO::WaitReadable, EOFError, IOError
              break
            end
          end
        end

        def default_stats(pid)
          path = "/proc/#{Integer(pid)}/stat"
          fields = File.read(path).split
          {"pid" => Integer(fields.fetch(0)), "state" => fields.fetch(2), "utime" => Integer(fields.fetch(13)), "stime" => Integer(fields.fetch(14))}
        end

        def process_start_time(pid)
          stat = File.read("/proc/#{Integer(pid)}/stat")
          Integer(stat[stat.rindex(")") + 1..].split.fetch(19))
        end

        def executable_digest(pid)
          path = "/proc/#{Integer(pid)}/exe"
          digest = Digest::SHA256.file(path).hexdigest
          "sha256:#{digest}"
        rescue SystemCallError, ArgumentError => error
          raise Error, "process executable identity could not be read: #{error.message}"
        end

        def normalize_hash(value)
          value.respond_to?(:to_h) ? value.to_h : {}
        end

        def normalize_stats(value)
          return value.to_h if value.respond_to?(:to_h)
          {}
        end
      end

    end
  end
end
