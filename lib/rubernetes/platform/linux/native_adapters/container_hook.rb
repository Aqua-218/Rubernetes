# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
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
              raise EffectError, "waitpid on hook #{pid} failed: #{Fiddle.last_error}" if result == -1 && Fiddle.last_error != Errno::EINTR::Errno
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
      end
    end
  end
end
