# frozen_string_literal: true

module Rubernetes
  module Node
    module Plugins
      # One helper interpreter per kubelet gRPC endpoint. The owning server
      # serializes start and writes with its mutex; each reader owns its pipes.
      module HelperProcess
        def stop
          stop_helper
          self
        end

        private

        def spawn_helper(program, *)
          input, writer = IO.pipe
          reader, output = IO.pipe
          pid = Process.spawn(@ruby, "-e", program, *, in: input, out: output, err: File::NULL, pgroup: true)
          @pid = pid
          @stdin = writer
          @reader = Thread.new do
            yield reader, writer
          ensure
            reader.close
          end
        ensure
          input&.close
          output&.close
          unless pid
            reader&.close
            writer&.close
          end
        end

        def stop_helper
          @mutex.synchronize do
            return unless @pid

            @stdin.close
            begin
              Process.kill(:TERM, @pid)
            rescue Errno::ESRCH
              # The child already exited.
            end
            begin
              Process.wait(@pid)
            rescue Errno::ECHILD
              # The process has already been reaped.
            end
            thread = @reader
            @pid = @stdin = @reader = nil
            thread
          end
        end
      end
    end
  end
end
