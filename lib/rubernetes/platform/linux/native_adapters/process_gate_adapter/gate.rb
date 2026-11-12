# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        class ProcessGateAdapter
          # The agent's end of a spawned workload's gate: releasing it lets the
          # wrapper start the workload, and returns once the workload has proved
          # its identity and exec'd (or raises with why it did not).
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
              return accept_readiness if marker == "R"

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

            # The trusted bootstrap reads the outermost NSpid and its start time
            # before any namespace transition and sends both only after all
            # security steps succeed. The clone identity pipe is an independent
            # proof from the clone3 parent; require the two cross-boundary
            # identities to agree before accepting either.
            def accept_readiness
              host_identity = @status_reader.read(16).to_s
              executable_identity = @status_reader.read(64).to_s
              length_field = @status_reader.read(4).to_s
              clone_identity = @identity_reader.read(8).to_s
              unless host_identity.bytesize == 16 && clone_identity.bytesize == 8 && length_field.bytesize == 4 &&
                     executable_identity.match?(/\A[0-9a-f]{64}\z/)
                raise EffectError, "workload readiness omitted its process identity"
              end

              metadata_raw = read_readiness_metadata(length_field.unpack1("L<"))
              host_pid, host_start_time = agreed_identity(host_identity, clone_identity)
              metadata = JSON.parse(metadata_raw)
              raise EffectError, "workload readiness metadata must be an object" unless metadata.is_a?(Hash)

              # A short-lived command can exit between the bootstrap write and
              # this read. When it is still live, verify the procfs start time;
              # when it has already exited, retain the bootstrap's
              # cross-boundary identity instead of scanning /proc and risking
              # PID reuse.
              verify_live_or_adopt_identity(host_pid, host_start_time)
              @workload_pid = host_pid
              @workload_start_time = host_start_time
              @workload_executable_digest = "sha256:#{executable_identity}"
              @workload_security = metadata.freeze
              true
            end

            # The metadata, then end of file: the readiness pipe is close-on-exec,
            # so anything after the metadata is the bootstrap's exec failure.
            def read_readiness_metadata(length)
              raise EffectError, "workload readiness metadata is too large" if length > 1024 * 1024

              raw = @status_reader.read(length).to_s
              raise EffectError, "workload readiness metadata was truncated" unless raw.bytesize == length

              exec_failure = @status_reader.read.to_s
              raise EffectError, "workload exec failed after security readiness: #{exec_failure}" unless exec_failure.empty?

              raw
            end

            def agreed_identity(host_identity, clone_identity)
              host_pid, host_start_time = host_identity.unpack("Q<2")
              clone_pid = clone_identity.unpack1("Q<")
              raise EffectError, "workload readiness identities do not agree" unless host_pid.positive? && host_start_time.positive? && clone_pid == host_pid

              [host_pid, host_start_time]
            end

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
        end
      end
    end
  end
end
