# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
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
          rescue Linux::Error
            false
          end
        end
      end
    end
  end
end
