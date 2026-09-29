# frozen_string_literal: true

require_relative "error"

module Rubernetes
  module Platform
    module Linux
      class KVM
        Probe = Data.define(:api_version, :capabilities)

        API_VERSION = 12
        KVM_GET_API_VERSION = 0xAE00
        KVM_CHECK_EXTENSION = 0xAE03
        KVM_CAP_USER_MEMORY = 3
        KVM_CAP_NR_VCPUS = 9
        DEFAULT_CAPABILITIES = [KVM_CAP_USER_MEMORY, KVM_CAP_NR_VCPUS].freeze

        def initialize(path: "/dev/kvm")
          @path = path
        end

        def probe(capabilities: DEFAULT_CAPABILITIES, resource_id: "kvm:#{@path}")
          # Ruby marks newly opened descriptors close-on-exec by default.
          device = File.open(@path, File::RDWR)
          api_version = device.ioctl(KVM_GET_API_VERSION, 0)
          if api_version != API_VERSION
            raise Linux::Error.new(
              errno: Errno::EPROTO::Errno,
              operation: "ioctl(KVM_GET_API_VERSION)",
              resource_id: resource_id,
              details: {expected: API_VERSION, actual: api_version}
            )
          end
          values = capabilities.to_h do |capability|
            [Integer(capability), device.ioctl(KVM_CHECK_EXTENSION, Integer(capability))]
          end
          Probe.new(api_version: api_version, capabilities: values.freeze)
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "kvm_probe", resource_id: resource_id), cause: error
        ensure
          device&.close
        end
      end
    end
  end
end
