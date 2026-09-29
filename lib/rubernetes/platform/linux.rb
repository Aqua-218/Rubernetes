# frozen_string_literal: true

require_relative "linux/abi_manifest"
require_relative "linux/bpf"
require_relative "linux/clone3"
require_relative "linux/error"
require_relative "linux/kvm"
require_relative "linux/mount"
require_relative "linux/netlink"
require_relative "linux/native_adapters"
require_relative "linux/pidfd"

module Rubernetes
  module Platform
    module Linux
      autoload :NamespaceProcess, "rubernetes/platform/linux/namespace_process"
      autoload :Openat2, "rubernetes/platform/linux/openat2"
      autoload :SecureRootfs, "rubernetes/platform/linux/secure_rootfs"
    end
  end
end
