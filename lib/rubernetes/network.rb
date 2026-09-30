# frozen_string_literal: true

# Public Network data-plane boundary.  Each component is adapter-injected so
# unprivileged tests can verify plans and recovery while production profiles
# use the AF_NETLINK and durable-state implementations.
require_relative "network/errors"
require_relative "network/support"
require_relative "network/durable_state"
require_relative "network/netlink"
require_relative "network/native_observer"
require_relative "network/host_forward"
require_relative "network/host_port"
require_relative "network/ipam"
require_relative "network/topology"
require_relative "network/sysctl"
require_relative "network/policy"
require_relative "network/nftables_policy"
require_relative "network/ebpf_policy"
require_relative "network/dns"
require_relative "network/interface"
require_relative "network/worker"

module Rubernetes
  module Network
    VERSION = "0.2" unless const_defined?(:VERSION, false)

    InterfaceContract = {
      add: %i[sandbox config],
      delete: [:sandbox],
      check: [:sandbox],
      recover: []
    }.freeze

    Network = Interface unless const_defined?(:Network, false)
  end
end
