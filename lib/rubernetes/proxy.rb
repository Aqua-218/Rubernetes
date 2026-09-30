# frozen_string_literal: true

# Service/EndpointSlice datapath.  The public entry point keeps model,
# compiler, conntrack, allocator, backend, and controller APIs together while
# each implementation remains independently require-able for node adapters.
require_relative "proxy/model"
require_relative "proxy/compiler"
require_relative "proxy/conntrack"
require_relative "proxy/conntrack_reconciler"
require_relative "proxy/node_port_allocator"
require_relative "proxy/nftables_netlink"
require_relative "proxy/backend"
require_relative "proxy/ebpf"
require_relative "proxy/engine"

module Rubernetes
  module Proxy
    VERSION = "0.1.0" unless const_defined?(:VERSION, false)

    InvalidService = ValidationError unless const_defined?(:InvalidService, false)
    NoHealthyEndpoint = NoRoute unless const_defined?(:NoHealthyEndpoint, false)
    AllocationConflict = AllocationError unless const_defined?(:AllocationConflict, false)

    ServiceModel = Service unless const_defined?(:ServiceModel, false)
    EndpointModel = Endpoint unless const_defined?(:EndpointModel, false)
    EndpointSliceModel = EndpointSlice unless const_defined?(:EndpointSliceModel, false)
    Conntrack = ConntrackTable unless const_defined?(:Conntrack, false)
    ConnectionTracker = ConntrackTable unless const_defined?(:ConnectionTracker, false)
    BackendAdapter = Backend unless const_defined?(:BackendAdapter, false)
    EBPFAdapter = EBPFBackend unless const_defined?(:EBPFAdapter, false)
    NftablesAdapter = NftablesBackend unless const_defined?(:NftablesAdapter, false)
  end
end
