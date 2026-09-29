# frozen_string_literal: true

# Public API-core entry point. Loading this file does not open a socket or
# construct a process singleton; callers inject registry and store explicitly.
require_relative "api/status"
require_relative "api/request"
require_relative "api/response"
require_relative "api/registry"
require_relative "api/event_conversion"
require_relative "api/selectors"
require_relative "api/patch"
require_relative "api/memory_store"
require_relative "api/storage_adapter"
require_relative "api/router"
require_relative "api/openapi"
require_relative "api/negotiation"
require_relative "api/table_printer"
require_relative "api/object_validation"
require_relative "api/openapi_v2_protobuf"
require_relative "api/subresource_bridge"
require_relative "api/crd/structural_schema"
require_relative "api/crd/manager"
require_relative "api/aggregator"
require_relative "api/node_endpoint_resolver"
require_relative "api/server"

module Rubernetes
  module API
    APICore = Server
    InProcessHandler = Server
    PatchEngine = Patch
  end
end
