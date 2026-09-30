# frozen_string_literal: true

# Node Agent public entry point.  Keeping the requires here makes each
# lifecycle component independently injectable while allowing applications to
# depend on one stable `rubernetes/node` boundary.
require_relative "node/service"
require_relative "node/log_service"
require_relative "node/streaming_server"
require_relative "node/kubelet_auth"
require_relative "node/kubelet_configz"
require_relative "node/client_certificate_manager"
require_relative "node/serving_certificate_manager"
require_relative "node/exec_service"
require_relative "node/attach_service"
require_relative "node/port_forward_service"
require_relative "node/registration"
require_relative "node/api_client_adapter"
require_relative "node/source_manager"
require_relative "node/admission"
require_relative "node/resource_manager"
require_relative "node/host_resources"
require_relative "node/eviction_manager"
require_relative "node/event_recorder"
require_relative "node/event_sink"
require_relative "node/image_credentials"
require_relative "node/garbage_collector"
require_relative "node/status"
require_relative "node/restart_manager"
require_relative "node/probe_manager"
require_relative "node/probe_connectors"
require_relative "node/resource_reader"
require_relative "node/field_ref"
require_relative "node/pod_volumes"
require_relative "node/pod_files"
require_relative "node/oom_score"
require_relative "node/container_spec"
require_relative "node/dns_service"
require_relative "node/lifecycle"
require_relative "node/pod_worker"
require_relative "node/sync_loop"
require_relative "node/wakeup_timer"
require_relative "node/agent"

module Rubernetes
  module Node
    NodeAgent = Agent unless const_defined?(:NodeAgent, false)
    PodSyncLoop = SyncLoop unless const_defined?(:PodSyncLoop, false)
  end
end
