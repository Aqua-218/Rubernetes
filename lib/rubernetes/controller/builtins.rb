# frozen_string_literal: true

require "json"
require "time"

require "digest"
require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "runtime"
require_relative "ownership"
require_relative "pod_deletion_ranking"

module Rubernetes
  module Controller
    # The built-in workload, node, endpoint and garbage-collection
    # controllers.  Each lives in its own file under builtins/; a controller
    # too large for one file keeps its public plan in <name>_controller.rb and
    # reopens the class in the files listed beside it below.
    module Builtins
      # The one place these controllers ask a store adapter what it can do.
      # The two real adapters genuinely differ: Controller::StoreAdapter wraps
      # a store that holds the whole corpus, while
      # Bootstrap::KubernetesStoreAdapter answers from informer caches of the
      # kinds it was given and can also read the API server directly.
      module AdapterCapability
        module_function

        # Can the adapter skip its cache and read the API server?
        def live_reads?(adapter) = adapter.respond_to?(:find_live)

        # Does the adapter cover a declared set of kinds rather than everything?
        def declares_kinds?(adapter) = adapter.respond_to?(:resource_descriptors)
      end
    end
  end
end

# WorkloadController comes first: the Deployment, DaemonSet and Job
# controllers (in their own files next to this one) and every workload
# controller below inherit its shared helpers.
require_relative "builtins/workload_controller"
require_relative "deployment_controller"
require_relative "builtins/replica_set_controller"
# StatefulSet: the plan (replicas, condemned Pods, rolling update), Pod
# identity with its volume claims, and the ControllerRevision history.
require_relative "builtins/stateful_set_controller"
require_relative "builtins/stateful_set_storage"
require_relative "builtins/stateful_set_revisions"
require_relative "daemonset_controller"
require_relative "job_controller"
# CronJob: the plan (history cleanup, active list, starting a Job), and cron
# expressions with the schedule times they yield.
require_relative "builtins/cron_job_controller"
require_relative "builtins/cron_job_schedule"
# Node lifecycle: the plan (heartbeat, Ready condition, taints, eviction), and
# the per-zone health metrics.
require_relative "builtins/node_controller"
require_relative "builtins/node_zone_health"
require_relative "builtins/endpoint_controller"
# Garbage collector: the plan with the periodic missing-owner sweep, and the
# foreground deletion protocol.
require_relative "builtins/garbage_collector_controller"
require_relative "builtins/garbage_collector_foreground"

module Rubernetes
  module Controller
    DeploymentController = Builtins::DeploymentController
    ReplicaSetController = Builtins::ReplicaSetController
    StatefulSetController = Builtins::StatefulSetController
    DaemonSetController = Builtins::DaemonSetController
    JobController = Builtins::JobController
    CronJobController = Builtins::CronJobController
    NodeController = Builtins::NodeController
    EndpointController = Builtins::EndpointController
    EndpointsController = Builtins::EndpointController
    GarbageCollectorController = Builtins::GarbageCollectorController
  end
end
