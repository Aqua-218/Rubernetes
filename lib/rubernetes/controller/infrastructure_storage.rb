# frozen_string_literal: true

require "fileutils"
require "securerandom"

require "digest"
require "time"

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

# Concrete infrastructure and storage controllers for the Kubernetes
# v1.36.2 contract. Behavior is anchored to commit
# 24e2b02af5543d7910c2bb074c7264df5a8f0467 and the upstream control-loop
# boundaries in pkg/controller/nodelifecycle/taint_manager.go,
# pkg/controller/volume/{persistentvolume,attachdetach,expand},
# pkg/controller/clusterroleaggregation, and
# staging/src/k8s.io/cloud-provider/controllers.
module Rubernetes
  module Controller
    # The one place these controllers ask an injected collaborator what it
    # can do.  Cloud providers are injected and answer to different method
    # names, only the API-server-backed store adapter can read past its
    # cache, and a failed write may or may not carry an HTTP status.
    module InfrastructureCapability
      module_function

      # Does the injected cloud provider implement this call?
      def implements?(provider, method_name) = provider.respond_to?(method_name)

      # A provider may answer with a Hash or with a value object.
      def hash_like?(value) = value.respond_to?(:to_h)

      # Can the store adapter skip its cache and read the API server?
      def live_reads?(adapter) = adapter.respond_to?(:find_live)

      # An API error saying the object is not there.
      def not_found?(error) = error.respond_to?(:status) && error.status.to_i == 404
    end
  end
end

# InfrastructureStorageSupport (shared helpers) comes first; the factory,
# which names every controller class, comes last.
require_relative "infrastructure_storage/support"
# Node and DRA device taint eviction.
require_relative "infrastructure_storage/taint_eviction_controller"
# Service load balancers, node routes and cloud node lifecycle.
require_relative "infrastructure_storage/cloud_provider_controllers"
# PersistentVolume binder: plan, constants and lookups; then syncClaim,
# provisioning, binding with volume matching, and syncVolume with reclaim.
require_relative "infrastructure_storage/persistent_volume_binder_controller"
require_relative "infrastructure_storage/persistent_volume_attach_detach_controller"
require_relative "infrastructure_storage/persistent_volume_expander_controller"
require_relative "infrastructure_storage/cluster_role_aggregation_controller"
require_relative "infrastructure_storage/factory"

module Rubernetes
  module Controller
    InfrastructureStorageFactory = InfrastructureStorageControllerFactory
    PinnedInfrastructureControllerFactory = InfrastructureStorageControllerFactory
  end
end
