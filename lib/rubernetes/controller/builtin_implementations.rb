# frozen_string_literal: true

module Rubernetes
  module Controller
    BASE_BUILTIN_IMPLEMENTATIONS = {
      "deployment-controller" => DeploymentController,
      "replicaset-controller" => ReplicaSetController,
      "statefulset-controller" => StatefulSetController,
      "daemonset-controller" => DaemonSetController,
      "job-controller" => JobController,
      "cronjob-controller" => CronJobController,
      "node-lifecycle-controller" => NodeController,
      "endpoints-controller" => EndpointController,
      "garbage-collector-controller" => GarbageCollectorController,
      "serviceaccount-token-controller" => ServiceAccountTokenController,
      "endpointslice-controller" => EndpointSliceController,
      "endpointslice-mirroring-controller" => EndpointSliceMirroringController,
      "replicationcontroller-controller" => ReplicationControllerController,
      "pod-garbage-collector-controller" => PodGarbageCollectorController,
      "resourcequota-controller" => ResourceQuotaController,
      "namespace-controller" => NamespaceController,
      "serviceaccount-controller" => ServiceAccountController,
      "horizontal-pod-autoscaler-controller" => HorizontalPodAutoscalerController
    }.freeze

    BUILTIN_FACTORY_MODULES = [
      SecurityLifecycleRegistration,
      InfrastructureStorageControllerFactory,
      ProtectionPublicationControllerFactory,
      AdvancedMiscControllerFactory
    ].freeze

    # Factory modules keep their implementation maps private to each batch;
    # flatten them once at the integration seam so the corpus and registry
    # share one 52-name inventory.  A duplicate name is a wiring error, not a
    # reason to silently prefer one implementation.
    BUILTIN_FACTORY_IMPLEMENTATIONS = BUILTIN_FACTORY_MODULES.each_with_object({}) do |factory, implementations|
      factory::IMPLEMENTATIONS.each do |name, implementation|
        raise ValidationError, "duplicate built-in implementation #{name.inspect}" if implementations.key?(name)

        implementations[name] = implementation
      end
    end.freeze

    BUILTIN_IMPLEMENTATIONS = BASE_BUILTIN_IMPLEMENTATIONS.merge(BUILTIN_FACTORY_IMPLEMENTATIONS).freeze

    # Completeness is derived from the concrete implementation contract and
    # the pinned corpus metadata.  A controller may not be promoted by a
    # placeholder reason or by suppressing a startup validation error.
    BUILTIN_INCOMPLETE_REASONS = {}.freeze

    UNIMPLEMENTED_BUILTIN_CONTROLLERS = (BuiltinControllerCorpus.names - BUILTIN_IMPLEMENTATIONS.keys).freeze
  end
end
