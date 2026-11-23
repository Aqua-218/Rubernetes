# frozen_string_literal: true

require_relative "../priority_classes"

require_relative "../api/startup_health"

module Rubernetes
  module Bootstrap
    # Registers persisted bootstrap objects before marking their startup checks ready.
    module APIServerStartupHooks
      # Kubernetes v1.36.2, pkg/controlplane/apiserver/aggregator.go and
      # cmd/kube-apiserver/app/aggregator.go. Unlisted group versions stay unregistered.
      LOCAL_API_PRIORITIES = {
        "" => [18_000, {"v1" => 1}],
        "apps" => [17_800, {"v1" => 15}],
        "events.k8s.io" => [17_750, {"v1" => 15, "v1beta1" => 5}],
        "authentication.k8s.io" => [17_700, {"v1" => 15, "v1beta1" => 9, "v1alpha1" => 1}],
        "authorization.k8s.io" => [17_600, {"v1" => 15}],
        "autoscaling" => [17_500, {"v1" => 15, "v2" => 30, "v2beta1" => 9, "v2beta2" => 1}],
        "batch" => [17_400, {"v1" => 15, "v1beta1" => 9, "v2alpha1" => 9}],
        "certificates.k8s.io" => [17_300, {"v1" => 15, "v1beta1" => 9, "v1alpha1" => 1}],
        "networking.k8s.io" => [17_200, {"v1" => 15, "v1beta1" => 9}],
        "policy" => [17_100, {"v1" => 15, "v1beta1" => 9}],
        "rbac.authorization.k8s.io" => [17_000, {"v1" => 15}],
        "storage.k8s.io" => [16_800, {"v1" => 15, "v1beta1" => 9, "v1alpha1" => 1}],
        "apiextensions.k8s.io" => [16_700, {"v1" => 15}],
        "admissionregistration.k8s.io" => [16_700, {"v1" => 15, "v1beta1" => 12, "v1alpha1" => 9}],
        "scheduling.k8s.io" => [16_600, {"v1" => 15, "v1alpha2" => 2}],
        "coordination.k8s.io" => [16_500, {"v1" => 15, "v1beta1" => 13, "v1alpha2" => 12}],
        "node.k8s.io" => [16_300, {"v1" => 15, "v1beta1" => 9, "v1alpha1" => 1}],
        "resource.k8s.io" => [16_200, {"v1" => 21, "v1beta2" => 15, "v1beta1" => 9, "v1alpha3" => 1}],
        "discovery.k8s.io" => [16_200, {"v1" => 15, "v1beta1" => 12}],
        "flowcontrol.apiserver.k8s.io" => [16_100, {"v1" => 21, "v1beta3" => 18, "v1beta2" => 15, "v1beta1" => 12, "v1alpha1" => 9}],
        "internal.apiserver.k8s.io" => [16_000, {"v1alpha1" => 9}],
        "storagemigration.k8s.io" => [15_800, {"v1beta1" => 9}]
      }.freeze

      BOOTSTRAP_IDENTITY = {"username" => "system:apiserver", "groups" => ["system:masters"].freeze}.freeze

      private def start_registration_hooks
        @registration_thread = Thread.new do
          @startup_health.complete("kube-apiserver-autoregistration")
          reconcile_startup_registrations until @stopping || @startup_registrations_complete
        end
        @registration_thread.name = "apiserver-bootstrap-registration"
      end

      private def reconcile_startup_registrations
        if @api_server.ready?
          priorities = ensure_system_priorities
          services = ensure_local_apiservices
          @startup_health.complete("scheduling/bootstrap-system-priority-classes") if priorities
          @startup_health.autoregistration_complete if services
          @startup_registrations_complete = priorities && services
        end
        sleep(0.25) unless @startup_registrations_complete || @stopping
      end

      private def ensure_system_priorities
        return true unless @api_server.local_group_versions.include?(["scheduling.k8s.io", "v1"])

        PriorityClasses::SYSTEM.map do |name, (value, description)|
          object = {"apiVersion" => "scheduling.k8s.io/v1", "kind" => "PriorityClass", "metadata" => {"name" => name},
                    "value" => value, "globalDefault" => false, "description" => description}
          !registered_bootstrap_object(object).nil?
        end.all?
      end

      private def ensure_local_apiservices
        versions = @api_server.local_group_versions
        return true unless versions.include?(["apiregistration.k8s.io", "v1"])

        versions.filter_map { |group, version| local_apiservice(group, version) }.map do |object|
          current = registered_bootstrap_object(object)
          Array(current&.dig("status", "conditions")).any? { |condition| condition.values_at("type", "status") == %w[Available True] }
        end.all?
      end

      private def local_apiservice(group, version)
        group_priority, versions = LOCAL_API_PRIORITIES[group]
        version_priority = versions&.[](version)
        return unless version_priority

        {"apiVersion" => "apiregistration.k8s.io/v1", "kind" => "APIService",
         "metadata" => {"name" => "#{version}.#{group}", "labels" => {"kube-aggregator.kubernetes.io/automanaged" => "onstart"}},
         "spec" => {"group" => group, "version" => version, "groupPriorityMinimum" => group_priority, "versionPriority" => version_priority}}
      end

      private def registered_bootstrap_object(object)
        path = collection_path(object)
        name = object.dig("metadata", "name")
        existing = @api_server.call(method: "GET", path: "#{path}/#{name}", identity: BOOTSTRAP_IDENTITY)
        return existing.body if existing.status == 200
        return unless existing.status == 404

        response = @api_server.call(method: "POST", path: path, identity: BOOTSTRAP_IDENTITY, body: object)
        return response.body if response.status == 201
        return if response.status == 409

        @logger.warn("startup.registration_failed", kind: object["kind"], name: name, status: response.status, message: response.body["message"])
        nil
      end

      private def dynamic_api_hooks_ready
        @startup_health.complete(
          "generic-apiserver-start-informers", "start-apiextensions-informers", "start-apiextensions-controllers", "crd-informer-synced",
          "start-kube-aggregator-informers", "apiservice-registration-controller", "apiservice-status-local-available-controller",
          "apiservice-status-remote-available-controller", "apiservice-openapi-controller"
        )
        @startup_health.dynamic_apis_synced
      end
    end
  end
end
