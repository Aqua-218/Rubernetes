# frozen_string_literal: true

module Rubernetes
  module API
    # Preferred served versions from the Kubernetes v1.36.2 discovery corpus.
    PINNED_VERSION_PRIORITY = {
      "admissionregistration.k8s.io" => %w[v1 v1beta1 v1alpha1],
      "apps" => %w[v1],
      "authentication.k8s.io" => %w[v1 v1beta1 v1alpha1],
      "authorization.k8s.io" => %w[v1 v1beta1 v1alpha1],
      "autoscaling" => %w[v2 v1],
      "batch" => %w[v1 v1beta1],
      "certificates.k8s.io" => %w[v1 v1beta1 v1alpha1],
      "coordination.k8s.io" => %w[v1 v1beta1 v1alpha2],
      "discovery.k8s.io" => %w[v1 v1beta1],
      "events.k8s.io" => %w[v1 v1beta1],
      "flowcontrol.apiserver.k8s.io" => %w[v1 v1beta3 v1beta2 v1beta1],
      "networking.k8s.io" => %w[v1 v1beta1],
      "node.k8s.io" => %w[v1 v1alpha1],
      "policy" => %w[v1 v1beta1],
      "rbac.authorization.k8s.io" => %w[v1 v1beta1],
      "resource.k8s.io" => %w[v1 v1beta2 v1beta1 v1alpha3],
      "scheduling.k8s.io" => %w[v1 v1alpha2],
      "storage.k8s.io" => %w[v1 v1beta1],
      "storagemigration.k8s.io" => %w[v1beta1],
      "internal.apiserver.k8s.io" => %w[v1alpha1],
      "apiregistration.k8s.io" => %w[v1 v1beta1],
      "auditregistration.k8s.io" => %w[v1alpha1],
      "metrics.k8s.io" => %w[v1beta1]
    }.transform_values(&:freeze).freeze
  end
end
