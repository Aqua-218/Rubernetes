# frozen_string_literal: true

module Conformance
  module K3InternalContractIndex
    RUNNER = "tools/conformance/k3_internal_contracts.rb"
    CASES = {
      "[sig-api-machinery] Etcd failure [Disruptive] should recover from SIGKILL" => "datastore-sigkill",
      "[sig-api-machinery] Etcd failure [Disruptive] should recover from network partition with master" => "datastore-partition",
      "[sig-api-machinery] kube-apiserver identity [Feature:APIServerIdentity] kube-apiserver identity should persist after restart [Disruptive]" =>
        "apiserver-identity-restart",
      "[sig-instrumentation] MetricsGrabber should grab all metrics from a Scheduler." => "scheduler-metrics",
      "[sig-instrumentation] MetricsGrabber should grab all metrics from a ControllerManager." => "controller-manager-metrics",
      "[sig-node] Kubelet [Serial] [Slow] regular resource usage tracking [Feature:RegularResourceUsageTracking] resource tracking for 0 pods per node" =>
        "node-resource-regular-idle",
      "[sig-node] Kubelet [Serial] [Slow] regular resource usage tracking [Feature:RegularResourceUsageTracking] resource tracking for 100 pods per node" =>
        "node-resource-regular-loaded",
      "[sig-node] Kubelet [Serial] [Slow] experimental resource usage tracking [Feature:ExperimentalResourceUsageTracking] " \
      "resource tracking for 100 pods per node" =>
        "node-resource-experimental-loaded"
    }.freeze
  end
end
