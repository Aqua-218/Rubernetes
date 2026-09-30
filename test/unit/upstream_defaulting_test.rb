# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

# pkg/apis/<group>/<version>/defaults.go: the defaults the generated OpenAPI
# corpus cannot carry, because they are procedural Go rather than a schema
# `default:`.  Every expectation below was read off the upstream function named
# in its comment.
class UpstreamDefaultingTest < Minitest::Test
  def defaulted(name, object)
    Rubernetes::Generated.definition_for(name)
      .defaulting
      .apply_hash(object, kubernetes_admission_defaults: true)
  end

  def pod(spec)
    defaulted("io.k8s.api.core.v1.Pod",
              "metadata" => {"name" => "p", "namespace" => "default"}, "spec" => spec)
  end

  # SetDefaults_Volume: ptr.AllPtrFieldsNil(&obj.VolumeSource) => EmptyDir{}.
  def test_volume_without_a_source_defaults_to_empty_dir
    volumes = pod("containers" => [{"name" => "c", "image" => "busybox"}],
                  "volumes" => [{"name" => "scratch"},
                                {"name" => "host", "hostPath" => {"path" => "/tmp"}}])
      .dig("spec", "volumes")

    assert_equal({}, volumes.fetch(0).fetch("emptyDir"))
    refute(volumes.fetch(1).key?("emptyDir"))
  end

  # SetDefaults_HostPathVolumeSource: HostPathUnset is the empty string.
  def test_host_path_type_defaults_to_the_unset_marker
    volume = pod("containers" => [{"name" => "c", "image" => "busybox"}],
                 "volumes" => [{"name" => "host", "hostPath" => {"path" => "/tmp"}}])
      .dig("spec", "volumes", 0)

    assert_equal("", volume.dig("hostPath", "type"))
  end

  # SetDefaults_SecretVolumeSource and its Projected/ConfigMap/DownwardAPI peers.
  def test_volume_default_modes_are_0644
    volumes = pod("containers" => [{"name" => "c", "image" => "busybox"}],
                  "volumes" => [{"name" => "s", "secret" => {"secretName" => "s"}},
                                {"name" => "c", "configMap" => {"name" => "c"}},
                                {"name" => "d", "downwardAPI" => {}},
                                {"name" => "p", "projected" => {"sources" => []}}])
      .dig("spec", "volumes")

    assert_equal(420, volumes.dig(0, "secret", "defaultMode"))
    assert_equal(420, volumes.dig(1, "configMap", "defaultMode"))
    assert_equal(420, volumes.dig(2, "downwardAPI", "defaultMode"))
    assert_equal(420, volumes.dig(3, "projected", "defaultMode"))
  end

  # SetDefaults_Probe compares against the zero value, so an explicitly supplied
  # 0 is defaulted exactly like an omitted field.
  def test_probe_timings_default_even_when_supplied_as_zero
    probe = pod("containers" => [{"name" => "c", "image" => "busybox",
                                  "livenessProbe" => {"httpGet" => {"port" => 80}, "periodSeconds" => 0}}])
      .dig("spec", "containers", 0, "livenessProbe")

    assert_equal(1, probe.fetch("timeoutSeconds"))
    assert_equal(10, probe.fetch("periodSeconds"))
    assert_equal(1, probe.fetch("successThreshold"))
    assert_equal(3, probe.fetch("failureThreshold"))
    assert_equal("/", probe.dig("httpGet", "path"))
    assert_equal("HTTP", probe.dig("httpGet", "scheme"))
  end

  # SetDefaults_ObjectFieldSelector: a downward API fieldRef without an
  # apiVersion is a v1 reference.
  def test_field_ref_api_version_defaults_to_v1
    env = pod("containers" => [{"name" => "c", "image" => "busybox",
                                "env" => [{"name" => "NS",
                                           "valueFrom" => {"fieldRef" => {"fieldPath" => "metadata.namespace"}}}]}])
      .dig("spec", "containers", 0, "env", 0)

    assert_equal("v1", env.dig("valueFrom", "fieldRef", "apiVersion"))
  end

  # ContainerPort.Protocol carries `+default="TCP"` in the Go types.
  def test_container_port_protocol_defaults_to_tcp
    port = pod("containers" => [{"name" => "c", "image" => "busybox",
                                 "ports" => [{"containerPort" => 8080}]}])
      .dig("spec", "containers", 0, "ports", 0)

    assert_equal("TCP", port.fetch("protocol"))
  end

  # defaultHostNetworkPorts: on the host network every container port is also a
  # host port, for init containers as well as regular ones.
  def test_host_network_defaults_every_container_port_to_a_host_port
    spec = pod("hostNetwork" => true,
               "initContainers" => [{"name" => "i", "image" => "busybox",
                                     "ports" => [{"containerPort" => 90}]}],
               "containers" => [{"name" => "c", "image" => "busybox",
                                 "ports" => [{"containerPort" => 8080},
                                             {"containerPort" => 9090, "hostPort" => 1234}]}])
      .fetch("spec")

    assert_equal(8080, spec.dig("containers", 0, "ports", 0, "hostPort"))
    assert_equal(1234, spec.dig("containers", 0, "ports", 1, "hostPort"))
    assert_equal(90, spec.dig("initContainers", 0, "ports", 0, "hostPort"))
  end

  def test_pod_without_host_network_keeps_container_ports_off_the_host
    port = pod("containers" => [{"name" => "c", "image" => "busybox",
                                 "ports" => [{"containerPort" => 8080}]}])
      .dig("spec", "containers", 0, "ports", 0)

    refute(port.key?("hostPort"))
  end

  # SetDefaults_Pod: a limit without a matching request defaults the request to
  # the limit, for both containers and initContainers.
  def test_resource_requests_default_to_limits
    spec = pod("initContainers" => [{"name" => "i", "image" => "busybox",
                                     "resources" => {"limits" => {"cpu" => "2"}}}],
               "containers" => [{"name" => "c", "image" => "busybox",
                                 "resources" => {"limits" => {"cpu" => "1", "memory" => "1Gi"},
                                                 "requests" => {"cpu" => "500m"}}}])
      .fetch("spec")

    assert_equal({"cpu" => "500m", "memory" => "1Gi"},
                 spec.dig("containers", 0, "resources", "requests"))
    assert_equal({"cpu" => "2"}, spec.dig("initContainers", 0, "resources", "requests"))
  end

  # The same rule is deliberately NOT applied to a bare PodSpec: upstream keeps
  # it on v1.Pod so a workload template preserves the author's sparse resources.
  def test_a_pod_template_keeps_sparse_resources
    deployment = defaulted(
      "io.k8s.api.apps.v1.Deployment",
      "metadata" => {"name" => "d"},
      "spec" => {"selector" => {"matchLabels" => {"a" => "b"}},
                 "template" => {"metadata" => {"labels" => {"a" => "b"}},
                                "spec" => {"containers" => [{"name" => "c", "image" => "busybox",
                                                             "resources" => {"limits" => {"cpu" => "1"}}}]}}}
    )

    assert_nil(deployment.dig("spec", "template", "spec", "containers", 0, "resources", "requests"))
  end

  # SetDefaults_Namespace: namespaceSelector must be able to address a namespace
  # by name without the author labelling it first.
  def test_namespace_carries_its_own_name_as_a_label
    namespace = defaulted("io.k8s.api.core.v1.Namespace",
                          "metadata" => {"name" => "demo", "labels" => {"team" => "x"}})

    assert_equal("demo", namespace.dig("metadata", "labels", "kubernetes.io/metadata.name"))
    assert_equal("x", namespace.dig("metadata", "labels", "team"))
  end

  def test_namespace_without_a_name_is_left_alone
    namespace = defaulted("io.k8s.api.core.v1.Namespace", "metadata" => {"generateName" => "demo-"})

    assert_nil(namespace.dig("metadata", "labels"))
  end

  # SetDefaults_Secret / SetDefaults_PersistentVolume / _PersistentVolumeClaimSpec.
  def test_secret_and_volume_defaults
    secret = defaulted("io.k8s.api.core.v1.Secret", "metadata" => {"name" => "s"})

    assert_equal("Opaque", secret.fetch("type"))

    volume = defaulted("io.k8s.api.core.v1.PersistentVolume",
                       "metadata" => {"name" => "v"},
                       "spec" => {"capacity" => {"storage" => "1Gi"},
                                  "accessModes" => ["ReadWriteOnce"],
                                  "hostPath" => {"path" => "/tmp/v"}})

    assert_equal("Retain", volume.dig("spec", "persistentVolumeReclaimPolicy"))
    assert_equal("Filesystem", volume.dig("spec", "volumeMode"))

    claim = defaulted("io.k8s.api.core.v1.PersistentVolumeClaim",
                      "metadata" => {"name" => "c"},
                      "spec" => {"accessModes" => ["ReadWriteOnce"],
                                 "resources" => {"requests" => {"storage" => "1Gi"}}})

    assert_equal("Filesystem", claim.dig("spec", "volumeMode"))
  end

  # SetDefaults_Endpoints walks every subset port; discovery's EndpointPort has
  # a defaulter of its own that also fills in the empty port name.
  def test_endpoint_ports_default_their_protocol
    endpoints = defaulted("io.k8s.api.core.v1.Endpoints",
                          "metadata" => {"name" => "e"},
                          "subsets" => [{"addresses" => [{"ip" => "10.0.0.1"}], "ports" => [{"port" => 80}]}])

    assert_equal("TCP", endpoints.dig("subsets", 0, "ports", 0, "protocol"))

    slice = defaulted("io.k8s.api.discovery.v1.EndpointSlice",
                      "metadata" => {"name" => "e"}, "addressType" => "IPv4",
                      "endpoints" => [{"addresses" => ["10.0.0.1"]}], "ports" => [{"port" => 80}])

    assert_equal("TCP", slice.dig("ports", 0, "protocol"))
    assert_equal("", slice.dig("ports", 0, "name"))
  end

  # SetDefaults_LimitRangeItem: max -> default -> defaultRequest, with min
  # filling any request the default did not.
  def test_container_limit_range_items_cascade_their_defaults
    item = defaulted("io.k8s.api.core.v1.LimitRange",
                     "metadata" => {"name" => "l"},
                     "spec" => {"limits" => [{"type" => "Container",
                                              "max" => {"cpu" => "2"},
                                              "min" => {"memory" => "64Mi"}}]})
      .dig("spec", "limits", 0)

    assert_equal({"cpu" => "2"}, item.fetch("default"))
    assert_equal({"cpu" => "2", "memory" => "64Mi"}, item.fetch("defaultRequest"))
  end

  def test_non_container_limit_range_items_are_untouched
    item = defaulted("io.k8s.api.core.v1.LimitRange",
                     "metadata" => {"name" => "l"},
                     "spec" => {"limits" => [{"type" => "Pod", "max" => {"cpu" => "2"}}]})
      .dig("spec", "limits", 0)

    refute(item.key?("default"))
    refute(item.key?("defaultRequest"))
  end

  # SetDefaults_ReplicationController: the template's labels stand in for both
  # an absent selector and absent object labels.
  def test_replication_controller_borrows_its_template_labels
    controller = defaulted(
      "io.k8s.api.core.v1.ReplicationController",
      "metadata" => {"name" => "r"},
      "spec" => {"template" => {"metadata" => {"labels" => {"app" => "r"}},
                                "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}}}
    )

    assert_equal({"app" => "r"}, controller.dig("spec", "selector"))
    assert_equal({"app" => "r"}, controller.dig("metadata", "labels"))
    assert_equal(1, controller.dig("spec", "replicas"))
  end

  # SetDefaults_Deployment / _DaemonSet / _StatefulSet / _ReplicaSet.
  def test_workload_rollout_strategies_are_fully_populated
    template = {"metadata" => {"labels" => {"a" => "b"}},
                "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}}
    selector = {"matchLabels" => {"a" => "b"}}

    deployment = defaulted("io.k8s.api.apps.v1.Deployment", "metadata" => {"name" => "d"},
                                                            "spec" => {"selector" => selector, "template" => template})

    assert_equal(1, deployment.dig("spec", "replicas"))
    assert_equal(10, deployment.dig("spec", "revisionHistoryLimit"))
    assert_equal(600, deployment.dig("spec", "progressDeadlineSeconds"))
    assert_equal({"type" => "RollingUpdate",
                  "rollingUpdate" => {"maxUnavailable" => "25%", "maxSurge" => "25%"}},
                 deployment.dig("spec", "strategy"))

    daemon_set = defaulted("io.k8s.api.apps.v1.DaemonSet", "metadata" => {"name" => "d"},
                                                           "spec" => {"selector" => selector, "template" => template})

    assert_equal({"type" => "RollingUpdate", "rollingUpdate" => {"maxUnavailable" => 1, "maxSurge" => 0}},
                 daemon_set.dig("spec", "updateStrategy"))

    replica_set = defaulted("io.k8s.api.apps.v1.ReplicaSet", "metadata" => {"name" => "r"},
                                                             "spec" => {"selector" => selector, "template" => template})

    assert_equal(1, replica_set.dig("spec", "replicas"))

    stateful_set = defaulted("io.k8s.api.apps.v1.StatefulSet", "metadata" => {"name" => "s"},
                                                               "spec" => {"serviceName" => "s", "selector" => selector,
                                                                          "template" => template})

    assert_equal(1, stateful_set.dig("spec", "replicas"))
    assert_equal("OrderedReady", stateful_set.dig("spec", "podManagementPolicy"))
    assert_equal({"type" => "RollingUpdate", "rollingUpdate" => {"partition" => 0}},
                 stateful_set.dig("spec", "updateStrategy"))
    assert_equal({"whenDeleted" => "Retain", "whenScaled" => "Retain"},
                 stateful_set.dig("spec", "persistentVolumeClaimRetentionPolicy"))
  end

  # SetDefaults_StatefulSet only materialises the rollingUpdate block when it
  # defaulted the type itself, so an explicit type keeps an absent block absent.
  def test_explicit_statefulset_strategy_keeps_its_shape
    stateful_set = defaulted(
      "io.k8s.api.apps.v1.StatefulSet",
      "metadata" => {"name" => "s"},
      "spec" => {"serviceName" => "s", "selector" => {"matchLabels" => {"a" => "b"}},
                 "updateStrategy" => {"type" => "OnDelete"},
                 "template" => {"metadata" => {"labels" => {"a" => "b"}},
                                "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}}}
    )

    assert_equal({"type" => "OnDelete"}, stateful_set.dig("spec", "updateStrategy"))
  end

  # SetDefaults_Job plus generateSelectorIfNeeded.
  def test_job_completion_and_selector_defaults
    job = defaulted(
      "io.k8s.api.batch.v1.Job",
      "metadata" => {"name" => "j", "uid" => "UID"},
      "spec" => {"template" => {"metadata" => {"labels" => {"a" => "b"}},
                                "spec" => {"restartPolicy" => "Never",
                                           "containers" => [{"name" => "c", "image" => "busybox"}]}}}
    )

    assert_equal(1, job.dig("spec", "completions"))
    assert_equal(1, job.dig("spec", "parallelism"))
    assert_equal(6, job.dig("spec", "backoffLimit"))
    assert_equal({"batch.kubernetes.io/controller-uid" => "UID"}, job.dig("spec", "selector", "matchLabels"))
    # obj.Labels aliases the template's label map upstream, so the generated
    # labels land on the Job object as well.
    assert_equal("UID", job.dig("metadata", "labels", "batch.kubernetes.io/controller-uid"))
    assert_equal("b", job.dig("metadata", "labels", "a"))
  end

  def test_job_parallelism_only_defaults_completions_when_both_are_absent
    job = defaulted(
      "io.k8s.api.batch.v1.Job",
      "metadata" => {"name" => "j", "uid" => "UID"},
      "spec" => {"parallelism" => 4,
                 "template" => {"spec" => {"restartPolicy" => "Never",
                                           "containers" => [{"name" => "c", "image" => "busybox"}]}}}
    )

    assert_equal(4, job.dig("spec", "parallelism"))
    assert_nil(job.dig("spec", "completions"))
  end

  # A podFailurePolicy switches the replacement policy upstream.
  def test_pod_failure_policy_changes_the_replacement_policy
    job = defaulted(
      "io.k8s.api.batch.v1.Job",
      "metadata" => {"name" => "j", "uid" => "UID"},
      "spec" => {"podFailurePolicy" => {"rules" => [{"action" => "FailJob",
                                                     "onExitCodes" => {"operator" => "In", "values" => [42]}}]},
                 "template" => {"spec" => {"restartPolicy" => "Never",
                                           "containers" => [{"name" => "c", "image" => "busybox"}]}}}
    )

    assert_equal("Failed", job.dig("spec", "podReplacementPolicy"))
  end

  # SetDefaults_NetworkPolicy: an absent policyTypes implies Ingress, plus
  # Egress when egress rules are present.
  def test_network_policy_types_and_port_protocol
    policy = defaulted("io.k8s.api.networking.v1.NetworkPolicy",
                       "metadata" => {"name" => "n"},
                       "spec" => {"podSelector" => {},
                                  "egress" => [{"ports" => [{"port" => 53}]}]})

    assert_equal(%w[Ingress Egress], policy.dig("spec", "policyTypes"))
    assert_equal("TCP", policy.dig("spec", "egress", 0, "ports", 0, "protocol"))
  end

  def test_ingress_only_network_policy_is_not_given_an_egress_type
    policy = defaulted("io.k8s.api.networking.v1.NetworkPolicy",
                       "metadata" => {"name" => "n"},
                       "spec" => {"podSelector" => {}})

    assert_equal(["Ingress"], policy.dig("spec", "policyTypes"))
  end

  # SetDefaults_StorageClass / _PriorityClass.
  def test_cluster_scoped_defaults
    storage_class = defaulted("io.k8s.api.storage.v1.StorageClass",
                              "metadata" => {"name" => "s"}, "provisioner" => "example.com/x")

    assert_equal("Delete", storage_class.fetch("reclaimPolicy"))
    assert_equal("Immediate", storage_class.fetch("volumeBindingMode"))

    priority_class = defaulted("io.k8s.api.scheduling.v1.PriorityClass",
                               "metadata" => {"name" => "p"}, "value" => 100)

    assert_equal("PreemptLowerPriority", priority_class.fetch("preemptionPolicy"))
  end

  # SetDefaults_RoleBinding and SetDefaults_Subject.
  def test_rbac_api_groups_default_by_kind
    binding = defaulted("io.k8s.api.rbac.v1.RoleBinding",
                        "metadata" => {"name" => "b"},
                        "roleRef" => {"kind" => "Role", "name" => "r"},
                        "subjects" => [{"kind" => "User", "name" => "u"},
                                       {"kind" => "ServiceAccount", "name" => "sa", "namespace" => "default"}])

    assert_equal("rbac.authorization.k8s.io", binding.dig("roleRef", "apiGroup"))
    assert_equal("rbac.authorization.k8s.io", binding.dig("subjects", 0, "apiGroup"))
    assert_equal("", binding.dig("subjects", 1, "apiGroup"))
  end

  # SetDefaults_CSIDriver.
  def test_csi_driver_spec_defaults
    spec = defaulted("io.k8s.api.storage.v1.CSIDriver",
                     "metadata" => {"name" => "d"}, "spec" => {})
      .fetch("spec")

    assert(spec.fetch("attachRequired"))
    refute(spec.fetch("podInfoOnMount"))
    refute(spec.fetch("storageCapacity"))
    refute(spec.fetch("requiresRepublish"))
    refute(spec.fetch("seLinuxMount"))
    assert_equal("ReadWriteOnceWithFSType", spec.fetch("fsGroupPolicy"))
    assert_equal(["Persistent"], spec.fetch("volumeLifecycleModes"))
  end

  # SetDefaults_Container: parsers.ParseImageName treats a missing tag as
  # :latest, which pulls Always.
  def test_image_pull_policy_follows_the_tag
    containers = pod("containers" => [{"name" => "a", "image" => "busybox"},
                                      {"name" => "b", "image" => "busybox:latest"},
                                      {"name" => "c", "image" => "busybox:1.36"},
                                      {"name" => "d", "image" => "registry:5000/busybox:1.36"}])
      .dig("spec", "containers")

    assert_equal(%w[Always Always IfNotPresent IfNotPresent],
                 containers.map { |container| container.fetch("imagePullPolicy") })
  end
end
