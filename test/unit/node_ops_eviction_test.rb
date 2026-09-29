# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/eviction_manager"

# pkg/kubelet/eviction (v1.36.2) ported: signals from the Summary API,
# hard/soft thresholds, minimum reclaim, the pressure transition period,
# rankMemoryPressure / rankDiskPressureFunc / rankPIDPressure, one eviction
# per pass with the kubelet's message and DisruptionTarget condition, local
# storage limits, and the eviction admit handler.
class NodeOpsEvictionTest < Minitest::Test
  EM = Rubernetes::Node::EvictionManager
  GI = 1024**3
  MI = 1024**2

  class Summary
    attr_accessor :node, :pods, :calls

    def initialize
      @node = {}
      @pods = []
      @calls = 0
      @tick = 0
    end

    # A fresh sample time on every call, as the kubelet's stats have.
    def summary
      @calls += 1
      @tick += 1
      stamp = (Time.utc(2026, 1, 1) + @tick).iso8601
      node = Marshal.load(Marshal.dump(@node))
      node.each_value { |value| value["time"] = stamp if value.is_a?(Hash) }
      {"node" => node, "pods" => @pods}
    end
  end

  def setup
    @now = 0.0
    @killed = []
    @summary = Summary.new
  end

  def manager(thresholds: EM.parse_threshold_config(allocatable_config: []), **options)
    EM.new(summary_provider: @summary, active_pods: -> { @pods || [] }, thresholds: thresholds,
           kill_pod: ->(pod, grace_period_seconds:, message:, condition:) { @killed << [pod.dig("metadata", "name"), grace_period_seconds, message, condition] },
           monotonic: -> { @now }, **options)
  end

  def pod(name, request: nil, priority: nil, limit: nil, **extra)
    resources = {}
    resources["requests"] = {"memory" => request} if request
    resources["limits"] = {"memory" => limit} if limit
    {"metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
     "spec" => {"priority" => priority, "containers" => [{"name" => "c", "resources" => resources}]}.compact.merge(extra.transform_keys(&:to_s))}
  end

  def pod_stats(name, memory: nil, rootfs: nil, logs: nil, volumes: [], processes: nil, ephemeral: nil)
    container = {"name" => "c"}
    container["memory"] = {"workingSetBytes" => memory} if memory
    container["rootfs"] = {"usedBytes" => rootfs, "inodesUsed" => 10} if rootfs
    container["logs"] = {"usedBytes" => logs, "inodesUsed" => 1} if logs
    stats = {"podRef" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"}, "containers" => [container],
             "volume" => volumes}
    stats["memory"] = {"workingSetBytes" => memory} if memory
    stats["process_stats"] = {"process_count" => processes} if processes
    stats["ephemeral-storage"] = {"usedBytes" => ephemeral} if ephemeral
    stats
  end

  def memory_node(available:, working_set: 4 * GI)
    {"memory" => {"availableBytes" => available, "workingSetBytes" => working_set}}
  end

  def test_threshold_config_matches_parse_threshold_config
    signals = EM.parse_threshold_config.map(&:signal)
    assert_equal %w[memory.available nodefs.available nodefs.inodesFree imagefs.available imagefs.inodesFree allocatableMemory.available],
                 signals
    hard = EM.parse_threshold_config.find { |threshold| threshold.signal == "nodefs.available" }
    assert_in_delta 0.10, hard.percentage
    assert hard.hard?

    error = assert_raises(EM::ConfigError) { EM.parse_threshold_config(hard: {}, soft: {"memory.available" => "1Gi"}) }
    assert_equal "grace period must be specified for the soft eviction threshold memory.available", error.message
    soft = EM.parse_threshold_config(hard: {}, soft: {"memory.available" => "1Gi"}, soft_grace_period: {"memory.available" => "1m30s"},
                                     minimum_reclaim: {"memory.available" => "500Mi"})
    assert_equal 90.0, soft.first.grace_period
    assert_equal 500 * MI, soft.first.min_reclaim.quantity.value
    # A soft threshold has no allocatable twin; 0% and 100% are no threshold.
    assert_equal ["memory.available"], soft.map(&:signal)
    assert_empty EM.parse_threshold_config(hard: {"nodefs.available" => "0%"}, allocatable_config: [])
    assert_raises(EM::ConfigError) { EM.parse_threshold_config(hard: {"memory.bogus" => "1Gi"}) }
  end

  def test_hard_memory_threshold_evicts_one_pod_ranked_like_the_kubelet
    @summary.node = memory_node(available: 50 * MI)
    # orderedBy(exceedMemoryRequests, priority, memory): over-request first,
    # then lower priority, then the larger excess.
    @pods = [pod("within", request: "1Gi"), pod("over-high", request: "100Mi", priority: 10),
             pod("over-low-small", request: "100Mi"), pod("over-low-big", request: "100Mi")]
    @summary.pods = [pod_stats("within", memory: 500 * MI), pod_stats("over-high", memory: 900 * MI),
                     pod_stats("over-low-small", memory: 200 * MI), pod_stats("over-low-big", memory: GI)]
    subject = manager
    assert_equal %w[over-low-big over-low-small over-high within],
                 subject.rank("memory.available", @pods, @summary.summary["pods"].to_h { |stats| [stats.dig("podRef", "uid"), stats] })
                        .map { |candidate| candidate.dig("metadata", "name") }

    evicted = subject.synchronize
    assert_equal ["over-low-big"], evicted.map { |candidate| candidate.dig("metadata", "name") }
    name, grace, message, condition = @killed.fetch(0)
    assert_equal "over-low-big", name
    assert_equal 1, grace, "a hard threshold evicts with the immediate grace period"
    assert_equal "The node was low on resource: memory. Threshold quantity: 100Mi, available: 50Mi. " \
                 "Container c was using 1Gi, request is 100Mi, has larger consumption of memory. ", message
    assert_equal({"type" => "DisruptionTarget", "status" => "True", "reason" => "TerminationByKubelet", "message" => message}, condition)
    assert_equal ["MemoryPressure"], subject.node_conditions
    assert subject.under_memory_pressure?
    assert_equal 1, @killed.length, "one Pod per pass"
  end

  def test_pods_without_stats_go_first_and_pod_level_requests_count
    @pods = [pod("container-level", request: "100Mi"), pod("pod-level", request: "100Mi", resources: {"requests" => {"memory" => "1Gi"}}),
             pod("no-stats")]
    stats = [pod_stats("container-level", memory: 500 * MI), pod_stats("pod-level", memory: 500 * MI)].to_h { |entry| [entry.dig("podRef", "uid"), entry] }
    ranked = manager.rank("memory.available", @pods, stats).map { |candidate| candidate.dig("metadata", "name") }
    assert_equal %w[no-stats container-level pod-level], ranked
  end

  def test_soft_threshold_waits_for_its_grace_period_and_caps_pod_grace
    thresholds = EM.parse_threshold_config(hard: {}, soft: {"memory.available" => "1Gi"}, soft_grace_period: {"memory.available" => "30s"},
                                           allocatable_config: [])
    @summary.node = memory_node(available: 512 * MI)
    @pods = [pod("a", request: "10Mi", terminationGracePeriodSeconds: 5)]
    @summary.pods = [pod_stats("a", memory: 100 * MI)]
    subject = manager(thresholds: thresholds, max_pod_grace_period_seconds: 20)
    assert_empty subject.synchronize
    assert_equal ["MemoryPressure"], subject.node_conditions, "the condition is reported before the grace period runs out"
    @now = 29.0
    assert_empty subject.synchronize
    @now = 31.0
    assert_equal ["a"], subject.synchronize.map { |candidate| candidate.dig("metadata", "name") }
    assert_equal 5, @killed.fetch(0)[1], "min(evictionMaxPodGracePeriod, terminationGracePeriodSeconds)"
  end

  def test_pressure_condition_is_held_for_the_transition_period
    @summary.node = memory_node(available: 50 * MI)
    subject = manager(pressure_transition_period: 300)
    subject.synchronize
    assert_equal ["MemoryPressure"], subject.node_conditions
    @summary.node = memory_node(available: 8 * GI)
    @now = 100.0
    subject.synchronize
    assert_equal ["MemoryPressure"], subject.node_conditions
    @now = 301.0
    subject.synchronize
    assert_empty subject.node_conditions
  end

  def test_minimum_reclaim_keeps_a_met_threshold_until_reclaimed
    thresholds = EM.parse_threshold_config(hard: {"memory.available" => "100Mi"}, minimum_reclaim: {"memory.available" => "500Mi"},
                                           allocatable_config: [])
    @summary.node = memory_node(available: 50 * MI)
    subject = manager(thresholds: thresholds, pressure_transition_period: 0)
    subject.synchronize
    @summary.node = memory_node(available: 300 * MI)
    @pods = [pod("a")]
    @summary.pods = [pod_stats("a", memory: MI)]
    assert_equal ["a"], subject.synchronize.map { |candidate| candidate.dig("metadata", "name") },
                 "300Mi available is above 100Mi but below 100Mi + 500Mi"
    @summary.node = memory_node(available: 700 * MI)
    assert_empty subject.synchronize
  end

  # thresholdsUpdatedStats: no second eviction on the same sample.
  def test_stale_observation_does_not_evict_again
    stamp = "2026-01-01T00:00:00Z"
    fixed = Struct.new(:data) { def summary = data }.new({"node" => {"memory" => {"availableBytes" => 50 * MI, "workingSetBytes" => GI, "time" => stamp}},
                                                          "pods" => [pod_stats("a", memory: GI)]})
    @pods = [pod("a")]
    subject = EM.new(summary_provider: fixed, active_pods: -> { @pods }, thresholds: EM.parse_threshold_config(allocatable_config: []),
                     kill_pod: ->(pod, **) { @killed << pod }, monotonic: -> { @now })
    assert_equal 1, subject.synchronize.length
    assert_empty subject.synchronize
  end

  def test_critical_pods_are_never_evicted
    @summary.node = memory_node(available: 50 * MI)
    @pods = [pod("critical", priority: 2_000_000_000), pod("static").tap { |entry| entry["metadata"]["annotations"] = {"kubernetes.io/config.source" => "file"} },
             pod("normal", request: "1Gi")]
    @summary.pods = [pod_stats("critical", memory: 2 * GI), pod_stats("static", memory: 2 * GI), pod_stats("normal", memory: MI)]
    assert_equal ["normal"], manager.synchronize.map { |candidate| candidate.dig("metadata", "name") }
  end

  def test_allocatable_memory_signal_from_the_pods_system_container
    @summary.node = memory_node(available: 100 * GI).merge(
      "systemContainers" => [{"name" => "pods", "memory" => {"availableBytes" => 10 * MI, "workingSetBytes" => 2 * GI}}]
    )
    @pods = [pod("a")]
    @summary.pods = [pod_stats("a", memory: GI)]
    subject = manager(thresholds: EM.parse_threshold_config)
    assert_equal ["a"], subject.synchronize.map { |candidate| candidate.dig("metadata", "name") }
    assert_match(/\AThe node was low on resource: memory\. Threshold quantity: 100Mi, available: /, @killed.first[2])
  end

  def test_disk_pressure_ranks_by_local_storage_and_formats_percentages
    capacity = 100 * GI
    @summary.node = {"fs" => {"availableBytes" => 5 * GI, "capacityBytes" => capacity, "inodesFree" => 1_000_000, "inodes" => 2_000_000}}
    @pods = [pod("logs", volumes: [{"name" => "scratch", "emptyDir" => {}}]), pod("rootfs"), pod("pvc", volumes: [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "x"}}])]
    @summary.pods = [pod_stats("logs", rootfs: GI, logs: GI, volumes: [{"name" => "scratch", "usedBytes" => 3 * GI, "inodesUsed" => 5}]),
                     pod_stats("rootfs", rootfs: 4 * GI, logs: 0),
                     pod_stats("pvc", rootfs: 0, logs: 0, volumes: [{"name" => "data", "usedBytes" => 50 * GI, "inodesUsed" => 5}])]
    subject = manager
    evicted = subject.synchronize
    assert_equal ["logs"], evicted.map { |candidate| candidate.dig("metadata", "name") }, "emptyDir usage counts, a PVC does not"
    assert_equal ["DiskPressure"], subject.node_conditions
    assert_equal "The node was low on resource: ephemeral-storage. Threshold quantity: 10737418400, available: 5Gi. " \
                 "Container c was using 2Gi, request is 0, has larger consumption of ephemeral-storage. ", @killed.first[2]
  end

  def test_pid_pressure_ranks_by_priority_then_process_count
    @summary.node = {"rlimit" => {"maxpid" => 1000, "curproc" => 990}}
    thresholds = EM.parse_threshold_config(hard: {"pid.available" => "20"}, allocatable_config: [])
    @pods = [pod("few"), pod("many"), pod("important", priority: 100)]
    @summary.pods = [pod_stats("few", processes: 2), pod_stats("many", processes: 400), pod_stats("important", processes: 500)]
    subject = manager(thresholds: thresholds)
    assert_equal ["many"], subject.synchronize.map { |candidate| candidate.dig("metadata", "name") }
    assert_equal ["PIDPressure"], subject.node_conditions
    assert_equal "The node was low on resource: pids. Threshold quantity: 20, available: 10. ", @killed.first[2]
  end

  def test_local_storage_limits_evict_without_node_pressure
    @summary.node = memory_node(available: 100 * GI)
    empty_dir = pod("empty-dir", volumes: [{"name" => "cache", "emptyDir" => {"sizeLimit" => "1Gi"}}])
    pod_limit = pod("pod-limit")
    pod_limit["spec"]["containers"][0]["resources"] = {"limits" => {"ephemeral-storage" => "1Gi"}}
    container_limit = pod("container-limit")
    container_limit["spec"]["containers"] << {"name" => "d", "resources" => {"limits" => {"ephemeral-storage" => "100Mi"}}}
    fine = pod("fine", volumes: [{"name" => "cache", "emptyDir" => {"sizeLimit" => "1Gi"}}])
    @pods = [empty_dir, pod_limit, container_limit, fine]
    @summary.pods = [pod_stats("empty-dir", volumes: [{"name" => "cache", "usedBytes" => 2 * GI}]),
                     pod_stats("pod-limit", ephemeral: 2 * GI),
                     pod_stats("container-limit").tap { |stats| stats["containers"] << {"name" => "d", "rootfs" => {"usedBytes" => 90 * MI}, "logs" => {"usedBytes" => 20 * MI}} },
                     pod_stats("fine", volumes: [{"name" => "cache", "usedBytes" => 10 * MI}])]
    subject = manager
    assert_equal %w[empty-dir pod-limit container-limit], subject.synchronize.map { |candidate| candidate.dig("metadata", "name") }
    messages = @killed.to_h { |name, _grace, message, _condition| [name, message] }
    assert_equal 'Usage of EmptyDir volume "cache" exceeds the limit "1Gi". ', messages["empty-dir"]
    assert_equal "Pod ephemeral local storage usage exceeds the total limit of containers 1Gi. ", messages["pod-limit"]
    assert_equal 'Container d exceeded its local ephemeral storage limit "100Mi". ', messages["container-limit"]
    assert(@killed.all? { |_name, grace, _message, condition| grace == 1 && condition.nil? })
    assert_empty subject.node_conditions
  end

  def test_node_level_reclaim_is_tried_before_evicting
    @summary.node = {"fs" => {"availableBytes" => 5 * GI, "capacityBytes" => 100 * GI}}
    @pods = [pod("a")]
    @summary.pods = [pod_stats("a", rootfs: GI, logs: 0)]
    reclaimed = []
    subject = manager(node_reclaim: {"nodefs.available" => [lambda {
      reclaimed << true
      @summary.node = {"fs" => {"availableBytes" => 50 * GI, "capacityBytes" => 100 * GI}}
    }]})
    assert_empty subject.synchronize
    assert_equal [true], reclaimed
    assert_empty @killed
  end

  def test_admit_handler_follows_the_node_conditions
    subject = manager
    assert_nil subject.admit(pod("best-effort"))
    @summary.node = memory_node(available: 50 * MI)
    subject.synchronize
    assert_equal ["Evicted", "The node had condition: [MemoryPressure]. "], subject.admit(pod("best-effort"))
    assert_nil subject.admit(pod("burstable", request: "10Mi")), "only BestEffort is refused under memory pressure alone"
    tolerating = pod("tolerating", tolerations: [{"key" => "node.kubernetes.io/memory-pressure", "operator" => "Exists", "effect" => "NoSchedule"}])
    assert_nil subject.admit(tolerating)
    assert_nil subject.admit(pod("critical", priority: 2_000_000_000))

    @summary.node = memory_node(available: 50 * MI).merge("fs" => {"availableBytes" => GI, "capacityBytes" => 100 * GI})
    subject.synchronize
    assert_equal ["Evicted", "The node had condition: [MemoryPressure DiskPressure]. "], subject.admit(pod("burstable", request: "10Mi"))
  end
end
