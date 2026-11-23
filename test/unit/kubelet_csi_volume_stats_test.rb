# frozen_string_literal: true

# CSI volume stats as the kubelet reports them: metricsCsi asks the driver
# (NodeGetVolumeStats) for a volume of a kubelet node plugin, leaves the
# volume out when the driver lacks GET_VOLUME_STATS, and the volume stats
# collector (collectors/volume_stats.go) turns PVC volumes into
# kubelet_volume_stats_* gauges on /metrics.

require_relative "../test_helper"
require_relative "../support/node_agent_fakes"
require_relative "../support/node_stats_summary_harness"

class KubeletCSIVolumeStatsTest < Minitest::Test
  include NodeStatsSummaryHarness

  def csi_records
    pod = {"metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1"},
           "spec" => {"volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}},
                                    {"name" => "other", "persistentVolumeClaim" => {"claimName" => "other-claim"}},
                                    {"name" => "scratch", "emptyDir" => {}}],
                      "containers" => [{"name" => "app"}]}}
    {"u1" => {uid: "u1", state: "Running", sandbox_id: "s1", pod: pod, started_at: "2026-01-01T00:00:00Z",
              containers: [{id: "c1", name: "app", started_at: "2026-01-01T00:00:01Z"}],
              volume: {"mounts" => {"data" => {"id" => "vol-csi", "path" => @volume},
                                    "other" => {"id" => "vol-nostats", "path" => @volume},
                                    "scratch" => {"id" => "vol-empty", "path" => @volume}}}}}
  end

  def csi_provider(calls = [], health: false, events: nil, source: nil, lifecycle: Lifecycle.new(csi_records), **)
    source ||= lambda do |id, _path|
      calls << id
      case id
      when "vol-csi" then {"capacityBytes" => 1000, "availableBytes" => 600, "usedBytes" => 400,
                           "inodes" => 50, "inodesFree" => 40, "inodesUsed" => 10,
                           "volumeCondition" => {"abnormal" => true, "message" => "I/O errors"}}
      when "vol-nostats" then :unsupported
      end
    end
    Rubernetes::Node::StatsProvider.new(node_name: "node-a", lifecycle: lifecycle,
                                        runtime: Runtime.new(usage(cpu_usec: 1)), pod_root: @dir, cgroup_root: @cgroup,
                                        proc_root: @proc, clock: -> { Time.utc(2026, 1, 1) + @mono }, monotonic: -> { @mono },
                                        volume_stats: source, volume_health: health, event_recorder: events, **)
  end

  def test_csi_volumes_report_the_driver_stats_and_unsupported_ones_are_left_out
    calls = []
    subject = csi_provider(calls)
    subject.sample_volume_stats
    volumes = subject.summary.fetch("pods").first.fetch("volume").to_h { |volume| [volume["name"], volume] }

    assert_equal %w[data scratch], volumes.keys.sort
    data = volumes.fetch("data")

    assert_equal [1000, 600, 400, 50, 40, 10],
                 data.values_at("capacityBytes", "availableBytes", "usedBytes", "inodes", "inodesFree", "inodesUsed")
    assert_equal({"name" => "claim", "namespace" => "ns"}, data["pvcRef"])
    refute data.key?("volumeHealthStats")
    assert_operator volumes.fetch("scratch")["usedBytes"], :>=, 4096, "not a CSI volume: measured like du"

    assert_equal 3, calls.length
  end

  def test_health_is_returned_and_events_are_emitted_only_for_fresh_driver_status
    events = []
    recorder = Object.new
    recorder.define_singleton_method(:record) { |**event| events << event }
    provider = csi_provider([], health: true, events: recorder)
    provider.sample_volume_stats

    assert_equal({"abnormal" => true}, provider.summary.dig("pods", 0, "volume", 0, "volumeHealthStats"))
    assert_equal ["Warning", "VolumeConditionAbnormal", "Volume data: I/O errors"], events.first.values_at(:type, :reason, :message)
    node = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(csi_records), stats_provider: provider)
    _, _, body = node.call(Request.new("/metrics", "GET", {}))

    assert_includes body.join, 'kubelet_volume_stats_health_status_abnormal{namespace="ns",persistentvolumeclaim="claim"} 1'
    assert_equal 1, events.length
  end

  def test_kubelet_metrics_expose_volume_stats_per_pvc
    provider = csi_provider
    provider.sample_volume_stats
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(csi_records), stats_provider: provider)
    status, _headers, body = server.call(Request.new("/metrics", "GET", {}))

    assert_equal 200, status
    text = body.join
    labels = '{namespace="ns",persistentvolumeclaim="claim"}'

    assert_includes text, "kubelet_volume_stats_capacity_bytes#{labels} 1000"
    assert_includes text, "kubelet_volume_stats_available_bytes#{labels} 600"
    assert_includes text, "kubelet_volume_stats_used_bytes#{labels} 400"
    assert_includes text, "kubelet_volume_stats_inodes#{labels} 50"
    assert_includes text, "kubelet_volume_stats_inodes_free#{labels} 40"
    assert_includes text, "kubelet_volume_stats_inodes_used#{labels} 10"
    refute_includes text, 'persistentvolumeclaim="other-claim"'
  end

  def test_scrapes_share_the_periodic_sample_and_do_not_scan_when_the_period_expires
    calls = []
    collected = []
    subject = csi_provider(calls, volume_stats_agg_period: 5)
    subject.metrics_observer = ->(source, _) { collected << source }
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(csi_records), stats_provider: subject)
    subject.sample_volume_stats
    initial = subject.summary.fetch("pods").first
    File.write(File.join(@volume, "additional"), "x" * 8192)
    @mono += 4
    subject.sample_volume_stats

    assert_equal [3, %w[csi fs]], [calls.size, collected]

    20.times do
      pod = subject.summary.fetch("pods").first

      assert_equal initial.fetch("volume"), pod.fetch("volume")
      assert_equal initial.dig("ephemeral-storage", "usedBytes"), pod.dig("ephemeral-storage", "usedBytes")
      assert_includes server.call(Request.new("/metrics", "GET", {})).last.join,
                      'kubelet_volume_stats_used_bytes{namespace="ns",persistentvolumeclaim="claim"} 400'
    end
    @mono += 1

    assert_equal initial.fetch("volume"), subject.summary.dig("pods", 0, "volume")
    assert_equal [3, %w[csi fs]], [calls.size, collected]

    subject.sample_volume_stats
    fresh = subject.summary.fetch("pods").first
    stamps = fresh.fetch("volume").map { |volume| volume.fetch("time") }

    assert_equal 6, calls.size
    assert_equal %w[csi fs csi fs], collected
    assert_equal ["2026-01-01T00:01:45Z"] * 2, stamps
    assert_operator fresh.dig("ephemeral-storage", "usedBytes"), :>, initial.dig("ephemeral-storage", "usedBytes")
  end

  def test_disabled_periods_skip_csi_and_local_volume_collection
    [0, -1].each do |period|
      calls = []
      provider = csi_provider(calls, volume_stats_agg_period: period)
      provider.start_volume_stats
      provider.sample_volume_stats

      assert_nil provider.summary.dig("pods", 0, "volume")
      assert_empty calls
    ensure
      provider&.stop_volume_stats
    end
  end

  def test_agent_collects_multiple_samples_before_any_scrape_and_stops_sampling
    collected = Thread::Queue.new
    source = lambda do |id, _|
      collected << id if id == "vol-csi"
      {"usedBytes" => 400}
    end
    provider = csi_provider(source: source, volume_stats_agg_period: 0.03,
                            monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
    agent = Rubernetes::Node::Agent.new(node_name: "node-a", api: NodeAgentFakes::API.new, lifecycle: NodeAgentFakes::Lifecycle.new,
                                        sync_loop: NodeAgentFakes::SyncLoop.new, stats_provider: provider, relist_period: 0.01,
                                        eviction: {"enabled" => false})
    agent.start

    assert_equal ["vol-csi"] * 2, Array.new(2) { collected.pop(timeout: 3) }

    agent.stop
    collected.clear

    assert_nil collected.pop(timeout: 0.09)
    assert_nil provider.summary.dig("pods", 0, "volume")
  ensure
    agent&.stop
  end

  def test_sampler_owns_csi_collection_and_joins_an_in_flight_sample_on_stop
    started = Thread::Queue.new
    release = Thread::Queue.new
    source = lambda do |id, _|
      started << id
      release.pop(timeout: 3) if id == "vol-csi"
      {"usedBytes" => 400}
    end
    provider = csi_provider(source: source)
    provider.start_volume_stats

    assert_equal "vol-csi", started.pop(timeout: 3)
    provider.sample_volume_stats

    assert_nil provider.summary.dig("pods", 0, "volume"), "scraping cannot block on an in-flight driver request"
    assert_empty started

    done = Thread::Queue.new
    stopper = Thread.new do
      provider.stop_volume_stats
      done << true
    end

    assert_nil done.pop(timeout: 0.03)
    release << true

    assert stopper.join(2)
    assert_equal true, done.pop(timeout: 1)
    assert_nil provider.summary.dig("pods", 0, "volume")
    assert_empty started
  ensure
    release << true
    provider&.stop_volume_stats
    stopper&.join(2)
  end

  def test_removal_and_replaced_mounts_do_not_expose_the_previous_sample
    records = csi_records
    lifecycle = Lifecycle.new(records)
    lifecycle.define_singleton_method(:stats_records) { records.values }
    calls = []
    provider = csi_provider(calls, lifecycle: lifecycle)
    provider.sample_volume_stats

    assert_equal 400, provider.summary.dig("pods", 0, "volume", 0, "usedBytes")
    removed = records.delete("u1")

    assert_empty provider.summary.fetch("pods")

    # Same Pod identity and paths, freshly provisioned mounts.
    records["u1"] = removed.merge(volume: Marshal.load(Marshal.dump(removed[:volume])))

    assert_nil provider.summary.dig("pods", 0, "volume")
    assert_equal 3, calls.size

    @mono += 60
    provider.sample_volume_stats

    assert_equal 400, provider.summary.dig("pods", 0, "volume", 0, "usedBytes")
    assert_equal 6, calls.size
  end
end
