# frozen_string_literal: true

# CSI volume stats as the kubelet reports them: metricsCsi asks the driver
# (NodeGetVolumeStats) for a volume of a kubelet node plugin, leaves the
# volume out when the driver lacks GET_VOLUME_STATS, and the volume stats
# collector (collectors/volume_stats.go) turns PVC volumes into
# kubelet_volume_stats_* gauges on /metrics.

require_relative "../test_helper"
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

  def csi_provider(calls)
    source = lambda do |id, _path|
      calls << id
      case id
      when "vol-csi" then {"capacityBytes" => 1000, "availableBytes" => 600, "usedBytes" => 400,
                           "inodes" => 50, "inodesFree" => 40, "inodesUsed" => 10}
      when "vol-nostats" then :unsupported
      end
    end
    Rubernetes::Node::StatsProvider.new(node_name: "node-a", lifecycle: Lifecycle.new(csi_records),
                                        runtime: Runtime.new(usage(cpu_usec: 1)), pod_root: @dir, cgroup_root: @cgroup,
                                        proc_root: @proc, clock: -> { Time.utc(2026, 1, 1, 0, 1) }, monotonic: -> { @mono },
                                        volume_stats: source)
  end

  def test_csi_volumes_report_the_driver_stats_and_unsupported_ones_are_left_out
    calls = []
    subject = csi_provider(calls)
    volumes = subject.summary.fetch("pods").first.fetch("volume").to_h { |volume| [volume["name"], volume] }

    assert_equal %w[data scratch], volumes.keys.sort
    data = volumes.fetch("data")

    assert_equal [1000, 600, 400, 50, 40, 10],
                 data.values_at("capacityBytes", "availableBytes", "usedBytes", "inodes", "inodesFree", "inodesUsed")
    assert_equal({"name" => "claim", "namespace" => "ns"}, data["pvcRef"])
    assert_operator volumes.fetch("scratch")["usedBytes"], :>=, 4096, "not a CSI volume: measured like du"

    # Cached for fs_ttl, as the kubelet's volume stats aggregation period.
    subject.summary

    assert_equal 3, calls.length
    @mono += 120
    subject.summary

    assert_equal 6, calls.length
  end

  def test_kubelet_metrics_expose_volume_stats_per_pvc
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(csi_records),
                                                   stats_provider: csi_provider([]))
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
end
