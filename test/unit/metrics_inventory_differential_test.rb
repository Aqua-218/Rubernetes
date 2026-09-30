# frozen_string_literal: true

# tools/differential/metrics_inventory_differential.rb: the static
# classification of upstream metrics and the per-family comparison the Go
# expfmt oracle's output goes through (the oracle run itself needs the
# Kubernetes source tree and is exercised by the tool).

require_relative "../test_helper"
require_relative "../../tools/differential/metrics_inventory_differential"

class MetricsInventoryDifferentialTest < Minitest::Test
  D = MetricsInventoryDifferential
  M = Rubernetes::Observability::Metrics

  def state(component, name) = D.classify(component).find { |row| row["name"] == name }&.fetch("state")

  def test_classification
    assert_equal "wired", state("kube-apiserver", "apiserver_cel_compilation_duration_seconds")
    assert_equal "hidden", state("kube-apiserver", "etcd_bookmark_counts")
    assert_equal "unimplemented", state("kube-apiserver", "apiserver_storage_list_total")
    assert_equal "upstream-unused", state("kube-apiserver", "aggregator_openapi_v2_regeneration_count")
    assert_equal "wired", state("kube-controller-manager", "job_controller_stale_sync_skips_total")
    assert_equal "wired", state("kube-controller-manager", "attachdetach_controller_total_volumes")
  end

  def test_component_base_hiding
    assert M.hidden?({"deprecatedVersion" => "1.36.0", "stabilityLevel" => "ALPHA"})
    refute M.hidden?({"deprecatedVersion" => "1.36.0", "stabilityLevel" => "BETA"})
    assert M.hidden?({"deprecatedVersion" => "1.35.0", "stabilityLevel" => "BETA"})
    refute M.hidden?({"deprecatedVersion" => "1.34.0", "stabilityLevel" => "STABLE"})
    assert M.hidden?({"deprecatedVersion" => "1.33.0", "stabilityLevel" => "STABLE"})
    refute M.hidden?({"stabilityLevel" => "ALPHA"})
  end

  def test_family_comparison
    entry = M.upstream.fetch("apiserver_watch_list_duration_seconds")
    family = {"name" => "apiserver_watch_list_duration_seconds", "type" => "HISTOGRAM", "help" => M.annotated_help(entry),
              "labels" => [%w[group resource scope version]],
              "buckets" => entry["buckets"].map { |bound| M.go_float(bound.to_f) } + ["+Inf"]}
    assert_empty D.family_problems("kube-apiserver", family)
    assert_match(/labels/, D.family_problems("kube-apiserver", family.merge("labels" => [%w[group resource]])).join)
    assert_match(/type COUNTER/, D.family_problems("kube-apiserver", family.merge("type" => "COUNTER")).join)
    assert_match(/buckets/, D.family_problems("kube-apiserver", family.merge("buckets" => ["1", "+Inf"])).join)
    assert_match(/does not serve/, D.family_problems("kubelet", family).join)
    # Const labels are part of the label set.
    seat = M.upstream.fetch("apiserver_flowcontrol_priority_level_seat_utilization")
    assert_empty D.family_problems("kube-apiserver", {"name" => "apiserver_flowcontrol_priority_level_seat_utilization", "type" => "HISTOGRAM",
                                                      "help" => M.annotated_help(seat), "labels" => [%w[phase priority_level]]})
  end

  def test_inventory_buckets_are_numbers
    bad = M.upstream.select { |_name, entry| Array(entry["buckets"]).any? { |bound| !bound.is_a?(Numeric) } }
    assert_empty bad.keys
  end
end
