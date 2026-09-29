# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"

# An update's defaulting and structural validation walked the whole object
# although the stored one was defaulted and validated when written: 2.5 ms of
# a Pod PUT, and "[sig-node] Pods Extended ... 500 podspec updates" changes a
# single field each time.  Fields equal to the stored ones now keep the stored
# (frozen, defaulted) values and are not validated again -- defaulting is
# idempotent, and CRD validation ratcheting skips unchanged values too.
class SchemaUpdateBaselineTest < Minitest::Test
  Schema = Rubernetes::Schema

  def pod_definition
    Rubernetes::Schema::Catalog.default.definition_for("io.k8s.api.core.v1.Pod") ||
      Rubernetes::Schema::Catalog.default.find(group: "", version: "v1", kind: "Pod")
  rescue StandardError
    Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod")
  end

  def contract
    Rubernetes::Bootstrap::APIServerService::SchemaContract.new(pod_definition)
  end

  def pod(containers)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns"},
     "spec" => {"activeDeadlineSeconds" => 10, "containers" => containers}}
  end

  def stored
    Schema::DeepFreeze.call(contract.default(pod([{"name" => "a", "image" => "busybox"}])))
  end

  def test_unchanged_fields_keep_the_stored_values
    old = stored
    incoming = JSON.parse(JSON.generate(old))
    incoming["spec"]["activeDeadlineSeconds"] = 9
    result = contract.default(incoming, old: old)

    assert_equal 9, result["spec"]["activeDeadlineSeconds"]
    assert_equal old["spec"]["containers"], result["spec"]["containers"]
    assert_same old["metadata"], result["metadata"]
  end

  def test_a_changed_subtree_is_still_defaulted
    old = stored
    incoming = JSON.parse(JSON.generate(old))
    incoming["spec"]["containers"] << {"name" => "b", "image" => "busybox:latest"}
    result = contract.default(incoming, old: old)
    added = result["spec"]["containers"].last

    assert_equal "Always", added["imagePullPolicy"]
    assert_equal "File", added["terminationMessagePolicy"]
    assert_equal result, contract.default(JSON.parse(JSON.generate(incoming))), "same result as defaulting from scratch"
  end

  def test_validation_still_reports_a_changed_invalid_value
    old = stored
    incoming = JSON.parse(JSON.generate(old))
    incoming["spec"]["activeDeadlineSeconds"] = "not a number"
    issues = pod_definition.validator.errors(incoming, operation: :update, old: old)

    assert(issues.any? { |issue| issue.path == %w[spec activeDeadlineSeconds] }, issues.map(&:path).inspect)
  end

  def test_deep_freeze_remembers_what_it_froze
    value = {"a" => [{"b" => "c"}]}
    Schema::DeepFreeze.call(value)
    assert Schema::DeepFreeze.deep_frozen?(value)
    assert Schema::DeepFreeze.deep_frozen?(value["a"])
    refute Schema::DeepFreeze.deep_frozen?({"x" => +"y"}.freeze), "shallowly frozen is not deep frozen"
  end

  # The update path truncates metav1.Time fields once, for its no-op check,
  # and the store takes that result without walking it again.
  def test_a_truncated_object_is_not_truncated_again
    codec = Rubernetes::API::StoreAdapter.time_codec
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "p", "creationTimestamp" => "2026-09-25T00:00:00.123456Z"}}
    truncated = codec.truncated_frozen(pod)

    assert_equal "2026-09-25T00:00:00Z", truncated["metadata"]["creationTimestamp"]
    assert truncated.frozen?
    assert_same truncated, codec.truncate_times(truncated)
  end
end

