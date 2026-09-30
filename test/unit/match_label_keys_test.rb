# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/schema"

# matchLabelKeys / mismatchLabelKeys (MatchLabelKeysInPodAffinity, GA, and
# MatchLabelKeysInPodTopologySpreadSelectorMerge, Beta): the API server
# merges them into the selectors when a Pod is created, and validates them
# for Pods and pod templates.  Neither happened before -- the scheduler read
# the keys itself, and nothing rejected a key named twice.  Compared with
# the upstream strategy + validation (test/conformance/kubernetes/label_keys_oracle).
class MatchLabelKeysTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator
  ORACLE = File.expand_path("../conformance/kubernetes/label_keys_oracle", __dir__)

  def render(issues, object)
    issues.map do |issue|
      cause = issue.to_cause(object)
      "#{cause["field"]}: #{cause["message"]}"
    end.sort
  end

  def same(expected, actual, message)
    expected.nil? ? assert_nil(actual, message) : assert_equal(expected, actual, message)
  end

  def test_every_case_matches_upstream
    expected_path = File.join(ORACLE, "expected.json")
    skip "expected.json not generated yet" unless File.exist?(expected_path)

    expected = JSON.parse(File.read(expected_path))
    server = Rubernetes::API::Server.new
    JSON.parse(File.read(File.join(ORACLE, "cases.json"))).each do |entry|
      want = expected.fetch(entry["name"])
      object = Marshal.load(Marshal.dump(entry["new"]))
      case entry["mode"]
      when "create"
        server.send(:merge_label_keys!, object)
        issues = Validator.send(:label_keys_errors, object, "Pod", :create, nil)
        spec = JSON.parse(JSON.generate(want["spec"]))
        same(spec["affinity"], object.dig("spec", "affinity"), "#{entry["name"]}: merged affinity")
        same(spec["topologySpreadConstraints"], object.dig("spec", "topologySpreadConstraints"), "#{entry["name"]}: merged constraints")
      when "update"
        issues = Validator.send(:label_keys_errors, object, "Pod", :update, entry["old"])
      else
        template = {"kind" => "PodTemplate", "template" => {"metadata" => object["metadata"], "spec" => object["spec"]}}
        issues = Validator.send(:label_keys_errors, template, "PodTemplate", :create, nil)
        object = template
      end

      assert_equal (want["errors"] || []), render(issues, object), entry["name"]
    end
  end
end
