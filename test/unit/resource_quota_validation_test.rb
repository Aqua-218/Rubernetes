# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/schema"

# ValidateResourceQuota / ValidateResourceQuotaUpdate /
# ValidateResourceQuotaStatusUpdate against the upstream oracle's output
# (test/conformance/kubernetes/quota_validation_oracle).  Only the scope
# selector was checked before: unknown resource names, negative and
# fractional counts, scopes that cannot apply to a resource, conflicting
# scopes and in-place scope changes were all stored.
class ResourceQuotaValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator
  ORACLE = File.expand_path("../conformance/kubernetes/quota_validation_oracle", __dir__)

  def test_every_case_matches_upstream
    expected = JSON.parse(File.read(File.join(ORACLE, "expected.json")))
    JSON.parse(File.read(File.join(ORACLE, "cases.json"))).each do |entry|
      operation = %w[update status].include?(entry["mode"]) ? :update : :create
      subresource = entry["mode"] == "status" ? "status" : nil
      issues = Validator.send(:resource_quota_errors, entry["new"], operation, entry["old"], subresource)
      rendered = issues.map do |issue|
        cause = issue.to_cause(entry["new"])
        "#{cause["field"]}: #{cause["message"]}"
      end

      assert_equal (expected.fetch(entry["name"]) || []), rendered.sort, entry["name"]
    end
  end
end
