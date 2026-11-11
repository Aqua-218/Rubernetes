# frozen_string_literal: true

# Two house rules, as one extension.
#
#   rubectl extension apply examples/extensions/team_rules.rb

# Every Pod says whose it is.
validate "pods", on: :create do |request|
  owner = request.object.dig("metadata", "labels", "team")
  request.reject("Pods need a `team` label so we know whom to ask") if owner.to_s.empty?
end

# Batch work stays off the nodes kept for interactive services.
filter "KeepBatchOffInteractive" do |pod, node|
  next true unless pod.labels["tier"] == "batch"

  node.labels["workload"] == "interactive" ? "node is reserved for interactive workloads" : true
end

# Among the nodes that are left, prefer the emptier ones a little more than
# the built-in scoring does.
score "PreferQuietNodes", weight: 2 do |_pod, node|
  100 - [node.pods.length * 10, 100].min
end
