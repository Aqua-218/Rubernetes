# frozen_string_literal: true

module Rubernetes
  module PriorityClasses
    SYSTEM = {
      "system-node-critical" => [2_000_001_000, "Used for system critical pods that must not be moved from their current node."],
      "system-cluster-critical" => [2_000_000_000,
                                    "Used for system critical pods that must run in the cluster, but can be moved to another node if necessary."]
    }.freeze
    MAX_USER_PRIORITY = 1_000_000_000
  end
end
