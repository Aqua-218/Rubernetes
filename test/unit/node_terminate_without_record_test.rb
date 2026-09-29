# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# The API server sets a Pod's deletionTimestamp and waits for the node
# whatever state the Pod reached, so a Pod that was scheduled here and never
# ran -- admission refused it, its namespace went away first -- still has to be
# confirmed gone.  It has nothing to clean up and everything to confirm, and
# returning without a word left it Terminating in the API for ever:
# "[sig-api-machinery] ... wait for pod to disappear" timed out after five
# minutes on Pods that had never started.
class NodeTerminateWithoutRecordTest < Minitest::Test
  Node = Rubernetes::Node

  def lifecycle(deleted)
    Node::Lifecycle.new(
      runtime: Object.new,
      pod_deleter: lambda { |namespace:, name:, uid: nil| deleted << [namespace, name, uid] }
    )
  end

  def pod(deletion: true)
    metadata = {"name" => "never-ran", "namespace" => "ns", "uid" => "pod-uid"}
    metadata["deletionTimestamp"] = "2026-09-16T00:00:00Z" if deletion
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata,
     "spec" => {"nodeName" => "worker-0", "containers" => [{"name" => "c", "image" => "busybox"}]},
     "status" => {"phase" => "Pending"}}
  end

  def test_a_pod_the_node_never_started_is_still_deleted
    deleted = []

    lifecycle(deleted).terminate(pod)

    assert_equal([["ns", "never-ran", "pod-uid"]], deleted)
  end

  # Only a Pod the API server actually marked for deletion: an unknown Pod
  # without a deletionTimestamp is not ours to remove.
  def test_a_pod_without_a_deletion_timestamp_is_left_alone
    deleted = []

    lifecycle(deleted).terminate(pod(deletion: false))

    assert_empty(deleted)
  end

  def test_a_uid_with_no_record_deletes_nothing
    deleted = []

    lifecycle(deleted).terminate("unknown-uid")

    assert_empty(deleted)
  end
end
