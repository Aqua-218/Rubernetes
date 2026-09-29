# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A node keeps a record per Pod, and the record keeps the Pod's own history.
# Neither may grow without bound: the trail is appended to on EVERY sync, so a
# Pod that is retried -- a crash-looping container, a cleanup that has not
# finished -- adds entries for as long as it lives, and a finished Pod's
# tombstone copied the whole trail again.  Measured over one conformance run a
# node agent's resident memory reached three and a half gigabytes for ten
# running Pods, which slows every Pod on that node down with it.
#
# kubelet drops a Pod's state once the Pod is gone (podManager.RemovePod,
# statusManager.RemoveOrphanedStatuses); so does this.
class NodeRecordMemoryTest < Minitest::Test
  Node = Rubernetes::Node

  def lifecycle(deleted = [])
    Node::Lifecycle.new(
      runtime: Object.new,
      pod_deleter: lambda { |namespace:, name:, uid: nil| deleted << [namespace, name, uid] }
    )
  end

  def record(uid: "pod-uid")
    {uid: uid, events: [], state: "Running", phase: "Running", cleanup_errors: [],
     pod: {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => uid}, "spec" => {}}}
  end

  def test_the_event_trail_is_bounded
    subject = lifecycle
    entry = record
    limit = Node::Lifecycle::MAX_RECORD_EVENTS

    (limit + 50).times { |index| subject.send(:event, entry, "sync", "index" => index) }

    assert_equal(limit, entry[:events].length)
  end

  # The newest entries are the ones worth having.
  def test_the_newest_events_are_the_ones_kept
    subject = lifecycle
    entry = record
    limit = Node::Lifecycle::MAX_RECORD_EVENTS

    (limit + 5).times { |index| subject.send(:event, entry, "sync", "index" => index) }

    assert_equal(limit + 4, entry[:events].last.fetch("index"))
    assert_equal(5, entry[:events].first.fetch("index"))
  end

  # A terminal tombstone exists to stop a later sync starting the Pod again and
  # to republish its final status; the diagnostic trail is no part of that.
  def test_a_finished_tombstone_drops_the_event_trail
    subject = lifecycle
    entry = record
    entry[:phase] = "Succeeded"
    entry[:pod]["spec"]["restartPolicy"] = "Never"
    20.times { |index| subject.send(:event, entry, "sync", "index" => index) }

    subject.send(:remember_finished, entry)
    remembered = subject.instance_variable_get(:@finished).fetch("pod-uid")

    assert_equal("Succeeded", remembered.fetch("phase"))
    assert_empty(remembered.fetch("record").fetch(:events))
  end

  # Once the API object is gone there is nothing left to start again and
  # nothing left to report.
  def test_the_record_is_forgotten_once_the_pod_is_deleted
    subject = lifecycle
    subject.instance_variable_get(:@finished)["pod-uid"] = {"phase" => "Succeeded", "record" => record}

    subject.send(:forget_pod, "pod-uid")

    assert_empty(subject.instance_variable_get(:@finished))
  end

  def test_forgetting_an_empty_uid_does_nothing
    subject = lifecycle
    subject.instance_variable_get(:@finished)["keep"] = {"phase" => "Succeeded"}

    subject.send(:forget_pod, nil)

    assert_equal(%w[keep], subject.instance_variable_get(:@finished).keys)
  end
end
