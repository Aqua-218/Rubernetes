# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# Behaviours taken from the upstream registry strategies rather than from a
# field list: a field-name audit cannot see them at all.
#   - Strategy.AllowCreateOnUpdate: a PUT to a missing object CREATES it for
#     Lease, LeaseCandidate, Endpoints, Event, LimitRange and Service.
#   - Strategy.DefaultGarbageCollectionPolicy: with no propagationPolicy from
#     the client, core/v1 ReplicationController and batch/v1 Job/CronJob ORPHAN
#     their dependents (back-compatibility), and Events support no cascade.
class APIStrategyHooksTest < Minitest::Test
  Server = Rubernetes::API::Server

  def descriptor(group, version, resource, kind = "X")
    Struct.new(:group, :version, :resource, :kind, :namespaced) do
      def custom? = false
    end.new(group, version, resource, kind, true)
  end

  def server
    Server.allocate
  end

  def test_create_on_update_kinds
    %w[leases endpoints limitranges services].each do |resource|
      group = resource == "leases" ? "coordination.k8s.io" : ""

      assert server.send(:allow_create_on_update?, descriptor(group, "v1", resource)),
             "#{resource} must be creatable through PUT"
    end
    assert server.send(:allow_create_on_update?, descriptor("", "v1", "events"))
    assert server.send(:allow_create_on_update?, descriptor("events.k8s.io", "v1", "events"))
  end

  def test_other_kinds_are_not_creatable_through_update
    %w[pods configmaps secrets deployments].each do |resource|
      group = resource == "deployments" ? "apps" : ""

      refute server.send(:allow_create_on_update?, descriptor(group, "v1", resource))
    end
  end

  def test_replication_controller_orphans_by_default
    assert server.send(:orphan_deletion?, {}, descriptor("", "v1", "replicationcontrollers")),
           "core/v1 ReplicationController defaults to orphaning its Pods"
  end

  def test_batch_v1_job_and_cronjob_orphan_by_default
    assert server.send(:orphan_deletion?, {}, descriptor("batch", "v1", "jobs"))
    assert server.send(:orphan_deletion?, {}, descriptor("batch", "v1", "cronjobs"))
  end

  def test_other_kinds_cascade_by_default
    refute server.send(:orphan_deletion?, {}, descriptor("apps", "v1", "deployments"))
    refute server.send(:orphan_deletion?, {}, descriptor("apps", "v1", "replicasets"))
  end

  def test_an_explicit_policy_always_wins
    rc = descriptor("", "v1", "replicationcontrollers")

    refute server.send(:orphan_deletion?, {"propagationPolicy" => "Background"}, rc)
    refute server.send(:orphan_deletion?, {"propagationPolicy" => "Foreground"}, rc)
    assert server.send(:orphan_deletion?, {"propagationPolicy" => "Orphan"},
                       descriptor("apps", "v1", "deployments"))
    refute server.send(:orphan_deletion?, {"orphanDependents" => false}, rc)
  end

  def test_events_do_not_cascade
    assert server.send(:garbage_collection_unsupported?, descriptor("", "v1", "events"))
    assert server.send(:garbage_collection_unsupported?, descriptor("events.k8s.io", "v1", "events"))
    refute server.send(:garbage_collection_unsupported?, descriptor("apps", "v1", "deployments"))
  end
end
