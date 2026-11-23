# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# container.resizePolicy says whether a given resource can change in place or
# requires the container to be restarted (types.go: NotRequired vs
# RestartContainer).  The field was validated by the API server and read by
# nobody, so a container that asked to be restarted for a memory change was
# silently resized in place instead.
class NodeResizePolicyTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  def subject
    Lifecycle.allocate
  end

  def definition(policies)
    {"name" => "c", "image" => "img",
     "resizePolicy" => policies.map { |resource, policy| {"resourceName" => resource, "restartPolicy" => policy} }}
  end

  def entry(resources)
    {name: "c", spec: {"resources" => resources}}
  end

  def test_memory_marked_restart_container_requires_a_restart
    assert subject.send(:resize_requires_restart?,
                        definition("memory" => "RestartContainer"),
                        entry("limits" => {"memory" => "100Mi"}),
                        {"limits" => {"memory" => "200Mi"}})
  end

  def test_a_resource_marked_not_required_resizes_in_place
    refute subject.send(:resize_requires_restart?,
                        definition("memory" => "NotRequired"),
                        entry("limits" => {"memory" => "100Mi"}),
                        {"limits" => {"memory" => "200Mi"}})
  end

  def test_a_policy_for_an_unchanged_resource_does_not_force_a_restart
    refute subject.send(:resize_requires_restart?,
                        definition("memory" => "RestartContainer"),
                        entry("limits" => {"memory" => "100Mi", "cpu" => "1"}),
                        {"limits" => {"memory" => "100Mi", "cpu" => "2"}}),
           "only a resource that actually changed can trigger its restart policy"
  end

  def test_cpu_marked_restart_container_requires_a_restart
    assert subject.send(:resize_requires_restart?,
                        definition("cpu" => "RestartContainer"),
                        entry("requests" => {"cpu" => "100m"}),
                        {"requests" => {"cpu" => "200m"}})
  end

  def test_pod_level_limit_change_requires_a_restart_only_for_containers_using_it
    policy = definition("cpu" => "RestartContainer")
    before = {"spec" => {"resources" => {"limits" => {"cpu" => "500m"}}}}
    after = {"spec" => {"resources" => {"limits" => {"cpu" => "700m"}}}}
    explicit = {"limits" => {"cpu" => "200m"}}

    assert subject.send(:resize_requires_restart?, policy, entry({}), {}, current_pod: before, desired_pod: after)
    refute subject.send(:resize_requires_restart?, policy, entry(explicit), explicit, current_pod: before, desired_pod: after)
  end

  def test_equivalent_quantities_do_not_require_a_restart
    policy = definition("cpu" => "RestartContainer")

    refute subject.send(:resize_requires_restart?, policy,
                        entry("limits" => {"cpu" => "1"}), {"limits" => {"cpu" => "1000m"}})
  end

  def test_no_policy_never_restarts
    refute subject.send(:resize_requires_restart?,
                        {"name" => "c", "image" => "img"},
                        entry("limits" => {"memory" => "100Mi"}),
                        {"limits" => {"memory" => "200Mi"}})
  end

  def test_changed_resource_names_covers_requests_and_limits
    names = subject.send(:changed_resource_names,
                         {"requests" => {"cpu" => "1"}, "limits" => {"memory" => "1Gi"}},
                         {"requests" => {"cpu" => "2"}, "limits" => {"memory" => "2Gi"}})

    assert_equal %w[cpu memory].sort, names.sort
  end

  def test_an_added_resource_counts_as_changed
    names = subject.send(:changed_resource_names, {}, {"limits" => {"memory" => "1Gi"}})

    assert_equal ["memory"], names
  end
end
