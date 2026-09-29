# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime"

# The CPU and memory managers' pinning reaches the container cgroup: the
# create-time cpuset (ContainerConfig.Linux.Resources.CpusetCpus/Mems) and
# the CPU manager's reconcile (UpdateContainerResources with CpusetCpus).
class NativeCpusetTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def limits_written(cgroup, handle)
    cgroup.calls.select { |call| call[0] == :configure && call[1] == handle }.map { |call| call[2].to_h.transform_keys(&:to_s) }
  end

  def test_the_cpuset_is_applied_at_create_and_updated_in_place
    cgroup = Native::FakeCgroup.new
    runtime = Native.new(profile: :pure, cgroup_adapter: cgroup)
    sandbox_id = runtime.run_sandbox({"id" => "pinned"})
    container = runtime.create_container(sandbox_id, {"id" => "c1", "command" => ["/bin/true"],
                                                      "limits" => {"cpuset.cpus" => "2-3", "cpuset.mems" => "0"}})
    id = container.respond_to?(:id) ? container.id : container
    handle = runtime.sandbox(sandbox_id).container(id).cgroup
    assert limits_written(cgroup, handle).any? { |limits| limits["cpuset.cpus"] == "2-3" && limits["cpuset.mems"] == "0" }

    assert runtime.update_container_cpuset(container, "0-1,4")
    assert_equal({"cpuset.cpus" => "0-1,4"}, limits_written(cgroup, handle).last)
    assert_equal "0-1,4", runtime.sandbox(sandbox_id).container(id).spec.dig("limits", "cpuset.cpus"),
                 "the container spec records the current cpuset"
  end
end
