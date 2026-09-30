# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime"

# The container's CPU ceiling, like its memory ceiling, is applied once the
# workload has exec'd: the bootstrap that builds the container's rootfs runs
# inside the container cgroup, and under a 10m limit it was throttled to 1 ms
# of CPU per 100 ms period.
class NativeDeferredCPULimitTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def limits_written(cgroup, handle)
    cgroup.calls.select { |call| call[0] == :configure && call[1] == handle }.map { |call| call[2].to_h.transform_keys(&:to_s) }
  end

  def test_cpu_max_is_withheld_until_the_workload_started
    cgroup = Native::FakeCgroup.new
    runtime = Native.new(profile: :pure, cgroup_adapter: cgroup)
    sandbox_id = runtime.run_sandbox({"id" => "cpu-deferred"})
    container = runtime.create_container(sandbox_id, {"id" => "c1", "command" => ["/bin/true"],
                                                      "limits" => {"cpu.max" => "1000 100000", "cpu.weight" => "10"}})
    handle = runtime.sandbox(sandbox_id).container(container.respond_to?(:id) ? container.id : container).cgroup
    before = limits_written(cgroup, handle)

    refute before.any? { |limits| limits.key?("cpu.max") }, "cpu.max is not set while the bootstrap runs"
    assert before.any? { |limits| limits["cpu.weight"] == "10" }, "the other limits are applied at create"

    runtime.start_container(container)

    assert limits_written(cgroup, handle).any? { |limits| limits["cpu.max"] == "1000 100000" }, "cpu.max is applied after exec"
  end
end
