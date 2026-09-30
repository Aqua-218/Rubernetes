# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime/native"

class NativeRuntimeLifecycleTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def setup
    @runtime = Native.new
  end

  def test_backend_completes_sandbox_and_container_lifecycle_without_host_effects
    sandbox_id = @runtime.run_sandbox({"request_id" => "request-1"})
    container = @runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"]})

    @runtime.start_container(container)

    assert_equal("running", @runtime.container_status(container)["state"])
    @runtime.stop_container(container)

    assert_equal("stopped", @runtime.container_status(container)["state"])
    @runtime.stop_sandbox(sandbox_id)
    @runtime.remove_sandbox(sandbox_id)

    assert_empty(@runtime.sandboxes)
  end

  # A workload that exits on its own must be observed as stopped: while status
  # kept reporting it as running, its Pod never reached a confirmed stop and
  # the node re-created the Pod on every sync.
  def test_status_observes_a_container_that_exited_on_its_own
    adapter = Class.new(Rubernetes::Runtime::Native::FakeProcessAdapter) do
      def wait(pid:, timeout: nil)
        super(pid: pid, timeout: nil)
      end
    end.new
    runtime = Native.new(adapters: {process_adapter: adapter})
    sandbox_id = runtime.run_sandbox({"request_id" => "request-exit"})
    container = runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"]})
    runtime.start_container(container)

    assert_equal("stopped", runtime.container_status(container)["state"])
  end

  def test_request_replay_is_idempotent
    first = @runtime.run_sandbox({"request_id" => "same"})
    second = @runtime.run_sandbox({"request_id" => "same"})

    assert_equal(first, second)
    assert_equal(1, @runtime.sandboxes.length)
  end

  def test_unsafe_rootfs_entry_fails_before_sandbox_effects
    error = assert_raises(Native::Filesystem::UnsafeEntry) do
      @runtime.run_sandbox({"request_id" => "unsafe", "rootfs_entries" => [{"path" => "../escape"}]})
    end

    assert_match(/parent traversal/, error.message)
    assert_empty(@runtime.sandboxes)
    assert_empty(@runtime.trace)
  end

  def test_sandbox_exports_verified_network_namespace_holder_context
    sandbox = Native::Sandbox.new(id: "sandbox-netns", identity: "sandbox:sandbox-netns", config: {})
    network_link = File.readlink("/proc/self/ns/net")
    sandbox.set_resources(namespace: {
                            "identity" => "namespace:sandbox-netns",
                            "kernel_identity" => {
                              "pid" => Process.pid,
                              "pidfd" => 91,
                              "start_time" => 123,
                              "namespace_links" => {"network" => network_link}
                            }
                          })

    context = sandbox.network_sandbox_context

    assert_equal "sandbox-netns", context.fetch("sandbox_id")
    assert_equal "namespace:sandbox-netns", context.dig("netns", "handle")
    assert_equal "/proc/#{Process.pid}/ns/net", context.dig("netns", "path")
    assert_equal File.stat("/proc/self/ns/net").ino, context.dig("netns", "inode")
    assert_equal 91, context.dig("netns", "pidfd")
  end

  def test_sandbox_fails_closed_when_network_namespace_inode_changed
    sandbox = Native::Sandbox.new(id: "sandbox-stale", identity: "sandbox:sandbox-stale", config: {})
    sandbox.set_resources(namespace: {
                            "identity" => "namespace:sandbox-stale",
                            "kernel_identity" => {
                              "pid" => Process.pid,
                              "namespace_links" => {"network" => "net:[1]"}
                            }
                          })

    error = assert_raises(Native::Sandbox::Error) { sandbox.network_sandbox_context }
    assert_match(/identity changed/, error.message)
  end
end
