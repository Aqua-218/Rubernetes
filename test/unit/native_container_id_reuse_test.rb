# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime/native/sandbox"

# Container ids are node-unique and must never be reused.  The id used to be
# derived from the LIVE COUNT of containers in the sandbox, so a restart --
# which removes the old container first -- handed the new container the removed
# one's id, and with it the removed one's create-request identity in the native
# request ledger.  The ledger answered the retry with the container that had
# just been removed, so every restart failed with "unknown container" and the
# Pod sat in CrashLoopBackOff for ever.  Observed live on 2026-09-15 as
# "Error: Rubernetes::Runtime::Native::Sandbox::Error: unknown container
# sandbox-4048844da6a06a76c2af485f.container-1".
class NativeContainerIdReuseTest < Minitest::Test
  Sandbox = Rubernetes::Runtime::Native::Sandbox

  def sandbox
    Sandbox.new(id: "sandbox-1", identity: "identity-1", config: {})
  end

  def test_the_sequence_only_moves_forward
    box = sandbox

    assert_equal(%w[sandbox-1.container-1 sandbox-1.container-2 sandbox-1.container-3],
                 Array.new(3) { box.next_container_id })
  end

  def test_a_removed_container_never_gives_its_id_back
    box = sandbox
    first = box.create_container(spec: {"name" => "app"}, id: box.next_container_id)
    box.remove_container(first.id)
    second = box.create_container(spec: {"name" => "app"}, id: box.next_container_id)

    refute_equal(first.id, second.id)
    assert_equal("sandbox-1.container-2", second.id)
  end

  def test_a_generated_id_is_node_unique
    box = sandbox
    container = box.create_container(spec: {"name" => "app"})

    assert(container.id.start_with?("sandbox-1."), "an id must name its sandbox, got #{container.id}")
  end

  def test_an_explicit_id_is_still_honoured
    box = sandbox

    assert_equal("chosen", box.create_container(spec: {"name" => "app"}, id: "chosen").id)
  end

  def test_kubelet_leaf_uses_the_reported_id_and_recovers_legacy_containers
    pod_uid = "1a111111-1111-4111-8111-111111111111"
    box, layout = kubelet_sandbox(pod_uid)
    legacy_id = "#{box.id}.container-8"
    legacy_leaf = container_path(layout, box, legacy_id)
    box.restore_container_sequence([legacy_id])

    id = box.next_container_id

    assert id.end_with?("-container-9")
    refute_includes id, pod_uid
    assert_equal id, File.basename(container_path(layout, box, id))
    assert_equal "rbn-aaa000000001-container-8", File.basename(legacy_leaf)

    restarted, = kubelet_sandbox(pod_uid)
    restarted.restore_container_sequence([legacy_id, id])

    assert_equal legacy_leaf, container_path(layout, restarted, legacy_id)
    assert restarted.next_container_id.end_with?("-container-10")
  end

  def test_kubelet_ids_do_not_collide_between_pods_with_the_same_generation
    first, = kubelet_sandbox("1a111111-1111-4111-8111-111111111111")
    second, = kubelet_sandbox("2b222222-2222-4222-8222-222222222222")

    refute_equal first.next_container_id, second.next_container_id
  end

  private

  def kubelet_sandbox(uid)
    layout = Rubernetes::Platform::Linux::KubeletCgroupLayout.new("/dev/test-cgroups")
    box = Sandbox.new(id: "pod#{uid}-aaa000000001", identity: "identity-#{uid}", config: {})
    path = layout.path(qos: "guaranteed", pod_id: box.id, container_id: "sandbox", pod_uid: uid, sandbox: nil)
    box.set_resources(cgroup: layout.handle(path))
    [box, layout]
  end

  def container_path(layout, box, id)
    layout.path(qos: "guaranteed", pod_id: box.id, container_id: box.cgroup_container_id(id), pod_uid: nil, sandbox: box.cgroup)
  end
end
