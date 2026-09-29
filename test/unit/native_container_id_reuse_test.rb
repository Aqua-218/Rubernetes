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
                 3.times.map { box.next_container_id })
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
end
