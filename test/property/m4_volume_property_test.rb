# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "tmpdir"

class M4VolumePropertyTest < Minitest::Test
  def test_randomized_rwo_attach_sequences_never_have_two_nodes
    directory = Dir.mktmpdir("m4-volume-property")
    manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
    100.times do |index|
      id = manager.create_volume({"name" => "v#{index}", "emptyDir" => {}, "accessModes" => ["ReadWriteOnce"]}, token: "create-#{index}")
      first = index.even? ? "node-a" : "node-b"
      second = first == "node-a" ? "node-b" : "node-a"
      manager.controller.publish(id, first, token: "attach-#{index}-first")
      assert_raises(Rubernetes::Volume::MultiAttachError) { manager.controller.publish(id, second, token: "attach-#{index}-second") }
      assert_equal [first], manager.fetch_record(id).attachments.keys
    end
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_replay_with_same_token_and_payload_is_side_effect_free
    directory = Dir.mktmpdir("m4-volume-property")
    adapter = Rubernetes::Volume::FilesystemAdapter.new(root: File.join(directory, "volumes"), fsync: false)
    manager = Rubernetes::Volume::Manager.new(data_dir: directory, adapter: adapter, mount_adapter: adapter, fsync: false)
    id = manager.create_volume({"name" => "same", "emptyDir" => {}}, token: "create")
    first = manager.controller.publish(id, "node-a", token: "attach")
    second = manager.controller.publish(id, "node-a", token: "attach")

    assert_equal first, second
    assert_empty adapter.list_mounts
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end
end
