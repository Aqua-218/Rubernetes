# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/lifecycle"
require "rubernetes/runtime/microvm"
require "rubernetes/runtime/microvm/guest/supervisor"

class MicroVMBlockVolumesTest < Minitest::Test
  M = Rubernetes::Runtime::MicroVM

  def test_node_passes_only_referenced_prepared_block_volumes_to_the_sandbox
    lifecycle = Rubernetes::Node::Lifecycle.allocate
    pod = {"spec" => {
      "initContainers" => [{"volumeDevices" => [{"name" => "init"}]}],
      "containers" => [{"volumeDevices" => [{"name" => "data"}, {"name" => "files"}]}]
    }}
    handle = {"mounts" => {
      "init" => {"volumeMode" => "Block", "path" => "/dev/init", "readonly" => true},
      "data" => {"volumeMode" => "Block", "path" => "/dev/data"},
      "unused" => {"volumeMode" => "Block", "path" => "/dev/unused"},
      "files" => {"path" => "/srv/files"}
    }}

    assert_equal({"init" => {"source" => "/dev/init", "readonly" => true},
                  "data" => {"source" => "/dev/data", "readonly" => false}},
                 lifecycle.send(:sandbox_block_volumes, pod, handle))
  end

  def test_host_translates_only_the_device_matching_the_prepared_source_and_mode
    session = M::VMSession.allocate
    session.instance_variable_set(:@block_volumes, {"data" => {"source" => "/dev/backing", "readonly" => true}})
    mount = {"name" => "data", "source" => "/dev/backing", "destination" => "/dev/raw", "device" => true,
             "readonly" => true, "major" => 7, "minor" => 100}
    spec = {"volumeDevices" => [{"name" => "data", "devicePath" => "/dev/raw"}], "mounts" => [mount]}

    translated = session.send(:container_spec_for_guest, spec).fetch("mounts").first

    assert_equal mount.slice("name", "destination", "device", "readonly").merge("volume_device" => true), translated
    assert_raises(M::PolicyError) { session.send(:container_spec_for_guest, spec.except("volumeDevices")) }
    [mount.merge("source" => "/dev/other"), mount.merge("readonly" => false)].each do |denied|
      assert_raises(M::PolicyError) { session.send(:container_spec_for_guest, spec.merge("mounts" => [denied])) }
    end
  end

  def test_guest_uses_local_block_node_and_its_readonly_permissions
    guest = M::Guest::Supervisor.new(prepare_filesystem: false)
    guest.instance_variable_set(:@block_volumes, {"data" => {"device" => "/dev/vdg", "readonly" => true}})
    mount = {"name" => "data", "source" => "/dev/backing", "destination" => "/work/raw", "device" => true,
             "volume_device" => true, "readonly" => true, "major" => 7, "minor" => 100, "permissions" => "mrw"}

    spec = guest.send(:translate_container_spec, {"mounts" => [mount]})

    assert_equal({"name" => "data", "destination" => "/work/raw", "device" => true, "source" => "/dev/vdg",
                  "readonly" => true, "propagation" => "None", "permissions" => "r"}, spec.fetch("mounts").first)
    assert_raises(M::PolicyError) { guest.send(:translate_container_spec, {"mounts" => [mount.merge("readonly" => false)]}) }
  end

  def test_pod_start_retry_preserves_volumes_while_sandbox_cleanup_is_pending
    volume = Minitest::Mock.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Object.new, pod_volumes: volume)
    pod = {"metadata" => {"name" => "pending", "uid" => "pending"}}
    record = lifecycle.send(:new_record, pod, request_id: nil)
    record[:sandbox_id] = "sandbox"
    record[:volume] = {"mounts" => {"data" => {"volumeMode" => "Block"}}}
    lifecycle.send(:set_state, record, "CleanupPending")

    assert_equal "CleanupPending", lifecycle.start(pod).state
    assert_same record, lifecycle.record("pending")
    assert_mock volume
  end

  def test_the_host_can_remove_a_container_the_guest_already_reaped
    adapter = Object.new
    adapter.define_singleton_method(:wait_container) { |**| {"state" => "terminated", "exitCode" => 0} }
    adapter.define_singleton_method(:container_status) { |**| {"state" => "stopped", "exitCode" => 0} }
    Dir.mktmpdir do |directory|
      runtime = M.new(data_dir: directory, artifacts: Object.new, adapter: adapter)
      sandbox = runtime.run_sandbox({}, runtime_class: runtime.runtime_class)
      waited = runtime.create_container(sandbox, {})
      observed = runtime.create_container(sandbox, {})
      runtime.start_container(waited)
      runtime.start_container(observed)

      assert_equal "terminated", runtime.wait_container(waited)["state"]
      assert_equal "stopped", runtime.container_status(observed)["state"]
      assert_equal waited, runtime.remove_container(waited)
      assert_equal observed, runtime.remove_container(observed)
    end
  end
end
