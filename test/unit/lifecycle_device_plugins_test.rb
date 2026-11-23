# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"

# The node side of devicemanager in the Pod lifecycle: allocation happens at
# admission (an unmet request is UnexpectedAdmissionError, a terminal
# rejection), and the container spec gets Allocate's environment, mounts and
# device nodes.
class LifecycleDevicePluginsTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle
  DP = Rubernetes::Node::DevicePlugins

  class Plugins
    def initialize(error: nil, host_mount: "/tmp")
      @error = error
      @host_mount = host_mount
    end

    def remove_stale(_uids) = nil

    def allocate_pod(_pod)
      raise DP::Manager::Error, @error if @error
    end

    def container_allocation(_uid, name)
      return nil unless name == "gpu"

      {"envs" => {"VISIBLE" => "d1"}, "mounts" => [{"container_path" => "/opt/drv", "host_path" => @host_mount, "read_only" => true}],
       "devices" => [{"container_path" => "/dev/fake0", "host_path" => "/dev/null"}], "annotations" => {}, "cdi_devices" => []}
    end
  end

  def subject(plugins)
    Lifecycle.allocate.tap do |lifecycle|
      lifecycle.instance_variable_set(:@device_plugins, plugins)
      lifecycle.instance_variable_set(:@records, {})
    end
  end

  def pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => {"containers" => [{"name" => "gpu"}]}}

  def test_the_allocation_reaches_the_container_spec
    spec = subject(Plugins.new).send(:apply_device_plugin_allocation, {uid: "u"}, {"env" => [{"name" => "A", "value" => "1"}]},
                                     {"name" => "gpu"})

    assert_equal [{"name" => "A", "value" => "1"}, {"name" => "VISIBLE", "value" => "d1"}], spec["env"]
    assert_includes spec["mounts"],
                    {"name" => "device-plugin-mount-0", "source" => "/tmp", "destination" => "/opt/drv", "readonly" => true,
                     "propagation" => "None"}
    assert_includes spec["mounts"], {"name" => "device-plugin-device-0", "source" => "/dev/null", "destination" => "/dev/fake0", "readonly" => false,
                                     "propagation" => "None", "device" => true}
    untouched = {"env" => []}

    assert_same untouched, subject(Plugins.new).send(:apply_device_plugin_allocation, {uid: "u"}, untouched, {"name" => "other"})
  end

  def test_an_unmet_request_rejects_the_pod_at_admission
    record = {}
    error = assert_raises(Lifecycle::LifecycleError) do
      subject(Plugins.new(error: "requested number of devices unavailable for example.com/gpu. Requested: 2, Available: 1"))
        .send(:allocate_devices!, pod, record)
    end
    assert_match(/UnexpectedAdmissionError: Allocate failed due to requested number of devices unavailable/, error.message)
    assert_equal "UnexpectedAdmissionError", record[:admission_reason]
  end

  def test_native_device_plugin_mount_prepares_an_absent_host_source_directory
    Dir.mktmpdir("rbn-device-plugin-mount-") do |root|
      host_mount = File.join(root, "driver-mount")
      lifecycle = subject(Plugins.new(host_mount: host_mount))
      lifecycle.instance_variable_set(:@pod_root, root)
      spec = lifecycle.send(:apply_device_plugin_allocation, {uid: "u"}, {}, {"name" => "gpu"})

      assert_equal host_mount, spec.fetch("mounts").first["source"]
      assert File.directory?(host_mount)
    end
  end
end
