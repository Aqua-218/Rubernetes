# frozen_string_literal: true

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
    def initialize(error: nil) = @error = error
    def remove_stale(_uids) = nil

    def allocate_pod(_pod)
      raise DP::Manager::Error, @error if @error
    end

    def container_allocation(_uid, name)
      return nil unless name == "gpu"

      {"envs" => {"VISIBLE" => "d1"}, "mounts" => [{"container_path" => "/opt/drv", "host_path" => "/tmp", "read_only" => true}],
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
    spec = subject(Plugins.new).send(:apply_device_plugin_allocation, {uid: "u"}, {"env" => [{"name" => "A", "value" => "1"}]}, {"name" => "gpu"})
    assert_equal [{"name" => "A", "value" => "1"}, {"name" => "VISIBLE", "value" => "d1"}], spec["env"]
    assert_includes spec["mounts"], {"name" => "device-plugin-mount-0", "source" => "/tmp", "destination" => "/opt/drv", "readonly" => true, "propagation" => "None"}
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
end
