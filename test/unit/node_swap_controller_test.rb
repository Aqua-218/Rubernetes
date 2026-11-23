# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/platform/linux/swap_controller"

class NodeSwapControllerTest < Minitest::Test
  Controller = Rubernetes::Platform::Linux::SwapController

  def test_detects_optional_swap_controller_in_the_process_cgroup
    Dir.mktmpdir("swap-controller") do |directory|
      membership = File.join(directory, "membership")
      cgroup = File.join(directory, "kubelet.service")
      FileUtils.mkdir(cgroup)
      File.write(membership, "0::/kubelet.service\n")

      refute Controller.available?(root: directory, membership: membership)

      File.write(File.join(cgroup, Controller::LIMIT), "max\n")

      assert Controller.available?(root: directory, membership: membership)
    end
  end

  def test_adds_the_default_limit_even_without_container_memory_resources
    pod = {"metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1"}, "spec" => {}}
    container = {"name" => "app", "image" => "busybox"}
    options = {pod: pod, category: :application}
    supported = Rubernetes::Node::ContainerSpec.new(swap_controller: true)
    unsupported = Rubernetes::Node::ContainerSpec.new(swap_controller: false)

    assert_equal({Controller::LIMIT => "0"}, supported.build(container: container, **options).fetch("limits"))
    refute unsupported.build(container: container, **options).key?("limits")

    explicit = container.merge("limits" => {Controller::LIMIT => "1024", "pids.max" => "128"})

    assert_equal explicit["limits"], supported.build(container: explicit, **options).fetch("limits")
  end
end
