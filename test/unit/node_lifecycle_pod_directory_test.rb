# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "rubernetes/node"

# Lifecycle#forget_pod removes the Pod's own directory under pod_root (perf,
# 2026-09-27): 316 leftover directories per worker after one round.
class NodeLifecyclePodDirectoryTest < Minitest::Test
  class Runtime
    def run_sandbox(*) = "sandbox-1"
    def create_container(*) = "container-1"
    def start_container(*) = true
    def wait_container(*) = {"state" => "terminated", "exitCode" => 0}
    def stop_container(*) = true
    def remove_container(*) = true
    def stop_sandbox(*) = true
    def remove_sandbox(*) = true
    def container_status(*) = {"state" => "running"}
  end

  def setup
    @root = Dir.mktmpdir("lifecycle-pod-root-")
    @lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, pod_root: @root)
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def test_forget_pod_removes_the_pod_directory_and_nothing_else
    directory = File.join(@root, "uid-1", "etc")
    FileUtils.mkdir_p(directory)
    File.write(File.join(directory, "hosts"), "127.0.0.1 localhost\n")
    FileUtils.mkdir_p(File.join(@root, "uid-2"))
    FileUtils.mkdir_p(File.join(@root, "volumes"))

    @lifecycle.send(:forget_pod, "uid-1")

    refute File.exist?(File.join(@root, "uid-1"))
    assert File.directory?(File.join(@root, "uid-2"))
    assert File.directory?(File.join(@root, "volumes"))
  end

  def test_forget_pod_without_pod_root_or_directory_is_a_no_op
    Rubernetes::Node::Lifecycle.new(runtime: Runtime.new).send(:forget_pod, "uid-1")
    @lifecycle.send(:forget_pod, "never-created")
    @lifecycle.send(:forget_pod, "")
    assert File.directory?(@root)
  end
end
