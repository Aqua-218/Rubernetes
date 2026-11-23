# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/cdi"

class CDIDeviceNodeTest < Minitest::Test
  CDI = Rubernetes::Node::CDI

  def test_stages_and_reuses_a_device_with_an_explicit_number
    skip "requires Linux CAP_MKNOD" unless RUBY_PLATFORM.include?("linux") && mknod_allowed?

    Dir.mktmpdir("rbn-cdi-node-") do |pod|
      target = File.join(pod, "container-only")
      edits = device("path" => target, "type" => "c", "major" => 1, "minor" => 3, "fileMode" => 0o640)
      mount = CDI.apply({}, edits, pod_directory: pod).fetch("mounts").first
      stat = File.lstat(mount.fetch("source"))

      assert_equal target, mount.fetch("destination")
      assert_path_exists mount.fetch("source")
      refute_path_exists target
      assert_predicate stat, :chardev?
      assert_equal [1, 3, 0o640], [stat.rdev_major, stat.rdev_minor, stat.mode & 0o777]
      retry_mount = CDI.apply({}, edits, pod_directory: pod).fetch("mounts").first

      assert_equal mount, retry_mount
      assert_equal stat.ino, File.lstat(retry_mount.fetch("source")).ino
    end
  end

  def test_preserves_an_explicit_host_node_without_creating_staging_files
    Dir.mktmpdir("rbn-cdi-node-") do |pod|
      definition = device("path" => "/tmp/cdi-device", "hostPath" => "/dev/null", "permissions" => "r")
      mount = CDI.apply({}, definition, pod_directory: pod).fetch("mounts").first

      assert_equal %w[/dev/null /tmp/cdi-device r], mount.values_at("source", "destination", "permissions")
      assert_empty Dir.children(pod)
    end
  end

  def test_rejects_invalid_destinations_and_missing_explicit_sources
    Dir.mktmpdir("rbn-cdi-node-") do |pod|
      malformed = device("path" => "/tmp/../device", "type" => "c", "major" => 1, "minor" => 3)
      missing = device("path" => "/tmp/target", "hostPath" => File.join(pod, "missing"), "type" => "c", "major" => 1, "minor" => 3)

      assert_raises(CDI::Error) { CDI.apply({}, malformed, pod_directory: pod) }
      assert_raises(CDI::Error) { CDI.apply({}, missing, pod_directory: pod) }
      assert_empty Dir.children(pod)
    end
  end

  private

  def device(node)
    CDI::Edits.empty.merge!("deviceNodes" => [node])
  end

  def mknod_allowed?
    mask = File.read("/proc/self/status")[/^CapEff:\s+([0-9a-f]+)/, 1]
    mask.to_s.to_i(16).anybits?(1 << 27)
  end
end
