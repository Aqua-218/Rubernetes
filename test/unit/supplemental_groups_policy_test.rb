# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"

# SupplementalGroupsPolicy: Merge (the default) adds the groups the image's
# /etc/group lists the container user in; Strict uses the Pod's alone.
class SupplementalGroupsPolicyTest < Minitest::Test
  def setup
    @rootfs = Dir.mktmpdir("sgp-rootfs")
    FileUtils.mkdir_p(File.join(@rootfs, "etc"))
    File.write(File.join(@rootfs, "etc", "passwd"), "root:x:0:0::/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n")
    File.write(File.join(@rootfs, "etc", "group"), "root:x:0:\nwheel:x:10:root,app\nvideo:x:44:app\napp:x:1000:\n")
    @spec = Rubernetes::Node::ContainerSpec.new(node_name: "n")
  end

  def teardown = FileUtils.rm_rf(@rootfs)

  def context(pod_context, container_context = {}, image_user: nil)
    pod = {"metadata" => {"name" => "p", "namespace" => "ns"}, "spec" => {"securityContext" => pod_context}}
    image = {"rootfs" => @rootfs, "user" => image_user}.compact
    @spec.send(:effective_security_context, pod, {"name" => "c", "securityContext" => container_context}, image)
  end

  def test_merge_adds_the_image_memberships
    assert_equal [5, 10, 44], context({"supplementalGroups" => [5], "runAsUser" => 1000})["supplementalGroups"]
    assert_equal [10, 44], context({}, image_user: "app")["supplementalGroups"], "the image USER by name"
    assert_equal [10], context({"runAsUser" => 0})["supplementalGroups"]
  end

  def test_strict_uses_only_the_pod_groups
    assert_equal [5],
                 context({"supplementalGroups" => [5], "runAsUser" => 1000, "supplementalGroupsPolicy" => "Strict"})["supplementalGroups"]
  end

  def test_an_unknown_uid_adds_nothing
    assert_nil context({"runAsUser" => 4242})["supplementalGroups"]
  end
end
