# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

# A subPath into an emptyDir that an EARLIER init container fills at runtime
# (GitLab's configure -> rails-secrets/secrets.yml) does not exist when the
# later container's mount is first resolved.  kubelet retries the mount on the
# next sync with the same request; we fenced the failed publish for ever with
# "previously failed".
class PodVolumeSubPathRetryTest < Minitest::Test
  Node = Rubernetes::Node

  def test_a_failed_subpath_publish_is_retried_with_the_same_token
    skip "openat2 subPath resolution needs root on this host" unless Process.uid.zero?

    Dir.mktmpdir do |dir|
      openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
      security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
      manager = Rubernetes::Volume::Manager.new(data_dir: dir, fsync: false, path_security: security)
      volumes = Node::PodVolumes.new(volume: manager, root: File.join(dir, "pods"), node_name: "worker-0")
      pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
             "spec" => {"initContainers" => [{"name" => "configure", "volumeMounts" => [{"name" => "secrets", "mountPath" => "/init-secrets"}]}],
                        "containers" => [{"name" => "app", "volumeMounts" => [{"name" => "secrets", "mountPath" => "/srv/config/secrets.yml",
                                                                               "subPath" => "rails-secrets/secrets.yml", "readOnly" => true}]}],
                        "volumes" => [{"name" => "secrets", "emptyDir" => {}}]}}
      handle = volumes.prepare(pod)
      mount = handle.dig("mounts", "secrets")
      # The subPath is resolved against the staged volume (the in-memory
      # adapter records the pod-level bind without a real mount).
      source = manager.fetch_record(mount["id"]).to_h.fetch("stages").keys.fetch(0)

      assert File.directory?(source), "prepared emptyDir stage: #{mount.inspect}"

      args = {volume_name: "secrets", sub_path: "rails-secrets/secrets.yml", container_name: "app", index: 0, readonly: true}
      first = assert_raises(StandardError) { volumes.sub_path(pod, handle, **args) }
      refute_match(/previously failed/, first.message)

      # Nothing changed: the retry fails the same way, not with the fence.
      second = assert_raises(StandardError) { volumes.sub_path(pod, handle, **args) }
      refute_match(/previously failed/, second.message)
      assert_equal first.class, second.class

      # The init container writes the file; the app container's mount is
      # resolved again with the same deterministic token.
      FileUtils.mkdir_p(File.join(source, "rails-secrets"))
      File.write(File.join(source, "rails-secrets", "secrets.yml"), "production: {}\n")
      target = volumes.sub_path(pod, handle, **args)

      assert File.exist?(target) || File.symlink?(target), "subPath target published at #{target}"
      assert_equal "rails-secrets/secrets.yml", mount.dig("subPaths", "app:0", "subPath")
    ensure
      begin
        volumes&.release(pod, handle) if handle
      rescue StandardError
        nil
      end
    end
  end
end
