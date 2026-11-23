# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/node/pod_volumes"
require "rubernetes/volume/backends"
require "rubernetes/api"

# kubelet mounts an image volume as the pulled image's filesystem, read-only.
# The node pins the reference (digest + unpacked rootfs) and the volume backend
# serves that rootfs; before this the volume was an empty directory and a tag
# reference was refused outright ("image volume requires an immutable digest"),
# so "[sig-node] ImageVolume should succeed with pod and pull policy of Always"
# never saw its Pod run.
class ImageVolumeRootfsTest < Minitest::Test
  DIGEST = "sha256:#{"ab" * 32}".freeze

  def test_translate_carries_the_pinned_digest_and_rootfs
    volumes = Rubernetes::Node::PodVolumes.allocate
    entry = {"name" => "volume", "image" => {"reference" => "registry.k8s.io/e2e-test-images/kitten:1.7", "pullPolicy" => "Always"}}
    images = {"registry.k8s.io/e2e-test-images/kitten:1.7" => {"digest" => DIGEST, "rootfs" => "/var/lib/rubernetes/images/kitten/rootfs"}}

    spec, readonly = volumes.send(:translate, entry, {"metadata" => {"namespace" => "ns"}}, pod_ip: nil, host_ip: nil, images: images)

    assert readonly
    assert_equal "image", spec["backend"]
    assert_equal DIGEST, spec["digest"]
    assert_equal "/var/lib/rubernetes/images/kitten/rootfs", spec["rootfs"]
    assert_equal "Always", spec["pullPolicy"]
  end

  def test_translate_without_a_pinned_image_leaves_the_backend_to_decide
    volumes = Rubernetes::Node::PodVolumes.allocate
    entry = {"name" => "volume", "image" => {"reference" => "example.com/app@#{DIGEST}"}}

    spec, = volumes.send(:translate, entry, {"metadata" => {"namespace" => "ns"}}, pod_ip: nil, host_ip: nil)

    refute spec.key?("rootfs")
    assert_equal "example.com/app@#{DIGEST}", spec["image"]
  end

  def test_the_backend_serves_the_pinned_rootfs_read_only
    Dir.mktmpdir("image-volume") do |dir|
      rootfs = File.join(dir, "rootfs")
      Dir.mkdir(rootfs)
      File.write(File.join(rootfs, "data.json"), "{\"image\":\"kitten.jpg\"}")
      backend = Rubernetes::Volume::ImageBackend.new(
        id: "vol-1", root: File.join(dir, "volumes"),
        spec: {"backend" => "image", "image" => "registry.k8s.io/e2e-test-images/kitten:1.7", "digest" => DIGEST, "rootfs" => rootfs}
      )

      result = backend.provision

      assert_equal rootfs, result["source"]
      assert_equal DIGEST, result["digest"]
      assert result["readonly"]
      assert_equal "{\"image\":\"kitten.jpg\"}", File.read(File.join(result["source"], "data.json"))
    end
  end

  def test_the_backend_still_requires_a_digest
    Dir.mktmpdir("image-volume") do |dir|
      backend = Rubernetes::Volume::ImageBackend.new(id: "vol-2", root: dir,
                                                     spec: {"backend" => "image", "image" => "registry.k8s.io/e2e-test-images/kitten:1.7"})
      assert_raises(Rubernetes::Volume::ValidationError) { backend.provision }
    end
  end

  def test_status_updates_drop_disabled_image_volume_status_and_preserve_existing_use
    api = Rubernetes::API::Server.new
    pods = "/api/v1/namespaces/default/pods"
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "volume-pod"},
           "spec" => {"containers" => [{"name" => "app", "image" => "x"}]}}

    assert_equal 201, api.call(method: "POST", path: pods, body: JSON.generate(pod), headers: {"content-type" => "application/json"}).status
    path = "#{pods}/volume-pod/status"
    headers = {"content-type" => "application/merge-patch+json"}
    mount_path = %w[status containerStatuses] + [0, "volumeMounts", 0, "volumeStatus", "image", "imageRef"]
    mount = {"name" => "data", "mountPath" => "/data", "volumeStatus" => {"image" => {"imageRef" => DIGEST}}}
    status = {"status" => {"containerStatuses" => [{"name" => "app", "image" => "x", "imageID" => "", "ready" => true,
                                                    "restartCount" => 0, "volumeMounts" => [mount]}]}}
    payload = JSON.generate(status)
    disabled = api.call(method: "PATCH", path: path, body: payload, headers: headers)

    assert_equal 200, disabled.status, disabled.body.inspect
    assert_nil disabled.body.dig(*mount_path)

    enabled = Rubernetes::API::Server.new(store: api.store, feature_gates: {"ImageVolumeWithDigest" => true})
    persisted = enabled.call(method: "PATCH", path: path, body: payload, headers: headers)

    assert_equal 200, persisted.status, persisted.body.inspect
    assert_equal DIGEST, persisted.body.dig(*mount_path)
    assert_equal DIGEST, api.call(method: "PATCH", path: path, body: payload, headers: headers).body.dig(*mount_path)

    mount["volumeStatus"]["image"]["imageRef"] = ""
    invalid = enabled.call(method: "PATCH", path: path, body: JSON.generate(status), headers: headers)

    assert_equal 422, invalid.status
    assert_equal "FieldValueRequired", invalid.body.dig("details", "causes", 0, "reason")
  end
end
