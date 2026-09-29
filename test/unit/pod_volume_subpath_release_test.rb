# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# An operation token is an identifier, not a path.  The release path built the
# subPath unpublish token out of the bind target's absolute path, so the token
# was rejected before the unmount was ever attempted ("operation token contains
# an unsafe path separator") -- which means that unpublish had never once run.
# Everything behind it then refused with "still has published consumers", the
# Pod stayed in CleanupPending, the node never issued its final delete, and
# "[sig-node] Variable Expansion should verify that a failing subpath expansion
# can be modified during the lifecycle of a container" waited five minutes for
# a Pod that was never going away.
class PodVolumeSubPathReleaseTest < Minitest::Test
  Node = Rubernetes::Node

  class RecordingVolume
    attr_reader :tokens

    def initialize = @tokens = []

    def node_unpublish(_id, _pod, target, token:)
      @tokens << [target, token]
      Rubernetes::Volume::Types.identifier(token, "operation token")
      true
    end

    def unstage(*, **) = true
    def unpublish(*, **) = true
    def delete_volume(*, **) = true
    def backends = {}
  end

  POD = {
    "apiVersion" => "v1", "kind" => "Pod",
    "metadata" => {"name" => "sp", "namespace" => "ns", "uid" => "pod-uid"},
    "spec" => {"volumes" => [{"name" => "workdir1", "emptyDir" => {}}]}
  }.freeze

  def handle
    {"ids" => ["vol-workdir1-abc"],
     "mounts" => {"workdir1" => {"name" => "workdir1", "id" => "vol-workdir1-abc",
                                 "path" => "/host/volumes/workdir1", "readonly" => false,
                                 "subPaths" => {"dapi-container:0" => {
                                   "target" => "/host/pods/pod-uid/volume-subpaths/dapi-container/workdir1/0",
                                   "subPath" => "mypath/foo"
                                 }}}}}
  end

  def release
    volume = RecordingVolume.new
    manager = Node::PodVolumes.new(volume: volume, root: "/host", node_name: "worker-0")
    begin
      manager.release(POD, handle, token: "release-pod-uid")
    rescue Node::PodVolumes::Error => error
      return [volume, error]
    end
    [volume, nil]
  end

  def test_the_subpath_unpublish_is_attempted_at_all
    volume, = release

    assert_equal(1, volume.tokens.count { |(target, _)| target.include?("volume-subpaths") },
                 "the subPath bind must be unpublished")
  end

  # A token with a path separator is refused before the unmount is attempted.
  def test_the_token_carries_no_path
    volume, = release
    _, token = volume.tokens.find { |(target, _)| target.include?("volume-subpaths") }

    refute_includes(token, "/")
    refute_includes(token, "\\")
  end

  # It still names one specific bind: container and index, the same pair the
  # publish token used.
  def test_the_token_identifies_the_bind
    volume, = release
    _, token = volume.tokens.find { |(target, _)| target.include?("volume-subpaths") }

    assert_includes(token, "dapi-container")
    assert_includes(token, "0")
  end

  def test_the_release_reports_no_error
    _volume, error = release

    assert_nil(error, error && error.message)
  end
end
