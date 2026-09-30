# frozen_string_literal: true

# The kubelet's in-use volume expansion (desired state populator
# checkVolumeFSResize and operationexecutor NodeExpander, v1.36.2): once the
# resizer grew a CSI PersistentVolume and marked its claim NodeResizePending,
# the node marks it NodeResizeInProgress, calls NodeExpandVolume on the Pod's
# target and records the new status.capacity (clearing the resize status and
# conditions); a final driver error adds a NodeResizeError condition.

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"

class KubeletVolumeExpansionTest < Minitest::Test
  class Reader
    attr_reader :patches
    attr_accessor :objects

    def initialize(objects)
      @objects = objects
      @patches = []
    end

    def get(resource, name, namespace: nil) = @objects[[resource, name]]

    def patch_status(resource, name, patch, namespace: nil, type: :merge)
      @patches << [resource, name, namespace, patch]
      {}
    end
  end

  class Volume
    attr_reader :calls
    attr_accessor :result

    def initialize(result)
      @result = result
      @calls = []
    end

    def node_expand_in_use(id, _pod, path, capacity_bytes:, token:)
      @calls << [id, path, capacity_bytes]
      raise @result if @result.is_a?(Exception)

      @result
    end
  end

  POD = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
         "spec" => {"volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}},
                                  {"name" => "scratch", "emptyDir" => {}}]}}.freeze
  HANDLE = {"mounts" => {"data" => {"id" => "vol-1", "path" => "/pods/u1/volumes/data"},
                         "scratch" => {"id" => "vol-2", "path" => "/pods/u1/volumes/scratch"}}}.freeze

  def objects(resize_status: "NodeResizePending", pv_size: "2Gi", claim_size: "1Gi", csi: true)
    claim = {"metadata" => {"name" => "claim", "namespace" => "ns", "resourceVersion" => "7"},
             "spec" => {"volumeName" => "pv-1"},
             "status" => {"capacity" => {"storage" => claim_size},
                          "allocatedResourceStatuses" => resize_status && {"storage" => resize_status},
                          "conditions" => [{"type" => "FileSystemResizePending", "status" => "True"},
                                           {"type" => "ModifyingVolume", "status" => "True"}]}.compact}
    pv = {"metadata" => {"name" => "pv-1"},
          "spec" => {"capacity" => {"storage" => pv_size}}.merge(csi ? {"csi" => {"driver" => "d", "volumeHandle" => "h"}} : {})}
    {%w[persistentvolumeclaims claim] => claim, %w[persistentvolumes pv-1] => pv}
  end

  def subject(reader, volume)
    Rubernetes::Node::PodVolumes.new(volume: volume, reader: reader, node_name: "n1", root: "/tmp/fake-pods",
                                     clock: -> { Time.utc(2026, 9, 25) })
  end

  def test_a_node_resize_pending_claim_is_expanded_and_its_status_recorded
    reader = Reader.new(objects)
    volume = Volume.new({"capacityBytes" => 2 * (1024**3)})
    results = subject(reader, volume).expand_in_use(POD, HANDLE)

    assert_equal [["data", :resized, 'MountVolume.NodeExpandVolume succeeded for volume "pv-1" n1']], results
    assert_equal [["vol-1", "/pods/u1/volumes/data", 2 * (1024**3)]], volume.calls
    assert_equal 2, reader.patches.length
    in_progress = reader.patches.first.last

    assert_equal({"storage" => "NodeResizeInProgress"}, in_progress.dig("status", "allocatedResourceStatuses"))
    assert_equal "7", in_progress.dig("metadata", "resourceVersion")
    finished = reader.patches.last.last["status"]

    assert_equal({"storage" => "2Gi"}, finished["capacity"])
    assert_nil finished["allocatedResourceStatuses"]
    assert_equal [{"type" => "ModifyingVolume", "status" => "True"}], finished["conditions"]
  end

  def test_nothing_happens_until_the_resizer_hands_the_claim_to_the_node
    [{resize_status: nil}, {resize_status: "ControllerResizeInProgress"}, {pv_size: "1Gi"},
     {csi: false}].each do |options|
      reader = Reader.new(objects(**options))
      volume = Volume.new({})

      assert_empty subject(reader, volume).expand_in_use(POD, HANDLE), options.inspect
      assert_empty volume.calls
      assert_empty reader.patches
    end
  end

  def test_an_in_progress_claim_is_not_marked_again
    reader = Reader.new(objects(resize_status: "NodeResizeInProgress"))
    subject(reader, Volume.new({})).expand_in_use(POD, HANDLE)

    assert_equal 1, reader.patches.length
    assert_equal({"storage" => "2Gi"}, reader.patches.last.last.dig("status", "capacity"))
  end

  def test_a_final_driver_error_adds_the_node_resize_error_condition
    reader = Reader.new(objects)
    volume = Volume.new(Rubernetes::Volume::CSIError.new("out of space"))
    results = subject(reader, volume).expand_in_use(POD, HANDLE)

    assert_equal :failed, results.first[1]
    assert_match(/out of space/, results.first[2])
    conditions = reader.patches.last.last.dig("status", "conditions")
    error = conditions.find { |condition| condition["type"] == "NodeResizeError" }

    assert_equal "failed to expand pvc with out of space", error["message"]

    reader = Reader.new(objects)
    volume = Volume.new(Rubernetes::Volume::CSIError.new("timeout", ambiguous: true))
    subject(reader, volume).expand_in_use(POD, HANDLE)

    assert_equal 1, reader.patches.length, "an ambiguous error only leaves the claim in progress"
  end

  def test_a_driver_without_expand_volume_fails_without_touching_capacity
    reader = Reader.new(objects)
    results = subject(reader, Volume.new(:unsupported)).expand_in_use(POD, HANDLE)

    assert_equal :failed, results.first[1]
    assert_equal 1, reader.patches.length
  end

  def test_the_resize_events_carry_the_kubelet_reasons
    reasons = Rubernetes::Node::KubeletEventPublisher::REASONS

    assert_equal %w[Normal FileSystemResizeSuccessful], reasons.fetch("volume.fs_resized").first(2)
    assert_equal %w[Warning FileSystemResizeFailed], reasons.fetch("volume.fs_resize_failed").first(2)
  end
end
