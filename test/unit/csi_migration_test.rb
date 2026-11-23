# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume/csi_migration"
require "rubernetes/node/pod_volumes"

class CSIMigrationTest < Minitest::Test
  Migration = Rubernetes::Volume::CSIMigration

  def test_all_migrated_inline_sources_have_persistent_driver_handles
    sources = [
      ["awsElasticBlockStore", {"volumeID" => "aws://zone/vol-1"}, "vol-1"],
      ["gcePersistentDisk", {"pdName" => "disk"}, "projects/UNSPECIFIED/zones/UNSPECIFIED/disks/disk"],
      ["azureDisk", {"diskURI" => "/subscriptions/s/disks/data"}, "/subscriptions/s/disks/data"],
      ["azureFile", {"secretName" => "azure-storage-account-acct-secret", "shareName" => "share"}, "#acct#share#data#team"],
      ["cinder", {"volumeID" => "a-b-c"}, "a-b-c"],
      ["vsphereVolume", {"volumePath" => "[ds] disks/app.vmdk"}, "[ds] disks/app.vmdk"],
      ["portworxVolume", {"volumeID" => "px/42"}, "px/42"]
    ]
    volumes = Rubernetes::Node::PodVolumes.new(volume: Object.new, root: "/unused")
    sources.each do |kind, source, handle|
      entry = {"name" => "data", kind => source}
      pod = {"metadata" => {"namespace" => "team"}, "spec" => {"volumes" => [entry]}}
      translated = Migration.inline_spec(entry, namespace: "team")
      driver = Migration::DRIVERS.fetch(kind)

      assert_equal handle, translated.dig("csi", "volumeHandle"), kind
      assert_equal "Filesystem", translated["volumeMode"]
      assert_equal ["kubernetes.io/csi/#{driver}^#{handle}"], volumes.attachable_volume_names(pod)
    end
  end

  def test_gce_regions_access_modes_and_topology_preserve_persisted_pv
    label = "failure-domain.beta.kubernetes.io/zone"
    pv = {"metadata" => {"labels" => {label => "us-central1-b__us-central1-a"}},
          "spec" => {"gcePersistentDisk" => {"pdName" => "existing"}, "accessModes" => %w[ReadOnlyMany ReadWriteMany],
                     "nodeAffinity" => {"required" => {"nodeSelectorTerms" => [{"matchFields" => [{"key" => "metadata.name"}]}, {}]}}}}
    original = Marshal.load(Marshal.dump(pv))
    translated = Migration.persistent_spec(pv)

    assert_equal original, pv
    assert_equal ["ReadWriteOnce"], translated["accessModes"]
    assert_equal "projects/UNSPECIFIED/regions/us-central1/disks/existing", translated.dig("csi", "volumeHandle")
    assert_equal "", translated.dig("csi", "volumeAttributes", "partition")
    translated.dig("nodeAffinity", "required", "nodeSelectorTerms").each do |term|
      assert_equal [{"key" => "topology.gke.io/zone", "operator" => "In", "values" => %w[us-central1-a us-central1-b]}], term["matchExpressions"]
    end
    pv["metadata"]["labels"][label] = "us-central1-a__us-west1-a"
    assert_raises(Migration::Invalid) { Migration.persistent_spec(pv) }
  end

  def test_claim_translation_keeps_azure_share_identity_and_only_node_secret_references
    pv = {"metadata" => {"name" => "pv", "annotations" => {"kubernetes.io/azure-file-resource-group" => "rg"}},
          "spec" => {"claimRef" => {"name" => "claim", "namespace" => "app"}, "mountOptions" => ["nosuid"],
                     "azureFile" => {"shareName" => "share", "secretName" => "account", "secretNamespace" => "vault", "readOnly" => true}}}
    objects = {"persistentvolumes" => pv, "persistentvolumeclaims" => {"status" => {"phase" => "Bound"}, "spec" => {"volumeName" => "pv"}}}
    reader = Object.new
    reader.define_singleton_method(:get) { |resource, *, **| objects.fetch(resource) }
    volumes = Rubernetes::Node::PodVolumes.new(volume: Object.new, reader: reader, root: "/unused")
    entry = {"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}}
    pod = {"metadata" => {"namespace" => "app"}, "spec" => {"volumes" => [entry]}}
    spec, readonly = volumes.send(:translate, entry, pod, pod_ip: nil, host_ip: nil)

    assert readonly
    assert_equal ["nosuid"], spec["mountOptions"]
    assert_equal "rg#account#share#pv#vault", spec.dig("csi", "volumeHandle")
    assert_equal({"nodeStage" => {"name" => "account", "namespace" => "vault"}}, spec.dig("csi", "secretRefs"))
    assert_equal ["kubernetes.io/csi/file.csi.azure.com^rg#account#share#pv#vault"], volumes.attachable_volume_names(pod)
    assert_raises(Migration::Invalid) do
      Migration.persistent_spec({"spec" => {"azureFile" => {"shareName" => "share", "secretName" => "account"}}})
    end
  end

  def test_unsupported_legacy_source_fails_before_any_driver_call
    volumes = Rubernetes::Node::PodVolumes.new(volume: Object.new, root: "/unused")
    pod = {"metadata" => {"uid" => "pod"}, "spec" => {"volumes" => [{"name" => "old", "azureDisk" => {"kind" => "Dedicated"}}]}}

    error = assert_raises(Rubernetes::Node::PodVolumes::Unsupported) { volumes.prepare(pod) }
    assert_match(/managed disk/, error.message)
  end
end
