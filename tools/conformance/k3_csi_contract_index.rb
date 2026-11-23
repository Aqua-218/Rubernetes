# frozen_string_literal: true

module Conformance
  module K3CSIContractIndex
    RUNNER = "tools/conformance/k3_csi_contracts.rb"
    ORIGIN = "[sig-storage] CSI Volumes [Driver: pd.csi.storage.gke.io] [Serial]"
    EXTERNAL = "External Storage [Driver: hostpath.csi.k8s.io]"
    EXTERNAL_NFS = "External Storage [Driver: nfs.csi.k8s.io]"
    RBD_DRIVER = "rook-ceph.rbd.csi.ceph.com"
    EXTERNAL_RBD = "External Storage [Driver: #{RBD_DRIVER}]".freeze
    DEFAULT_PATTERN = "Dynamic PV (default fs)"
    FILESYSTEM_MODE_PATTERN = "Dynamic PV (filesystem volmode)"
    BLOCK_MODE_PATTERN = "Dynamic PV (block volmode)"
    EXT3_PATTERN = "Dynamic PV (ext3)"
    EXT4_PATTERN = "Dynamic PV (ext4)"
    XFS_PATTERN = "Dynamic PV (xfs)"
    IMMEDIATE_TOPOLOGY = "Dynamic PV (immediate binding)"
    DELAYED_TOPOLOGY = "Dynamic PV (delayed binding)"
    ALLOWED_TOPOLOGY = "topology should provision a volume and schedule a pod with AllowedTopologies"
    CONFLICTING_TOPOLOGY = "topology should fail to schedule a pod which has topologies that conflict with AllowedTopologies"
    EXPANSION_PATTERN = "Dynamic PV (default fs)(allowExpansion)"
    BLOCK_EXPANSION_PATTERN = "#{BLOCK_MODE_PATTERN}(allowExpansion)".freeze
    EXPANSION_DISABLED = "volume-expand should not allow expansion of pvcs without AllowVolumeExpansion property"
    EXPANSION_OFFLINE = "volume-expand Verify if offline PVC expansion works"
    EXPANSION_RECREATED = "volume-expand should resize volume when PVC is edited and the pod is re-created on the same node after controller resize is finished"
    EXPANSION_ONLINE = "volume-expand should resize volume when PVC is edited while pod is using it"
    UNUSED_VOLUME = "volumeMode should not mount / map unused volumes in a pod [LinuxOnly]"
    EPHEMERAL_PATTERN = "Generic Ephemeral-volume (default fs) (late-binding)"
    EPHEMERAL_BLOCK_PATTERN = "Generic Ephemeral-volume (block volmode) (late-binding)"
    EPHEMERAL_IMMEDIATE_PATTERN = "Generic Ephemeral-volume (default fs) (immediate-binding)"
    EPHEMERAL_EXPANSION = "ephemeral should support expansion of pvcs created for ephemeral pvcs"
    ALWAYS = "fsgroupchangepolicy (Always)[LinuxOnly]"
    ON_ROOT_MISMATCH = "fsgroupchangepolicy (OnRootMismatch)[LinuxOnly]"
    NEW_GROUP = "pod created with an initial fsgroup, new pod fsgroup applied to volume contents"
    CHANGED_GROUP = "pod created with an initial fsgroup, volume contents ownership changed via chgrp in first pod"
    SNAPSHOT_SUITE = "snapshottable [Feature:VolumeSnapshotDataSource] volume snapshot controller"
    SNAPSHOT_RESTORE = "should check snapshot fields, check restore correctly works"
    PERSISTENT_SNAPSHOT = "#{SNAPSHOT_SUITE} #{SNAPSHOT_RESTORE} after modifying source data, check deletion (persistent)".freeze
    EPHEMERAL_SNAPSHOT = "#{SNAPSHOT_SUITE} #{SNAPSHOT_RESTORE}, check deletion (ephemeral)".freeze
    CONCURRENT_SNAPSHOT = "multiVolume [Slow] should concurrently access the volume and restored snapshot from pods on the same node " \
                          "[LinuxOnly] [Feature:VolumeSnapshotDataSource] [Feature:VolumeSourceXFS]"
    SNAPSHOT_STRESS = "snapshottable-stress [Feature:VolumeSnapshotDataSource] should support snapshotting of many volumes repeatedly [Slow] [Serial]"
    RESTART_DATA = "disruptive [Disruptive] [LinuxOnly] Should test that pv written before kubelet restart is readable after restart."
    DELETE_WHILE_DOWN = "disruptive [Disruptive] [LinuxOnly] Should test that pv used in a pod that is "
    CLEAN_UP_ON_RESTART = "deleted while the kubelet is down cleans up when the kubelet returns."
    CROSS_NODE_RECREATION = "multiVolume [Slow] should access to two volumes with the same volume mode " \
                            "and retain data across pod recreation on different node"
    CROSS_NODE_MIXED_MODE_RECREATION = "multiVolume [Slow] should access to two volumes with different volume mode " \
                                       "and retain data across pod recreation on different node"

    NFS_SUBPATH_CASES = %w[
      csi-nfs-subpath-existing-single-file csi-nfs-subpath-existing-dir csi-nfs-subpath-file csi-nfs-subpath-missing
      csi-nfs-subpath-deleted csi-nfs-subpath-outside-missing csi-nfs-subpath-outside-dir csi-nfs-subpath-outside-file
      csi-nfs-subpath-backstep csi-nfs-subpath-multiple csi-nfs-subpath-readonly-source csi-nfs-subpath-readonly-dir
      csi-nfs-subpath-readonly-file csi-nfs-subpath-restart-dir csi-nfs-subpath-restart-file csi-nfs-subpath-readonly-write
    ].freeze

    # The pinned GCE PD driver configures late binding, ReadWriteOnce, 5 GiB
    # minimum provisioning and a 100 MiB file limit. Each mapped case uses the
    # same upstream suite and requirements with a real external CSI driver.
    CONTRACTS = {
      "csi-store-data" => ["volumes.go", "volumes should store data"],
      "csi-exec" => ["volumes.go", "volumes should allow exec of files on the volume"],
      "csi-volume-io" => ["volume_io.go", "volumeIO should write files of various sizes, verify size, validate content [Slow]"],
      "csi-volume-stress" => ["volume_stress.go", "volume-stress multiple pods should access different volumes repeatedly [Slow] [Serial]"],
      "csi-raw-volume-stress" => [
        "volume_stress.go", "volume-stress multiple pods should access different volumes repeatedly [Slow] [Serial]", BLOCK_MODE_PATTERN
      ],
      "csi-ext3-store" => ["volumes.go", "volumes should store data", EXT3_PATTERN],
      "csi-ext3-exec" => ["volumes.go", "volumes should allow exec of files on the volume", EXT3_PATTERN],
      "csi-ext4-store" => ["volumes.go", "volumes should store data", EXT4_PATTERN],
      "csi-ext4-exec" => ["volumes.go", "volumes should allow exec of files on the volume", EXT4_PATTERN],
      "csi-ext4-multi-pod" => [
        "multivolume.go", "multiVolume [Slow] should concurrently access the single volume from pods on the same node", EXT4_PATTERN
      ],
      "csi-ext4-multi-pod-readonly" => [
        "multivolume.go", "multiVolume [Slow] should concurrently access the single read-only volume from pods on the same node", EXT4_PATTERN
      ],
      "csi-ext4-multi-pod-recreated" => [
        "multivolume.go", "multiVolume [Slow] should access to two volumes with the same volume mode and retain data across pod recreation on the same node",
        EXT4_PATTERN
      ],
      "csi-subpath-existing-single-file" => ["subpath.go", "subPath should support existing single file [LinuxOnly]"],
      "csi-subpath-existing-dir" => ["subpath.go", "subPath should support existing directory"],
      "csi-subpath-file" => ["subpath.go", "subPath should support file as subpath [LinuxOnly]"],
      "csi-subpath-missing" => ["subpath.go", "subPath should support non-existent path"],
      "csi-subpath-deleted" => ["subpath.go", "subPath should be able to unmount after the subpath directory is deleted [LinuxOnly]"],
      "csi-subpath-outside-missing" => ["subpath.go", "subPath should fail if non-existent subpath is outside the volume [Slow] [LinuxOnly]"],
      "csi-subpath-outside-dir" => ["subpath.go", "subPath should fail if subpath directory is outside the volume [Slow] [LinuxOnly]"],
      "csi-subpath-outside-file" => ["subpath.go", "subPath should fail if subpath file is outside the volume [Slow] [LinuxOnly]"],
      "csi-subpath-backstep" => ["subpath.go", "subPath should fail if subpath with backstepping is outside the volume [Slow] [LinuxOnly]"],
      "csi-subpath-multiple" => ["subpath.go", "subPath should support creating multiple subpath from same volumes [Slow]"],
      "csi-subpath-readonly-source" => ["subpath.go", "subPath should support existing directories when readOnly specified in the volumeSource"],
      "csi-subpath-readonly-dir" => ["subpath.go", "subPath should support readOnly directory specified in the volumeMount"],
      "csi-subpath-readonly-file" => ["subpath.go", "subPath should support readOnly file specified in the volumeMount [LinuxOnly]"],
      "csi-subpath-restart-dir" => ["subpath.go", "subPath should support restarting containers using directory as subpath [Slow]"],
      "csi-subpath-restart-file" => ["subpath.go", "subPath should support restarting containers using file as subpath [Slow] [LinuxOnly]"],
      "csi-subpath-readonly-write" => ["subpath.go", "subPath should verify container cannot write to subpath readonly volumes [Slow]"],
      "csi-subpath-delete-during-restart" => [
        "subpath.go", "subPath should unmount if pod is gracefully deleted while kubelet is down [Disruptive] [Slow] [LinuxOnly]"
      ],
      "csi-subpath-force-delete-during-restart" => [
        "subpath.go", "subPath should unmount if pod is force deleted while kubelet is down [Disruptive] [Slow] [LinuxOnly]"
      ],
      "csi-fsgroup-root-mismatch" => [
        "fsgroupchangepolicy.go", "#{ON_ROOT_MISMATCH}, #{CHANGED_GROUP}, new pod with different fsgroup applied to the volume contents"
      ],
      "csi-fsgroup-root-match" => [
        "fsgroupchangepolicy.go", "#{ON_ROOT_MISMATCH}, #{CHANGED_GROUP}, new pod with same fsgroup skips ownership changes to the volume contents"
      ],
      "csi-fsgroup-root-new" => ["fsgroupchangepolicy.go", "#{ON_ROOT_MISMATCH}, #{NEW_GROUP}"],
      "csi-fsgroup-always-new" => ["fsgroupchangepolicy.go", "#{ALWAYS}, #{NEW_GROUP}"],
      "csi-fsgroup-always-changed" => [
        "fsgroupchangepolicy.go", "#{ALWAYS}, #{CHANGED_GROUP}, new pod with different fsgroup applied to the volume contents"
      ],
      "csi-fsgroup-always-same" => [
        "fsgroupchangepolicy.go", "#{ALWAYS}, #{CHANGED_GROUP}, new pod with same fsgroup applied to the volume contents"
      ],
      "csi-fsgroup-always-rwop" => ["fsgroupchangepolicy.go", "#{ALWAYS}, rwop #{NEW_GROUP}"],
      "csi-multi-pod-same-node" => [
        "multivolume.go",
        "multiVolume [Slow] should concurrently access the single volume from pods on the same node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-multi-pod-readonly" => [
        "multivolume.go",
        "multiVolume [Slow] should concurrently access the single read-only volume from pods on the same node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-multi-pod-recreated" => [
        "multivolume.go",
        "multiVolume [Slow] should access to two volumes with the same volume mode and retain data across pod recreation on the same node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-multi-pv-same-handle" => ["provisioning.go", "provisioning should mount multiple PV pointing to the same storage on the same node"],
      "csi-nfs-cross-node-recreated" => [
        "multivolume.go",
        "multiVolume [Slow] should access to two volumes with the same volume mode and retain data across pod recreation on different node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-nfs-cross-node-concurrent" => [
        "multivolume.go", "multiVolume [Slow] should concurrently access the single volume from pods on different node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-nfs-shared-readwrite" => [
        "multivolume.go", "multiVolume [Slow] should concurrently access the single volume from pods on the same node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-nfs-shared-readonly" => [
        "multivolume.go", "multiVolume [Slow] should concurrently access the single read-only volume from pods on the same node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-nfs-same-node-recreated" => [
        "multivolume.go", "multiVolume [Slow] should access to two volumes with the same volume mode and retain data across pod recreation on the same node",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-nfs-volume-io" => ["volume_io.go", "volumeIO should write files of various sizes, verify size, validate content [Slow]"],
      "csi-rbd-cross-node-filesystem" => ["multivolume.go", CROSS_NODE_RECREATION, FILESYSTEM_MODE_PATTERN],
      "csi-rbd-cross-node-ext4" => ["multivolume.go", CROSS_NODE_RECREATION, EXT4_PATTERN],
      "csi-rbd-cross-node-block" => ["multivolume.go", CROSS_NODE_RECREATION, BLOCK_MODE_PATTERN],
      "csi-rbd-cross-node-mixed" => ["multivolume.go", CROSS_NODE_MIXED_MODE_RECREATION, BLOCK_MODE_PATTERN],
      "csi-rbd-mount-options" => ["provisioning.go", "provisioning should provision storage with mount options"],
      "csi-nfs-restart-filesystem" => ["disruptive.go", RESTART_DATA, FILESYSTEM_MODE_PATTERN],
      "csi-nfs-unused-filesystem" => ["volumemode.go", UNUSED_VOLUME, FILESYSTEM_MODE_PATTERN],
      "csi-nfs-block-provision-denied" => [
        "volumemode.go", "volumeMode should fail in binding dynamic provisioned PV to PVC [Slow] [LinuxOnly]", BLOCK_MODE_PATTERN
      ],
      "csi-nfs-expand-disabled" => ["volume_expand.go", EXPANSION_DISABLED],
      "csi-nfs-subpath-delete-during-restart" => [
        "subpath.go", "subPath should unmount if pod is gracefully deleted while kubelet is down [Disruptive] [Slow] [LinuxOnly]"
      ],
      "csi-nfs-subpath-force-delete-during-restart" => [
        "subpath.go", "subPath should unmount if pod is force deleted while kubelet is down [Disruptive] [Slow] [LinuxOnly]"
      ],
      "csi-volume-mode-mismatch" => [
        "volumemode.go",
        "volumeMode should fail to use a volume in a pod with mismatched mode [Slow]",
        FILESYSTEM_MODE_PATTERN
      ],
      "csi-raw-store" => ["volumes.go", "volumes should store data", BLOCK_MODE_PATTERN],
      "csi-raw-volume-mode-mismatch" => [
        "volumemode.go", "volumeMode should fail to use a volume in a pod with mismatched mode [Slow]", BLOCK_MODE_PATTERN
      ],
      "csi-unused-filesystem" => ["volumemode.go", UNUSED_VOLUME, FILESYSTEM_MODE_PATTERN],
      "csi-unused-block" => ["volumemode.go", UNUSED_VOLUME, BLOCK_MODE_PATTERN],
      "csi-raw-multi-pod" => [
        "multivolume.go", "multiVolume [Slow] should concurrently access the single volume from pods on the same node",
        BLOCK_MODE_PATTERN
      ],
      "csi-raw-multi-pod-readonly" => [
        "multivolume.go", "multiVolume [Slow] should concurrently access the single read-only volume from pods on the same node",
        BLOCK_MODE_PATTERN
      ],
      "csi-raw-multi-pod-recreated" => [
        "multivolume.go",
        "multiVolume [Slow] should access to two volumes with the same volume mode and retain data across pod recreation on the same node",
        BLOCK_MODE_PATTERN
      ],
      "csi-raw-mixed-mode-recreated" => [
        "multivolume.go",
        "multiVolume [Slow] should access to two volumes with different volume mode and retain data across pod recreation on the same node",
        BLOCK_MODE_PATTERN
      ],
      "csi-expand-disabled" => ["volume_expand.go", EXPANSION_DISABLED],
      "csi-expand-offline" => ["volume_expand.go", EXPANSION_OFFLINE, EXPANSION_PATTERN],
      "csi-expand-recreated" => ["volume_expand.go", EXPANSION_RECREATED, EXPANSION_PATTERN],
      "csi-expand-online" => ["volume_expand.go", EXPANSION_ONLINE, EXPANSION_PATTERN],
      "csi-expand-block-disabled" => ["volume_expand.go", EXPANSION_DISABLED, BLOCK_MODE_PATTERN],
      "csi-expand-block-offline" => ["volume_expand.go", EXPANSION_OFFLINE, BLOCK_EXPANSION_PATTERN],
      "csi-expand-block-recreated" => ["volume_expand.go", EXPANSION_RECREATED, BLOCK_EXPANSION_PATTERN],
      "csi-expand-block-online" => ["volume_expand.go", EXPANSION_ONLINE, BLOCK_EXPANSION_PATTERN],
      "csi-xfs-store" => ["volumes.go", "[Slow] volumes should store data", XFS_PATTERN],
      "csi-xfs-exec" => ["volumes.go", "[Slow] volumes should allow exec of files on the volume", XFS_PATTERN],
      "csi-xfs-multi-pod" => [
        "multivolume.go",
        "[Slow] multiVolume [Slow] should concurrently access the single volume from pods on the same node",
        XFS_PATTERN
      ],
      "csi-xfs-multi-pod-readonly" => [
        "multivolume.go",
        "[Slow] multiVolume [Slow] should concurrently access the single read-only volume from pods on the same node",
        XFS_PATTERN
      ],
      "csi-xfs-multi-pod-recreated" => [
        "multivolume.go",
        "[Slow] multiVolume [Slow] should access to two volumes with the same volume mode and retain data across pod recreation on the same node",
        XFS_PATTERN
      ],
      "csi-xfs-expand-offline" => ["volume_expand.go", "[Slow] #{EXPANSION_OFFLINE}", XFS_PATTERN],
      "csi-xfs-expand-recreated" => ["volume_expand.go", "[Slow] #{EXPANSION_RECREATED}", XFS_PATTERN],
      "csi-xfs-expand-online" => ["volume_expand.go", "[Slow] #{EXPANSION_ONLINE}", XFS_PATTERN],
      "csi-rwop-preempt" => [
        "readwriteoncepod.go", "read-write-once-pod should preempt lower priority pods using ReadWriteOncePod volumes [Serial]"
      ],
      "csi-rwop-same-node" => [
        "readwriteoncepod.go", "read-write-once-pod should block a second pod from using an in-use ReadWriteOncePod volume on the same node"
      ],
      "csi-topology-immediate-allowed" => ["topology.go", ALLOWED_TOPOLOGY, IMMEDIATE_TOPOLOGY],
      "csi-topology-immediate-conflict" => ["topology.go", CONFLICTING_TOPOLOGY, IMMEDIATE_TOPOLOGY],
      "csi-topology-delayed-allowed" => ["topology.go", ALLOWED_TOPOLOGY, DELAYED_TOPOLOGY],
      "csi-topology-delayed-conflict" => ["topology.go", CONFLICTING_TOPOLOGY, DELAYED_TOPOLOGY],
      "csi-ephemeral-readonly" => ["ephemeral.go", "ephemeral should create read-only inline ephemeral volume", EPHEMERAL_PATTERN],
      "csi-ephemeral-readwrite" => ["ephemeral.go", "ephemeral should create read/write inline ephemeral volume", EPHEMERAL_PATTERN],
      "csi-ephemeral-multiple" => ["ephemeral.go", "ephemeral should support multiple inline ephemeral volumes", EPHEMERAL_PATTERN],
      "csi-ephemeral-replicas" => ["ephemeral.go", "ephemeral should support two pods which have the same volume definition", EPHEMERAL_PATTERN],
      "csi-nfs-ephemeral-readonly" => ["ephemeral.go", "ephemeral should create read-only inline ephemeral volume", EPHEMERAL_PATTERN],
      "csi-nfs-ephemeral-readwrite" => ["ephemeral.go", "ephemeral should create read/write inline ephemeral volume", EPHEMERAL_PATTERN],
      "csi-nfs-ephemeral-multiple" => ["ephemeral.go", "ephemeral should support multiple inline ephemeral volumes", EPHEMERAL_PATTERN],
      "csi-nfs-ephemeral-replicas" => ["ephemeral.go", "ephemeral should support two pods which have the same volume definition", EPHEMERAL_PATTERN],
      "csi-ephemeral-expansion" => ["ephemeral.go", EPHEMERAL_EXPANSION, EPHEMERAL_PATTERN],
      "csi-ephemeral-block-readwrite" => [
        "ephemeral.go", "ephemeral should create read/write inline ephemeral volume", EPHEMERAL_BLOCK_PATTERN
      ],
      "csi-ephemeral-block-multiple" => [
        "ephemeral.go", "ephemeral should support multiple inline ephemeral volumes", EPHEMERAL_BLOCK_PATTERN
      ],
      "csi-ephemeral-block-replicas" => [
        "ephemeral.go", "ephemeral should support two pods which have the same volume definition", EPHEMERAL_BLOCK_PATTERN
      ],
      "csi-ephemeral-block-expansion" => ["ephemeral.go", EPHEMERAL_EXPANSION, EPHEMERAL_BLOCK_PATTERN],
      "csi-ephemeral-immediate-readonly" => [
        "ephemeral.go", "ephemeral should create read-only inline ephemeral volume", EPHEMERAL_IMMEDIATE_PATTERN
      ],
      "csi-ephemeral-immediate-readwrite" => [
        "ephemeral.go", "ephemeral should create read/write inline ephemeral volume", EPHEMERAL_IMMEDIATE_PATTERN
      ],
      "csi-ephemeral-immediate-replicas" => [
        "ephemeral.go", "ephemeral should support two pods which have the same volume definition", EPHEMERAL_IMMEDIATE_PATTERN
      ],
      "csi-snapshot-source" => [
        "provisioning.go", "provisioning should provision storage with snapshot data source [Feature:VolumeSnapshotDataSource]"
      ],
      "csi-snapshot-block-source" => [
        "provisioning.go", "provisioning should provision storage with snapshot data source [Feature:VolumeSnapshotDataSource]", BLOCK_MODE_PATTERN
      ],
      "csi-snapshot-block-concurrent" => ["multivolume.go", CONCURRENT_SNAPSHOT, BLOCK_MODE_PATTERN],
      "csi-ext4-snapshot-concurrent" => ["multivolume.go", CONCURRENT_SNAPSHOT, EXT4_PATTERN],
      "csi-xfs-snapshot-concurrent" => ["multivolume.go", "[Slow] #{CONCURRENT_SNAPSHOT}", XFS_PATTERN],
      "csi-arbitrary-data-source" => ["provisioning.go", "provisioning should provision storage with any volume data source [Serial]"],
      "csi-restart-filesystem" => ["disruptive.go", RESTART_DATA, FILESYSTEM_MODE_PATTERN],
      "csi-restart-block" => ["disruptive.go", RESTART_DATA, BLOCK_MODE_PATTERN],
      "csi-restart-delete-block" => ["disruptive.go", "#{DELETE_WHILE_DOWN}#{CLEAN_UP_ON_RESTART}", BLOCK_MODE_PATTERN],
      "csi-restart-force-delete-block" => ["disruptive.go", "#{DELETE_WHILE_DOWN}force #{CLEAN_UP_ON_RESTART}", BLOCK_MODE_PATTERN],
      "csi-snapshot-dynamic-delete" => ["snapshottable.go", PERSISTENT_SNAPSHOT, "Dynamic Snapshot (delete policy)"],
      "csi-snapshot-dynamic-retain" => ["snapshottable.go", PERSISTENT_SNAPSHOT, "Dynamic Snapshot (retain policy)"],
      "csi-snapshot-preprovisioned-delete" => ["snapshottable.go", PERSISTENT_SNAPSHOT, "Pre-provisioned Snapshot (delete policy)"],
      "csi-snapshot-preprovisioned-retain" => ["snapshottable.go", PERSISTENT_SNAPSHOT, "Pre-provisioned Snapshot (retain policy)"],
      "csi-snapshot-ephemeral-delete" => ["snapshottable.go", EPHEMERAL_SNAPSHOT, "Ephemeral Snapshot (delete policy)"],
      "csi-snapshot-ephemeral-retain" => ["snapshottable.go", EPHEMERAL_SNAPSHOT, "Ephemeral Snapshot (retain policy)"],
      "csi-snapshot-stress-delete" => ["snapshottable_stress.go", SNAPSHOT_STRESS, "Dynamic Snapshot (delete policy)"],
      "csi-snapshot-stress-retain" => ["snapshottable_stress.go", SNAPSHOT_STRESS, "Dynamic Snapshot (retain policy)"]
    }.then do |cases|
      cases.merge(NFS_SUBPATH_CASES.to_h { |key| [key, cases.fetch(key.sub("csi-nfs-", "csi-"))] })
    end.freeze

    def self.patterned_suffix(key)
      _, suffix, pattern = CONTRACTS.fetch(key)
      "[Testpattern: #{pattern || DEFAULT_PATTERN}] #{suffix}"
    end

    def self.external_for(key)
      return EXTERNAL_NFS if key.start_with?("csi-nfs-")
      return EXTERNAL_RBD if key.start_with?("csi-rbd-")

      EXTERNAL
    end

    # Capability groups from the pinned drivers/in_tree.go. Every case in a
    # group has the same pattern, published source and public assertions for
    # each provider listed. Provider-specific capabilities remain separate.
    BLOCK_PROVIDER_CASES = %w[
      csi-store-data csi-exec csi-volume-io
      csi-subpath-existing-single-file csi-subpath-existing-dir csi-subpath-file csi-subpath-missing
      csi-subpath-deleted csi-subpath-outside-missing csi-subpath-outside-dir csi-subpath-outside-file
      csi-subpath-backstep csi-subpath-multiple csi-subpath-readonly-source csi-subpath-readonly-dir
      csi-subpath-readonly-file csi-subpath-restart-dir csi-subpath-restart-file csi-subpath-readonly-write
      csi-subpath-delete-during-restart csi-subpath-force-delete-during-restart
      csi-fsgroup-root-mismatch csi-fsgroup-root-match csi-fsgroup-root-new
      csi-fsgroup-always-new csi-fsgroup-always-changed csi-fsgroup-always-same
      csi-volume-mode-mismatch csi-raw-volume-mode-mismatch csi-raw-store
      csi-unused-filesystem csi-unused-block
      csi-multi-pod-recreated csi-raw-multi-pod-recreated csi-raw-mixed-mode-recreated
      csi-ephemeral-readonly csi-ephemeral-readwrite csi-ephemeral-multiple csi-ephemeral-replicas
      csi-ephemeral-block-readwrite csi-ephemeral-block-multiple csi-ephemeral-block-replicas
      csi-topology-immediate-allowed csi-topology-immediate-conflict csi-topology-delayed-allowed csi-topology-delayed-conflict
      csi-restart-filesystem csi-restart-block
      csi-restart-delete-block csi-restart-force-delete-block
      csi-rbd-cross-node-filesystem csi-rbd-cross-node-block csi-rbd-cross-node-mixed
    ].freeze
    MULTI_POD_PROVIDER_CASES = %w[
      csi-multi-pod-same-node csi-multi-pod-readonly csi-raw-multi-pod csi-raw-multi-pod-readonly
      csi-ext4-store csi-ext4-exec csi-ext4-multi-pod csi-ext4-multi-pod-readonly csi-ext4-multi-pod-recreated
    ].freeze
    LEGACY_CASES = {
      "azure-disk" => BLOCK_PROVIDER_CASES + MULTI_POD_PROVIDER_CASES + %w[
        csi-multi-pv-same-handle csi-xfs-store csi-xfs-exec csi-xfs-multi-pod csi-xfs-multi-pod-readonly csi-xfs-multi-pod-recreated
        csi-fsgroup-always-rwop csi-rbd-cross-node-ext4
      ],
      "cinder" => BLOCK_PROVIDER_CASES + %w[csi-fsgroup-always-rwop],
      "vsphere" => BLOCK_PROVIDER_CASES + MULTI_POD_PROVIDER_CASES + %w[csi-fsgroup-always-rwop csi-rbd-cross-node-ext4],
      "azure-file" => %w[
        csi-store-data csi-exec csi-multi-pv-same-handle
        csi-nfs-cross-node-recreated csi-nfs-cross-node-concurrent csi-nfs-shared-readwrite csi-nfs-shared-readonly
        csi-nfs-same-node-recreated csi-nfs-volume-io csi-nfs-restart-filesystem csi-nfs-unused-filesystem
        csi-nfs-subpath-delete-during-restart csi-nfs-subpath-force-delete-during-restart
        csi-nfs-block-provision-denied csi-nfs-expand-disabled
        csi-nfs-ephemeral-readonly csi-nfs-ephemeral-readwrite csi-nfs-ephemeral-multiple csi-nfs-ephemeral-replicas
        csi-ephemeral-immediate-readonly csi-ephemeral-immediate-readwrite csi-ephemeral-immediate-replicas
      ] + NFS_SUBPATH_CASES
    }.freeze

    CASES = CONTRACTS.keys.flat_map do |key|
      providers = LEGACY_CASES.filter_map { |driver, cases| "[sig-storage] In-tree Volumes [Driver: #{driver}]" if cases.include?(key) }
      origins = key.start_with?("csi-nfs-", "csi-ephemeral-immediate-") ? providers : [ORIGIN, *providers]
      origins.map { |origin| ["#{origin} #{patterned_suffix(key)}", key] }
    end.to_h.freeze
    FILES = CONTRACTS.transform_values { |file, *_| "test/e2e/storage/testsuites/#{file}" }.freeze

    def self.case_for(id, source)
      key = CASES[id]
      key if key && FILES.fetch(key) == source
    end
  end
end
