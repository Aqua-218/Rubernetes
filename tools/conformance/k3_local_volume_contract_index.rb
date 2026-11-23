# frozen_string_literal: true

module Conformance
  module K3LocalVolumeContractIndex
    FILE = "test/e2e/storage/testsuites/volumes.go"
    SUBPATH_FILE = "test/e2e/storage/testsuites/subpath.go"
    IO_FILE = "test/e2e/storage/testsuites/volume_io.go"
    RUNNER = "tools/conformance/k3_local_volume_contracts.rb"
    PREFIX = "[sig-storage] In-tree Volumes [Driver: local] [LocalVolumeType: gce-localssd-scsi-fs] [Serial] " \
             "[Testpattern: Pre-provisioned PV (default fs)]"
    FILESYSTEM_PREFIX = PREFIX.sub("(default fs)", "(filesystem volmode)").freeze
    BLOCK_PREFIX = PREFIX.sub("(default fs)", "(block volmode)").freeze
    BLOCK_CASES = {
      "#{BLOCK_PREFIX} volumeMode should fail to create pod by failing to mount volume [Slow]" => "gce-local-ssd-block-refused"
    }.freeze
    VOLUME_CASES = {
      "#{PREFIX} volumes should store data" => "gce-local-ssd-store-data",
      "#{PREFIX} volumes should allow exec of files on the volume" => "gce-local-ssd-exec"
    }.freeze
    SUBPATH_CASES = {
      "should support non-existent path" => "subpath-missing",
      "should support existing directory" => "subpath-existing-directory",
      "should support existing single file [LinuxOnly]" => "subpath-existing-single-file",
      "should support file as subpath [LinuxOnly]" => "subpath-single-file",
      "should fail if subpath directory is outside the volume [Slow] [LinuxOnly]" => "subpath-directory-outside",
      "should fail if subpath file is outside the volume [Slow] [LinuxOnly]" => "subpath-file-outside",
      "should fail if non-existent subpath is outside the volume [Slow] [LinuxOnly]" => "subpath-missing-outside",
      "should fail if subpath with backstepping is outside the volume [Slow] [LinuxOnly]" => "subpath-backstep-outside",
      "should support creating multiple subpath from same volumes [Slow]" => "subpath-multiple",
      "should support readOnly directory specified in the volumeMount" => "subpath-readonly-directory",
      "should support readOnly file specified in the volumeMount [LinuxOnly]" => "subpath-readonly-file",
      "should support existing directories when readOnly specified in the volumeSource" => "subpath-readonly-source",
      "should verify container cannot write to subpath readonly volumes [Slow]" => "subpath-refuse-write",
      "should be able to unmount after the subpath directory is deleted [LinuxOnly]" => "subpath-removed-directory",
      "should support restarting containers using directory as subpath [Slow]" => "subpath-restart-directory",
      "should support restarting containers using file as subpath [Slow] [LinuxOnly]" => "subpath-restart-file",
      "should unmount if pod is gracefully deleted while kubelet is down [Disruptive] [Slow] [LinuxOnly]" => "subpath-unmount-graceful",
      "should unmount if pod is force deleted while kubelet is down [Disruptive] [Slow] [LinuxOnly]" => "subpath-unmount-force"
    }.transform_keys { |suffix| "#{PREFIX} subPath #{suffix}" }.freeze
    IO_CASES = {
      "#{PREFIX} volumeIO should write files of various sizes, verify size, validate content [Slow]" => "gce-local-ssd-io"
    }.freeze
    FILESYSTEM_CASES = {
      "multiVolume [Slow] should concurrently access the single volume from pods on the same node" =>
        ["gce-local-ssd-concurrent", "multivolume.go"],
      "multiVolume [Slow] should concurrently access the single read-only volume from pods on the same node" =>
        ["gce-local-ssd-concurrent-readonly", "multivolume.go"],
      "volumeMode should not mount / map unused volumes in a pod [LinuxOnly]" =>
        ["gce-local-ssd-unused", "volumemode.go"],
      "disruptive [Disruptive] [LinuxOnly] Should test that pv written before kubelet restart is readable after restart." =>
        ["gce-local-ssd-restart", "disruptive.go"]
    }.transform_keys { |suffix| "#{FILESYSTEM_PREFIX} #{suffix}" }.freeze
    CASES = VOLUME_CASES.merge(SUBPATH_CASES, IO_CASES, FILESYSTEM_CASES.transform_values(&:first), BLOCK_CASES).freeze
    FILES = VOLUME_CASES.merge(SUBPATH_CASES, IO_CASES).to_h do |id, key|
      file = if SUBPATH_CASES.key?(id)
               SUBPATH_FILE
             elsif IO_CASES.key?(id)
               IO_FILE
             else
               FILE
             end
      [key, file]
    end.merge(FILESYSTEM_CASES.values.to_h { |key, file| [key, "test/e2e/storage/testsuites/#{file}"] },
              "gce-local-ssd-block-refused" => "test/e2e/storage/testsuites/volumemode.go").freeze

    def self.case_for(id, source)
      key = CASES[id]
      key if key && FILES.fetch(key) == source
    end
  end
end
