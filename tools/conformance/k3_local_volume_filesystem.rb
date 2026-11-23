# frozen_string_literal: true

require "digest"

module Conformance
  module K3LocalVolumeFilesystem
    D = K7ClusterDriver
    SHARED_VOLUME_PATH = "/mnt/volume1"
    MULTI_VOLUME_IMAGE = "registry.k8s.io/e2e-test-images/glibc-dns-testing:2.0.0"
    SLEEP = ["/bin/sh", "-c", "trap exit TERM; while true; do sleep 1; done"].freeze

    private

    def verify_filesystem(key, namespace, claim, worker)
      case key
      when "gce-local-ssd-concurrent", "gce-local-ssd-concurrent-readonly"
        verify_concurrent_volume(namespace, claim, readonly: key.end_with?("-readonly"))
      when "gce-local-ssd-unused" then verify_unused_volume(namespace, claim)
      when "gce-local-ssd-restart" then verify_restart_volume(namespace, claim, worker)
      when "gce-local-ssd-block-refused" then verify_unsupported_block_volume(namespace, claim)
      else raise ArgumentError, "unknown Local PV contract #{key.inspect}"
      end
    end

    def verify_unsupported_block_volume(namespace, claim)
      name = "unsupported-block"
      container = {"name" => "volume", "image" => self.class::BUSYBOX, "command" => SLEEP,
                   "volumeDevices" => [{"name" => "data", "devicePath" => "/dev/local-test"}]}
      object = JSON.parse(create(pod(namespace, claim, name, container)))
      uid = object.fetch("metadata").fetch("uid")
      failure = nil
      D.wait_until("the worker to refuse a directory-backed block volume", self.class::TIMEOUT) do
        watched = D.kubectl_object("-n", namespace, "get", "pod", name)
        raise "directory-backed Block volume started the Pod" if watched&.dig("status", "phase") == "Running"

        events = D.kubectl_object("-n", namespace, "get", "events", "--field-selector=involvedObject.uid=#{uid}")
        failure = Array(events&.fetch("items")).find do |event|
          event["reason"] == "FailedMount" && event.fetch("message", "").include?("does not match type BlockDevice")
        end
        failure && watched&.dig("status", "phase") == "Pending"
      end
      pv = D.kubectl_object("get", "pv", namespace)
      raise "the local Block PV was not bound" unless pv&.dig("status", "phase") == "Bound" && pv.dig("spec", "volumeMode") == "Block"

      {"pod_uid" => uid, "pvc" => claim, "failure" => failure.slice("reason", "message"), "phase" => "Pending"}
    end

    def verify_concurrent_volume(namespace, claim, readonly:)
      if readonly
        filesystem_pod(namespace, claim, "initialize")
        delete_pod(namespace, "initialize")
      end
      pods = %w[first second].map do |name|
        object = filesystem_pod(namespace, claim, name, readonly: readonly, image: MULTI_VOLUME_IMAGE)
        {"name" => name, "uid" => object.dig("metadata", "uid"), "node" => object.dig("spec", "nodeName"),
         "mount_options" => check_filesystem(namespace, name, readonly: readonly)}
      end
      nodes = pods.map { |pod| pod.fetch("node") }.uniq
      raise "both Pods must run on the same worker: #{nodes}" unless nodes.one? && nodes.first

      digests = readonly ? [] : exchange_samples(namespace)
      delete_pod(namespace, "second")
      surviving_options = check_filesystem(namespace, "first", readonly: readonly)
      unless readonly
        check_sample(namespace, "first", digests.last)
        digests << write_sample(namespace, "first")
        check_sample(namespace, "first", digests.last)
      end
      {"node" => nodes.first, "pods" => pods, "readonly" => readonly, "sample_digests" => digests,
       "first_pod_still_mounted" => true, "first_pod_mount_options_after_deletion" => surviving_options}
    end

    def exchange_samples(namespace)
      first = write_sample(namespace, "first")
      check_sample(namespace, "first", first)
      check_sample(namespace, "second", first)
      second = write_sample(namespace, "second")
      check_sample(namespace, "second", second)
      [first, second]
    end

    def verify_unused_volume(namespace, claim)
      object = filesystem_pod(namespace, claim, "unused", mounted: false)
      node = object.dig("spec", "nodeName")
      uid = object.dig("metadata", "uid")
      root = pod_volume_root(node, uid)
      data_mounts = mounts_below(root).select { |mount| mount.end_with?("/data") }
      raise "the node mounted the unused PVC: #{data_mounts}" unless data_mounts.empty?

      add_ephemeral(namespace, "unused", "use-volume", SHARED_VOLUME_PATH)
      D.wait_until("the ephemeral container using the previously unused volume", self.class::TIMEOUT) do
        observed = D.kubectl_object("-n", namespace, "get", "pod", "unused")
        Array(observed&.dig("status", "ephemeralContainerStatuses")).any? { |status| status["name"] == "use-volume" && status.dig("state", "running") }
      end
      exec_in(namespace, "unused", "use-volume", "test", "-d", SHARED_VOLUME_PATH)
      {"node" => node, "pod_uid" => uid, "pvc_mounts_before_use" => data_mounts, "ephemeral_volume_ready" => true}
    end

    def verify_restart_volume(namespace, claim, worker)
      name = "retain-data"
      original = filesystem_pod(namespace, claim, name)
      digest = write_sample(namespace, name)
      check_sample(namespace, name, digest)
      pid = D.pid_of(worker)
      with_agent_stopped(worker) { nil }
      sleep 20
      await_ready(namespace, name)
      restarted = D.kubectl_object("-n", namespace, "get", "pod", name)
      raise "the Pod UID changed after node agent restart" unless original.dig("metadata", "uid") == restarted.dig("metadata", "uid")

      check_filesystem(namespace, name)
      check_sample(namespace, name, digest)
      {"sha256" => digest, "pod_uid" => original.dig("metadata", "uid"), "worker_pids" => [pid, D.pid_of(worker)]}
    end

    def filesystem_pod(namespace, claim, name, readonly: false, mounted: true, image: self.class::BUSYBOX)
      container = mounted_container("volume", image, SHARED_VOLUME_PATH, SLEEP)
      container.delete("volumeMounts") unless mounted
      object = pod(namespace, claim, name, container)
      spec = object.fetch("spec")
      spec.dig("volumes", 0, "persistentVolumeClaim")["readOnly"] = true if readonly
      spec["terminationGracePeriodSeconds"] = 3
      spec["restartPolicy"] = "OnFailure"
      spec["securityContext"] = {"seLinuxOptions" => {"level" => "s0:c0,c1"}}
      create(object)
      await_ready(namespace, name)
      D.kubectl_object("-n", namespace, "get", "pod", name)
    end

    def check_filesystem(namespace, name, readonly: false)
      exec_in(namespace, name, "volume", "/bin/sh", "-ec", 'test -d "$1"; test ! -b "$1"', "check", SHARED_VOLUME_PATH)
      mountinfo = exec_in(namespace, name, "volume", "cat", "/proc/self/mountinfo").lines.map(&:split)
      mount = mountinfo.find { |entry| entry[4] == SHARED_VOLUME_PATH }
      options = mount&.fetch(5)&.split(",")
      mode = readonly ? "ro" : "rw"
      raise "#{name} does not have a #{mode} mount at #{SHARED_VOLUME_PATH}: #{options.inspect}" unless options&.include?(mode)

      options
    end

    def write_sample(namespace, name)
      bytes = SecureRandom.random_bytes(64)
      exec_in(namespace, name, "volume", "/bin/sh", "-ec",
              'printf %s "$1" | base64 -d | dd of="$2/file1.txt" bs=64 count=1',
              "write", [bytes].pack("m0"), SHARED_VOLUME_PATH)
      Digest::SHA256.hexdigest(bytes)
    end

    def check_sample(namespace, name, digest)
      observed = exec_in(namespace, name, "volume", "sha256sum", "#{SHARED_VOLUME_PATH}/file1.txt").split.first
      raise "#{name} read the wrong sample from the shared volume" unless observed == digest
    end
  end
end
