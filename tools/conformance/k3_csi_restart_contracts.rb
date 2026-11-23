# frozen_string_literal: true

require "base64"
require "securerandom"
require_relative "k3_worker_restart"

module Conformance
  class K3CSIRestartContracts
    include K3WorkerRestart

    D = K7ClusterDriver
    BUSYBOX = "registry.k8s.io/e2e-test-images/busybox:1.37.0-1"
    TIMEOUT = 180
    CASES = {
      "csi-restart-filesystem" => {block: false},
      "csi-restart-block" => {block: true},
      "csi-restart-delete-block" => {block: true, delete: :graceful},
      "csi-restart-force-delete-block" => {block: true, delete: :force},
      "csi-unused-filesystem" => {block: false, unused: true},
      "csi-unused-block" => {block: true, unused: true},
      "csi-subpath-delete-during-restart" => {block: false, subpath: true, delete: :graceful},
      "csi-subpath-force-delete-during-restart" => {block: false, subpath: true, delete: :force},
      "csi-nfs-restart-filesystem" => {block: false},
      "csi-nfs-unused-filesystem" => {block: false, unused: true},
      "csi-nfs-subpath-delete-during-restart" => {block: false, subpath: true, delete: :graceful},
      "csi-nfs-subpath-force-delete-during-restart" => {block: false, subpath: true, delete: :force}
    }.freeze

    def initialize(storage_class, node, nfs: false)
      @storage_class = storage_class
      @worker = D.processes.find { |process| process.fetch("name") == "agent-#{node}" }
      raise D::Unsupported, "CSI restart case requires a local worker" unless @worker && D.pid_of(@worker)

      @node = node
      @nfs = nfs
      config = YAML.safe_load_file(@worker.fetch("config")).fetch("processes").fetch("rubernetes-agent")
      root = config.fetch("pod_root", File.join(File.dirname(config.fetch("journal_path")), "pods"))
      @volume_root = File.join(root, "volumes")
      @stage_root = File.join(File.dirname(config.fetch("journal_path")), "volumes", "csi-staging")
      @csi_plugin_root = File.join(File.dirname(root), "plugins", "kubernetes.io", "csi")
    end

    def run(block:, delete: nil, unused: false, subpath: false)
      @namespace = "k3-csi-restart-#{SecureRandom.hex(4)}"
      kubectl!("create", "namespace", @namespace)
      begin
        prepare_claim(block)
        return verify_unused_volume(block) if unused

        original_stages = global_stages if subpath
        pod = prepare_pod(block, subpath: subpath)
        uid = pod.dig("metadata", "uid")
        path = File.join(@volume_root, uid)
        publish_target = File.join(path, "volumes", "data")
        mounts = mounts_below(path)
        raise "CSI volume has no published kernel mount for Pod #{uid}" unless mounts.include?(publish_target)

        filesystem = publication_filesystem(publish_target)
        nested_mounts = mounts.grep(%r{/volume-subpaths/})
        raise "CSI subPath mount was not observed" if subpath && nested_mounts.empty?

        staged = global_stages - original_stages if subpath
        raise "unexpected CSI global staging for the registered driver" if subpath && staged.empty? != @nfs

        first_pid = D.pid_of(@worker)
        preserve = delete ? deletion_case(path, delete) : verify_data_after_restart(uid, block)
        second_pid = D.pid_of(@worker)
        raise "node agent did not restart" if second_pid.nil? || second_pid == first_pid

        if subpath
          D.wait_until("CSI subPath cleanup left no global staging residue", TIMEOUT) { global_stages == original_stages }
          preserve["subpath_mounts_before"] = nested_mounts
          preserve["case_global_stages"] = staged
          preserve["global_stages_after"] = global_stages
        end

        {"pod_uid" => uid, "published_mount" => publish_target, "filesystem" => filesystem, "mode" => block ? "Block" : "Filesystem",
         "agent_pids" => [first_pid, second_pid]}.merge(preserve)
      ensure
        kubectl!("delete", "namespace", @namespace, "--timeout=#{TIMEOUT}s")
      end
    end

    private

    def prepare_claim(block)
      create("apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => "data"},
             "spec" => {"storageClassName" => @storage_class, "accessModes" => ["ReadWriteOnce"], "volumeMode" => block ? "Block" : "Filesystem",
                        "resources" => {"requests" => {"storage" => "5Gi"}}})
    end

    def prepare_pod(block, name: "volume", mounted: true, subpath: false)
      container = {"name" => "volume", "image" => BUSYBOX, "command" => ["/bin/sh", "-c", "while true; do sleep 2; done"]}
      if mounted && block
        container["volumeDevices"] = [{"name" => "data", "devicePath" => "/dev/csi-test"}]
      elsif mounted
        container["volumeMounts"] = [{"name" => "data", "mountPath" => "/test"}]
      end
      spec = {"nodeSelector" => {"kubernetes.io/hostname" => @node}, "containers" => [container],
              "volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "data"}}]}
      configure_subpath(spec, container) if subpath
      create("apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name}, "spec" => spec)
      in_namespace("wait", "--for=condition=Ready", "pod/#{name}", "--timeout=#{TIMEOUT}s")
      exec!("test -b /dev/csi-test", pod: name) if block && mounted
      pod_object(name)
    end

    def configure_subpath(spec, container)
      spec["terminationGracePeriodSeconds"] = 30
      spec["initContainers"] = [{"name" => "prepare", "image" => BUSYBOX, "command" => ["/bin/sh", "-ec", "mkdir -p /test/subset"],
                                 "volumeMounts" => [{"name" => "data", "mountPath" => "/test"}]}]
      container.fetch("volumeMounts") << {"name" => "data", "mountPath" => "/subset", "subPath" => "subset"}
    end

    def global_stages
      legacy = Dir.glob(File.join(@stage_root, "*")) + mounts_below(@stage_root)
      kubelet = Dir.glob(File.join(@csi_plugin_root, "*", "*", "globalmount")) + mounts_below(@csi_plugin_root)
      (legacy + kubelet).uniq.sort
    end

    def publication_filesystem(target)
      entry = File.foreach("/proc/self/mountinfo").find { |line| mountinfo_target(line) == target }
      filesystem = entry&.partition(" - ")&.last.to_s.split.first
      raise "expected a kernel NFS publication at #{target}" if @nfs && filesystem != "nfs4"

      filesystem
    end

    def verify_unused_volume(block)
      control = prepare_pod(block)
      unused = prepare_pod(block, name: "unused", mounted: false)
      claim = unused.fetch("spec").fetch("volumes").find { |volume| volume["name"] == "data" }
      raise "unused Pod has lost its intended PVC declaration" unless claim&.dig("persistentVolumeClaim", "claimName") == "data"

      control_root = File.join(@volume_root, control.dig("metadata", "uid"))
      unused_root = File.join(@volume_root, unused.dig("metadata", "uid"))
      control_target = File.join(control_root, "volumes", "data")
      unused_target = File.join(unused_root, "volumes", "data")
      raise "mounted control Pod has no CSI publication" unless mounts_below(control_root).include?(control_target)
      raise "unused CSI volume was published" if mounts_below(unused_root).include?(unused_target) || File.exist?(unused_target)

      {"mode" => block ? "Block" : "Filesystem", "control_publication" => control_target, "filesystem" => publication_filesystem(control_target),
       "unused_pod_uid" => unused.dig("metadata", "uid"), "unexpected_publication" => false}
    end

    def verify_data_after_restart(uid, block)
      sample = Base64.strict_encode64(SecureRandom.random_bytes(64))
      destination = block ? "/dev/csi-test" : "/test/sample"
      exec!('printf %s "$1" | base64 -d | dd of="$2" bs=64 count=1 conv=notrunc', sample, destination)
      with_agent_stopped(@worker) do
        raise "CSI volume was removed while the worker was down" if mounts_below(File.join(@volume_root, uid)).empty?
      end
      D.wait_until("read CSI payload from the same Pod after agent restart", TIMEOUT) do
        observed = pod_object
        raise "Pod identity changed during agent restart" if observed && observed.dig("metadata", "uid") != uid

        begin
          exec!('dd if="$1" bs=64 count=1 2>/dev/null | base64', destination).delete("\n") == sample
        rescue RuntimeError
          false
        end
      end
      {"verified_bytes" => 64}
    end

    def deletion_case(path, delete)
      with_agent_stopped(@worker) do
        raise "CSI publication disappeared while the worker was down" if mounts_below(path).empty?

        flags = delete == :force ? %w[--force --grace-period=0] : []
        in_namespace("delete", "pod", "volume", "--wait=false", *flags)
        observed = pod_object
        raise "force deletion left the Pod in the API" if delete == :force && observed
        raise "graceful deletion did not mark the Pod while the worker was down" if delete == :graceful && !observed&.dig("metadata", "deletionTimestamp")
      end
      D.wait_until("deleted CSI Pod and every publication removed", TIMEOUT) do
        pod_object.nil? && mounts_below(path).empty? && !File.exist?(File.join(path, "volumes", "data"))
      end
      {"deletion" => delete.to_s, "remaining_pod_mounts" => mounts_below(path)}
    end

    def create(object)
      kubectl!("-n", @namespace, "create", "-f", "-", input: JSON.generate(object))
    end

    def in_namespace(*) = kubectl!("-n", @namespace, *)

    def pod_object(name = "volume") = D.kubectl_object("-n", @namespace, "get", "pod", name)

    def exec!(command, *, pod: "volume") = in_namespace("exec", pod, "--", "/bin/sh", "-ec", command, "volume", *)

    def kubectl!(*args, input: "")
      output, error, status = Open3.capture3({"NO_PROXY" => "*", "no_proxy" => "*"}, D::KUBECTL,
                                             "--request-timeout=15s", *args, stdin_data: input)
      raise "kubectl #{args.join(" ")}: #{error.strip}" unless status.success?

      output
    end
  end
end
