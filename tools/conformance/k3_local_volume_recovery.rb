# frozen_string_literal: true

require_relative "k3_worker_restart"

module Conformance
  module K3LocalVolumeRecovery
    include K3WorkerRestart

    D = K7ClusterDriver

    private

    def verify_subpath_cleanup(namespace, claim, worker, force:)
      name = "mounted-subpath"
      node = worker.fetch("name").delete_prefix("agent-")
      root = pod_volume_root(node)
      original_stages = stage_mounts(mounts_below(root))
      pod = running_subpath(namespace, claim, name, grace_period: 30)
      raise "the Pod is not on #{node}" unless pod.dig("spec", "nodeName") == node

      pod_root = pod_volume_root(node, pod.dig("metadata", "uid"))
      mounts = mounts_below(pod_root)
      volume = File.join(pod_root, "volumes", "data")
      subpath = File.join(pod_root, "volume-subpaths", "subpath", "data", "0")
      raise "expected both PVC and subPath mounts: #{mounts}" unless mounts.include?(volume) && mounts.include?(subpath)

      write_volume_sample(namespace, name)
      before_restart = D.pid_of(worker)
      restart_during_deletion(namespace, name, worker, pod_root, force: force)
      kubectl!("-n", namespace, "wait", "--for=delete", "pod/#{name}", "--timeout=#{self.class::TIMEOUT}s")
      D.wait_until("the volume and every subPath unmounted", self.class::TIMEOUT) { mounts_below(pod_root).empty? }
      remaining_stages = stage_mounts(mounts_below(root))
      raise "staged mounts changed: #{original_stages} -> #{remaining_stages}" unless original_stages == remaining_stages

      {"deletion" => (force ? "force" : "graceful"), "volume_mount" => volume, "subpath_mount" => subpath,
       "mounts_remaining" => [], "original_stage_count" => original_stages.length,
       "retained_stage_count" => remaining_stages.length, "worker_pids" => [before_restart, D.pid_of(worker)]}
    end

    def restart_during_deletion(namespace, name, worker, pod_root, force:)
      with_agent_stopped(worker) do
        raise "the agent exited without leaving volume mounts to reconstruct" if mounts_below(pod_root).empty?

        options = force ? ["--force", "--grace-period=0"] : []
        kubectl!("-n", namespace, "delete", "pod", name, "--wait=false", *options)
        pod = D.kubectl_object("-n", namespace, "get", "pod", name)
        raise "force deletion did not remove the Pod with the agent stopped" if force && pod
        raise "graceful deletion did not leave a terminating Pod with the agent stopped" if !force && !pod&.dig("metadata", "deletionTimestamp")
      end
    end

    def write_volume_sample(namespace, name)
      data = SecureRandom.base64(64)
      exec_in(namespace, name, "subpath", *K3LocalSubpathContracts::SHELL,
              'printf %s "$1" | base64 -d | dd of="$2/file1.txt" bs=64 count=1; test "$(wc -c < "$2/file1.txt")" -eq 64',
              "write", data, K3LocalSubpathContracts::VOLUME)
    end

    def pod_volume_root(node, uid = nil)
      File.join(D.cluster_root, "runtime", node, "pods", "volumes", uid.to_s).delete_suffix("/")
    end

    def stage_mounts(mounts) = mounts.grep(%r{/stages/})
  end
end
