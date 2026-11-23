#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "securerandom"
require "tmpdir"
require_relative "k7_cluster_driver"
require_relative "k3_local_volume_contract_index"
require_relative "k3_local_subpath_contracts"
require_relative "k3_local_volume_recovery"
require_relative "k3_local_volume_filesystem"

module Conformance
  # Replays upstream GCE local SSD default-filesystem workload contracts on
  # a directory-backed Local PV in the cluster fixture.
  class K3LocalVolumeContracts
    include K3LocalSubpathContracts
    include K3LocalVolumeRecovery
    include K3LocalVolumeFilesystem

    D = K7ClusterDriver
    IDS = K3LocalVolumeContractIndex::CASES.invert.freeze
    BUSYBOX = "registry.k8s.io/e2e-test-images/busybox:1.37.0-1"
    NGINX = "registry.k8s.io/e2e-test-images/nginx:1.15-4"
    IDLE = ["/bin/sh", "-c", "while true; do sleep 2; done"].freeze
    TIMEOUT = 180

    def run(cases)
      raise ArgumentError, "select at least one known local volume contract" if cases.empty? || (cases - IDS.keys).any?

      descriptor = JSON.parse(File.read(D.descriptor_path))
      unless descriptor["kind"] == "conformance_cluster" && File.identical?(descriptor.fetch("kubeconfig"), ENV.fetch("KUBECONFIG"))
        raise D::Unsupported, "the kubeconfig must name the local fixture recorded in cluster.json"
      end

      worker = descriptor.fetch("processes").find { |entry| entry["executable"] == "rubernetes-agent" }
      raise D::Unsupported, "the fixture needs a local worker" unless worker && D.pid_of(worker)

      cases.map { |key| execute(key, worker) }
    end

    private

    def execute(key, worker)
      started = Time.now.utc.iso8601
      identity = {"id" => IDS.fetch(key), "file" => K3LocalVolumeContractIndex::FILES.fetch(key), "replacement_case" => key}
      mode = key == "gce-local-ssd-block-refused" ? "Block" : "Filesystem"
      observations = with_volume(worker.fetch("name").delete_prefix("agent-"), mode: mode) do |namespace, claim|
        case key
        when "gce-local-ssd-store-data" then verify_store_data(namespace, claim)
        when "gce-local-ssd-exec" then verify_exec(namespace, claim)
        when "gce-local-ssd-io" then verify_volume_io(namespace, claim)
        when "subpath-unmount-graceful", "subpath-unmount-force"
          verify_subpath_cleanup(namespace, claim, worker, force: key == "subpath-unmount-force")
        else
          key.start_with?("subpath-") ? verify_subpath(key, namespace, claim) : verify_filesystem(key, namespace, claim, worker)
        end
      end
      identity.merge("passed" => true, "started_at" => started, "observations" => observations)
    rescue StandardError => error
      identity.merge("passed" => false, "started_at" => started, "reason" => "#{error.class}: #{error.message}")
    end

    def with_volume(node, mode:)
      namespace = "k3-local-#{SecureRandom.hex(6)}"
      claim = "local-data"
      @volume_pods = []
      path = Dir.mktmpdir("k3-local-pv-", File.join(D.cluster_root, "runtime"))
      kubectl!("create", "namespace", namespace)
      create(local_volume(namespace, claim, node, path, mode: mode))
      create({"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => claim, "namespace" => namespace},
              "spec" => {"accessModes" => ["ReadWriteOnce"], "storageClassName" => "", "volumeName" => namespace, "volumeMode" => mode,
                         "resources" => {"requests" => {"storage" => "1Gi"}}}})
      await(namespace, "pvc", claim, %w[status phase], "Bound")
      yield namespace, claim
    ensure
      if namespace
        kubectl!("delete", "namespace", namespace, "--ignore-not-found", "--wait=true", "--timeout=#{TIMEOUT}s")
        kubectl!("delete", "pv", namespace, "--ignore-not-found", "--wait=true", "--timeout=#{TIMEOUT}s")
      end
      if path && File.directory?(path)
        D.wait_until("the Local PV backing directory to be unmounted", TIMEOUT) do
          @volume_pods.all? { |uid| mounts_below(pod_volume_root(node, uid)).empty? }
        end
        FileUtils.remove_entry_secure(path)
      end
    end

    def local_volume(namespace, claim, node, path, mode:)
      affinity = {"required" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname",
                                                                                  "operator" => "In", "values" => [node]}]}]}}
      {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => namespace},
       "spec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"], "volumeMode" => mode,
                  "persistentVolumeReclaimPolicy" => "Retain", "storageClassName" => "", "local" => {"path" => path},
                  "nodeAffinity" => affinity, "claimRef" => {"namespace" => namespace, "name" => claim}}}
    end

    def verify_store_data(namespace, claim)
      path = "/opt/0"
      expected = "Hello from local from namespace #{namespace}"
      running_pod(namespace, claim, "injector", path, privileged: true)
      exec_in(namespace, "injector", "volume", "/bin/sh", "-ec", 'printf "%s\n" "$1" > "$2/index.html"; sync', "write", expected, path)
      injector = read_volume(namespace, "injector", "volume", path, expected)
      kubectl!("-n", namespace, "delete", "pod", "injector", "--wait=true", "--timeout=#{TIMEOUT}s")

      running_pod(namespace, claim, "client", path)
      client = read_volume(namespace, "client", "volume", path, expected)
      ephemeral = "volume-ephemeral-container"
      add_ephemeral(namespace, "client", ephemeral, path)
      D.wait_until("the ephemeral container running", TIMEOUT) do
        status = D.kubectl_object("-n", namespace, "get", "pod", "client")
        Array(status&.dig("status", "ephemeralContainerStatuses")).any? { |entry| entry["name"] == ephemeral && entry.dig("state", "running") }
      end
      {"injector" => injector, "client" => client, "ephemeral" => read_volume(namespace, "client", ephemeral, path, expected)}
    end

    def verify_exec(namespace, claim)
      path = "/vol1"
      script = "test-preprovisioned.sh"
      command = "printf '%s\\n' 'ls #{path}' > #{path}/#{script}; chmod u+x #{path}/#{script}; #{path}/#{script}"
      container = mounted_container("volume", NGINX, path, ["/bin/sh", "-ec", command])
      create(pod(namespace, claim, "exec-volume-test", container))
      await(namespace, "pod", "exec-volume-test", %w[status phase], "Succeeded")
      output = kubectl!("-n", namespace, "logs", "exec-volume-test")
      raise "the script did not list itself on the mounted volume" unless output.lines.map(&:strip).include?(script)

      {"script" => script, "output" => output.strip}
    end

    def verify_volume_io(namespace, claim)
      path = "/opt"
      input = "#{path}/local-#{namespace}-dd_if"
      target = "#{path}/local_io_test_#{namespace}-1048576"
      bytes = "abcdefghijklmnopqrstuvwxyz123456" * 32
      command = "i=0; while [ \"$i\" -lt 1024 ]; do printf %s '#{bytes}' >> #{input}; i=$((i+1)); done"
      init = mounted_container("prepare", BUSYBOX, path, ["/bin/sh", "-ec", command])
      container = mounted_container("volume", BUSYBOX, path, IDLE)
      object = pod(namespace, claim, "volume-io", container)
      object["spec"]["initContainers"] = [init]
      object["spec"]["securityContext"] = {"fsGroup" => 1234}
      create(object)
      await_ready(namespace, "volume-io")
      exec_in(namespace, "volume-io", "volume", "/bin/sh", "-ec", "dd if=#{input} bs=1048576 > #{target}")
      size = exec_in(namespace, "volume-io", "volume", "stat", "-c", "%s", target).strip
      digest = exec_in(namespace, "volume-io", "volume", "sha256sum", target).split.first
      unless size == "1048576" && digest == "aa39c2cbd49a28425c977d229b43e1ff9579ecd98cea7b466982bab04753f2ab"
        raise "volume I/O mismatch: #{size} bytes, SHA-256 #{digest}"
      end

      exec_in(namespace, "volume-io", "volume", "rm", input, target)
      {"size" => size.to_i, "sha256" => digest}
    end

    def mounted_container(name, image, path, command)
      {"name" => name, "image" => image, "command" => command, "volumeMounts" => [{"name" => "data", "mountPath" => path}]}
    end

    def pod(namespace, claim, name, container)
      {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => namespace},
       "spec" => {"restartPolicy" => "Never", "containers" => [container],
                  "volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => claim}}]}}
    end

    def running_pod(namespace, claim, name, path, privileged: false)
      container = mounted_container("volume", BUSYBOX, path, IDLE)
      container["securityContext"] = {"privileged" => true} if privileged
      create(pod(namespace, claim, name, container))
      kubectl!("-n", namespace, "wait", "--for=condition=Ready", "pod/#{name}", "--timeout=#{TIMEOUT}s")
    end

    def add_ephemeral(namespace, name, container, path)
      object = D.kubectl_object("-n", namespace, "get", "pod", name)
      object.fetch("spec")["ephemeralContainers"] = [mounted_container(container, BUSYBOX, path, IDLE)]
      kubectl!("replace", "--raw", "/api/v1/namespaces/#{namespace}/pods/#{name}/ephemeralcontainers", "-f", "-", input: JSON.generate(object))
    end

    def read_volume(namespace, pod, container, path, expected)
      exec_in(namespace, pod, container, "/bin/sh", "-ec", 'test -d "$1" && test ! -b "$1"', "check", path)
      actual = exec_in(namespace, pod, container, "cat", "#{path}/index.html").strip
      raise "#{pod}/#{container} read the wrong volume data" unless actual == expected

      actual
    end

    def await(namespace, resource, name, field, expected)
      D.wait_until("#{resource}/#{name} #{expected}", TIMEOUT) do
        object = D.kubectl_object("-n", namespace, "get", resource, name)
        if resource == "pod" && object&.dig("status", "phase") == "Failed" && expected != "Failed"
          raise "pod/#{name} failed: #{object.dig("status", "containerStatuses")}"
        end

        object&.dig(*field) == expected
      end
    end

    def create(object)
      response = kubectl!("create", "-o", "json", "-f", "-", input: JSON.generate(object))
      @volume_pods << JSON.parse(response).fetch("metadata").fetch("uid") if object["kind"] == "Pod"
      response
    end

    def exec_in(namespace, pod, container, *command)
      kubectl!("-n", namespace, "exec", pod, "-c", container, "--", *command)
    end

    def kubectl!(*arguments, input: "")
      stdout, stderr, status = Open3.capture3({"NO_PROXY" => "*", "no_proxy" => "*"}, D::KUBECTL, *arguments, stdin_data: input)
      raise "kubectl #{arguments.join(" ")} failed: #{stderr.strip}" unless status.success?

      stdout
    end
  end
end

if $PROGRAM_NAME == __FILE__
  results = Conformance::K3LocalVolumeContracts.new.run(ARGV)
  puts JSON.pretty_generate("results" => results)
  exit(results.all? { |result| result["passed"] } ? 0 : 1)
end
