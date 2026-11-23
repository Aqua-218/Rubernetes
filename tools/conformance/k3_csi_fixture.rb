# frozen_string_literal: true

require "fileutils"
require "securerandom"
require "tmpdir"
require_relative "k7_cluster_driver"
require_relative "k3_csi_tools"
require_relative "k3_csi_snapshot_fixture"
require_relative "k3_csi_topology_fixture"
require_relative "k3_csi_nfs_fixture"
require_relative "k3_csi_rbd_fixture"
require_relative "lock"

module Conformance
  class K3CSIFixture
    include K3CSISnapshotFixture
    include K3CSITopologyFixture
    include K3CSINFSFixture
    include K3CSIRBDFixture

    DRIVER = "hostpath.csi.k8s.io"
    HOSTPATH_TOPOLOGY = "topology.hostpath.csi/node"
    MANIFEST_ROOT = "test/e2e/testing-manifests/storage-csi"
    D = K7ClusterDriver

    def initialize(source, reports)
      @source = source
      @reports = reports
      @name = "k3-csi-#{SecureRandom.hex(5)}"
      @pids = []
      @created = []
      @registration_sockets = []
    end

    FILESYSTEM_FORMATTERS = {
      "ext3" => %w[mkfs.ext3 -q -F], "ext4" => %w[mkfs.ext4 -q -F], "xfs" => %w[mkfs.xfs -q -f]
    }.freeze

    def with_driver(snapshots: false, expansion: false, filesystem: nil, backing_capacity: 12 * (1024**3))
      worker, pid = local_workers.first
      config = worker_config(worker)

      tools_directory = File.join(Lock::ROOT, "build/conformance/bin/k3-csi")
      @tools = K3CSITools.install(tools_directory, snapshots: snapshots, expansion: expansion)
      Dir.mktmpdir("k3csi-", "/tmp") do |working_directory|
        @socket = File.join(working_directory, "csi.sock")
        begin
          mount_backing_filesystem(working_directory, pid, filesystem, backing_capacity) if filesystem
          publish_api_objects(node: config.fetch("node_name"))
          publish_snapshot_objects if snapshots
          publish_role("external-resizer", pinned_manifest("external-resizer/rbac.yaml")) if expansion
          start_driver(working_directory, config, pid, socket: @socket)
          sidecar_config = service_account_kubeconfig(working_directory, @name)
          start("csi-attacher", "--csi-address=#{@socket}", "--kubeconfig=#{sidecar_config}")
          provisioner_flags = snapshots ? ["--timeout=120s"] : []
          start("csi-provisioner", "--csi-address=#{@socket}", "--kubeconfig=#{sidecar_config}", *provisioner_flags)
          start_snapshot_controllers(working_directory, sidecar_config) if snapshots
          start("csi-resizer", "--csi-address=#{@socket}", "--kubeconfig=#{sidecar_config}", "--leader-election=false") if expansion
          result = yield @name, config.fetch("node_name")
          wait_for_volume_deletion(config.fetch("node_name"))
          wait_for_snapshot_deletion if snapshots
          result
        ensure
          begin
            disconnect_driver
          ensure
            unmount_backing_filesystem(working_directory, pid) if filesystem
          end
        end
      end
    end

    private

    def local_workers
      descriptor = JSON.parse(File.read(D.descriptor_path))
      if descriptor["kind"] != "conformance_cluster" || !File.identical?(descriptor.fetch("kubeconfig"), ENV.fetch("KUBECONFIG"))
        raise D::Unsupported, "K3 CSI needs the local fixture identified by cluster.json"
      end

      workers = descriptor.fetch("processes").filter_map do |worker|
        next unless worker["executable"] == "rubernetes-agent"

        pid = D.pid_of(worker)
        node = D.kubectl_object("get", "node", worker.fetch("name").delete_prefix("agent-")) if pid
        [worker, pid] if node && D.ready_node?(node)
      end
      raise D::Unsupported, "K3 CSI needs a Ready local worker" if workers.empty?

      workers
    end

    def worker_config(worker)
      YAML.safe_load_file(worker.fetch("config")).fetch("processes").fetch("rubernetes-agent")
    end

    def registration_directory(config)
      default_pods = File.join(File.dirname(config.fetch("journal_path")), "pods")
      kubelet_root = File.dirname(File.expand_path(config.fetch("pod_root", default_pods)))
      config.fetch("dra", {}).fetch("plugins_registry", File.join(kubelet_root, "plugins_registry"))
    end

    def publish_api_objects(attach: true, node: nil)
      driver = YAML.safe_load(pinned_manifest("hostpath/hostpath/csi-hostpath-driverinfo.yaml"))
      driver.fetch("spec")["attachRequired"] = false unless attach
      create(driver)
      create("apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => @name})
      kubectl!("create", "serviceaccount", @name, "-n", @name)
      publish_role("external-provisioner", pinned_manifest("external-provisioner/rbac.yaml"))
      publish_role("external-attacher", pinned_manifest("external-attacher/rbac.yaml")) if attach
      storage_class = {"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass", "metadata" => {"name" => @name},
                       "provisioner" => DRIVER, "volumeBindingMode" => "WaitForFirstConsumer"}
      storage_class["allowedTopologies"] = [{"matchLabelExpressions" => [{"key" => HOSTPATH_TOPOLOGY, "values" => [node]}]}] if node
      create(storage_class)
    end

    def publish_role(name, contents, service_account: @name)
      role = YAML.load_stream(contents).find { |entry| entry["kind"] == "ClusterRole" }
      role_name = "#{@name}-#{name}"
      role.fetch("metadata")["name"] = role_name
      role.fetch("metadata").delete("namespace")
      create(role)
      kubectl!("create", "clusterrolebinding", role_name, "--clusterrole=#{role_name}", "--serviceaccount=#{@name}:#{service_account}")
      @created << ["clusterrolebinding", role_name]
    end

    def pinned_manifest(path)
      pinned_source("#{MANIFEST_ROOT}/#{path}")
    end

    def pinned_source(path)
      content, error, status = Open3.capture3("git", "-C", @source, "show", "#{Lock.source_commit}:#{path}")
      raise D::Unsupported, "pinned CSI manifest #{path} unavailable: #{error.strip}" unless status.success?

      content
    end

    def create(object)
      kubectl!("create", "-f", "-", input: JSON.generate(object))
      @created << [object.fetch("kind").downcase, object.fetch("metadata").fetch("name")]
    end

    def start_driver(directory, config, pid, socket:, attach: true, log_prefix: "")
      node = config.fetch("node_name")
      state = File.join(directory, "state")
      FileUtils.mkdir_p(state)
      start("hostpathplugin", "--drivername=#{DRIVER}", "--enable-attach=#{attach}", "--endpoint=unix://#{socket}",
            "--nodeid=#{node}", "--statedir=#{state}", prefix: ["nsenter", "--target=#{pid}", "--mount"], log_prefix: log_prefix)
      register_driver(config, socket: socket, driver_name: DRIVER, log_prefix: log_prefix)
    end

    def register_driver(config, socket:, driver_name:, log_prefix:)
      node = config.fetch("node_name")
      registration = registration_directory(config)
      registration_socket = File.join(registration, "#{driver_name}-reg.sock")
      raise "the CSI registration socket already exists" if File.exist?(registration_socket)
      raise "the worker's CSI registration path exceeds the Linux Unix socket limit" if registration_socket.bytesize > 107

      FileUtils.mkdir_p(registration)
      @registration_sockets << registration_socket
      D.wait_until("official CSI driver socket", 60) { File.socket?(socket) }
      start("csi-node-driver-registrar", "--csi-address=#{socket}", "--kubelet-registration-path=#{socket}",
            "--plugin-registration-path=#{registration}", log_prefix: log_prefix)
      D.wait_until("CSI registration on #{node}", 60) do
        resource = D.kubectl_object("get", "csinode", node)
        driver = Array(resource&.dig("spec", "drivers")).find { |entry| entry["name"] == driver_name }
        File.write(File.join(@reports, "#{log_prefix}registration.json"), JSON.generate("node" => node, "driver" => driver)) if driver
      end
    end

    def mount_backing_filesystem(directory, pid, filesystem, backing_capacity)
      image = File.join(directory, "backing.#{filesystem}")
      File.open(image, "wb") { |file| file.truncate(backing_capacity) }
      formatter = FILESYSTEM_FORMATTERS.fetch(filesystem)
      raise D::Unsupported, "#{formatter.first} failed for the CSI test filesystem" unless system(*formatter, image, out: File::NULL)

      signature, error, status = Open3.capture3("blkid", "-p", "-s", "TYPE", "-o", "value", image)
      unless status.success? && signature.strip == filesystem
        raise D::Unsupported, "CSI test image must have a #{filesystem} superblock (#{signature.strip} #{error.strip})"
      end

      state = File.join(directory, "state")
      FileUtils.mkdir_p(state)
      namespace = ["nsenter", "--target=#{pid}", "--mount"]
      _, error, status = Open3.capture3(*namespace, "mount", "-t", filesystem, "-o", "loop", image, state)
      raise D::Unsupported, "mount CSI test filesystem: #{error.strip}" unless status.success?

      mounts, error, status = Open3.capture3(*namespace, "findmnt", "--json", "--mountpoint", state)
      raise D::Unsupported, "read CSI test filesystem: #{error.strip}" unless status.success?

      File.write(File.join(@reports, "storage-filesystem.json"), JSON.generate(JSON.parse(mounts).merge("imageFilesystem" => signature.strip)))
    end

    def unmount_backing_filesystem(directory, pid)
      state = File.join(directory, "state")
      namespace = ["nsenter", "--target=#{pid}", "--mount"]
      return unless system(*namespace, "mountpoint", "--quiet", state)

      _, error, status = Open3.capture3(*namespace, "umount", state)
      raise "unmount CSI test filesystem: #{error.strip}" unless status.success?
    end

    def start(name, *, prefix: [], log_prefix: "", environment: {})
      log = File.join(@reports, "#{log_prefix}#{name}.log")
      @pids << Process.spawn({"NO_PROXY" => "*", "no_proxy" => "*"}.merge(environment), *prefix, @tools.fetch(name), *, "--v=4",
                             out: log, err: %i[child out])
    end

    def service_account_kubeconfig(directory, service_account)
      token = kubectl!("create", "token", service_account, "-n", @name, "--duration=2h").strip
      config = JSON.parse(kubectl!("config", "view", "--raw", "--minify", "--flatten", "-o", "json"))
      config["users"] = [{"name" => service_account, "user" => {"token" => token}}]
      config.fetch("contexts").first.fetch("context")["user"] = service_account
      path = File.join(directory, "#{service_account}.kubeconfig")
      File.write(path, JSON.generate(config), perm: 0o600)
      path
    end

    def disconnect_driver
      @pids.reverse_each { |pid| stop(pid) }
      FileUtils.rm_f(@registration_sockets)
      @created.reverse_each { |kind, name| kubectl!("delete", kind, name, "--ignore-not-found", "--wait=true", "--timeout=90s") }
    end

    def wait_for_volume_deletion(*nodes, driver_name: DRIVER)
      report = File.join(@reports, "storage-cleanup.json")
      read_error = nil
      D.wait_until("CSI provisioner and attacher deletion", 180) do
        volumes = driver_objects("pv", "csi", "driver", driver_name: driver_name)
        attachments = driver_objects("volumeattachments", "attacher", driver_name: driver_name)
        in_use = nodes.flat_map do |node|
          status = read_api_object("node", node).fetch("status")
          Array(status["volumesInUse"]).select { |name| name.start_with?("kubernetes.io/csi/#{driver_name}^") }
        end
        File.write(report, JSON.generate("persistentVolumes" => volumes, "volumeAttachments" => attachments, "nodeVolumesInUse" => in_use))
        volumes.empty? && attachments.empty? && in_use.empty?
      rescue JSON::ParserError => error
        read_error = error
        false
      end
    rescue RuntimeError => error
      raise "#{error.message}; last unreadable API response: #{read_error.message}" if read_error

      raise
    end

    def driver_objects(resource, *field, driver_name: DRIVER)
      read_api_object(resource).fetch("items").filter_map do |object|
        object.dig("metadata", "name") if object.dig("spec", *field) == driver_name
      end
    end

    def read_api_object(*resource)
      JSON.parse(kubectl!("get", *resource, "-o", "json"))
    rescue JSON::ParserError => error
      raise JSON::ParserError, "kubectl get #{resource.join(" ")} did not return JSON (#{error.message})"
    end

    def stop(pid)
      Process.kill("TERM", pid)
      Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end

    def kubectl!(*arguments, input: nil)
      env = {"NO_PROXY" => "*", "no_proxy" => "*"}
      out, err, status = Open3.capture3(env, D::KUBECTL, "--request-timeout=15s", *arguments, stdin_data: input.to_s)
      raise "kubectl #{arguments.join(" ")}: #{err.strip}" unless status.success?

      out
    end
  end
end
