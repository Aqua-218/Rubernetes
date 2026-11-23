# frozen_string_literal: true

module Conformance
  module K3CSINFSFixture
    NFS_DRIVER = "nfs.csi.k8s.io"

    def with_nfs_driver(select_node: false)
      server = ENV["RUBERNETES_K3_NFS_SERVER"].to_s
      share = ENV["RUBERNETES_K3_NFS_SHARE"].to_s
      if server.empty? || !share.start_with?("/")
        raise self.class::D::Unsupported, "K3 network CSI needs the dedicated test export in RUBERNETES_K3_NFS_SERVER and RUBERNETES_K3_NFS_SHARE"
      end

      workers = local_workers
      raise self.class::D::Unsupported, "K3 network CSI needs two Ready local workers" if workers.length < 2

      check_nfs_clients(workers)
      tools_directory = File.join(Lock::ROOT, "build/conformance/bin/k3-csi")
      @tools = K3CSITools.install(tools_directory, nfs: true)
      Dir.mktmpdir("k3csi-nfs-", "/tmp") do |directory|
        publish_nfs_objects(server, share)
        sidecar_config = service_account_kubeconfig(directory, @name)
        endpoints = workers.map { |worker, pid| start_nfs_worker(directory, worker, pid) }
        start("csi-provisioner", "--csi-address=#{endpoints.first.last}", "--kubeconfig=#{sidecar_config}", "--timeout=60s")
        result = yield @name, (endpoints.first.first if select_node)
        wait_for_volume_deletion(*endpoints.map(&:first), driver_name: NFS_DRIVER)
        result
      ensure
        disconnect_driver
      end
    end

    private

    def check_nfs_clients(workers)
      workers.each do |worker, pid|
        next if system("nsenter", "--target=#{pid}", "--mount", "test", "-x", "/sbin/mount.nfs")

        raise self.class::D::Unsupported, "K3 network CSI needs mount.nfs on #{worker.fetch("name")}"
      end
    end

    def publish_nfs_objects(server, share)
      create("apiVersion" => "storage.k8s.io/v1", "kind" => "CSIDriver", "metadata" => {"name" => NFS_DRIVER},
             "spec" => {"attachRequired" => false, "fsGroupPolicy" => "File", "volumeLifecycleModes" => ["Persistent"]})
      create("apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => @name})
      kubectl!("create", "serviceaccount", @name, "-n", @name)
      publish_role("external-provisioner", pinned_manifest("external-provisioner/rbac.yaml"))
      create("apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass", "metadata" => {"name" => @name},
             "provisioner" => NFS_DRIVER, "volumeBindingMode" => "Immediate",
             "parameters" => {"server" => server, "share" => share}, "mountOptions" => ["vers=4.1"])
    end

    def start_nfs_worker(directory, worker, pid)
      config = worker_config(worker)
      node = config.fetch("node_name")
      workspace = Dir.mktmpdir("node-", directory)
      socket = File.join(workspace, "csi.sock")
      start("nfsplugin", "--endpoint=unix://#{socket}", "--nodeid=#{node}", "--working-mount-dir=#{workspace}",
            prefix: ["nsenter", "--target=#{pid}", "--mount"], log_prefix: "#{node}-")
      register_driver(config, socket: socket, driver_name: NFS_DRIVER, log_prefix: "#{node}-")
      [node, socket]
    end
  end
end
