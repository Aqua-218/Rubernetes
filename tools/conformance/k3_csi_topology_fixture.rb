# frozen_string_literal: true

module Conformance
  module K3CSITopologyFixture
    TOPOLOGY_KEY = "topology.hostpath.csi/node"

    def with_topology_driver
      workers = local_workers
      raise self.class::D::Unsupported, "K3 CSI topology needs two Ready local workers" if workers.length < 2

      tools_directory = File.join(Lock::ROOT, "build/conformance/bin/k3-csi")
      @tools = K3CSITools.install(tools_directory)
      Dir.mktmpdir("k3csi-topology-", "/tmp") do |directory|
        publish_api_objects(attach: false)
        config = service_account_kubeconfig(directory, @name)
        nodes = workers.map { |worker, pid| start_topology_worker(directory, worker, pid, config) }
        record_topologies(nodes)
        result = yield @name, nil
        wait_for_volume_deletion(*nodes)
        result
      ensure
        disconnect_driver
      end
    end

    private

    def start_topology_worker(directory, worker, pid, sidecar_config)
      config = worker_config(worker)
      node = config.fetch("node_name")
      workspace = Dir.mktmpdir("node-", directory)
      socket = File.join(workspace, "csi.sock")
      start_driver(workspace, config, pid, socket: socket, attach: false, log_prefix: "#{node}-")
      start("csi-provisioner", "--csi-address=#{socket}", "--kubeconfig=#{sidecar_config}", "--node-deployment=true",
            "--strict-topology=true", "--node-deployment-base-delay=1s", "--node-deployment-max-delay=5s",
            log_prefix: "#{node}-", environment: {"NODE_NAME" => node})
      node
    end

    def record_topologies(nodes)
      topologies = nodes.to_h do |node|
        resource = self.class::D.kubectl_object("get", "node", node)
        [node, resource.fetch("metadata").fetch("labels").fetch(TOPOLOGY_KEY)]
      end
      raise "CSI topology labels must identify distinct workers" unless topologies.values.uniq.length == nodes.length

      File.write(File.join(@reports, "node-topologies.json"), JSON.generate(topologies))
    end
  end
end
