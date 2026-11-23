# frozen_string_literal: true

require_relative "k3_csi_contract_index"

module Conformance
  module K3CSIRBDFixture
    MOUNT_OPTIONS = %w[debug nouid32].freeze

    def with_rbd_driver(mount_options: false)
      name = K3CSIContractIndex::RBD_DRIVER
      storage_class = ENV["RUBERNETES_K3_RBD_STORAGE_CLASS"].to_s
      driver = self.class::D.kubectl_object("get", "csidriver", name)
      class_object = self.class::D.kubectl_object("get", "storageclass", storage_class) unless storage_class.empty?
      unless driver&.dig("spec", "attachRequired") == true && class_object&.dig("provisioner") == name && class_object["reclaimPolicy"] == "Delete"
        raise self.class::D::Unsupported, "K3 RBD needs RUBERNETES_K3_RBD_STORAGE_CLASS to identify a dedicated attachable Rook Ceph StorageClass"
      end

      nodes = rbd_worker_registrations(name)
      ensure_empty_rbd_fixture!(name)
      File.write(File.join(@reports, "rbd-registrations.json"), JSON.generate(nodes))
      observer = watch_rbd_mount_options(nodes) if mount_options
      result = yield storage_class, nil
      wait_for_volume_deletion(*nodes.keys, driver_name: name)
      ensure_empty_rbd_fixture!(name)
      File.write(File.join(@reports, "rbd-mapping-cleanup.json"), JSON.generate("mappedDevices" => rbd_mapping_devices))
      record_rbd_mount_options(observer) if observer
      result
    ensure
      observer.first.kill.join if observer
    end

    private

    def rbd_worker_registrations(driver)
      nodes = local_workers.to_h do |worker, pid|
        node = worker_config(worker).fetch("node_name")
        registrations = read_api_object("csinode", node).dig("spec", "drivers")
        registration = Array(registrations).find { |entry| entry["name"] == driver }
        [node, {"nodeID" => registration&.fetch("nodeID"), "pid" => pid, "mountNamespace" => File.readlink("/proc/#{pid}/ns/mnt")}]
      end
      ids = nodes.values.map { |node| node["nodeID"] }
      namespaces = nodes.values.map { |node| node["mountNamespace"] }
      return nodes if nodes.size >= 2 && ids.all? { |id| id && !id.empty? } && ids.uniq == ids && namespaces.uniq == namespaces

      raise self.class::D::Unsupported, "K3 RBD needs multiple Ready workers with separate mount namespaces and distinct CSI node identities"
    end

    def watch_rbd_mount_options(nodes)
      witness = Queue.new
      thread = Thread.new do
        loop do
          observation = nodes.filter_map { |node, details| observed_rbd_options(node, details.fetch("pid")) }.first
          break witness << observation if observation

          sleep 0.2
        end
      end
      [thread, witness]
    end

    def observed_rbd_options(node, pid)
      File.foreach("/proc/#{pid}/mountinfo") do |line|
        fields, source = line.split(" - ", 2)
        fstype, device, options = source.to_s.split
        next unless fstype == "ext4" && device.start_with?("/dev/rbd") && fields.split.fetch(4).include?("/pods/")
        next unless (MOUNT_OPTIONS - options.split(",")).empty?

        return {"node" => node, "mountinfo" => line.strip}
      end
      nil
    end

    def record_rbd_mount_options(observer)
      _, witness = observer
      raise "RBD ext4 publication never reported the required kernel mount options" if witness.empty?

      File.write(File.join(@reports, "rbd-mount-options.json"), JSON.generate(witness.pop))
    end

    def rbd_mapping_devices
      path = "/sys/bus/rbd/devices"
      raise self.class::D::Unsupported, "K3 RBD needs the Linux RBD kernel driver" unless File.directory?(path)

      Dir.children(path).sort
    end

    def ensure_empty_rbd_fixture!(name)
      return if rbd_mapping_devices.empty? && driver_objects("pv", "csi", "driver", driver_name: name).empty? &&
                driver_objects("volumeattachments", "attacher", driver_name: name).empty?

      raise "K3 RBD fixture has outstanding mappings, PersistentVolumes or VolumeAttachments"
    end
  end
end
