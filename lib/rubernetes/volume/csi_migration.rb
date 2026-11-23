# frozen_string_literal: true

require "uri"
require_relative "csi_migration/topology"

module Rubernetes
  module Volume
    # The node and attach/detach controller translate legacy sources in memory.
    # Drivers see the same disk identity whether it occurs in a Pod or in a PV.
    module CSIMigration
      class Invalid < ArgumentError; end

      DRIVERS = {
        "awsElasticBlockStore" => "ebs.csi.aws.com",
        "gcePersistentDisk" => "pd.csi.storage.gke.io",
        "azureDisk" => "disk.csi.azure.com",
        "azureFile" => "file.csi.azure.com",
        "cinder" => "cinder.csi.openstack.org",
        "portworxVolume" => "pxd.portworx.com",
        "vsphereVolume" => "csi.vsphere.vmware.com"
      }.freeze

      module_function

      def persistent_spec(pv)
        spec = pv.fetch("spec", {})
        kind = DRIVERS.each_key.find { |key| spec[key].is_a?(Hash) }
        return spec unless kind

        csi = translate(kind, spec.fetch(kind), metadata: pv.fetch("metadata", {}), claim: spec["claimRef"])
        result = spec.except(kind).merge("csi" => csi)
        if kind == "gcePersistentDisk" && (modes = spec["accessModes"])
          writable = modes.intersect?(%w[ReadWriteOnce ReadWriteMany])
          result["accessModes"] = [!writable && modes.include?("ReadOnlyMany") ? "ReadOnlyMany" : "ReadWriteOnce"]
        end
        Topology.translate(result, kind, pv.dig("metadata", "labels") || {})
      end

      def inline_spec(entry, namespace:)
        kind = DRIVERS.each_key.find { |key| entry[key].is_a?(Hash) }
        return unless kind

        source = entry.fetch(kind)
        csi = translate(kind, source, metadata: entry.slice("name"), namespace: namespace)
        mode = if kind == "azureFile"
                 "ReadWriteMany"
               elsif %w[gcePersistentDisk portworxVolume].include?(kind) && source["readOnly"]
                 "ReadOnlyMany"
               else
                 "ReadWriteOnce"
               end
        {"accessModes" => [mode], "volumeMode" => "Filesystem", "csi" => csi}
      end

      def translate(kind, source, metadata:, namespace: nil, claim: nil)
        csi = {"driver" => DRIVERS.fetch(kind)}
        csi["readOnly"] = true if source["readOnly"] && kind != "portworxVolume"
        csi["fsType"] = source["fsType"] unless source["fsType"].to_s.empty?
        attrs = {}
        handle = case kind
                 when "awsElasticBlockStore"
                   attrs["partition"] = source.fetch("partition", 0).to_s
                   ebs_handle(source.fetch("volumeID"))
                 when "gcePersistentDisk"
                   partition = source.fetch("partition", 0)
                   attrs["partition"] = partition.zero? ? "" : partition.to_s
                   gce_handle(source.fetch("pdName"), metadata.fetch("labels", {}))
                 when "azureDisk"
                   azure_disk(source, attrs, inline: !namespace.nil?)
                 when "azureFile"
                   azure_file(source, metadata, claim, namespace, csi, attrs)
                 when "vsphereVolume"
                   attrs["storagepolicyname"] = source["storagePolicyName"] unless source["storagePolicyName"].to_s.empty?
                   source.fetch("volumePath")
                 when "portworxVolume"
                   portworx_secrets(csi, metadata.fetch("annotations", {}))
                   source.fetch("volumeID")
                 when "cinder"
                   source.fetch("volumeID")
                 end
        raise Invalid, "#{kind} has no volume handle" if handle.to_s.empty?

        csi["volumeAttributes"] = attrs unless attrs.empty?
        csi.merge("volumeHandle" => handle)
      rescue KeyError => error
        raise Invalid, "#{kind} requires #{error.key}"
      end
      private_class_method :translate

      def ebs_handle(id)
        return id unless id.start_with?("aws://")

        path = URI::DEFAULT_PARSER.unescape(URI.parse(id).path.to_s).gsub(%r{\A/+|/+\z}, "")
        return path if path.match?(%r{\Avol-[^/]*\z})

        raise Invalid, "invalid AWS volume ID #{id.inspect}"
      rescue URI::InvalidURIError => error
        raise Invalid, error.message
      end
      private_class_method :ebs_handle

      def gce_handle(disk, labels)
        zone = labels["failure-domain.beta.kubernetes.io/zone"]
        zone = labels["topology.kubernetes.io/zone"] if zone.to_s.empty?
        zones = zone.to_s.split("__", -1)
        location = if zones.length > 1
                     regions = zones.map do |item|
                       parts = item.split("-", -1)
                       raise Invalid, "invalid GCE zone #{item.inspect}" unless parts.length == 3

                       parts.first(2).join("-")
                     end.uniq
                     raise Invalid, "GCE disk zones belong to different regions" unless regions.one?

                     "regions/#{regions.first}"
                   else
                     "zones/#{zone.to_s.empty? ? "UNSPECIFIED" : zone}"
                   end
        "projects/UNSPECIFIED/#{location}/disks/#{disk}"
      end
      private_class_method :gce_handle

      def azure_disk(source, attrs, inline:)
        kind = source["kind"]
        raise Invalid, "Azure Disk migration requires a managed disk" if kind && !kind.casecmp?("Managed")

        attrs["kind"] = "Managed"
        attrs["fstype"] = source["fsType"] if source.key?("fsType")
        cache = source["cachingMode"]
        attrs["cachingmode"] = cache if cache && (!inline || !cache.empty?)
        source.fetch("diskURI")
      end
      private_class_method :azure_disk

      def azure_file(source, metadata, claim, pod_namespace, csi, attrs)
        secret = source.fetch("secretName")
        account = secret[/azure-storage-account-(.+)-secret/, 1] || secret
        namespace = if pod_namespace.nil?
                      source.fetch("secretNamespace") { claim&.fetch("namespace", nil) }
                    else
                      pod_namespace.empty? ? "default" : pod_namespace
                    end
        raise Invalid, "Azure File needs a secret namespace in the volume or claim reference" if namespace.to_s.empty?

        share = source.fetch("shareName")
        attrs["sharename"] = share
        csi["nodeStageSecretRef"] = {"name" => secret, "namespace" => namespace}
        [metadata.dig("annotations", "kubernetes.io/azure-file-resource-group"), account, share, metadata["name"], namespace].join("#")
      end
      private_class_method :azure_file

      def portworx_secrets(csi, annotations)
        name = annotations["openstorage.io/auth-secret-name"]
        namespace = annotations["openstorage.io/auth-secret-namespace"]
        return unless name && namespace

        %w[controllerPublish nodePublish nodeStage controllerExpand nodeExpand].each do |purpose|
          csi["#{purpose}SecretRef"] = {"name" => name, "namespace" => namespace}
        end
      end
      private_class_method :portworx_secrets
    end
  end
end
