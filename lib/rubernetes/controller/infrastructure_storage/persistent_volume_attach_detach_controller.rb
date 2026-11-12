# frozen_string_literal: true

module Rubernetes
  module Controller
    # pkg/controller/volume/attachdetach (v1.36.2) for CSI volumes: the
    # desired state is every attachable volume of every scheduled,
    # not-terminated Pod on a node whose kubelet leaves attach/detach to the
    # controller (volumes.kubernetes.io/controller-managed-attach-detach);
    # the actual state is the VolumeAttachments.  The reconciler detaches
    # what is no longer desired once the node reports it unmounted (or
    # maxWaitForUnmountDuration has passed), and attaches what is desired
    # through a VolumeAttachment named csi-<sha256(handle+driver+node)> --
    # refusing a second node for a volume that cannot be multi-attached
    # (Multi-Attach error).
    class PersistentVolumeAttachDetachController < BaseController
      include InfrastructureStorageSupport

      PV = ResourceDescriptor.parse("PersistentVolume")
      PVC = ResourceDescriptor.parse("PersistentVolumeClaim")
      POD = ResourceDescriptor.parse("Pod")
      NODE = ResourceDescriptor.parse("Node")
      CSI_DRIVER = ResourceDescriptor.parse({"apiVersion" => "storage.k8s.io/v1", "kind" => "CSIDriver"},
                                            resource: "csidrivers", scope: :cluster)
      VOLUME_ATTACHMENT = ResourceDescriptor.parse({"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment"},
                                                   resource: "volumeattachments", scope: :cluster)
      MANAGED_ANNOTATION = "volumes.kubernetes.io/controller-managed-attach-detach"
      CSI_PLUGIN = "kubernetes.io/csi"
      MAX_WAIT_FOR_UNMOUNT = 6 * 60
      RECHECK_SECONDS = 1.0

      def initialize(*, clock: -> { Time.now.utc }, **)
        super(*, **)
        @clock = clock
        @detach_requested = {}
        @reported = {}
        @mutex = Mutex.new
      end

      def plan(volume, store: nil, pods: nil, claims: nil, volume_attachments: nil, attachments: nil, nodes: nil, csi_drivers: nil,
               volumes: nil, **_options)
        adapter = adapter_for_storage(store)
        pods ||= list_storage_objects(adapter, POD, namespace: :all)
        claims ||= list_storage_objects(adapter, PVC, namespace: :all)
        volume_attachments ||= attachments || list_storage_objects(adapter, VOLUME_ATTACHMENT, namespace: :all)
        nodes ||= list_storage_objects(adapter, NODE, namespace: :all)
        csi_drivers ||= list_storage_objects(adapter, CSI_DRIVER, namespace: :all)
        context = {operations: [], events: [], requeue: nil, detaching: []}
        csi = Support.value(Support.spec(volume), "csi", nil)
        if csi.is_a?(Hash) && attach_required?(csi, csi_drivers)
          desired = desired_pods_by_node(volume, pods, claims, nodes)
          existing = Array(volume_attachments).select { |attachment| attachment_for_volume?(attachment, volume) }
          detach_unneeded(volume, csi, existing, desired, nodes, context)
          attach_desired(volume, csi, existing, desired, context)
        end
        report_attached_volumes(volume, adapter, volumes, volume_attachments, nodes, csi_drivers, context)
        result_for(volume, context)
      end

      # The A/D controller's plugins that can serve a volume (fc, iscsi and
      # csi -- ProbeAttachableVolumePlugins), by
      # GetFullQualifiedPluginNameForVolume; nil for any other volume.
      def self.attachable_plugin(source)
        return nil unless source.is_a?(Hash)
        return "kubernetes.io/csi:#{source.dig("csi", "driver")}" if source["csi"].is_a?(Hash)
        return "kubernetes.io/fc" if source["fc"].is_a?(Hash)
        return "kubernetes.io/iscsi" if source["iscsi"].is_a?(Hash)

        nil
      end

      # attachDetachStateCollector: volumes in use by the scheduled Pods of
      # each node, by plugin (storage_count_attachable_volumes_in_use), and
      # the volumes of the desired (every attachable volume a managed node's
      # running Pods need) and actual (attached VolumeAttachments) state of
      # the world by plugin (attachdetach_controller_total_volumes).
      def self.state_counts(pods:, claims:, volumes:, nodes:, attachments:, drivers:)
        pv_by_name = Array(volumes).to_h { |pv| [Support.name(pv), pv] }
        claim_by_key = Array(claims).to_h { |claim| [[Support.namespace(claim).to_s, Support.name(claim).to_s], claim] }
        planner = allocate
        managed = planner.send(:managed_nodes, nodes).to_h { |node| [Support.name(node), true] }
        in_use = Hash.new(0)
        desired = {}
        Array(pods).each do |pod|
          node_name = Support.value(Support.spec(pod), "nodeName", "").to_s
          next if node_name.empty?

          Array(Support.value(Support.spec(pod), "volumes", [])).each do |entry|
            source = volume_source(pod, entry, claim_by_key, pv_by_name)
            plugin = attachable_plugin(source)
            next unless plugin

            in_use[[node_name, plugin]] += 1
            next unless managed[node_name] && !planner.send(:terminated?, pod)
            next if source["csi"].is_a?(Hash) && !planner.send(:attach_required?, source["csi"], drivers)

            desired[[node_name, source]] = plugin
          end
        end
        totals = Hash.new(0)
        desired.each_value { |plugin| totals[[plugin, "desired_state_of_world"]] += 1 }
        Array(attachments).each do |attachment|
          next unless Support.value(Support.status(attachment), "attached", false) == true

          pv = pv_by_name[Support.value(Support.value(Support.spec(attachment), "source", {}) || {}, "persistentVolumeName", nil).to_s]
          plugin = attachable_plugin(pv && Support.spec(pv))
          totals[[plugin, "actual_state_of_world"]] += 1 if plugin
        end
        {in_use: in_use, totals: totals}
      end

      # CreateVolumeSpec: a claim (or a generic ephemeral volume's claim)
      # resolves to its bound PersistentVolume's spec, anything else is the
      # Pod's own volume source.
      def self.volume_source(pod, entry, claim_by_key, pv_by_name)
        claim_name = Support.value(Support.value(entry, "persistentVolumeClaim", {}) || {}, "claimName", nil)
        claim_name ||= "#{Support.name(pod)}-#{Support.value(entry, "name", "")}" if Support.value(entry, "ephemeral", nil).is_a?(Hash)
        return entry unless claim_name

        claim = claim_by_key[[Support.namespace(pod).to_s, claim_name.to_s]]
        pv = claim && pv_by_name[Support.value(Support.spec(claim), "volumeName", "").to_s]
        pv && Support.spec(pv)
      end

      private

      # Detach: attachments no scheduled Pod needs any more, once the node
      # reports the volume unmounted or maxWaitForUnmountDuration has passed.
      def detach_unneeded(volume, csi, existing, desired, nodes, context)
        unique_name = "#{CSI_PLUGIN}/#{csi["driver"]}^#{csi["volumeHandle"]}"
        existing.each do |attachment|
          node_name = attachment_node(attachment)
          next if desired.key?(node_name) || deleting?(attachment)

          key = [Support.name(volume), node_name]
          if volume_in_use?(nodes, node_name, unique_name)
            first = @mutex.synchronize { @detach_requested[key] ||= @clock.call }
            if @clock.call - first < MAX_WAIT_FOR_UNMOUNT
              context[:requeue] = RECHECK_SECONDS
              next
            end
          end
          @mutex.synchronize { @detach_requested.delete(key) }
          context[:detaching] << Support.name(attachment)
          detach = operation_delete(attachment, descriptor: VOLUME_ATTACHMENT, reason: "DetachVolume.Detach")
          # Still mounted after maxWaitForUnmountDuration: a forced detach.
          if detach && volume_in_use?(nodes, node_name, unique_name)
            detach = detach.observed do |succeeded, _|
              if succeeded
                ControllerMetrics.increment("attach_detach_controller_attachdetach_controller_forced_detaches",
                                            {"reason" => "timeout"})
              end
            end
          end
          context[:operations] << detach if detach
        end
      end

      # Attach: desired nodes without an attachment get a VolumeAttachment,
      # unless the volume is attached elsewhere and cannot be multi-attached.
      def attach_desired(volume, csi, existing, desired, context)
        attached_nodes = existing.reject { |attachment| deleting?(attachment) }.map { |attachment| attachment_node(attachment) }
        desired.sort.each do |node_name, node_pods|
          @mutex.synchronize { @detach_requested.delete([Support.name(volume), node_name]) }
          attachment = existing.find { |candidate| attachment_node(candidate) == node_name && !deleting?(candidate) }
          if attachment
            report_attach_result(volume, attachment, node_pods, context)
            next
          end

          others = attached_nodes - [node_name]
          if !others.empty? && !multi_attach_allowed?(volume)
            report_multi_attach_error(volume, node_pods, desired.slice(*others).values.flatten, context)
            next
          end

          context[:operations] << operation_create(volume_attachment(volume, csi["driver"].to_s, csi["volumeHandle"].to_s, node_name),
                                                   descriptor: VOLUME_ATTACHMENT, reason: "AttachVolume.Attach")
          attached_nodes << node_name
          context[:requeue] = RECHECK_SECONDS
        end
      end

      # nodeStatusUpdater: node.status.volumesAttached lists, per managed
      # node, every volume the controller has attached there (a CSI volume's
      # devicePath is empty; attacher.Attach returns none), and a volume
      # stops being reported the moment its detach starts so the kubelet
      # cannot begin a new mount of it.  The list is the whole node's, from
      # every VolumeAttachment, so any volume's sync repairs it; only a node
      # whose list changes is patched.
      def report_attached_volumes(volume, adapter, volumes, attachments, nodes, drivers, context)
        volumes ||= list_storage_objects(adapter, PV, namespace: :all)
        by_name = Array(volumes).to_h { |pv| [Support.name(pv), pv] }
        by_name[Support.name(volume)] = volume
        desired = Hash.new { |hash, key| hash[key] = [] }
        Array(attachments).each do |attachment|
          next if deleting?(attachment) || context[:detaching].include?(Support.name(attachment))
          next unless Support.value(Support.status(attachment), "attached", false) == true

          pv = by_name[Support.value(Support.value(Support.spec(attachment), "source", {}) || {}, "persistentVolumeName", nil).to_s]
          csi = pv && Support.value(Support.spec(pv), "csi", nil)
          next unless csi.is_a?(Hash) && attach_required?(csi, drivers)

          desired[attachment_node(attachment)] << {"name" => "#{CSI_PLUGIN}/#{csi["driver"]}^#{csi["volumeHandle"]}", "devicePath" => ""}
        end
        managed_nodes(nodes).each do |node|
          wanted = desired.fetch(Support.name(node), []).uniq { |entry| entry["name"] }.sort_by { |entry| entry["name"] }
          current = Array(Support.value(Support.status(node), "volumesAttached", [])).map do |entry|
            {"name" => Support.value(entry, "name", "").to_s, "devicePath" => Support.value(entry, "devicePath", "").to_s}
          end.sort_by { |entry| entry["name"] }
          next if current == wanted

          context[:operations] << operation_status_merge(node, {"volumesAttached" => wanted.empty? ? nil : wanted}, descriptor: NODE,
                                                                                                                    reason: "node volumesAttached")
        end
      end

      def result_for(volume, context)
        ReconcileResult.new(operations: context[:operations], events: context[:events], controller: name, key: Support.name(volume),
                            requeue_after: context[:requeue])
      end

      # csi plugin CanAttach: attachRequired defaults to true, also when the
      # CSIDriver object does not exist.
      def attach_required?(csi, drivers)
        driver = Array(drivers).find { |item| Support.name(item) == csi["driver"].to_s }
        return true if driver.nil?

        Support.value(Support.spec(driver), "attachRequired", true) != false
      end

      # desiredStateOfWorldPopulator: node => Pods using the volume.
      def desired_pods_by_node(volume, pods, claims, nodes)
        managed = managed_nodes(nodes).map { |node| Support.name(node) }
        claim_keys = Array(claims).select { |claim| Support.value(Support.spec(claim), "volumeName", "").to_s == Support.name(volume) }
          .map { |claim| [Support.namespace(claim).to_s, Support.name(claim).to_s] }
        result = Hash.new { |hash, key| hash[key] = [] }
        Array(pods).each do |pod|
          node_name = Support.value(Support.spec(pod), "nodeName", "").to_s
          next if node_name.empty? || !managed.include?(node_name) || terminated?(pod)

          uses = Array(Support.value(Support.spec(pod), "volumes", [])).any? do |entry|
            claim_name = Support.value(Support.value(entry, "persistentVolumeClaim", {}) || {}, "claimName", nil)
            claim_name && claim_keys.include?([Support.namespace(pod).to_s, claim_name.to_s])
          end
          result[node_name] << pod if uses
        end
        result.to_h
      end

      # Nodes whose kubelet leaves attach/detach to this controller.
      def managed_nodes(nodes)
        Array(nodes).select do |node|
          (Support.value(Support.metadata(node), "annotations", {}) || {})[MANAGED_ANNOTATION] == "true"
        end
      end

      # util.IsPodTerminated.
      def terminated?(pod)
        phase = Support.value(Support.status(pod), "phase", "").to_s
        return true if %w[Succeeded Failed].include?(phase)
        return false if Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?

        Array(Support.value(Support.status(pod), "containerStatuses", [])).none? do |status|
          (Support.value(status, "state", {}) || {}).key?("running")
        end
      end

      # util.IsMultiAttachAllowed: an RWX/ROX volume, or one with no modes.
      def multi_attach_allowed?(volume)
        modes = Array(Support.value(Support.spec(volume), "accessModes", [])).map(&:to_s)
        modes.empty? || modes.intersect?(%w[ReadWriteMany ReadOnlyMany])
      end

      def volume_in_use?(nodes, node_name, unique_name)
        node = Array(nodes).find { |item| Support.name(item) == node_name }
        node && Array(Support.value(Support.status(node), "volumesInUse", [])).map(&:to_s).include?(unique_name)
      end

      def attachment_for_volume?(attachment, volume)
        source = Support.value(Support.spec(attachment), "source", {}) || {}
        Support.value(source, "persistentVolumeName", nil).to_s == Support.name(volume)
      end

      def attachment_node(attachment) = Support.value(Support.spec(attachment), "nodeName", "").to_s
      def deleting?(attachment) = !Support.value(Support.metadata(attachment), "deletionTimestamp", nil).nil?

      # getAttachmentName.
      def volume_attachment(volume, driver, handle, node_name)
        {"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment",
         "metadata" => {"name" => "csi-#{Digest::SHA256.hexdigest("#{handle}#{driver}#{node_name}")}"},
         "spec" => {"attacher" => driver, "nodeName" => node_name, "source" => {"persistentVolumeName" => Support.name(volume)}}}
      end

      # operation_generator: SuccessfulAttachVolume / FailedAttachVolume on
      # the Pods, once per attachment outcome.
      def report_attach_result(volume, attachment, pods, context)
        status = Support.status(attachment)
        outcome = if Support.value(status, "attached", false) == true
                    ["Normal", "SuccessfulAttachVolume", "AttachVolume.Attach succeeded for volume #{Support.name(volume).dump} "]
                  elsif (error = Support.value(Support.value(status, "attachError", {}) || {}, "message", nil))
                    ["Warning", "FailedAttachVolume", "AttachVolume.Attach failed for volume #{Support.name(volume).dump} : #{error}"]
                  end
        unless outcome
          context[:requeue] = RECHECK_SECONDS
          return
        end

        # One event per attachment outcome, not one per sync.
        key = Support.name(attachment)
        already = @mutex.synchronize do
          seen = @reported[key] == outcome[1]
          @reported[key] = outcome[1]
          @reported.shift while @reported.length > 4096
          seen
        end
        return if already

        pods.each { |pod| context[:events] << pod_event(pod, *outcome) }
      end

      def report_multi_attach_error(volume, pods, blocking, context)
        prefix = "Multi-Attach error for volume #{Support.name(volume).dump}"
        if blocking.empty?
          pods.each do |pod|
            context[:events] << pod_event(pod, "Warning", "FailedAttachVolume",
                                          "#{prefix} Volume is already exclusively attached to one node and can't be attached to another")
          end
          return
        end

        pods.each do |pod|
          local = blocking.select { |other| Support.namespace(other) == Support.namespace(pod) }.map { |other| Support.name(other) }
          elsewhere = blocking.length - local.length
          message = if local.empty?
                      "Volume is already used by #{elsewhere} pod(s) in different namespaces"
                    else
                      text = "Volume is already used by pod(s) #{local.join(", ")}"
                      elsewhere.positive? ? "#{text} and #{elsewhere} pod(s) in different namespaces" : text
                    end
          context[:events] << pod_event(pod, "Warning", "FailedAttachVolume", "#{prefix} #{message}")
        end
      end

      def pod_event(pod, type, reason, message)
        {"type" => type, "reason" => reason, "message" => message,
         "involvedObject" => {"apiVersion" => "v1", "kind" => "Pod", "namespace" => Support.namespace(pod), "name" => Support.name(pod),
                              "uid" => Support.uid(pod)}.compact}
      end
    end
  end
end
