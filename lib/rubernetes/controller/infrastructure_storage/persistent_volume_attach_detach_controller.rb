# frozen_string_literal: true

require_relative "attach_detach_volumes"

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
      CSI_DRIVER = ResourceDescriptor.parse("CSIDriver")
      VOLUME_ATTACHMENT = ResourceDescriptor.parse("VolumeAttachment")
      MANAGED_ANNOTATION = "volumes.kubernetes.io/controller-managed-attach-detach"
      MAX_WAIT_FOR_UNMOUNT = 6 * 60
      RECHECK_SECONDS = 1.0
      ATTACH_WRITE_GRACE_SECONDS = 10

      def initialize(*, clock: -> { Time.now.utc }, **)
        super(*, **)
        @clock = clock
        @detach_requested = {}
        @attach_writes = {}
        @reported = {}
        @mutex = Mutex.new
      end

      def plan(resource, store: nil, pods: nil, claims: nil, volume_attachments: nil, attachments: nil, nodes: nil, csi_drivers: nil,
               volumes: nil, **_options)
        adapter = adapter_for(store)
        pods ||= list_storage_objects(adapter, POD, namespace: :all)
        claims ||= list_storage_objects(adapter, PVC, namespace: :all)
        volume_attachments ||= attachments || list_storage_objects(adapter, VOLUME_ATTACHMENT, namespace: :all)
        nodes ||= list_storage_objects(adapter, NODE, namespace: :all)
        csi_drivers ||= list_storage_objects(adapter, CSI_DRIVER, namespace: :all)
        volumes ||= list_storage_objects(adapter, PV, namespace: :all)
        target_node = reconciliation_node(resource)
        volumes = Array(volumes) + [resource] if target_node.nil?
        sources = AttachDetachVolumes.new(volumes, claims)
        selected = sources.persistent(resource) if target_node.nil?
        desired, definitions = desired_pods_by_volume(pods, nodes, sources, csi_drivers)
        actual = volume_attachments.group_by { |attachment| sources.attachment_volume(attachment)&.identity }
        context = {operations: [], events: [], requeue: nil, detaching: []}
        if target_node
          identities = desired.keys.select { |identity| desired[identity].key?(target_node) }
          identities |= actual.keys.compact.select { |identity| actual[identity].any? { |attachment| attachment_node(attachment) == target_node } }
          identities.each do |identity|
            existing = actual.fetch(identity, [])
            volume = definitions.dig(identity, target_node) || sources.attachment_volume(existing.first)
            plan_volume(volume, existing, desired.fetch(identity, {}), nodes, context, target_node: target_node)
          end
        elsif selected&.identity && attach_required?(selected.csi, csi_drivers)
          plan_volume(selected, actual.fetch(selected.identity, []), desired.fetch(selected.identity, {}), nodes, context)
        end
        reported_nodes = target_node ? nodes.select { |node| Support.name(node) == target_node } : nodes
        report_attached_volumes(sources, volume_attachments, reported_nodes, csi_drivers, context)
        result_for(resource, context)
      end

      def orphan_cleanup? = true

      def plan_orphans(key, store: nil)
        return if key.to_s.include?("/")

        plan({"kind" => "Node", "metadata" => {"name" => key.to_s}}, store: store)
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
        sources = AttachDetachVolumes.new(volumes, claims)
        planner = allocate
        managed = planner.send(:managed_nodes, nodes).to_h { |node| [Support.name(node), true] }
        in_use = Hash.new(0)
        desired = {}
        Array(pods).each do |pod|
          node_name = Support.value(Support.spec(pod), "nodeName", "").to_s
          next if node_name.empty?

          Array(Support.value(Support.spec(pod), "volumes", [])).each do |entry|
            volume = sources.pod_volume(pod, entry)
            plugin = attachable_plugin(volume&.spec)
            next unless plugin

            in_use[[node_name, plugin]] += 1
            next unless managed[node_name] && !planner.send(:terminated?, pod)
            next if volume.csi.is_a?(Hash) && (!volume.source || !planner.send(:attach_required?, volume.csi, drivers))

            desired[[node_name, volume.identity || volume.spec]] = plugin
          end
        end
        totals = Hash.new(0)
        desired.each_value { |plugin| totals[[plugin, "desired_state_of_world"]] += 1 }
        actual = {}
        Array(attachments).each do |attachment|
          next unless Support.value(Support.status(attachment), "attached", false) == true

          volume = sources.attachment_volume(attachment)
          plugin = attachable_plugin(volume&.spec)
          next unless plugin

          actual[[planner.send(:attachment_node, attachment), volume.identity || volume.spec]] = plugin
        end
        actual.each_value { |plugin| totals[[plugin, "actual_state_of_world"]] += 1 }
        {in_use: in_use, totals: totals}
      end

      private

      def reconciliation_node(resource)
        case Support.kind(resource)
        when "Node" then Support.name(resource)
        when "VolumeAttachment" then attachment_node(resource)
        end
      end

      def plan_volume(volume, existing, desired, nodes, context, target_node: nil)
        detaching = target_node ? existing.select { |attachment| attachment_node(attachment) == target_node } : existing
        detach_unneeded(volume, detaching, desired, nodes, context)
        attach_desired(volume, existing, desired, context, target_node: target_node)
      end

      # Detach: attachments no scheduled Pod needs any more, once the node
      # reports the volume unmounted or maxWaitForUnmountDuration has passed.
      def detach_unneeded(volume, existing, desired, nodes, context)
        unique_name = volume.unique_name
        existing.each do |attachment|
          node_name = attachment_node(attachment)
          next if desired.key?(node_name) || deleting?(attachment)

          key = [volume.identity, node_name]
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
      def attach_desired(volume, existing, desired, context, target_node:)
        attached_nodes = existing.map { |attachment| attachment_node(attachment) }
        multi_attach = multi_attach_allowed?(volume)
        first_node = desired.keys.min
        desired.sort.each do |node_name, node_pods|
          next if target_node && target_node != node_name

          @mutex.synchronize { @detach_requested.delete([volume.identity, node_name]) }
          attachment = existing.find { |candidate| attachment_node(candidate) == node_name }
          if attachment
            report_attach_result(volume, attachment, node_pods, context) unless deleting?(attachment)
            next
          end

          others = attached_nodes - [node_name]
          if !others.empty? && !multi_attach
            report_multi_attach_error(volume, node_pods, desired.slice(*others).values.flatten, context)
            next
          end
          # Until a first attachment exists, separately queued nodes must
          # agree on which node may win an exclusive volume.
          next if !multi_attach && node_name != first_node

          operation = operation_create(volume_attachment(volume, node_name), descriptor: VOLUME_ATTACHMENT, reason: "AttachVolume.Attach")
          operation = track_exclusive_write(volume, operation) if target_node && !multi_attach
          context[:requeue] = RECHECK_SECONDS
          next unless operation

          context[:operations] << operation
          attached_nodes << node_name
        end
      end

      # Two nodes can plan from different snapshots while the first create is
      # still reaching the store. Reserve an exclusive write until it fails or
      # the shared informer has had time to observe it.
      def track_exclusive_write(volume, operation)
        identity = volume.identity
        written = @clock.call
        reserved = @mutex.synchronize do
          @attach_writes.delete_if { |_key, time| written - time >= ATTACH_WRITE_GRACE_SECONDS }
          next false if @attach_writes.key?(identity)

          @attach_writes[identity] = written
        end
        return unless reserved

        operation.observed do |succeeded, _error|
          @mutex.synchronize { @attach_writes.delete(identity) if !succeeded && @attach_writes[identity].equal?(written) }
        end
      end

      # nodeStatusUpdater: node.status.volumesAttached lists, per managed
      # node, every volume the controller has attached there (a CSI volume's
      # devicePath is empty; attacher.Attach returns none), and a volume
      # stops being reported the moment its detach starts so the kubelet
      # cannot begin a new mount of it.  The list is the whole node's, from
      # every VolumeAttachment, so any volume's sync repairs it; only a node
      # whose list changes is patched.
      def report_attached_volumes(sources, attachments, nodes, drivers, context)
        desired = Hash.new { |hash, key| hash[key] = [] }
        Array(attachments).each do |attachment|
          next if deleting?(attachment) || context[:detaching].include?(Support.name(attachment))
          next unless Support.value(Support.status(attachment), "attached", false) == true

          volume = sources.attachment_volume(attachment)
          next unless volume&.identity && attach_required?(volume.csi, drivers)

          desired[attachment_node(attachment)] << {"name" => volume.unique_name, "devicePath" => ""}
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

      def desired_pods_by_volume(pods, nodes, sources, drivers)
        managed = managed_nodes(nodes).to_set { |node| Support.name(node) }
        definitions = {}
        desired = {}
        Array(pods).each do |pod|
          node_name = Support.value(Support.spec(pod), "nodeName", "").to_s
          next if !managed.include?(node_name) || terminated?(pod)

          Array(Support.spec(pod)["volumes"]).each do |entry|
            volume = sources.pod_volume(pod, entry)
            next unless volume&.source && volume.identity && attach_required?(volume.csi, drivers)

            identity = volume.identity
            (definitions[identity] ||= {})[node_name] ||= volume
            consumers = ((desired[identity] ||= {})[node_name] ||= [])
            consumers << pod unless consumers.last.equal?(pod)
          end
        end
        [desired, definitions]
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
        modes = Array(volume.spec["accessModes"]).map(&:to_s)
        modes.empty? || modes.intersect?(%w[ReadWriteMany ReadOnlyMany])
      end

      def volume_in_use?(nodes, node_name, unique_name)
        node = Array(nodes).find { |item| Support.name(item) == node_name }
        node && Array(Support.value(Support.status(node), "volumesInUse", [])).map(&:to_s).include?(unique_name)
      end

      def attachment_node(attachment) = Support.value(Support.spec(attachment), "nodeName", "").to_s
      def deleting?(attachment) = !Support.value(Support.metadata(attachment), "deletionTimestamp", nil).nil?

      # getAttachmentName.
      def volume_attachment(volume, node_name)
        driver, handle = volume.identity
        {"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment",
         "metadata" => {"name" => "csi-#{Digest::SHA256.hexdigest("#{handle}#{driver}#{node_name}")}"},
         "spec" => {"attacher" => driver, "nodeName" => node_name, "source" => volume.source}}
      end

      # operation_generator: SuccessfulAttachVolume / FailedAttachVolume on
      # the Pods, once per attachment outcome.
      def report_attach_result(volume, attachment, pods, context)
        status = Support.status(attachment)
        outcome = if Support.value(status, "attached", false) == true
                    ["Normal", "SuccessfulAttachVolume", "AttachVolume.Attach succeeded for volume #{volume.name.dump} "]
                  elsif (error = Support.value(Support.value(status, "attachError", {}) || {}, "message", nil))
                    ["Warning", "FailedAttachVolume", "AttachVolume.Attach failed for volume #{volume.name.dump} : #{error}"]
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
        prefix = "Multi-Attach error for volume #{volume.name.dump}"
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
