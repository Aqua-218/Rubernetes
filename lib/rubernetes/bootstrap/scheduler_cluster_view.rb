# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    module SchedulerClusterView
      # Changes that can make an unschedulable Pod schedulable.
      REQUEUE_KINDS = %w[Namespace PersistentVolume PersistentVolumeClaim StorageClass
                         ResourceClaim ResourceSlice DeviceClass CSINode CSIDriver VolumeAttachment
                         CSIStorageCapacity PodGroup PodDisruptionBudget].freeze

      private

      def cluster_key(object)
        metadata = Controller::Support.value(object, "metadata", {}) || {}
        [Controller::Support.value(metadata, "namespace", "").to_s, Controller::Support.value(metadata, "name", "").to_s].join("/")
      end

      def observe_cluster_object(kind, object, deleted: false)
        added = false
        previous_object = nil
        changed = @mutex.synchronize do
          key = cluster_key(object)
          previous = @cluster_objects[kind][key]
          previous_object = previous
          added = previous.nil? && !deleted
          if deleted
            @cluster_objects[kind].delete(key)
          else
            @cluster_objects[kind][key] = object
          end
          (deleted || previous != object).tap { |value| @cluster_generation += 1 if value }
        end
        return unless changed

        event = "#{kind}#{if deleted
                            "Delete"
                          else
                            (added ? "Add" : "Update")
                          end}"
        timed_event(event) do
          if REQUEUE_KINDS.include?(kind)
            retry_unschedulable("#{kind.downcase}_changed", event: event, old_object: deleted ? object : previous_object,
                                                            new_object: deleted ? nil : object)
          end
        end
      end

      # The plugin inputs for one cycle, rebuilt only after an informer event.
      EMPTY_CLUSTER_VIEW = {namespace_labels: nil, volume_data: nil, workload_selectors: nil, pod_groups: nil}.freeze

      def cluster_view
        return EMPTY_CLUSTER_VIEW if @cluster_objects.nil? || @cluster_informers.nil?

        @mutex.synchronize do
          return @cluster_view if @cluster_view && @cluster_view[:generation] == @cluster_generation

          objects = @cluster_objects
          value = ->(object, *path) { path.reduce(object) { |current, key| Controller::Support.value(current, key, nil) } }
          namespaces = objects["Namespace"].values.to_h do |namespace|
            [value.call(namespace, "metadata", "name").to_s, value.call(namespace, "metadata", "labels") || {}]
          end
          controllers = {}
          {"ReplicationController" => %w[spec selector], "ReplicaSet" => %w[spec selector],
           "StatefulSet" => %w[spec selector]}.each do |kind, path|
            objects[kind].each_value do |controller|
              key = "#{kind}/#{value.call(controller, "metadata", "namespace")}/#{value.call(controller, "metadata", "name")}"
              controllers[key] = value.call(controller, *path)
            end
          end
          services = objects["Service"].values.filter_map do |service|
            selector = value.call(service, "spec", "selector")
            {"namespace" => value.call(service, "metadata", "namespace").to_s, "selector" => selector} if selector.is_a?(Hash)
          end
          track = !@cluster_informers.empty?
          @cluster_view = {
            generation: @cluster_generation,
            namespace_labels: track && @cluster_informers.key?("Namespace") ? namespaces : nil,
            volume_data: if track
                           {"persistentVolumes" => objects["PersistentVolume"].values,
                            "persistentVolumeClaims" => objects["PersistentVolumeClaim"].values,
                            "storageClasses" => objects["StorageClass"].values,
                            "resourceClaims" => objects["ResourceClaim"].values,
                            "resourceSlices" => objects["ResourceSlice"].values,
                            "deviceClasses" => objects["DeviceClass"].values,
                            "csiNodes" => objects["CSINode"].values,
                            "csiDrivers" => objects["CSIDriver"].values,
                            "volumeAttachments" => objects["VolumeAttachment"].values,
                            "csiStorageCapacities" => objects["CSIStorageCapacity"].values}
                         end,
            workload_selectors: if track
                                  {"services" => services, "controllers" => controllers,
                                   "podDisruptionBudgets" => objects["PodDisruptionBudget"].values}
                                end,
            pod_groups: track && @cluster_informers.key?("PodGroup") ? objects["PodGroup"].dup : nil
          }
        end
      end
    end
  end
end
