# frozen_string_literal: true

module Rubernetes
  module Node
    class PodVolumes
      private

      def volume_provision_spec(spec, pod, name, projection:, uid:, token:)
        result = spec.merge("podUid" => uid, "attempt" => token)
        return result unless projection

        directories = nested_volume_mountpoints(pod, name)
        result["nestedMountpoints"] = directories unless directories.empty?
        result
      end

      # The volume plugins create these directories before exposing the
      # projection read-only. A child belongs only to its closest mount.
      def nested_volume_mountpoints(pod, name)
        spec = pod.fetch("spec", {})
        %w[initContainers containers ephemeralContainers].flat_map do |group|
          Array(spec[group]).flat_map { |container| container_mountpoints(container, name) }
        end.uniq
      end

      def container_mountpoints(container, name)
        mounts = Array(container["volumeMounts"]).filter_map do |mount|
          path = mount["mountPath"].to_s
          next unless path.start_with?("/") && !path.include?("\0")

          [File.expand_path(path), mount["name"]]
        end.to_h
        mounts.each_key.filter_map do |path|
          parent = mounts.each_key.select { |candidate| path.start_with?(mountpoint_prefix(candidate)) && path != candidate }.max_by(&:length)
          path.delete_prefix(mountpoint_prefix(parent)) if parent && mounts.fetch(parent) == name
        end
      end

      def mountpoint_prefix(path)
        path == "/" ? path : "#{path}/"
      end
    end
  end
end
