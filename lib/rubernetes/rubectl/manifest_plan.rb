# frozen_string_literal: true

module Rubernetes
  module Rubectl
    # Compare server-side apply's preview to the version read from the cluster.
    # Report field paths so a plan can be shared without printing Secret values.
    module ManifestPlan
      module_function

      def for_resource(client, manifest, namespace:, field_manager:, force:)
        name = manifest.dig("metadata", "name")
        raise Client::UsageError, "plan manifest metadata.name is required" if name.to_s.empty?

        live = begin
          client.get(manifest, name, namespace: namespace)
        rescue Client::APIError => error
          raise unless error.status == 404

          nil
        end
        preview = client.apply(manifest, namespace: namespace, field_manager: field_manager, force: force, dry_run: true)
        metadata = preview.fetch("metadata")
        if live&.dig("metadata", "resourceVersion") != metadata["resourceVersion"] || (live && live.dig("metadata", "uid") != metadata["uid"])
          raise Client::Error, "#{manifest["kind"]}/#{name} changed while building the plan; run plan again"
        end

        result = preview.slice("apiVersion", "kind").merge("metadata" => metadata.slice("name", "namespace"))
        return result.merge("action" => "create") unless live

        paths = changed_paths(comparable(live), comparable(preview), "")
        result.merge("action" => paths.empty? ? "unchanged" : "update", "changedPaths" => paths)
      end

      def text(report)
        metadata = report.fetch("metadata")
        resource = [report.fetch("kind"), metadata["namespace"], metadata.fetch("name")].compact.join("/")
        title = "#{report.fetch("action").upcase} #{resource}"
        paths = Array(report["changedPaths"]).map do |path|
          "  #{path.gsub(/[[:cntrl:]]/) { |character| character.dump[1...-1] }}"
        end
        ([title] + paths).join("\n")
      end

      def comparable(object)
        metadata = object.fetch("metadata").except("generation")
        if (fields = metadata["managedFields"])
          metadata["managedFields"] = fields.map { |entry| entry.except("time") }
        end
        object.merge("metadata" => metadata)
      end

      # JSON Pointer escapes keep a label or annotation containing '/' or '~'
      # distinct from a nested field. An array changing length is one change.
      def changed_paths(before, after, pointer)
        return [] if before == after
        return [pointer] if pointer == "/metadata/managedFields"

        if before.is_a?(Hash) && after.is_a?(Hash)
          (before.keys | after.keys).sort.flat_map do |key|
            child = "#{pointer}/#{key.gsub("~", "~0").gsub("/", "~1")}"
            before.key?(key) && after.key?(key) ? changed_paths(before[key], after[key], child) : [child]
          end
        elsif before.is_a?(Array) && after.is_a?(Array) && before.size == after.size
          before.each_index.flat_map { |index| changed_paths(before[index], after[index], "#{pointer}/#{index}") }
        else
          [pointer]
        end
      end
    end
  end
end
