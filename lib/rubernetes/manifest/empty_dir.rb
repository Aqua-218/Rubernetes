# frozen_string_literal: true

require_relative "../schema/quantity"

module Rubernetes
  module Manifest
    module Workload
      # A Ruby reference stays local to one Pod template. On the wire a mount
      # contains only the volume's Kubernetes name.
      EmptyDirReference = Data.define(:name, :workload)

      module EmptyDirDeclarations
        def empty_dir(name, medium: :disk, size_limit: nil)
          name = String(name).dup.freeze
          raise Error, "invalid emptyDir name #{name.inspect}" unless Rubernetes::Schema::KubernetesValidator.dns1123_label_messages(name).empty?

          fields = case medium
                   when :disk, "" then {}
                   when :memory, "Memory" then {"medium" => "Memory"}
                   else raise Error, "empty_dir medium must be :disk or :memory"
                   end
          unless size_limit.nil?
            quantity = Rubernetes::Schema::Quantity.from_json(size_limit)
            raise Error, "empty_dir size_limit must be non-negative" if quantity.negative?

            fields["sizeLimit"] = quantity.to_s
          end
          volume(name, empty_dir: fields)
          declared_at = caller(1, 1)
          at_finish do
            entries = Array(pod_spec["volumes"]).select { |entry| entry && entry["name"] == name }
            templates = Array(@workload.dig("spec", "volumeClaimTemplates"))
            if entries.length != 1 || entries.first["emptyDir"] != fields || templates.any? { |claim| claim && claim.dig("metadata", "name") == name }
              raise Error, "emptyDir #{name.inspect} conflicts with another volume declaration", declared_at
            end
          end
          EmptyDirReference.new(name, @workload)
        rescue Rubernetes::Schema::Quantity::ParseError => error
          raise Error, "invalid empty_dir size_limit #{size_limit.inspect}: #{error.message}"
        end
      end
    end
  end
end
