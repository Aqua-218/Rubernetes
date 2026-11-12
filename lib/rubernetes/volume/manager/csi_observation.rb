# frozen_string_literal: true

# What recovery asks the CSI driver: ListVolumes and ListSnapshots, paginated
# under a bound, with every entry validated and sanitized before it is used to
# resolve an operation.
module Rubernetes
  module Volume
    class Manager
      module CSIObservation
        private

        def index_csi_entries(entries, id_key)
          Array(entries).each_with_object({}) do |entry, result|
            hash = Capability.hash_like?(entry) ? entry.to_h.transform_keys(&:to_s) : {}
            id = Types.key(hash, id_key, Types.key(hash, "id"))
            result[id.to_s] = hash if Types.present?(id)
          end
        end

        def csi_driver_id(record)
          result = Types.key(record.spec, "backendResult", {})
          Types.key(result, "volumeId", Types.key(result, "volume_id"))&.to_s
        end

        def csi_published_nodes(observed)
          return nil unless observed

          status = Types.key(observed, "status")
          return nil unless status

          Array(Types.key(status, "publishedNodeIds", Types.key(status, "published_node_ids"))).map(&:to_s)
        end

        def list_csi_snapshots
          entries = {}
          remote_records = volume_store.values.select { |record| record.backend.to_s.casecmp?("csi") }
          remote_records.each do |record|
            driver_id = csi_driver_id(record)
            next unless Types.present?(driver_id)

            kwargs = {
              source_volume_id: driver_id,
              secrets: resolve_csi_secrets(record.id, record.spec, purpose: :list_snapshots)
            }
            paginate_csi_observation(:list_snapshots, operation: "ListSnapshots", entry_keys: %w[entries snapshots],
                                                      id_key: "snapshotId", kwargs: kwargs).each do |entry|
              value = AdapterSupport.result_hash(entry)
              snapshot_id = Types.key(value, "snapshotId", Types.key(value, "snapshot_id"))
              source_volume_id = Types.key(value, "sourceVolumeId", Types.key(value, "source_volume_id"))
              unless source_volume_id.is_a?(String) && !source_volume_id.empty? && source_volume_id == driver_id.to_s
                raise CSIError,
                      "CSI ListSnapshots returned snapshot #{snapshot_id.inspect} for an unexpected source volume"
              end
              entries[snapshot_id.to_s] = sanitize_for_persistence(value) if Types.present?(snapshot_id)
            end
          end
          {"entries" => entries.values}
        end

        def list_csi_volumes
          entries = paginate_csi_observation(
            :list_volumes, operation: "ListVolumes", entry_keys: %w[entries volumes], id_key: "volumeId", kwargs: {}
          )
          {"entries" => entries}
        end

        def paginate_csi_observation(method_name, operation:, entry_keys:, id_key:, kwargs:)
          entries = []
          starting_token = nil
          seen_tokens = {}
          pages = 0
          loop do
            pages += 1
            raise CSIError, "CSI #{operation} pagination exceeded the recovery bound" if pages > CSI_RECOVERY_PAGE_LIMIT

            page = invoke_csi_with_supported_keywords(method_name, kwargs.merge(starting_token: starting_token))
            raise CSIError, "CSI #{operation} returned a malformed pagination page" unless page.is_a?(Array) || (!page.nil? && Capability.hash_like?(page))

            hash = page.is_a?(Array) ? {} : AdapterSupport.result_hash(page)
            page_entries = page.is_a?(Array) ? page : entry_keys.lazy.map { |key| hash[key] }.find(&:itself)
            entries.concat(csi_page_entry_list(page_entries, operation).map do |entry|
              normalize_csi_observation_entry(entry, id_key: id_key, operation: operation)
            end)
            next_token = hash["nextToken"] || hash["next_token"]
            break if next_token.nil? || next_token == ""
            raise CSIError, "CSI #{operation} returned a non-string pagination token" unless next_token.is_a?(String)

            token = next_token
            raise CSIError, "CSI #{operation} pagination repeated token" if seen_tokens.key?(token)

            seen_tokens[token] = true
            starting_token = token
          end
          entries
        end

        def csi_page_entry_list(page_entries, operation)
          if page_entries.nil?
            []
          elsif page_entries.is_a?(Array)
            page_entries
          elsif !page_entries.is_a?(Hash) && !page_entries.is_a?(String) && Capability.list_like?(page_entries)
            page_entries.to_a
          else
            raise CSIError, "CSI #{operation} returned malformed entries"
          end
        end

        def normalize_csi_observation_entry(entry, id_key:, operation:)
          raise CSIError, "CSI #{operation} returned a malformed entry" unless !entry.nil? && Capability.hash_like?(entry)

          hash = AdapterSupport.result_hash(entry)
          nested_key = id_key == "volumeId" ? "volume" : "snapshot"
          if hash.key?(nested_key)
            nested = hash[nested_key]
            raise CSIError, "CSI #{operation} returned a malformed #{nested_key} entry" unless !nested.nil? && Capability.hash_like?(nested)

            hash = AdapterSupport.result_hash(nested).merge(hash.reject { |key, _| key == nested_key })
          end
          underscored_id_key = id_key.gsub(/([A-Z])/, '_\\1').downcase
          id = Types.key(hash, id_key, Types.key(hash, underscored_id_key, Types.key(hash, "id")))
          raise CSIError, "CSI #{operation} returned an entry without #{id_key}" unless Types.present?(id)

          hash
        end

        def invoke_csi_with_supported_keywords(method_name, kwargs)
          method = @csi.method(method_name)
          parameters = method.parameters
          accepted = if parameters.any? { |kind, _| kind == :keyrest }
                       kwargs
                     else
                       kwargs.select do |key, _|
                         parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name.to_sym == key.to_sym }
                       end
                     end
          method.call(**accepted)
        end
      end
    end
  end
end
