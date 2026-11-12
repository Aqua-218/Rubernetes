# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # The resource inventory recovery compares the ledger against: what the
      # adapters actually hold (never what the ledger says they hold), in one
      # canonical shape -- kind, id, identity, owner, metadata.
      module Inventory
        # Adapters may expose stable identity fields at the top level
        # (pid/start time, namespace links, mount ID, cgroup inode). Carry
        # them into the canonical metadata map so restart adoption sees the
        # same proof material as the durable ledger claim.
        IDENTITY_FIELDS = %w[pid workload_pid wrapper_pid start_time workload_start_time
                             pidfd workload_pidfd executable_digest workload_executable_digest
                             namespace_links kernel_identity supervisor_pid mount_identity cgroup_inode cgroup_id
                             command path plan].freeze

        # Returns the resources currently accounted for by the native adapters.
        # It deliberately never reads the ledger: the caller needs an honest
        # view of kernel-side state in order to detect a missing or duplicated
        # durable ownership record after a crash.
        def resource_inventory
          source = @adapters[:observer]
          return normalize_inventory(invoke_observer(source)) if source

          resources = []
          @mutex.synchronize do
            @sandboxes.values.each { |sandbox| add_sandbox_inventory(resources, sandbox) }
          end

          add_component_inventory(resources, @filesystem, "workspace")
          add_component_inventory(resources, @namespace, "namespace")
          add_component_inventory(resources, @cgroup, "cgroup")
          normalize_inventory(resources)
        end

        alias list_resources resource_inventory
        alias observe_resources resource_inventory

        private

        def add_sandbox_inventory(resources, sandbox)
          owner = sandbox.identity
          live = sandbox.state != :removed
          add_inventory_resource(resources, "workspace", sandbox.workspace, owner: owner,
                                                                            live: live, parent: sandbox.id)
          add_inventory_resource(resources, "namespace", sandbox.namespace, owner: owner,
                                                                            live: live, parent: sandbox.id)
          add_inventory_resource(resources, "cgroup", sandbox.cgroup, owner: owner,
                                                                      live: live, parent: sandbox.id)
          sandbox.containers.each do |container_hash|
            if container_hash["workspace"]
              add_inventory_resource(resources, "workspace", container_hash["workspace"], owner: owner,
                                                                                          live: live, parent: sandbox.id)
            end
            container = sandbox.container(container_hash.fetch("id"))
            if container.cgroup
              add_inventory_resource(resources, "cgroup", container.cgroup, owner: owner,
                                                                            live: container.state == :running, parent: sandbox.id)
            end
            resources << process_inventory_resource(sandbox, container, owner) if container.process
          end
        end

        def process_inventory_resource(sandbox, container, owner)
          process = container.process.to_h
          process_id = container_resource_id(sandbox, container)
          process_identity = process_identity_for(sandbox, container, process)
          managed_inventory_resource(
            "process", process_id, process_identity, owner,
            metadata: {"parent" => sandbox.id, "container_id" => container.id,
                       "live" => container.state == :running, "managed_by" => "rubernetes-native",
                       "id" => process["id"] || process[:id],
                       "command" => process["command"] || process[:command],
                       "state" => process["state"] || process[:state],
                       "started_at" => process["started_at"] || process[:started_at],
                       "pid" => process["workload_pid"] || process[:workload_pid] || process["pid"] || process[:pid],
                       "wrapper_pid" => process["pid"] || process[:pid],
                       "start_time" => process["workload_start_time"] || process[:workload_start_time],
                       "executable_digest" => process["workload_executable_digest"] || process[:workload_executable_digest],
                       "pidfd" => process["workload_pidfd"] || process[:workload_pidfd] || process["pidfd"] || process[:pidfd],
                       "cgroup" => container.cgroup&.path}
          )
        end

        def normalize_inventory(value)
          normalized = Array(value).map { |resource| normalize_inventory_entry(resource.to_h) }
          normalized.each_with_object({}) do |entry, result|
            key = resource_key(entry)
            existing = result[key]
            if existing.nil?
              result[key] = entry
            else
              unless existing["identity"] == entry["identity"] && existing["owner"] == entry["owner"]
                raise RecoveryRequired, "observed native resource #{key} has duplicate identities"
              end

              result[key] = existing.merge(
                "metadata" => existing.fetch("metadata", {}).merge(entry.fetch("metadata", {}))
              )
            end
          end.values
        end

        def normalize_inventory_entry(hash)
          kind = String(hash.fetch("kind") { hash.fetch(:kind) })
          id = hash["id"] || hash[:id]
          if id.nil? && hash["pod_id"]
            id = hash["container_id"].to_s == "sandbox" ? hash["pod_id"] : "#{hash.fetch("pod_id")}:#{hash.fetch("container_id")}"
          end
          raise RecoveryRequired, "observed native resource #{kind.inspect} has no stable id" if id.nil?

          identity = hash["identity"] || hash[:identity] || hash["stable_identity"] || hash[:stable_identity]
          if identity.nil? || String(identity).empty?
            raise RecoveryRequired,
                  "observed native resource #{kind}:#{id} has no stable identity"
          end

          {
            "kind" => kind,
            "id" => String(id),
            "identity" => String(identity),
            "owner" => String(hash["owner"] || hash[:owner] || ""),
            "metadata" => normalize_inventory_metadata(hash)
          }
        end

        def normalize_inventory_metadata(hash)
          metadata = hash["metadata"] || hash[:metadata] || {}
          metadata = metadata.to_h.transform_keys(&:to_s)
          IDENTITY_FIELDS.each do |field|
            metadata[field] ||= hash[field] if hash.key?(field)
            metadata[field] ||= hash[field.to_sym] if hash.key?(field.to_sym)
          end
          metadata["path"] ||= hash["path"] if hash.key?("path")
          metadata["path"] ||= hash[:path] if hash.key?(:path)
          metadata["managed_by"] ||= hash["managed_by"] || hash[:managed_by]
          metadata["live"] = hash["live"] if hash.key?("live")
          metadata["live"] = hash[:live] if hash.key?(:live)
          metadata.delete("path") if metadata["path"].nil?
          metadata.delete("managed_by") if metadata["managed_by"].nil?
          metadata
        end

        def add_inventory_resource(resources, kind, component, owner:, live:, parent: nil)
          return unless component

          hash = component.to_h
          id = hash["id"] || hash[:id]
          if id.nil? && (pod_id = hash["pod_id"] || hash[:pod_id])
            container_id = hash["container_id"] || hash[:container_id]
            id = container_id.to_s == "sandbox" ? pod_id : "#{pod_id}:#{container_id}"
          end
          return if id.nil?

          identity = hash["identity"] || hash[:identity] || hash["stable_identity"] || hash[:stable_identity]
          return if identity.nil?

          metadata = {
            "managed_by" => "rubernetes-native",
            "live" => live
          }
          metadata.merge!(hash["metadata"].to_h.transform_keys(&:to_s))
          identity_metadata_fields(hash).each { |key, value| metadata[key] ||= value }
          metadata["parent"] = parent if parent
          metadata["path"] = hash["path"] || hash[:path] if hash["path"] || hash[:path]
          resources << managed_inventory_resource(kind, id, identity, owner, metadata: metadata)
        end

        def add_component_inventory(resources, component, kind)
          Array(component.resources).each do |entry|
            hash = entry.to_h
            id = hash["id"] || hash[:id]
            if id.nil? && hash["pod_id"]
              id = hash["container_id"].to_s == "sandbox" ? hash["pod_id"] : "#{hash.fetch("pod_id")}:#{hash.fetch("container_id")}"
            end
            next if id.nil?

            identity = hash["identity"] || hash[:identity] || hash["stable_identity"] || hash[:stable_identity]
            next if identity.nil?

            owner = owner_for_resource(kind, id)
            metadata = {
              "managed_by" => "rubernetes-native",
              "live" => hash.key?("live") ? hash["live"] : hash[:live]
            }
            metadata.merge!(hash["metadata"].to_h.transform_keys(&:to_s))
            identity_metadata_fields(hash).each { |key, value| metadata[key] ||= value }
            metadata["path"] = hash["path"] || hash[:path] if hash["path"] || hash[:path]
            metadata["parent"] = hash["pod_id"] || hash[:pod_id] if hash["pod_id"] || hash[:pod_id]
            resources << managed_inventory_resource(kind, id, identity, owner, metadata: metadata)
          end
        end

        def managed_inventory_resource(kind, id, identity, owner, metadata: {})
          {
            "kind" => String(kind),
            "id" => String(id),
            "identity" => String(identity),
            "owner" => String(owner),
            "metadata" => metadata.transform_keys(&:to_s)
          }
        end

        def identity_metadata_fields(hash)
          IDENTITY_FIELDS.each_with_object({}) do |field, result|
            value = hash[field] if hash.key?(field)
            value = hash[field.to_sym] if value.nil? && hash.key?(field.to_sym)
            result[field] = value unless value.nil?
          end
        end

        def owner_for_resource(kind, id)
          resource = @ledger.resources(include_released: false).find do |entry|
            (entry["kind"].to_s == String(kind) && entry["id"].to_s == String(id)) ||
              (entry[:kind].to_s == String(kind) && entry[:id].to_s == String(id))
          end
          (resource.to_h["owner"] || resource.to_h[:owner]).to_s
        end

        def resource_key(resource)
          kind = resource["kind"] || resource[:kind]
          id = resource["id"] || resource[:id]
          "#{kind}:#{id}"
        end
      end
    end
  end
end
