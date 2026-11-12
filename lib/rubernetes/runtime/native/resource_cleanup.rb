# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Cleanup of one observed resource during recovery.  A resource is
      # removed only when it is dead, managed by this runtime, and still
      # carries the exact identity the caller observed; anything else fails
      # closed.
      module ResourceCleanup
        # Removes one adapter-owned resource after the caller has established
        # that it is a dead, managed resource with a stable identity.  Unknown
        # or live resources fail closed and are never delegated to an adapter.
        def cleanup_resource(resource)
          value = normalize_inventory([resource]).fetch(0)
          metadata = value.fetch("metadata", {})
          raise RecoveryRequired, "cannot cleanup a live native resource #{resource_key(value)}" unless metadata["live"] == false
          unless metadata["managed_by"] == "rubernetes-native" || @adapters[:cleaner]
            raise CapabilityError, "native resource #{resource_key(value)} has no trusted cleanup owner"
          end

          if (cleaner = @adapters[:cleaner])
            return invoke_cleaner(cleaner, value)
          end

          kind = value.fetch("kind")
          case kind
          when "workspace" then cleanup_workspace_resource(value, metadata)
          when "namespace" then cleanup_namespace_resource(value)
          when "cgroup" then cleanup_cgroup_resource(value, metadata)
          when "process" then cleanup_process_resource(value, metadata)
          else
            raise CapabilityError, "native cleanup does not support resource kind #{kind.inspect}"
          end
          true
        end

        # The workspace a ledger record describes, when its identity is exactly
        # the record's: never adopted after a restart, so only the ledger knows it.
        def orphan_workspace(value, metadata)
          fields = %w[id root upper work identity image_digest]
          return nil unless fields.all? { |field| metadata.key?(field) } && metadata["identity"] == value.fetch("identity")

          metadata.slice(*fields)
        end

        # A cgroup under this runtime's hierarchy that a dead operation left
        # behind; the caller still checks its identity and inode.
        def orphan_cgroup(value, metadata)
          path = metadata["path"].to_s
          root = cgroup_hierarchy_root
          return nil if path.empty? || root.empty? || !path.start_with?("#{root}/") || !File.directory?(path)

          Platform::Linux::CgroupV2::Handle.new(path: path, qos: metadata["qos"], pod_id: metadata["pod_id"],
                                                container_id: metadata["container_id"], identity: value.fetch("identity"))
        end

        private

        def cleanup_workspace_resource(value, metadata)
          handle = @filesystem.workspaces.find do |entry|
            entry["id"].to_s == value.fetch("id") && entry["identity"] == value.fetch("identity")
          end
          workspace = if handle
                        @filesystem.workspaces.find { |entry| entry["id"].to_s == value.fetch("id") }
                      else
                        # A dead operation's workspace that this (restarted)
                        # runtime never adopted: the ledger's own record says
                        # where it is.
                        orphan_workspace(value, metadata)
                      end
          raise RecoveryRequired, "workspace #{resource_key(value)} is not present in this runtime" unless workspace

          @filesystem.cleanup(Native::Filesystem::Workspace.new(**workspace.transform_keys(&:to_sym)))
        end

        def cleanup_namespace_resource(value)
          handle = @namespace.lookup(value.fetch("id"))
          unless handle.identity == value.fetch("identity")
            raise Native::Namespace::Error,
                  "namespace #{resource_key(value)} identity changed"
          end

          @namespace.destroy(handle)
        end

        def cleanup_cgroup_resource(value, metadata)
          handle = begin
            @cgroup.lookup(metadata["path"] || value.fetch("id"))
          rescue Platform::Linux::CgroupV2::Error
            orphan_cgroup(value, metadata) || raise
          end
          unless handle.identity == value.fetch("identity")
            raise Platform::Linux::CgroupV2::Error,
                  "cgroup #{resource_key(value)} identity changed"
          end

          expected_inode = metadata["cgroup_inode"] || metadata["cgroup_id"]
          if expected_inode
            actual_inode = File.stat(handle.path).ino
            unless actual_inode == Integer(expected_inode)
              raise Platform::Linux::CgroupV2::Error,
                    "cgroup #{resource_key(value)} kernel identity changed"
            end
          end

          @cgroup.remove(handle, force: true)
        end

        def cleanup_process_resource(value, metadata)
          handle = @process_supervisor.handles.values.find { |entry| process_handle_matches?(entry, value, metadata) }
          raise RecoveryRequired, "process #{resource_key(value)} is not present in this runtime" unless handle

          if handle.running? || handle.state == :created
            @process_supervisor.stop(handle, timeout: 1.0,
                                             resource_id: value.fetch("identity"))
          end
          @process_supervisor.close(handle)
        end

        # A supervisor handle is the observed process when it carries the
        # resource's id, or when pid, start time and executable digest
        # reproduce the observed identity exactly -- a pid alone never does.
        def process_handle_matches?(entry, value, metadata)
          return true if entry.id.to_s == value.fetch("id")

          expected = value.fetch("identity")
          metadata_pid = metadata["pid"] || metadata["workload_pid"]
          metadata_start = metadata["start_time"] || metadata["workload_start_time"]
          observed = entry.to_h
          candidate_pid = observed["workload_pid"] || observed["pid"]
          candidate_start = observed["workload_start_time"]
          candidate_digest = observed["workload_executable_digest"] || observed["executable_digest"]
          candidate_identity = if candidate_pid
                                 "process:#{metadata["parent"]}:#{metadata["container_id"]}:#{candidate_pid}:" \
                                   "#{candidate_start || "unknown"}:#{candidate_digest || "unknown"}"
                               end
          candidate_identity == expected &&
            (metadata_pid.nil? || candidate_pid.to_i == metadata_pid.to_i) &&
            (metadata_start.nil? || candidate_start.to_i == metadata_start.to_i)
        end
      end
    end
  end
end
