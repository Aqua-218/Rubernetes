# frozen_string_literal: true

require_relative "../../platform/linux/secure_rootfs"

module Rubernetes
  module Runtime
    class Native
      module ContainerLogRetention
        def retire_container(value, previous_id: nil, **)
          sandbox, container = find_container(value)
          if previous_id && !sandbox.container_if_present(previous_id) && container_log_ids(sandbox.id, sandbox.identity).include?(previous_id)
            remove_container_logs(sandbox.id, [previous_id])
          end
          remove_container(container, preserve_logs: true)
        end

        private

        def container_log_ids(sandbox_id, owner)
          prefix = "#{sandbox_id}:"
          @ledger.resources(owner: owner, include_released: true).filter_map do |resource|
            id = resource[:id]
            id.delete_prefix(prefix) if resource[:kind] == "cgroup" && id.start_with?(prefix)
          end
        end

        def remove_sandbox_logs(sandbox_id, owner, container_ids: [])
          remove_container_logs(sandbox_id, (container_ids + container_log_ids(sandbox_id, owner)).uniq)
        end

        def clean_finished_sandbox_logs
          @ledger.operations.each do |operation|
            next unless operation[:state] == "Removed"

            remove_sandbox_logs(operation[:id], operation[:owner])
          rescue StandardError => error
            record(:sandbox_log_cleanup_error, sandbox_id: operation[:id], error: error_payload(error))
          end
        end

        def remove_container_logs(sandbox_id, container_ids)
          return if container_ids.empty? || !File.directory?(config.log_root)

          filesystem = Platform::Linux::SecureRootfs.new(root: config.log_root)
          container_ids.each do |id|
            key = process_log_key(sandbox_id, id)
            filesystem.remove(key)
          end
        ensure
          filesystem&.close
        end

        def process_log_key(sandbox_id, container_id)
          unless [sandbox_id, container_id].all? { |id| /\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/.match?(id) }
            raise Error, "invalid sandbox or container log identity"
          end

          "process-#{sandbox_id}-#{container_id}"
        end

        def archived_container_log_handle(value, sandbox_id)
          id = String(reference_id(value))
          owner = sandbox(sandbox_id)
          raise Error, "unknown container #{id}" unless container_log_ids(owner.id, owner.identity).include?(id)

          process_log_key(owner.id, id)
        end
      end
    end
  end
end
