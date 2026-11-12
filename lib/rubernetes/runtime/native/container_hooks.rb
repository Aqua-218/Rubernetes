# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # OCI hooks of a container (CDI container edits): the runtime's side of
      # Hooks -- which hooks a container carries, the bundle they are handed,
      # and running them at the lifecycle stages this process owns.
      module ContainerHooks
        private

        def container_hooks(spec)
          return {} if Array(spec["cdi_hooks"]).empty?

          Hooks.normalize(spec["cdi_hooks"])
        rescue Hooks::Error => error
          raise FailClosed, "container hooks are invalid: #{error.message}"
        end

        def hook_bundle_directory(sandbox, container)
          File.join(File.dirname(config.journal_path), "oci-bundles", "#{sandbox.id}.#{container.id}")
        end

        def prepare_hook_bundle(sandbox, container, spec, command, rootfs, hooks)
          directory = hook_bundle_directory(sandbox, container)
          annotations = spec["annotations"].is_a?(Hash) ? spec["annotations"].transform_values(&:to_s) : {}
          env = (spec["env"] || {}).to_h.compact.map { |name, value| "#{name}=#{value}" }
          Hooks.write_bundle(directory, root: rootfs || "/", process: {"args" => Array(command), "env" => env, "cwd" => spec["cwd"] || "/"},
                                        mounts: Array(spec["mounts"]), annotations: annotations, hooks: hooks)
          {directory: directory, id: container.id, annotations: annotations,
           state: Hooks.state(id: container.id, status: "creating", pid: nil, bundle: directory, annotations: annotations)}
        end

        # Runs the hooks of +stages+ in order, in this process's namespaces.
        def run_hooks(hooks, stages, plan, pid:)
          stages.each do |stage|
            Array(hooks[stage]).each_with_index do |hook, index|
              state = Hooks.state(id: plan[:id], status: Hooks::STATUS.fetch(stage), pid: pid, bundle: plan[:directory],
                                  annotations: plan[:annotations])
              Hooks.run(hook, state, stage: stage, index: index)
            end
          end
          true
        end

        # poststart and poststop failures are warnings: the lifecycle goes on.
        def run_post_hooks(sandbox, container, hooks, plan, stage, pid:)
          run_hooks(hooks, [stage], plan, pid: pid)
        rescue Hooks::Error, SystemCallError => error
          record(:container_hook_warning, sandbox_id: sandbox.id, container_id: container.id, stage: stage, error: error.message)
          false
        end

        # The bundle marks a container whose poststop hooks are still owed; it
        # is removed once they ran, so a retried removal runs them only once.
        def run_poststop_hooks(sandbox, container)
          return if container.nil?

          hooks = container_hooks(container.spec || {})
          directory = hook_bundle_directory(sandbox, container)
          return if hooks.empty? || !File.directory?(directory)

          plan = {directory: directory, id: container.id,
                  annotations: container.spec["annotations"].is_a?(Hash) ? container.spec["annotations"].transform_values(&:to_s) : {}}
          run_post_hooks(sandbox, container, hooks, plan, "poststop", pid: nil)
          FileUtils.rm_rf(directory)
        rescue FailClosed
          nil
        end
      end
    end
  end
end
