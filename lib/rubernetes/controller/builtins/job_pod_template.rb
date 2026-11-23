# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      # Indexed Job template fields that all created Pods share.
      module JobPodTemplate
        private

        def add_completion_index_env!(pod_template)
          spec = pod_template["spec"] ||= {}
          %w[initContainers containers].each do |key|
            next unless spec[key].is_a?(Array)

            spec[key].each do |container|
              next unless container.is_a?(Hash)

              env = Array(container["env"]).dup
              next if env.any? { |variable| Support.value(variable, "name", "").to_s == JobController::COMPLETION_INDEX_ENV }

              env << {"name" => JobController::COMPLETION_INDEX_ENV,
                      "valueFrom" => {"fieldRef" => {"fieldPath" => "metadata.annotations['#{JobController::COMPLETION_INDEX_ANNOTATION}']"}}}
              container["env"] = env
            end
          end
        end

        # names.MaxGeneratedNameLength = 63 - 5
        def pod_generate_name_with_index(job_name, index)
          suffix = "-#{index}-"
          prefix = "#{job_name}#{suffix}"
          max = 58
          return prefix if prefix.length <= max

          "#{prefix[0, max - suffix.length]}#{suffix}"
        end
      end
    end
  end
end
