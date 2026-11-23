# frozen_string_literal: true

require_relative "../../../priority_classes"

module Rubernetes
  module Security
    module Admission
      module Plugins
        module PriorityAdmission
          def admit(attributes)
            return unless attributes.object && attributes.subresource.to_s.empty?

            if resource?(attributes, "", "pods")
              admit_pod_priority(attributes)
            elsif resource?(attributes, "scheduling.k8s.io", "podgroups") && attributes.operation == "CREATE" &&
                  @context.feature_enabled?("WorkloadAwarePreemption")
              resolve_pod_group_priority(attributes)
            end
          end

          def validate(attributes)
            return unless resource?(attributes, "scheduling.k8s.io", "priorityclasses") && attributes.subresource.to_s.empty?
            return unless %w[CREATE UPDATE].include?(attributes.operation) && attributes.object&.fetch("globalDefault", false)

            current = default_priority_class
            return unless current
            return if attributes.operation == "UPDATE" && current.dig("metadata", "name") == attributes.name

            reject!("PriorityClass #{current.dig("metadata", "name")} is already marked as default. Only one default can exist")
          end

          private

          def default_priority_class
            classes = @context.list("priorityclasses", nil, group: "scheduling.k8s.io")
            classes.select { |klass| klass["globalDefault"] == true }.min_by { |klass| klass["value"].to_i }
          end

          def resolve_priority(class_name)
            klass = if class_name.empty?
                      default_priority_class
                    else
                      @context.get("priorityclasses", nil, class_name, group: "scheduling.k8s.io")
                    end
            return [klass.dig("metadata", "name") || class_name, klass["value"].to_i, klass["preemptionPolicy"] || "PreemptLowerPriority"] if klass
            return [class_name, 0, "PreemptLowerPriority"] if class_name.empty?
            return [class_name, PriorityClasses::SYSTEM.fetch(class_name).first, "PreemptLowerPriority"] if PriorityClasses::SYSTEM.key?(class_name)

            reject!("no PriorityClass with name #{class_name} was found")
          end

          def admit_pod_priority(attributes)
            fields = attributes.object["spec"] ||= {}
            if attributes.operation == "UPDATE"
              %w[priority preemptionPolicy].each do |key|
                previous = attributes.old_object&.dig("spec", key)
                fields[key] = previous if fields[key].nil? && !previous.nil?
              end
              return
            end
            return unless attributes.operation == "CREATE"

            name, priority, policy = resolve_priority(fields["priorityClassName"].to_s)
            if !fields["priority"].nil? && fields["priority"] != priority
              reject!("the integer value of priority (#{fields["priority"]}) must not be provided in pod spec; " \
                      "priority admission controller computed #{priority} from the given PriorityClass name")
            end
            if !fields["preemptionPolicy"].nil? && fields["preemptionPolicy"] != policy
              reject!("the string value of PreemptionPolicy (#{fields["preemptionPolicy"]}) must not be provided in pod spec; " \
                      "priority admission controller computed #{policy} from the given PriorityClass name")
            end
            fields["priorityClassName"] = name unless name.empty?
            fields["priority"] = priority
            fields["preemptionPolicy"] = policy
          end

          def resolve_pod_group_priority(attributes)
            fields = attributes.object["spec"] ||= {}
            name, priority, = resolve_priority(fields["priorityClassName"].to_s)
            if !fields["priority"].nil? && fields["priority"] != priority
              reject!("priority set in the pod group (#{fields["priority"]}) must match the priority computed (#{priority}) " \
                      "based on the priority class set in the spec")
            end
            fields["priorityClassName"] = name unless name.empty?
            fields["priority"] = priority
          end
        end
      end
    end
  end
end
