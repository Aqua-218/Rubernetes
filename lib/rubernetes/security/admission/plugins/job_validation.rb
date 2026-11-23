# frozen_string_literal: true

module Rubernetes
  module Security
    module Admission
      module Plugins
        class JobValidation < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "batch", "jobs") && attributes.operation == "UPDATE" && attributes.subresource.to_s.empty?
            return unless @context.feature_enabled?("GenericWorkload") || @context.feature_enabled?("WorkloadWithJob")

            old_job = attributes.old_object
            job = attributes.object
            return unless old_job.is_a?(Hash) && job.is_a?(Hash)
            return if spec(old_job)["parallelism"] == spec(job)["parallelism"]

            namespace = metadata(old_job)["namespace"] || attributes.namespace
            pod_group_name = spec(old_job).dig("template", "spec", "schedulingGroup", "podGroupName")
            groups = matching_pod_groups(namespace, pod_group_name, metadata(old_job)["uid"])
            gang = groups.find { |group| spec(group).dig("schedulingPolicy", "gang").is_a?(Hash) }
            return unless gang

            reject!("jobs.batch #{attributes.name.inspect} is forbidden: cannot change parallelism for a Job referencing gang-scheduled PodGroup " \
                    "#{metadata(gang)["name"].inspect}")
          end

          private

          def matching_pod_groups(namespace, name, job_uid)
            version = {group: "scheduling.k8s.io", version: "v1alpha2"}
            return [@context.get("podgroups", namespace, name, **version)].compact unless name.nil?
            return [] if job_uid.to_s.empty?

            @context.list("podgroups", namespace, **version).select do |group|
              Array(metadata(group)["ownerReferences"]).any? do |reference|
                reference["controller"] == true && reference["uid"] == job_uid
              end
            end
          end
        end
        Registry.register("JobValidation") { |context, config| JobValidation.new("JobValidation", context: context, config: config) }
      end
    end
  end
end
