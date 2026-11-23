# frozen_string_literal: true

require_relative "../../client/errors"

module Rubernetes
  module Controller
    module Builtins
      # pkg/controller/job/job_scheduling_manager.go's indexed gang Job lifecycle.
      module JobScheduling
        GATE = "WorkloadWithJob"
        WORKLOAD = ResourceDescriptor.parse("Workload")
        POD_GROUP = ResourceDescriptor.parse("PodGroup")
        MAX_NAME_LENGTH = 253

        private

        def gang_job?(job)
          parallelism(job) > 1 && indexed?(job) && completions(job) == parallelism(job) &&
            Support.value(Support.spec(template(job)), "schedulingGroup", nil).nil?
        end

        def job_scheduling(job, pods, adapter)
          workloads = scheduling_objects(adapter, WORKLOAD, job)
          return if workloads.nil?

          matching = workloads.select do |workload|
            reference = Support.spec(workload)["controllerRef"]
            reference == {"apiGroup" => "batch", "kind" => "Job", "name" => Support.name(job)}
          end
          if matching.empty?
            return create_job_workload(job, workloads) if new_gang_job?(job, pods)

            return
          end
          return unless matching.length == 1 && owner_ref?(job, matching.first)

          workload = matching.first
          templates = Array(Support.spec(workload)["podGroupTemplates"])
          return unless templates.length == 1

          groups = scheduling_objects(adapter, POD_GROUP, job)
          return if groups.nil?

          matching = groups.select { |group| Support.spec(group).dig("podGroupTemplateRef", "workload", "workloadName") == Support.name(workload) }
          return create_job_pod_group(job, workload, templates.first, groups) if matching.empty?
          return unless matching.length == 1 && owner_ref?(job, matching.first)

          matching.first
        end

        def scheduling_objects(adapter, descriptor, job)
          list_children(adapter, descriptor, Support.namespace(job))
        rescue Client::Error, StoreError
          nil
        end

        def new_gang_job?(job, pods)
          status = Support.status(job)
          pods.empty? && status["startTime"].nil? && status["failed"].to_i.zero? && status["succeeded"].to_i.zero? &&
            find_condition(status["conditions"], "Suspended").nil?
        end

        def create_job_workload(job, workloads)
          hash = scheduling_name_hash("(types.UID)#{Support.uid(job)}")
          prefix = Support.name(job).slice(0, MAX_NAME_LENGTH - hash.length - 1)
          workload_name = "#{prefix}-#{hash}"
          raise StoreError, "Workload #{workload_name.inspect} already exists" if workloads.any? { |workload| Support.name(workload) == workload_name }

          workload = {"apiVersion" => WORKLOAD.api_version, "kind" => WORKLOAD.kind,
                      "metadata" => {"name" => workload_name, "namespace" => Support.namespace(job)},
                      "spec" => {"controllerRef" => {"apiGroup" => "batch", "kind" => "Job", "name" => Support.name(job)},
                                 "podGroupTemplates" => [{"name" => "#{Support.name(job)}-pgt-0",
                                                          "schedulingPolicy" => {"gang" => {"minCount" => parallelism(job)}}}]}}
          event = event("Normal", "WorkloadCreated", "Created Workload #{workload_name} for Job #{Support.name(job)}")
          scheduling_create_result(job, workload, WORKLOAD, events: [event])
        end

        def create_job_pod_group(job, workload, template, groups)
          workload_name = Support.name(workload)
          template_name = template.fetch("name")
          group_name = job_pod_group_name(workload_name, template_name)
          raise StoreError, "PodGroup #{group_name.inspect} already exists" if groups.any? { |group| Support.name(group) == group_name }

          group = {"apiVersion" => POD_GROUP.api_version, "kind" => POD_GROUP.kind,
                   "metadata" => {"name" => group_name, "namespace" => Support.namespace(job),
                                  "ownerReferences" => [scheduling_owner_reference(workload)]},
                   "spec" => {"podGroupTemplateRef" => {"workload" => {"workloadName" => workload_name, "podGroupTemplateName" => template_name}},
                              "schedulingPolicy" => template.fetch("schedulingPolicy")}}
          scheduling_create_result(job, group, POD_GROUP)
        end

        def scheduling_create_result(job, object, descriptor, events: [])
          # Observe the server-assigned UID at the next reconcile before a
          # dependent can refer to this object.
          operation = operation_create(object, owner: job, descriptor: descriptor, reason: "create Job #{descriptor.kind}")
          ReconcileResult.new(operations: [operation], events: events, status: Support.status(job), controller: name,
                              key: "#{Support.namespace(job)}/#{Support.name(job)}", requeue_after: 0.05)
        end

        def job_pod_group_name(workload_name, template_name)
          hash = scheduling_name_hash(workload_name + template_name)
          available = MAX_NAME_LENGTH - hash.length - 2
          half = available / 2
          workload_limit = [available - [template_name.length, half].min, workload_name.length].min
          template_limit = available - workload_limit
          "#{workload_name.slice(0, workload_limit)}-#{template_name.slice(0, template_limit)}-#{hash}"
        end

        def scheduling_name_hash(bytes)
          Support.safe_encode_string(Support.fnv32a(bytes).to_s)
        end

        def scheduling_owner_reference(object)
          Support.owner_reference(object, controller: false, block_owner_deletion: false).except("controller", "blockOwnerDeletion")
        end
      end
    end
  end
end
