# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      # Pod removal operations shared by managed scale-down and Job completion.
      module JobPodRemoval
        private

        # deleteJobPods releases tracking before DELETE so scale-down and
        # suspension cannot charge these Pods against the failure budget.
        def delete_managed_pods(pods)
          return if pods.empty?

          pods.each do |pod|
            remove_tracking_finalizer(pod) if @c.tracking_finalizer?(pod)
          end
          pods.each { |pod| delete_pod(pod) }
          @pods -= pods
        end

        def remove_tracking_finalizer(pod)
          candidate = Support.deep_copy(pod)
          metadata = Support.metadata(candidate)
          key = metadata.key?("finalizers") ? "finalizers" : :finalizers
          metadata[key] = Array(metadata[key]) - [JobController::TRACKING_FINALIZER]
          @operations << @c.operation_update(pod, candidate, descriptor: JobController::POD, reason: "job tracking finalizer removal")
        end

        def delete_pod(pod)
          @operations << @c.operation_delete(pod, descriptor: JobController::POD, reason: "job pod removal")
          @events << @c.event("Normal", "SuccessfulDelete", "Deleted pod: #{Support.name(pod)}")
        end
      end
    end
  end
end
