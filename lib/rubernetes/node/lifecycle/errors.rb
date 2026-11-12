# frozen_string_literal: true

module Rubernetes
  module Node
    # The errors the Pod lifecycle raises.  LifecycleError is what a failed
    # start, stop or cleanup step is reported as; any other exception is a
    # kubelet defect and is reported with its origin.
    class Lifecycle
      class Error < StandardError; end
      LifecycleError = Error
      # The runtime no longer knows the sandbox (startup recovery released it).
      class SandboxGone < LifecycleError; end

      # Raised when a Pod's claims cannot be prepared; the kubelet reports
      # FailedPrepareDynamicResources and retries, the Pod stays
      # ContainerCreating.
      class DynamicResourcesError < LifecycleError; end
    end
  end
end
