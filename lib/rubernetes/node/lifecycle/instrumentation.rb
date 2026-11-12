# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # The kubelet metrics observer and the instrumented calls into the
      # injected ports (kubelet_runtime_operations_*).
      module Instrumentation
        # KubeletMetrics: sees every trace entry (started Pods and containers,
        # terminations, Pod start latency).
        attr_reader :metrics_observer

        # kubelet /metrics: the lifecycle's observer, and the volume operations
        # (storage_operation_duration_seconds) through the Pod volumes.
        def metrics_observer=(observer)
          @metrics_observer = observer
          report_volume_reconstruction(observer)
          return if @pod_volumes.nil? || observer.nil?

          @pod_volumes.metrics_observer = lambda { |plugin, operation, status, seconds|
            observer.storage_operation(plugin, operation, status, seconds)
          }
        end

        # reconstruct_volume_operations_total: what the volume manager rebuilt
        # from its durable state when it started.
        def report_volume_reconstruction(observer)
          return if observer.nil? || @pod_volumes.nil?

          # A report, not a step: failing to deliver it changes nothing the
          # volume manager did.
          best_effort do
            stats = @pod_volumes.reconstruction_stats
            next unless stats

            observer.volume_reconstruction(stats[:attempted], stats[:errors],
                                           force_cleaned: stats[:force_cleaned].to_i, force_clean_errors: stats[:force_clean_errors].to_i)
          end
        end

        private

        # Metrics are reported on a best-effort basis: no observer, an
        # observer that fails, or a narrower one that does not take this
        # report never changes what the lifecycle does.
        def metrics_call(name, *)
          best_effort { @metrics_observer&.public_send(name, *) }
        end

        def accepts_keyword?(target, method_name, keyword)
          parameters = target.method(method_name).parameters
          parameters.any? { |kind, name| kind == :keyrest || (%i[key keyreq].include?(kind) && name == keyword) }
        rescue NameError
          false
        end

        # The CRI call each runtime method is (instrumented_services.go
        # recordOperation), for kubelet_runtime_operations_*.
        RUNTIME_OPERATIONS = {run_sandbox: "run_podsandbox", create_sandbox: "run_podsandbox",
                              remove_sandbox: "remove_podsandbox", create_container: "create_container",
                              start_container: "start_container", stop_container: "stop_container",
                              kill_container: "stop_container", remove_container: "remove_container",
                              container_status: "container_status", exec: "exec_sync",
                              update_container_resources: "update_container_resources",
                              update_pod_resources: "update_podsandbox_resources"}.freeze

        def invoke(target, method_name, *, **keywords)
          operation = @metrics_observer && target.equal?(@runtime) ? RUNTIME_OPERATIONS[method_name.to_sym] : nil
          return invoke_uninstrumented(target, method_name, *, **keywords) unless operation

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          failed = false
          begin
            invoke_uninstrumented(target, method_name, *, **keywords)
          rescue StandardError
            failed = true
            raise
          ensure
            seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
            handler = operation == "run_podsandbox" ? {runtime_handler: keywords[:runtime_class]} : {}
            best_effort { @metrics_observer.runtime_operation(operation, seconds, failed: failed, **handler) }
          end
        end

        def invoke_uninstrumented(target, method_name, *, **keywords)
          return target.public_send(method_name, *) if keywords.empty?

          begin
            target.public_send(method_name, *, **keywords)
          rescue ArgumentError => error
            raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

            target.public_send(method_name, *)
          end
        end
      end
    end
  end
end
