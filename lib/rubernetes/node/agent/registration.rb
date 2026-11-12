# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # Registering the Node and keeping its Lease alive: the heartbeat the
      # node lifecycle controller watches.
      module NodeRegistration
        def register(force: false)
          ensure_recovered!
          @mutex.synchronize do
            return node if @registered && !force
          end
          object = build_node(ready: true)
          @kubelet_metrics&.node_registration_attempted
          persist_node(object)
          @mutex.synchronize do
            @registered = true
            @ready = true
            @startup_error = nil
          end
          renew_lease(force: true)
          object
        rescue StandardError => error
          set_ready(false, reason: "RegistrationFailed", message: error.message, persist: false)
          raise
        end

        alias register_node register

        def renew_lease(force: false, now: nil)
          timestamp = time_value(now)
          @mutex.synchronize do
            return @lease&.to_h if !force && @last_lease_renewal && timestamp.to_f - @last_lease_renewal.to_f < @lease_renew_interval
          end
          previous = @mutex.synchronize { @lease }
          current = Lease.new(
            node_name: @node_name,
            namespace: @node_namespace,
            duration_seconds: @lease_duration_seconds,
            renew_time: iso8601(timestamp),
            transitions: previous ? previous.transitions : 0
          ).freeze
          persist_lease(current.to_h)
          @mutex.synchronize do
            @lease = current
            @last_lease_renewal = timestamp
            @ready = true
          end
          current.to_h
        rescue StandardError => error
          set_ready(false, reason: "LeaseRenewalFailed", message: error.message)
          raise
        end

        alias heartbeat renew_lease

        private

        def start_lease_thread
          @mutex.synchronize do
            return if @lease_thread&.alive?

            @lease_thread = Thread.new { lease_loop }
          end
        end

        # Renews while registered; until then it retries the registration and
        # opens the sync loop only once the node is in the API.
        def lease_loop
          until @mutex.synchronize { @stop_requested }
            begin
              if registered?
                renew_lease
                sync_extended_resources
              else
                register
                start_sync_loop unless @mutex.synchronize { @stop_requested }
              end
            rescue StandardError => error
              @error_handler&.call(error)
            end
            wait_for_lease_interval
          end
        end

        def wait_for_lease_interval
          if @sleeper.equal?(DEFAULT_SLEEPER)
            @mutex.synchronize do
              @lease_condition.wait(@mutex, @lease_renew_interval) unless @stop_requested
            end
          else
            @sleeper.call(@lease_renew_interval)
          end
        end
      end
    end
  end
end
