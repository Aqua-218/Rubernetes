# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # Starting and stopping the node: recovery, registration, then the sync
      # loop and the background loops beside it (PLEG relist, node status,
      # eviction, image GC, shutdown watch, plugin registration).
      module RunLoop
        def start(lease_thread: false)
          perform_recovery!
          unless registered?
            begin
              register
            rescue StandardError => error
              @mutex.synchronize { @startup_error = error }
              # Registration is a readiness boundary. The sync loop must not
              # accept Pods while the node is absent from the API server; the
              # lease thread retries registration without opening the worker.
              raise unless @error_handler
            end
          end
          unless registered?
            @mutex.synchronize do
              @running = false
              @ready = false
            end
            start_lease_thread if lease_thread
            return self
          end
          start_sync_loop
          start_lease_thread if lease_thread
          self
        end

        def run
          start(lease_thread: true)
          @lease_thread&.join
          self
        end

        def stop(reason: "shutdown")
          @mutex.synchronize do
            @running = false
            @stop_requested = true
            @lease_condition.broadcast
          end
          @mutex.synchronize { @node_status_condition.broadcast }
          @sync_loop.stop
          @wakeups.stop
          stop_managers
          [@relist_thread, @node_status_thread, @lease_thread].each do |thread|
            thread.join if thread && thread != Thread.current
          end
          set_ready(false, reason: "NodeStopping", message: reason.to_s, persist: false)
          self
        end

        alias close stop

        # Deterministic single iteration: renew the lease if due and let the
        # SyncLoop process watch/resync input.
        def run_once(events: nil, now: nil, resync: true)
          perform_recovery!
          register unless registered?
          renew_lease(now: now)
          @sync_loop.run_once(events: events, now: monotonic_value(now), resync: resync)
          self
        rescue StandardError => error
          set_ready(false, reason: "AgentLoopFailed", message: error.message)
          @error_handler&.call(error)
          raise
        end

        alias tick run_once

        private

        # The background loops run only on the wall clock: an injected sleeper
        # (a deterministic test, a probe) drives the agent by hand.
        def wall_clock?
          @sleeper.equal?(DEFAULT_SLEEPER)
        end

        def stop_managers
          [@static_pods, @device_plugins, @pod_resources, @eviction_manager, @image_gc_manager, *@cri_image_gc_managers,
           @container_manager, @qos_cgroup_manager, @shutdown_manager, @plugin_manager, @dra_manager, @evented_pleg,
           @pod_certificate_manager].each { |manager| manager&.stop }
        end

        def start_sync_loop
          return if @mutex.synchronize { @running || @stop_requested }

          @sync_loop.start
          @static_pods&.start
          [@pod_resources, @device_plugins].each do |server|
            server&.start
          rescue StandardError => error
            @error_handler&.call(error)
          end
          start_relist_thread
          start_evented_pleg
          check_cri_runtime_support
          start_node_status_thread
          start_periodic_managers if wall_clock?
          @mutex.synchronize do
            @running = true
            @stop_requested = false
          end
          true
        end

        def start_periodic_managers
          # kubelet: evictionManager.Start(..., evictionMonitoringPeriod).
          @eviction_manager&.start
          # kubelet StartGarbageCollection: image GC every ImageGCPeriod.
          @image_gc_manager&.start
          @cri_image_gc_managers.each(&:start)
          # The shutdown manager's logind watch (inhibitor lock + PrepareForShutdown).
          @shutdown_manager&.start
          # cpuManager reconcileState every cpuManagerReconcilePeriod.
          @container_manager&.start_reconcile
          # DRA: registration reconciler (1 s) and the manager's own loop.
          @dra_manager&.start
          begin
            # InitializeCSINodeWithAnnotation, before any plugin registers.
            @csi_plugins&.initialize_csi_node
          rescue StandardError => error
            @error_handler&.call(error, :csi_node_init)
          end
          @plugin_manager&.start
        end

        # PLEG-style relist: notice containers that exited on their own between
        # syncs so restart policy and Pod phase follow the process, not the
        # resync timer.
        def start_relist_thread
          return unless wall_clock?

          @mutex.synchronize do
            return if @relist_thread&.alive?

            @relist_thread = Thread.new { relist_loop }
          end
        end

        def relist_loop
          until @mutex.synchronize { @stop_requested }
            begin
              relist_once
            rescue StandardError => error
              @error_handler&.call(error, :relist)
            end
            sleep(@relist_period)
          end
        end

        def relist_once
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          relist_pods
        ensure
          @kubelet_metrics&.pleg_relist(started, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) if started
        end

        def relist_pods
          @lifecycle.running_pod_uids.each do |uid|
            @lifecycle.observe_exits(uid)
          rescue StandardError => error
            # GenericPLEG: a Pod whose runtime state could not be inspected
            # this relist is skipped (its events discarded) and tried again.
            @kubelet_metrics&.pleg_discard_event
            @error_handler&.call(error, :relist, uid)
          end
          begin
            @lifecycle.retry_pending_cleanups
          rescue StandardError => error
            @error_handler&.call(error, :relist)
          end
        end

        # EventedPLEG (feature gate, off by default): with a CRI runtime that
        # streams container events, the generic relist slows to 300 s and the
        # events drive the lifecycle; if the stream keeps failing the relist
        # period is restored.
        def start_evented_pleg
          return unless @feature_gates.fetch("EventedPLEG", false) == true && runtime_event_stream?
          return if @evented_pleg&.in_use?

          default_period = @relist_period
          @evented_pleg = EventedPLEG.new(
            client: @runtime.client, metrics: @kubelet_metrics, logger: @logger,
            on_event: lambda do |uid, _type, _container_id|
              @lifecycle.observe_exits(uid)
            rescue StandardError => error
              @error_handler&.call(error, :evented_pleg, uid)
            end,
            relist: -> { relist_once },
            on_fallback: lambda do
              @relist_period = default_period
              @error_handler&.call(RuntimeError.new("evented PLEG gave up after #{EventedPLEG::MAX_STREAM_RETRIES} stream failures; generic relist at " \
                                                    "#{default_period}s"), :evented_pleg)
            end
          )
          @relist_period = EventedPLEG::GENERIC_RELIST_SECONDS_WITH_EVENTS
          @evented_pleg.start
        end

        # RuntimeConfig support of the CRI runtimes (kubelet_cri_losing_support).
        def check_cri_runtime_support
          return if @runtime.nil?

          Thread.new do
            Thread.current.name = "cri-support-check"
            CRISupportCheck.run(runtime: @runtime, metrics: @kubelet_metrics, logger: @logger)
          rescue StandardError => error
            @error_handler&.call(error, :cri_support_check)
          end
        end
      end
    end
  end
end
