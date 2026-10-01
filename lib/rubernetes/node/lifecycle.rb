# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "time"

require_relative "../network/host_port"
require_relative "../volume/deferred_fsync"
require_relative "status"
require_relative "probe_manager"
require_relative "image_credentials"
require_relative "restart_manager"
require_relative "pod_resize"
require_relative "container_spec"
require_relative "pod_files"
require_relative "pod_volumes"
require_relative "cdi"
require_relative "device_plugins/manager"
require_relative "dra_manager"
require_relative "preemption"
require_relative "../runtime/common/strict_json"

module Rubernetes
  module Node
    # Coordinates the Pod-level lifecycle.  Runtime, Volume, and Network are
    # deliberately ports: M2 owns ordering and rollback, while M4 supplies
    # the concrete data-plane implementations.
    class Lifecycle
      class Error < StandardError; end
      LifecycleError = Error
      # The runtime no longer knows the sandbox (startup recovery released it).
      class SandboxGone < LifecycleError; end

      # Small atomic state store for the node-side reconciliation cache.  The
      # runtime ledger remains the authority for kernel ownership; this store
      # preserves the request/result, container identities, probe counters and
      # restart backoff so a new agent process does not reset policy state.
      class StateStore
        MAX_BYTES = 16 * 1024 * 1024

        def initialize(path)
          @path = File.expand_path(String(path))
          FileUtils.mkdir_p(File.dirname(@path))
        end

        attr_reader :path

        def load
          return {} unless File.file?(@path)
          raise Error, "node lifecycle state exceeds #{MAX_BYTES} bytes" if File.size(@path) > MAX_BYTES

          body = File.binread(@path)
          raise Error, "node lifecycle state is not newline terminated" unless body.end_with?("\n")

          Runtime::StrictJSON.parse(body, max_bytes: MAX_BYTES, max_depth: 100, require_newline: true)
        rescue Runtime::StrictJSON::Error, JSON::ParserError, SystemCallError => error
          raise Error, "node lifecycle state could not be loaded: #{error.message}"
        end

        def save(value)
          save_body(JSON.generate(value) << "\n")
        end

        # +body+: the complete newline-terminated JSON document.
        def save_body(body)
          raise Error, "node lifecycle state exceeds #{MAX_BYTES} bytes" if body.bytesize > MAX_BYTES

          temporary = "#{@path}.tmp-#{Process.pid}-#{Thread.current.object_id}"
          File.open(temporary, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |file|
            file.write(body)
            file.flush
          end
          File.rename(temporary, @path)
          # Atomic rename keeps the file whole; durability is coalesced (see
          # Volume::DeferredFsync).  Two fsyncs per lifecycle event, some
          # thirty events per Pod, serialized 33 concurrent Pod starts behind
          # the disk.
          Volume::DeferredFsync.schedule(@path)
          true
        ensure
          File.delete(temporary) if temporary && File.exist?(temporary)
        end

        private

        def fsync_directory
          directory = File.open(File.dirname(@path), File::RDONLY)
          directory.fsync
        ensure
          directory&.close
        end
      end

      RUNTIME_STATES = %w[
        New Validated ImagePinned WorkspaceAllocated IsolationCreated
        ResourcesAttached WorkloadStopped Running Stopping Stopped Removed
        RollingBack CleanupPending StateUnknown
      ].freeze
      POD_PHASES = %w[Pending Running Succeeded Failed Unknown].freeze

      Result = Data.define(
        :pod_uid, :state, :phase, :status, :events, :resources,
        :error, :cleanup_errors
      ) do
        def success?
          error.nil? && %w[Running Succeeded].include?(phase)
        end

        def failed?
          !error.nil? || phase == "Failed"
        end

        def to_h
          {
            "podUID" => pod_uid,
            "state" => state,
            "phase" => phase,
            "status" => Helpers.deep_copy(status),
            "events" => Helpers.deep_copy(events),
            "resources" => Helpers.deep_copy(resources),
            "error" => error,
            "cleanupErrors" => Helpers.deep_copy(cleanup_errors)
          }
        end
      end

      def initialize(runtime_value = nil, runtime: nil, volume: nil, network: nil, admission: nil,
                     status: nil, probe_manager: nil, restart_manager: nil,
                     endpoint_manager: nil, reporter: nil,
                     clock: -> { Time.now.utc }, sleeper: ->(seconds) { sleep(seconds) },
                     event_sink: nil, runtime_class_resolver: nil, image_resolver: nil,
                     state_store: nil, recovery_observer: nil, recovery_cleaner: nil,
                     container_spec: nil, pod_volumes: nil, pod_files: nil, pod_root: nil, host_ports: nil,
                     pod_deleter: nil,
                     resource_reader: nil, node_name: nil, host_ip: nil, node_allocatable: nil,
                     cluster_domain: "cluster.local", dra_manager: nil, cdi_spec_dirs: CDI::DEFAULT_SPEC_DIRS,
                     container_manager: nil, device_plugins: nil, credential_providers: nil, preemption: nil)
        runtime ||= runtime_value
        # CriticalPodAdmissionHandler: evicts lower-priority Pods when a
        # critical Pod is refused for lack of resources.
        @preemption = preemption
        # volumeManager: the attachable volumes node.status.volumesInUse has
        # reported (MarkVolumesAsReportedInUse); an attachable volume is
        # mounted only once it is in the list.  The observer is told when the
        # desired set changes so the node status goes out at once.
        @reported_in_use = {}
        @reported_in_use_changed = ConditionVariable.new
        @volumes_in_use_observer = nil
        # The Pods a terminate is running for right now: a second terminate
        # (a cleanup retry, a DELETED event) waits for the first instead of
        # running the same cleanup concurrently.  Two concurrent cleanups of
        # one Pod raced the runtime's removal and left a stale cleanup error
        # that made the record CleanupPending for ever.
        @terminating = {}
        @terminating_done = ConditionVariable.new
        # Image credential provider plugins (--image-credential-provider-*).
        @credential_providers = credential_providers
        # Device plugins (devicemanager): devices allocated at admission,
        # applied to each container's spec.
        @device_plugins = device_plugins
        # The CPU/memory/topology managers' internal container lifecycle:
        # cpuset pinning at create, registration at start, release at removal.
        @container_manager = container_manager
        # Dynamic Resource Allocation: claims prepared by their drivers before
        # the sandbox exists, CDI devices applied to the containers that name
        # them, claims unprepared once the containers are gone.
        @dra_manager = dra_manager
        @cdi_spec_dirs = Array(cdi_spec_dirs)
        raise ArgumentError, "runtime is required" unless runtime

        @runtime = runtime
        @volume = volume
        @network = network
        # Programs containerPort.hostPort on the node.  Nil in unit fixtures
        # that have no network at all.
        @host_ports = host_ports || (network ? Network::HostPort.new : nil)
        @pod_deleter = pod_deleter
        @node_name = node_name.to_s
        @host_ip = host_ip
        @pod_root = pod_root && File.expand_path(String(pod_root))
        @resource_reader = resource_reader
        # The kubelet-side translation: Pod volumes to host paths, Pod files
        # (/etc/hosts, resolv.conf) and the per-container runtime spec.  They
        # are only built when the node knows where Pod files live; the pure
        # lifecycle tests hand the Pod straight to a fake runtime.
        @pod_volumes = pod_volumes
        if volume && @pod_root
          @pod_volumes ||= PodVolumes.new(volume: volume, reader: resource_reader, node_name: @node_name,
                                          root: File.join(@pod_root, "volumes"), clock: clock,
                                          node_allocatable: node_allocatable)
        end
        @pod_files = pod_files
        @container_spec = container_spec
        if @pod_root
          @container_spec ||= ContainerSpec.new(reader: resource_reader, node_name: @node_name, node_allocatable: node_allocatable,
                                                cluster_domain: cluster_domain, pod_volumes: @pod_volumes)
        end
        @admission = admission
        @clock = clock
        @sleeper = sleeper
        @event_sink = event_sink
        @runtime_class_resolver = runtime_class_resolver
        @image_resolver = image_resolver || (runtime.respond_to?(:image_resolver) ? runtime.image_resolver : nil)
        @state_store = state_store.is_a?(String) ? StateStore.new(state_store) : state_store
        @recovery_observer = recovery_observer
        @recovery_cleaner = recovery_cleaner
        @status = status || Status.new(endpoint_manager: endpoint_manager, reporter: reporter, clock: clock)
        @probes = probe_manager || ProbeManager.new(runtime: runtime, clock: clock, sleeper: sleeper)
        @restarts = restart_manager || RestartManager.new(clock: monotonic_clock, sleeper: sleeper)
        @mutex = Mutex.new
        @persist_mutex = Mutex.new
        @persist_counter_mutex = Mutex.new
        @persist_requested = 0
        @persist_completed = 0
        @records = {}
        # Pods that ran to completion, by uid.  The API status cannot carry
        # this decision on its own: the node writes that status itself, so one
        # spurious restart makes the Pod look Running again and the node keeps
        # re-creating it forever.  A local tombstone is the durable answer.
        @finished = {}
        # Evictions the eviction manager asked for, carried out by the Pod's
        # own worker on its next sync (the kubelet sends the kill through the
        # pod worker too), so they never race a reconcile of the same Pod.
        @eviction_requests = {}
        @recovery_report = nil
        @recovery_done = false
        restore_state!
      end

      attr_reader :runtime, :volume, :network, :status, :probes, :restarts, :recovery_report,
                  :pod_volumes, :container_spec, :pod_root

      # HandlePodRemoves: the Pod left the API; admission stops counting it
      # now, even while a worker is still killing its containers.
      def pod_removed(uid)
        @mutex.synchronize do
          record = @records[uid.to_s]
          record[:config_removed] = true if record
        end
      end

      # Reconcile one desired Pod with the local record.  A deletion timestamp
      # is treated as a normal termination, never as an abrupt resource drop.
      def reconcile(pod, action: nil, request_id: nil)
        object = normalize_pod(pod)
        uid = pod_uid(object)
        if action.to_s.upcase == "DELETED" || deletion_requested?(object)
          return terminate(object, request_id: request_id, gone: action.to_s.upcase == "DELETED")
        end

        existing = record(uid)
        acknowledge_generation(object, existing) if existing
        if (eviction = @mutex.synchronize { @eviction_requests.delete(uid.to_s) }) &&
           existing && !%w[Stopped Removed].include?(existing[:state].to_s) && !existing[:forced_terminal]
          return evict(object, **eviction)
        end

        # kubelet never re-creates a Pod that has already reached a terminal
        # phase: its containers ran, stopped, and the restart policy does not
        # ask for another attempt.  Starting one again allocates a fresh
        # sandbox and a fresh image staging directory on every sync, so a
        # completed Pod quietly fills the node's disk while the API still
        # reports it as Succeeded.
        if pod_finished?(object, existing, uid)
          # The terminal record is the truth even when a stray earlier sync
          # republished the Pod as Running: re-publish it so the API stops
          # disagreeing with a Pod that has already finished.
          terminal = terminal_record(uid, existing)
          if terminal && Helpers.key(Helpers.key(object, "status", {}), "phase", "").to_s != terminal[:phase].to_s
            update_status(object, terminal)
            persist_state!
          end
          return terminal ? result_for(terminal) : nil
        end

        unless existing && existing.fetch(:state) == "Running"
          # A retried start waits out its backoff (kubelet: the sandbox/
          # container creation backoff) instead of allocating a fresh sandbox
          # on every sync.
          # kubelet keys its restart backoff on the container's hash, so a Pod
          # whose containers were edited starts again immediately instead of
          # waiting out the failed version's backoff.  Without that a Pod
          # whose broken field was just corrected sits in a backoff that grows
          # to minutes -- long past what a client waiting for it will allow.
          if existing && existing[:phase].to_s == "Pending" && existing[:error]
            # Labels and annotations stay out of config_digest so a metadata
            # change never restarts a HEALTHY Pod -- but a Pod stuck in
            # CreateContainerConfigError is exactly the case where the metadata
            # IS the fix: a downward-API env var reading
            # metadata.annotations['x'] cannot expand until the annotation
            # exists.  kubelet retries container creation on the sync that
            # follows the update; waiting out a backoff grown to 30s instead
            # is longer than the client watching the Pod will allow.
            if config_digest(existing.fetch(:pod)) == config_digest(object) &&
               metadata_digest(existing.fetch(:pod)) == metadata_digest(object)
              return result_for(existing) if start_retry_pending?(uid)
            else
              clear_start_retry(uid)
            end
          end

          return start(object, request_id: request_id)
        end

        # spec.activeDeadlineSeconds is the kubelet's to enforce: a Pod that has
        # been active on the node longer than the deadline is killed and marked
        # Failed/DeadlineExceeded.  The field was validated by the API server
        # and then read by nobody, so the deadline never elapsed.  Conformance:
        # "[sig-node] Pods should allow activeDeadlineSeconds to be updated"
        # (test/e2e/common/node/pods.go).
        if active_deadline_exceeded?(existing, object)
          return terminate(object, request_id: request_id, reason: DEADLINE_EXCEEDED_REASON,
                                   terminal_phase: "Failed",
                                   message: DEADLINE_EXCEEDED_MESSAGE)
        end

        config_changed = config_digest(existing.fetch(:pod)) != config_digest(object)

        # An ephemeral container is ADDED to a running Pod; upstream starts it
        # in place and never restarts the Pod for it (that is the whole point
        # of the ephemeralcontainers subresource).  Precisely because it must
        # not restart anything, spec.ephemeralContainers is one of
        # RESTART_NEUTRAL_SPEC_FIELDS and is stripped from the config digest --
        # so the digest can never be what tells us one arrived.  Asking it
        # anyway made this branch unreachable and the container stayed in
        # ContainerCreating for ever.  Compare the spec against the containers
        # actually started instead.  Conformance: "[sig-node] Ephemeral
        # Containers will start an ephemeral container in an existing pod" and
        # "... should update the ephemeral containers in an existing pod"
        # (test/e2e/common/node/ephemeral_containers.go).
        if existing[:state] == "Running" && pending_ephemeral_containers?(object, existing)
          start_ephemeral_containers(object, existing)
          unless config_changed
            existing[:pod] = object
            persist_state!
            return result_for(existing)
          end
        end

        # A resize that was waiting (PodResizePending) and has been reverted
        # to what the Pod already runs with: nothing to actuate, the
        # condition goes.
        if !config_changed && existing[:resize_pending] && !PodResize.resources_changed?(existing[:pod], object)
          existing[:resize_pending] = nil
          update_status(object, existing)
        end

        if config_changed
          if existing[:state] == "Running" && resize_only_change?(existing.fetch(:pod), object)
            resize_pod(existing, object)
            persist_state!
            return result_for(existing)
          end

          # kubelet's status manager acknowledges the new spec generation on
          # the sync that observes it, before the containers are replaced;
          # reporting it only once the restarted Pod is up made
          # observedGeneration lag an image pull ("... pod generation should
          # start at 1 and increment per update" allows 20 s).
          existing[:pod] = object
          update_status(object, existing)
          terminate(existing.fetch(:pod), request_id: request_id)
          start(object, request_id: request_id)
        else
          # Same configuration, newer object: the status the node publishes
          # is derived from the Pod it holds (metadata.generation ->
          # status.observedGeneration, labels for the downward API), so it
          # follows the latest copy.  Holding the copy from the first start
          # left observedGeneration at 1 for ever.
          previous_generation = Helpers.key(Helpers.key(existing[:pod] || {}, "metadata", {}), "generation", nil)
          previous_projected = projected_metadata(existing[:pod])
          existing[:pod] = object
          mark_dirty(existing)
          observe_exits(existing, object)
          # A new generation is answered with a status carrying its
          # observedGeneration right away (kubelet syncs on the update event;
          # e2e waits 20 s for it), not on the next periodic status pass.
          current_generation = Helpers.key(Helpers.key(object, "metadata", {}), "generation", nil)
          update_status(object, existing) if current_generation != previous_generation
          resume_backoff_restarts(existing, object) if existing[:state] == "Running"
          probe_running_containers(existing, object) if existing[:state] == "Running"
          # Labels and annotations are what downward API volumes project;
          # kubelet re-syncs the Pod on the update event, so a change reaches
          # the files at once instead of on the next periodic volume sync.
          metadata_changed = projected_metadata(object) != previous_projected
          sync_volumes(existing, object) if existing[:state] == "Running" && (metadata_changed || volume_sync_due?(existing))
          persist_state!
          result_for(existing)
        end
      end

      # kubelet's status manager records the generation it is acting on at
      # the start of the sync, whatever the sync then does (restart, retry a
      # failed start, nothing).  Without this a spec update that lands while
      # a restart is in flight is acknowledged only when the next sync
      # happens to publish, past the 20 s the e2e allows.
      def acknowledge_generation(object, record)
        current = Helpers.key(Helpers.key(object, "metadata", {}), "generation", nil)
        seen = Helpers.key(Helpers.key(record[:pod] || {}, "metadata", {}), "generation", nil)
        return if current.nil? || current.to_i <= seen.to_i
        # An in-place resize publishes the new generation together with its
        # PodResizeInProgress condition (kubelet allocates the resize in the
        # same sync).  Acknowledging it first told the resize e2e "done" --
        # observedGeneration caught up, no resize condition, Pod ready -- a
        # moment before the condition appeared (round 101, "extended resize
        # with equivalents").
        return if resizing_in_place?(record, object)

        update_status(object, record)
      rescue StandardError
        nil
      end

      # PLEG-style relist: notice containers that exited on their own and
      # apply the restart policy to them.  The runtime only learns of an exit
      # when asked, so without this sweep a finished container stays
      # "running" until the next full sync.  Returns the number of exits
      # handled.
      def observe_exits(record_or_uid, pod = nil, now: nil)
        record = record_or_uid.is_a?(Hash) && record_or_uid.key?(:uid) ? record_or_uid : record(record_or_uid)
        return 0 unless record && record[:state] == "Running"

        object = pod ? normalize_pod(pod) : record[:pod]
        handled = 0
        record[:containers].dup.each do |entry|
          next unless entry[:started]
          next unless @runtime.respond_to?(:container_status)

          status = begin
            invoke(@runtime, :container_status, entry[:id])
          rescue StandardError => error
            # The runtime no longer knows a container this record started:
            # startup recovery released its sandbox after the agent crashed,
            # or it was removed behind the agent's back.  Swallowing that
            # left the Pod "Running" with a dead process for ever (and exec
            # answering "unknown container").  kubelet's PLEG treats a
            # container missing from the runtime as dead: it is reported
            # Terminated/ContainerStatusUnknown (137) and, when the sandbox
            # itself is gone, the Pod is killed and synced from scratch.
            next unless lost_container_error?(error)
            return lose_sandbox!(object, record, error) if sandbox_lost?(record)

            {"state" => "exited", "exit_code" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON,
             "message" => CONTAINER_STATUS_UNKNOWN_MESSAGE}
          end
          status = status.to_h if status.respond_to?(:to_h) && !status.is_a?(Hash)
          next unless status.is_a?(Hash)

          # Every relist (each second) asks every running container; only an
          # exited one needs its whole status converted.
          state = Helpers.key(status, "state", "").to_s
          next unless %w[stopped terminated exited].include?(state)

          status = Helpers.string_keys(status)

          exit_code, signal = exit_details(status)
          exit_code = 128 + Integer(signal) if exit_code.nil? && !signal.nil?
          next if exit_code.nil?

          reason = status["oom_killed"] == true ? "OOMKilled" : Helpers.key(status, "reason", nil)
          begin
            handle_container_exit(object, container_name: entry[:name], exit_code: Integer(exit_code), reason: reason, now: now,
                                          message: Helpers.key(status, "message", nil))
          rescue StandardError => error
            # A restart that fails (runtime refused the create, backoff
            # bookkeeping raised) must not abort the whole relist; the next
            # sync retries it and the record says why.
            event(record, "container.restart_failed", name: entry[:name], error: Helpers.failure_message(error))
            record[:error] = "container #{entry[:name].inspect} restart failed: #{Helpers.failure_message(error)}"
            update_status(object, record)
          end
          handled += 1
        end
        handled
      end

      CONTAINER_STATUS_UNKNOWN_REASON = "ContainerStatusUnknown"
      CONTAINER_STATUS_UNKNOWN_MESSAGE = "The container could not be located when the pod was terminated"

      def lost_container_error?(error)
        Helpers.failure_message(error).match?(/unknown container|no such container|container .* not found/i)
      end

      def sandbox_lost?(record)
        return false unless record[:sandbox_id] && @runtime.respond_to?(:sandbox)

        invoke(@runtime, :sandbox, record[:sandbox_id])
        false
      rescue StandardError => error
        Helpers.failure_message(error).include?("unknown sandbox")
      end

      # kubelet SyncPod on a sandbox the runtime lost ("pod sandbox changed"):
      # every container that ran is reported Terminated with
      # ContainerStatusUnknown/137, the Pod is killed, and the restart policy
      # decides what follows -- Always/OnFailure start it again on the next
      # sync (no tombstone), Never ends it Failed.
      def lose_sandbox!(object, record, error)
        event(record, "sandbox.lost", sandbox_id: record[:sandbox_id], message: Helpers.failure_message(error))
        finished_at = Helpers.now(@clock).iso8601(6)
        record[:containers].each do |entry|
          next unless entry[:started]

          @probes.unregister(entry[:id]) if @probes.respond_to?(:unregister)
          restart_count = entry[:status].is_a?(Hash) ? entry[:status]["restartCount"].to_i : 0
          terminated = {"exitCode" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON, "message" => CONTAINER_STATUS_UNKNOWN_MESSAGE,
                        "finishedAt" => finished_at, "containerID" => entry[:id]}
          terminated["startedAt"] = entry[:started_at] if entry[:started_at]
          entry[:started] = false
          entry[:status] = {"state" => "terminated", "exitCode" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON,
                            "terminated" => terminated, "ready" => false, "started" => false, "restartCount" => restart_count}
        end
        # kubelet getPhase: every container stopped under Always (or a failed
        # one under OnFailure) is still a Running Pod -- it is being
        # restarted; only Never ends Failed.
        policy = Helpers.key(Helpers.key(object || {}, "spec", {}), "restartPolicy", "Always").to_s
        terminate(object || record[:uid], reason: "SandboxLost", terminal_phase: policy == "Never" ? "Failed" : "Running",
                                          message: CONTAINER_STATUS_UNKNOWN_MESSAGE)
        record[:containers].length
      end

      # The exit code and terminating signal a runtime status carries.  The
      # Native runtime keeps them on the process handle; simpler runtimes
      # report them at the top level or under "terminated".
      def exit_details(status)
        candidates = [status, Helpers.key(status, "process", nil), Helpers.key(status, "terminated", nil)].compact
        candidates = candidates.filter_map { |candidate| candidate.respond_to?(:to_h) ? Helpers.string_keys(candidate.to_h) : nil }
        exit_code = nil
        signal = nil
        candidates.each do |candidate|
          if exit_code.nil?
            exit_code = Helpers.key(candidate, "exit_status",
                                    Helpers.key(candidate, "exitCode", Helpers.key(candidate, "exit_code", nil)))
          end
          signal = Helpers.key(candidate, "term_signal", Helpers.key(candidate, "signal", nil)) if signal.nil?
        end
        [exit_code.nil? ? nil : Integer(exit_code), signal.nil? ? nil : Integer(signal)]
      rescue ArgumentError, TypeError
        [nil, nil]
      end

      # Every record with a running workload, for the agent's relist thread.
      def running_pod_uids
        @mutex.synchronize { @records.select { |_uid, record| record[:state] == "Running" }.keys }
      end

      # A Pod whose release failed is CleanupPending: it still owns mounts,
      # a sandbox or an address, and its record and API object wait for the
      # next attempt.  That attempt only ever came from another sync of the
      # Pod -- and a Pod already deleted from the API is synced by nobody, so
      # one unmount the kernel answered ambiguously left its ledger entries
      # in place for the rest of the node's life and every later mount that
      # drew the same kernel mount id was refused.  kubelet's volume
      # reconciler retries a failed unmount on every loop; this retries the
      # whole cleanup with a short backoff from the relist thread.  Returns
      # the uids retried.
      CLEANUP_RETRY_INITIAL_SECONDS = 5.0
      CLEANUP_RETRY_MAX_SECONDS = 60.0

      def retry_pending_cleanups(now: nil)
        moment = now || monotonic_clock.call
        pending = @mutex.synchronize do
          @records.values.select { |record| record[:state] == "CleanupPending" }.map { |record| record[:uid] }
        end
        retried = []
        pending.each do |uid|
          attempt = (@cleanup_retries ||= {})[uid.to_s]
          next if attempt && moment < attempt[:next_at]

          record = @records[uid]
          next unless record && record[:state] == "CleanupPending"
          next if @mutex.synchronize { @terminating.key?(uid.to_s) }

          count = (attempt ? attempt[:count] : 0) + 1
          delay = [CLEANUP_RETRY_INITIAL_SECONDS * (2**(count - 1)), CLEANUP_RETRY_MAX_SECONDS].min
          @cleanup_retries[uid.to_s] = {count: count, next_at: moment + delay}
          event(record, "cleanup.retry", attempt: count, errors: Array(record[:cleanup_errors]).map(&:to_s))
          retried << uid
          result = terminate(record[:pod], request_id: record[:request_id], reason: record[:reason] || "PodTerminating")
          @cleanup_retries.delete(uid.to_s) if result.nil? || result.state != "CleanupPending"
        rescue StandardError => error
          event(record, "cleanup.retry_failed", error: Helpers.failure_message(error)) if record
        end
        retried
      end

      # Pod IPs the network attached, in family order, for status and env.
      def pod_ips(record)
        network = record[:network]
        return [] unless network.is_a?(Hash)

        ips = Helpers.key(network, "ips", nil)
        ips = [Helpers.key(network, "ip", nil)].compact if ips.nil?
        Array(ips).flatten.map(&:to_s).reject(&:empty?)
      end

      alias sync reconcile

      # Execute the normative M2 order:
      # admission -> Volume -> sandbox -> network -> init -> sidecar -> app.
      def start(pod, request_id: nil)
        object = normalize_pod(pod)
        uid = pod_uid(object)
        existing = record(uid)
        return result_for(existing) if existing && existing.fetch(:state) == "Running"

        # A start attempt that follows an earlier one for the same Pod must
        # not leave the earlier attempt's volumes staged.  Stage paths are
        # keyed by Pod uid and volume name, so preparing again would try to
        # mount over a mount that is still there and fail the Pod for good.
        # kubelet keeps one idempotent volume set per Pod; here the previous
        # set is released before a new one is prepared.
        release_stale_volumes(existing) if existing
        record = new_record(object, request_id: request_id)
        # A retried start builds a fresh record, but the containers in it are
        # the same containers restarting.  Carry what the previous attempt
        # ended with so each one can report its lastState.
        record[:previous_terminations] = terminations_of(existing)
        set_state(record, "New")
        begin
          admit!(object, record)
          set_state(record, "Validated")
          # The Pod is in the desired state of the world from here on: its
          # attachable volumes are reported in use before they are mounted.
          note_attachable_volumes(object, record)
          pin_images(object, record)
          set_state(record, "ImagePinned")

          wait_for_volumes_reported_in_use(object, record)
          record[:volume] = timed(record, "volume.ready") { prepare_volume(object, record) }
          # subPaths are bound when each container's spec is built, i.e. when
          # that container starts (kubelet makeMounts): an emptyDir subPath an
          # init container fills does not exist before then.  The sandbox sees
          # binds made after it exists because the Pod root is a shared mount
          # and the holder's namespace is its slave (PodVolumes
          # #ensure_propagating_root!).
          set_state(record, "WorkspaceAllocated")

          prepare_dynamic_resources(object, record)
          record[:sandbox_id] = timed(record, "sandbox.ready") { create_sandbox(object, record) }
          raise LifecycleError, "runtime returned an empty sandbox identity" if record[:sandbox_id].to_s.empty?

          record[:sandbox_context] = network_sandbox_context(record)
          record[:resources] << {"kind" => "sandbox", "id" => record[:sandbox_id].to_s}
          set_state(record, "IsolationCreated")

          record[:network] = timed(record, "network.ready") { connect_network(object, record) }
          record[:resources] << {"kind" => "network", "id" => record[:network].to_s} unless record[:network].nil?
          apply_sysctls(object, record)
          prepare_pod_files(object, record)
          set_state(record, "ResourcesAttached")
          set_state(record, "WorkloadStopped")

          timed(record, "init.ready") { start_init_containers(object, record) }
          timed(record, "app.ready") { start_application_containers(object, record) }
          set_state(record, "Running")
          record[:phase] = "Running"
          # A reason from an earlier attempt (FailedMount, ContainerCreating)
          # describes a state the Pod has left; carrying it into a running
          # Pod's status makes `kubectl get pods` report the old failure as
          # the Pod's STATUS forever.
          record[:reason] = nil
          record[:error] = nil
          clear_start_retry(uid)
          update_status(object, record)
          persist_state!
          result_for(record)
        rescue LifecycleError => error
          fail_record(record, error)
        rescue StandardError => error
          # An unexpected exception here is a kubelet defect, not a Pod
          # condition: keep its origin (kubelet logs the stack) so the failure
          # can be diagnosed from the agent log instead of only "Pod start failed".
          frames = Array(error.backtrace).first(6).map { |frame| frame.to_s.sub(%r{\A.*/lib/rubernetes/}, "") }
          event(record, "pod.start_error", error: Helpers.failure_message(error),
                                           message: "#{Helpers.failure_message(error)} at #{frames.join(" <- ")}")
          fail_record(record, LifecycleError.new("Pod start failed: #{Helpers.failure_message(error)}"))
        end
      end

      alias create start
      alias start_pod start

      # Terminate in the observable Kubernetes order and release resources in
      # reverse acquisition order.  Cleanup errors are retained alongside the
      # original failure instead of replacing it.
      def terminate(pod_or_uid, request_id: nil, reason: "PodTerminating", terminal_phase: nil, message: nil, gone: false)
        object, uid, record = resolve_record(pod_or_uid)
        # One terminate per Pod at a time; a concurrent caller waits for the
        # running one and gets its outcome.
        first = @mutex.synchronize do
          if @terminating.key?(uid.to_s)
            @terminating_done.wait(@mutex) while @terminating.key?(uid.to_s)
            false
          else
            @terminating[uid.to_s] = true
            true
          end
        end
        unless first
          _object, _uid, current = resolve_record(pod_or_uid)
          return current ? result_for(current) : nil
        end
        begin
          terminate_once(object, uid, record, request_id: request_id, reason: reason, terminal_phase: terminal_phase,
                                              message: message, gone: gone)
        ensure
          @mutex.synchronize do
            @terminating.delete(uid.to_s)
            @terminating_done.broadcast
          end
        end
      end

      def terminate_once(object, uid, record, request_id:, reason:, terminal_phase:, message:, gone:)
        unless record
          # A Pod this node never started still has to be confirmed gone.  The
          # API server sets a deletionTimestamp and waits for the kubelet
          # whatever state the Pod reached, so one that was scheduled here and
          # never ran -- admission refused it, the namespace went away first --
          # has nothing to clean up and everything to confirm.  Returning
          # without a word left it Terminating in the API for ever.
          complete_graceful_deletion(object, {cleanup_errors: [], events: [], state: "Removed", uid: uid}) if object
          return nil
        end

        record[:phase] = "Running" if record[:phase].to_s.empty?
        record[:reason] = reason.to_s
        record[:termination_message] = message if message
        # HandlePodRemoves: a Pod whose API object is gone leaves the pod
        # manager at once, so admission stops counting it even while its
        # containers are still being killed.  Counting it refused the Pods a
        # preemption made room for ("Node didn't have enough resource").
        @mutex.synchronize { record[:config_removed] = true } if gone
        remove_endpoints(object, uid)
        set_state(record, "Stopping") unless %w[Stopped Removed].include?(record[:state])
        kill_grace = kill_grace_seconds(record, object)
        hooks_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          run_pre_stop_hooks(object, record, budget: kill_grace)
        rescue StandardError => error
          # A preStop hook that fails does not stop the kill.  kubelet records
          # a FailedPreStopHook event and carries on
          # (pkg/kubelet/kuberuntime/kuberuntime_container.go killContainer:
          # "if the pre-stop hook fails, we still want to kill the container"),
          # because the container has to go either way.  Counting it as a
          # cleanup error instead left the Pod in CleanupPending, so the node
          # never issued its final delete and the Pod stayed Terminating in the
          # API for ever -- a failed hook made the Pod immortal.
          event(record, "container.failed_prestop", reason: "FailedPreStopHook",
                                                    message: "PreStopHook failed: #{Helpers.failure_message(error)}")
        end
        # killContainer: the preStop hook spends the grace period; what is
        # left, at least the minimum, is the stop's -- unless an eviction
        # overrides it, which applies last.
        spent = Process.clock_gettime(Process::CLOCK_MONOTONIC) - hooks_started
        stop_grace = [(kill_grace - spent).ceil, MINIMUM_GRACE_PERIOD_SECONDS].max
        stop_grace = Integer(record[:grace_override]) unless record[:grace_override].nil?
        stop_containers(record, grace: stop_grace)
        clear_cleanup_error(record, "stop")
        set_state(record, "Stopped") unless record[:state] == "Stopped"
        cleanup_resources(record)
        if record[:cleanup_errors].empty?
          set_state(record, "Removed")
        else
          # A failed release is durable work, not a successful stop.  Keep the
          # record and owned resources so the next reconciliation can retry
          # cleanup after the workload has been confirmed stopped.
          set_state(record, "CleanupPending") unless record[:state] == "CleanupPending"
        end
        # kubelet getPhase for a terminal Pod: Succeeded only when every
        # container stopped with exit 0, otherwise Failed.
        if record[:cleanup_errors].empty?
          # A forced terminal phase wins over the exit-code rule: a Pod killed
          # for exceeding its deadline is Failed even when its containers were
          # stopped cleanly.
          record[:phase] = terminal_phase || terminal_phase(record)
          # A phase the kubelet forced (DeadlineExceeded, Evicted) is final
          # whatever the restart policy says.
          record[:forced_terminal] = true if terminal_phase
        end
        record[:phase] = "Unknown" unless record[:cleanup_errors].empty?
        remember_finished(record)
        record[:resources] = [] if record[:cleanup_errors].empty?
        update_status(object, record)
        withdraw_host_ports(record)
        forget_terminated_probe_and_restart_state(record)
        persist_state!
        # A Pod deleted gracefully keeps its API object until the kubelet says
        # the containers are gone; upstream's status manager then issues the
        # final delete with grace 0.  Without it a gracefully deleted Pod is
        # stopped on the node and left in the API for ever, Terminating.
        complete_graceful_deletion(object, record)
        result = result_for(record)
        # The API object is already gone (the informer delivered DELETED):
        # nothing is left to report or restart, so the record goes too.
        # Keeping it -- and its tombstone -- for every Pod the node ever ran
        # made each later Pod start slower (every persist and sync walks the
        # records): ~2,000 per conformance round.
        forget_pod(uid) if gone && record[:cleanup_errors].empty?
        result
      rescue StandardError => error
        record ||= new_record(object || {"metadata" => {"uid" => uid}}, request_id: request_id)
        fail_record(record, LifecycleError.new("Pod termination failed: #{Helpers.failure_message(error)}"), preserve_phase: true)
      end

      EVICTED_REASON = "Evicted"

      # Queue an eviction for the Pod's next sync (see #evict).
      def request_eviction(uid, message:, grace_period_seconds: nil, condition: nil, reason: EVICTED_REASON)
        @mutex.synchronize do
          @eviction_requests[uid.to_s] = {message: message, grace_period_seconds: grace_period_seconds, condition: condition,
                                          reason: reason}
        end
        true
      end

      # The eviction manager's killPodFunc (evict=true): stop the Pod within
      # +grace_period_seconds+ and report it Failed/Evicted with +message+
      # and the DisruptionTarget +condition+ (TerminationByKubelet).
      # The node shutdown manager kills the same way with reason Terminated.
      def evict(pod_or_uid, message:, grace_period_seconds: nil, condition: nil, reason: EVICTED_REASON)
        object, _uid, record = resolve_record(pod_or_uid)
        return nil unless record

        record[:grace_override] = Integer(grace_period_seconds) unless grace_period_seconds.nil?
        if condition
          record[:disruption_condition] = Helpers.string_keys(condition).merge(
            "lastTransitionTime" => Helpers.now(@clock).iso8601(6)
          )
        end
        terminate(object || record[:pod], reason: reason, terminal_phase: "Failed", message: message)
      end

      alias stop terminate
      alias delete terminate
      alias stop_pod terminate
      alias delete_pod terminate

      PROBE_EVENT_NAMES = {"startup" => "Startup", "liveness" => "Liveness", "readiness" => "Readiness"}.freeze

      # Probe one live container and restart it when liveness fails.  Readiness
      # only changes endpoint membership; it never triggers a restart.
      def probe(pod_or_uid, container_name: nil, now: nil)
        object, uid, record = resolve_record(pod_or_uid)
        raise LifecycleError, "Pod #{uid} is not running" unless record && record[:state] == "Running"

        # A container waiting out its restart backoff has no live container to
        # probe; probing the address anyway would fail liveness again and push
        # the backoff out on every sync.
        selected = record[:containers].select do |entry|
          entry[:restart_pending].nil? && (container_name.nil? || entry[:name] == container_name.to_s)
        end
        results = selected.to_h do |entry|
          definition = entry[:spec]
          container_id = entry[:id]
          probes = {
            "startupProbe" => Helpers.key(definition, "startupProbe", nil),
            "livenessProbe" => Helpers.key(definition, "livenessProbe", nil),
            "readinessProbe" => Helpers.key(definition, "readinessProbe", nil)
          }
          context = {"ports" => Helpers.key(definition, "ports", [])}
          pod_metadata = Helpers.key(object, "metadata", {})
          context["metric_labels"] = {"container" => entry[:name].to_s, "pod" => Helpers.key(pod_metadata, "name", "").to_s,
                                      "namespace" => Helpers.key(pod_metadata, "namespace", "").to_s,
                                      "pod_uid" => Helpers.key(pod_metadata, "uid", "").to_s}
          # kubelet probes the Pod IP (or the node when hostNetwork); the
          # loopback default only fits runtimes that execute the probe inside
          # the sandbox.
          probe_host = pod_ips(record).first
          probe_host = @host_ip if Helpers.key(Helpers.key(object, "spec", {}), "hostNetwork", false) == true
          context["host"] = probe_host if probe_host
          [entry[:name], @probes.evaluate(container_id, probes: probes, context: context, now: now)]
        end
        readiness_before = selected.map { |entry| entry[:status].is_a?(Hash) ? entry[:status]["ready"] : nil }
        restarted = false
        selected.each do |entry|
          result = results.fetch(entry[:name])
          # prober: every failed probe records a Warning "Unhealthy" event with the
          # probe's output ("Liveness probe failed: ...") -- without it a failing
          # probe was invisible until the Killing event.
          PROBE_EVENT_NAMES.each do |key, label|
            outcome = result[key]
            next unless outcome&.failed?

            detail = outcome.respond_to?(:message) ? outcome.message.to_s : ""
            event(record, "probe.unhealthy", name: entry[:name], container_id: entry[:id], reason: "Unhealthy",
                                             probe: key, message: "#{label} probe failed: #{detail}".rstrip)
          end
          liveness = result["liveness"]
          if liveness && liveness.failed? && @probes.liveness_failed?(entry[:id])
            restart_container(object, record, entry, reason: "LivenessProbe", now: now)
            restarted = true
          end
          readiness = result["readiness"]
          readiness_state = if readiness
                              state = @probes.state(entry[:id])
                              state[:readiness] || state["readiness"] || {failed: false}
                            end
          if readiness && readiness.failed? && readiness_state.fetch(:failed)
            remove_endpoints(object, uid)
          elsif readiness && readiness.success? && !readiness_state.fetch(:failed)
            mark_ready(object, uid)
          end
          entry[:status]["ready"] = @probes.ready?(entry[:id]) if entry[:started] && entry[:status].is_a?(Hash)
        end
        # A probe pass that changed nothing the Pod status shows -- the
        # common case, every periodSeconds for every probed container --
        # neither republishes status nor persists the node's state (kubelet
        # keeps probe results in memory only).  It was half of what the agent
        # allocated once probes ran on their own schedule.
        readiness_after = selected.map { |entry| entry[:status].is_a?(Hash) ? entry[:status]["ready"] : nil }
        # A container status replaced since the last publish (a started
        # ephemeral container, say) is published here too, as every pass did.
        if restarted || readiness_after != readiness_before || record[:published_status_signature] != status_signature(record)
          update_status(object, record)
          persist_state!
        end
        results
      end

      # Which status object each container holds: transitions replace it, so
      # a difference means something was not published yet.
      # Device health (ResourceHealthStatus) is part of it: a health change
      # alone republishes the status, as the kubelet's update channel does.
      def status_signature(record)
        record[:containers].map { |entry| [entry[:name], entry[:status].object_id, resource_health(record, entry)] }
      end

      # allocatedResourcesStatus: device plugin resources, then DRA claims.
      def resource_health(record, entry)
        health = []
        health.concat(@device_plugins.allocated_resources_status(record[:uid], entry[:name])) if @device_plugins
        if @dra_manager.respond_to?(:allocated_resources_status)
          claims = Helpers.key(Helpers.key(entry[:spec] || {}, "resources", {}) || {}, "claims", nil)
          if claims.is_a?(Array) && !claims.empty?
            health.concat(@dra_manager.allocated_resources_status(Helpers.string_keys(record[:pod]), Helpers.string_keys(entry[:spec])))
          end
        end
        health
      rescue StandardError
        # Health is informational: a failing lookup never blocks status.
        []
      end

      alias probe_containers probe

      def restart_container(pod, record = nil, entry = nil, reason: "Failure", now: nil, attempt: nil)
        object = normalize_pod(pod)
        uid = pod_uid(object)
        record ||= self.record(uid)
        raise LifecycleError, "Pod #{uid} is not running" unless record

        entry ||= record[:containers].first
        policy = container_policy(object, entry[:spec])
        restart_key = restart_identity(record, entry)
        attempt ||= @restarts.record_exit(
          restart_key, exit_code: 1, reason: reason, policy: policy,
                       at: now, liveness_failure: reason.to_s == "LivenessProbe"
        )
        return attempt unless @restarts.should_restart?(policy: policy, exit_code: 1, reason: reason,
                                                        liveness_failure: reason.to_s == "LivenessProbe")

        if reason.to_s == "LivenessProbe"
          # kubelet: events.Killing "Container <name> failed liveness probe, will be restarted"
          event(record, "container.killing", name: entry[:name], container_id: entry[:id], reason: "Killing",
                                             message: "Container #{entry[:name]} failed liveness probe, will be restarted")
        end
        remove_endpoints(object, uid)
        stop_one(entry[:id], grace_seconds(object), release_process: false)
        # kubelet keeps the dead container until its replacement starts: its
        # log is what `kubectl logs` serves while the restart backs off
        # (CrashLoopBackOff), and the e2e DNS specs read exactly that.
        # Removing it here answered every such request with "waiting to
        # start".  The retired container goes when the next one is created.
        entry[:retired_id] = entry[:id]
        last_state = if entry[:status].is_a?(Hash) && entry[:status]["state"] == "terminated"
                       {"exitCode" => Integer(entry[:status]["exitCode"] || 0), "reason" => entry[:status]["reason"].to_s}
                     else
                       {"exitCode" => reason.to_s == "LivenessProbe" ? 137 : 1, "reason" => "Error"}
                     end
        entry[:last_state] = {"terminated" => last_state}
        if attempt.delay_seconds.positive?
          # kubelet parity: while the restart backoff runs the container waits
          # in CrashLoopBackOff and reports its last termination.  The wait is
          # RECORDED rather than slept through -- sleeping here held the node's
          # whole sync loop for every other Pod, and a restart interrupted
          # anywhere after the sleep left the container waiting for ever: a
          # liveness-failing Pod restarted exactly once and then sat in
          # "back-off 10s" until it was deleted.  kubelet's SyncPod does the
          # same: the backoff is a check on the next sync, not a sleep.
          entry[:started] = false
          # kubelet reports the exited container's own restart count while it
          # waits (the CRI annotation of the container that just died); the
          # count moves when the next container is created.
          entry[:status] = {
            "state" => "waiting", "ready" => false, "started" => false,
            "restartCount" => entry[:restart_count_before_exit] || attempt.restart_count,
            "waiting" => {"reason" => "CrashLoopBackOff",
                          "message" => "back-off #{attempt.delay_seconds}s restarting failed container=#{entry[:name]} pod=#{backoff_pod_identity(
                            object, uid
                          )}"},
            "lastState" => entry[:last_state]
          }
          entry[:restart_pending] = restart_key
          entry[:restart_attempt] = attempt.restart_count
          update_status(object, record)
          persist_state!
          schedule_wakeup(uid, attempt.delay_seconds)
          return attempt
        end
        resume_restart(object, record, entry, attempt.restart_count)
        attempt
      end

      # The tail of a restart: create and start the container again, register
      # its probes, and publish it as running.
      def resume_restart(pod, record, entry, restart_count)
        object = normalize_pod(pod)
        uid = pod_uid(object)
        entry.delete(:restart_pending)
        entry.delete(:restart_attempt)
        entry[:id] = create_container(record[:sandbox_id], entry[:spec])
        # The new container is this restart count's run from now on: an exit
        # observed before this thread records the start (exit 0 within 100 ms)
        # takes the count from the status, and with the previous run's 0 there
        # the Pod finished Succeeded with restartCount 0 where 1 was due
        # ("Container Runtime blackbox test ... terminate-cmd-rpof", round 101).
        entry[:status] = entry[:status].merge("restartCount" => restart_count) if entry[:status].is_a?(Hash)
        # kubelet emits Created/Started for every restart, not only the first.
        event(record, "container.create", name: entry[:name], container_id: entry[:id])
        pre_start_container(record, entry)
        start_container(entry[:id])
        entry[:started] = true
        # The retired container served the log until this moment; now the
        # replacement has one of its own.
        if (retired = entry.delete(:retired_id))
          begin
            remove_container(retired)
          rescue StandardError => error
            event(record, "container.remove_failed", name: entry[:name], container_id: retired,
                                                     message: Helpers.failure_message(error))
          end
        end
        # A restarted container can run to completion before this thread gets
        # here: the exit observer already recorded "terminated" for this very
        # container id (exit 0, 90 ms after start).  Writing "running" over it
        # reported a Succeeded Pod's container as Running again --
        # "[sig-node] Container Runtime blackbox test ... terminate-cmd-rpof"
        # expected Terminated.  The exit wins; nothing here may undo it.
        if exited_already?(entry)
          entry[:started] = false
          event(record, "container.started", name: entry[:name], container_id: entry[:id],
                                             restart_count: restart_count, exited_before_start_recorded: true)
          update_status(object, record)
          persist_state!
          return
        end
        started_at = mark_container_started(entry, record)
        entry[:status] = {"state" => "running", "running" => {"startedAt" => started_at},
                          "ready" => false, "started" => true, "restartCount" => restart_count,
                          "lastState" => entry[:last_state]}
        @probes.register(entry[:id], probes: probes_for(entry[:spec]))
        schedule_probe_wakeup(uid, [entry], first: true)
        entry[:status]["ready"] = @probes.ready?(entry[:id])
        mark_ready(object, uid) if @probes.ready?(entry[:id])
        event(record, "container.started", name: entry[:name], container_id: entry[:id],
                                           restart_count: restart_count)
        update_status(object, record)
        persist_state!
      end

      # True exactly once per container run: the caller that wins records the
      # exit, every other observer of the same run is told it was recorded.
      def claim_exit!(entry)
        @exit_mutex ||= Mutex.new
        @exit_mutex.synchronize do
          return false if exited_already?(entry) || entry[:exit_recorded_for].to_s == entry[:id].to_s

          entry[:exit_recorded_for] = entry[:id]
          true
        end
      end

      def exited_already?(entry)
        status = entry[:status]
        status.is_a?(Hash) && status["state"] == "terminated" &&
          status.dig("terminated", "containerID").to_s == entry[:id].to_s
      end

      # Called with (pod uid, seconds) when a Pod needs a sync at a given time
      # rather than at the next periodic one (the agent enqueues it then).
      attr_accessor :wakeup
      # KubeletMetrics: sees every trace entry (started Pods and containers,
      # terminations, Pod start latency).
      attr_reader :metrics_observer
      # The kubelet-side Pod volume translation and the node's API reader
      # (the agent attaches the SELinux tracker to them).
      attr_reader :resource_reader

      # kubelet /metrics: the lifecycle's observer, and the volume operations
      # (storage_operation_duration_seconds) through the Pod volumes.
      def metrics_observer=(observer)
        @metrics_observer = observer
        report_volume_reconstruction(observer)
        return unless @pod_volumes.respond_to?(:metrics_observer=) && observer.respond_to?(:storage_operation)

        @pod_volumes.metrics_observer = lambda { |plugin, operation, status, seconds|
          observer.storage_operation(plugin, operation, status, seconds)
        }
      end

      # reconstruct_volume_operations_total: what the volume manager rebuilt
      # from its durable state when it started.
      def report_volume_reconstruction(observer)
        return unless observer.respond_to?(:volume_reconstruction) && @pod_volumes.respond_to?(:reconstruction_stats)

        stats = @pod_volumes.reconstruction_stats
        return unless stats

        observer.volume_reconstruction(stats[:attempted], stats[:errors],
                                       force_cleaned: stats[:force_cleaned].to_i, force_clean_errors: stats[:force_clean_errors].to_i)
      rescue StandardError
        nil
      end

      # A backoff ended between two periodic syncs (every five seconds) and the
      # restart waited for the next one: 2-5 s on top of each of kubelet's
      # 10/20/40 s delays ("Probing container should have monotonically
      # increasing restart count" ran 20-30 s over upstream).  The Pod is now
      # woken when its backoff ends.
      def schedule_wakeup(uid, delay)
        return if @wakeup.nil? || delay.nil?

        @wakeup.call(uid, Float(delay))
      rescue StandardError
        nil
      end

      # A container waiting out its CrashLoopBackOff is restarted by the first
      # sync that finds the backoff elapsed.
      def resume_backoff_restarts(record, pod, now: nil)
        record[:containers].each do |entry|
          key = entry[:restart_pending]
          next if key.nil?
          next unless @restarts.restart_ready?(key, now: now)

          begin
            resume_restart(pod, record, entry, entry[:restart_attempt].to_i)
          rescue StandardError => error
            # A failed re-create must not strand the container: drop the
            # pending marker so the next sync tries again rather than leaving
            # it waiting for ever.
            entry.delete(:restart_pending)
            event(record, "container.restart_failed", name: entry[:name],
                                                      message: Helpers.failure_message(error))
          end
        end
      end

      # Apply restartPolicy to a runtime-reported process exit.  Runtime
      # adapters can call this without knowing how Pod status or backoff is
      # represented internally.
      def handle_container_exit(pod_or_uid, container_name:, exit_code: 0, reason: nil, now: nil, message: nil)
        object, uid, record = resolve_record(pod_or_uid)
        raise LifecycleError, "Pod #{uid} is not known" unless record

        entry = record[:containers].find { |candidate| candidate[:name] == container_name.to_s }
        raise LifecycleError, "container #{container_name.inspect} is not known in Pod #{uid}" unless entry

        policy = container_policy(object, entry[:spec])
        restart_key = restart_identity(record, entry)
        # The relist thread and a sync worker can both find the same exited
        # container; only the first observation records it.  Both did, the
        # restart counted twice, and "Container Runtime blackbox test ...
        # terminate-cmd-rpof" saw restartCount 2 where one restart happened.
        return @restarts.attempt(restart_key, container_id: entry[:id]) unless claim_exit!(entry)

        # kubelet reports Completed for a zero exit and Error otherwise.
        reason = Integer(exit_code).zero? ? "Completed" : "Error" if reason.to_s.empty?
        # The restart count this run had; the next start (or a
        # RestartAllContainers reset) is what moves it on.
        entry[:restart_count_before_exit] = entry[:status].is_a?(Hash) ? entry[:status]["restartCount"].to_i : 0
        attempt = @restarts.record_exit(restart_key, exit_code: exit_code, reason: reason, policy: policy, at: now)
        @probes.unregister(entry[:id]) if @probes.respond_to?(:unregister)
        entry[:started] = false
        finished_at = Helpers.now(@clock).iso8601(6)
        terminated = {"exitCode" => Integer(exit_code), "reason" => reason.to_s, "finishedAt" => finished_at}
        terminated["startedAt"] = entry[:started_at] if entry[:started_at]
        terminated["containerID"] = entry[:id]
        message ||= termination_message_for(entry, exit_code: Integer(exit_code), reason: reason)
        terminated["message"] = message unless message.nil? || message.empty?
        entry[:status] = {
          "state" => "terminated", "exitCode" => Integer(exit_code), "reason" => reason.to_s,
          "terminated" => terminated,
          "ready" => false, "started" => false, "restartCount" => entry[:restart_count_before_exit]
        }
        entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
        event(record, "container.exited", name: entry[:name], container_id: entry[:id], exit_code: Integer(exit_code), reason: reason.to_s)
        remove_endpoints(object, uid) if entry[:category] == "app" && record[:containers].select do |candidate|
          candidate[:category] == "app"
        end.none? { |candidate| candidate[:started] }
        if restart_all_rule?(entry, exit_code)
          restart_all_containers(object, record, [entry])
          persist_state!
          return attempt
        end
        should_restart = @restarts.should_restart?(policy: policy, exit_code: exit_code, reason: reason,
                                                   rules: Helpers.key(entry[:spec], "restartPolicyRules", nil))
        if should_restart
          restart_container(object, record, entry, reason: reason || "Failure", now: now, attempt: attempt)
        else
          # kubelet getPhase: the Pod stays Running while any container still
          # runs; only when every app container stopped (and none restarts)
          # does it reach Succeeded/Failed.
          app_entries = record[:containers].select { |candidate| candidate[:category] == "app" }
          if app_entries.none? { |candidate| candidate[:started] }
            record[:phase] = terminal_phase(record)
            # Sidecars (restartable init containers) are stopped once the
            # last app container is gone, as kubelet does.
            stop_sidecars(record)
          end
          update_status(object, record)
        end
        persist_state!
        attempt
      end

      # kubelet: after every regular container exited, running sidecars are
      # terminated so the Pod can reach its terminal phase.
      def stop_sidecars(record)
        record[:containers].select { |entry| entry[:category] == "sidecar" && entry[:started] }.reverse_each do |entry|
          begin
            stop_one(entry[:id], grace_seconds(record[:pod]))
          rescue StandardError
            nil
          end
          entry[:started] = false
          terminated = stopped_termination(entry[:id])
          entry[:status] = {"state" => "terminated", "exitCode" => terminated.fetch("exitCode"), "reason" => terminated.fetch("reason"),
                            "terminated" => terminated, "ready" => false, "started" => false,
                            "restartCount" => entry[:status]["restartCount"].to_i}
        end
      end

      # kubelet getTerminationMessage: the termination message file (last 4 KiB)
      # or, with FallbackToLogsOnError and a failed exit, the last 80 lines /
      # 2 KiB of the container log.
      TERMINATION_MESSAGE_LIMIT = 4 * 1024
      TERMINATION_LOG_LIMIT = 2 * 1024
      TERMINATION_LOG_LINES = 80

      def termination_message_for(entry, exit_code:, reason:)
        spec = entry[:spec] || {}
        settings = Helpers.key(spec, "termination_message", nil)
        return nil unless settings.is_a?(Hash)

        host_path = Helpers.key(settings, "host_path", nil)
        message = ""
        if host_path && File.file?(host_path)
          size = File.size(host_path)
          message = File.open(host_path, "rb") do |file|
            file.seek([size - TERMINATION_MESSAGE_LIMIT, 0].max)
            file.read.to_s
          end
          message = message.dup.force_encoding(Encoding::UTF_8).scrub
        end
        failed = !Integer(exit_code).zero? || reason.to_s == "OOMKilled"
        message = tail_container_log(entry[:id]) if message.empty? && failed && Helpers.key(settings, "policy", "File").to_s == "FallbackToLogsOnError"
        message.empty? ? nil : message
      rescue StandardError
        nil
      end

      def tail_container_log(container_id)
        return "" unless @runtime.respond_to?(:logs)

        output = invoke(@runtime, :logs, container_id, follow: false, tail: TERMINATION_LOG_LINES)
        text = if output.respond_to?(:read)
                 output.read.to_s
               else
                 (output.respond_to?(:each) && !output.is_a?(String) ? output.to_a.join : output.to_s)
               end
        text = text.dup.force_encoding(Encoding::UTF_8).scrub
        text = text.lines.last(TERMINATION_LOG_LINES).join
        text.byteslice(-TERMINATION_LOG_LIMIT, TERMINATION_LOG_LIMIT) || text
      rescue StandardError
        ""
      end

      alias container_exited handle_container_exit
      alias on_container_exit handle_container_exit

      def record(pod_or_uid)
        uid = pod_uid(pod_or_uid)
        @mutex.synchronize { @records[uid] }
      end

      # What the Summary API needs of each running Pod, without the deep copy
      # #records makes of every record (a pass every 10 s for the eviction
      # manager).  The Pod objects are the stored, immutable ones.
      def stats_records
        @mutex.synchronize do
          @records.values.filter_map do |record|
            next unless record[:state].to_s == "Running" && record[:sandbox_id]

            {uid: record[:uid], state: record[:state], sandbox_id: record[:sandbox_id], pod: record[:pod],
             started_at: record[:started_at], volume: record[:volume],
             containers: Array(record[:containers]).map { |entry| {id: entry[:id], name: entry[:name], started_at: entry[:started_at]} }}
          end
        end
      end

      # The runtime containers of a Pod as the CPU manager's reconcile reads
      # them (podStatusProvider): {name:, id:, state: "running"|"exited"|"waiting"}.
      def container_states(pod_uid)
        @mutex.synchronize do
          record = @records[pod_uid.to_s]
          next [] unless record

          Array(record[:containers]).map do |entry|
            status = entry[:status].is_a?(Hash) ? entry[:status] : {}
            state = case status["state"].to_s
                    when "running" then "running"
                    when "terminated", "exited" then "exited"
                    else "waiting"
                    end
            {name: entry[:name].to_s, id: entry[:id].to_s, state: state}
          end
        end
      end

      # node.status.volumesInUse (volumeManager.GetVolumesInUse): the
      # attachable volumes of the desired state -- every admitted Pod's,
      # from admission until the Pod's containers are gone -- and of the
      # actual state -- every volume still mounted -- sorted and unique; the
      # attach/detach controller does not detach one while it is listed.
      def volumes_in_use
        @mutex.synchronize do
          @records.values.flat_map do |record|
            next [] if record[:state].to_s == "Removed"

            desired = INACTIVE_STATES.include?(record[:state].to_s) ? [] : Array(record[:attachable_volumes])
            mounted = if record[:volume].is_a?(Hash) && !(record[:cleanup_completed] || {})["volume"]
                        Array((record[:volume]["mounts"] || {}).values).filter_map { |mount| mount.is_a?(Hash) ? mount["uniqueName"] : nil }
                      else
                        []
                      end
            desired + mounted
          end.map(&:to_s).uniq.sort
        end
      end

      # Called with no arguments whenever the desired set of attachable
      # volumes changes (a node status sync is due).
      attr_accessor :volumes_in_use_observer

      # MarkVolumesAsReportedInUse: the list the Node's status now carries.
      def mark_volumes_reported_in_use(names)
        @mutex.synchronize do
          @reported_in_use = Array(names).map(&:to_s).to_h { |name| [name, true] }
          @reported_in_use_changed.broadcast
        end
        true
      end

      def volumes_reported_in_use = @mutex.synchronize { @reported_in_use.keys.sort }

      # How long a Pod start waits for its attachable volumes to be reported
      # in use (podAttachAndMountTimeout).
      VOLUME_REPORTED_IN_USE_TIMEOUT_SECONDS = 120
      attr_writer :volumes_reported_in_use_timeout

      # The Pods whose records still exist on the node (image GC's in-use set).
      def pods_on_node
        @mutex.synchronize { @records.values.filter_map { |record| record[:pod] unless record[:state].to_s == "Removed" } }
      end

      def records
        @mutex.synchronize do
          @records.transform_values { |value| immutable_record(value) }.freeze
        end
      end

      def state(pod_or_uid)
        record(pod_or_uid)&.fetch(:state, nil)
      end

      # Reconcile durable runtime and Node lifecycle state before the sync loop
      # can accept a Pod. A pending/unknown record is never treated as a fresh
      # start: it is stopped and cleaned only after the runtime has completed
      # its own identity-based observation. Failed cleanup keeps the original
      # ownership record and leaves the agent unready for a later retry.
      def recover(observer: nil, cleaner: nil, force: false)
        @mutex.synchronize do
          return Helpers.deep_copy(@recovery_report) if @recovery_done && !force
        end

        runtime_report = recover_runtime(observer: observer, cleaner: cleaner)
        runtime_hash = normalize_recovery_report(runtime_report)
        runtime_errors = Array(runtime_hash["errors"]).map(&:to_s)
        runtime_errors.concat(Array(runtime_hash["identity_mismatch"]).map do |entry|
          "resource identity mismatch: #{recovery_resource_key(entry)}"
        end)
        cleaned_orphans = Array(runtime_hash["cleaned_orphans"]).map(&:to_s)
        unresolved_orphans = Array(runtime_hash["orphans"]).filter_map do |entry|
          key = recovery_resource_key(entry)
          key unless cleaned_orphans.include?(key)
        end
        runtime_errors.concat(unresolved_orphans.map { |key| "unresolved orphan resource: #{key}" })
        recovered = []
        blocked = []
        errors = runtime_errors.dup
        # One Pod's leftover is that Pod's problem (kubelet never refuses to
        # start over one): its cleanup errors are reported per Pod, the
        # record stays CleanupPending for the periodic retry, and the node
        # comes up.  Only runtime-level errors keep the node down.
        pod_errors = {}

        pending_records.each do |record|
          uid = record.fetch(:uid)
          if record.fetch(:state) == "StateUnknown" && !recovery_record_observed?(record, runtime_hash)
            blocked << uid
            next
          end

          begin
            result = terminate(record[:pod], request_id: record[:request_id], reason: "StartupRecovery")
            if result && result.state == "Removed"
              recovered << uid
            else
              blocked << uid
              pod_errors[uid] = Array(result&.cleanup_errors).map(&:to_s)
            end
          rescue StandardError => error
            blocked << uid
            pod_errors[uid] = ["Pod #{uid} recovery failed: #{Helpers.failure_message(error)}"]
          end
        end

        report = {
          "runtime" => runtime_hash,
          "recovered" => recovered.uniq,
          "blocked" => blocked.uniq,
          "errors" => errors.uniq,
          "pod_errors" => pod_errors,
          "ready" => errors.empty?
        }
        # kubelet_orphan_pod_cleaned_volumes: the Pods this sweep tore down
        # (their volumes with them) and the ones it could not.
        if @metrics_observer.respond_to?(:orphan_pod_volumes)
          begin
            @metrics_observer.orphan_pod_volumes(recovered.uniq.length, blocked.uniq.length)
          rescue StandardError
            nil
          end
        end
        @mutex.synchronize do
          @recovery_report = Helpers.deep_copy(report).freeze
          @recovery_done = true
        end
        persist_state!
        Helpers.deep_copy(report)
      rescue StandardError
        @mutex.synchronize { @recovery_done = false }
        raise
      end

      private

      def restore_state!
        return unless @state_store

        payload = if @state_store.respond_to?(:load)
                    @state_store.load
                  elsif @state_store.respond_to?(:read)
                    @state_store.read
                  elsif @state_store.respond_to?(:call)
                    @state_store.call
                  else
                    raise LifecycleError, "lifecycle state store must implement load, read, or call"
                  end
        payload = Helpers.string_keys(payload || {})
        raise LifecycleError, "lifecycle state snapshot must be a JSON object" unless payload.is_a?(Hash)

        schema = Helpers.key(payload, "schema", nil)
        raise LifecycleError, "unsupported lifecycle state schema #{schema.inspect}" if schema && schema.to_s != "rubernetes.node.lifecycle.v1"

        Array(Helpers.key(payload, "records", [])).each do |value|
          record = restore_record(value)
          @records[record.fetch(:uid)] = record
        end
        Helpers.key(payload, "finished", {}).to_h.each { |uid, phase| @finished[uid.to_s] = phase.to_s }
        @probes.restore(Helpers.key(payload, "probes", {})) if @probes.respond_to?(:restore)
        @restarts.restore(Helpers.key(payload, "restarts", [])) if @restarts.respond_to?(:restore)
      rescue StandardError => error
        raise LifecycleError, "lifecycle state restore failed: #{Helpers.failure_message(error)}"
      end

      def pending_records
        @mutex.synchronize do
          @records.values.select { |record| %w[RollingBack CleanupPending StateUnknown].include?(record[:state]) }
        end
      end

      def recover_runtime(observer:, cleaner:)
        return {"status" => "NOT_APPLICABLE", "errors" => []} unless @runtime.respond_to?(:recover)

        observer ||= @recovery_observer
        cleaner ||= @recovery_cleaner
        callable = @runtime.method(:recover)
        options = {observer: observer, cleaner: cleaner}
        if callable.parameters.any? { |kind, _| kind == :keyrest }
          value = callable.call(**options.compact)
        else
          accepted = callable.parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
          value = callable.call(**options.select { |key, _| accepted.include?(key) })
        end
        normalize_recovery_report(value)
      rescue ArgumentError => error
        raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

        normalize_recovery_report(@runtime.recover)
      end

      def normalize_recovery_report(value)
        hash = if value.respond_to?(:to_h)
                 value.to_h
               elsif value.is_a?(Hash)
                 value
               elsif value == true
                 {"status" => "PASS", "errors" => []}
               elsif value == false
                 {"status" => "INCOMPLETE", "errors" => ["runtime recovery returned false"]}
               elsif value.nil?
                 {"status" => "INCOMPLETE", "errors" => ["runtime recovery returned no report"]}
               else
                 {"status" => "INCOMPLETE", "value" => value, "errors" => ["runtime recovery returned an invalid report"]}
               end
        Helpers.string_keys(hash || {})
      end

      def recovery_record_observed?(record, runtime_report)
        return true unless record.fetch(:state) == "StateUnknown"
        return true if runtime_report["state_unknown_observed"] == true
        return false unless @runtime.respond_to?(:resource_inventory)

        observed = Array(@runtime.resource_inventory)
        owned = Array(record[:resources]).filter_map do |resource|
          resource = Helpers.string_keys(resource)
          [resource["kind"].to_s, resource["id"].to_s, resource["identity"].to_s]
        end
        return false if owned.empty?

        owned.all? do |kind, id, identity|
          observed.any? do |entry|
            value = Helpers.string_keys(entry.respond_to?(:to_h) ? entry.to_h : entry)
            value["kind"].to_s == kind && value["id"].to_s == id && value["identity"].to_s == identity
          end
        end
      rescue StandardError
        false
      end

      def recovery_resource_key(entry)
        return entry.to_s unless entry.is_a?(Hash)

        kind = entry["kind"] || entry[:kind]
        id = entry["id"] || entry[:id]
        return entry.to_s if kind.nil? || id.nil?

        "#{kind}:#{id}"
      end

      # A Pod that finished cleanup ("Removed") carries no recovery obligation:
      # its resources were released and @finished holds the terminal phase.
      # Persisting every one of them rewrote the whole state file on EVERY
      # state transition -- 250 dead records / 10.3 MB on a conformance node,
      # and a Pod start makes ~8 transitions, so ~80 MB of JSON churn per Pod.
      # A bounded window of recent removals is kept so a restart can still
      # reason about what just went away.
      PERSISTED_REMOVED_RECORDS = 16

      def persistable_records
        live = []
        removed = []
        @records.each_value do |record|
          (record[:state].to_s == "Removed" ? removed : live) << record
        end
        (live + removed.last(PERSISTED_REMOVED_RECORDS)).map { |record| serializable_record(record) }
      end

      # The persisted records as JSON text, each re-encoded only when it
      # changed (Hash#hash of the live record, computed in C).  Converting
      # every live record on every transition was half of a busy node agent's
      # CPU: with 30 Pods starting, each of their ~15 transitions re-walked
      # all 30 records, and Pod start latency grew from 1 s to 15 s as the
      # agent's single interpreter lock saturated.
      def persistable_record_json
        live = []
        removed = []
        @records.each_value do |record|
          (record[:state].to_s == "Removed" ? removed : live) << record
        end
        cache = (@record_json_cache ||= {})
        dirty = (@dirty_records ||= {}.compare_by_identity)
        now = monotonic_clock.call
        # Every lifecycle change goes through #event or #update_status, which
        # mark the record; only marked records are encoded again.  A sweep
        # that fingerprints every record catches anything changed without a
        # mark within FULL_CHECK_SECONDS.
        full_check = @last_full_record_check.nil? || now - @last_full_record_check >= FULL_CHECK_SECONDS
        @last_full_record_check = now if full_check
        kept = {}
        encoded = (live + removed.last(PERSISTED_REMOVED_RECORDS)).map do |record|
          key = record[:uid] || record.object_id
          cached = cache[key]
          if cached && !dirty.key?(record) && !full_check
            kept[key] = cached
            next cached.last
          end
          fingerprint = record_fingerprint(record)
          json = if cached && cached.first == fingerprint
                   cached.last
                 else
                   JSON.generate(serializable_record(record))
                 end
          kept[key] = [fingerprint, json]
          json
        end
        dirty.clear
        @record_json_cache = kept
        encoded
      end

      FULL_CHECK_SECONDS = 2.0

      def mark_dirty(record)
        (@dirty_records ||= {}.compare_by_identity)[record] = true if record.is_a?(Hash)
      end

      # What decides whether a record must be encoded again.  A deeply frozen
      # part (the Pod object from the informer, container specs) cannot
      # change, so its identity stands in for its content; everything else is
      # hashed.  Hashing the whole record, frozen Pod included, was an eighth
      # of a busy agent's CPU.  (object_id is never reused in Ruby 3.4.)
      def record_fingerprint(record)
        record.map { |key, value| [key, part_fingerprint(value, 0)] }.hash
      end

      def part_fingerprint(value, depth)
        case value
        when Hash, Array
          return value.object_id if frozen_part?(value)
          return value.hash if depth >= 2

          if value.is_a?(Hash)
            value.map { |key, child| [key, part_fingerprint(child, depth + 1)] }
          else
            value.map { |child| part_fingerprint(child, depth + 1) }
          end
        else
          value.hash
        end
      end

      def frozen_part?(value)
        return false unless value.frozen?

        Helpers.deep_frozen?(value) || (defined?(Watch::Support::DEEP_FROZEN) && Watch::Support::DEEP_FROZEN.key?(value))
      end

      # Group commit: every call is numbered, and a writer persists the state
      # as it is once it holds the lock, which covers every call numbered
      # before that point.  A call whose number such a write already covers
      # returns without writing -- its change is on disk.  Each write
      # serializes every live record (~1 MB with fifteen 50-volume Pods), and
      # concurrent Pod workers used to write it once per transition each.
      def persist_state!
        return true unless @state_store

        ticket = @persist_counter_mutex.synchronize { @persist_requested += 1 }
        @persist_mutex.synchronize do
          return true if @persist_completed >= ticket

          covered = @persist_counter_mutex.synchronize { @persist_requested }
          if @state_store.respond_to?(:save_body)
            records = @mutex.synchronize { persistable_record_json }
            finished = @mutex.synchronize { @finished.transform_values { |value| value.is_a?(Hash) ? value["phase"] : value } }
            body = +%({"schema":"rubernetes.node.lifecycle.v1","records":[)
            body << records.join(",") << "],"
            body << %("probes":) << JSON.generate(@probes.respond_to?(:snapshot) ? @probes.snapshot : {}) << ","
            body << %("restarts":) << JSON.generate(@restarts.respond_to?(:snapshot) ? @restarts.snapshot : []) << ","
            body << %("finished":) << JSON.generate(finished) << "}\n"
            @state_store.save_body(body)
            @persist_completed = covered
            next true
          end
          snapshot = {
            "schema" => "rubernetes.node.lifecycle.v1",
            "records" => @mutex.synchronize { persistable_records },
            "probes" => @probes.respond_to?(:snapshot) ? @probes.snapshot : {},
            "restarts" => @restarts.respond_to?(:snapshot) ? @restarts.snapshot : [],
            "finished" => @mutex.synchronize { @finished.transform_values { |value| value.is_a?(Hash) ? value["phase"] : value } }
          }
          if @state_store.respond_to?(:save)
            @state_store.save(snapshot)
          elsif @state_store.respond_to?(:write)
            @state_store.write(snapshot)
          elsif @state_store.respond_to?(:call)
            @state_store.call(snapshot)
          else
            raise LifecycleError, "lifecycle state store must implement save, write, or call"
          end
          @persist_completed = covered
        end
        true
      rescue StandardError => error
        raise LifecycleError, "lifecycle state persist failed: #{Helpers.failure_message(error)}"
      end

      def serializable_record(record)
        json_safe(record)
      end

      # The JSON conversions of a record's FROZEN parts (a Pod object, a
      # container spec, a status snapshot, an event entry), kept between
      # persists: a deeply frozen value cannot change, so its conversion is
      # reused as it is.  Keyed by object identity (compare_by_identity), so
      # no two values ever share an entry; strong references with an LRU
      # bound, because an ObjectSpace::WeakMap drops its values at the next
      # GC (the earlier cache missed almost always).  Mutable parts (a
      # container entry, its status) are converted every time: verifying a
      # cached conversion against them costs as much as converting.
      class ConversionCache
        DEFAULT_LIMIT = 8192

        def initialize(limit: DEFAULT_LIMIT)
          @entries = {}.compare_by_identity
          @limit = Integer(limit)
        end

        def size = @entries.size

        def fetch(value)
          converted = @entries.delete(value)
          return nil if converted.nil?

          @entries[value] = converted
        end

        def store(value, converted)
          @entries.delete(value)
          @entries[value] = converted
          @entries.shift while @entries.size > @limit
          converted
        end
      end

      def json_safe(value)
        return json_safe_uncached(value) unless Helpers.deep_frozen?(value)

        cache = (@conversion_cache ||= ConversionCache.new)
        cache.fetch(value) || cache.store(value, Helpers.deep_freeze(json_safe_uncached(value)))
      end

      def json_safe_uncached(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, child), result| result[key.to_s] = json_safe(child) }
        when Array
          value.map { |child| json_safe(child) }
        when Time
          value.utc.iso8601(6)
        else
          if value.nil? || value == true || value == false || value.is_a?(Numeric) || value.is_a?(String)
            value
          elsif value.respond_to?(:to_h)
            json_safe(value.to_h)
          else
            value.to_s
          end
        end
      end

      def restore_record(value)
        hash = Helpers.string_keys(value || {})
        uid = String(Helpers.key(hash, "uid", ""))
        raise LifecycleError, "persisted lifecycle record has no uid" if uid.empty?

        state = String(Helpers.key(hash, "state", "StateUnknown"))
        allowed = RUNTIME_STATES + %w[Failed Unknown]
        raise LifecycleError, "persisted lifecycle record has invalid state #{state.inspect}" unless allowed.include?(state)

        containers = Array(Helpers.key(hash, "containers", [])).map do |entry|
          item = Helpers.string_keys(entry || {})
          {
            id: String(Helpers.key(item, "id", "")),
            name: String(Helpers.key(item, "name", "")),
            spec: Helpers.immutable(Helpers.key(item, "spec", {})),
            category: String(Helpers.key(item, "category", "app")),
            started: !!Helpers.key(item, "started", false),
            status: Helpers.string_keys(Helpers.key(item, "status", {}))
          }
        end
        {
          uid: uid,
          pod: Helpers.immutable(Helpers.key(hash, "pod", {})),
          request_id: Helpers.key(hash, "request_id", uid),
          state: state,
          phase: String(Helpers.key(hash, "phase", "Unknown")),
          status: Helpers.string_keys(Helpers.key(hash, "status", {})),
          volume: Helpers.key(hash, "volume", nil),
          sandbox_id: Helpers.key(hash, "sandbox_id", nil),
          sandbox_context: Helpers.key(hash, "sandbox_context", nil),
          network: Helpers.key(hash, "network", nil),
          images: Array(Helpers.key(hash, "images", [])),
          image_by_container: Helpers.string_keys(Helpers.key(hash, "image_by_container", {})),
          containers: containers,
          events: Array(Helpers.key(hash, "events", [])),
          resources: Array(Helpers.key(hash, "resources", [])),
          cleanup_errors: Array(Helpers.key(hash, "cleanup_errors", [])),
          cleanup_completed: Helpers.string_keys(Helpers.key(hash, "cleanup_completed", {})),
          error: Helpers.key(hash, "error", nil),
          started_at: Helpers.key(hash, "started_at", nil),
          reason: Helpers.key(hash, "reason", nil),
          # The attachable volumes reported in use for this Pod (volumesInUse
          # survives a restart, as the desired state does).
          attachable_volumes: Helpers.key(hash, "attachable_volumes", nil)
        }
      end

      def monotonic_clock
        -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      end

      def normalize_pod(pod)
        value = if pod.respond_to?(:to_h) && !pod.is_a?(Hash)
                  pod.to_h
                else
                  pod
                end
        value ||= {}
        raise ArgumentError, "Pod must be a hash" unless value.is_a?(Hash)
        raise ArgumentError, "Pod metadata.name is required" if Helpers.key(Helpers.key(value, "metadata", {}), "name", "").to_s.empty?
        return value if Helpers.immutable?(value)

        Helpers.immutable(value)
      end

      def pod_uid(pod)
        return pod.to_s unless pod.is_a?(Hash)

        metadata = Helpers.key(pod, "metadata", {})
        uid = Helpers.key(metadata, "uid", nil)
        return uid.to_s unless uid.nil? || uid.to_s.empty?

        namespace = Helpers.key(metadata, "namespace", "default")
        name = Helpers.key(metadata, "name", "")
        "#{namespace}/#{name}"
      end

      def pod_name(pod)
        metadata = Helpers.key(pod, "metadata", {})
        Helpers.key(metadata, "name", pod_uid(pod)).to_s
      end

      # The final delete of a Pod the API server marked for deletion.  Only for
      # a Pod that actually carries a deletionTimestamp, and only once its
      # cleanup succeeded: a CleanupPending record still owns resources.
      def complete_graceful_deletion(pod, record)
        return unless @pod_deleter
        return unless deletion_requested?(pod)
        return unless record[:cleanup_errors].empty?

        metadata = Helpers.key(pod, "metadata", {})
        name = Helpers.key(metadata, "name", "").to_s
        namespace = Helpers.key(metadata, "namespace", "").to_s
        return if name.empty?

        @pod_deleter.call(namespace: namespace, name: name, uid: Helpers.key(metadata, "uid", nil))
        event(record, "pod.deleted", name: name)
        # The API object is gone, so there is nothing left to start again and
        # nothing left to report: keeping the record and its tombstone only
        # grows the node's memory for every Pod it ever ran.  kubelet does the
        # same once a Pod is removed (podManager.RemovePod and
        # statusManager.RemoveOrphanedStatuses).
        forget_pod(Helpers.key(metadata, "uid", nil))
      rescue StandardError => error
        # Already gone (the namespace was deleted, or another deleter won):
        # the final delete has nothing left to do, and the record must not
        # outlive it.  Most Pods of a conformance round end this way.
        if error.message.include?("HTTP 404") || (error.respond_to?(:status) && error.status.to_i == 404)
          forget_pod(Helpers.key(Helpers.key(pod, "metadata", {}), "uid", nil))
          return
        end
        # The API can refuse or be unreachable; the next sync retries.
        event(record, "pod.delete_failed", name: Helpers.key(Helpers.key(pod, "metadata", {}), "name", nil),
                                           error: Helpers.failure_message(error))
      end

      def forget_pod(uid)
        identifier = uid.to_s
        return if identifier.empty?

        @mutex.synchronize do
          @finished.delete(identifier)
          @start_retries&.delete(identifier)
          @cleanup_retries&.delete(identifier)
        end
        @records.delete(identifier)
        remove_pod_directory(identifier)
        nil
      end

      # The Pod's own directory (etc/hosts, resolv.conf, container files)
      # goes with the record, as kubelet removes /var/lib/kubelet/pods/<uid>
      # once the Pod is gone; left behind, a worker had 316 of them after
      # one round.  The sandbox and every mount under it are gone by now.
      def remove_pod_directory(identifier)
        return unless @pod_root

        directory = File.join(@pod_root, identifier)
        FileUtils.rm_rf(directory) if File.directory?(directory)
      rescue SystemCallError
        # A directory still busy (a mount that outlived the sandbox) stays;
        # the next agent start's stale-state sweep sees it.
        nil
      end

      def deletion_requested?(pod)
        metadata = Helpers.key(pod, "metadata", {})
        !Helpers.key(metadata, "deletionTimestamp", nil).nil?
      end

      def schedule_start_retry(uid)
        if (record = @records[uid])
          event(record, "container.backoff", message: "Back-off restarting failed container in pod #{pod_name(record[:pod])}")
        end
        @start_retries ||= {}
        attempt = @start_retries[uid.to_s] || {count: 0}
        count = attempt[:count] + 1
        delay = [START_BACKOFF_INITIAL_SECONDS * (2**(count - 1)), START_BACKOFF_MAX_SECONDS].min
        @start_retries[uid.to_s] = {count: count, next_at: monotonic_clock.call + delay}
      end

      def start_retry_pending?(uid)
        attempt = (@start_retries ||= {})[uid.to_s]
        return false unless attempt

        monotonic_clock.call < attempt[:next_at]
      end

      def clear_start_retry(uid)
        (@start_retries ||= {}).delete(uid.to_s)
      end

      # True while this Pod is waiting to be started again after a failed
      # attempt, whether or not its backoff has elapsed.
      def start_retry_scheduled?(uid)
        (@start_retries ||= {}).key?(uid.to_s)
      end

      def new_record(pod, request_id: nil)
        uid = pod_uid(pod)
        record = {
          uid: uid,
          pod: pod,
          request_id: request_id || uid,
          state: "New",
          phase: "Pending",
          status: {},
          volume: nil,
          sandbox_id: nil,
          sandbox_context: nil,
          network: nil,
          images: [],
          image_by_container: {},
          # spec.volumes[].image references -> the pinned image (digest,
          # unpacked rootfs), and the resolver handles to release with them.
          volume_images: {},
          volume_image_handles: [],
          containers: [],
          events: [],
          resources: [],
          cleanup_errors: [],
          cleanup_completed: {},
          error: nil,
          started_at: nil,
          reason: nil,
          termination_message: nil
        }
        @mutex.synchronize { @records[uid] = record }
        persist_state!
        record
      end

      def immutable_record(record)
        Helpers.deep_freeze(Helpers.deep_copy(record))
      end

      def record_for(uid)
        @mutex.synchronize { @records[uid] }
      end

      # A Pod is finished when a terminal phase was reached and its restart
      # policy does not call for another attempt.  Either the live record or
      # the Pod's own published status is proof: after a completed termination
      # the local record is gone, and only the reported phase remains.
      def pod_finished?(pod, record, uid = nil)
        # Checked before the restart policy: a Pod the kubelet itself failed
        # (activeDeadlineSeconds, eviction) is terminal even with
        # restartPolicy Always -- upstream never restarts a Failed Pod, and
        # restarting one here brought an evicted Pod straight back.
        return true if uid && @mutex.synchronize { @finished.key?(uid.to_s) }
        return true if record && record[:forced_terminal]

        policy = Helpers.key(Helpers.key(pod, "spec", {}), "restartPolicy", "Always").to_s
        return false if policy == "Always"

        phases = []
        phases << record[:phase].to_s if record
        phases << Helpers.key(Helpers.key(pod, "status", {}), "phase", "").to_s
        return true if phases.include?("Succeeded")

        policy == "Never" && phases.include?("Failed")
      end

      # The record that reached the terminal phase, which is not necessarily the
      # one in @records: a stray restart can have replaced it.
      def terminal_record(uid, existing)
        remembered = @mutex.synchronize { @finished[uid.to_s] }
        return existing unless remembered.is_a?(Hash)
        return existing if existing && existing[:phase].to_s == remembered["phase"].to_s

        remembered.fetch("record")
      end

      # Remember a Pod that reached a terminal phase so no later sync starts it
      # again, whatever the reported status says by then.
      def remember_finished(record)
        policy = Helpers.key(Helpers.key(record[:pod] || {}, "spec", {}), "restartPolicy", "Always").to_s
        return if record[:phase].to_s == "Pending"

        phase = record[:phase].to_s
        forced = record[:forced_terminal] && %w[Failed Succeeded].include?(phase)
        return if policy == "Always" && !forced
        return unless forced || phase == "Succeeded" || (policy == "Never" && phase == "Failed")

        # The tombstone exists to stop a later sync from starting this Pod
        # again, and to republish the terminal status; the diagnostic event
        # trail is no part of that.  Copying it too made every finished Pod
        # keep tens of kilobytes alive for the life of the process.
        snapshot = Marshal.load(Marshal.dump(record))
        snapshot[:events] = []
        @mutex.synchronize { @finished[record[:uid].to_s] = {"phase" => phase, "record" => snapshot} }
      end

      DEADLINE_EXCEEDED_REASON = "DeadlineExceeded"
      DEADLINE_EXCEEDED_MESSAGE = "Pod was active on the node longer than the specified deadline"

      # kubelet's podIsActiveDeadlineExceeded: measured from the Pod's start
      # time on THIS node, and only while it is still running.
      def active_deadline_exceeded?(record, pod, now: nil)
        return false unless record.is_a?(Hash)
        return false unless %w[Running Pending].include?(record[:phase].to_s)
        return false if %w[Stopped Removed].include?(record[:state].to_s)

        deadline = Helpers.key(Helpers.key(pod, "spec", {}), "activeDeadlineSeconds", nil)
        return false if deadline.nil?

        seconds = begin
          Integer(deadline)
        rescue StandardError
          nil
        end
        return false unless seconds && seconds.positive?

        started = record[:started_at]
        return false if started.nil?

        started = Time.parse(started.to_s) unless started.is_a?(Time)
        ((now || @clock.call).to_f - started.to_f) >= seconds
      rescue ArgumentError, TypeError
        false
      end

      # kubelet's convertToAPIContainerStatuses always stamps state.running
      # .startedAt, and carries it onto state.terminated.startedAt when the
      # container exits.  Ours reported `startedAt: null`, which every client
      # that measures container runtime reads as "never started".  The Pod's
      # own startTime is the first container start, which is also what
      # activeDeadlineSeconds counts from.
      def mark_container_started(entry, record)
        started_at = Helpers.now(@clock).iso8601(6)
        entry[:started_at] = started_at
        record[:started_at] ||= started_at
        started_at
      end

      # A Pod is Succeeded only if its app containers ran and every one of
      # them exited zero.  This used to answer "Succeeded" for a Pod whose
      # containers had NEVER run -- nothing had exited non-zero, so nothing
      # looked failed -- and a Pod whose container cannot be created was
      # reported as completed while its own container status still said
      # Waiting/CreateContainerConfigError.  kubelet keeps that Pod Pending
      # and retries creating the container ("[sig-node] Variable Expansion
      # should verify that a failing subpath expansion can be modified during
      # the lifetime of a container" waits for exactly that Pending).
      def terminal_phase(record)
        app_entries = record[:containers].select { |entry| entry[:category] == "app" }
        ran = app_entries.any? { |entry| entry[:status].is_a?(Hash) }
        unless ran
          return "Failed" if TERMINAL_START_REASONS.include?(record[:reason].to_s)

          return "Pending"
        end
        failed = app_entries.any? do |entry|
          entry[:status].is_a?(Hash) && Integer(entry[:status]["exitCode"] || 0) != 0
        end
        failed ? "Failed" : "Succeeded"
      end

      def result_for(record)
        Result.new(
          pod_uid: record[:uid], state: record[:state], phase: record[:phase],
          status: Helpers.immutable(record[:status] || {}),
          events: Helpers.immutable(record[:events] || []),
          resources: Helpers.immutable(record[:resources] || []),
          error: record[:error], cleanup_errors: Helpers.immutable(record[:cleanup_errors] || [])
        ).freeze
      end

      def set_state(record, state)
        state = state.to_s
        raise LifecycleError, "unknown lifecycle state #{state.inspect}" unless RUNTIME_STATES.include?(state) || %w[Failed Unknown].include?(state)

        previous = record[:state]
        record[:state] = state
        event(record, "state", from: previous, to: state)
      end

      # How much of a Pod's own history the node keeps.
      #
      # The trail is diagnostic, not durable state, and it is APPENDED TO ON
      # EVERY SYNC: a Pod that is retried -- a crash-looping container, a
      # cleanup that has not finished -- adds entries for as long as it lives.
      # Unbounded, one Pod's record reached tens of kilobytes and the node's
      # resident memory grew into the gigabytes over a single conformance run,
      # which slows every Pod on the node down with it.  The most recent
      # entries are the ones worth having.
      MAX_RECORD_EVENTS = 200

      def event(record, type, payload = {})
        mark_dirty(record)
        entry = {"type" => type.to_s, "state" => record[:state], "at" => Helpers.now(@clock).iso8601(6)}
        entry.merge!(Helpers.string_keys(payload))
        # An entry never changes once recorded.  Frozen, json_safe converts
        # it once and reuses the conversion on every later persist of the
        # record (a record's ~200 entries were re-walked on each transition).
        Helpers.deep_freeze(entry)
        events = record[:events]
        events << entry
        events.shift(events.length - MAX_RECORD_EVENTS) if events.length > MAX_RECORD_EVENTS
        @event_sink.call(record[:uid], entry) if @event_sink
        @metrics_observer&.observe(record, entry)
      end

      # A hostPort is a node-wide resource: two Pods cannot both have it.
      #
      # kubelet's own admission refuses the second one (PodFitsHostPorts in
      # lifecycle/predicate.go GeneralPredicates), which is what makes the Pod
      # Failed so its controller can replace it.  Admitting both instead let
      # each install its own DNAT rule for the same port and neither Pod ever
      # failed -- "[sig-apps] StatefulSet Should recreate evicted statefulset"
      # waits for exactly that failure, because it deliberately parks a Pod on
      # the port the StatefulSet wants.
      HOST_PORT_CONFLICT_REASON = "PodFitsHostPorts"

      def host_port_conflict(pod)
        wanted = host_port_claims(pod)
        return nil if wanted.empty?

        uid = pod_uid(pod)
        @records.each do |other_uid, other|
          next if other_uid.to_s == uid.to_s
          next if %w[Stopped Removed CleanupPending].include?(other[:state].to_s)
          next if %w[Succeeded Failed].include?(other[:phase].to_s)
          # A Pod still in admission holds nothing yet, and one admission
          # refused never will (kubelet's predicate counts admitted Pods
          # only).  Counting them let a StatefulSet's rapidly recreated Pod
          # collide with its own previous incarnation for ever: "host port
          # 21017 is already used by ss-0" for five minutes after the real
          # conflicting Pod was gone ("Should recreate evicted statefulset").
          next if other[:state].to_s == "New" || other[:reason].to_s == "PodAdmissionFailed"

          taken = host_port_claims(other[:pod])
          conflict = wanted.find { |claim| taken.any? { |held| host_ports_collide?(claim, held) } }
          return [conflict, pod_name(other[:pod])] if conflict
        end
        nil
      end

      # A claim on 0.0.0.0 collides with every address on that port.
      def host_ports_collide?(left, right)
        return false unless left[:port] == right[:port] && left[:protocol] == right[:protocol]

        left[:ip] == right[:ip] || left[:ip] == "0.0.0.0" || right[:ip] == "0.0.0.0"
      end

      def host_port_claims(pod)
        spec = Helpers.key(pod || {}, "spec", {})
        containers = Array(Helpers.key(spec, "initContainers", [])) + Array(Helpers.key(spec, "containers", []))
        containers.flat_map do |container|
          Array(Helpers.key(Helpers.string_keys(container), "ports", [])).filter_map do |value|
            port = Helpers.string_keys(value)
            number = Helpers.key(port, "hostPort", nil)
            next nil if number.nil? || number.to_i.zero?

            {port: number.to_i,
             protocol: Helpers.key(port, "protocol", "TCP").to_s.upcase,
             ip: Helpers.key(port, "hostIP", "0.0.0.0").to_s}
          end
        end
      end

      # The Pods this node has admitted and not finished with: what the
      # kubelet's predicate admit handler sizes the node's remaining room by.
      INACTIVE_STATES = %w[Stopped Removed CleanupPending RollingBack].freeze

      def admitted_pods(except: nil)
        @mutex.synchronize do
          @records.values.filter_map do |candidate|
            next if candidate[:uid].to_s == except.to_s
            next if INACTIVE_STATES.include?(candidate[:state].to_s) || %w[Succeeded Failed].include?(candidate[:phase].to_s)
            next if candidate[:config_removed]
            # A Pod whose eviction is queued (preemption, node pressure) is
            # being killed: the kubelet no longer counts it as active.
            next if @eviction_requests.key?(candidate[:uid].to_s)
            next if %w[New].include?(candidate[:state].to_s) && candidate[:containers].to_a.empty? && candidate[:sandbox_id].nil?

            candidate[:pod]
          end
        end
      end
      # The agent's activePods for the shutdown, eviction, QoS, container
      # and DRA managers (it checks respond_to?, which a private method fails).
      public :admitted_pods

      def admit!(pod, record)
        if (conflict = host_port_conflict(pod))
          claim, holder = conflict
          record[:reason] = "PodAdmissionFailed"
          record[:admission_reason] = HOST_PORT_CONFLICT_REASON
          raise LifecycleError,
                "admission rejected Pod #{pod_name(pod)}: #{HOST_PORT_CONFLICT_REASON}: " \
                "host port #{claim[:port]}/#{claim[:protocol]} on #{claim[:ip]} is already used by #{holder}"
        end
        result = run_admission(pod)
        allowed = Helpers.success_result?(result)
        # lifecycle/predicate.go Admit: a refusal goes to the admission failure
        # handler (critical-Pod preemption); once it made room the Pod is
        # judged again against what is left.
        attempts = 0
        while !allowed && @preemption && attempts < PREEMPTION_ATTEMPTS
          attempts += 1
          begin
            break unless @preemption.handle_admission_failure(pod, result)
          rescue Preemption::Error => error
            result = {"reason" => Preemption::UNEXPECTED_REASON, "message" => Preemption.unexpected_message(error)}
            break
          end
          event(record, "pod.preempted_others", attempt: attempts)
          result = run_admission(pod)
          allowed = Helpers.success_result?(result)
        end
        return allocate_devices!(pod, record) if allowed

        reason, message = if result.is_a?(Hash)
                            [Helpers.key(result, "reason", "Rejected"),
                             Helpers.key(result, "message", "Pod was rejected by node admission")]
                          elsif result.respond_to?(:reason) && result.respond_to?(:message)
                            [result.reason || "Rejected", result.message || "Pod was rejected by node admission"]
                          else
                            ["Rejected", "Pod was rejected by node admission"]
                          end
        # kubelet: an admission rejection is terminal (phase Failed with the
        # admission reason); every other start failure is retried.
        record[:reason] = "PodAdmissionFailed"
        record[:admission_reason] = reason.to_s
        raise LifecycleError, "admission rejected Pod #{pod_name(pod)}: #{reason}: #{message}"
      end

      # One admission per resource a preemption can free (cpu, memory,
      # ephemeral-storage, pods, ...), then the refusal stands.
      PREEMPTION_ATTEMPTS = 4

      def run_admission(pod)
        if @admission.nil?
          true
        elsif @admission.respond_to?(:admit?)
          @admission.admit?(pod)
        elsif @admission.respond_to?(:admit) && accepts_keyword?(@admission, :admit, :other_pods)
          @admission.admit(pod, other_pods: admitted_pods(except: pod_uid(pod)))
        elsif @admission.respond_to?(:admit)
          @admission.admit(pod)
        elsif @admission.respond_to?(:call)
          @admission.call(pod)
        else
          raise LifecycleError, "admission dependency must implement admit? or admit"
        end
      end

      # devicemanager Allocate in the admit handler: a request the plugins
      # cannot meet rejects the Pod (UnexpectedAdmissionError).
      def allocate_devices!(pod, record)
        return true if @device_plugins.nil?

        @device_plugins.remove_stale(@records.keys)
        @device_plugins.allocate_pod(Helpers.string_keys(pod))
        true
      rescue DevicePlugins::Manager::Error => error
        record[:reason] = "PodAdmissionFailed"
        record[:admission_reason] = "UnexpectedAdmissionError"
        raise LifecycleError,
              "admission rejected Pod #{pod_name(pod)}: UnexpectedAdmissionError: Allocate failed due to #{error.message}, which is unexpected"
      end

      # The container's device plugin allocation: environment, device nodes
      # and mounts from Allocate, and its CDI devices.
      def apply_device_plugin_allocation(record, spec, definition)
        return spec if @device_plugins.nil?

        allocation = @device_plugins.container_allocation(record[:uid], Helpers.key(definition, "name", ""))
        return spec if allocation.nil?

        env = Array(spec["env"]).map(&:dup)
        allocation["envs"].each do |name, value|
          env.reject! { |entry| entry["name"] == name }
          env << {"name" => name.to_s, "value" => value.to_s}
        end
        spec["env"] = env
        mounts = Array(spec["mounts"]).dup
        allocation["mounts"].each_with_index do |mount, index|
          mounts << {"name" => "device-plugin-mount-#{index}", "source" => mount["host_path"].to_s, "destination" => mount["container_path"].to_s,
                     "readonly" => mount["read_only"] == true, "propagation" => "None"}
        end
        allocation["devices"].each_with_index do |device, index|
          host = device["host_path"].to_s
          raise LifecycleError, "device plugin device #{host} does not exist on the node" unless File.exist?(host)

          mount = {"name" => "device-plugin-device-#{index}", "source" => host,
                   "destination" => (device["container_path"].to_s.empty? ? host : device["container_path"].to_s),
                   "readonly" => false, "propagation" => "None", "device" => true}
          # DeviceSpec.permissions ("rwm" subset) become the cgroup rule.
          mount["permissions"] = device["permissions"].to_s unless device["permissions"].to_s.empty?
          mounts << mount
        end
        spec["mounts"] = mounts
        ids = allocation["cdi_devices"].map { |device| device["name"].to_s }.reject(&:empty?)
        spec = CDI.apply(spec, CDI.resolve(ids, spec_dirs: @cdi_spec_dirs)) unless ids.empty?
        spec
      rescue CDI::Error => error
        record[:reason] = "CreateContainerError"
        raise LifecycleError,
              "container #{Helpers.key(definition, "name", "").inspect}: device plugin CDI injection failed: #{error.message}"
      end

      def release_stale_volumes(existing)
        return unless @pod_volumes

        handle = existing[:volume]
        return unless handle.is_a?(Hash)
        return if existing[:cleanup_completed] && existing[:cleanup_completed]["volume"]

        event(existing, "volume.release_stale")
        @pod_volumes.release(existing[:pod], handle, token: "release-stale-#{existing[:uid]}")
        existing[:cleanup_completed]["volume"] = true if existing[:cleanup_completed]
      rescue StandardError => error
        # The next prepare will fail loudly if the stage really is still
        # there; losing the reason for that here would hide it.
        event(existing, "volume.release_stale_failed", "error" => Helpers.failure_message(error))
      end

      # The trail is the only place a Pod start can be broken down after the
      # fact, and "how long did this step take" is the question it is read to
      # answer.  Without it, locating the 21 s in a 27 s start meant diffing
      # the timestamps of whatever unrelated events happened to bracket it.
      def timed(record, type, payload = {})
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = yield
        event(record, type, payload.merge(seconds: (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(3)))
        result
      end

      # desiredStateOfWorldPopulator.processPodVolumes for this Pod: the
      # attachable volumes it names, kept on the record (durably) so the node
      # status reports them from now until the Pod is gone.
      def note_attachable_volumes(pod, record)
        return unless @pod_volumes.respond_to?(:attachable_volume_names)

        names = @pod_volumes.attachable_volume_names(pod)
        return if names.empty?

        record[:attachable_volumes] = names
        event(record, "volume.desired", volumes: names)
        @volumes_in_use_observer&.call
      rescue StandardError => error
        event(record, "volume.desired_failed", error: Helpers.failure_message(error))
      end

      # reconciler.waitForVolumeAttach: an attachable volume is mounted only
      # after the node status reported it in use (so the attach/detach
      # controller knows the node holds it).  Without a status publisher
      # (no observer) there is nobody to wait for.
      def wait_for_volumes_reported_in_use(pod, record)
        names = Array(record[:attachable_volumes])
        return if names.empty? || @volumes_in_use_observer.nil?

        timeout = @volumes_reported_in_use_timeout || VOLUME_REPORTED_IN_USE_TIMEOUT_SECONDS
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        # The Pod's claim-backed volume names, for the kubelet's message.
        volume_names = Array(Helpers.key(Helpers.key(pod, "spec", {}), "volumes", [])).filter_map do |volume|
          name = Helpers.key(volume, "name", "").to_s
          name if Helpers.key(volume, "persistentVolumeClaim", nil) || Helpers.key(volume, "ephemeral", nil)
        end
        @mutex.synchronize do
          loop do
            missing = names.reject { |name| @reported_in_use.key?(name) }
            return if missing.empty?

            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            if remaining <= 0
              record[:reason] = "FailedMount"
              raise LifecycleError,
                    "Unable to attach or mount volumes: unmounted volumes=#{volume_names}, " + "unattached volumes=#{volume_names}, failed to process " \
                                                                                               "volumes=[]: timed out waiting for the condition"
            end
            @volumes_in_use_observer&.call
            @reported_in_use_changed.wait(@mutex, [remaining, 1.0].min)
          end
        end
      end

      def prepare_volume(pod, record)
        event(record, "volume.prepare")
        if @pod_volumes
          begin
            handle = @pod_volumes.prepare(pod, token: "prepare-#{record[:uid]}", host_ip: @host_ip,
                                               images: record[:volume_images] || {})
          rescue PodVolumes::MissingDependency, PodVolumes::Unsupported, PodVolumes::SELinuxConflict => error
            record[:reason] = "FailedMount"
            raise LifecycleError, "MountVolume.SetUp failed: #{error.message}"
          end
          record[:resources] << {"kind" => "volume", "id" => Array(handle["ids"]).join(",")} unless Array(handle["ids"]).empty?
          return handle
        end

        handle = if @volume.nil?
                   nil
                 elsif @volume.respond_to?(:prepare)
                   @volume.prepare(pod)
                 elsif @volume.respond_to?(:prepare_pod)
                   @volume.prepare_pod(pod)
                 elsif @volume.respond_to?(:mount)
                   @volume.mount(pod)
                 elsif @volume.respond_to?(:setup)
                   @volume.setup(pod)
                 else
                   raise LifecycleError, "volume dependency does not implement prepare, mount, or setup"
                 end
        record[:resources] << {"kind" => "volume", "id" => handle.to_s} unless handle.nil?
        handle
      end

      # Resolve every container image before the first volume, filesystem,
      # network, or runtime effect. The resolver is an explicit dependency so
      # pure tests never perform registry I/O accidentally.
      # One image, for pin_images' pull threads: the resolved image, or the
      # exception the pull raised (re-raised by the caller in order).
      def resolve_image(reference, keyring, pull_policy = nil, on_pull = nil)
        resolve_with_keyring(reference, keyring, pull_policy, on_pull)
      rescue StandardError => error
        error
      end

      # KubeletEnsureSecretPulledImages: the resolver also learns which Secret
      # the credential came from and every Secret of the Pod for the image,
      # when it takes them.
      def resolve_with_keyring(reference, keyring, pull_policy = nil, on_pull = nil)
        credential = keyring&.lookup(reference)
        keywords = {}
        keywords[:on_pull] = on_pull if on_pull && resolver_accepts?(:on_pull)
        keywords[:credentials] = credential.to_h if credential
        keywords[:pull_policy] = pull_policy.to_s unless pull_policy.to_s.empty?
        if resolver_accepts?(:pull_secret)
          keywords[:pull_secret] = credential.pull_secret if credential.respond_to?(:pull_secret) && credential.pull_secret
          keywords[:pod_credentials] = lambda do
            secrets = keyring.respond_to?(:lookup_all) ? keyring.lookup_all(reference).filter_map(&:pull_secret) : []
            account = keyring.respond_to?(:service_account_for) ? keyring.service_account_for(reference) : nil
            [secrets.reject { |secret| secret[:service_account] }, account]
          end
        end
        keywords.empty? ? invoke(@image_resolver, :resolve, reference) : invoke(@image_resolver, :resolve, reference, **keywords)
      end

      def resolver_accepts?(keyword)
        @resolver_keywords ||= begin
          parameters = @image_resolver.method(:resolve).parameters
          if parameters.any? { |kind, _| kind == :keyrest }
            :any
          else
            parameters.filter_map do |kind, name|
              name if %i[key keyreq].include?(kind)
            end
          end
        rescue StandardError
          []
        end
        @resolver_keywords == :any ? false : @resolver_keywords.include?(keyword)
      end

      def pin_images(pod, record)
        definitions = []
        spec = Helpers.key(pod, "spec", {})
        Array(Helpers.key(spec, "initContainers", [])).each_with_index do |definition, index|
          definitions << ["init", index, Helpers.string_keys(definition)]
        end
        Array(Helpers.key(spec, "containers", [])).each_with_index do |definition, index|
          definitions << ["app", index, Helpers.string_keys(definition)]
        end
        return if definitions.empty?

        references = definitions.filter_map { |_category, _index, definition| Helpers.key(definition, "image", nil) }
        if @image_resolver.nil?
          if native_runtime? && references.any? { |reference| !reference.to_s.empty? }
            raise LifecycleError, "image resolver is required before starting a Native Pod"
          end

          return
        end

        cache = {}
        keyring = image_keyring(pod)
        definitions.each do |_category, _index, definition|
          reference = Helpers.key(definition, "image", nil)
          raise LifecycleError, "container #{Helpers.key(definition, "name", "").inspect} has no image" if reference.to_s.empty?
        end
        # A Pod's distinct images are pulled side by side (kubelet's parallel
        # image pulls); one after the other, a DNS spec's Pod waited for
        # agnhost and then for jessie-dnsutils.
        pending = definitions.each_with_object({}) do |(_category, _index, definition), unique|
          unique[Helpers.key(definition, "image", nil).to_s] ||= Helpers.key(definition, "name", nil)
        end
        # imagePullPolicy per image: Always when any container of it asks,
        # Never only when all of them do.
        policies = definitions.group_by { |_category, _index, definition| Helpers.key(definition, "image", nil).to_s }
          .transform_values do |entries|
          values = entries.map { |_category, _index, definition| Helpers.key(definition, "imagePullPolicy", nil).to_s }
          if values.include?("Always") then "Always"
          elsif !values.empty? && values.all?("Never") then "Never"
          elsif values.include?("IfNotPresent") then "IfNotPresent"
          end
        end
        # kubelet's image manager reports each image as it gets there: Pulling
        # when a pull starts, then per container Pulled with the pull's time
        # and size, or "already present" (see image_events).  A resolver that
        # cannot tell pulls apart only has Pulling, up front.
        reports = pending.keys.to_h { |cache_key| [cache_key, {}] }
        reporting = resolver_accepts?(:on_pull)
        lock = Mutex.new
        pending.each { |cache_key, name| event(record, "image.resolve", reference: cache_key, name: name) } unless reporting
        pulls = pending.keys.map do |cache_key|
          reporter = reporting ? image_reporter(record, cache_key, pending[cache_key], reports[cache_key], lock) : nil
          [cache_key, Thread.new { resolve_image(cache_key, keyring, policies[cache_key], reporter) }]
        end
        failure = nil
        pulls.each do |cache_key, thread|
          outcome = thread.value
          if outcome.is_a?(Exception)
            failure ||= [cache_key, outcome]
            next
          end
          cache[cache_key] = outcome
        end
        image_events(record, definitions, reports, failure) if reporting
        if failure
          cache_key, error = failure
          raise error if error.is_a?(LifecycleError)

          if defined?(::Rubernetes::Image::NeverPullError) && error.is_a?(::Rubernetes::Image::NeverPullError)
            # ErrImageNeverPull: pull policy Never and the image is not here.
            record[:reason] = "ErrImageNeverPull"
            raise LifecycleError, error.message
          end
          # kubelet: a pull that fails leaves the container Waiting with
          # reason ErrImagePull (ImagePullBackOff while the retry waits)
          # and the Pod Pending; e2e reads exactly that reason.
          record[:reason] = "ErrImagePull"
          raise LifecycleError, "Failed to pull image #{cache_key.inspect}: #{Helpers.failure_message(error)}"
        end
        pending.each_key do |cache_key|
          resolved = cache.fetch(cache_key)
          raise LifecycleError, "image resolver returned no image for #{cache_key.inspect}" if resolved.nil?

          record[:images] << resolved
        end
        definitions.each do |category, index, definition|
          reference = Helpers.key(definition, "image", nil)
          image_hash = image_to_hash(cache.fetch(reference.to_s), reference)
          record[:image_by_container][image_key(category, index)] = image_hash
        end
        # An image volume (spec.volumes[].image) is pulled and pinned like a
        # container image; its unpacked rootfs is what the volume mounts,
        # read-only.  It is kept apart from record[:images], which are the
        # containers' own overlay lowerdirs.
        Array(Helpers.key(spec, "volumes", [])).each do |volume|
          entry = Helpers.string_keys(volume)
          source = Helpers.key(entry, "image", nil)
          next unless source.is_a?(Hash)

          reference = Helpers.key(source, "reference", nil).to_s
          raise LifecycleError, "image volume #{Helpers.key(entry, "name", "").inspect} has no reference" if reference.empty?
          next if record[:volume_images].key?(reference)

          resolved = ensure_image(record, reference, nil, keyring, Helpers.key(source, "pullPolicy", nil),
                                  volume: Helpers.key(entry, "name", nil))
          raise LifecycleError, "image resolver returned no image for #{reference.inspect}" if resolved.nil?

          record[:volume_image_handles] << resolved
          record[:volume_images][reference] = image_to_hash(resolved, reference)
        end
        digests = record[:images].map { |image| image_to_hash(image).fetch("digest") }.uniq.sort
        raise LifecycleError, "image resolver returned no pinned digest" if digests.empty?

        record[:image_digest] = "sha256:#{::Digest::SHA256.hexdigest(JSON.generate(digests))}"
        event(record, "image.pinned", digests: digests, aggregate_digest: record[:image_digest])
      end

      # One image outside the Pod's start sweep (an ephemeral container, an
      # image volume), with the same events.
      def ensure_image(record, reference, name, keyring, policy, volume: nil)
        unless resolver_accepts?(:on_pull)
          event(record, "image.resolve", **{reference: reference, name: name, volume: volume}.compact)
          return resolve_with_keyring(reference, keyring, policy)
        end

        report = {}
        outcome = resolve_image(reference, keyring, policy, image_reporter(record, reference, name, report, Mutex.new))
        definition = {"image" => reference, "name" => name, "imagePullPolicy" => policy}.compact
        image_events(record, [[nil, nil, definition]], {reference => report}, outcome.is_a?(Exception) ? [reference, outcome] : nil)
        raise outcome if outcome.is_a?(Exception)

        outcome
      end

      # One image's pull as the resolver reports it (Image::Resolver#resolve
      # on_pull), from its pull thread.
      def image_reporter(record, reference, name, report, lock)
        lambda do |stage, *details|
          case stage
          when :present then report[:present] = details.first
          when :required then report[:required] = true
          when :start
            report[:pulled] = true
            lock.synchronize { event(record, "image.resolve", reference: reference, name: name) }
          when :done
            report[:seconds], report[:size] = details
            report[:finished_at] = Helpers.now(@clock).iso8601(6)
          when :failed then report[:error] = details.first
          end
        end
      end

      # EnsureImageExists, container by container in start order: the first
      # container of an image reports its pull (Pulled, Failed or
      # ErrImageNeverPull), every later one finds it already present.  It
      # stops at the container whose image failed, as kubelet does, and
      # counts kubelet_image_manager_ensure_image_requests_total.
      def image_events(record, definitions, reports, failure)
        failed, error = failure
        never = defined?(::Rubernetes::Image::NeverPullError) && error.is_a?(::Rubernetes::Image::NeverPullError)
        seen = {}
        definitions.each do |_category, _index, definition|
          reference = Helpers.key(definition, "image", nil).to_s
          name = Helpers.key(definition, "name", nil)
          policy = Helpers.key(definition, "imagePullPolicy", nil).to_s
          report = seen.key?(reference) ? {present: true} : reports.fetch(reference, {})
          seen[reference] = true
          if reference == failed && never
            # policy Never: not here, or not usable by this Pod.
            required = report[:required] ? "true" : "unknown"
            event(record, "image.never_pull", reference: reference, name: name, policy: policy, present: report[:present],
                                              required: required)
            break
          elsif reference == failed
            # Only a pull that ran reports Failed; credentials that could not
            # be read end EnsureImageExists before it.
            if report[:pulled]
              event(record, "image.pull_failed", reference: reference, name: name, policy: policy, present: report[:present],
                                                 error: (report[:error] || error).message.to_s)
            end
            break
          elsif report[:pulled]
            event(record, "image.pulled", reference: reference, name: name, policy: policy, present: report[:present],
                                          seconds: report[:seconds].to_f, size: report[:size].to_i, finished_at: report[:finished_at])
          else
            event(record, "image.present", reference: reference, name: name, policy: policy)
          end
        end
      end

      def create_sandbox(pod, record)
        event(record, "sandbox.create")
        runtime_class = Helpers.key(Helpers.key(pod, "spec", {}), "runtimeClassName", nil)
        runtime_class = @runtime_class_resolver.call(pod) if @runtime_class_resolver
        runtime_input = pod
        unless record[:images].empty?
          runtime_input = Helpers.deep_copy(pod)
          runtime_input["resolved_images"] = record[:images].map { |image| image_to_hash(image) }
          runtime_input["image_digest"] = record[:image_digest]
          runtime_input["lowerdirs"] = record[:images].filter_map do |image|
            image_to_hash(image)["rootfs"]
          end.uniq
        end
        if @container_spec
          runtime_input = Helpers.deep_copy(runtime_input) if runtime_input.equal?(pod)
          # kubelet: the UTS hostname is spec.hostname or the Pod name.
          runtime_input["hostname"] = @container_spec.pod_hostname(pod)
        end
        if @runtime.respond_to?(:run_sandbox)
          invoke(@runtime, :run_sandbox, runtime_input, runtime_class: runtime_class)
        elsif @runtime.respond_to?(:create_sandbox)
          invoke(@runtime, :create_sandbox, runtime_input, runtime_class: runtime_class)
        else
          raise LifecycleError, "runtime does not implement run_sandbox or create_sandbox"
        end
      end

      # imagePullSecrets (Pod + ServiceAccount) become the registry keyring
      # for this Pod's pulls; without a resource reader there is nothing to
      # read them from and pulls stay anonymous.
      def image_keyring(pod)
        return nil unless @resource_reader || @credential_providers

        keyring = ImageCredentials.for_pod(pod, reader: @resource_reader, providers: @credential_providers)
        keyring.empty? ? nil : keyring
      rescue StandardError => error
        raise LifecycleError, "imagePullSecrets could not be read: #{Helpers.failure_message(error)}"
      end

      # kubelet applies spec.securityContext.sysctls to the sandbox's network
      # and IPC namespaces once they exist; admission already refused unsafe
      # ones.
      def apply_sysctls(pod, record)
        sysctls = Array(Helpers.key(Helpers.key(Helpers.key(pod, "spec", {}), "securityContext", {}) || {}, "sysctls", []))
        sysctls = sysctls.map { |entry| Helpers.string_keys(entry) }.reject { |entry| entry["name"].to_s == "" }
        return if sysctls.empty?
        raise LifecycleError, "runtime does not apply sysctls" unless @runtime.respond_to?(:apply_sysctls)

        event(record, "sysctls.apply", sysctls: sysctls.map { |entry| "#{entry["name"]}=#{entry["value"]}" })
        invoke(@runtime, :apply_sysctls, record[:sandbox_id], sysctls)
      end

      def connect_network(pod, record)
        event(record, "network.connect", sandbox_id: record[:sandbox_id])
        return nil unless @network

        sandbox = network_sandbox_context(record)

        result = if @network.respond_to?(:add)
                   invoke(@network, :add, sandbox, pod)
                 elsif @network.respond_to?(:connect)
                   invoke(@network, :connect, sandbox, pod)
                 elsif @network.respond_to?(:setup)
                   invoke(@network, :setup, sandbox, pod)
                 else
                   raise LifecycleError, "network dependency does not implement add, connect, or setup"
                 end
        if result.is_a?(Hash) || result.respond_to?(:to_h)
          record[:network] =
            Helpers.string_keys(result.respond_to?(:to_h) ? result.to_h : result)
        end
        publish_host_ports(pod, record)
        result
      end

      # containerPort.hostPort has to be programmed on the node once the Pod
      # has an address; nothing did, so a Pod with a hostPort was scheduled and
      # then unreachable.
      def publish_host_ports(pod, record)
        return if @host_ports.nil?

        mappings = Network::HostPort.mappings_for(pod)
        return if mappings.empty?

        ips = pod_ips(record)
        return if ips.empty?

        ips.each do |ip|
          family = ip.include?(":") ? :ipv6 : :ipv4
          published = @host_ports.ensure!(pod_uid: record[:uid], pod_ip: ip, pod: pod, family: family)
          next if published.nil? || published.empty?

          event(record, "network.host_ports_published",
                ports: published.map { |mapping| "#{mapping.protocol}/#{mapping.host_port}->#{mapping.container_port}" })
        end
      rescue StandardError => error
        raise LifecycleError, "host port publication failed: #{Helpers.failure_message(error)}"
      end

      def withdraw_host_ports(record)
        return if @host_ports.nil?

        %i[ipv4 ipv6].each { |family| @host_ports.remove!(pod_uid: record[:uid], family: family) }
      rescue StandardError
        nil
      end

      # An init container whose exit matches a RestartAllContainers rule
      # resets the Pod and the init sequence runs again from the first one.
      def start_init_containers(pod, record)
        loop do
          break unless run_init_containers(pod, record) == :restart_all
        end
      end

      def run_init_containers(pod, record)
        spec = Helpers.key(pod, "spec", {})
        Array(Helpers.key(spec, "initContainers", [])).each_with_index do |definition, index|
          definition = Helpers.string_keys(definition)
          name = Helpers.key(definition, "name", "")
          event(record, "init.start", name: name)
          category = restartable_init?(definition) ? "sidecar" : "init"
          entry = create_entry(record, definition, category: category, index: index)
          record[:containers] << entry
          start_entry(entry, record)
          if restartable_init?(definition)
            event(record, "init.sidecar.running", name: name)
            next
          end
          exit_status = wait_for_init(entry, record)
          if restart_all_rule?(entry, init_exit_code(exit_status))
            reset_all_containers(pod, record, [entry])
            return :restart_all
          end
          unless init_success?(exit_status)
            record[:reason] = "Init:Error"
            record_failed_init_exit(record, entry, exit_status)
            raise LifecycleError, "init container #{name.inspect} failed"
          end
          # kubelet reports a completed init container as Ready and no longer
          # started (kubelet/status: initialized init containers are ready).
          entry[:status] = status_hash(exit_status, fallback: {"state" => "terminated", "exitCode" => 0})
            .merge("ready" => true, "started" => false, "restartCount" => entry[:status]["restartCount"].to_i)
          entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
          entry[:started] = false
          event(record, "init.completed", name: name)
        end
        :completed
      end

      def init_exit_code(exit_status)
        return 0 if init_success?(exit_status)

        code = Helpers.key(status_hash(exit_status), "exitCode", nil)
        code.nil? ? 1 : Integer(code)
      rescue ArgumentError, TypeError
        1
      end

      # container.restartPolicyRules: does this exit match a rule whose action
      # is RestartAllContainers?
      def restart_all_rule?(entry, exit_code)
        rule = @restarts.matching_restart_rule(Helpers.key(entry[:spec], "restartPolicyRules", nil), exit_code)
        rule && Helpers.key(rule, "action", nil).to_s == "RestartAllContainers"
      end

      RESTARTING_ALL_CONTAINERS = "RestartingAllContainers"
      RESTARTING_ALL_CONTAINERS_MESSAGE = "The container is removed because RestartAllContainers in place"

      # kuberuntime SyncPod with restartAllContainers (KEP-5532): a container
      # exited with a RestartAllContainers rule, so every init, sidecar and
      # regular container is killed without grace and removed -- the
      # containers that did not trigger it first, the source last -- while
      # the sandbox, its network and its volumes stay.  The Pod then starts
      # again from its first init container.  The rule was matched and
      # treated as a plain restart of the one container that exited.
      def restart_all_containers(pod, record, sources)
        object = normalize_pod(pod)
        reset_all_containers(object, record, sources)
        begin
          start_init_containers(object, record)
          start_application_containers(object, record)
        rescue LifecycleError => error
          fail_record(record, error)
          return
        rescue StandardError => error
          fail_record(record, LifecycleError.new("Pod restart failed: #{Helpers.failure_message(error)}"))
          return
        end
        record[:reason] = nil
        record[:error] = nil
        update_status(object, record)
      end

      def reset_all_containers(pod, record, sources)
        object = normalize_pod(pod)
        uid = record[:uid]
        resettable = record[:containers].reject { |entry| entry[:category] == "ephemeral" }
        targets = resettable - sources
        by_category = ->(entries, app) { entries.select { |entry| (entry[:category] == "app") == app } }
        ordered = by_category.call(targets, true) + by_category.call(targets, false) +
                  by_category.call(sources, true) + by_category.call(sources, false)
        event(record, "pod.restart_all_containers", sources: sources.map { |entry| entry[:name] })
        remove_endpoints(object, uid)
        record[:restarting_all] = true
        record[:previous_terminations] = {} unless record[:previous_terminations].is_a?(Hash)
        ordered.each do |entry|
          if entry[:started]
            event(record, "container.killing", name: entry[:name], container_id: entry[:id], reason: "Killing", message: "killing")
            entry[:started] = false
            begin
              stop_one(entry[:id], 0)
            rescue StandardError
              nil
            end
          end
          @probes.unregister(entry[:id]) if @probes.respond_to?(:unregister)
          [entry.delete(:retired_id), entry[:id]].compact.each do |container_id|
            remove_container(container_id)
          rescue StandardError => error
            event(record, "container.remove_failed", name: entry[:name], container_id: container_id,
                                                     message: Helpers.failure_message(error))
          end
          entry.delete(:restart_pending)
          terminated = {"exitCode" => 137, "reason" => RESTARTING_ALL_CONTAINERS, "message" => RESTARTING_ALL_CONTAINERS_MESSAGE}
          before = entry.delete(:restart_count_before_exit)
          before = nil unless sources.include?(entry)
          before = entry[:status].is_a?(Hash) ? entry[:status]["restartCount"].to_i : 0 if before.nil?
          restart_count = before + 1
          @restarts.advance_restart_count(restart_identity(record, entry), to: restart_count)
          entry[:last_state] = {"terminated" => terminated}
          entry[:status] = {"state" => "waiting", "ready" => false, "started" => false, "restartCount" => restart_count,
                            "waiting" => {"reason" => RESTARTING_ALL_CONTAINERS, "message" => RESTARTING_ALL_CONTAINERS_MESSAGE},
                            "lastState" => entry[:last_state]}
          record[:previous_terminations][entry[:name].to_s] = entry[:last_state]
        end
        # Published once with AllContainersRestarting=True while nothing runs.
        update_status(object, record)
        persist_state!
        record[:containers] = record[:containers] - resettable
        record[:restarting_all] = false
      end

      # A non-zero init container exit is a container exit like any other: it
      # is what the restart backoff counts and what the next attempt reports as
      # its previous state.  Only the app-container path recorded exits, so an
      # init container that failed on every attempt stayed at restartCount 0
      # with an empty lastState no matter how long the Pod had been looping.
      def record_failed_init_exit(record, entry, exit_status)
        status = status_hash(exit_status, fallback: {"state" => "terminated", "exitCode" => 1})
        exit_code = Helpers.key(status, "exitCode", 1).to_i
        terminated = {"exitCode" => exit_code, "reason" => "Error",
                      "finishedAt" => Helpers.now(@clock).iso8601(6), "containerID" => entry[:id]}
        terminated["startedAt"] = entry[:started_at] if entry[:started_at]
        attempt = @restarts.record_exit(restart_identity(record, entry), exit_code: exit_code, reason: "Error",
                                                                         policy: container_policy(record[:pod], entry[:spec]))
        entry[:started] = false
        entry[:status] = status.merge("state" => "terminated", "exitCode" => exit_code, "reason" => "Error",
                                      "terminated" => terminated, "ready" => false, "started" => false,
                                      "restartCount" => attempt.respond_to?(:restart_count) ? attempt.restart_count : 0)
        entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
        entry[:last_state] = {"terminated" => terminated}
      end

      def start_application_containers(pod, record)
        spec = Helpers.key(pod, "spec", {})
        Array(Helpers.key(spec, "containers", [])).each_with_index do |definition, index|
          definition = Helpers.string_keys(definition)
          name = Helpers.key(definition, "name", "")
          event(record, "app.start", name: name)
          entry = create_entry(record, definition, category: "app", index: index)
          record[:containers] << entry
          start_entry(entry, record)
        end
      end

      def restartable_init?(definition)
        Helpers.key(definition, "restartPolicy", nil).to_s == "Always"
      end

      def create_entry(record, definition, category:, index:)
        definition = Helpers.deep_copy(definition)
        # Restartable init containers are represented as sidecars for runtime
        # status/restart policy, but their image was pinned in the init list.
        # Keep the source-list key stable so a sidecar cannot silently lose its
        # digest/entrypoint on the first start or on a restart.
        source_category = category == "sidecar" ? "init" : category
        if (resolved_image = record[:image_by_container][image_key(source_category, index)])
          definition["resolved_image"] = resolved_image
        end
        definition = build_container_spec(record, definition, category: category, index: index)
        container_id = create_container(record[:sandbox_id], definition)
        if container_id.to_s.empty?
          raise LifecycleError,
                "runtime returned an empty container identity for #{Helpers.key(definition, "name", "")}"
        end

        name = Helpers.key(definition, "name", "").to_s
        # A Pod whose start failed is started again from a fresh record, so the
        # container object is new -- but it is the SAME container restarting,
        # and kubelet numbers it as such.  Seeding from zero reported
        # restartCount 0 for ever no matter how many times the Pod had been
        # through this, which is exactly what an init container that keeps
        # failing is counted by.
        entry = {
          id: container_id.to_s,
          name: name,
          spec: definition,
          category: category,
          started: false,
          status: {"state" => "waiting", "ready" => false,
                   "restartCount" => previous_restart_count(record, name)}
        }
        if (last = previous_termination(record, name))
          entry[:last_state] = last
          entry[:status]["lastState"] = last
        end
        entry
      end

      def previous_restart_count(record, name)
        return 0 unless @restarts.respond_to?(:restart_count)

        @restarts.restart_count("#{record[:uid]}/#{name}").to_i
      rescue StandardError
        0
      end

      # What each container of the previous attempt ended with, keyed by name.
      def terminations_of(previous)
        return {} unless previous.is_a?(Hash)

        Array(previous[:containers]).each_with_object({}) do |entry, result|
          state = entry[:last_state] || begin
            terminated = entry[:status].is_a?(Hash) ? entry[:status]["terminated"] : nil
            terminated.nil? ? nil : {"terminated" => terminated}
          end
          result[entry[:name].to_s] = state if state
        end
      end

      # The terminated state of the previous attempt, so a restarted container
      # reports where it came from (status.lastState.terminated).
      def previous_termination(record, name)
        terminations = record[:previous_terminations]
        terminations.is_a?(Hash) ? terminations[name.to_s] : nil
      end

      # kubelet generateContainerConfig: the Pod container definition becomes
      # the runtime spec only after env, security context, mounts and the
      # termination message file are resolved against the live Pod.
      def build_container_spec(record, definition, category:, index:)
        return definition unless @container_spec

        pod = record[:pod]
        spec = @container_spec.build(
          pod: pod, container: definition, category: category, index: index,
          resolved_image: definition["resolved_image"], volumes: record[:volume].is_a?(Hash) ? record[:volume] : {},
          pod_files: record[:pod_files] || {}, pod_ips: pod_ips(record), host_ip: @host_ip,
          pod_directory: pod_directory(record)
        )
        spec = apply_cdi_devices(record, spec, definition)
        spec = apply_device_plugin_allocation(record, spec, definition)
        apply_resource_affinity(record, spec, definition)
      rescue ContainerSpec::ConfigError, PodVolumes::Error => error
        record[:reason] = "CreateContainerConfigError"
        raise LifecycleError, "container #{Helpers.key(definition, "name", "").inspect}: #{error.message}"
      end

      # PreCreateContainer: the container's cpuset.cpus (its exclusive CPUs,
      # or the shared pool) and cpuset.mems (its NUMA nodes), as explicit
      # cgroup settings.
      def apply_resource_affinity(record, spec, definition)
        return spec unless @container_manager && spec.is_a?(Hash)

        limits = @container_manager.container_limits(Helpers.string_keys(record[:pod]), Helpers.string_keys(definition))
        return spec if limits.empty?

        spec["limits"] = Helpers.string_keys(spec["limits"] || {}).merge(limits)
        spec
      end

      # PreStartContainer.
      def pre_start_container(record, entry)
        return unless @container_manager

        @container_manager.pre_start(Helpers.string_keys(record[:pod]), Helpers.string_keys(entry[:spec] || {}), entry[:id])
      end

      # Raised when a Pod's claims cannot be prepared; the kubelet reports
      # FailedPrepareDynamicResources and retries, the Pod stays
      # ContainerCreating.
      class DynamicResourcesError < LifecycleError; end

      def dynamic_resources?(pod)
        return false if @dra_manager.nil?

        !Array(Helpers.key(Helpers.key(pod, "spec", {}), "resourceClaims", [])).empty? ||
          !Helpers.key(Helpers.key(pod, "status", {}), "extendedResourceClaimStatus", nil).nil?
      end

      # kuberuntime SyncPod: PrepareDynamicResources before the sandbox.
      def prepare_dynamic_resources(pod, record)
        return unless dynamic_resources?(pod)

        timed(record, "dra.prepared") { @dra_manager.prepare_resources(Helpers.string_keys(pod)) }
        record[:dra_prepared] = true
      rescue StandardError => error
        detail = error.is_a?(DRAManager::Error) ? error.message : Helpers.failure_message(error)
        message = "Failed to prepare dynamic resources: #{detail}"
        event(record, "pod.dra_prepare_failed", message: message)
        record[:reason] = "ContainerCreating"
        raise DynamicResourcesError, message
      end

      # GetResources: the container's CDI devices, applied through CDI edits
      # (containerd's "CDI device injection").
      def apply_cdi_devices(record, spec, definition)
        return spec unless dynamic_resources?(record[:pod])
        if Array(Helpers.key(Helpers.key(definition, "resources", {}), "claims", [])).empty? &&
           Helpers.key(Helpers.key(record[:pod], "status", {}), "extendedResourceClaimStatus", nil).nil?
          return spec
        end

        ids = @dra_manager.container_cdi_devices(Helpers.string_keys(record[:pod]), Helpers.string_keys(definition))
        return spec if ids.empty?

        CDI.apply(spec, CDI.resolve(ids, spec_dirs: @cdi_spec_dirs))
      rescue CDI::Error, DRAManager::Error => error
        record[:reason] = "CreateContainerError"
        raise LifecycleError, "container #{Helpers.key(definition, "name", "").inspect}: CDI device injection failed: #{error.message}"
      end

      def pod_directory(record)
        return nil unless @pod_root

        File.join(@pod_root, record[:uid].to_s)
      end

      # /etc/hosts, /etc/hostname and /etc/resolv.conf for the Pod, plus a
      # second pass over downward API projections now that the Pod IP exists.
      def prepare_pod_files(pod, record)
        return unless @pod_root

        directory = File.join(pod_directory(record), "etc")
        writer = @pod_files || PodFiles.new
        host_network = Helpers.key(Helpers.key(pod, "spec", {}), "hostNetwork", false) == true
        ips = host_network ? [@host_ip].compact : pod_ips(record)
        begin
          record[:pod_files] = writer.write(pod, directory: directory, pod_ips: ips, host_network: host_network,
                                                 hostname: @container_spec ? @container_spec.pod_hostname(pod) : nil)
        rescue PodFiles::Error => error
          record[:reason] = "CreateContainerConfigError"
          raise LifecycleError, error.message
        end
        event(record, "pod.files", files: record[:pod_files].keys)
        return unless @pod_volumes && record[:volume].is_a?(Hash)

        @pod_volumes.refresh(pod, record[:volume], pod_ips: ips, host_ip: @host_ip) if @pod_volumes.respond_to?(:refresh)
      end

      # kubelet's periodic sync also revisits the Pod's volumes: projected
      # ServiceAccount tokens are rotated before they expire (a token that
      # ran out took every in-cluster client with it) and ConfigMap / Secret
      # / downward API content is re-projected when it changed.
      # Projected volume contents follow the Pod's labels and annotations, which
      # only a periodic sync can notice -- but rebuilding every projected file
      # on every housekeeping tick is most of what the node spends its CPU on.
      # kubelet refreshes them on its own sync frequency (~60s); this keeps the
      # refresh well inside what clients wait for without paying for it every
      # few seconds.
      VOLUME_SYNC_INTERVAL_SECONDS = 15.0

      def projected_metadata(pod)
        metadata = Helpers.key(pod || {}, "metadata", {})
        [Helpers.key(metadata, "labels", nil), Helpers.key(metadata, "annotations", nil)]
      end

      def volume_sync_due?(record)
        now = monotonic_clock.call
        last = record[:last_volume_sync]
        return true if last.nil? || (now - last) >= VOLUME_SYNC_INTERVAL_SECONDS

        false
      end

      def sync_volumes(record, pod)
        record[:last_volume_sync] = monotonic_clock.call
        return unless @pod_volumes && record[:volume].is_a?(Hash)

        ips = pod_ips(record)
        if @pod_volumes.respond_to?(:rotate_tokens)
          rotated = @pod_volumes.rotate_tokens(pod, record[:volume], pod_ips: ips, host_ip: @host_ip)
          event(record, "volume.tokens_rotated", volumes: rotated) unless rotated.empty?
        end
        if @pod_volumes.respond_to?(:expand_in_use)
          @pod_volumes.expand_in_use(pod, record[:volume]).each do |name, outcome, message|
            event(record, outcome == :resized ? "volume.fs_resized" : "volume.fs_resize_failed", volume: name, message: message)
          end
        end
        if @pod_volumes.respond_to?(:republish_csi)
          republished = @pod_volumes.republish_csi(pod, record[:volume])
          event(record, "volume.republished", volumes: republished) unless republished.empty?
        end
        return unless @pod_volumes.respond_to?(:refresh_contents)

        refreshed = @pod_volumes.refresh_contents(pod, record[:volume], pod_ips: ips, host_ip: @host_ip)
        event(record, "volume.contents_refreshed", volumes: refreshed) unless refreshed.empty?
      rescue StandardError => error
        event(record, "volume.sync_failed", error: error.message)
      end

      def start_entry(entry, record)
        event(record, "container.create", name: entry[:name], container_id: entry[:id])
        pre_start_container(record, entry)
        start_container(entry[:id])
        entry[:started] = true
        started_at = mark_container_started(entry, record)
        entry[:status] = {"state" => "running", "running" => {"startedAt" => started_at},
                          "ready" => false, "started" => true,
                          "restartCount" => entry[:status]["restartCount"].to_i}
        entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
        @probes.register(entry[:id], probes: probes_for(entry[:spec]), started_at: @clock.call)
        schedule_probe_wakeup(record[:uid], [entry], first: true)
        # Without a readiness probe a running container is Ready (kubelet parity).
        entry[:status]["ready"] = @probes.ready?(entry[:id])
        run_post_start_hook(entry, record)
        @restarts.record_start(restart_identity(record, entry), policy: container_policy(record[:pod], entry[:spec]))
        event(record, "container.started", name: entry[:name], container_id: entry[:id])
      end

      def wait_for_init(entry, _record)
        if @runtime.respond_to?(:wait_container)
          invoke(@runtime, :wait_container, entry[:id])
        elsif @runtime.respond_to?(:wait)
          invoke(@runtime, :wait, entry[:id])
        elsif @runtime.respond_to?(:container_status)
          invoke(@runtime, :container_status, entry[:id])
        else
          raise LifecycleError, "runtime cannot confirm init container exit"
        end
      end

      def init_success?(value)
        # A missing wait result is an unknown/timeout outcome.  Treating nil
        # as exit 0 lets an init container race ahead of the runtime and makes
        # recovery indistinguishable from a successful completion.
        return false if value.nil?
        return true if value == true

        if value.respond_to?(:exit_status)
          exit_status = value.exit_status
          term_signal = value.respond_to?(:term_signal) ? value.term_signal : nil
          return false if exit_status.nil? && term_signal.nil?

          return Integer(exit_status).zero? unless exit_status.nil?

          return false
        end
        if value.is_a?(Hash)
          exit_code = Helpers.key(value, "exitCode", Helpers.key(value, "exit_code", Helpers.key(value, "code", nil)))
          if value.key?("exitCode") || value.key?("exit_code") || value.key?("code") || value.key?(:exitCode) || value.key?(:exit_code) || value.key?(:code)
            return false if exit_code.nil?

            return Integer(exit_code).zero?
          end
          return false if Helpers.key(value, "state", nil).to_s.match?(/\A(?:created|running|waiting|pending)\z/i)

          return Helpers.success_result?(value) if value.key?("success") || value.key?("allowed") || value.key?(:success) || value.key?(:allowed)
          return false if value.key?("state") || value.key?(:state)

          status = Helpers.key(value, "status", nil)
          return Helpers.success_result?(value) if status.is_a?(Numeric)

          return false
        end
        return value.to_i.zero? if value.is_a?(Numeric)

        Helpers.success_result?(value)
      end

      def status_hash(value, fallback: {})
        result = value.is_a?(Hash) ? Helpers.string_keys(value) : {}
        result.empty? ? fallback : result
      end

      def probes_for(definition)
        {
          "startupProbe" => Helpers.key(definition, "startupProbe", nil),
          "livenessProbe" => Helpers.key(definition, "livenessProbe", nil),
          "readinessProbe" => Helpers.key(definition, "readinessProbe", nil)
        }
      end

      def run_post_start_hook(entry, record)
        handler = Helpers.key(Helpers.key(entry[:spec], "lifecycle", {}), "postStart", nil)
        return if handler.nil?

        event(record, "postStart", name: entry[:name])
        execute_hook(entry[:id], handler, record: record)
      end

      # kuberuntime killContainer: minimumGracePeriodInSeconds.
      MINIMUM_GRACE_PERIOD_SECONDS = 2

      # setTerminationGracePeriod: an eviction's override, else the
      # deletion's (a force delete is 0), else the Pod's
      # terminationGracePeriodSeconds.  The preStop hook runs only when it is
      # above zero, and within it.
      def kill_grace_seconds(record, object)
        grace = record[:grace_override]
        if grace.nil?
          deletion = Helpers.key(Helpers.key(object || {}, "metadata", {}), "deletionGracePeriodSeconds", nil)
          grace = deletion.nil? ? grace_seconds(record[:pod]) : Integer(deletion)
        end
        [Integer(grace), 0].max
      rescue ArgumentError, TypeError
        grace_seconds(record[:pod])
      end

      # executePreStopHook runs within the grace period: a hook still running
      # when it ends is abandoned and the container killed.
      def run_pre_stop_hooks(_pod, record, budget: nil)
        return if budget && !budget.positive?

        deadline = budget && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + budget)
        record[:containers].reverse_each do |entry|
          handler = Helpers.key(Helpers.key(entry[:spec], "lifecycle", {}), "preStop", nil)
          next if handler.nil? || !entry[:started]

          remaining = deadline ? deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC) : HOOK_TIMEOUT_SECONDS
          break unless remaining.positive?

          event(record, "preStop", name: entry[:name])
          execute_hook(entry[:id], handler, timeout: deadline ? remaining : HOOK_TIMEOUT_SECONDS, record: record,
                                            grace_bounded: !deadline.nil?)
        end
      end

      HOOK_TIMEOUT_SECONDS = 30.0

      def wait_for_exec(result, timeout:)
        status = if result.respond_to?(:fetch) && result.respond_to?(:key?) && result.key?(:status)
                   result[:status]
                 elsif result.respond_to?(:status)
                   result.status
                 end
        drain = Thread.new do
          %i[stdout stderr].each do |name|
            stream = result.respond_to?(:key?) && result.key?(name) ? result[name] : nil
            next unless stream.respond_to?(:read)

            begin
              loop { break if stream.read(65_536).nil? }
            rescue StandardError
              nil
            end
          end
        end
        if status.respond_to?(:pop)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout)
          loop do
            value = status.pop(true)
            return value
          rescue ThreadError
            break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

            sleep 0.05
          end
        else
          drain.join(timeout)
        end
        nil
      ensure
        drain&.join(1)
      end

      def execute_hook(container_id, handler, timeout: HOOK_TIMEOUT_SECONDS, record: nil, grace_bounded: false)
        definition = Helpers.string_keys(handler)
        if (exec = Helpers.key(definition, "exec", nil))
          command = Array(Helpers.key(exec, "command", []))
          raise LifecycleError, "lifecycle exec command must not be empty" if command.empty?

          # kubelet runs the hook synchronously and only then stops the
          # container; returning with the stream open let the container be
          # killed while the hook's command was still running.
          wait_for_exec(invoke(@runtime, :exec, container_id, command, tty: false), timeout: timeout)
        elsif (http = Helpers.key(definition, "httpGet", nil))
          raise LifecycleError, "runtime does not implement lifecycle HTTP hook" unless @runtime.respond_to?(:http_get)

          # A lifecycle hook is not a probe: it gets the hook timeout, not the
          # one-second default a readiness check is happy with.  A postStart or
          # preStop hook calls another Pod over the network, and under load one
          # second is not enough to reach it -- and a hook that "fails" on a
          # timeout is a hook the workload never received.
          http_hook(container_id, Helpers.string_keys(http), [timeout, HOOK_TIMEOUT_SECONDS].min, record)
        elsif (tcp = Helpers.key(definition, "tcpSocket", nil))
          raise LifecycleError, "runtime does not implement lifecycle TCP hook" unless @runtime.respond_to?(:tcp_socket)

          invoke(@runtime, :tcp_socket, container_id, tcp, timeout: [timeout, HOOK_TIMEOUT_SECONDS].min)
        elsif (sleep_action = Helpers.key(definition, "sleep", nil))
          wanted = Integer(Helpers.key(sleep_action, "seconds", 0) || 0)
          seconds = [wanted, timeout].min
          @sleeper.call(seconds) if seconds.positive?
          # runSleepHandler: the grace period ended first.
          if grace_bounded && wanted > timeout
            event(record, "hook.sleep_terminated") if record
            raise LifecycleError, "container terminated before sleep hook finished"
          end
        else
          raise LifecycleError, "lifecycle hook must define exec, httpGet, tcpSocket, or sleep"
        end
      end

      # runHTTPHandler: an HTTPS hook answered in plain HTTP is retried over
      # HTTP without the Authorization header, and the fallback reported
      # (LifecycleHTTPFallback, kubelet_lifecycle_handler_http_fallbacks_total).
      HTTP_RESPONSE_TO_HTTPS = /server gave HTTP response to HTTPS client|wrong version number|packet length too long|record layer failure/i

      def http_hook(container_id, http, timeout, record)
        invoke(@runtime, :http_get, container_id, http, timeout: timeout)
      rescue StandardError => error
        raise unless Helpers.key(http, "scheme", "").to_s.casecmp("HTTPS").zero? && error.message.match?(HTTP_RESPONSE_TO_HTTPS)

        plain = http.merge("scheme" => "HTTP")
        plain["httpHeaders"] = Array(http["httpHeaders"]).reject do |header|
          header.is_a?(Hash) && header["name"].to_s.casecmp("Authorization").zero?
        end
        result = invoke(@runtime, :http_get, container_id, plain, timeout: timeout)
        host = Helpers.join_host_port(Helpers.key(http, "host", nil) || record_pod_ip(record) || "127.0.0.1", Helpers.key(http, "port", 80))
        event(record, "hook.http_fallback", host: host) if record
        result
      end

      def record_pod_ip(record)
        record ? pod_ips(record).first : nil
      rescue StandardError
        nil
      end

      def stop_containers(record, grace: nil)
        grace ||= record[:grace_override] || grace_seconds(record[:pod])
        record[:containers].reverse_each do |entry|
          next unless entry[:started]

          event(record, "container.term", name: entry[:name], container_id: entry[:id])
          # kubelet: events.Killing "Stopping container <name>"
          event(record, "container.killing", name: entry[:name], container_id: entry[:id], reason: "Killing",
                                             message: "Stopping container #{entry[:name]}")
          (@stop_details ||= {}).delete(entry[:id])
          stopped = stop_one(entry[:id], grace)
          raise LifecycleError, "container #{entry[:name].inspect} did not reach a confirmed stopped state" unless stopped

          entry[:started] = false
          terminated = stopped_termination(entry[:id])
          entry[:status] = {"state" => "terminated", "exitCode" => terminated.fetch("exitCode"), "reason" => terminated.fetch("reason"),
                            "terminated" => terminated, "ready" => false, "started" => false,
                            "restartCount" => entry[:status]["restartCount"].to_i}
        end
      end

      # The termination the runtime reports after a stop: a SIGKILL after the
      # grace period exits 137 (Error); otherwise the runtime status (exit
      # code, reason, termination message) is used when it is available.
      def stopped_termination(container_id)
        details = (@stop_details ||= {})[container_id] || {}
        status = if @runtime.respond_to?(:container_status)
                   value = begin
                     invoke(@runtime, :container_status, container_id)
                   rescue StandardError
                     nil
                   end
                   value = value.to_h if value.respond_to?(:to_h) && !value.is_a?(Hash)
                   value.is_a?(Hash) ? Helpers.string_keys(value) : {}
                 else
                   {}
                 end
        terminated = Helpers.key(status, "terminated", status)
        terminated = Helpers.string_keys(terminated.is_a?(Hash) ? terminated : {})
        exit_code, signal = exit_details(status)
        exit_code = 128 + signal if exit_code.nil? && signal
        exit_code = details[:killed] ? 137 : 0 if exit_code.nil?
        exit_code = Integer(exit_code)
        reason = Helpers.key(terminated, "reason", nil)
        reason = "OOMKilled" if status["oom_killed"] == true
        reason = exit_code.zero? ? "Completed" : "Error" if reason.nil? || reason.to_s.empty?
        result = {"exitCode" => exit_code, "reason" => reason.to_s, "finishedAt" => Helpers.now(@clock).iso8601(6)}
        message = Helpers.key(terminated, "message", nil)
        if message.nil? || message.to_s.empty?
          entry = @records.values.flat_map { |candidate| candidate[:containers] }.find { |candidate| candidate[:id] == container_id }
          message = termination_message_for(entry, exit_code: exit_code, reason: reason) if entry
        end
        result["message"] = message.to_s unless message.nil? || message.to_s.empty?
        result
      end

      def backoff_pod_identity(pod, uid)
        metadata = Helpers.key(pod, "metadata", {})
        "#{Helpers.key(metadata, "name", "")}_#{Helpers.key(metadata, "namespace", "")}(#{uid})"
      end

      # +release_process+: false keeps the exited process handle so the
      # container's log stays readable (a container waiting out its restart
      # backoff); the handle goes with the container itself.
      def stop_one(container_id, grace, release_process: true)
        send_signal(container_id, "TERM") if @runtime.respond_to?(:signal)
        result = if @runtime.respond_to?(:stop_container)
                   begin
                     options = {timeout: grace}
                     options[:release_process] = release_process if accepts_keyword?(@runtime, :stop_container, :release_process)
                     invoke(@runtime, :stop_container, container_id, **options)
                   rescue StandardError
                     false
                   end
                 elsif @runtime.respond_to?(:signal)
                   invoke(@runtime, :signal, container_id, "TERM")
                 else
                   false
                 end
        running = if result.is_a?(Hash)
                    Helpers.key(result, "running", false)
                  elsif result == false
                    true
                  end
        if running
          @sleeper.call(grace) if grace.positive?
          (@stop_details ||= {})[container_id] = {killed: true}
          kill_result = kill_container(container_id)
          return true if kill_result != false && !@runtime.respond_to?(:container_status)

          result = if @runtime.respond_to?(:stop_container)
                     invoke(@runtime, :stop_container, container_id, timeout: grace)
                   else
                     false
                   end
          # Minimal injected runtimes often model SIGKILL as the terminal
          # confirmation and intentionally keep stop_container returning
          # `running`. Native runtimes expose container_status/wait and take
          # the stricter path below.
          return true if result == false && kill_result != false && !@runtime.respond_to?(:container_status)
        end
        return false if result.nil? || result == false

        confirm_stopped(container_id, result)
      end

      def confirm_stopped(container_id, result)
        if result.is_a?(Hash)
          running = Helpers.key(result, "running", nil)
          return false if running == true

          state = Helpers.key(result, "state", nil)
          return false if %w[running created].include?(state.to_s)

          exit_code = Helpers.key(result, "exitCode", Helpers.key(result, "exit_code", :unknown))
          return false if exit_code.nil?
        end
        if @runtime.respond_to?(:container_status)
          status = invoke(@runtime, :container_status, container_id)
          status = status.to_h if status.respond_to?(:to_h)
          return false if status.is_a?(Hash) && %w[running created].include?(Helpers.key(status, "state", "").to_s)
        end
        true
      rescue StandardError
        # Native stop_container returns only after its process wait/pidfd
        # confirmation. Generic adapters may not expose container_status, so
        # retain their successful stop result as the confirmation boundary.
        result == true
      end

      def kill_container(container_id)
        if @runtime.respond_to?(:kill_container)
          invoke(@runtime, :kill_container, container_id, signal: "KILL")
        elsif @runtime.respond_to?(:signal)
          send_signal(container_id, "KILL")
        end
      end

      def send_signal(container_id, signal)
        @runtime.signal(container_id, signal)
      rescue ArgumentError => error
        raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

        @runtime.signal(container_id, signal: signal)
      end

      # The runtime's own word that a sandbox's removal completed.
      def sandbox_already_removed?(sandbox_id)
        return false if sandbox_id.nil? || !@runtime.respond_to?(:sandbox_removed?)

        @runtime.sandbox_removed?(sandbox_id) == true
      rescue StandardError
        false
      end

      def cleanup_resources(record)
        record[:cleanup_completed] ||= {}
        stage_failed = false
        record[:containers].reverse_each do |entry|
          next unless @runtime.respond_to?(:remove_container)

          key = "container:#{entry[:id]}"
          next if record[:cleanup_completed][key]

          begin
            event(record, "container.remove", name: entry[:name], container_id: entry[:id])
            @container_manager&.post_stop(entry[:id])
            invoke(@runtime, :remove_container, entry[:id])
            record[:cleanup_completed][key] = true
            clear_cleanup_error(record, key)
          rescue StandardError => error
            record_cleanup_error(record, key, "container #{entry[:name]} cleanup failed: #{Helpers.failure_message(error)}")
            stage_failed = true
          end
        end
        return persist_state! if stage_failed

        # Claims are unprepared after every container has stopped and before
        # the Pod is reported terminal (kubelet killPod -> UnprepareDynamicResources).
        if record[:dra_prepared] && @dra_manager && !record[:cleanup_completed]["dra"]
          begin
            @dra_manager.unprepare_resources(Helpers.string_keys(record[:pod]))
            record[:cleanup_completed]["dra"] = true
            clear_cleanup_error(record, "dra")
          rescue StandardError => error
            record_cleanup_error(record, "dra", "dynamic resources cleanup failed: #{Helpers.failure_message(error)}")
            return persist_state!
          end
        end

        stage_failed = false
        if @network && !record[:network].nil?
          key = "network:#{record[:sandbox_id]}"
          unless record[:cleanup_completed][key]
            begin
              event(record, "network.delete")
              sandbox = begin
                network_sandbox_context(record)
              rescue SandboxGone => error
                # The sandbox (and its namespace) no longer exists: tear down
                # with the stored descriptor so IPAM and bridge state are
                # released, and accept the result either way -- a Pod whose
                # namespace is gone must not stay CleanupPending for ever
                # (the agent refused to come up over one such Pod, 2026-09-30).
                event(record, "network.delete.sandbox_gone", message: error.message)
                record[:sandbox_context] || :gone
              end
              if sandbox == :gone
                nil
              elsif @network.respond_to?(:delete)
                invoke(@network, :delete, sandbox)
              elsif @network.respond_to?(:disconnect)
                invoke(@network, :disconnect, sandbox)
              end
              record[:cleanup_completed][key] = true
              clear_cleanup_error(record, key)
            rescue StandardError => error
              record_cleanup_error(record, key, "network cleanup failed: #{Helpers.failure_message(error)}")
              stage_failed = true
            end
          end
        end
        return persist_state! if stage_failed

        stage_failed = false
        if record[:sandbox_id] && @runtime.respond_to?(:remove_sandbox)
          key = "sandbox:#{record[:sandbox_id]}"
          unless record[:cleanup_completed][key]
            begin
              event(record, "sandbox.remove", sandbox_id: record[:sandbox_id])
              invoke(@runtime, :remove_sandbox, record[:sandbox_id])
              record[:cleanup_completed][key] = true
              clear_cleanup_error(record, key)
            rescue StandardError => error
              if sandbox_already_removed?(record[:sandbox_id])
                # The runtime finished removing it (an earlier attempt, or a
                # concurrent one): the record is clean on that step.
                event(record, "sandbox.already_removed", sandbox_id: record[:sandbox_id])
                record[:cleanup_completed][key] = true
                clear_cleanup_error(record, key)
              else
                record_cleanup_error(record, key, "sandbox cleanup failed: #{Helpers.failure_message(error)}")
                stage_failed = true
              end
            end
          end
        end
        return persist_state! if stage_failed

        volume_failed = false
        unless @volume.nil? || record[:volume].nil? || record[:cleanup_completed]["volume"]
          begin
            event(record, "volume.release")
            if @pod_volumes && record[:volume].is_a?(Hash)
              @pod_volumes.release(record[:pod], record[:volume], token: "release-#{record[:uid]}")
            elsif @volume.respond_to?(:release)
              invoke(@volume, :release, record[:volume])
            elsif @volume.respond_to?(:cleanup)
              invoke(@volume, :cleanup, record[:volume])
            elsif @volume.respond_to?(:unmount)
              invoke(@volume, :unmount, record[:volume])
            elsif @volume.respond_to?(:teardown)
              invoke(@volume, :teardown, record[:volume])
            end
            record[:cleanup_completed]["volume"] = true
            clear_cleanup_error(record, "volume")
          rescue StandardError => error
            record_cleanup_error(record, "volume", "volume cleanup failed: #{Helpers.failure_message(error)}")
            volume_failed = true
          end
        end
        return persist_state! if volume_failed

        return persist_state! if release_images(record)

        persist_state!
      end

      # kubelet keeps retrying a Pod whose start failed before its workload
      # ran (a missing ConfigMap, an unbound claim, a sandbox that could not
      # be created): the Pod stays Pending with the reason in its status and
      # the next sync tries again after a backoff.  Only an admission
      # rejection is terminal.
      TERMINAL_START_REASONS = %w[PodAdmissionFailed].freeze
      # kubelet's volume manager and sandbox creation retry quickly (the
      # reconciler loop is sub-second with exponential backoff on repeated
      # failure); the slow 10s..5m curve belongs to CrashLoopBackOff only.
      START_BACKOFF_INITIAL_SECONDS = 1.0
      START_BACKOFF_MAX_SECONDS = 30.0

      # kubelet: a failed init container ends a RestartNever Pod (phase Failed,
      # reason Init:Error); OnFailure/Always retry it under CrashLoopBackOff.
      def restart_policy_never?(record)
        Helpers.key(Helpers.key(record[:pod] || {}, "spec", {}), "restartPolicy", "Always").to_s == "Never"
      end

      def fail_record(record, error, preserve_phase: false)
        record[:error] = error.message
        retryable = !preserve_phase && !TERMINAL_START_REASONS.include?(record[:reason].to_s) &&
                    !(record[:reason].to_s.start_with?("Init:") && restart_policy_never?(record))
        failure_type = case record[:reason].to_s
                       when "FailedMount" then "volume.failed"
                       when "PodAdmissionFailed" then "pod.admission_failed"
                       else "pod.failed"
                       end
        # A DRA preparation failure has already been reported as
        # FailedPrepareDynamicResources.
        event(record, failure_type, message: error.message, reason: record[:reason].to_s) unless error.is_a?(DynamicResourcesError)
        record[:phase] = "Failed" unless preserve_phase || retryable
        if retryable
          record[:phase] = "Pending"
          record[:reason] ||= "ContainerCreating"
          schedule_start_retry(record[:uid])
        end
        set_state(record, "RollingBack") unless %w[RollingBack Stopped Removed].include?(record[:state])
        stop_confirmed = true
        begin
          stop_containers(record)
          clear_cleanup_error(record, "stop")
        rescue StandardError => stop_error
          stop_confirmed = false
          record_cleanup_error(record, "stop", "workload stop failed: #{Helpers.failure_message(stop_error)}")
        end
        unless stop_confirmed
          # Never remove a container, network, sandbox, image, or volume while
          # a started workload lacks a confirmed terminal state. Keep all
          # ownership durable so the next reconciliation can retry stopping
          # before entering reverse-order cleanup.
          set_state(record, "CleanupPending")
          record[:phase] = "Unknown"
          update_status(record[:pod], record)
          persist_state!
          return result_for(record)
        end
        cleanup_resources(record)
        set_state(record, "Stopped") unless record[:state] == "Stopped"
        if record[:cleanup_errors].empty?
          set_state(record, "Removed")
        else
          set_state(record, "CleanupPending")
        end
        record[:resources] = [] if record[:cleanup_errors].empty?
        update_status(record[:pod], record)
        forget_terminated_probe_and_restart_state(record)
        persist_state!
        result_for(record)
      end

      # kubelet removes a Pod's probe workers (probeManager.RemovePod) and its
      # restart backoff entries once the Pod is gone.  Ours kept both for every
      # Pod the node had ever run, and both are serialised in full on EVERY
      # state transition of EVERY Pod, under one lock -- 415 KB of dead probe
      # state and 50 KB of dead backoff state per node, rewritten ~8 times per
      # Pod start, which is what serialised Pod starts on a node behind each
      # other.  Called only once cleanup has succeeded, and after the record's
      # final status has been reported from it.
      def forget_terminated_probe_and_restart_state(record)
        return unless record[:cleanup_errors].to_a.empty?
        # A Pod whose start failed is rolled back through this same path and
        # then STARTED AGAIN.  Its restart history is what makes the retries a
        # restart count rather than a series of first attempts, so it must
        # survive the rollback: kubelet keeps the backoff across them, and
        # "[sig-node] InitContainer should not start app containers if init
        # containers fail on a RestartAlways pod" waits for restartCount 3.
        return if start_retry_scheduled?(record[:uid])

        if @probes.respond_to?(:unregister)
          Array(record[:containers]).each do |entry|
            identifier = entry[:id]
            @probes.unregister(identifier) unless identifier.nil?
          end
        end
        @restarts.forget_pod(record[:uid]) if @restarts.respond_to?(:forget_pod)
      end

      # kubelet reports *why* a container is waiting: a Pod that cannot be
      # configured shows CreateContainerConfigError on the container, not only
      # on the Pod.  Clients wait on that reason -- the subPath expansion
      # conformance spec waits for exactly it -- so a reasonless `waiting`
      # leaves them waiting forever.
      def container_observation(entry, record)
        observation = entry[:status].merge("containerID" => entry[:id])
        user = container_user(entry)
        observation = observation.merge("user" => user) if user
        # ResourceHealthStatus: the health of each device the container holds.
        health = resource_health(record, entry)
        observation = observation.merge("allocatedResourcesStatus" => health) unless health.empty?
        reason = record[:reason].to_s
        return observation unless observation["state"].to_s == "waiting" && !reason.empty?

        waiting = observation["waiting"]
        waiting = waiting.is_a?(Hash) ? waiting.dup : {}
        return observation unless waiting["reason"].to_s.empty?

        waiting["reason"] = reason
        message = record[:error].to_s
        waiting["message"] = message unless message.empty?
        observation.merge("waiting" => waiting)
      end

      # ContainerStatus.user (SupplementalGroupsPolicy): the identity the
      # container runs with once it exists -- uid, gid and every group, in
      # the runtime's order (the gid, the image's memberships, the Pod's
      # supplementalGroups, fsGroup).
      def container_user(entry)
        return nil if entry[:id].nil? || !entry[:spec].is_a?(Hash)
        return nil unless %w[running terminated exited].include?(entry[:status].is_a?(Hash) ? entry[:status]["state"].to_s : "")

        context = Helpers.string_keys(Helpers.key(entry[:spec], "security_context", {}) || {})
        uid = Integer(context["runAsUser"] || 0)
        gid = Integer(context["runAsGroup"] || 0)
        image = Array(context["imageSupplementalGroups"]).map { |group| Integer(group) }
        pod = Array(context["supplementalGroups"]).map { |group| Integer(group) } - image
        groups = ([gid] + image + pod + [context["fsGroup"]].compact.map { |group| Integer(group) }).uniq
        {"linux" => {"uid" => uid, "gid" => gid, "supplementalGroups" => groups}}
      rescue ArgumentError, TypeError
        nil
      end

      def update_status(pod, record)
        mark_dirty(record)
        record[:published_status_signature] = status_signature(record)
        # An ephemeral container is reported in its own status list upstream
        # (status.ephemeralContainerStatuses); folding it in with the init
        # containers left the debug container invisible to every client that
        # waits for it.
        state = {
          "containers" => record[:containers].select { |entry| entry[:category] == "app" }.to_h do |entry|
            [entry[:name], container_observation(entry, record)]
          end,
          "initContainers" => record[:containers].select { |entry| %w[init sidecar].include?(entry[:category].to_s) }.to_h do |entry|
            [entry[:name], container_observation(entry, record)]
          end,
          "ephemeralContainers" => record[:containers].select { |entry| entry[:category] == "ephemeral" }.to_h do |entry|
            [entry[:name], container_observation(entry, record)]
          end
        }
        ips = pod_ips(record)
        host_network = Helpers.key(Helpers.key(pod, "spec", {}), "hostNetwork", false) == true
        ips = [@host_ip].compact if host_network && ips.empty? && @host_ip
        snapshot = @status.aggregate(
          pod: pod,
          state: state,
          phase: record[:phase],
          reason: record[:reason] || (record[:error] && "StartFailed"),
          message: record[:error] || record[:termination_message],
          start_time: record[:started_at],
          # The newest generation this node has seen for the Pod: a status
          # published by the old record's termination must not roll
          # observedGeneration back below the one the restarted record saw.
          observed_generation: [pod, record[:pod]].compact.filter_map do |candidate|
            value = Helpers.key(Helpers.key(candidate, "metadata", {}), "generation", nil)
            value.nil? ? nil : Integer(value)
          end.max,
          pod_ip: ips.first,
          pod_ips: ips,
          host_ip: @host_ip,
          all_containers_restarting: record[:restarting_all] == true,
          # Kubelet-owned conditions beyond the standard ones: the resize
          # conditions and an eviction's DisruptionTarget.
          resize_conditions: [record[:resize_pending], record[:resize_in_progress], record[:disruption_condition]].compact,
          pod_resources: pod_status_resources(record),
          allocated_resources: record[:pod] ? PodResize.allocated_resources(record[:pod]) : nil
        )
        # A fresh copy nobody mutates afterwards: frozen, json_safe converts
        # it once per status change instead of on every persist of the record.
        record[:status] = Helpers.deep_freeze(snapshot.to_h)
        snapshot
      end

      # status.resources: the allocated pod-level resources, and once Running
      # what the Pod cgroup actually holds (read when the Pod starts running
      # and after each resize).
      def pod_status_resources(record)
        allocated = record[:pod]
        return nil if allocated.nil?

        running = record[:phase].to_s == "Running"
        record[:pod_cgroup] ||= runtime_pod_cgroup(record) if running
        previous = record[:status].is_a?(Hash) ? record[:status]["resources"] : nil
        previous_phase = record[:status].is_a?(Hash) ? record[:status]["phase"] : nil
        PodResize.status_resources(allocated, phase: record[:phase], cgroup: running ? record[:pod_cgroup] : nil,
                                              previous: previous, previous_phase: previous_phase)
      end

      def probe_running_containers(record, pod)
        return if record[:containers].empty?

        probe(pod)
        running = record[:containers].select { |entry| entry[:restart_pending].nil? && entry[:started] }
        schedule_probe_wakeup(record[:uid], running, first: false)
      rescue LifecycleError
        nil
      end

      # kubelet runs each probe from its own ticker: the first at
      # initialDelaySeconds, then every periodSeconds (default 10).  Here the
      # Pod is woken for its next due probe; left to whatever event happened
      # to reconcile it, a liveness probe ran about every 10 s from the
      # container's start and first failed at 20 s where kubelet's does at
      # 10-20 ("Probing container should have monotonically increasing
      # restart count": 5 restarts in 172 s, upstream 146).
      DEFAULT_PROBE_PERIOD_SECONDS = 10
      FIRST_PROBE_MINIMUM_SECONDS = 0.2

      def schedule_probe_wakeup(uid, entries, first:)
        return if uid.nil? || @wakeup.nil?

        definitions = Array(entries).flat_map { |entry| probes_for(entry[:spec]).values.compact }.grep(Hash)
        return if definitions.empty?

        delay = if first
                  [definitions.map { |probe| Helpers.key(probe, "initialDelaySeconds", 0).to_f }.min, FIRST_PROBE_MINIMUM_SECONDS].max
                else
                  definitions.map { |probe| Helpers.key(probe, "periodSeconds", DEFAULT_PROBE_PERIOD_SECONDS).to_f }.min
                end
        schedule_wakeup(uid, delay)
      end

      def remove_endpoints(pod, uid)
        @status.remove_from_endpoints(uid, pod: pod)
      end

      def mark_ready(pod, uid)
        endpoint = @status.endpoint_manager
        return unless endpoint

        if endpoint.respond_to?(:set_ready)
          endpoint.set_ready(uid, true)
        elsif endpoint.respond_to?(:add)
          endpoint.add(uid, pod)
        elsif endpoint.respond_to?(:mark_ready)
          endpoint.mark_ready(uid)
        end
      end

      def resolve_record(pod_or_uid)
        if pod_or_uid.is_a?(Hash)
          object = normalize_pod(pod_or_uid)
          uid = pod_uid(object)
          [object, uid, record_for(uid)]
        else
          uid = pod_or_uid.to_s
          existing = record_for(uid)
          [existing && existing[:pod], uid, existing]
        end
      end

      def image_key(category, index)
        "#{category}:#{index}"
      end

      def image_to_hash(image, fallback_reference = nil)
        value = image.respond_to?(:to_h) ? image.to_h : image
        hash = Helpers.string_keys(value)
        raise LifecycleError, "image resolver must return a hash-like image" unless hash.is_a?(Hash)

        digest = Helpers.key(hash, "digest", nil)
        raise LifecycleError, "image resolver returned an invalid pinned digest" unless digest.to_s.match?(/\Asha256:[0-9a-fA-F]{64}\z/)

        hash["digest"] = digest.to_s.downcase
        unless fallback_reference.nil?
          hash["reference"] ||= fallback_reference.to_s
          hash["requested_reference"] ||= fallback_reference.to_s
        end
        hash
      end

      def native_runtime?
        defined?(Rubernetes::Runtime::Native) && @runtime.is_a?(Rubernetes::Runtime::Native)
      end

      def network_sandbox_context(record)
        sandbox_id = record.fetch(:sandbox_id)
        context = if @runtime.respond_to?(:network_sandbox_context)
                    invoke(@runtime, :network_sandbox_context, sandbox_id)
                  else
                    record[:sandbox_context]
                  end
        context = context.to_h if context.respond_to?(:to_h)
        return sandbox_id unless context.is_a?(Hash)

        value = Helpers.string_keys(context)
        value["sandbox_id"] ||= sandbox_id.to_s
        return sandbox_id if value.keys == ["sandbox_id"]

        record[:sandbox_context] = Helpers.deep_copy(value)
        value
      rescue StandardError => error
        # A stored descriptor remains valid recovery input only when the
        # runtime cannot expose a live descriptor. If a live lookup exists
        # and fails, do not silently target the host namespace.
        if @runtime.respond_to?(:network_sandbox_context)
          # The runtime no longer holds the sandbox at all (startup recovery
          # released it: its namespace and links are gone with it).  That is
          # not a lookup that might land on the host namespace; it is the
          # answer "nothing left to enter", which the caller handles.
          raise SandboxGone, "sandbox #{sandbox_id} is gone: #{Helpers.failure_message(error)}" if Helpers.failure_message(error).include?("unknown sandbox")

          raise LifecycleError,
                "sandbox network namespace lookup failed: #{Helpers.failure_message(error)}"
        end

        record[:sandbox_context] || sandbox_id
      end

      def release_images(record)
        failed = false
        return if @image_resolver.nil? || !@image_resolver.respond_to?(:release)

        handles = Array(record[:images]).map { |image| ["image", image] } +
                  Array(record[:volume_image_handles]).map { |image| ["volume-image", image] }
        handles.each_with_index do |(prefix, image), index|
          key = "#{prefix}:#{index}"
          next if record[:cleanup_completed][key]

          begin
            invoke(@image_resolver, :release, image)
            record[:cleanup_completed][key] = true
            clear_cleanup_error(record, key)
          rescue StandardError => error
            record_cleanup_error(record, key, "image cleanup failed: #{Helpers.failure_message(error)}")
            failed = true
          end
        end
        failed
      end

      def record_cleanup_error(record, key, message)
        record[:cleanup_errors].reject! { |entry| entry.start_with?("#{key}: ") }
        record[:cleanup_errors] << "#{key}: #{message}"
      end

      def clear_cleanup_error(record, key)
        record[:cleanup_errors].reject! { |entry| entry.start_with?("#{key}: ") }
      end

      # InPlacePodVerticalScaling: the only difference between the running
      # Pod and the desired one is container resources.
      # True when the desired spec names an ephemeral container this record has
      # not started yet.  The config digest deliberately ignores
      # spec.ephemeralContainers, so the containers actually started -- not the
      # digest -- are what the desired spec must be compared against.
      def pending_ephemeral_containers?(pod, record)
        started = Array(record[:containers]).select { |entry| entry[:category] == "ephemeral" }
          .map { |entry| entry[:name].to_s }
        ephemeral_definitions(pod).any? do |definition|
          name = Helpers.key(definition, "name", "").to_s
          !name.empty? && !started.include?(name)
        end
      end

      def ephemeral_definitions(pod)
        Array(Helpers.key(Helpers.key(pod, "spec", {}), "ephemeralContainers", [])).map do |entry|
          Helpers.string_keys(entry)
        end
      end

      # Ephemeral containers never restart and carry no resources or probes;
      # they join the Pod's existing sandbox.
      def start_ephemeral_containers(pod, record)
        started = record[:containers].select { |entry| entry[:category] == "ephemeral" }.map { |entry| entry[:name].to_s }
        ephemeral_definitions(pod).each_with_index do |definition, index|
          name = Helpers.key(definition, "name", "").to_s
          next if name.empty? || started.include?(name)

          pin_ephemeral_image(pod, record, definition, index)
          event(record, "ephemeral.start", name: name)
          entry = create_entry(record, definition, category: "ephemeral", index: index)
          record[:containers] << entry
          start_entry(entry, record)
          # Published at once: nothing else is bound to run for this Pod soon
          # (its probes pass rarely republishes), and clients wait for the
          # debug container to show as running.
          update_status(pod, record)
          persist_state!
        end
      end

      # An ephemeral container is added after the Pod is already running, so its
      # image is pinned here rather than in the initial pin_images sweep.
      def pin_ephemeral_image(pod, record, definition, index)
        return if record[:image_by_container].key?(image_key("ephemeral", index))

        reference = Helpers.key(definition, "image", nil)
        raise LifecycleError, "ephemeral container #{Helpers.key(definition, "name", "").inspect} has no image" if reference.to_s.empty?
        return if @image_resolver.nil?

        resolved = ensure_image(record, reference.to_s, Helpers.key(definition, "name", nil), image_keyring(pod),
                                Helpers.key(definition, "imagePullPolicy", nil))
        raise LifecycleError, "image resolver returned no image for #{reference.to_s.inspect}" if resolved.nil?

        record[:images] << resolved
        record[:image_by_container][image_key("ephemeral", index)] = image_to_hash(resolved, reference)
      end

      def resizing_in_place?(record, object)
        record[:state] == "Running" && record[:pod] && PodResize.resources_changed?(record[:pod], object) &&
          resize_only_change?(record[:pod], object)
      rescue StandardError
        false
      end

      def resize_only_change?(current, desired)
        strip = lambda do |pod|
          value = Helpers.deep_copy(Helpers.string_keys(pod))
          spec = value["spec"].is_a?(Hash) ? value["spec"] : {}
          %w[containers initContainers].each do |field|
            Array(spec[field]).each { |container| container.delete("resources") if container.is_a?(Hash) }
          end
          # InPlacePodLevelResourcesVerticalScaling: pod-level resources are
          # resized in place too, not by recreating the Pod.
          spec.delete("resources")
          value
        end
        config_digest(strip.call(current)) == config_digest(strip.call(desired))
      end

      # allocation manager handlePodResourcesResize + kuberuntime
      # doPodResizeAction.  A resize that does not fit what the node has left
      # waits as PodResizePending/Deferred (retried on every sync); one that
      # fits is actuated -- pod-level resources through the Pod cgroup,
      # container resources through each container's -- with
      # PodResizeInProgress while it runs and, on failure (a memory limit
      # below current usage), until the next attempt.
      def resize_pod(record, pod)
        object = normalize_pod(pod)
        allocated = record[:pod]
        generation = Helpers.key(Helpers.key(object, "metadata", {}), "generation", nil)
        generation = generation.nil? ? nil : Integer(generation)
        unless PodResize.resources_changed?(allocated, object)
          record[:resize_pending] = nil
          resize_containers(record, object)
          return
        end
        # HandlePodUpdates recordContainerResizeOperations: once per update
        # that changes what is asked for.
        requested = record[:resize_requested] || allocated
        if PodResize.resources_changed?(requested, object)
          metrics_call(:resize_requested, requested, object)
          record[:resize_requested] = object
        end

        infeasible = resize_infeasible(allocated, object)
        if infeasible
          detail, message = infeasible
          previous = record[:resize_pending]
          record[:resize_pending] = {"type" => "PodResizePending", "reason" => "Infeasible", "message" => message,
                                     "observedGeneration" => generation,
                                     "lastTransitionTime" => if previous &&
                                                                previous["reason"] == "Infeasible"
                                                               previous["lastTransitionTime"]
                                                             else
                                                               Helpers.now(@clock).iso8601(6)
                                                             end}
          metrics_call(:pod_infeasible_resize, detail)
          if previous.nil? || previous["reason"] != "Infeasible" || previous["observedGeneration"] != generation
            event(record, "pod.resize_infeasible", message: PodResize.message("Pod resize Infeasible", object, generation, message))
          end
          update_status(object, record)
          return
        end

        decision = resize_admission(record, object)
        unless decision.nil? || Helpers.success_result?(decision)
          message = decision.respond_to?(:message) ? decision.message.to_s : Helpers.key(decision, "message", "").to_s
          previous = record[:resize_pending]
          record[:resize_pending] = {"type" => "PodResizePending", "reason" => "Deferred", "message" => message,
                                     "observedGeneration" => generation,
                                     "lastTransitionTime" => previous ? previous["lastTransitionTime"] : Helpers.now(@clock).iso8601(6)}
          if previous.nil? || previous["observedGeneration"] != generation
            event(record, "pod.resize_deferred", message: PodResize.message("Pod resize Deferred", object, generation, message))
          end
          update_status(object, record)
          return
        end

        deferred = record[:resize_pending]
        if deferred && deferred["reason"] == "Deferred"
          # retryPendingResizes: the Pod's own update, or a later retry.
          metrics_call(:deferred_resize_accepted, deferred["observedGeneration"] == generation ? "periodic_retry" : "pod_updated")
        end
        record[:resize_pending] = nil
        started = Helpers.now(@clock).iso8601(6)
        actuation = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        record[:resize_in_progress] = {"type" => "PodResizeInProgress", "observedGeneration" => generation, "lastTransitionTime" => started}
        event(record, "pod.resize_started", message: PodResize.message("Pod resize started", object, generation))
        pod_level = PodResize.pod_level_changed?(allocated, object)
        error = resize_memory_error(record, allocated, object)
        unless error.nil?
          record[:resize_in_progress] = record[:resize_in_progress].merge("reason" => "Error", "message" => error)
          metrics_call(:pod_resize_duration, Process.clock_gettime(Process::CLOCK_MONOTONIC) - actuation, false)
          event(record, "pod.resize_error", message: PodResize.message("Pod resize error", object, generation, error))
          update_status(object, record)
          return
        end

        grows = pod_level && pod_level_grows?(allocated, object)
        update_pod_cgroup(record, object) if pod_level && grows
        resize_containers(record, object)
        update_pod_cgroup(record, object) if pod_level && !grows
        record[:pod_cgroup] = runtime_pod_cgroup(record)
        record[:resize_in_progress] = nil
        metrics_call(:pod_resize_duration, Process.clock_gettime(Process::CLOCK_MONOTONIC) - actuation, true)
        event(record, "pod.resize_completed", message: PodResize.message("Pod resize completed", object, generation))
        update_status(object, record)
      rescue StandardError => error
        raise unless record[:resize_in_progress]

        metrics_call(:pod_resize_duration, Process.clock_gettime(Process::CLOCK_MONOTONIC) - actuation, false) if actuation
        record[:resize_in_progress] = record[:resize_in_progress].merge("reason" => "Error", "message" => Helpers.failure_message(error))
        event(record, "pod.resize_error",
              message: PodResize.message("Pod resize error", object, generation, Helpers.failure_message(error)))
        update_status(object, record)
      end

      def metrics_call(name, *)
        @metrics_observer.public_send(name, *) if @metrics_observer.respond_to?(name)
      rescue StandardError
        nil
      end

      def resize_infeasible(allocated, desired)
        return nil unless @container_manager.respond_to?(:cpu_manager_policy)

        PodResize.infeasible(allocated, desired, cpu_policy: @container_manager.cpu_manager_policy,
                                                 memory_policy: @container_manager.memory_manager_policy)
      rescue StandardError
        nil
      end

      # canAdmitPod(..., ResizeOperation): the resized Pod against what the
      # other admitted Pods leave on the node.
      def resize_admission(record, pod)
        return nil if @admission.nil? || !@admission.respond_to?(:admit) || !accepts_keyword?(@admission, :admit, :other_pods)

        @admission.admit(pod, other_pods: admitted_pods(except: record[:uid]))
      end

      # validateMemoryResizeAction: a pod-level memory limit that decreases
      # below what the Pod uses now is refused.
      def resize_memory_error(record, allocated, desired)
        resources = Runtime::Native::Resources
        old_limit = resources.pod_cgroup_limits(allocated)["memory.max"]
        new_limit = resources.pod_cgroup_limits(desired)["memory.max"]
        return nil if new_limit.nil?
        return nil if old_limit && Integer(new_limit) >= Integer(old_limit)

        readback = runtime_pod_cgroup(record)
        usage = readback && readback["memory.current"]
        return "cannot decrease memory limits: missing pod memory usage" if usage.nil? && readback
        return nil if usage.nil?
        return nil if Integer(usage) < Integer(new_limit)

        "cannot decrease memory limits: attempting to set pod memory limit (#{Integer(new_limit)}) below current usage (#{Integer(usage)})"
      rescue ArgumentError, TypeError
        nil
      end

      def pod_level_grows?(allocated, desired)
        before = ResourceHelpers.pod_limits(allocated)
        after = ResourceHelpers.pod_limits(desired)
        %w[cpu memory].any? { |name| after[name] && (before[name].nil? || after[name].value > before[name].value) }
      end

      def update_pod_cgroup(record, pod)
        return unless @runtime.respond_to?(:update_pod_resources) && record[:sandbox_id]

        invoke(@runtime, :update_pod_resources, record[:sandbox_id], pod_spec: Helpers.key(pod, "spec", {}))
      end

      def runtime_pod_cgroup(record)
        return nil unless @runtime.respond_to?(:pod_cgroup_readback) && record[:sandbox_id]

        invoke(@runtime, :pod_cgroup_readback, record[:sandbox_id])
      rescue StandardError
        nil
      end

      # kubelet doPodResizeAction: reconfigure the container (and Pod) cgroups
      # for the new requests/limits; the Pod keeps running and its status
      # reports the resources it now runs with.
      def resize_containers(record, pod)
        object = normalize_pod(pod)
        spec = Helpers.key(object, "spec", {})
        %w[containers initContainers].each do |field|
          Array(Helpers.key(spec, field, [])).each do |definition|
            name = Helpers.key(definition, "name", "").to_s
            entry = record[:containers].find { |candidate| candidate[:name] == name }
            next if entry.nil?

            resources = Helpers.deep_copy(Helpers.key(definition, "resources", {}) || {})
            next if Helpers.deep_copy(Helpers.key(entry[:spec], "resources", {}) || {}) == resources

            # container.resizePolicy: a resource whose policy is
            # RestartContainer cannot be changed in place -- the container is
            # restarted with the new value instead (types.go: "resize the
            # container in-place" vs "RestartContainer").  The field was
            # validated by the API server and read by nobody, so a container
            # that asked to be restarted for a memory change was silently
            # resized in place.
            restart_needed = resize_requires_restart?(definition, entry, resources)
            applied = nil
            if restart_needed && entry[:started]
              event(record, "container.resize_restart", name: name, container_id: entry[:id])
              entry[:spec] = Helpers.immutable(Helpers.deep_copy(entry[:spec]).merge("resources" => resources))
              restart_container(object, record, entry, reason: "ResizeRestart")
              next
            end
            if entry[:started] && @runtime.respond_to?(:update_container_resources)
              applied = invoke(@runtime, :update_container_resources, entry[:id], resources: resources, pod_spec: spec)
            end
            entry[:spec] = Helpers.immutable(Helpers.deep_copy(entry[:spec]).merge("resources" => resources))
            event(record, "container.resized", name: name, container_id: entry[:id], started: entry[:started],
                                               runtime: @runtime.respond_to?(:update_container_resources), runtime_class: @runtime.class.name, limits: applied)
          end
        end
        record[:pod] = Helpers.immutable(object)
        update_status(object, record)
      end

      # Which resources changed, and does any of them carry
      # resizePolicy: RestartContainer?
      def resize_requires_restart?(definition, entry, desired_resources)
        policies = Array(Helpers.key(definition, "resizePolicy", [])).to_h do |rule|
          [Helpers.key(rule, "resourceName", "").to_s, Helpers.key(rule, "restartPolicy", "").to_s]
        end
        return false if policies.empty?

        current = Helpers.deep_copy(Helpers.key(entry[:spec], "resources", {}) || {})
        changed_resource_names(current, desired_resources).any? do |name|
          policies[name].to_s == "RestartContainer"
        end
      end

      def changed_resource_names(current, desired)
        names = []
        %w[requests limits].each do |section|
          before = Helpers.key(current, section, {}) || {}
          after = Helpers.key(desired, section, {}) || {}
          (before.keys | after.keys).each do |key|
            names << key.to_s if before[key].to_s != after[key].to_s
          end
        end
        names.uniq
      end

      # Only the metadata a container's configuration can read back: a label or
      # annotation change matters to a Pod that could not be configured, and to
      # nothing else.
      def metadata_digest(pod)
        metadata = Helpers.key(Helpers.string_keys(pod), "metadata", {})
        Digest::SHA256.hexdigest(JSON.generate(canonical_config_value(
          "labels" => Helpers.key(metadata, "labels", {}),
          "annotations" => Helpers.key(metadata, "annotations", {})
        )))
      end

      def config_digest(pod)
        value = Helpers.string_keys(pod)
        metadata = Helpers.key(value, "metadata", {})
        # Labels and annotations are not part of the digest: kubelet never
        # restarts a Pod for a metadata change (a released ReplicaSet Pod
        # keeps running); projected downward API content is refreshed by
        # the periodic volume sync instead.
        desired_metadata = %w[name namespace uid].each_with_object({}) do |field, result|
          result[field] = metadata[field] if metadata.key?(field)
        end
        # TypeMeta is deliberately not part of the digest: a list item and a
        # watch event describe the same Pod with and without apiVersion/kind,
        # and a digest that flips between them terminates and recreates a
        # healthy Pod on every resync.
        # kubelet restarts containers for a change of the container's own
        # spec (computeHash over the v1.Container), never for scheduling or
        # lifecycle fields the API allows on a running Pod: tolerations,
        # activeDeadlineSeconds, terminationGracePeriodSeconds, priority.
        # Hashing the whole spec killed and recreated a Pod on every such
        # update ("[sig-node] Pods Extended pod generation should start at 1
        # and increment per update" adds a toleration and watched its
        # container die).
        spec = Helpers.key(value, "spec", {})
        spec = spec.reject { |key, _| RESTART_NEUTRAL_SPEC_FIELDS.include?(key.to_s) } if spec.is_a?(Hash)
        # kubelet computePodActions never re-runs an init container that has
        # completed, so a change to one (the e2e swaps its image to pause,
        # which would block for ever) restarts nothing; only restartable init
        # containers (sidecars) are live containers whose hash matters.
        if spec.is_a?(Hash) && spec.key?("initContainers")
          spec = spec.merge("initContainers" => Array(spec["initContainers"]).select do |container|
            restartable_init?(Helpers.string_keys(container))
          end)
        end
        desired = {
          "metadata" => desired_metadata,
          "spec" => spec
        }
        Digest::SHA256.hexdigest(JSON.generate(canonical_config_value(desired)))
      end

      RESTART_NEUTRAL_SPEC_FIELDS = %w[
        tolerations activeDeadlineSeconds terminationGracePeriodSeconds priority priorityClassName
        schedulerName schedulingGates nodeName nodeSelector affinity preemptionPolicy
        readinessGates ephemeralContainers
      ].freeze

      def canonical_config_value(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.to_h do |key|
            child = value.key?(key) ? value[key] : value[key.to_sym]
            [key, canonical_config_value(child)]
          end
        when Array
          value.map { |child| canonical_config_value(child) }
        else
          value
        end
      end

      def grace_seconds(pod)
        spec = Helpers.key(pod, "spec", {})
        value = Helpers.key(spec, "terminationGracePeriodSeconds", 30)
        Integer(value || 30).clamp(0, 3600)
      rescue ArgumentError, TypeError
        30
      end

      def container_policy(pod, definition)
        Helpers.key(definition, "restartPolicy", Helpers.key(Helpers.key(pod, "spec", {}), "restartPolicy", "Always")).to_s.then do |value|
          value.empty? ? "Always" : value
        end
      end

      def create_container(sandbox_id, definition)
        raise LifecycleError, "runtime does not implement create_container" unless @runtime.respond_to?(:create_container)

        value = invoke(@runtime, :create_container, sandbox_id, definition)
        return value.id.to_s if value.respond_to?(:id) && !value.id.to_s.empty?

        if value.is_a?(Hash)
          identifier = Helpers.key(value, "id", Helpers.key(value, "containerID", nil))
          return identifier.to_s unless identifier.nil? || identifier.to_s.empty?
        end

        value
      end

      def restart_identity(record, entry)
        "#{record.fetch(:uid)}/#{entry.fetch(:name)}"
      end

      def start_container(container_id)
        raise LifecycleError, "runtime does not implement start_container" unless @runtime.respond_to?(:start_container)

        invoke(@runtime, :start_container, container_id)
      end

      def remove_container(container_id)
        # PostStopContainer: the topology manager forgets the container.
        @container_manager&.post_stop(container_id)
        return unless @runtime.respond_to?(:remove_container)

        invoke(@runtime, :remove_container, container_id)
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
          begin
            seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
            if operation == "run_podsandbox"
              @metrics_observer.runtime_operation(operation, seconds, failed: failed, runtime_handler: keywords[:runtime_class])
            else
              @metrics_observer.runtime_operation(operation, seconds, failed: failed)
            end
          rescue StandardError
            nil
          end
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
