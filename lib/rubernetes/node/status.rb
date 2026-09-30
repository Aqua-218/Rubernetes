# frozen_string_literal: true

require "time"

require_relative "../node_declared_features"

module Rubernetes
  module Node
    # Shared value normalization and immutable-copy helpers used by the node
    # agent.  Kubernetes objects arrive from more than one adapter, so the
    # agent accepts both string and symbol keys while keeping its internal
    # snapshots detached from API-server caches.
    module Helpers
      module_function

      def key(value, name, default = nil)
        return default unless value.respond_to?(:key?)

        return value[name] if value.key?(name)

        string = name.to_s
        return value[string] if value.key?(string)

        symbol = string.to_sym
        return value[symbol] if value.key?(symbol)

        default
      end

      # net.JoinHostPort: an IPv6 literal (anything with a colon, zone id
      # included) is bracketed unless it already is.
      def join_host_port(host, port)
        host = host.to_s
        host = "[#{host}]" if host.include?(":") && !host.start_with?("[")
        "#{host}:#{port}"
      end

      def string_keys(value)
        case value
        when Hash
          value.each_with_object({}) do |(name, child), result|
            result[name.to_s] = string_keys(child)
          end
        when Array
          value.map { |child| string_keys(child) }
        else
          value
        end
      end

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(name, child), result| result[name] = deep_copy(child) }
        when Array
          value.map { |child| deep_copy(child) }
        else
          value
        end
      end

      # Every Hash and Array frozen here -- children first -- is recorded, so
      # a caller can tell a deeply frozen value (safe to memoize anything
      # derived from it) from one that is merely frozen at the top.
      DEEP_FROZEN = ObjectSpace::WeakMap.new

      def deep_freeze(value)
        # A value recorded here is already frozen all the way down; walking it
        # again was most of what Helpers.immutable cost on a cached Pod.
        return value if (value.is_a?(Hash) || value.is_a?(Array)) && DEEP_FROZEN.key?(value)

        case value
        when Hash
          value.each do |name, child|
            deep_freeze(name)
            deep_freeze(child)
          end
          value.freeze
          DEEP_FROZEN[value] = true
        when Array
          value.each { |child| deep_freeze(child) }
          value.freeze
          DEEP_FROZEN[value] = true
        end
        value.freeze
      end

      def deep_frozen?(value)
        (value.is_a?(Hash) || value.is_a?(Array)) && DEEP_FROZEN.key?(value)
      end

      # Values Helpers.immutable produced: string-keyed and frozen all the way
      # down, so handing one in again returns it as it is.  string_keys
      # already builds new Hashes and Arrays (the deep_copy it used to follow
      # copied the same containers a second time), and every Pod the agent
      # normalises passed through here two or three times per event.
      IMMUTABLE = ObjectSpace::WeakMap.new

      def immutable(value)
        return value if (value.is_a?(Hash) || value.is_a?(Array)) && IMMUTABLE.key?(value)

        # One walk that copies with string keys and freezes as it goes: the
        # same result as deep_freeze(string_keys(value)) in half the work
        # (a tenth of a busy agent's CPU was these two walks per Pod object).
        result = frozen_string_keys(value)
        IMMUTABLE[result] = true if result.is_a?(Hash) || result.is_a?(Array)
        result
      end

      def frozen_string_keys(value)
        return value if (value.is_a?(Hash) || value.is_a?(Array)) && DEEP_FROZEN.key?(value) && string_keyed?(value)

        case value
        when Hash
          result = value.each_with_object({}) { |(name, child), copy| copy[name.to_s.freeze] = frozen_string_keys(child) }
          result.freeze
          DEEP_FROZEN[result] = true
          result
        when Array
          result = value.map { |child| frozen_string_keys(child) }
          result.freeze
          DEEP_FROZEN[result] = true
          result
        else
          value.freeze
        end
      end

      # A deep-frozen value whose keys are all strings (Helpers.immutable's
      # own output, or a Pod from the informer): nothing to copy.
      def string_keyed?(value)
        case value
        when Hash then value.all? { |name, child| name.is_a?(String) && string_keyed?(child) }
        when Array then value.all? { |child| string_keyed?(child) }
        else true
        end
      end

      def immutable?(value)
        (value.is_a?(Hash) || value.is_a?(Array)) && IMMUTABLE.key?(value)
      end

      def call_if(target, method_name, *, **keywords, &)
        return :__missing__ unless target && target.respond_to?(method_name)

        if keywords.empty?
          target.public_send(method_name, *, &)
        else
          target.public_send(method_name, *, **keywords, &)
        end
      end

      def first_call(target, methods, *, **keywords, &)
        Array(methods).each do |method_name|
          next unless target && target.respond_to?(method_name)

          return keywords.empty? ? target.public_send(method_name, *,
                                                      &) : target.public_send(method_name, *, **keywords, &)
        end
        :__missing__
      end

      def now(clock)
        value = clock.call
        value.respond_to?(:utc) ? value.utc : Time.at(value.to_f).utc
      end

      # Go's time.Duration.String() of a duration truncated to milliseconds,
      # as kubelet's messages print them: "0s", "567ms", "1.5s", "1m2.345s".
      def go_duration(seconds)
        millis = (seconds.to_f * 1000).floor
        return "0s" if millis <= 0
        return "#{millis}ms" if millis < 1000

        hours, rest = millis.divmod(3_600_000)
        minutes, rest = rest.divmod(60_000)
        whole, fraction = rest.divmod(1000)
        text = fraction.zero? ? "#{whole}s" : "#{whole}.#{format("%03d", fraction).sub(/0+\z/, "")}s"
        text = "#{minutes}m#{text}" if minutes.positive? || hours.positive?
        text = "#{hours}h#{text}" if hours.positive?
        text
      end

      def success_result?(result)
        return result if [true, false].include?(result)
        return false if result.nil?

        return !!result.success? if result.respond_to?(:success?)
        return !!result.successful? if result.respond_to?(:successful?)

        if result.is_a?(Hash)
          explicit = key(result, :success, nil)
          return !!explicit unless explicit.nil?

          allowed = key(result, :allowed, nil)
          return !!allowed unless allowed.nil?

          status = key(result, :status, key(result, :status_code, nil))
          return status.to_i.between?(200, 399) unless status.nil?

          exit_code = key(result, :exit_code, key(result, :exitCode, nil))
          return exit_code.to_i.zero? unless exit_code.nil?
        end
        true
      end

      def failure_message(error)
        "#{error.class}: #{error.message}"
      end
    end

    # Pod lifecycle status aggregator.  It stores immutable snapshots and
    # optionally sends status-only updates through an injected reporter.
    class Status
      # v1.PodCondition on the wire: camelCase keys, reason/message only when
      # set, lastTransitionTime preserved while the status does not change.
      Condition = Data.define(
        :type, :status, :reason, :message, :last_transition_time, :last_heartbeat_time, :observed_generation
      ) do
        # observedGeneration (PodObservedGenerationTracking) is optional so
        # every existing constructor keeps working.
        def initialize(observed_generation: nil, **rest)
          super
        end

        def to_h
          {
            "type" => type,
            "status" => status,
            "lastProbeTime" => nil,
            "lastTransitionTime" => last_transition_time
          }.tap do |payload|
            payload["observedGeneration"] = observed_generation unless observed_generation.nil?
            # The status is delivered as a merge patch, so a field that is
            # simply omitted keeps whatever the API server already holds.  A
            # Pod that recovered from a failed mount would otherwise keep
            # reporting `FailedMount` as its reason for the rest of its life,
            # which is what `kubectl get pods` prints in the STATUS column.
            # An explicit null clears it.
            payload["reason"] = reason.to_s.empty? ? nil : reason
            payload["message"] = message.to_s.empty? ? nil : message
          end
        end
      end
      Snapshot = Data.define(
        :pod_uid, :phase, :conditions, :container_statuses, :init_container_statuses,
        :ephemeral_container_statuses,
        :reason, :message, :pod_ip, :host_ip, :start_time, :observed_generation, :pod_ips,
        :resources, :allocated_resources
      ) do
        def to_h
          {
            "phase" => phase,
            "conditions" => conditions.map(&:to_h),
            "containerStatuses" => Helpers.deep_copy(container_statuses),
            "initContainerStatuses" => Helpers.deep_copy(init_container_statuses)
          }.tap do |payload|
            # An ephemeral container has a status list of its own upstream; an
            # empty one is omitted so a Pod that never had a debug container
            # does not report an empty array it never had.
            unless Array(ephemeral_container_statuses).empty?
              payload["ephemeralContainerStatuses"] = Helpers.deep_copy(ephemeral_container_statuses)
            end
            # The status is delivered as a merge patch, so a field that is
            # simply omitted keeps whatever the API server already holds.  A
            # Pod that recovered from a failed mount would otherwise keep
            # reporting `FailedMount` as its reason for the rest of its life,
            # which is what `kubectl get pods` prints in the STATUS column.
            # An explicit null clears it.
            payload["reason"] = reason.to_s.empty? ? nil : reason
            payload["message"] = message.to_s.empty? ? nil : message
            payload["podIP"] = pod_ip unless pod_ip.to_s.empty?
            ips = Array(pod_ips).map(&:to_s).reject(&:empty?)
            ips = [pod_ip.to_s] if ips.empty? && !pod_ip.to_s.empty?
            payload["podIPs"] = ips.map { |ip| {"ip" => ip} } unless ips.empty?
            payload["hostIP"] = host_ip unless host_ip.to_s.empty?
            payload["hostIPs"] = [{"ip" => host_ip}] unless host_ip.to_s.empty?
            payload["startTime"] = start_time unless start_time.to_s.empty?
            payload["observedGeneration"] = observed_generation unless observed_generation.nil?
            # InPlacePodLevelResourcesVerticalScaling: the Pod's actuated and
            # allocated pod-level resources (kubelet_pods.go generateAPIPodStatus).
            payload["resources"] = Helpers.deep_copy(resources) unless resources.nil?
            payload["allocatedResources"] = Helpers.deep_copy(allocated_resources) unless allocated_resources.nil?
          end
        end
      end

      attr_reader :reporter, :endpoint_manager
      # ->(pod, status, seconds) after the API server took a status.
      attr_accessor :sync_observer

      def initialize(reporter: nil, endpoint_manager: nil, clock: -> { Time.now.utc })
        @reporter = reporter
        @endpoint_manager = endpoint_manager
        @clock = clock
        @mutex = Mutex.new
        @snapshots = {}
        @reported = {}
        # Per-Pod ordering of reports (see aggregate).
        @sequence = 0
        @reported_sequence = {}
        @report_locks = Hash.new { |locks, key| locks[key] = Mutex.new }
      end

      # Aggregate runtime observations into a Kubernetes-compatible status.
      # The returned object is detached and frozen so callers cannot mutate a
      # snapshot that another reconciliation thread is using.
      def aggregate(pod_value = nil, pod: nil, containers: nil, init_containers: nil, state: nil, phase: nil,
                    pod_ip: nil, host_ip: nil, reason: nil, message: nil,
                    observed_generation: nil, start_time: nil, pod_ips: nil, all_containers_restarting: false,
                    pod_resources: nil, allocated_resources: nil, resize_conditions: [])
        # The caller read the Pod's state just before this call: a sequence
        # taken now orders snapshots by when their inputs were read.
        sequence = @mutex.synchronize { @sequence += 1 }
        computed_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        pod = pod_value if pod.nil?
        object = Helpers.string_keys(pod || {})
        uid = Helpers.key(Helpers.key(object, "metadata", {}), "uid", nil).to_s
        uid = pod_key(object) if uid.empty?
        spec = Helpers.key(object, "spec", {})
        desired_containers = Array(containers || Helpers.key(spec, "containers", []))
        desired_init = Array(init_containers || Helpers.key(spec, "initContainers", []))
        desired_ephemeral = Array(Helpers.key(spec, "ephemeralContainers", []))
        observations = Helpers.string_keys(state || {})
        # kubelet convertToAPIContainerStatuses seeds every not-yet-started
        # container with a waiting state that always carries a reason: a Pod
        # with init containers reports PodInitializing, one without reports
        # ContainerCreating.  Ours reported `waiting: {}`, which every client
        # that prints or waits on a container's reason reads as no reason at
        # all.
        default_waiting = Array(Helpers.key(spec, "initContainers", [])).empty? ? "ContainerCreating" : "PodInitializing"
        regular_statuses = build_container_statuses(desired_containers, observations, regular: true,
                                                                                      default_waiting_reason: default_waiting)
        init_statuses = build_container_statuses(desired_init, observations, regular: false,
                                                                             default_waiting_reason: default_waiting)
        ephemeral_statuses = build_container_statuses(desired_ephemeral, observations, regular: :ephemeral,
                                                                                       default_waiting_reason: default_waiting)
        # A start that failed before any container was created leaves every
        # container unobserved; kubelet still reports the failure reason on
        # each waiting container (CreateContainerConfigError, ErrImagePull...),
        # and clients wait on exactly that reason.
        apply_container_reason(regular_statuses, reason, message)
        apply_container_reason(init_statuses, reason, message)
        phase = derive_phase(
          object,
          regular_statuses,
          init_statuses,
          explicit_phase: phase,
          explicit_reason: reason
        )
        earlier = @mutex.synchronize { @snapshots[uid] }
        conditions = build_conditions(
          phase: phase,
          regular_statuses: regular_statuses,
          init_statuses: init_statuses,
          pod: object,
          previous: earlier ? earlier.conditions : [],
          sandbox_ready: sandbox_ready?(object, pod_ip || Helpers.key(observations, "podIP", ""),
                                        regular_statuses, init_statuses),
          all_containers_restarting: all_containers_restarting
        )
        # PodResizePending / PodResizeInProgress carry the generation of the
        # resize they describe, not the Pod's current one.
        conditions += Array(resize_conditions).map do |entry|
          Condition.new(type: entry.fetch("type"), status: "True", reason: entry["reason"].to_s, message: entry["message"].to_s,
                        last_transition_time: entry["lastTransitionTime"] || Helpers.now(@clock).iso8601(6),
                        last_heartbeat_time: Helpers.now(@clock).iso8601(6), observed_generation: entry["observedGeneration"])
        end
        snapshot = Snapshot.new(
          pod_uid: uid,
          phase: phase,
          conditions: conditions.freeze,
          container_statuses: Helpers.immutable(regular_statuses),
          init_container_statuses: Helpers.immutable(init_statuses),
          ephemeral_container_statuses: Helpers.immutable(ephemeral_statuses),
          reason: reason.to_s,
          message: message.to_s,
          pod_ip: pod_ip || Helpers.key(observations, "podIP", ""),
          host_ip: host_ip || Helpers.key(observations, "hostIP", ""),
          start_time: first_start_time(start_time, observations, object, earlier),
          observed_generation: observed_generation || Helpers.key(observations, "observedGeneration", nil),
          pod_ips: Array(pod_ips || Helpers.key(observations, "podIPs", [])).map { |entry| Helpers.key(entry, "ip", entry).to_s }.freeze,
          resources: pod_resources.nil? ? nil : Helpers.immutable(pod_resources),
          allocated_resources: allocated_resources.nil? ? nil : Helpers.immutable(allocated_resources)
        ).freeze
        status = snapshot.to_h
        # Several threads compute a Pod's status (the sync loop, probes,
        # container events, a resize) and each reports its own.  Unordered, a
        # status computed before a later one could land after it: a probe's
        # snapshot taken while a resize was running delivered
        # PodResizeInProgress after the resize's own "completed" report, and
        # the condition stayed on the Pod ("[sig-node] Pod InPlace Resize ...
        # unexpected resize condition type PodResizeInProgress").  kubelet's
        # status manager never sends a status older than one it has sent; a
        # snapshot older than the newest delivered one is dropped here.
        report_lock = @mutex.synchronize { @report_locks[uid] }
        report_lock.synchronize do
          stale = @mutex.synchronize do
            newer = @reported_sequence[uid].to_i > sequence
            @snapshots[uid] = snapshot unless newer
            newer
          end
          return @mutex.synchronize { @snapshots[uid] } if stale

          publish_in_order(uid, object, status, sequence, computed_at)
        end
        snapshot
      end

      def publish_in_order(uid, object, status, sequence, computed_at = nil)
        already_reported = @mutex.synchronize { @reported[uid] == status }
        # kubelet's status manager only talks to the API server when the
        # status it computed differs from the one it last delivered.  Without
        # that check a steady Pod is patched once per reconcile, and every
        # patch is a write through consensus for a status nobody changed.
        # The comparison is on the status payload that goes on the wire, not
        # on the snapshot: a snapshot carries per-observation bookkeeping such
        # as a condition's heartbeat time that never reaches the API server,
        # and comparing that would make every pass look like a change.  The
        # last *delivered* payload is tracked separately from the last
        # computed snapshot, so a failed report is retried on the next pass.
        unless already_reported
          delivered = report(object, status)
          @mutex.synchronize { @reported[uid] = Helpers.deep_copy(status) }
          # statusManager.syncPod: kubelet_pod_status_sync_duration_seconds
          # from the status's computation, and the startup SLI's first
          # all-running status.
          if delivered && @sync_observer
            begin
              @sync_observer.call(object, status, computed_at && (Process.clock_gettime(Process::CLOCK_MONOTONIC) - computed_at))
            rescue StandardError
              nil
            end
          end
        end
        @mutex.synchronize { @reported_sequence[uid] = sequence }
      end

      alias update aggregate

      def [](pod_or_uid)
        @mutex.synchronize { @snapshots[pod_uid(pod_or_uid)] }
      end

      def fetch(pod_or_uid)
        self[pod_or_uid] || raise(KeyError, "status is not available for #{pod_uid(pod_or_uid)}")
      end

      def all
        @mutex.synchronize { @snapshots.values.dup.freeze }
      end

      def status_for(pod_or_uid)
        snapshot = self[pod_or_uid]
        snapshot&.to_h
      end

      alias status status_for

      def remove(pod_or_uid)
        @mutex.synchronize do
          key = pod_uid(pod_or_uid)
          @reported.delete(key)
          @reported_sequence.delete(key)
          @report_locks.delete(key)
          @snapshots.delete(key)
        end
      end

      # Mark a Pod unavailable before termination.  Endpoint managers are
      # intentionally injected because M4 owns the concrete endpoint store.
      def remove_from_endpoints(pod_or_uid, pod: nil)
        return unless @endpoint_manager

        uid = pod_uid(pod || pod_or_uid)
        if @endpoint_manager.respond_to?(:remove)
          @endpoint_manager.remove(uid)
        elsif @endpoint_manager.respond_to?(:set_ready)
          @endpoint_manager.set_ready(uid, false)
        elsif @endpoint_manager.respond_to?(:mark_not_ready)
          @endpoint_manager.mark_not_ready(uid)
        end
      end

      def ready?(pod_or_uid)
        snapshot = self[pod_or_uid]
        return false unless snapshot

        condition = snapshot.conditions.find { |entry| entry.type == "Ready" }
        condition&.status == "True"
      end

      def pod_uid(value)
        return value.to_s unless value.is_a?(Hash)

        metadata = Helpers.key(value, "metadata", {})
        uid = Helpers.key(metadata, "uid", nil)
        return uid.to_s unless uid.nil? || uid.to_s.empty?

        pod_key(value)
      end

      private

      def pod_key(pod)
        metadata = Helpers.key(pod, "metadata", {})
        namespace = Helpers.key(metadata, "namespace", "default")
        name = Helpers.key(metadata, "name", "")
        "#{namespace}/#{name}"
      end

      CONTAINER_WAITING_REASONS = %w[CreateContainerConfigError CreateContainerError ErrImagePull ImagePullBackOff InvalidImageName].freeze

      # The seeded PodInitializing/ContainerCreating reason is a placeholder,
      # not an observation: kubelet replaces it with the real failure the same
      # way it would fill an empty one (kubelet_pods.go isDefaultWaitingStatus).
      DEFAULT_WAITING_REASONS = %w[PodInitializing ContainerCreating].freeze

      def apply_container_reason(statuses, reason, message)
        return unless CONTAINER_WAITING_REASONS.include?(reason.to_s)

        statuses.each do |status|
          waiting = status.is_a?(Hash) && status.dig("state", "waiting")
          next unless waiting.is_a?(Hash)
          next unless waiting["reason"].to_s.empty? || DEFAULT_WAITING_REASONS.include?(waiting["reason"].to_s)

          waiting["reason"] = reason.to_s
          waiting["message"] = message.to_s unless message.to_s.empty?
        end
      end

      def build_container_statuses(desired, observations, regular:, default_waiting_reason: "ContainerCreating")
        section = case regular
                  when :ephemeral then "ephemeralContainers"
                  when true then "containers"
                  else "initContainers"
                  end
        observed = Helpers.key(observations, section, observations)
        observed = Helpers.string_keys(observed || {})
        if observed.is_a?(Array)
          observed = observed.each_with_object({}) do |entry, result|
            name = Helpers.key(entry, "name", nil)
            result[name.to_s] = entry if name
          end
        end
        desired.map do |container|
          definition = Helpers.string_keys(container || {})
          name = Helpers.key(definition, "name", "")
          runtime = Helpers.key(observed, name, {})
          runtime = Helpers.string_keys(runtime || {})
          normalize_container_status(definition, runtime, default_waiting_reason: default_waiting_reason)
        end
      end

      def normalize_container_status(definition, runtime, default_waiting_reason: "ContainerCreating")
        status = Helpers.key(runtime, "status", runtime)
        status = Helpers.string_keys(status || {})
        state = Helpers.key(status, "state", nil)
        state = infer_state(status) if state.nil?
        image = Helpers.key(status, "image", Helpers.key(definition, "image", ""))
        image_id = Helpers.key(status, "imageID", Helpers.key(status, "image_id", ""))
        result = {
          "name" => Helpers.key(definition, "name", Helpers.key(status, "name", "")).to_s,
          "image" => image.to_s,
          "imageID" => image_id.to_s,
          "ready" => !!Helpers.key(status, "ready", state == "running"),
          "restartCount" => Integer(Helpers.key(status, "restartCount", Helpers.key(status, "restart_count", 0)) || 0),
          "state" => state_hash(state, status, default_waiting_reason: default_waiting_reason),
          "started" => !!Helpers.key(status, "started", state == "running")
        }
        container_id = Helpers.key(status, "containerID", Helpers.key(status, "container_id", nil))
        result["containerID"] = container_id.to_s unless container_id.nil? || container_id.to_s.empty?
        # kubelet convertToAPIContainerStatuses: a running container reports
        # the resources it runs with (never nil -- clients dereference it)
        # and allocatedResources carries its requests.
        if state.to_s == "running"
          resources = Helpers.key(definition, "resources", nil)
          resources = {} unless resources.is_a?(Hash)
          result["resources"] = Helpers.deep_copy(resources)
          requests = Helpers.key(resources, "requests", nil)
          result["allocatedResources"] = Helpers.deep_copy(requests) if requests.is_a?(Hash) && !requests.empty?
        end
        last_state = Helpers.key(status, "lastState", Helpers.key(status, "last_state", nil))
        result["lastState"] = Helpers.deep_copy(last_state) if last_state
        user = Helpers.key(status, "user", nil)
        result["user"] = Helpers.deep_copy(user) if user.is_a?(Hash)
        health = Helpers.key(status, "allocatedResourcesStatus", nil)
        result["allocatedResourcesStatus"] = Helpers.deep_copy(health) if health.is_a?(Array) && !health.empty?
        mounts = volume_mount_statuses(definition)
        result["volumeMounts"] = mounts if mounts && %w[running terminated].include?(state.to_s)
        result
      end

      # RecursiveReadOnlyMounts: each volume mount as the container got it;
      # a read-only one says whether it is recursively read-only (the node
      # applies Enabled and IfPossible, see NativeAdapters#recursive_readonly).
      def volume_mount_statuses(definition)
        mounts = Array(Helpers.key(definition, "volumeMounts", []))
        return nil if mounts.empty?

        mounts.map do |mount|
          mount = Helpers.string_keys(mount)
          entry = {"name" => mount["name"].to_s, "mountPath" => mount["mountPath"].to_s}
          entry["readOnly"] = true if mount["readOnly"] == true
          if mount["readOnly"] == true
            entry["recursiveReadOnly"] = %w[Enabled IfPossible].include?(mount["recursiveReadOnly"].to_s) ? "Enabled" : "Disabled"
          end
          entry
        end
      end

      def infer_state(status)
        return "running" if status.key?("running")
        return "terminated" if status.key?("terminated")
        return "waiting" if status.key?("waiting")
        return "running" if Helpers.key(status, "running", false)
        return "terminated" if Helpers.key(status, "terminated", false)
        return "waiting" if Helpers.key(status, "waiting", false)

        "waiting"
      end

      def state_hash(state, status, default_waiting_reason: "ContainerCreating")
        case state.to_s.downcase
        when "running"
          running = Helpers.key(status, "running", {})
          {"running" => Helpers.string_keys(running.is_a?(Hash) ? running : {})}
        when "terminated", "exited"
          terminated = Helpers.key(status, "terminated", {})
          terminated = Helpers.string_keys(terminated.is_a?(Hash) ? terminated : {})
          terminated["exitCode"] = Integer(Helpers.key(status, "exitCode", Helpers.key(terminated, "exitCode", 0)) || 0)
          {"terminated" => terminated}
        else
          waiting = Helpers.key(status, "waiting", {})
          waiting = Helpers.string_keys(waiting.is_a?(Hash) ? waiting : {})
          waiting["reason"] = default_waiting_reason if waiting["reason"].to_s.empty?
          {"waiting" => waiting}
        end
      end

      def derive_phase(pod, regular_statuses, init_statuses, explicit_phase:, explicit_reason:)
        # A terminal or explicit non-Running phase is the lifecycle's verdict;
        # "Running" is only ever what the container states say (kubelet has no
        # other source), so a Pod whose third container is still being
        # created stays Pending however far the start sequence got.
        return explicit_phase.to_s unless explicit_phase.nil? || explicit_phase.to_s == "Running"

        restart_policy = Helpers.key(Helpers.key(pod, "spec", {}), "restartPolicy", "Always").to_s
        failed_init = init_statuses.find { |status| terminated_failure?(status) }
        return "Failed" if failed_init && restart_policy == "Never"
        # A container removed by RestartAllContainers waits with that reason
        # as its last termination: kubelet getPhase counts it as a stopped
        # container that will restart, not as one that never started.
        return "Pending" if init_statuses.any? { |status| !init_initialized?(status) && !restarting_all?(status) }

        # kubelet getPhase (pkg/kubelet/kubelet_pods.go): count the regular
        # containers by state.  A container still Waiting (no earlier
        # termination) keeps the Pod Pending -- "Running" means every
        # container has been started.  Reporting Running with a container
        # still ContainerCreating let clients ask for its logs and get a 400
        # ("[sig-network] DNS should provide DNS for ExternalName services"
        # reads every container's logs once the Pod is Running).
        running = stopped = succeeded = waiting = 0
        restartable_stopped = 0
        regular_statuses.each do |status|
          state = Helpers.key(status, "state", {})
          terminated = Helpers.key(state, "terminated", nil)
          last_terminated = Helpers.key(Helpers.key(status, "lastState", {}), "terminated", nil)
          if Helpers.key(state, "running", nil)
            running += 1
          elsif restarting_all?(status)
            stopped += 1
            restartable_stopped += 1
          elsif terminated || last_terminated
            stopped += 1
            exit_code = Integer(Helpers.key(terminated || last_terminated, "exitCode", 1) || 1)
            succeeded += 1 if terminated && exit_code.zero?
            restartable_stopped += 1 if restart_policy == "Always" || (restart_policy == "OnFailure" && !exit_code.zero?)
          else
            waiting += 1
          end
        end
        expected = Array(Helpers.key(Helpers.key(pod, "spec", {}), "containers", [])).length
        unknown = [expected - regular_statuses.length, 0].max
        return "Pending" if waiting.positive?
        return "Running" if running.positive? && unknown.zero?

        if running.zero? && stopped.positive? && unknown.zero?
          return "Failed" if explicit_reason.to_s == "Failed" && restart_policy == "Never"
          return "Running" if restartable_stopped.positive?
          return "Succeeded" if stopped == succeeded

          return "Failed"
        end
        return "Failed" if explicit_reason.to_s == "Failed"

        "Pending"
      end

      def sidecar_names(pod)
        Array(Helpers.key(Helpers.key(pod, "spec", {}), "initContainers", [])).filter_map do |container|
          Helpers.key(container, "restartPolicy", nil).to_s == "Always" ? Helpers.key(container, "name", nil).to_s : nil
        end
      end

      def restarting_all?(status)
        Helpers.key(Helpers.key(Helpers.key(status, "state", {}), "waiting", {}) || {}, "reason", nil).to_s == "RestartingAllContainers"
      end

      def terminated_success?(status)
        terminated = Helpers.key(status, "state", {})["terminated"]
        !terminated.nil? && Integer(Helpers.key(terminated, "exitCode", 1) || 1).zero?
      end

      def terminated_failure?(status)
        terminated = Helpers.key(status, "state", {})["terminated"]
        !terminated.nil? && !Integer(Helpers.key(terminated, "exitCode", 1) || 1).zero?
      end

      def init_initialized?(status)
        return true if terminated_success?(status)

        state = Helpers.key(status, "state", {})
        !Helpers.key(state, "running", nil).nil? && !status["ready"].nil?
      end

      # kubelet's status manager stamps startTime on the first status it ever
      # publishes for a Pod and never moves it again
      # (pkg/kubelet/status/status_manager.go updateStatusInternal).  A Pod
      # whose startTime stayed nil reports no start at all to every client that
      # measures how long it took to run.
      def first_start_time(explicit, observations, pod, earlier)
        value = explicit || Helpers.key(observations, "startTime", nil)
        value ||= earlier && earlier.start_time
        value ||= Helpers.key(Helpers.key(pod, "status", {}), "startTime", nil)
        value || Helpers.now(@clock).iso8601(6)
      end

      # GeneratePodReadyToStartContainersCondition is True once a sandbox with
      # networking already exists, which is exactly when a container has been
      # observed and the Pod holds the address its containers will run on.
      def sandbox_ready?(pod, pod_ip, regular_statuses, init_statuses)
        observed = (regular_statuses + init_statuses).any? do |status|
          state = Helpers.key(status, "state", {})
          !Helpers.key(state, "running", nil).nil? || !Helpers.key(state, "terminated", nil).nil?
        end
        return false unless observed
        return true if Helpers.key(Helpers.key(pod, "spec", {}), "hostNetwork", false) == true

        !pod_ip.to_s.empty?
      end

      def build_conditions(phase:, regular_statuses:, init_statuses:, pod:, previous: [], sandbox_ready: false,
                           all_containers_restarting: false)
        timestamp = Helpers.now(@clock).iso8601(6)
        # GeneratePodInitializedCondition: a restartable init container
        # (sidecar) counts once it has started; only regular init containers
        # have to run to completion.  Requiring every sidecar to have exited
        # 0 kept a Pod with a running sidecar ContainersNotInitialized for ever.
        sidecars = sidecar_names(pod)
        init_done = ->(status) { terminated_success?(status) || (sidecars.include?(status["name"].to_s) && status["started"] == true) }
        initialized = init_statuses.all?(&init_done)
        # GeneratePodInitializedCondition (RestartAllContainersOnContainerExits):
        # a Pod once initialized stays initialized while its init containers
        # run again in place.
        initialized ||= Array(previous).any? { |entry| entry.type == "Initialized" && entry.status == "True" }
        containers_ready = phase == "Running" && regular_statuses.any? && regular_statuses.all? { |status| status["ready"] }
        # kubelet GeneratePodReadyCondition: every readinessGate's condition
        # must also be True before the Pod is Ready.  spec.readinessGates was
        # validated by the API server and read by nobody, so a Pod with an
        # unsatisfied gate reported itself Ready.
        gates_ready = readiness_gates_satisfied?(pod, previous)
        # kubelet's Generate*Condition functions: a condition that is not True
        # says WHY, and clients print and wait on exactly those reasons.
        # Initialized is ContainersNotInitialized while an init container has
        # not finished; ContainersReady and Ready are PodCompleted once the Pod
        # is terminal and ContainersNotReady otherwise; Ready simply mirrors
        # ContainersReady whenever that is not True, and only then considers
        # the readiness gates.
        initialized_condition = condition("Initialized", initialized, timestamp)
        unless initialized
          incomplete = init_statuses.reject(&init_done)
            .map { |status| status["name"] }
          initialized_condition = condition(
            "Initialized", false, timestamp,
            reason: "ContainersNotInitialized",
            message: "containers with incomplete status: [#{incomplete.join(" ")}]"
          )
        end
        containers_ready_condition = containers_ready_state(containers_ready, phase, regular_statuses, timestamp)
        ready_condition = if containers_ready_condition.status != "True"
                            condition("Ready", false, timestamp,
                                      reason: containers_ready_condition.reason,
                                      message: containers_ready_condition.message)
                          elsif gates_ready
                            condition("Ready", true, timestamp)
                          else
                            condition("Ready", false, timestamp, reason: "ReadinessGatesNotReady",
                                                                 message: "corresponding condition of pod readiness gate is not \"True\"")
                          end
        conditions = [
          condition("PodReadyToStartContainers", sandbox_ready, timestamp),
          initialized_condition,
          containers_ready_condition
        ]
        conditions << ready_condition
        conditions << condition("PodScheduled", pod_scheduled?(pod), timestamp)
        restarting = all_containers_restarting_condition(pod, phase, all_containers_restarting, timestamp)
        conditions << restarting if restarting
        # PodObservedGenerationTracking: every condition the kubelet writes
        # names the metadata.generation it observed ("[sig-node] Pods Extended
        # pod observedGeneration field set in pod conditions").
        generation = Helpers.key(Helpers.key(pod, "metadata", {}), "generation", nil)
        (conditions + custom_conditions(pod, previous)).map do |entry|
          preserved = preserve_transition(entry, previous)
          generation.nil? ? preserved : preserved.with(observed_generation: Integer(generation))
        end.freeze
      end

      # status.GenerateAllContainersRestartingCondition, published only for a
      # Pod with a RestartAllContainers rule (podutil.AllContainersCouldRestart).
      def all_containers_restarting_condition(pod, phase, restarting, timestamp)
        return nil unless NodeDeclaredFeatures::Features::RestartAllContainers.new.infer_for_scheduling(pod)
        return condition("AllContainersRestarting", false, timestamp, reason: "PodCompleted") if phase.to_s == "Succeeded"
        return condition("AllContainersRestarting", false, timestamp, reason: "PodFailed") if phase.to_s == "Failed"
        return condition("AllContainersRestarting", false, timestamp, reason: "") unless restarting

        condition("AllContainersRestarting", true, timestamp, reason: "RestartAllContainersStarted",
                                                              message: "container exited with restart policy rule")
      end

      # generateContainersReadyConditionForTerminalPhase: a Pod that has
      # finished reports PodCompleted rather than a list of unready containers.
      def containers_ready_state(containers_ready, phase, regular_statuses, timestamp)
        return condition("ContainersReady", true, timestamp) if containers_ready
        return condition("ContainersReady", false, timestamp, reason: "PodCompleted") if %w[Succeeded Failed].include?(phase.to_s)

        unready = regular_statuses.reject { |status| status["ready"] }.map { |status| status["name"] }
        return condition("ContainersReady", false, timestamp) if unready.empty?

        condition("ContainersReady", false, timestamp, reason: "ContainersNotReady",
                                                       message: "containers with unready status: [#{unready.join(" ")}]")
      end

      # kubelet: lastTransitionTime only moves when the condition's status
      # changes.
      def preserve_transition(entry, previous)
        earlier = Array(previous).find { |candidate| candidate.type == entry.type }
        return entry if earlier.nil? || earlier.status != entry.status

        entry.with(last_transition_time: earlier.last_transition_time)
      end

      KUBELET_CONDITION_TYPES = %w[PodReadyToStartContainers Initialized ContainersReady Ready PodScheduled AllContainersRestarting
                                   PodResizePending PodResizeInProgress].freeze

      def readiness_gate_types(pod)
        Array(Helpers.key(Helpers.key(pod, "spec", {}), "readinessGates", [])).filter_map do |gate|
          value = Helpers.key(gate, "conditionType", nil).to_s
          value.empty? ? nil : value
        end
      end

      # A gate is satisfied only by an existing condition of that type whose
      # status is "True"; an absent condition is not ready.  The conditions a
      # gate names are written by something other than the kubelet, so they are
      # read from the Pod's current status.
      def readiness_gates_satisfied?(pod, previous)
        types = readiness_gate_types(pod)
        return true if types.empty?

        published = pod_conditions(pod, previous)
        types.all? { |type| published[type].to_s == "True" }
      end

      # Conditions the kubelet does not own (a readiness gate's own condition,
      # written by a controller) must survive a status update rather than be
      # dropped.
      def custom_conditions(pod, previous)
        published = pod_conditions(pod, previous)
        timestamp = Helpers.now(@clock).iso8601(6)
        published.reject { |type, _| KUBELET_CONDITION_TYPES.include?(type) }.map do |type, status|
          Condition.new(type: type, status: status.to_s, reason: "", message: "",
                        last_transition_time: timestamp, last_heartbeat_time: timestamp)
        end
      end

      def pod_conditions(pod, previous)
        result = {}
        Array(previous).each { |entry| result[entry.type.to_s] = entry.status.to_s }
        Array(Helpers.key(Helpers.key(pod, "status", {}), "conditions", [])).each do |entry|
          type = Helpers.key(entry, "type", nil).to_s
          next if type.empty?

          result[type] = Helpers.key(entry, "status", "").to_s
        end
        result
      end

      def pod_scheduled?(pod)
        spec = Helpers.key(pod, "spec", {})
        !Helpers.key(spec, "nodeName", nil).to_s.empty?
      end

      def condition(type, truthy, timestamp, reason: nil, message: nil)
        Condition.new(
          type: type,
          status: truthy ? "True" : "False",
          reason: reason || (truthy ? "" : "ContainersNotReady"),
          message: message.to_s,
          last_transition_time: timestamp,
          last_heartbeat_time: timestamp
        )
      end

      def report(pod, status)
        return unless @reporter

        uid = pod_uid(pod)
        if @reporter.respond_to?(:report)
          @reporter.report(pod, status)
        elsif @reporter.respond_to?(:update_status)
          @reporter.update_status(pod, status)
        elsif @reporter.respond_to?(:status)
          @reporter.status(uid, status)
        elsif @reporter.respond_to?(:update)
          begin
            @reporter.update(pod, status: status)
          rescue ArgumentError
            @reporter.update(uid, status)
          end
        elsif @reporter.respond_to?(:call)
          @reporter.call(pod, status)
        end
        true
      rescue StandardError => error
        # The Pod is already gone from the API (force-deleted, namespace
        # torn down): kubelet drops the status write instead of failing the
        # termination it was reporting.
        gone = (error.respond_to?(:status) && error.status.to_i == 404) || error.message.to_s.include?("HTTP 404")
        raise unless gone

        nil
      end
    end

    PodStatus = Status
  end
end
