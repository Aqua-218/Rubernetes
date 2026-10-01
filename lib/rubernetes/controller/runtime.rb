# frozen_string_literal: true

require "json"
require "time"
require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "store_adapter"
require_relative "apply_failures"
require_relative "lease"

module Rubernetes
  module Controller
    # Common reconcile execution path.  `plan` is pure; `reconcile` optionally
    # applies the resulting diff through StoreAdapter and always returns the
    # immutable decision record for tracing and property tests.
    class BaseController
      attr_reader :store, :definition, :name

      def initialize(store: nil, definition: nil, name: nil, apply: true, event_sink: nil)
        raise MissingReconcileError, "BaseController is abstract and requires a concrete controller implementation" if instance_of?(BaseController)

        @store = store
        @adapter = store && (store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store))
        @definition = definition
        @name = (name || definition&.name || self.class.name.split("::").last).to_s
        @apply = !!apply
        @event_sink = event_sink
      end

      # StaleControllerConsistency (Beta, on): the four workload controllers
      # remember the resourceVersion of the object they last wrote and skip a
      # sync whose informer copy is older than that (the watch cache has not
      # caught up), counting it in <controller>_stale_sync_skips_total and
      # retrying shortly after.
      CONSISTENCY_CONTROLLERS = {"daemonset-controller" => "daemonset_controller_stale_sync_skips_total",
                                 "job-controller" => "job_controller_stale_sync_skips_total",
                                 "replicaset-controller" => "replicaset_controller_stale_sync_skips_total",
                                 "statefulset-controller" => "statefulset_controller_stale_sync_skips_total"}.freeze
      STALE_SYNC_RETRY_SECONDS = 0.1

      module ConsistencyStore
        LOCK = Mutex.new
        WRITTEN = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache)

        module_function

        def newer?(candidate, current)
          Integer(candidate.to_s, 10) > Integer(current.to_s, 10)
        rescue ArgumentError, TypeError
          false
        end

        def record(controller, key, resource_version)
          return if resource_version.to_s.empty?

          LOCK.synchronize do
            current = WRITTEN[[controller.to_s, key]]
            WRITTEN[[controller.to_s, key]] = resource_version.to_s if current.nil? || newer?(resource_version, current)
          end
        end

        def expected(controller, key) = LOCK.synchronize { WRITTEN[[controller.to_s, key]] }
        def clear(controller, key) = LOCK.synchronize { WRITTEN.delete([controller.to_s, key]) }
        def reset! = LOCK.synchronize { WRITTEN.clear }
      end

      def reconcile(resource_or_key, store: @store, apply: nil, **options)
        leader_guard = options.delete(:leader_guard)
        raise ArgumentError, "leader_guard must respond to call" if leader_guard && !leader_guard.respond_to?(:call)

        adapter = store && (store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store))
        resource = resolve_resource(resource_or_key, adapter)
        stale = stale_sync_skip(resource)
        return stale if stale

        result = plan(resource, store: adapter, **options)
        should_apply = apply.nil? ? (!adapter.nil? && @apply) : !!apply
        return result unless should_apply

        begin
          responses = result.batches.each_with_object([]) do |batch, collected|
            batch_responses = Support.with_controller(result.controller || name) { adapter.apply_batch(batch, fence: leader_guard) }
            batch_responses.each_with_index do |response, index|
              collected << response
              @event_sink&.call(batch.fetch(index))
            end
          end
          ApplyFailures.clear(result.controller || name, result.key)
          remember_written_versions(resource, responses)
          responses
        rescue LeadershipLostError
          raise
        rescue StandardError => error
          # The planner has to be able to see that its last write was refused:
          # a ReplicaFailure condition exists for no other reason.
          record_apply_failure(result, error)
          raise
        end
        ReconcileResult.new(operations: result.operations, batches: result.batches, status: result.status,
                            events: result.events, controller: result.controller,
                            key: result.key, applied: true, requeue_after: result.requeue_after).tap { |_record| }
      end

      def plan(_resource, store: nil, **_options)
        raise MissingReconcileError, "controller #{self.class} must implement #plan before it can reconcile"
      end

      def consistency_prefix
        CONSISTENCY_CONTROLLERS[name.to_s]
      end

      def consistency_key(resource)
        "#{Support.namespace(resource)}/#{Support.name(resource)}"
      end

      # nil when the sync proceeds, else the result standing in for the skip.
      def stale_sync_skip(resource)
        prefix = consistency_prefix
        return nil unless prefix && resource.is_a?(Hash)

        key = consistency_key(resource)
        expected = ConsistencyStore.expected(name, key)
        return nil if expected.nil?

        cached = Support.value(Support.metadata(resource), "resourceVersion", nil).to_s
        unless ConsistencyStore.newer?(expected, cached)
          ConsistencyStore.clear(name, key)
          return nil
        end
        descriptor = respond_to?(:resource_descriptor) ? resource_descriptor : nil
        ControllerMetrics.increment(prefix,
                                    {"group" => descriptor.respond_to?(:group) ? descriptor.group.to_s : "",
                                     "resource" => descriptor.respond_to?(:resource) ? descriptor.resource.to_s : ""})
        ReconcileResult.new(controller: name, key: key, requeue_after: STALE_SYNC_RETRY_SECONDS)
      end

      # The resourceVersions this sync wrote to the object it reconciles.
      def remember_written_versions(resource, responses)
        return unless consistency_prefix && resource.is_a?(Hash)

        kind = Support.kind(resource).to_s
        key = consistency_key(resource)
        Array(responses).each do |response|
          next unless response.is_a?(Hash) && Support.kind(response).to_s == kind && consistency_key(response) == key

          ConsistencyStore.record(name, key, Support.value(Support.metadata(response), "resourceVersion", nil))
        end
      rescue StandardError
        nil
      end

      # A key whose object is gone can still owe work.  A deleted Job leaves
      # its Pods holding the tracking finalizer, and with the Job removed no
      # sync will ever release them: the Pods stay Terminating and their
      # namespace never finishes deleting.  A controller with such cleanup
      # implements #plan_orphans; the reconcile loop calls it for a key that
      # resolves to nothing.  Returning nil means there is nothing to do.
      def plan_orphans(_key, store: nil)
        nil
      end

      # Overridden to true by a controller that implements #plan_orphans, so
      # the reconcile loop does not pay a store lookup per controller per key
      # asking the ones that never have orphan work.
      def orphan_cleanup?
        false
      end

      def reconcile_orphans(key, store: @store, apply: true, leader_guard: nil)
        adapter = store && (store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store))
        result = plan_orphans(key, store: adapter)
        return nil if result.nil?
        return result unless apply && adapter

        Support.with_controller(result.controller || name) do
          result.batches.each { |batch| adapter.apply_batch(batch, fence: leader_guard) }
        end
        result
      end

      # Controllers expose the same lifecycle vocabulary even when a
      # particular resource treats one operation as a no-op.  Keeping these
      # entry points on the common boundary lets callers issue a lifecycle
      # request without reaching into an implementation class.
      def rollout(resource, **)
        plan(resource, **)
      end

      def rollback(resource, **)
        plan(resource, **)
      end

      def scale(resource, replicas = nil, **)
        return plan(resource, **) if replicas.nil?

        candidate = Support.deep_copy(resource)
        candidate["spec"] ||= {}
        candidate["spec"]["replicas"] = Integer(replicas)
        plan(candidate, **)
      end

      def delete(resource, **_options)
        descriptor = ResourceDescriptor.parse(resource)
        ReconcileResult.new(operations: [operation_delete(resource, descriptor: descriptor, reason: "resource deletion")],
                            controller: name,
                            key: [Support.namespace(resource), Support.name(resource)].compact.join("/"))
      end

      def owned(resource, children, controller: true)
        Array(children).select { |child| Support.owner_reference_matches?(resource, child, controller: controller) }
      end

      def operation_update(resource, candidate, descriptor: nil, reason: nil)
        return nil if resource == candidate

        descriptor ||= ResourceDescriptor.parse(resource)
        Operation.new(action: :update, resource: descriptor,
                      key: object_key(descriptor, candidate), object: candidate,
                      reason: reason)
      end

      def operation_status(resource, status, descriptor: nil, reason: "status update", force: false)
        return nil if !force && Support.status(resource) == status

        descriptor ||= ResourceDescriptor.parse(resource)
        Operation.new(action: :status_update, resource: descriptor,
                      key: object_key(descriptor, resource), object: resource,
                      patch: status, reason: reason)
      end

      # A JSON merge patch of the status subresource: the fields named, nil
      # removing one.  For a controller that owns a single field of a status
      # another component writes (the attach/detach controller's
      # node.status.volumesAttached, PatchNodeStatus upstream).
      def operation_status_merge(resource, patch, descriptor: nil, reason: "status patch")
        descriptor ||= ResourceDescriptor.parse(resource)
        Operation.new(action: :status_merge, resource: descriptor, key: object_key(descriptor, resource), object: resource,
                      patch: patch, reason: reason)
      end

      def operation_create(object, owner: nil, descriptor: nil, reason: nil, operation_key: nil)
        candidate = Support.deep_copy(object)
        candidate["metadata"] ||= {}
        if owner
          refs = Array(candidate["metadata"]["ownerReferences"])
          reference = Support.owner_reference(owner)
          refs.reject! do |existing|
            controller = Support.ref_value(existing, "controller", false)
            controller == true || controller.to_s.casecmp("true").zero? ||
              (Support.ref_value(existing, "kind", "").to_s == Support.kind(owner) &&
               Support.ref_value(existing, "name", "").to_s == Support.name(owner))
          end
          refs << reference
          candidate["metadata"]["ownerReferences"] = refs
        end
        descriptor ||= ResourceDescriptor.parse(candidate)
        Operation.new(action: :create, resource: descriptor,
                      key: operation_key || object_key(descriptor, candidate), object: candidate,
                      owner: owner, reason: reason)
      end

      def record_apply_failure(result, error)
        ApplyFailures.record_apply_failure(result, error, fallback: name)
      end

      # +options+: DeleteOptions for the request ({"gracePeriodSeconds" => 0}
      # for a force delete), carried as the operation's patch.
      def operation_delete(object, descriptor: nil, reason: nil, options: nil)
        descriptor ||= ResourceDescriptor.parse(object)
        Operation.new(action: :delete, resource: descriptor,
                      key: object_key(descriptor, object), object: object,
                      patch: options, reason: reason)
      end

      # The events of a sync that reports the same thing as the last sync of
      # the same object, emitted once.  Upstream's recorder folds each repeat
      # into the existing Event (EventCorrelator) and its spam filter drops
      # the rest; here a replay of an unchanged object emits nothing, which
      # the controller idempotency contract (controllers.md §5.5.1) requires.
      # A changed set is emitted in full and remembered.
      def once_per_state(key, events)
        events = Array(events)
        signature = events.map do |event|
          if event.is_a?(Hash)
            event.reject do |field, _|
              field.to_s == "involvedObject"
            end.sort.to_s
          else
            event.to_s
          end
        end
        @emitted_events_mutex ||= Mutex.new
        @emitted_events_mutex.synchronize do
          @emitted_events ||= {}
          @emitted_events.shift while @emitted_events.size > 4096
          return [] if !events.empty? && @emitted_events[key.to_s] == signature

          @emitted_events[key.to_s] = signature
        end
        events
      end

      protected

      def resolve_resource(resource_or_key, adapter)
        if resource_or_key.is_a?(Hash)
          return resource_or_key unless adapter

          descriptor = ResourceDescriptor.parse(resource_or_key)
          current = adapter.find(descriptor, name: Support.name(resource_or_key), namespace: Support.namespace(resource_or_key))
          return current || resource_or_key
        end
        raise ArgumentError, "resource key requires a store" unless adapter

        key = resource_or_key.to_s
        all = adapter.list(resource_descriptor, namespace: :all)
        found = all.find do |object|
          [Support.namespace(object), Support.name(object)].compact.join("/") == key ||
            Support.name(object) == key || object_key(ResourceDescriptor.parse(object), object) == key
        end
        raise StoreError, "resource #{key.inspect} was not found" unless found

        found
      end

      def object_key(descriptor, object)
        namespace = descriptor.cluster_scoped? ? "_cluster" : (Support.namespace(object) || "default")
        "registry/#{descriptor.api_version}/#{descriptor.resource}/#{namespace}/#{Support.name(object)}"
      end

      def resource_descriptor
        ResourceDescriptor.parse(@definition&.kind || infer_kind)
      end

      def infer_kind
        self.class.name.to_s.split("::").last.delete_suffix("Controller")
      end

      public :resource_descriptor
    end

    # Executes a ControllerDefinition's reconcile block while retaining the
    # definition's factory closure and injected configuration. Factory
    # definitions (for example cloud and certificate controllers) are the
    # compatibility boundary; instantiating their implementation class
    # directly would silently discard those captured dependencies.
    class DefinitionController
      attr_reader :definition, :store

      def initialize(definition, store:, options: {})
        @definition = definition
        @store = store
        @options = options.is_a?(Hash) ? options.dup : {}
        @event_sink = @options.delete(:event_sink) || @options.delete("event_sink")
        @options.freeze
      end

      def name
        definition.name
      end

      # A separate instance from the one the reconcile block keeps: the
      # planner is pure, so a second one costs nothing and keeps the orphan
      # path independent of the reconcile path's lazily built state.
      def orphan_implementation(store)
        @orphan_mutex ||= Mutex.new
        @orphan_mutex.synchronize do
          @orphan_implementation ||= definition.implementation.new(store: store, definition: definition)
        end
      end
      private :orphan_implementation

      # Asks the orphan pass for its next run as soon as a key carries it:
      # the garbage collector's sweep after an owner was deleted.
      def expedite_orphan_pass!
        return false unless orphan_cleanup?

        implementation = orphan_implementation(@store)
        return false unless implementation.respond_to?(:expedite_sweeps!)

        implementation.expedite_sweeps!
        true
      end

      def resource_descriptor
        definition.kind
      end

      def plan(resource, store: @store, **options)
        merged_options = @options.merge(options)
        merged_options[:store] ||= store
        result = definition.reconcile(resource, {store: store, options: merged_options})
        return result if result.is_a?(ReconcileResult)

        raise MissingReconcileError,
              "controller #{name} reconcile block must return a ReconcileResult"
      end

      # The reconcile loop asks every controller whether it owes cleanup for a
      # key whose object is gone.  A built-in controller reaches the loop
      # wrapped in this definition, so the hook has to be delegated: without
      # it BaseController#plan_orphans is only ever reachable from a test that
      # instantiates the implementation directly.
      def orphan_cleanup?
        klass = definition&.implementation
        return false unless klass.is_a?(Class) && klass.method_defined?(:plan_orphans)

        klass.instance_method(:plan_orphans).owner != BaseController
      rescue NameError
        false
      end

      def plan_orphans(key, store: @store)
        return nil unless orphan_cleanup?

        orphan_implementation(store).plan_orphans(key, store: store)
      end

      def reconcile_orphans(key, store: @store, apply: true, leader_guard: nil)
        result = plan_orphans(key, store: store)
        return nil if result.nil?
        return result unless apply

        adapter = store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store)
        Support.with_controller(result.controller || name) do
          result.batches.each { |batch| adapter.apply_batch(batch, fence: leader_guard) }
        end
        result
      end

      def record_apply_failure(result, error)
        ApplyFailures.record_apply_failure(result, error, fallback: name)
      end

      def reconcile(resource, store: @store, apply: true, leader_guard: nil, **)
        result = plan(resource, store: store, **)

        return result unless apply

        adapter = store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store)
        begin
          Support.with_controller(result.controller || name) do
            result.batches.each { |batch| adapter.apply_batch(batch, fence: leader_guard) }
          end
          ApplyFailures.clear(result.controller || name, result.key)
        rescue LeadershipLostError
          raise
        rescue StandardError => error
          record_apply_failure(result, error)
          raise
        end
        @event_sink&.call(resource, result)
        ReconcileResult.new(operations: result.operations, batches: result.batches,
                            status: result.status, events: result.events,
                            controller: result.controller || name, key: result.key,
                            applied: true, requeue_after: result.requeue_after)
      end
    end

    # Deterministic controller-manager wrapper.  Informer and WorkQueue are
    # supplied by the existing watch package; this class only owns the bridge
    # from queue keys to controller reconcile calls and the leader gate.
    class Manager
      attr_reader :registry, :elector, :controllers, :queue, :informers, :last_error

      # A reconcile that takes longer than this is reported: one slow key
      # blocks every other key behind it, and a manager that goes quiet for
      # minutes is otherwise indistinguishable from an idle one.
      SLOW_RECONCILE_SECONDS = 5.0

      # kube-controller-manager runs each controller with several workers
      # (--concurrent-*-syncs, five by default for most of them).  Ours drained
      # one key at a time, and since a reconcile is dominated by API round
      # trips -- not CPU -- the loop idled while the queue grew: under a
      # parallel conformance run a new namespace waited over two minutes for
      # its default ServiceAccount.  The WorkQueue already hands a key to
      # exactly one worker, so the drain can be shared.
      #
      # Four was still far too few.  Upstream gives EACH of its forty-odd
      # controllers its own pool of five; ours share one, so four workers meant
      # the whole control plane had less concurrency than upstream gives a
      # single controller.  Measured under a parallel conformance run, the four
      # workers were 97% saturated and the average key waited 40 seconds.
      DEFAULT_WORKER_COUNT = 16

      def initialize(store:, identity:, registry: nil, lease: {}, queue: nil, controller_options: {},
                     error_handler: nil, slow_handler: nil, orphan_handler: nil,
                     worker_count: DEFAULT_WORKER_COUNT, store_for: nil)
        require_relative "../watch/work_queue"
        # Reconcile failures are retried through the WorkQueue; the handler
        # is how a process gets to log them (kube-controller-manager logs
        # every sync error) instead of learning about them from silence.
        @error_handler = error_handler
        @slow_handler = slow_handler
        @orphan_handler = orphan_handler
        @store = store
        # --use-service-account-credentials: the store each controller
        # reconciles and applies through (its own ServiceAccount's client);
        # nil, or a nil answer, is the manager's store.
        @store_for = store_for
        @controller_stores = {}
        @registry = registry || Controller.default_registry
        # Fail closed before any informer can enqueue work.  A controller
        # manager with an incomplete corpus must never start processing
        # resources it cannot reconcile.
        @registry.startup_validate!
        # One queue drained by every controller (workqueue_* as
        # "controller-manager").
        @queue = queue || Rubernetes::Watch::WorkQueue.new(name: "controller-manager")
        @elector = LeaseElector.new(store: store, identity: identity, **lease)
        @elector_mutex = Mutex.new
        @worker_count = [Integer(worker_count), 1].max
        @reconciled_total = 0
        @reconciled_mutex = Mutex.new
        # Where a key's time actually goes.  Queue wait says the loop is
        # behind; this says which half of the work put it there.
        @key_time = Hash.new(0.0)
        @key_count = 0
        @orphan_capable = nil
        @orphan_capable_generation = nil
        @controller_options = normalize_controller_options(controller_options)
        validate_required_providers!
        @controllers = {}
        @informers = {}
        @manager_mutex = Mutex.new
        @queue_routes = {}
        @timer_routes = {}
        @route_mutex = Mutex.new
        @running = false
        @last_error = nil
      end

      def store_for(controller)
        return @store unless @store_for

        name = controller.respond_to?(:name) ? controller.name.to_s : controller.to_s
        @manager_mutex.synchronize do
          @controller_stores.fetch(name) { @controller_stores[name] = @store_for.call(name) || @store }
        end
      end

      def register(controller, name: nil)
        definition = controller.respond_to?(:definition) ? controller.definition : nil
        key = (name || definition&.name || controller.name).to_s
        raise ArgumentError, "controller name must not be empty" if key.empty?

        @manager_mutex.synchronize do
          existing = @controllers[key]
          raise DuplicateControllerError, "controller #{key.inspect} is already registered" if existing && !existing.equal?(controller)

          @controllers[key] = controller
        end
        self
      end

      def register_definition(definition, store: @store, options: @controller_options)
        raise UnknownControllerError, "controller #{definition.name} has no implementation" unless definition.implementation

        register(DefinitionController.new(definition, store: store, options: options), name: definition.name)
      end

      def register_informer(name, informer)
        raise ArgumentError, "informer must respond to on" unless informer.respond_to?(:on)

        normalized_name = name.to_s
        raise ArgumentError, "controller name must not be empty" if normalized_name.empty?

        @manager_mutex.synchronize { @informers[normalized_name] = informer }
        informer.on do |object, old_object = nil, type = nil|
          enqueue_for(normalized_name, object, old_object, type)
          owner_deleted if type == :delete
        end
        self
      end

      # garbagecollector.go reacts to a deletion through its dependency graph
      # at once; the sweep here ran every ten seconds unless it had already
      # seen an owner in foreground deletion.  An owner removed outright -- a
      # Pod deleted with its dependents' ownerReferences pointing at it --
      # left them for the next sweep, and a chain of owners cost ten seconds
      # a link ("should not be blocked by dependency circle": 20 s, upstream
      # 5).  Any delete now brings the next sweep forward (at most one a
      # second, FOREGROUND_SWEEP_SECONDS), and a key is queued to carry it,
      # again a little later in case the sweep ran moments ago.  Every
      # controller's handler reports the same delete; queueing an already
      # queued key is a no-op, so that costs nothing.
      OWNER_DELETED_KEY = "garbage-collector/owner-deleted"
      OWNER_DELETED_RETRY_SECONDS = 1.1

      def owner_deleted
        collectors = @manager_mutex.synchronize { @controllers.values.select { |controller| garbage_collector?(controller) } }
        collectors.each do |controller|
          next unless controller.respond_to?(:expedite_orphan_pass!) && controller.expedite_orphan_pass!

          enqueue(OWNER_DELETED_KEY, controller: controller.name)
          @queue.add_after(OWNER_DELETED_KEY, OWNER_DELETED_RETRY_SECONDS) if @queue.respond_to?(:add_after)
        end
      rescue StandardError
        nil
      end

      def enqueue(key, controller: nil)
        normalized = key.to_s
        @route_mutex.synchronize do
          if controller
            routes = (@queue_routes[normalized] ||= [])
            controller_name = controller.to_s
            routes << controller_name unless routes.include?(controller_name)
          end
          # Keep route registration and queue insertion under one lock. This
          # makes route cleanup linearizable with an informer event: a route
          # cannot be removed between enqueue and WorkQueue.add.
          @queue.add(normalized)
        end
        self
      end

      def leader?
        @elector.leader?
      end

      # `wait` is how long the first key may be waited for; the rest of the
      # batch is drained without waiting.  A caller that polls on its own
      # schedule leaves it at 0; the process loop passes a real timeout so a
      # queued key is picked up the moment it arrives instead of waiting out
      # a fixed sleep.
      def step(wait: 0)
        election = @elector_mutex.synchronize { @elector.step }
        return {election: election, reconciled: 0, follower: true}.freeze unless @elector.leader?

        # step(wait: 0) is a synchronous pass (run_once, tests, tools): drain
        # what is queued now on this thread.  A waiting step is the
        # controller-manager loop, which the persistent pool serves.
        reconciled = if @worker_count > 1 && Float(wait).positive?
                       parallel_drain(wait)
                     else
                       drain(wait, first: true)
                     end
        {election: election, reconciled: reconciled, follower: false}.freeze
      end

      # A persistent pool of workers drains the shared queue, the way
      # client-go controllers run N `wait.Until(worker)` goroutines for the
      # life of the process.
      #
      # Workers used to be spawned per pass and to leave when the queue looked
      # empty.  Whatever bookkeeping decided "empty" raced with a sibling's
      # dequeue, so workers left while one was still busy; that survivor then
      # kept the pass open by draining every key that arrived, alone, for as
      # long as keys kept arriving.  The pool collapsed to one worker for
      # minutes at a time -- 75 queued keys and multi-second waits with 16
      # workers configured, and a 58 s median in "Service endpoints latency".
      #
      # `step` now only makes sure the pool runs and reports what it did.
      def parallel_drain(wait)
        ensure_worker_pool(wait)
        before = @pool_reconciled_mutex.synchronize { @pool_reconciled }
        pause = Float(wait)
        sleep(pause) if pause.positive?
        @pool_reconciled_mutex.synchronize { @pool_reconciled } - before
      end

      def ensure_worker_pool(wait)
        @pool_mutex ||= Mutex.new
        @pool_reconciled_mutex ||= Mutex.new
        @pool_reconciled ||= 0
        @pool_mutex.synchronize do
          @pool_threads ||= []
          @pool_threads.select!(&:alive?)
          (@worker_count - @pool_threads.length).times do
            @pool_threads << Thread.new { run_pool_worker(wait) }
          end
          start_node_health_monitor_locked
        end
      end

      # monitorNodeHealth: every --node-monitor-period (5 s) the node
      # lifecycle controller looks at every Node's heartbeat, whether or not
      # an event arrived, so a node that fell silent is noticed on time.
      NODE_MONITOR_PERIOD_SECONDS = 5.0
      NODE_CONTROLLER_NAMES = %w[node-lifecycle-controller node-controller].freeze

      def node_controller
        return nil if @controllers.nil?

        lookup = -> { NODE_CONTROLLER_NAMES.filter_map { |name| @controllers[name] }.first }
        @manager_mutex ? @manager_mutex.synchronize(&lookup) : lookup.call
      end

      def start_node_health_monitor_locked
        return if @node_monitor_thread&.alive?
        return if node_controller.nil?

        @node_monitor_thread = Thread.new do
          Thread.current.name = "node-health-monitor"
          until @queue.shutdown?
            sleep(@node_monitor_period || NODE_MONITOR_PERIOD_SECONDS)
            break if @queue.shutdown?

            begin
              node_health_pass! if @elector.leader?
            rescue StandardError => error
              @last_error = error
            end
          end
        end
        @pool_threads << @node_monitor_thread
      end

      # One pass over all Nodes, timed as
      # node_collector_update_all_nodes_health_duration_seconds.
      def node_health_pass!
        controller = node_controller
        return 0 if controller.nil?

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        store = store_for(controller)
        adapter = store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store)
        nodes = adapter.list(controller.resource_descriptor, namespace: :all)
        reconciled = 0
        Array(nodes).each do |node|
          break unless @elector.leader?

          begin
            controller.reconcile(node, store: store, apply: true,
                                       leader_guard: lambda {
                                         unless @elector.leader?
                                           raise LeadershipLostError, "controller leadership was lost before applying an operation"
                                         end
                                       })
            reconciled += 1
          rescue LeadershipLostError
            break
          rescue StandardError => error
            # Same (key, error) contract as the queue path; the controller
            # name travels on the error.
            error.instance_variable_set(:@rubernetes_controller, controller.name.to_s)
            unless error.respond_to?(:rubernetes_controller)
              error.define_singleton_method(:rubernetes_controller) { @rubernetes_controller }
            end
            begin
              @error_handler&.call(Support.name(node), error)
            rescue StandardError
              nil
            end
          end
        end
        ControllerMetrics.observe("node_collector_update_all_nodes_health_duration_seconds",
                                  Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        reconciled
      end

      POOL_IDLE_SECONDS = 0.5

      def run_pool_worker(wait)
        idle = [Float(wait), POOL_IDLE_SECONDS].max
        idle = POOL_IDLE_SECONDS unless idle.positive?
        until @queue.shutdown?
          unless @elector.leader?
            sleep(idle)
            next
          end
          reconciled = drain(idle, first: true)
          @pool_reconciled_mutex.synchronize { @pool_reconciled += reconciled }
        end
      rescue StandardError => error
        @last_error = error
      end

      # How much work is waiting, and how much has been done: the two numbers
      # that say whether a manager is idle or behind.
      attr_reader :queue

      def reconciled_total
        @reconciled_mutex.synchronize { @reconciled_total }
      end

      def leader?
        @elector.leader?
      end

      def drain(wait, first: true)
        reconciled = 0
        loop do
          key, shutdown = @queue.get(timeout: first ? wait : 0)
          first = false
          break if shutdown || key.nil?

          begin
            unless refresh_leadership
              # Work acquired before a lease loss must remain dirty.  The
              # WorkQueue releases it after this ensure block so another
              # leader can process it without dropping the event.
              @queue.add(key)
              break
            end
            leadership_lost = false
            requeue_after = nil
            timer_controllers = []
            promote_timer_routes(key)
            key_started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            orphan_started_at = key_started_at
            orphan_controllers_for_key(key).each do |controller|
              break unless refresh_leadership

              orphan_result = controller.reconcile_orphans(key, store: store_for(controller), apply: true,
                                                                leader_guard: lambda {
                                                                  unless refresh_leadership
                                                                    raise LeadershipLostError, "controller leadership was lost before applying an operation"
                                                                  end
                                                                })
              # Collecting an object nobody asked about is invisible otherwise:
              # say what was reclaimed, for the same reason kube-controller-manager
              # logs its garbage-collector deletions.
              next if orphan_result.nil? || @orphan_handler.nil?

              operations = orphan_result.respond_to?(:operations) ? Array(orphan_result.operations) : []
              @orphan_handler.call(key, controller.name, operations.length) unless operations.empty?
            end
            orphan_elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - orphan_started_at
            # Controllers that share a key are independent, as they are in
            # kube-controller-manager where each has its own queue: the root CA
            # publisher failing to write a ConfigMap a webhook refuses must not
            # stop the ServiceAccount controller creating "default" in the same
            # namespace.  The first failure is re-raised once every controller
            # had its turn, so the key is still retried with backoff.
            controller_error = nil
            controllers_for_key(key).each do |controller, resource|
              unless refresh_leadership
                leadership_lost = true
                break
              end

              started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              result = begin
                controller.reconcile(resource, store: store_for(controller), apply: true,
                                               leader_guard: lambda {
                                                 unless refresh_leadership
                                                   raise LeadershipLostError, "controller leadership was lost before applying an operation"
                                                 end
                                               })
              rescue LeadershipLostError
                raise
              rescue StandardError => error
                # The error handler sees the key only; name the controller so a
                # failed write can be traced to the loop that issued it.
                error.instance_variable_set(:@rubernetes_controller, controller.name.to_s)
                unless error.respond_to?(:rubernetes_controller)
                  error.define_singleton_method(:rubernetes_controller) { @rubernetes_controller }
                end
                controller_error ||= error
                next
              end
              elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
              trace_key("reconcile.trace", key, controller: controller.name, seconds: elapsed.round(3),
                                                operations: Array(result.respond_to?(:operations) ? result.operations : []).map do |operation|
                                                  [operation.action, operation.object && Support.name(operation.object)]
                                                end,
                                                status: result.respond_to?(:status) ? result.status : nil)
              record_controller_time(controller.name, elapsed)
              if elapsed > SLOW_RECONCILE_SECONDS && @slow_handler
                begin
                  @slow_handler.call(key, controller.name, elapsed)
                rescue StandardError
                  nil
                end
              end
              reconciled += 1
              delay = result.respond_to?(:requeue_after) ? result.requeue_after : nil
              unless delay.nil?
                requeue_after = [requeue_after, delay].compact.min
                timer_controllers << controller.name.to_s
              end
            end
            record_key_time(orphan_elapsed, Process.clock_gettime(Process::CLOCK_MONOTONIC) - key_started_at)
            raise controller_error if controller_error && !leadership_lost

            if leadership_lost
              @queue.add(key)
              break
            end
            @queue.forget(key)
            # A controller-owned timer (upstream queue.AddAfter): the key is
            # re-synced once the backoff or progress deadline elapses even when
            # no informer event arrives.
            unless requeue_after.nil?
              remember_timer_routes(key, timer_controllers)
              @queue.add_after(key, requeue_after)
            end
          rescue LeadershipLostError
            @queue.add(key)
            break
          rescue StandardError => error
            @last_error = error
            begin
              @error_handler&.call(key, error)
            rescue StandardError
              nil
            end
            # C5: reconcile failures are returned to the per-key WorkQueue.
            # The manager must keep serving unrelated keys while this key
            # waits for its exponential retry/backoff window.
            if terminal_reconcile_error?(error)
              @queue.forget(key)
            else
              @queue.add_rate_limited(key) unless @queue.shutdown?
            end
          ensure
            @queue.done(key)
            clear_route_if_idle(key)
          end
        end
        @reconciled_mutex.synchronize { @reconciled_total += reconciled }
        reconciled
      end

      def record_key_time(orphan_elapsed, total_elapsed)
        @reconciled_mutex.synchronize do
          @key_time[:orphans] += orphan_elapsed
          @key_time[:total] += total_elapsed
          @key_count += 1
        end
      end

      # {keys:, orphans:, reconcile:} seconds since the last call, then reset.
      # Where the reconcile time goes, per controller.  The totals alone said
      # the workers were busy, not with what: a burst of Service creations
      # ("[sig-network] Service endpoints latency should not be very high"
      # creates 200) is served by several controllers per key, and knowing
      # which of them the time goes to is the whole question.
      def record_controller_time(name, elapsed)
        @reconciled_mutex.synchronize do
          @controller_time ||= Hash.new(0.0)
          @controller_count ||= Hash.new(0)
          @controller_time[name.to_s] += elapsed
          @controller_count[name.to_s] += 1
        end
      end

      def take_controller_time(top: 5)
        @reconciled_mutex.synchronize do
          times = @controller_time || {}
          counts = @controller_count || {}
          @controller_time = Hash.new(0.0)
          @controller_count = Hash.new(0)
          times.sort_by { |_name, seconds| -seconds }.first(top).to_h do |name, seconds|
            [name, {"seconds" => seconds.round(2), "count" => counts[name]}]
          end
        end
      end

      def take_key_time
        @reconciled_mutex.synchronize do
          stats = {keys: @key_count, orphans: @key_time[:orphans],
                   reconcile: @key_time[:total] - @key_time[:orphans]}
          @key_time = Hash.new(0.0)
          @key_count = 0
          stats
        end
      end

      def run_once
        step
      end

      def stop
        @running = false
        @queue.shutdown
        threads = @pool_mutex ? @pool_mutex.synchronize { Array(@pool_threads).dup } : []
        begin
          @node_monitor_thread&.wakeup
        rescue StandardError
          nil
        end
        threads.each { |thread| thread.join(5) }
        self
      end

      private

      def enqueue_for(name, object, _old_object = nil, type = nil)
        controller = @manager_mutex.synchronize { @controllers[name.to_s] }
        return unless controller

        # A controller may decline an event outright (the quota controller
        # ignores its own status writes and plain adds, as upstream's does).
        if controller.respond_to?(:skip_event?)
          arity = controller.method(:skip_event?).arity
          skipped = arity == 2 ? controller.skip_event?(object, _old_object) : controller.skip_event?(object, _old_object, type)
          return if skipped
        end

        # The old object is routed too so a label or owner change reaches the
        # keys it used to match; a status-only update (the bulk of Pod
        # events) matches the same keys twice and was routed twice.
        observed_objects = [object]
        observed_objects << _old_object if _old_object && routing_identity(_old_object) != routing_identity(object)
        observed_objects.each do |observed|
          watches = controller_watches(controller)
          matching = watches.select { |watch| watch_matches?(watch, observed) }
          if watches.empty?
            enqueue([Support.namespace(observed), Support.name(observed)].compact.join("/"), controller: name)
            next
          end

          # A declared watch is an explicit GVK boundary. An event for the
          # same kind/name at another apiVersion must not fall through to the
          # legacy name-only route, or a controller can reconcile the wrong
          # object after an API migration.
          next if matching.empty?

          matching.each do |watch|
            next unless watch.predicate.nil? || watch.predicate.call(observed)

            queue_keys_for(controller, watch, observed).each do |key|
              trace_key("enqueue.trace", key, controller: name, kind: Support.kind(observed), name: Support.name(observed),
                                              resource_version: Support.value(Support.metadata(observed), "resourceVersion", nil))
              enqueue(key, controller: name)
            end
          end
        end
      end

      # RUBERNETES_TRACE_KEYS=<regexp> logs every enqueue and reconcile of the
      # matching queue keys: which event arrived, what the controller planned
      # and the status it computed.  A lost event and a wrong plan look the
      # same from the outside ("status never caught up"); this tells them
      # apart without a debugger on a live control plane.
      TRACE_KEYS = (pattern = ENV["RUBERNETES_TRACE_KEYS"].to_s).empty? ? nil : Regexp.new(pattern)

      def trace_key(event, key, **fields)
        return if TRACE_KEYS.nil? || !TRACE_KEYS.match?(key.to_s)

        line = {"timestamp" => Time.now.utc.iso8601(6), "level" => "info", "event" => event,
                "key" => key.to_s}.merge(fields.transform_keys(&:to_s))
        $stderr.write(JSON.generate(line) << "\n")
      rescue StandardError
        nil
      end

      def controllers_for_key(key)
        routed_names = @route_mutex.synchronize { Array(@queue_routes[key.to_s]).dup }
        controllers = @manager_mutex.synchronize do
          if routed_names.empty?
            @controllers.values.dup
          else
            routed_names.filter_map { |name| @controllers[name] }
          end
        end

        controllers.filter_map do |controller|
          object = find_resource(controller, key)
          [controller, object] if object
        end
      end

      # Controllers with cleanup to do for an object that is no longer there.
      #
      # The garbage collector's own kind is a controller-only marker, so no
      # event ever routes a key to IT -- but it watches Pods, ReplicaSets,
      # Deployments and the rest, and those routes are what carry it here.
      # Asking every controller instead, on every key, was the single most
      # expensive thing the reconcile loop did: measured under a parallel
      # conformance run it spent 220 seconds of worker time per 30 seconds of
      # wall clock resolving orphan candidates that were never going to have
      # any work, and the average key waited 24 seconds behind it.
      #
      # A key with no route at all (a retry, a timer) still asks everyone: it
      # is the fallback that guarantees no cleanup is lost, and it is rare.
      def orphan_controllers_for_key(key)
        routed = @route_mutex.synchronize { Array(@queue_routes[key.to_s]).dup }
        candidates = orphan_capable_controllers
        unless routed.empty?
          names = routed.to_h { |name| [name.to_s, true] }
          # The garbage collector owns no kind and is never a key's route, so
          # routing alone silenced its missing-owner sweep for good: pods
          # whose ReplicationController had been deleted lived on for ever
          # ("[sig-api-machinery] Garbage collector should delete pods created
          # by rc when not orphaning").  It rides along on every key; its own
          # sweep interval bounds the cost.
          candidates = candidates.select { |controller| names.key?(controller.name.to_s) || garbage_collector?(controller) }
        end
        candidates.select { |controller| find_resource(controller, key).nil? }
      end

      def garbage_collector?(controller)
        descriptor = controller.respond_to?(:resource_descriptor) ? controller.resource_descriptor : nil
        descriptor.respond_to?(:kind) && descriptor.kind.to_s == "GarbageCollector"
      rescue StandardError
        false
      end

      # #orphan_cleanup? is reflection over the implementation class, so the
      # answer is asked once per controller rather than once per key.
      def orphan_capable_controllers
        @manager_mutex.synchronize do
          current = @controllers.values
          if @orphan_capable.nil? || @orphan_capable_generation != current.length
            @orphan_capable_generation = current.length
            @orphan_capable = current.select do |controller|
              controller.respond_to?(:orphan_cleanup?) && controller.orphan_cleanup?
            end.freeze
          end
          @orphan_capable
        end
      end

      def find_resource(controller, key)
        found = lookup_by_key(controller.resource_descriptor, key)
        return found if found

        # A :self-routed foreign watch addresses the observed object itself, and
        # the controller's own kind frequently has nothing under that key yet --
        # creating it is what the reconcile is for.  Resolve against the watched
        # kind so the event is not dropped for want of the object it would make.
        controller_watches(controller).each do |watch|
          next unless watch.route == :self

          found = lookup_by_key(watch.resource, key)
          return found if found
        end
        nil
      end

      # Queue keys are "namespace/name" for namespaced kinds and "name" for
      # cluster-scoped ones, so the object is fetched directly instead of
      # scanning a full collection for every controller on every key.
      def lookup_by_key(descriptor, key)
        value = key.to_s
        namespaced = descriptor.respond_to?(:cluster_scoped?) && !descriptor.cluster_scoped?
        # A namespaced object is always keyed "namespace/name".  A key without
        # a namespace cannot name one, so there is nothing to look for -- and
        # searching anyway means listing the kind across every namespace for
        # each controller on each queue key, which is what starves the
        # reconcile loop.
        return nil if namespaced && !value.include?("/")

        namespace, name = split_queue_key(descriptor, value)
        found = store_adapter.find(descriptor, name: name, namespace: namespace)
        return found if found
        return nil unless namespace.nil? && value.include?("/")

        # A cluster-scoped kind keyed with a namespace prefix (a foreign
        # watch's key) still resolves by its trailing name.
        store_adapter.find(descriptor, name: value.split("/").last, namespace: nil)
      end

      def split_queue_key(descriptor, key)
        value = key.to_s
        return [nil, value] if descriptor.respond_to?(:cluster_scoped?) && descriptor.cluster_scoped?
        return [nil, value] unless value.include?("/")

        namespace, _, name = value.partition("/")
        [namespace, name]
      end

      def controller_watches(controller)
        definition = controller.respond_to?(:definition) ? controller.definition : nil
        definition ? Array(definition.watches) : []
      end

      def watch_matches?(watch, object)
        return false unless Support.kind(object) == watch.resource.kind

        Support.api_version(object).to_s == watch.resource.api_version
      end

      def routing_identity(object)
        metadata = Support.metadata(object)
        [Support.namespace(object), Support.name(object), Support.labels(object),
         Support.value(metadata, "ownerReferences", nil)]
      end

      def queue_keys_for(controller, watch, object)
        if watch.via == :owner_reference
          direct_reference = Support.owner_references(object).find do |reference|
            controller_flag = Support.ref_value(reference, "controller", false)
            (controller_flag == true || controller_flag.to_s.casecmp("true").zero?) &&
              valid_owner_reference?(controller, object, reference)
          end
          if direct_reference
            direct = owner_watch_queue_key(watch, object, direct_reference)
            return normalize_queue_keys(direct)
          end

          ancestor = ownership_ancestor(controller, object)
          return normalize_queue_keys([Support.namespace(ancestor), Support.name(ancestor)].compact.join("/")) if ancestor

          return []
        end

        if %i[label selector].include?(watch.via)
          return matching_controller_keys(controller, object, selector_source: watch.selector_source)
        end

        # A Namespace controller's relation to a namespaced object is plain
        # containment: the object's own namespace is the only key worth
        # reconciling.  Falling through to the fan-out below made every event
        # on any namespaced object re-sweep every namespace in the cluster,
        # so one namespace deletion cost a full content sweep per namespace
        # per event.
        if watch.via == :all && controller.resource_descriptor.kind == "Namespace" &&
           watch.resource.kind != "Namespace"
          return normalize_queue_keys(Support.namespace(object))
        end

        # A foreign `:all` watch has no owner identity in the observed object.
        # Queueing its namespace/name would either address a controller with
        # the wrong kind or silently drop a cluster-scoped event (for example,
        # a Node change watched by every DaemonSet). Fan the event out to the
        # controller's own resources; self-watches still use their declared
        # queue key below so same-GVK routing remains precise.
        # route: :namespace confines the fan-out to the controller's objects
        # in the observed object's namespace: a quota only ever counts its
        # own namespace, and fanning every Pod event in the cluster out to
        # every quota made each quota recompute dozens of times a minute --
        # often in the window between admission charging it for a new object
        # and that object being stored, which erased the charge.
        if watch.via == :all && watch.route == :namespace && watch.resource.gvk != controller.resource_descriptor.gvk
          return namespace_controller_keys(controller, object)
        end
        if watch.via == :all && watch.resource.gvk != controller.resource_descriptor.gvk &&
           watch.route != :self
          return all_controller_keys(controller)
        end

        normalize_queue_keys(watch.queue_key&.call(object))
      end

      def normalize_queue_keys(key)
        Array(key).filter_map do |candidate|
          value = candidate.to_s
          value unless value.empty?
        end.uniq
      end

      # A custom queue-key block is allowed to inspect ownerReferences. Feed it
      # a detached object with the validated reference first so a stale or
      # foreign reference cannot win merely because it appeared earlier in the
      # API payload.
      def owner_watch_queue_key(watch, object, reference)
        return [Support.namespace(object), Support.ref_value(reference, "name", "")].compact.join("/") unless watch.queue_key

        candidate = Support.deep_copy(object)
        candidate["metadata"] ||= {}
        references = Array(Support.value(candidate["metadata"], "ownerReferences", []))
        selected = references.find { |entry| entry == reference }
        candidate["metadata"]["ownerReferences"] = [selected || reference] + references.reject do |entry|
          entry == selected || entry == reference
        end
        watch.queue_key.call(candidate)
      end

      # `selector_source` names the kind whose label selector decides
      # membership when the controller's own kind carries none: an Endpoints
      # or EndpointSlice takes its selector from the Service it is named
      # after.  The key is still namespace/name, which those kinds share with
      # their Service.
      def matching_controller_keys(controller, object, selector_source: nil)
        descriptor = selector_source || controller.resource_descriptor
        store_adapter.list(descriptor, namespace: Support.namespace(object) || :all).filter_map do |candidate|
          selector = Support.value(Support.spec(candidate), "selector", {})
          next unless Support.selector_matches?(selector, object)

          [Support.namespace(candidate), Support.name(candidate)].compact.join("/")
        end.uniq
      end

      def namespace_controller_keys(controller, object)
        namespace = Support.namespace(object)
        return [] if namespace.to_s.empty?

        store_adapter.list(controller.resource_descriptor, namespace: namespace).filter_map do |candidate|
          key = [Support.namespace(candidate), Support.name(candidate)].compact.join("/")
          key unless key.empty?
        end.uniq
      end

      def all_controller_keys(controller)
        store_adapter.list(controller.resource_descriptor, namespace: :all).filter_map do |candidate|
          key = [Support.namespace(candidate), Support.name(candidate)].compact.join("/")
          key unless key.empty?
        end.uniq
      end

      # Walk controller owner references up to an object of the controller's
      # own kind (a Pod owned by a ReplicaSet owned by a Deployment).
      #
      # Each reference names its owner, so it is resolved by kind and name.
      # Building an index of every object of every kind instead -- which is
      # what an ownerReference UID lookup needs -- costs a full scan on every
      # event, and the events that land here are the common ones: any object
      # whose direct owner is not the controller's kind.
      MAX_OWNERSHIP_DEPTH = 8

      def ownership_ancestor(controller, object)
        owner_descriptor = controller.resource_descriptor
        pending = [object]
        visited = {}
        depth = 0
        until pending.empty? || depth > MAX_OWNERSHIP_DEPTH
          depth += 1
          child = pending.shift
          child_uid = Support.uid(child)
          next if child_uid && visited[child_uid]

          visited[child_uid] = true if child_uid
          Support.owner_references(child).each do |reference|
            controller_flag = Support.ref_value(reference, "controller", false)
            next unless controller_flag == true || controller_flag.to_s.casecmp("true").zero?

            parent = resolve_owner_reference(reference, Support.namespace(child))
            next unless parent
            next unless owner_reference_matches_object?(reference, parent)
            if Support.kind(parent).to_s == owner_descriptor.kind.to_s &&
               Support.api_version(parent).to_s == owner_descriptor.api_version.to_s
              return parent
            end

            pending << parent
          end
        end
        nil
      end

      def resolve_owner_reference(reference, namespace)
        api_version = Support.ref_value(reference, "apiVersion", nil).to_s
        kind = Support.ref_value(reference, "kind", "").to_s
        name = Support.ref_value(reference, "name", "").to_s
        return nil if kind.empty? || name.empty?

        descriptor = owner_descriptor_for(api_version, kind)
        return nil if descriptor.nil?

        store_adapter.find(descriptor, name: name,
                                       namespace: descriptor.cluster_scoped? ? nil : namespace)
      rescue StandardError
        nil
      end

      def owner_descriptor_for(api_version, kind)
        @owner_descriptors ||= {}
        key = "#{api_version}/#{kind}"
        return @owner_descriptors[key] if @owner_descriptors.key?(key)

        # The apiVersion/kind pair, not "v1/ReplicationController" as text:
        # a two-part string is read as a kind name, so every core-group owner
        # became kind "v1/ReplicationController", missed the informer cache
        # and was fetched from the API server -- one GET per Pod event per
        # controller, inside the Pod informer's dispatch.  A mass Pod deletion
        # then held that informer back by seconds.
        @owner_descriptors[key] = begin
          api_version.empty? ? ResourceDescriptor.parse(kind) : ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => kind})
        rescue StandardError
          nil
        end
      end

      # A namespace on its way out answers every write with 403 "because it is
      # being terminated", and then with 404 once it is gone.  Such a key can
      # never succeed, and retrying it crowds out the keys that can: under a
      # conformance run the retries alone grew the work queue without bound
      # while real work waited.  Upstream's controllers simply stop working on
      # a terminating namespace.
      NAMESPACE_GONE_PATTERNS = [
        /because it is being terminated/,
        /namespaces "[^"]*" not found/
      ].freeze

      def terminal_reconcile_error?(error)
        message = error.respond_to?(:message) ? error.message.to_s : ""
        NAMESPACE_GONE_PATTERNS.any? { |pattern| message.match?(pattern) }
      end

      # Several workers ask this on every reconcile; the elector rate-limits
      # its own renewals, but its bookkeeping is not concurrent, so the lease
      # is stepped under a lock.
      def refresh_leadership
        @elector_mutex.synchronize { @elector.step }
        @elector.leader?
      end

      def store_adapter
        @store.is_a?(StoreAdapter) ? @store : StoreAdapter.new(@store)
      end

      def normalize_controller_options(options)
        return {} unless options.is_a?(Hash)

        options.each_with_object({}) do |(key, value), result|
          result[key.is_a?(String) ? key.to_sym : key] = value
        end
      end

      def validate_required_providers!
        return unless @registry.respond_to?(:requires_corpus?) && @registry.requires_corpus?
        return unless @registry.respond_to?(:corpus)

        cloud_entries = @registry.corpus.entries.select(&:cloud_provider)
        return if cloud_entries.empty?
        return unless @controller_options[:cloud_provider].nil? && @controller_options["cloud_provider"].nil? &&
                      @controller_options[:provider].nil? && @controller_options["provider"].nil?

        names = cloud_entries.map(&:name).join(", ")
        raise ProviderUnavailableError,
              "controller manager requires an injected cloud provider for #{names}"
      end

      def owner_reference_matches_object?(reference, owner)
        api_version = Support.ref_value(reference, "apiVersion", nil).to_s
        api_version == Support.api_version(owner).to_s &&
          Support.ref_value(reference, "kind", "").to_s == Support.kind(owner) &&
          Support.ref_value(reference, "name", "").to_s == Support.name(owner) &&
          Support.ref_value(reference, "uid", nil).to_s == Support.uid(owner).to_s
      end

      def valid_owner_reference?(controller, object, reference)
        owner_descriptor = controller.resource_descriptor
        return false unless Support.ref_value(reference, "apiVersion", nil).to_s == owner_descriptor.api_version
        return false unless Support.ref_value(reference, "kind", "").to_s == owner_descriptor.kind

        reference_uid = Support.ref_value(reference, "uid", nil).to_s
        reference_name = Support.ref_value(reference, "name", "").to_s
        return false if reference_uid.empty? || reference_name.empty?

        owner_namespace = owner_descriptor.namespaced? ? Support.namespace(object) : nil
        owner = store_adapter.find(owner_descriptor, name: reference_name, namespace: owner_namespace)
        owner && owner_reference_matches_object?(reference, owner)
      end

      # A controller's timer (upstream: queue.AddAfter on THAT controller's own
      # queue) comes back routed to the controllers that asked for it.  An
      # unrouted key is offered to every controller, so the endpointslice
      # controller's 15 s resync of each Service also ran the endpoints and
      # mirroring controllers and the orphan pass on it: 200 Services made
      # thousands of no-op reconciles and "[sig-network] Service endpoints
      # latency should not be very high" waited behind them.
      def remember_timer_routes(key, controller_names)
        return if controller_names.empty?

        @route_mutex.synchronize do
          routes = ((@timer_routes ||= {})[key.to_s] ||= [])
          controller_names.each { |name| routes << name unless routes.include?(name) }
        end
      end

      def promote_timer_routes(key)
        @route_mutex.synchronize do
          timer = (@timer_routes ||= {}).delete(key.to_s)
          next if timer.nil?

          routes = (@queue_routes[key.to_s] ||= [])
          timer.each { |name| routes << name unless routes.include?(name) }
        end
      end

      def clear_route_if_idle(key)
        @route_mutex.synchronize do
          next if @queue.processing?(key) || @queue.queued?(key) || @queue.dirty?(key)

          @queue_routes.delete(key.to_s)
        end
      end
    end
  end
end
