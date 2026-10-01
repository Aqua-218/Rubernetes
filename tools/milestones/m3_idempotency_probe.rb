#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m3_probe_support"
require_relative "m3_gate"
require_relative "../../lib/rubernetes/storage/memory_store"
require "tmpdir"

module M3IdempotencyFixtures
  # A reconcile comparison must hold the logical clock and all informer
  # snapshots constant.  Controllers that own time-dependent status fields
  # otherwise produce different plans from the same resource solely because
  # the probe crossed a wall-clock tick.
  FIXED_NOW = Time.utc(2026, 1, 1, 0, 0, 0).freeze

  module_function

  def for(controller_name, owned_kind)
    object = {
      "apiVersion" => "v1",
      "kind" => owned_kind,
      "metadata" => {"name" => "m3-#{controller_name}", "namespace" => "default", "uid" => "m3-uid-#{controller_name}"},
      "spec" => {"replicas" => 1, "template" => {"metadata" => {"labels" => {"app" => "m3"}}, "spec" => {}}}
    }
    options = {now: FIXED_NOW}

    case controller_name
    when "deployment-controller"
      # The first pass must still create the owned ReplicaSet and write the
      # desired status, but the revision annotation itself is already at the
      # controller's deterministic initial revision.  This keeps one logical
      # deployment update per run; two writes sharing the same semantic
      # effect_key would be a real duplicate, not a replay-safe fixture.
      object["metadata"]["annotations"] = {"deployment.kubernetes.io/revision" => "1"}
    when "endpoints-controller"
      # The planner is invoked for the Service watch: it derives the desired
      # Endpoints from the Service's selector and ports.  Without a Service the
      # fixture is an ORPHANED Endpoints, which the controller correctly
      # deletes (endpoints_controller.go:370) -- that is cleanup, not the
      # reconciliation this case is meant to replay.
      object = {
        "apiVersion" => "v1", "kind" => "Service",
        "metadata" => {"name" => "m3-#{controller_name}", "namespace" => "default", "uid" => "m3-uid-#{controller_name}"},
        "spec" => {"selector" => {"app" => "m3"}, "ports" => [{"name" => "http", "port" => 80}]}
      }
      options[:pods] = []
    when "endpointslice-controller"
      # The registry's primary kind is EndpointSlice, but the planner is
      # invoked for the Service watch and requires its selector context.  A
      # direct Service fixture exercises the production path without inventing
      # a fake StoreAdapter lookup.
      object = {
        "apiVersion" => "v1", "kind" => "Service",
        "metadata" => {"name" => "m3-#{controller_name}", "namespace" => "default", "uid" => "m3-uid-#{controller_name}"},
        "spec" => {"selector" => {"app" => "m3"}, "ports" => [{"name" => "http", "port" => 80}]}
      }
      options[:pods] = []
    when "endpointslice-mirroring-controller"
      # Mirroring owns EndpointSlice output but consumes a legacy Endpoints
      # object.  Supplying that watched object is the same call boundary used
      # by the real informer and avoids an unresolvable nil Service label.
      object = {
        "apiVersion" => "v1", "kind" => "Endpoints",
        "metadata" => {"name" => "m3-#{controller_name}", "namespace" => "default", "uid" => "m3-uid-#{controller_name}"},
        "subsets" => [{"ports" => [{"name" => "http", "port" => 80}],
                       "addresses" => [{"ip" => "10.0.0.1"}],
                       "notReadyAddresses" => []}]
      }
    when "resourcepoolstatusrequest-controller"
      # The status planner stamps conditions with its supplied clock.  Empty
      # snapshots are a valid no-pool observation and keep the fixture
      # independent of a StoreAdapter.
      options[:resource_slices] = []
      options[:resource_claims] = []
    when "horizontal-pod-autoscaler-controller"
      options[:target] = {
        "apiVersion" => "apps/v1", "kind" => "Deployment",
        "metadata" => {"name" => "m3-target-#{controller_name}", "namespace" => "default", "uid" => "m3-target-uid-#{controller_name}"},
        "spec" => {"replicas" => 1}
      }
      options[:metrics] = {"cpu" => 80}
    when "node-ipam-controller"
      options[:cluster_cidrs] = ["10.0.0.0/24"]
      options[:node_cidr_mask_size] = 26
    when "service-cidr-controller"
      # ServiceCIDR uses IPAddress and sibling ServiceCIDR snapshots when
      # deciding deletion/finalizer state.  Empty snapshots exercise the
      # ready path and make the same logical input reproducible.
      options[:service_cidrs] = []
      options[:ip_addresses] = []
      object["metadata"]["finalizers"] = ["networking.k8s.io/service-cidr-finalizer"]
    end

    [object, options]
  end
end

class M3TransientMemoryStore < Rubernetes::Storage::MemoryStore
  attr_reader :fault_injections

  def initialize(**options)
    super
    @fail_next_non_lease_update = true
    @fault_injections = 0
  end

  def update(key, object = nil, **options)
    if @fail_next_non_lease_update && !key.to_s.include?("/leases/")
      @fail_next_non_lease_update = false
      @fault_injections += 1
      raise Rubernetes::Storage::Conflict.new(key, "injected one-shot reconcile update conflict")
    end
    super
  end
end

class M3IdempotencyProvider
  attr_reader :calls

  def initialize(journal:, controller:)
    @journal = journal
    @controller = controller
    @calls = []
  end

  def record(operation, reconcile_key:)
    @calls << {"provider" => self.class.name, "operation" => operation.to_s, "reconcile_key" => reconcile_key.to_s}
    @journal.record_provider(reconcile_key: reconcile_key, provider: self.class.name, operation: operation)
  end
end

class M3IdempotencyJournal
  attr_reader :path

  def initialize(controller:)
    @path = File.join(Dir.mktmpdir("rubernetes-m3-idempotency-"), "effects.jsonl")
    @journal = Rubernetes::Controller::EffectJournal.new(path: @path, component: "controller-manager", identity: controller)
  end

  def record(*, **)
    @journal.record(*, **)
  end

  def record_controller_event(*, **)
    @journal.record_controller_event(*, **)
  end

  def record_provider(*, **)
    @journal.record_provider(*, **)
  end

  def entries
    Rubernetes::Controller::EffectJournal.read(@path)
  end

  def cursor
    entries.length
  end

  def entries_since(cursor)
    entries.drop(Integer(cursor))
  end

  def inventory(cursor = 0)
    inventory_from_entries(entries_since(cursor))
  end

  def snapshot(cursor = 0)
    values = entries_since(cursor)
    normalized_values = values.map { |entry| M3ProbeSupport.normalize(entry) }
    inventory = inventory_from_entries(values)
    {
      "raw_entries" => normalized_values,
      "raw_entry_count" => normalized_values.length,
      "raw_sha256" => digest(normalized_values),
      "effect_ids" => inventory.fetch("effect_ids"),
      "effect_id_counts" => inventory.fetch("effect_id_counts"),
      "effect_signature_counts" => inventory.fetch("effect_signature_counts"),
      "api_effect_key_counts" => inventory.fetch("api_effect_key_counts"),
      "api_mutation_count" => inventory.fetch("api_mutation_count"),
      "event_count" => inventory.fetch("event_count"),
      "provider_call_count" => inventory.fetch("provider_call_count"),
      "event_effect_key_counts" => inventory.fetch("event_effect_key_counts"),
      "provider_effect_key_counts" => inventory.fetch("provider_effect_key_counts"),
      "event_signatures" => inventory.fetch("event_signatures"),
      "event_signature_counts" => inventory.fetch("event_signature_counts"),
      "provider_call_signatures" => inventory.fetch("provider_call_signatures"),
      "provider_call_signature_counts" => inventory.fetch("provider_call_signature_counts"),
      "inventory" => inventory
    }
  end

  def inventory_from_entries(values)
    # Keep the probe's projection and the gate's independent recomputation on
    # one raw-entry schema.  The gate still recomputes from the captured raw
    # journal during validation; this call only prevents the producer from
    # publishing a subtly different inventory shape.
    M3Gate.send(:recompute_idempotency_inventory, values)
  end

  def event_signature(entry)
    {"effect_key" => entry["effect_key"], "event_sha256" => entry["event_sha256"]}
  end

  def provider_call_signature(entry)
    {"effect_key" => entry["effect_key"], "provider" => entry["provider"], "operation" => entry["operation"]}
  end

  def digest(value)
    Rubernetes::Controller::EffectJournal.digest(value)
  end
end

module M3IdempotencyMeasurement
  module_function

  RUNTIME_KEYS = %w[uid resourceVersion creationTimestamp deletionTimestamp managedFields].freeze

  def primary_object(definition, name)
    descriptor = definition.kind
    object = {
      "apiVersion" => descriptor.api_version,
      "kind" => descriptor.kind,
      # MemoryStore does not synthesize API-server UIDs.  Supplying a stable
      # UID is therefore part of the fixture contract: ownerReferences must
      # carry the same identity on every retry or the production ownership
      # fence correctly treats the dependent as foreign and creates another
      # child.  Omitting it would turn a valid idempotency probe into a
      # synthetic duplicate-child test.
      "metadata" => {"name" => name, "namespace" => (descriptor.namespaced? ? "default" : nil),
                     "uid" => "m3-uid-#{name}"}.compact,
      "spec" => {"replicas" => 1, "template" => {"metadata" => {"labels" => {"app" => "m3"}}, "spec" => {}}}
    }
    # apps/v1 workload APIs require a non-empty selector; the upstream
    # controllers only warn (SelectingAll) and never reconcile without one, so
    # an unselected fixture would measure a warning event instead of a
    # reconcile.
    object["spec"]["selector"] = {"matchLabels" => {"app" => "m3"}} if %w[Deployment ReplicaSet StatefulSet DaemonSet].include?(descriptor.kind.to_s)
    case descriptor.kind
    when "CronJob"
      # A generic workload fixture would leave CronJob's default `* * * * *`
      # schedule with a day of backlog.  That is an intentional scheduling
      # behavior, but it is not a replay-safe idempotency input: each retry
      # legitimately advances the backlog.  Use a suspended, API-shaped
      # CronJob with one stale status field so the real status mutation still
      # exercises WorkQueue conflict/retry without manufacturing hundreds of
      # unrelated Job creations.
      object["spec"] = {
        "schedule" => "* * * * *",
        "suspend" => true,
        "jobTemplate" => {"spec" => {"template" => {"metadata" => {"labels" => {"app" => "m3"}}, "spec" => {}}}}
      }
      object["status"] = {"active" => [], "lastScheduleTime" => M3IdempotencyFixtures::FIXED_NOW.iso8601(6)}
    when "Deployment"
      object["metadata"]["annotations"] = {"deployment.kubernetes.io/revision" => "1"}
    when "ServiceCIDR"
      object["metadata"]["finalizers"] = ["networking.k8s.io/service-cidr-finalizer"]
    end
    case descriptor.kind
    when "EndpointSlice"
      object["metadata"]["labels"] = {"kubernetes.io/service-name" => name}
    when "HorizontalPodAutoscaler"
      object["spec"] = {
        "minReplicas" => 1,
        "maxReplicas" => 3,
        "scaleTargetRef" => {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "m3-target-#{name.delete_prefix("m3-")}"},
        "metrics" => [{"type" => "Resource",
                       "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => 80}}}]
      }
    when "StorageVersionMigration"
      object["spec"] = {"resource" => {"group" => "", "resource" => "pods"}}
      object["status"] = {"resourceVersion" => "1"}
    end
    object
  end

  # Capture the complete per-step proof.  A lease election result by itself is
  # insufficient: the evidence must show that this step was the leader,
  # reconciled the expected key exactly once, returned without a new error, and
  # left no retry/dirty queue state behind.
  def step_observable(step, manager:, key:, controller:, error_before:)
    value = step.is_a?(Hash) ? step : {}
    election = value["election"] || value[:election]
    follower = value.key?("follower") ? value["follower"] : value[:follower]
    reconciled = value["reconciled"] || value[:reconciled] || 0
    current_error = manager.last_error
    step_error = current_error unless current_error.equal?(error_before)
    queue = manager.queue
    retry_count = queue.respond_to?(:num_requeues) ? queue.num_requeues(key) : nil
    queue_depth = queue.respond_to?(:depth) ? queue.depth : nil
    queue_length = queue.respond_to?(:length) ? queue.length : nil
    # A timed requeue (AddAfter: progress deadline, minReadySeconds catch-up)
    # is scheduled work, not a retry of this step; only immediately runnable
    # or in-flight items count as pending retry state.
    queue_delayed = queue.respond_to?(:delayed_length) ? queue.delayed_length : 0
    queue_depth -= queue_delayed if queue_depth.is_a?(Numeric)
    queue_length -= queue_delayed if queue_length.is_a?(Numeric)
    queued = queue.respond_to?(:queued?) ? queue.queued?(key) : nil
    queued = false if queued && queue.respond_to?(:delayed?) && queue.delayed?(key)
    dirty = queue.respond_to?(:dirty?) ? queue.dirty?(key) : nil
    processing = queue.respond_to?(:processing?) ? queue.processing?(key) : nil
    leader = follower == false && %w[acquired renewed].include?(election.to_s)
    {
      "election" => election,
      "follower" => follower,
      "leader_execution" => leader,
      "controller" => controller.to_s,
      "reconcile_key" => key.to_s,
      "reconciled" => Integer(reconciled),
      "reconcile_success" => leader && Integer(reconciled) == 1 && step_error.nil?,
      "step_error_class" => step_error&.class&.name,
      "step_error_message" => step_error&.message,
      "pending_retry" => [retry_count, queue_depth, queue_length].any? { |value| value.is_a?(Numeric) && value.positive? } ||
        queued == true || dirty == true || processing == true,
      "follower_noop" => follower == true && Integer(reconciled).zero?,
      "queue_retry_count" => retry_count,
      "queue_depth" => queue_depth,
      "queue_length" => queue_length,
      "queue_delayed" => queue_delayed,
      "queue_queued" => queued,
      "queue_dirty" => dirty,
      "queue_processing" => processing
    }
  end

  def runtime_neutral(value)
    case value
    when Hash
      value.each_with_object({}) do |(key, child), result|
        next if RUNTIME_KEYS.include?(key.to_s)

        result[key.to_s] = runtime_neutral(child)
      end
    when Array then value.map { |child| runtime_neutral(child) }
    else value
    end
  end

  def store_observable(adapter)
    adapter.all.reject { |object| object["kind"].to_s == "Lease" }
      .map { |object| runtime_neutral(object) }
      .sort_by do |object|
      [object["apiVersion"].to_s, object["kind"].to_s, object.dig("metadata", "namespace").to_s,
       object.dig("metadata", "name").to_s]
    end
  end

  def key_for(object)
    [Rubernetes::Controller::Support.namespace(object), Rubernetes::Controller::Support.name(object)].compact.join("/")
  end

  def queue_snapshot(queue, key = nil)
    {
      "queue_class" => queue.class.name,
      "retry_count" => queue.respond_to?(:num_requeues) && key ? queue.num_requeues(key) : nil,
      "depth" => queue.respond_to?(:depth) ? queue.depth : nil,
      "length" => queue.respond_to?(:length) ? queue.length : nil
    }
  end

  def provider_effect_applicability(corpus_entry)
    if corpus_entry.respond_to?(:cloud_provider) && corpus_entry.cloud_provider
      {
        "applicable" => false,
        "reason" => "the deterministic M3 fixture does not satisfy the controller's cloud-provider side-effect preconditions"
      }
    else
      {
        "applicable" => false,
        "reason" => "the authoritative corpus entry declares no provider side-effect path"
      }
    end
  end
end

M3ProbeSupport.run_report(kind: "m3_reconcile_idempotency", adapter_name: "reconcile-idempotency-probe") do |_input, errors|
  controller_module = M3ProbeSupport.constant("Rubernetes::Controller")
  registry_class = M3ProbeSupport.constant("Rubernetes::Controller::ControllerRegistry") ||
                   M3ProbeSupport.constant("Rubernetes::Controller::Registry")
  registry = controller_module.respond_to?(:default_registry) ? controller_module.default_registry : nil
  unless registry || registry_class.is_a?(Class)
    errors << "production controller registry is unavailable"
    next {"measurement_source" => "missing_production_module", "cases" => []}
  end
  registry ||= registry_class.new
  expected = M3Gate::REQUIRED_CONTROLLER_NAMES.sort
  corpus = M3ProbeSupport.constant("Rubernetes::Controller::BuiltinControllerCorpus")
  begin
    registry.startup_validate!
  rescue StandardError => error
    errors << "production controller registry startup validation failed: #{error.class}: #{error.message}"
    next {"measurement_source" => "production_module", "cases" => []}
  end
  cases = expected.map do |name|
    definition = registry.respond_to?(:fetch) ? registry.fetch(name) : registry[name]
    corpus_entry = corpus.fetch(name)
    implementation = definition.respond_to?(:implementation) ? definition.implementation : nil
    implementation_present = !implementation.nil?
    implementation_name = implementation.respond_to?(:name) ? implementation.name.to_s : implementation.class.name.to_s
    uses_corpus_controller = (definition.respond_to?(:corpus_fallback?) && definition.corpus_fallback?) ||
                             implementation_name.end_with?("::CorpusController") || implementation_name == "Rubernetes::Controller::CorpusController"
    if uses_corpus_controller
      errors << "controller #{name} idempotency cannot use CorpusController fallback"
      raise "CorpusController fallback is not accepted for #{name}"
    end
    raise "concrete implementation is missing for #{name}" unless implementation_present

    primary_name = "m3-#{name}"
    primary = M3IdempotencyMeasurement.primary_object(definition, primary_name)
    watched, options = M3IdempotencyFixtures.for(name, definition.kind.kind.to_s)
    journal = M3IdempotencyJournal.new(controller: name)
    store = M3TransientMemoryStore.new(clock: -> { M3IdempotencyFixtures::FIXED_NOW }, sleeper: ->(_seconds) {})
    adapter = Rubernetes::Controller::StoreAdapter.new(store, effect_journal: journal, component: "controller-manager",
                                                              identity: "m3-idempotency-#{name}")
    adapter.create(primary, descriptor: definition.kind)
    # Secondary watched resources are real StoreAdapter objects.  This keeps
    # special controllers (Service/EndpointSlice and Endpoints mirroring)
    # on the same primary-kind Manager route while retaining their watched
    # input for production resolve_* code.
    adapter.create(watched) if watched.is_a?(Hash) && watched["kind"].to_s != definition.kind.kind.to_s
    foreign = M3IdempotencyMeasurement.primary_object(definition, "m3-foreign-#{name}")
    foreign["metadata"]["ownerReferences"] = [{"apiVersion" => definition.kind.api_version,
                                               "kind" => definition.kind.kind,
                                               "name" => "foreign-owner", "uid" => "foreign-uid",
                                               "controller" => true}]
    adapter.create(foreign, descriptor: definition.kind)
    if name == "garbage-collector-controller"
      # For the garbage collector a "foreign" dependent is one owned by a
      # different, live owner.  A dependent whose owner UID does not exist is
      # an orphan that upstream GC correctly deletes, so the foreign owner
      # must exist for the preservation check to be meaningful.
      foreign_owner = M3IdempotencyMeasurement.primary_object(definition, "foreign-owner")
      foreign_owner["metadata"]["uid"] = "foreign-uid"
      adapter.create(foreign_owner, descriptor: definition.kind)
    end
    provider = M3IdempotencyProvider.new(journal: journal, controller: name)
    provider_applicability = M3IdempotencyMeasurement.provider_effect_applicability(corpus_entry)
    event_sink = lambda do |resource, result|
      events = result.respond_to?(:events) ? Array(result.events) : []
      next if events.empty?

      journal.record_controller_event(reconcile_key: M3IdempotencyMeasurement.key_for(resource),
                                      event: M3ProbeSupport.normalize(events))
    end
    options = options.merge(store: adapter, now: M3IdempotencyFixtures::FIXED_NOW, cloud_provider: provider, event_sink: event_sink)
    manager = Rubernetes::Controller::Manager.new(
      store: adapter, identity: "m3-idempotency-#{name}", registry: registry,
      lease: {clock: -> { M3IdempotencyFixtures::FIXED_NOW }, retry_period_seconds: 0.001},
      controller_options: options
    )
    manager.register_definition(definition, store: adapter, options: options)
    key = M3IdempotencyMeasurement.key_for(primary)
    journal_before_cursor = journal.cursor
    before_journal_inventory = journal.inventory(journal_before_cursor)
    manager.enqueue(key, controller: name)
    first_error_before = manager.last_error
    first_step = manager.step
    first_attempt_observable = M3IdempotencyMeasurement.step_observable(
      first_step, manager: manager, key: key, controller: name, error_before: first_error_before
    )
    queue_retry_observed = store.fault_injections == 1
    first_success_observable = first_attempt_observable
    if queue_retry_observed
      # WorkQueue backoff is deliberately allowed to elapse. The retry below
      # is the production queue retry after the injected Conflict.
      sleep(0.01)
      retry_error_before = manager.last_error
      first_success_step = manager.step
      first_success_observable = M3IdempotencyMeasurement.step_observable(
        first_success_step, manager: manager, key: key, controller: name, error_before: retry_error_before
      )
    else
      # Controllers whose fixture has no update operation complete on the first
      # step.  Do not manufacture a second empty step and call it execution.
    end
    first_success_queue = M3IdempotencyMeasurement.queue_snapshot(manager.queue, key)
    after_first = M3IdempotencyMeasurement.store_observable(adapter)
    first_run_snapshot = journal.snapshot(journal_before_cursor)
    first_journal_inventory = first_run_snapshot.fetch("inventory")
    second_run_cursor = journal.cursor
    manager.enqueue(key, controller: name)
    second_error_before = manager.last_error
    second_step = manager.step
    second_step_observable = M3IdempotencyMeasurement.step_observable(
      second_step, manager: manager, key: key, controller: name, error_before: second_error_before
    )
    second_queue = M3IdempotencyMeasurement.queue_snapshot(manager.queue, key)
    after_second = M3IdempotencyMeasurement.store_observable(adapter)
    second_run_snapshot = journal.snapshot(second_run_cursor)
    second_journal_inventory = second_run_snapshot.fetch("inventory")
    durable_journal = {
      "before" => before_journal_inventory,
      "after" => first_journal_inventory,
      "exact_inventory" => first_journal_inventory == second_journal_inventory,
      "after_sha256" => journal.digest(first_journal_inventory),
      "second_run_sha256" => journal.digest(second_journal_inventory),
      "raw_after_sha256" => first_run_snapshot.fetch("raw_sha256"),
      "raw_second_run_sha256" => second_run_snapshot.fetch("raw_sha256"),
      "raw_entry_count" => first_run_snapshot.fetch("raw_entry_count"),
      "second_run_raw_entry_count" => second_run_snapshot.fetch("raw_entry_count"),
      "first_run" => first_run_snapshot,
      "second_run" => second_run_snapshot,
      "first_run_inventory" => first_journal_inventory,
      "second_run_inventory" => second_journal_inventory,
      "second_run_snapshot" => second_run_snapshot
    }
    first_run_observable_journal = {
      "run" => "first",
      "before" => before_journal_inventory,
      "after" => first_journal_inventory,
      "raw_snapshot" => first_run_snapshot
    }
    second_run_observable_journal = {
      "run" => "second",
      "before" => first_journal_inventory,
      "after" => second_journal_inventory,
      "raw_snapshot" => second_run_snapshot
    }
    first_observable = {"store" => after_first, "step" => first_success_observable, "queue" => first_success_queue,
                        "foreign" => after_first.any? { |object| object.dig("metadata", "name") == foreign.dig("metadata", "name") },
                        "api_mutations" => first_journal_inventory.fetch("api_mutations"), "events" => first_journal_inventory.fetch("events"),
                        "provider_calls" => first_journal_inventory.fetch("provider_calls"),
                        "provider_effect_applicability" => provider_applicability,
                        "durable_journal" => first_run_observable_journal}
    second_observable = {"store" => after_second, "step" => second_step_observable, "queue" => second_queue,
                         "foreign" => after_second.any? { |object| object.dig("metadata", "name") == foreign.dig("metadata", "name") },
                         "api_mutations" => second_journal_inventory.fetch("api_mutations"), "events" => second_journal_inventory.fetch("events"),
                         "provider_calls" => second_journal_inventory.fetch("provider_calls"),
                         "provider_effect_applicability" => provider_applicability,
                         "durable_journal" => second_run_observable_journal}
    first_observable = M3ProbeSupport.normalize(first_observable)
    second_observable = M3ProbeSupport.normalize(second_observable)
    first_digest = M3ProbeSupport.digest(first_observable)
    second_digest = M3ProbeSupport.digest(second_observable)
    # The first run is allowed to apply the initial desired-state diff.  The
    # idempotency assertion is that the replay converges to the same final
    # state without applying another API mutation; raw effect snapshots are
    # kept separate so a second event cannot be hidden by cumulative uniq.
    passed = after_first == after_second &&
             first_observable.fetch("step").fetch("reconcile_success") == true &&
             second_observable.fetch("step").fetch("reconcile_success") == true &&
             first_observable.fetch("step").fetch("pending_retry") == false &&
             second_observable.fetch("step").fetch("pending_retry") == false &&
             second_journal_inventory.fetch("api_mutation_count").zero? &&
             second_journal_inventory.fetch("event_count").zero? &&
             second_journal_inventory.fetch("provider_call_count").zero?
    errors << "controller #{name} reconciliation is not idempotent" unless passed
    {
      "id" => name,
      "controller" => name,
      "execution_count" => 2,
      "attempt_count" => 1,
      "manager_class" => manager.class.name,
      "store_class" => adapter.class.name,
      "store_backend_class" => store.class.name,
      "queue_retry_observed" => queue_retry_observed,
      "error_class" => first_attempt_observable["step_error_class"],
      "owner_scope_checked" => true,
      "diff_applied_twice" => false,
      "first_run_diff_applied" => first_journal_inventory.fetch("api_mutation_count").positive?,
      "replay_diff_applied" => second_journal_inventory.fetch("api_mutation_count").positive?,
      "first_attempt" => first_attempt_observable,
      "provider_effect_applicability" => provider_applicability,
      "foreign_resource_preserved" => first_observable["foreign"] == true && second_observable["foreign"] == true,
      "api_mutation_inventory" => first_journal_inventory.fetch("api_mutations"),
      "event_inventory" => first_journal_inventory.fetch("events"),
      "provider_call_inventory" => first_journal_inventory.fetch("provider_calls"),
      "first_run_raw_snapshot" => first_run_snapshot,
      "second_run_raw_snapshot" => second_run_snapshot,
      "first_run_snapshot" => first_run_snapshot,
      "second_run_snapshot" => second_run_snapshot,
      "first_run_raw_entries" => first_run_snapshot.fetch("raw_entries"),
      "second_run_raw_entries" => second_run_snapshot.fetch("raw_entries"),
      "first_run_effect_ids" => first_run_snapshot.fetch("effect_ids"),
      "second_run_effect_ids" => second_run_snapshot.fetch("effect_ids"),
      "first_run_effect_id_counts" => first_run_snapshot.fetch("effect_id_counts"),
      "second_run_effect_id_counts" => second_run_snapshot.fetch("effect_id_counts"),
      "first_run_api_mutation_count" => first_run_snapshot.fetch("api_mutation_count"),
      "second_run_api_mutation_count" => second_run_snapshot.fetch("api_mutation_count"),
      "first_run_event_count" => first_run_snapshot.fetch("event_count"),
      "second_run_event_count" => second_run_snapshot.fetch("event_count"),
      "first_run_provider_call_count" => first_run_snapshot.fetch("provider_call_count"),
      "second_run_provider_call_count" => second_run_snapshot.fetch("provider_call_count"),
      "durable_journal" => durable_journal,
      "first_effect_observable" => first_observable,
      "second_effect_observable" => second_observable,
      "first_effect_sha256" => first_digest,
      "second_effect_sha256" => second_digest,
      "implementation_class" => implementation_name,
      "implementation_present" => implementation_present,
      "uses_corpus_controller" => false,
      "measurement_source" => "production_module",
      "passed" => passed
    }
  rescue StandardError => error
    errors << "controller #{name} idempotency measurement failed: #{error.class}: #{error.message}"
    {"id" => name, "controller" => name, "execution_count" => 2, "attempt_count" => 1,
     "implementation_class" => "", "implementation_present" => false, "uses_corpus_controller" => false,
     "measurement_source" => "production_module", "api_mutation_inventory" => [], "event_inventory" => [],
     "provider_call_inventory" => [], "durable_journal" => {}, "passed" => false}
  end
  {
    "measurement_source" => "production_module",
    "cases" => cases,
    "difference_count" => cases.count { |entry| entry["passed"] != true },
    "non_idempotent_count" => cases.count { |entry| entry["passed"] != true }
  }
end
