# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/storage/memory_store"
require "rubernetes/api"

class MemoryStoreTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore
  Gone = Rubernetes::Storage::Gone
  Conflict = Rubernetes::Storage::Conflict
  WatchOverflow = Rubernetes::Storage::WatchOverflow

  def setup
    @store = Store.new(history_revisions: nil, history_seconds: nil)
  end

  def test_mutations_use_one_global_monotonic_revision_and_return_immutable_copies
    first = @store.create("pods/a", object(name: "a", labels: {"app" => "web"}))
    second = @store.create("services/a", object(name: "a"))

    assert_equal("1", first.dig("metadata", "resourceVersion"))
    assert_equal("2", second.dig("metadata", "resourceVersion"))
    assert_equal(2, @store.revision)
    assert_predicate(first, :frozen?)
    assert_predicate(first.fetch("metadata"), :frozen?)
    assert_raises(FrozenError) { first.fetch("metadata")["name"] = "changed" }
    assert_equal("a", @store.get("pods/a").dig("metadata", "name"))
  end

  def test_create_update_delete_enforce_preconditions
    created = @store.create("pods/a", object(name: "a"))
    updated = @store.guaranteed_update("pods/a", prec: created.dig("metadata", "resourceVersion")) do |current|
      current["spec"] = {"replicas" => 2}
      current
    end

    assert_equal("2", updated.dig("metadata", "resourceVersion"))
    assert_raises(Conflict) { @store.delete("pods/a", prec: "") }
    assert_raises(Conflict) do
      @store.delete("pods/a", prec: created.dig("metadata", "resourceVersion"))
    end
    deleted = @store.delete("pods/a", prec: updated.dig("metadata", "resourceVersion"))

    assert_equal("a", deleted.dig("metadata", "name"))
    assert_equal("3", deleted.dig("metadata", "resourceVersion"))
    assert_raises(Rubernetes::Storage::NotFound) { @store.get("pods/a") }
  end

  def test_request_uid_replays_without_a_second_revision
    request = "request-1"
    first = @store.create("pods/a", object(name: "a"), request_uid: request)
    replay = @store.create("pods/a", object(name: "a"), request_uid: request)

    assert_equal(first, replay)
    assert_equal(1, @store.revision)

    updated = @store.guaranteed_update("pods/a", request_uid: "request-2") do |current|
      current["spec"] = {"ready" => true}
      current
    end
    replayed_update = @store.guaranteed_update("pods/a", request_uid: "request-2") do |current|
      current["spec"] = {"ready" => false}
      current
    end

    assert_equal(updated, replayed_update)
    assert_equal(2, @store.revision)
  end

  def test_list_selectors_and_continue_token_pin_a_snapshot
    3.times do |index|
      @store.create(
        "pods/#{index}",
        object(name: index.to_s, labels: {"app" => index.even? ? "web" : "worker"})
      )
    end

    first = @store.list("pods/", label_selector: "app=web", limit: 1)
    @store.create("pods/3", object(name: "3", labels: {"app" => "web"}))
    second = @store.list("pods/", label_selector: "app=web", limit: 1, continue: first.continue_token)

    assert_equal(["0"], first.items.map { |item| item.dig("metadata", "name") })
    assert_equal(["2"], second.items.map { |item| item.dig("metadata", "name") })
    assert_nil(second.continue_token)
    assert_equal(first.resource_version, second.resource_version)
  end

  def test_watch_replays_without_gaps_and_emits_bookmarks
    created = @store.create("pods/a", object(name: "a"))
    watcher = @store.watch("pods/", since: 0, allow_bookmarks: true, bookmark_interval: 0)
    updated = @store.guaranteed_update("pods/a") do |current|
      current["status"] = {"phase" => "Running"}
      current
    end
    @store.delete("pods/a")

    added = watcher.next
    modified = watcher.next
    deleted = watcher.next

    assert_equal("ADDED", added.type)
    assert_equal(created.dig("metadata", "resourceVersion").to_i, added.revision)
    assert_equal("MODIFIED", modified.type)
    assert_equal(updated.dig("metadata", "resourceVersion").to_i, modified.revision)
    assert_equal("DELETED", deleted.type)
    assert_equal(@store.revision, deleted.revision)
    assert_equal(deleted.revision.to_s, deleted.object.dig("metadata", "resourceVersion"))
    assert_equal("BOOKMARK", watcher.next.type)
  ensure
    watcher&.close
  end

  def test_watch_overflow_is_terminal_and_requires_relist
    watcher = @store.watch("pods/", since: 0, buffer_size: 1)
    @store.create("pods/a", object(name: "a"))
    @store.create("pods/b", object(name: "b"))

    assert_predicate(watcher, :overflowed?)
    assert_raises(WatchOverflow) { watcher.next }
  end

  def test_compaction_returns_gone_for_old_watch_and_keeps_boundary_snapshot
    store = Store.new(history_revisions: 2, history_seconds: nil)
    4.times { |index| store.create("pods/#{index}", object(name: index.to_s)) }

    assert_equal(2, store.compacted_revision)
    # A revision the store no longer holds history for cannot be served; zero
    # is exempt because it asks for the current state, not for history.
    assert_raises(Gone) { store.watch("pods/", since: 1) }
    watcher = store.watch("pods/", since: 2)
    store.create("pods/4", object(name: "4"))

    assert_equal("ADDED", watcher.next.type)
  ensure
    watcher&.close
  end

  def test_concurrent_guaranteed_updates_are_serialized
    store = Store.new(history_revisions: nil, history_seconds: nil, sleeper: ->(_seconds) {})
    store.create("counter", object(name: "counter", spec: {"count" => 0}))
    threads = Array.new(8) do
      Thread.new do
        store.guaranteed_update("counter") do |current|
          current["spec"]["count"] += 1
          current
        end
      end
    end
    threads.each(&:join)

    assert_equal(8, store.get("counter").dig("spec", "count"))
    assert_equal(9, store.revision)
  end

  def test_update_and_replace_keep_cas_and_immutable_copy_contracts
    created = @store.create("pods/replace", object(name: "replace"))
    candidate = Rubernetes::Storage::MemoryStoreSupport.deep_dup(created)
    candidate["spec"] = {"value" => "updated"}

    updated = @store.update(
      "pods/replace",
      candidate,
      resource_version: created.dig("metadata", "resourceVersion")
    )

    assert_equal("1", candidate.dig("metadata", "resourceVersion"))
    assert_equal("2", updated.dig("metadata", "resourceVersion"))
    assert_predicate(updated, :frozen?)
    assert_predicate(updated.fetch("spec"), :frozen?)
    assert_raises(Conflict) { @store.replace("pods/replace", candidate, resource_version: "1") }

    replacement = Rubernetes::Storage::MemoryStoreSupport.deep_dup(updated)
    replacement["spec"]["value"] = "replaced"
    replaced = @store.replace("pods/replace", replacement, resource_version: "2")

    assert_equal("3", replaced.dig("metadata", "resourceVersion"))
    assert_equal("replaced", replaced.dig("spec", "value"))
  end

  def test_concurrent_replay_of_one_request_uid_commits_once
    store = Store.new(history_revisions: nil, history_seconds: nil, sleeper: ->(_seconds) {})
    store.create("counter", object(name: "counter", spec: {"count" => 0}))
    results = Array.new(10) do
      Thread.new do
        store.guaranteed_update("counter", request_uid: "same-request") do |current|
          current["spec"]["count"] += 1
          current
        end
      end
    end.map(&:value)

    assert_equal(1, store.get("counter").dig("spec", "count"))
    assert_equal(2, store.revision)
    assert(results.all?(results.first))
  end

  def test_field_selector_and_selector_transition_are_applied_to_watch
    @store.create("pods/a", object(name: "a", labels: {"app" => "web"}))
    @store.create("pods/b", object(name: "b", labels: {"app" => "worker"}))
    result = @store.list("pods/", field_selector: "metadata.name=a")

    assert_equal(["a"], result.items.map { |item| item.dig("metadata", "name") })

    watcher = @store.watch("pods/", since: 0, label_selector: "app=web")
    @store.guaranteed_update("pods/b") do |current|
      current["metadata"]["labels"]["app"] = "web"
      current
    end

    assert_equal("ADDED", watcher.next.type)
    assert_equal("ADDED", watcher.next.type)

    @store.guaranteed_update("pods/a") do |current|
      current["metadata"]["labels"]["app"] = "worker"
      current
    end

    assert_equal("DELETED", watcher.next.type)
  ensure
    watcher&.close
  end

  def test_time_compaction_is_deterministic_with_an_injected_clock
    now = 0.0
    store = Store.new(history_revisions: nil, history_seconds: 10, clock: -> { now })
    store.create("pods/a", object(name: "a"))
    store.create("pods/b", object(name: "b"))
    now = 11.0
    store.compact!

    assert_equal(2, store.compacted_revision)
    assert_raises(Gone) { store.watch("pods/", since: 1) }
  end

  def test_stale_precondition_cannot_commit_after_delete_and_recreate_aba
    original = @store.create("pods/aba", object(name: "first"))
    @store.delete("pods/aba", prec: original.dig("metadata", "resourceVersion"))
    replacement = @store.create("pods/aba", object(name: "second"))

    assert_raises(Conflict) do
      @store.guaranteed_update("pods/aba", prec: original.dig("metadata", "resourceVersion")) do |current|
        current["metadata"]["name"] = "stale-write"
        current
      end
    end
    assert_equal("second", @store.get("pods/aba").dig("metadata", "name"))
    assert_equal("3", replacement.dig("metadata", "resourceVersion"))
  end

  def test_unconditional_update_retries_after_delete_and_recreate_aba
    store = Store.new(history_revisions: nil, history_seconds: nil, sleeper: ->(_seconds) {})
    original = store.create("pods/aba", object(name: "first"))
    entered = Queue.new
    release = Queue.new
    result_queue = Queue.new
    paused = false

    updater = Thread.new do
      result_queue << store.guaranteed_update("pods/aba") do |current|
        unless paused
          paused = true
          entered << true
          release.pop
        end
        current["spec"] = {"updated" => true}
        current
      end
    end
    begin
      entered.pop
      store.delete("pods/aba", prec: original.dig("metadata", "resourceVersion"))
      replacement = store.create("pods/aba", object(name: "second"))
      release << true
      result = result_queue.pop
    ensure
      release << true
      updater.join
    end

    assert_equal("second", result.dig("metadata", "name"))
    assert_equal("true", result.dig("spec", "updated").to_s)
    assert_equal("4", result.dig("metadata", "resourceVersion"))
    assert_equal("second", store.get("pods/aba").dig("metadata", "name"))
    assert_equal(replacement.dig("metadata", "resourceVersion").to_i + 1, store.revision)
  end

  def test_parallel_create_update_delete_preserves_unique_global_revisions
    store = Store.new(history_revisions: nil, history_seconds: nil, sleeper: ->(_seconds) {})
    create_done = Queue.new
    update_done = Queue.new
    watcher = store.watch("pods/", since: 0)

    creator = Thread.new do
      store.create("pods/parallel", object(name: "created"))
      create_done << true
    end
    updater = Thread.new do
      create_done.pop
      store.guaranteed_update("pods/parallel") do |current|
        current["status"] = {"phase" => "Running"}
        current
      end
      update_done << true
    end
    deleter = Thread.new do
      update_done.pop
      store.delete("pods/parallel")
    end
    [creator, updater, deleter].each(&:join)

    assert_equal([1, 2, 3], Array.new(3) { watcher.next.revision })
    assert_equal(3, store.revision)
    assert_raises(Rubernetes::Storage::NotFound) { store.get("pods/parallel") }
  ensure
    watcher&.close
  end

  def test_list_then_watch_replays_mutation_that_landed_between_calls
    @store.create("pods/base", object(name: "base"))
    list_revision = @store.list("pods/").resource_version.to_i
    @store.create("pods/raced", object(name: "raced"))

    watcher = @store.watch("pods/", since: list_revision)
    event = watcher.next

    assert_equal("ADDED", event.type)
    assert_equal("raced", event.object.dig("metadata", "name"))
    assert_equal(list_revision + 1, event.revision)
  ensure
    watcher&.close
  end

  # "Get State and Start at Any": an unset or zero resourceVersion asks for the
  # current state as synthetic ADDED events before the stream, which is what a
  # client that watches right after creating an object depends on.
  def test_watch_without_a_resource_version_replays_the_current_state_first
    @store.create("pods/base", object(name: "base"))
    watcher = @store.watch("pods/", resource_version: "")
    @store.create("pods/next", object(name: "next"))

    first = watcher.next

    assert_equal("ADDED", first.type)
    assert_equal("base", first.object.dig("metadata", "name"))
    assert_equal("next", watcher.next.object.dig("metadata", "name"))
    assert_nil(watcher.next(timeout: 0))
  ensure
    watcher&.close
  end

  def test_watch_at_zero_replays_the_current_state_rather_than_history
    @store.create("pods/base", object(name: "base"))
    @store.update("pods/base", object(name: "base", labels: {"round" => "two"}))
    watcher = @store.watch("pods/", resource_version: "0")

    first = watcher.next

    assert_equal("ADDED", first.type)
    assert_equal("two", first.object.dig("metadata", "labels", "round"))
    assert_nil(watcher.next(timeout: 0))
  ensure
    watcher&.close
  end

  def test_watch_at_an_explicit_revision_streams_only_later_changes
    @store.create("pods/base", object(name: "base"))
    watcher = @store.watch("pods/", resource_version: @store.revision.to_s)
    @store.create("pods/next", object(name: "next"))

    assert_equal("next", watcher.next.object.dig("metadata", "name"))
    assert_nil(watcher.next(timeout: 0))
  ensure
    watcher&.close
  end

  def test_watch_selector_reports_full_membership_transition
    @store.create("pods/a", object(name: "a", labels: {"app" => "blue"}))
    watcher = @store.watch("pods/", since: @store.revision, label_selector: "app=web")

    @store.guaranteed_update("pods/a") do |current|
      current["metadata"]["labels"]["app"] = "web"
      current
    end

    assert_equal("ADDED", watcher.next.type)

    @store.guaranteed_update("pods/a") do |current|
      current["status"] = {"phase" => "Running"}
      current
    end

    assert_equal("MODIFIED", watcher.next.type)

    @store.guaranteed_update("pods/a") do |current|
      current["metadata"]["labels"]["app"] = "blue"
      current
    end

    assert_equal("DELETED", watcher.next.type)
  ensure
    watcher&.close
  end

  def test_watcher_cancel_wakes_reader_and_unregisters_without_leak
    watcher = @store.watch("pods/", since: @store.revision)
    reader = Thread.new { watcher.next }
    watcher.close

    assert_nil(reader.value)
    assert_equal(0, @store.watcher_count)
    assert_predicate(watcher, :closed?)
  end

  def test_slow_watcher_overflow_is_removed_from_store
    watcher = @store.watch("pods/", since: 0, buffer_size: 2)
    3.times { |index| @store.create("pods/#{index}", object(name: index.to_s)) }

    assert_predicate(watcher, :overflowed?)
    assert_equal(0, @store.watcher_count)
    assert_raises(WatchOverflow) { watcher.next }
  end

  def test_continue_token_rejects_tamper_cross_prefix_and_compacted_snapshot
    3.times { |index| @store.create("pods/#{index}", object(name: index.to_s)) }
    first_page = @store.list("pods/", limit: 1)
    token = first_page.continue_token

    tampered = token.dup
    tampered[-1] = tampered[-1] == "A" ? "B" : "A"
    assert_raises(Rubernetes::Storage::InvalidContinueToken) do
      @store.list("pods/", limit: 1, continue: tampered)
    end
    assert_raises(Rubernetes::Storage::InvalidContinueToken) do
      @store.list("services/", limit: 1, continue: token)
    end

    @store.create("pods/3", object(name: "3"))
    @store.compact!(revision: @store.revision)
    assert_raises(Gone) { @store.list("pods/", limit: 1, continue: token) }
  end

  # The revision cap and the time window each make history droppable on their
  # own: the window is the retention promise (etcd's compaction interval) and
  # the count is a memory cap.  Taking the smaller target let the cap veto the
  # window -- on a young store `revision - 100_000` is negative, so nothing was
  # ever compacted and no continue token or watch resourceVersion ever expired.
  def test_the_time_window_compacts_even_under_a_large_revision_cap
    now = 1_000.0
    store = Store.new(history_revisions: 100_000, history_seconds: 300, clock: -> { now })
    5.times { |index| store.create("pods/#{index}", object(name: index.to_s)) }
    page = store.list("pods/", limit: 2)

    assert_equal(0, store.compacted_revision, "nothing is older than the window yet")

    6.times do |round|
      now += 200
      store.create("pods/z#{round}", object(name: "z#{round}"))
    end

    assert_operator(store.compacted_revision, :>, 5, "history older than the window must be compacted")
    assert_raises(Gone) { store.list("pods/", limit: 2, continue: page.continue_token) }
  end

  # A continue token whose snapshot was compacted away is answered with 410
  # and an "inconsistent" token that resumes at the same position against the
  # current snapshot.  A client that has to start over instead re-reads every
  # page it already had, and a chunked listing then reports more objects than
  # exist -- which is exactly what the API chunking conformance spec counts.
  def test_a_compacted_continue_token_comes_back_with_an_inconsistent_continue
    10.times { |index| @store.create(format("pods/%02d", index), object(name: format("%02d", index))) }
    first_page = @store.list("pods/", limit: 3)

    assert_equal(3, first_page.items.length)

    @store.create("pods/10", object(name: "10"))
    @store.compact!(revision: @store.revision)

    error = assert_raises(Gone) { @store.list("pods/", limit: 3, continue: first_page.continue_token) }
    resumed = error.details["continue"]

    refute_nil(resumed, "410 must carry a continue token the client can resume from")

    seen = first_page.items.length
    token = resumed
    until token.nil?
      page = @store.list("pods/", limit: 3, continue: token)
      seen += page.items.length
      token = page.continue_token
    end

    assert_equal(11, seen, "every object is listed exactly once across the resumed pages")
  end

  def test_request_uid_with_different_payload_is_rejected
    @store.create("pods/idempotent", object(name: "one"), request_uid: "same")

    assert_raises(Rubernetes::Storage::RequestUIDConflict) do
      @store.create("pods/idempotent", object(name: "two"), request_uid: "same")
    end

    @store.guaranteed_update("pods/idempotent", request_uid: "update") do |current|
      current["spec"] = {"value" => "one"}
      current
    end
    assert_raises(Rubernetes::Storage::RequestUIDConflict) do
      @store.guaranteed_update("pods/idempotent", request_uid: "update", prec: "2") do |current|
        current["spec"] = {"value" => "two"}
        current
      end
    end
  end

  def test_guaranteed_update_retries_eight_times_with_bounded_full_jitter
    sleeps = []
    random = Class.new do
      def rand
        1.0
      end
    end.new
    store = Store.new(
      history_revisions: nil,
      history_seconds: nil,
      sleeper: ->(duration) { sleeps << duration },
      random: random
    )
    store.create("counter", object(name: "counter", spec: {"count" => 0}))
    attempts = 0

    assert_raises(Conflict) do
      store.guaranteed_update("counter", max_retries: 8) do |current|
        attempts += 1
        store.guaranteed_update("counter") do |other|
          other["spec"]["count"] += 1
          other
        end
        current
      end
    end

    assert_equal(9, attempts)
    assert_equal(8, sleeps.length)
    sleeps.each_with_index do |duration, index|
      ceiling = [0.005 * (2**index), 0.640].min

      assert_operator(duration, :>=, 0.0)
      assert_operator(duration, :<=, ceiling)
    end
  end

  def test_api_store_adapter_runs_crud_selectors_and_continue_against_storage_store
    store = Store.new(history_revisions: nil, history_seconds: nil)
    server = api_server(store)
    first = api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
                       "metadata" => {"name" => "first", "labels" => {"app" => "web"}},
                       "data" => {"value" => "one"}
                     })
    second = api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
                        "metadata" => {"name" => "second", "labels" => {"app" => "worker"}},
                        "data" => {"value" => "two"}
                      })
    third = api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
                       "metadata" => {"name" => "third", "labels" => {"app" => "web"}},
                       "data" => {"value" => "three"}
                     })

    assert_equal(201, first.status)
    assert_equal("1", first.body.dig("metadata", "resourceVersion"))
    assert_equal(201, second.status)
    assert_equal(201, third.status)
    assert_equal("first", api_call(server, "GET", "/api/v1/namespaces/dev/configmaps/first").body.dig("metadata", "name"))

    selected = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {"labelSelector" => "app=web"}
    )

    assert_equal(%w[first third], selected.body.fetch("items").map { |item| item.dig("metadata", "name") })

    page = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {"limit" => "1", "labelSelector" => "app=web"}
    )
    continue_token = page.body.dig("metadata", "continue")

    refute_nil(continue_token)
    next_page = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {"limit" => "1", "labelSelector" => "app=web", "continue" => continue_token}
    )

    assert_equal(["third"], next_page.body.fetch("items").map { |item| item.dig("metadata", "name") })
    assert_equal(page.body.dig("metadata", "resourceVersion"), next_page.body.dig("metadata", "resourceVersion"))

    updated = api_call(server, "PUT", "/api/v1/namespaces/dev/configmaps/first", {
                         "metadata" => {"name" => "first", "resourceVersion" => "1"},
                         "data" => {"value" => "updated"}
                       })

    assert_equal(200, updated.status)
    assert_equal("4", updated.body.dig("metadata", "resourceVersion"))
    assert_equal("updated", updated.body.dig("data", "value"))

    stale = api_call(server, "PUT", "/api/v1/namespaces/dev/configmaps/first", {
                       "metadata" => {"name" => "first", "resourceVersion" => "1"},
                       "data" => {"value" => "stale"}
                     })

    assert_equal(409, stale.status)

    deleted = api_call(server, "DELETE", "/api/v1/namespaces/dev/configmaps/first")

    assert_equal(200, deleted.status)
    assert_equal("Status", deleted.body.fetch("kind"))
    assert_equal("Success", deleted.body.fetch("status"))
    assert_equal("first", deleted.body.dig("details", "name"))
    assert_equal("configmaps", deleted.body.dig("details", "kind"))
    assert_equal("5", store.resource_version_string)
    assert_equal(404, api_call(server, "GET", "/api/v1/namespaces/dev/configmaps/first").status)
    assert_respond_to(store, :replace)
  end

  # M1 API contract: server-side apply creation must persist the namespace
  # selected by the request path even when the manifest omits metadata.namespace.
  def test_api_apply_create_populates_path_namespace_with_storage_store
    store = Store.new(history_revisions: nil, history_seconds: nil)
    server = api_server(store)

    response = api_call(
      server,
      "PATCH",
      "/api/v1/namespaces/dev/configmaps/applied",
      {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "applied"}},
      query: {"fieldManager" => "namespace-regression"},
      headers: {"Content-Type" => "application/apply-patch+yaml"}
    )

    assert_equal(201, response.status)
    assert_equal("dev", response.body.dig("metadata", "namespace"))
    assert_equal(
      "dev",
      api_call(server, "GET", "/api/v1/namespaces/dev/configmaps/applied").body.dig("metadata", "namespace")
    )
  end

  def test_api_watch_stream_and_compaction_resume_errors_use_storage_contract
    store = Store.new(history_revisions: nil, history_seconds: nil)
    server = api_server(store)
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
               "metadata" => {"name" => "base", "labels" => {"app" => "web"}}
             })
    watch_response = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {"watch" => "true", "resourceVersion" => "0", "labelSelector" => "app=web"}
    )
    stream = watch_response.body
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
               "metadata" => {"name" => "ignored", "labels" => {"app" => "worker"}}
             })
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
               "metadata" => {"name" => "followed", "labels" => {"app" => "web"}}
             })

    assert_equal(200, watch_response.status)
    assert_equal(
      [%w[ADDED base], %w[ADDED followed]],
      stream.to_a.map { |event| [event.type, event.object.dig("metadata", "name")] }
    )
    assert_respond_to(stream, :each_json_line)
    stream.close

    page = api_call(server, "GET", "/api/v1/namespaces/dev/configmaps", query: {"limit" => "1"})
    snapshot_revision = page.body.dig("metadata", "resourceVersion").to_i
    token = page.body.dig("metadata", "continue")
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "after-page"}})
    store.compact!(revision: store.revision)

    expired_page = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {"limit" => "1", "continue" => token}
    )

    assert_operator(snapshot_revision, :<, store.compacted_revision)
    assert_equal(410, expired_page.status)
    expired_watch = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {"watch" => "true", "resourceVersion" => snapshot_revision.to_s}
    )

    assert_equal(410, expired_watch.status)
  ensure
    stream&.close
  end

  def test_api_send_initial_events_are_added_then_bookmarked
    store = Store.new(history_revisions: nil, history_seconds: nil)
    server = api_server(store)
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "initial"}})

    response = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {
        "watch" => "true",
        "sendInitialEvents" => "true",
        "resourceVersionMatch" => "NotOlderThan",
        "allowWatchBookmarks" => "true"
      }
    )
    stream = response.body
    events = stream.to_a

    assert_equal(%w[ADDED BOOKMARK], events.map(&:type))
    assert_equal("initial", events.first.object.dig("metadata", "name"))
    assert_equal(store.resource_version_string, events.last.object.dig("metadata", "resourceVersion"))
    assert_equal("v1", events.last.object["apiVersion"])
    assert_equal("ConfigMap", events.last.object["kind"])
    assert_equal("true", events.last.object.dig("metadata", "annotations", "k8s.io/initial-events-end"))
  ensure
    stream&.close
  end

  def test_api_send_initial_events_respect_resource_namespace_and_selectors
    store = Store.new(history_revisions: nil, history_seconds: nil)
    server = api_server(store)
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
               "metadata" => {"name" => "selected", "labels" => {"track" => "yes"}}
             })
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {
               "metadata" => {"name" => "filtered", "labels" => {"track" => "no"}}
             })
    api_call(server, "POST", "/api/v1/namespaces/other/configmaps", {
               "metadata" => {"name" => "wrong-namespace", "labels" => {"track" => "yes"}}
             })

    response = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {
        "watch" => "true",
        "sendInitialEvents" => "true",
        "resourceVersionMatch" => "NotOlderThan",
        "allowWatchBookmarks" => "true",
        "labelSelector" => "track=yes"
      }
    )
    stream = response.body
    events = stream.to_a

    assert_equal(%w[ADDED BOOKMARK], events.map(&:type))
    assert_equal(["selected"], events.filter_map { |event| event.object.dig("metadata", "name") })
  ensure
    stream&.close
  end

  def test_api_send_initial_events_omit_bookmark_unless_bookmarks_are_allowed
    store = Store.new(history_revisions: nil, history_seconds: nil)
    server = api_server(store)
    api_call(server, "POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "initial"}})

    response = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {
        "watch" => "true",
        "sendInitialEvents" => "true",
        "resourceVersionMatch" => "NotOlderThan"
      }
    )
    stream = response.body

    assert_equal(["ADDED"], stream.to_a.map(&:type))
  ensure
    stream&.close
  end

  def test_api_send_initial_events_requires_not_older_than_match
    server = api_server(Store.new(history_revisions: nil, history_seconds: nil))

    response = api_call(
      server,
      "GET",
      "/api/v1/namespaces/dev/configmaps",
      query: {"watch" => "true", "sendInitialEvents" => "true"}
    )

    assert_equal(422, response.status)
    assert_equal(
      {
        "apiVersion" => "v1",
        "kind" => "Status",
        "metadata" => {},
        "status" => "Failure",
        "message" => "ListOptions.meta.k8s.io \"\" is invalid: resourceVersionMatch: Forbidden: sendInitialEvents requires setting resourceVersionMatch to NotOlderThan",
        "reason" => "Invalid",
        "details" => {
          "group" => "meta.k8s.io",
          "kind" => "ListOptions",
          "causes" => [{
            "reason" => "FieldValueForbidden",
            "message" => "Forbidden: sendInitialEvents requires setting resourceVersionMatch to NotOlderThan",
            "field" => "resourceVersionMatch"
          }]
        },
        "code" => 422
      },
      response.body
    )
  end

  private

  def api_server(store)
    Rubernetes::API::Server.new(registry: Rubernetes::API::Registry.new, store: store)
  end

  def api_call(server, method, path, body = nil, query: nil, headers: {})
    server.call(method: method, path: path, body: body, query: query, headers: headers)
  end

  def object(name:, labels: nil, spec: nil)
    metadata = {"name" => name}
    metadata["labels"] = labels if labels
    value = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata}
    value["spec"] = spec if spec
    value
  end
end
