# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/storage/memory_store"

# Fixed-seed state-sequence verification for the M1 watch exit criterion.
# Every resource mutation, list, and watch starts at API::Server so these tests
# cover the observable API::StoreAdapter -> Storage::MemoryStore contract.
class MemoryStoreWatchPropertyTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore
  WatchOverflow = Rubernetes::Storage::WatchOverflow
  PROPERTY_SEEDS = [0x5EED, 0xC0FFEE, 0x51A7E].freeze
  COLLECTION_PATH = "/api/v1/namespaces/property/configmaps"

  # Spec: store S2, informer I1, kubernetes-api W1/W5, M1 exit criterion 7.
  # Type: fixed-seed state-sequence/property; regression for list/watch races.
  # Risk: a mutation between list and subscription is lost, replayed at N, or
  # delivered in a different order to equivalent watchers after reconnect.
  # Mutation target: > N history filter and atomic replay/live registration.
  def test_seeded_state_sequences_have_no_gap_and_reconnect_after_exact_revision
    PROPERTY_SEEDS.each do |seed|
      store = new_store
      server = api_server(store)
      random = Random.new(seed)
      known = {}

      3.times do |index|
        response = create(server, "seed-#{seed}-base-#{index}", value: index)
        assert_status(201, response, seed: seed, operation: :initial_create)
        known[name_of(response.body)] = response.body
      end

      listed = api_call(server, "GET", COLLECTION_PATH)
      assert_status(200, listed, seed: seed, operation: :list)
      listed_revision = listed.body.dig("metadata", "resourceVersion").to_i

      # This commit deliberately lands after list and before either watch. It
      # must be recovered from retained history by both subscribers.
      raced = create(server, "seed-#{seed}-raced", value: -1)
      assert_status(201, raced, seed: seed, operation: :raced_create)
      known[name_of(raced.body)] = raced.body
      expected = [response_trace("ADDED", raced.body)]

      first_response = watch(server, listed_revision)
      second_response = watch(server, listed_revision)
      assert_status(200, first_response, seed: seed, operation: :first_watch)
      assert_status(200, second_response, seed: seed, operation: :second_watch)
      first = first_response.body
      second = second_response.body

      begin
        32.times do |step|
          action = random.rand(100)
          if action < 35 || known.empty?
            name = "seed-#{seed}-created-#{step}"
            response = create(server, name, value: random.rand(10_000))
            assert_status(201, response, seed: seed, operation: :create, step: step)
            known[name] = response.body
            expected << response_trace("ADDED", response.body)
          elsif action < 75
            name = known.keys.sort.fetch(random.rand(known.length))
            candidate = deep_copy(known.fetch(name))
            candidate["data"] = {"value" => "updated-#{seed}-#{step}-#{random.rand(10_000)}"}
            response = api_call(server, "PUT", "#{COLLECTION_PATH}/#{name}", candidate)
            assert_status(200, response, seed: seed, operation: :update, step: step)
            known[name] = response.body
            expected << response_trace("MODIFIED", response.body)
          else
            name = known.keys.sort.fetch(random.rand(known.length))
            response = api_call(server, "DELETE", "#{COLLECTION_PATH}/#{name}")
            assert_status(200, response, seed: seed, operation: :delete, step: step)
            known.delete(name)
            # Kubernetes DELETE returns a Status object; the deleted resource
            # remains observable on the watch stream at the store's new RV.
            expected << ["DELETED", name, store.revision]
          end
        end

        first_trace = event_trace(first.to_a)
        second_trace = event_trace(second.to_a)
        assert_equal expected, first_trace, "seed=#{seed}: first watcher lost, duplicated, or reordered an event"
        assert_equal expected, second_trace, "seed=#{seed}: equivalent watchers observed different histories"
        assert_equal first_trace, second_trace, "seed=#{seed}: W5 watcher ordering differs"
        assert expected.all? { |_type, _name, revision| revision > listed_revision },
               "seed=#{seed}: resourceVersion=N replayed an event at or before N"
        assert_strictly_increasing(expected.map(&:last), seed: seed)

        resume_at = expected.fetch(expected.length / 2).last
        resumed_response = watch(server, resume_at)
        assert_status(200, resumed_response, seed: seed, operation: :reconnect)
        resumed = resumed_response.body
        begin
          expected_suffix = expected.select { |_type, _name, revision| revision > resume_at }
          assert_equal expected_suffix, event_trace(resumed.to_a),
                       "seed=#{seed}: reconnect did not resume immediately after resourceVersion=#{resume_at}"
        ensure
          resumed.close
        end
      ensure
        first&.close
        second&.close
        store.close
      end
    end
  end

  # Spec: kubernetes-api W1/W3 and M1 exit criterion 7.
  # Type: deterministic clock/state transition; boundary at exactly 30 seconds.
  # Risk: bookmark uses a stale resume point or overtakes a committed mutation.
  # Mutation target: bookmark scheduling and Store-monitor ordering.
  def test_bookmark_is_a_reconnectable_resume_point_at_the_injected_clock_boundary
    now = 0.0
    store = new_store(clock: -> { now }, bookmark_interval: 30)
    server = api_server(store)
    created = create(server, "bookmark-base", value: 0)
    assert_status(201, created, operation: :create)
    listed = api_call(server, "GET", COLLECTION_PATH)
    listed_revision = listed.body.dig("metadata", "resourceVersion").to_i

    response = watch(server, listed_revision, "allowWatchBookmarks" => "true")
    assert_status(200, response, operation: :watch)
    stream = response.body
    assert_nil stream.next(timeout: 0), "bookmark was emitted before its 30 second interval"

    now = 30.0
    bookmark = stream.next(timeout: 0)
    assert_equal "BOOKMARK", bookmark.type
    assert_equal listed_revision, bookmark.revision
    assert_equal listed_revision.to_s, bookmark.object.dig("metadata", "resourceVersion")

    followed = create(server, "bookmark-followed", value: 1)
    assert_status(201, followed, operation: :followed_create)
    assert_equal response_trace("ADDED", followed.body), event_trace([stream.next(timeout: 0)]).first

    resumed_response = watch(server, bookmark.revision)
    assert_status(200, resumed_response, operation: :reconnect)
    resumed = resumed_response.body
    assert_equal [response_trace("ADDED", followed.body)], event_trace(resumed.to_a)
  ensure
    stream&.close
    resumed&.close
    store&.close
  end

  # Spec: kubernetes-api W1/W6 and M1 exit criterion 7.
  # Type: fixed-seed state-sequence/property for initial synchronization.
  # Risk: an initial object is omitted/duplicated, a live event appears before
  # the sync BOOKMARK, or reconnect from that bookmark repeats initial state.
  # Mutation target: sendInitialEvents snapshot, bookmark, live registration.
  def test_seeded_send_initial_events_form_one_snapshot_then_live_suffix
    PROPERTY_SEEDS.each do |seed|
      store = new_store
      server = api_server(store)
      random = Random.new(seed ^ 0x1A171A1)
      known = {}

      10.times do |index|
        name = "initial-#{seed}-#{index}"
        response = create(server, name, value: random.rand(10_000))
        assert_status(201, response, seed: seed, operation: :create)
        known[name] = response.body
      end
      6.times do |step|
        name = known.keys.sort.fetch(random.rand(known.length))
        if random.rand(2).zero?
          response = api_call(server, "DELETE", "#{COLLECTION_PATH}/#{name}")
          assert_status(200, response, seed: seed, operation: :delete, step: step)
          known.delete(name)
        else
          candidate = deep_copy(known.fetch(name))
          candidate["data"] = {"value" => "initial-update-#{step}"}
          response = api_call(server, "PUT", "#{COLLECTION_PATH}/#{name}", candidate)
          assert_status(200, response, seed: seed, operation: :update, step: step)
          known[name] = response.body
        end
      end

      listed = api_call(server, "GET", COLLECTION_PATH)
      assert_status(200, listed, seed: seed, operation: :list)
      snapshot_revision = listed.body.dig("metadata", "resourceVersion").to_i
      expected_names = listed.body.fetch("items").map { |object| name_of(object) }.sort

      response = watch(
        server,
        snapshot_revision,
        "sendInitialEvents" => "true", "resourceVersionMatch" => "NotOlderThan",
        "allowWatchBookmarks" => "true"
      )
      assert_status(200, response, seed: seed, operation: :initial_watch)
      stream = response.body
      live = create(server, "initial-#{seed}-live", value: random.rand(10_000))
      assert_status(201, live, seed: seed, operation: :live_create)

      begin
        events = stream.to_a
        bookmark_index = events.index { |event| event.type == "BOOKMARK" }
        refute_nil bookmark_index, "seed=#{seed}: initial synchronization did not emit BOOKMARK"
        initial_events = events.take(bookmark_index)
        suffix = events.drop(bookmark_index + 1)
        assert initial_events.all? { |event| event.type == "ADDED" },
               "seed=#{seed}: initial state was not entirely synthetic ADDED"
        assert_equal expected_names, initial_events.map { |event| name_of(event.object) }.sort,
                     "seed=#{seed}: initial snapshot membership differs from list"
        assert_equal snapshot_revision, events.fetch(bookmark_index).revision,
                     "seed=#{seed}: initial BOOKMARK does not identify the snapshot revision"
        assert_equal "true",
                     events.fetch(bookmark_index).object.dig("metadata", "annotations", "k8s.io/initial-events-end"),
                     "seed=#{seed}: initial BOOKMARK does not carry the Kubernetes completion annotation"
        assert_equal [response_trace("ADDED", live.body)], event_trace(suffix),
                     "seed=#{seed}: live suffix did not follow the initial BOOKMARK exactly once"

        resumed_response = watch(server, snapshot_revision)
        assert_status(200, resumed_response, seed: seed, operation: :reconnect)
        resumed = resumed_response.body
        begin
          assert_equal [response_trace("ADDED", live.body)], event_trace(resumed.to_a),
                       "seed=#{seed}: reconnect from initial BOOKMARK repeated initial state"
        ensure
          resumed.close
        end
      ensure
        stream&.close
        store.close
      end
    end
  end

  # Spec: store S4, kubernetes-api W1/W2, M1 exit criterion 7.
  # Type: exact boundary/negative-path test through API Status responses.
  # Risk: compaction rejects the retained boundary N or accepts N-1.
  # Mutation target: compacted revision comparison and API 410 translation.
  def test_compaction_rejects_n_minus_one_but_resumes_immediately_after_n
    store = new_store
    server = api_server(store)
    4.times do |index|
      response = create(server, "compact-#{index}", value: index)
      assert_status(201, response, operation: :create)
    end
    listed = api_call(server, "GET", COLLECTION_PATH)
    boundary = listed.body.dig("metadata", "resourceVersion").to_i
    store.compact!(revision: boundary)

    expired = watch(server, boundary - 1)
    assert_equal 410, expired.status
    assert_equal "Failure", expired.body.fetch("status")

    retained = watch(server, boundary)
    assert_status(200, retained, operation: :boundary_watch)
    stream = retained.body
    assert_nil stream.next(timeout: 0), "resourceVersion=N replayed an event at N"
    next_commit = create(server, "compact-next", value: boundary + 1)
    assert_status(201, next_commit, operation: :next_create)
    assert_equal [response_trace("ADDED", next_commit.body)], event_trace([stream.next(timeout: 0)])
    assert_nil stream.next(timeout: 0), "boundary watch emitted more than the N+1 mutation"
  ensure
    stream&.close
    store&.close
  end

  # Spec: kubernetes-api W4/W7.
  # Type: bounded-buffer adversarial test with an API-created slow consumer.
  # Risk: a slow watcher retains unbounded memory or remains registered after
  # terminal overflow, contaminating future commits.
  # Mutation target: queue event limit, close/error state, watcher cleanup.
  def test_api_slow_watcher_overflow_closes_terminally_without_a_subscription_leak
    store = new_store(watcher_buffer_size: 3)
    server = api_server(store)
    response = watch(server, 0)
    assert_status(200, response, operation: :watch)
    stream = response.body

    4.times do |index|
      created = create(server, "overflow-#{index}", value: index)
      assert_status(201, created, operation: :create, step: index)
    end

    assert_predicate stream, :closed?
    assert_predicate stream, :overflowed?
    assert_equal 0, store.watcher_count
    error = assert_raises(Rubernetes::API::Status::Expired) { stream.next(timeout: 0) }
    assert_equal 410, error.code
    assert_equal "Expired", error.reason
  ensure
    stream&.close
    store&.close
  end

  private

  def new_store(**options)
    Store.new(history_revisions: nil, history_seconds: nil, **options)
  end

  def api_server(store)
    Rubernetes::API::Server.new(registry: Rubernetes::API::Registry.new, store: store)
  end

  def api_call(server, method, path, body = nil, query: nil)
    server.call(method: method, path: path, body: body, query: query)
  end

  def create(server, name, value:)
    api_call(
      server,
      "POST",
      COLLECTION_PATH,
      {"metadata" => {"name" => name}, "data" => {"value" => value.to_s}}
    )
  end

  def watch(server, resource_version, extra_query = {})
    api_call(
      server,
      "GET",
      COLLECTION_PATH,
      query: {"watch" => "true", "resourceVersion" => resource_version.to_s}.merge(extra_query)
    )
  end

  def response_trace(type, object)
    [type, name_of(object), object.dig("metadata", "resourceVersion").to_i]
  end

  def event_trace(events)
    events.map do |event|
      revision = event.object.dig("metadata", "resourceVersion").to_i
      assert_equal revision, event.revision, "watch envelope and object resourceVersion differ"
      [event.type, name_of(event.object), revision]
    end
  end

  def name_of(object)
    object.dig("metadata", "name")
  end

  def deep_copy(value)
    JSON.parse(JSON.generate(value))
  end

  def assert_status(expected, response, context = {})
    assert_equal expected, response.status, "#{context.inspect}: unexpected response #{response.body.inspect}"
  end

  def assert_strictly_increasing(revisions, seed:)
    revisions.each_cons(2) do |left, right|
      assert_operator left, :<, right, "seed=#{seed}: revisions are not strictly increasing"
    end
  end
end
