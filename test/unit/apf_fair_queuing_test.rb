# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/observability/metrics"

# API Priority and Fairness as k8s.io/apiserver/pkg/util/flowcontrol does it:
# fair queues on a virtual clock, the work estimator (list size, watchers of
# a mutation), and seats lent and borrowed between priority levels.
class APFFairQueuingTest < Minitest::Test
  FC = Rubernetes::Security::FlowControl
  S = Rubernetes::Security

  class Recorder
    attr_reader :events

    def initialize = @events = []
    def method_missing(name, *args) = @events << [name, *args]
    def respond_to_missing?(*) = true
  end

  def setup
    @now = 100.0
    @clock = -> { @now }
  end

  def work(initial = 1, final: 0, latency: 0.0) = FC::WorkEstimate.new(initial_seats: initial, final_seats: final, additional_latency: latency)

  def queue_set(limit: 1, queues: 2, hand: 1, length: 10, observer: nil, after: nil)
    FC::QueueSet.new(name: "test", desired_queues: queues, queue_length_limit: length, hand_size: hand, concurrency_limit: limit,
                     concurrency_denominator: limit, clock: @clock, observer: observer, after: after)
  end

  # Flow hashes that land on different queues (hand 1, two queues: the card is hash % 2).
  def hash_for_queue(index) = index

  def test_fair_queuing_serves_the_quiet_flow_before_the_flood
    recorder = Recorder.new
    set = queue_set(limit: 1, observer: recorder)
    holder = set.start_request(work: work, hash_value: hash_for_queue(0), distinguisher: "a", flow_schema: "fs")
    assert_equal :execute, holder.decision
    flood = 3.times.map { set.start_request(work: work, hash_value: hash_for_queue(0), distinguisher: "a", flow_schema: "fs") }
    quiet = set.start_request(work: work, hash_value: hash_for_queue(1), distinguisher: "b", flow_schema: "fs")
    assert_equal 4, set.total_waiting
    assert(flood.all? { |request| request.decision == :pending })

    order = []
    @now += 0.003
    set.finish(holder)
    dispatched = (flood + [quiet]).find { |request| request.decision == :execute }
    order << dispatched.distinguisher
    @now += 0.003
    set.finish(dispatched)
    dispatched = (flood + [quiet]).find { |request| request.decision == :execute && !order.include?(request) && request != dispatched }
    second = (flood + [quiet]).select { |request| request.decision == :execute && request.start_time == @now }.first
    order << second.distinguisher
    # The flood's queue already spent virtual time on the holder, so the
    # quiet flow's request finishes earliest in virtual time and goes first.
    assert_equal %w[b a], order
    assert_includes recorder.events, [:add_requests_in_queues, "fs", 1]
    dispatch_metrics = recorder.events.select { |event| event.first == :set_dispatch_metrics }
    refute_empty dispatch_metrics
    r, s, s_min, s_max, ds_min, ds_max = dispatch_metrics.last[1..]
    assert_operator r, :>=, 0
    assert_operator s_max, :>=, s_min
    assert_operator ds_max, :>=, ds_min
    assert_operator s, :>=, 0
  end

  def test_virtual_time_advances_with_the_seats_in_use_over_active_queues
    recorder = Recorder.new
    set = queue_set(limit: 4, observer: recorder)
    assert_equal 0, set.current_r
    @now += 1.0
    set.sync_time
    assert_equal 0, set.current_r, "an idle queue set's clock stands still"
    held = set.start_request(work: work(2), hash_value: 0, distinguisher: "a", flow_schema: "fs")
    @now += 1.0
    set.sync_time
    assert_equal FC::SeatSeconds.of(2, 1.0), set.current_r, "two seats in use on one active queue: R runs at two seat-seconds per second"
    assert_equal [:set_current_r, 2.0], recorder.events.reverse.find { |event| event.first == :set_current_r }
    set.finish(held)
  end

  def test_no_accommodation_and_oversized_requests
    recorder = Recorder.new
    set = queue_set(limit: 2, observer: recorder)
    small = set.start_request(work: work(1), hash_value: 0, distinguisher: "a", flow_schema: "fs")
    big = set.start_request(work: work(3), hash_value: 1, distinguisher: "b", flow_schema: "fs")
    assert_equal :pending, big.decision, "three seats do not fit while another request executes"
    assert_includes recorder.events, [:add_dispatch_with_no_accommodation, "fs"]
    set.finish(small)
    assert_equal :execute, big.decision, "a request wider than the limit runs alone"
    set.finish(big)
  end

  def test_queue_full_time_out_and_rejection_reasons
    recorder = Recorder.new
    set = queue_set(limit: 1, queues: 1, hand: 1, length: 1, observer: recorder)
    holder = set.start_request(work: work, hash_value: 0, distinguisher: "a", flow_schema: "fs")
    waiter = set.start_request(work: work, hash_value: 0, distinguisher: "a", flow_schema: "fs")
    error = assert_raises(FC::RejectedError) { set.start_request(work: work, hash_value: 0, distinguisher: "a", flow_schema: "fs") }
    assert_equal "queue-full", error.reason
    assert_includes recorder.events, [:add_reject, "fs", "queue-full"]
    refute set.wait(waiter, deadline: @now - 1), "a passed deadline ejects the request"
    assert_equal :cancel, waiter.decision
    assert_includes recorder.events, [:add_reject, "fs", "time-out"]
    assert_equal 0, set.total_waiting
    set.finish(holder)

    reject_only = queue_set(limit: 1, queues: 0, observer: recorder)
    held = reject_only.start_request(work: work, hash_value: 0, distinguisher: "a", flow_schema: "fs")
    error = assert_raises(FC::RejectedError) { reject_only.start_request(work: work, hash_value: 0, distinguisher: "a", flow_schema: "fs") }
    assert_equal "concurrency-limit", error.reason
    reject_only.finish(held)
    exempt = queue_set(limit: 0, queues: -1, observer: recorder)
    5.times { assert_equal :execute, exempt.start_request(work: work, hash_value: 0, distinguisher: "a", flow_schema: "fs").decision }
  end

  def test_epoch_advance_when_r_grows_too_large
    recorder = Recorder.new
    set = queue_set(limit: 1, observer: recorder)
    set.current_r = FC::QueueSet::HIGH_R - FC::SeatSeconds.of(1, 1.0)
    held = set.start_request(work: work, hash_value: 0, distinguisher: "a", flow_schema: "fs")
    waiting = set.start_request(work: work, hash_value: 1, distinguisher: "b", flow_schema: "fs")
    @now += 2.0
    set.sync_time
    assert_operator set.current_r, :<, FC::QueueSet::HIGH_R
    assert_includes recorder.events, [:add_epoch_advance, true]
    assert_operator waiting.arrival_r, :>=, 0
    set.finish(held)
  end

  def test_lingering_final_seats_are_released_after_the_additional_latency
    timers = []
    recorder = Recorder.new
    set = queue_set(limit: 2, observer: recorder, after: ->(seconds, &block) { timers << [seconds, block] })
    mutation = set.start_request(work: work(1, final: 2, latency: 0.005), hash_value: 0, distinguisher: "a", flow_schema: "fs")
    assert_equal 2, set.total_seats_in_use, "max seats are held from dispatch"
    set.finish(mutation)
    assert_equal 2, set.total_seats_in_use, "the final seats linger"
    assert_equal 0, set.total_executing
    assert_in_delta 0.005, timers.first.first, 1e-9
    timers.first.last.call
    assert_equal 0, set.total_seats_in_use
  end

  # -- work estimator ----------------------------------------------------------

  def attributes(verb:, resource: "pods", group: "", namespace: "ns", name: "", subresource: "", field_selector: nil, user: "u")
    S::Authorization::Attributes.new(user: S::UserInfo.new(name: user, groups: ["system:authenticated"]), verb: verb, api_group: group, api_version: "v1",
                                     resource: resource, namespace: namespace, name: name, subresource: subresource, path: "/x", resource_request: true,
                                     field_selector: field_selector)
  end

  def estimator(max_seats: 15, source: nil)
    counts = FC::ObjectCountTracker.new(source: source, clock: @clock)
    counts.set("pods", 5000, 2000)
    counts.set("deployments.apps", 10, 500)
    @watches = FC::WatchTracker.new
    @samples = []
    FC::WorkEstimator.new(object_counts: counts, watch_tracker: @watches, max_seats: ->(_level) { max_seats },
                          watch_count_observer: ->(level, schema, count) { @samples << [level, schema, count] })
  end

  def test_list_work_is_the_memory_a_list_loads
    subject = estimator
    from_cache = subject.estimate(attributes(verb: "list"), {}, "fs", "pl")
    assert_equal 10, from_cache.initial_seats, "5000 x 2000 bytes from the cache is capped at 1 MB, 100 KB a seat"
    limited = subject.estimate(attributes(verb: "list"), {"limit" => "10"}, "fs", "pl")
    assert_equal 1, limited.initial_seats
    single = subject.estimate(attributes(verb: "list", name: "one"), {}, "fs", "pl")
    assert_equal 1, single.initial_seats
    exact = subject.estimate(attributes(verb: "list"), {"resourceVersionMatch" => "Exact", "resourceVersion" => "5", "labelSelector" => "a=b"}, "fs", "pl")
    assert_equal 15, exact.initial_seats, "an exact-revision list with a selector loads half the objects from storage: 50 seats, capped by the level"
    small = subject.estimate(attributes(verb: "list", resource: "deployments", group: "apps"), {}, "fs", "pl")
    assert_equal 1, small.initial_seats
    unknown = subject.estimate(attributes(verb: "list", resource: "widgets"), {}, "fs", "pl")
    assert_equal 1, unknown.initial_seats, "no count for the resource: the minimum"
    @now += 200.0
    stale = subject.estimate(attributes(verb: "list", resource: "pods"), {"limit" => "100"}, "fs", "pl")
    assert_equal 10, stale.initial_seats, "a stale count is treated as infinite objects of the largest size"
    watch_init = subject.estimate(attributes(verb: "watch"), {"sendInitialEvents" => "true", "resourceVersion" => "5"}, "fs", "pl")
    assert_equal 10, watch_init.initial_seats
    plain_watch = subject.estimate(attributes(verb: "watch"), {"resourceVersion" => "5"}, "fs", "pl")
    assert_equal 1, plain_watch.initial_seats
    assert_equal 1, subject.estimate(attributes(verb: "get"), {}, "fs", "pl").initial_seats
  end

  def test_mutating_work_follows_the_interested_watchers
    subject = estimator(max_seats: 10)
    forgets = 25.times.map { @watches.register(attributes(verb: "watch", namespace: "")) }
    forgets << @watches.register(attributes(verb: "watch", namespace: "ns"))
    forgets << @watches.register(attributes(verb: "watch", namespace: "other"))
    forgets << @watches.register(attributes(verb: "watch", namespace: "", field_selector: "spec.nodeName=n1"), field_selector: "spec.nodeName=n1")
    assert_equal 26, @watches.interested_watch_count(attributes(verb: "update")), "cluster-wide watches plus the namespace's, not the other namespace's nor a node-pinned one"
    estimate = subject.estimate(attributes(verb: "update"), {}, "fs", "pl")
    assert_equal 1, estimate.initial_seats
    assert_equal 3, estimate.final_seats, "26 watchers, ten a seat"
    assert_in_delta 0.005, estimate.additional_latency, 1e-9
    assert_equal [["pl", "fs", 26]], @samples
    token = subject.estimate(attributes(verb: "create", resource: "serviceaccounts", subresource: "token"), {}, "fs", "pl")
    assert_equal 0, token.final_seats
    forgets.each(&:call)
    assert_equal 0, @watches.size
    quiet = subject.estimate(attributes(verb: "delete"), {}, "fs", "pl")
    assert_equal 0, quiet.final_seats
  end

  # -- borrowing -------------------------------------------------------------

  RULE = [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}],
           "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "namespaces" => ["*"], "clusterScope" => true}]}].freeze

  def level(name, shares:, lendable:, borrowing: nil)
    limited = {"nominalConcurrencyShares" => shares, "lendablePercent" => lendable,
               "limitResponse" => {"type" => "Queue", "queuing" => {"queues" => 8, "handSize" => 2, "queueLengthLimit" => 50}}}
    limited["borrowingLimitPercent"] = borrowing if borrowing
    {"metadata" => {"name" => name}, "spec" => {"type" => "Limited", "limited" => limited}}
  end

  def schema(name, level, namespace)
    {"metadata" => {"name" => name}, "spec" => {"matchingPrecedence" => 1, "priorityLevelConfiguration" => {"name" => level},
                                                 "distinguisherMethod" => {"type" => "ByUser"},
                                                 "rules" => [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}],
                                                              "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "namespaces" => [namespace]}]}]}}
  end

  def test_seats_are_lent_to_the_level_that_needs_them
    controller = FC::Controller.new(flow_schemas: [schema("busy-fs", "busy", "busy"), schema("idle-fs", "idle", "idle")],
                                    priority_level_configurations: [level("busy", shares: 1, lendable: 50), level("idle", shares: 1, lendable: 50)],
                                    read_seats: 20, mutating_seats: 0, clock: @clock, borrowing_adjustment_seconds: nil)
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, component: "kube-apiserver")
    controller.metrics = registry
    busy = controller.priority_levels["busy"]
    idle = controller.priority_levels["idle"]
    assert_equal [10, 5, 30], [busy.nominal_seats, busy.min_seats, busy.max_seats]
    text = registry.render
    assert_match(/apiserver_flowcontrol_lower_limit_seats\{priority_level="busy"\} 5/, text)
    assert_match(/apiserver_flowcontrol_upper_limit_seats\{priority_level="busy"\} 30/, text)
    assert_match(/apiserver_flowcontrol_nominal_limit_seats\{priority_level="busy"\} 10/, text)
    assert_match(/apiserver_flowcontrol_seat_fair_frac \d/, text)
    initial = busy.current_seats
    assert_operator initial, :>=, busy.min_seats

    tickets = []
    waiters = []
    initial.times { tickets << controller.enter(attributes(verb: "get", namespace: "busy", user: "u#{tickets.length}")) }
    5.times do |i|
      waiters << Thread.new { controller.enter(attributes(verb: "get", namespace: "busy", user: "w#{i}")) }
    end
    Thread.pass until busy.waiting == 5
    # Ten seconds of that demand, then the adjustment period ends.
    @now += 10.0
    controller.adjust_borrowing!
    assert_operator busy.current_seats, :>, initial, "the busy level borrows"
    assert_equal idle.min_seats, idle.current_seats, "the idle level lends down to its lower bound"
    assert_equal 20, busy.current_seats + idle.current_seats, "the server's seats are conserved"
    text = registry.render
    assert_match(/apiserver_flowcontrol_current_limit_seats\{priority_level="busy"\} #{busy.current_seats}/, text)
    assert_match(/apiserver_flowcontrol_demand_seats_high_watermark\{priority_level="busy"\} #{initial + 5}/, text)
    assert_match(/apiserver_flowcontrol_demand_seats_average\{priority_level="busy"\} #{initial + 5}/, text)
    assert_match(/apiserver_flowcontrol_demand_seats_stdev\{priority_level="busy"\} 0/, text)
    assert_match(/apiserver_flowcontrol_demand_seats_smoothed\{priority_level="busy"\} #{initial + 5}/, text)
    assert_match(/apiserver_flowcontrol_target_seats\{priority_level="busy"\} #{initial + 5}/, text)
    assert_match(/apiserver_flowcontrol_target_seats\{priority_level="idle"\} 5/, text)
    assert_match(/apiserver_flowcontrol_seat_fair_frac 1/, text)
    assert_match(/apiserver_flowcontrol_current_r\{priority_level="busy"\} \d/, text)
    assert_match(/apiserver_flowcontrol_dispatch_r\{priority_level="busy"\} \d/, text)
    assert_match(/apiserver_flowcontrol_next_s_bounds\{bound="max",priority_level="busy"\} \d/, text)
    # The borrowed seats let the waiters through.
    Thread.pass until waiters.all? { |thread| !thread.alive? } || busy.waiting.zero?
    tickets.concat(waiters.map(&:value))
    tickets.each { |ticket| controller.release(ticket) }
    assert_equal 0, busy.inflight

    # With the demand gone the smoothed demand decays (0.977 a period) and
    # the borrowed seats go back over the following periods.
    borrowed = busy.current_seats
    60.times do
      @now += 10.0
      controller.adjust_borrowing!
      assert_operator busy.current_seats, :<=, borrowed
      borrowed = busy.current_seats
    end
    assert_equal busy.current_seats, idle.current_seats
    assert_equal 10, busy.current_seats
  end

  def test_concurrency_allocation
    allocs, fair = FC::Controller.compute_concurrency_allocation(20, [{lower: 10.0, upper: 30.0, target: 15.0}, {lower: 5.0, upper: 30.0, target: 5.0}])
    assert_equal [15.0, 5.0], allocs
    assert_in_delta 1.0, fair, 1e-9
    allocs, fair = FC::Controller.compute_concurrency_allocation(10, [{lower: 2.0, upper: 4.0, target: 3.0}, {lower: 2.0, upper: 100.0, target: 3.0}])
    assert_in_delta 4.0, allocs[0], 1e-9
    assert_in_delta 6.0, allocs[1], 1e-9
    assert_in_delta 2.0, fair, 1e-9
    allocs, = FC::Controller.compute_concurrency_allocation(4, [{lower: 2.0, upper: 4.0, target: 3.0}, {lower: 2.0, upper: 100.0, target: 3.0}])
    assert_equal [2.0, 2.0], allocs, "constrained from below"
    assert_raises(ArgumentError) { FC::Controller.compute_concurrency_allocation(3, [{lower: 2.0, upper: 4.0, target: 3.0}, {lower: 2.0, upper: 4.0, target: 3.0}]) }
  end

  def test_dealer_hands_distinct_cards
    dealer = FC::Dealer.new(64, 6)
    hand = dealer.deal(0x1234_5678_9abc_def0)
    assert_equal 6, hand.length
    assert_equal hand.uniq, hand
    assert(hand.all? { |card| card.between?(0, 63) })
    assert_equal [3, 1, 0], FC::Dealer.new(4, 3).deal(7)
  end
end
