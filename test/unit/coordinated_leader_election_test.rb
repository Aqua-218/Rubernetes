# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class CoordinatedLeaderElectionTest < Minitest::Test
  Coordination = Rubernetes::Bootstrap::CoordinatedLeaderElection
  IDENTITY = Coordination::Store::IDENTITY
  GROUP = "/apis/coordination.k8s.io"
  LEASES = "#{GROUP}/v1/namespaces/default/leases".freeze
  CANDIDATES = "#{GROUP}/v1beta1/namespaces/default/leasecandidates".freeze

  class Logger
    def debug(*, **) = nil
  end

  def setup
    @time = Time.utc(2026, 11, 19)
    @server = api(gate: true)
    @controller = Coordination.new(api_server: @server, logger: Logger.new, identity: "test-apiserver", clock: -> { @time })
  end

  def test_oldest_emulation_version_wins_at_highest_binary_strategy
    create_candidate("new", emulation: "1.36.0", binary: "1.37.0")
    create_candidate("old", emulation: "1.35.0", binary: "1.36.0")
    @controller.send(:reconcile)
    lease = request("GET", "#{LEASES}/shared").body.fetch("spec")

    assert_equal Coordination::OLDEST, lease["strategy"]
    assert_equal "old", lease["holderIdentity"]
    assert_equal 5, lease["leaseDurationSeconds"]
  end

  def test_ping_then_prefer_new_candidate_without_replacing_live_holder
    lease = object("Lease", "shared", {"holderIdentity" => "previous", "renewTime" => timestamp, "leaseDurationSeconds" => 20})

    assert_equal 201, request("POST", LEASES, lease).status

    create_candidate("candidate", renewal: @time - 6)
    @controller.send(:reconcile)
    candidate = request("GET", "#{CANDIDATES}/candidate").body

    assert_equal timestamp, candidate.dig("spec", "pingTime")
    assert_equal "previous", request("GET", "#{LEASES}/shared").body.dig("spec", "holderIdentity")

    @time += 1
    renewed = candidate.merge("spec" => candidate.fetch("spec").merge("renewTime" => timestamp))

    assert_equal 200, request("PUT", "#{CANDIDATES}/candidate", renewed).status

    @controller.send(:reconcile)
    preferred = request("GET", "#{LEASES}/shared").body.fetch("spec")

    assert_equal "previous", preferred["holderIdentity"]
    assert_equal "candidate", preferred["preferredHolder"]
  end

  def test_third_party_strategy_creates_lease_without_claiming_it
    create_candidate("candidate", strategy: "example.test/custom")
    @controller.send(:reconcile)
    lease = request("GET", "#{LEASES}/shared").body.fetch("spec")

    assert_equal "example.test/custom", lease["strategy"]
    refute lease.key?("holderIdentity")
  end

  def test_expired_candidate_is_collected
    create_candidate("candidate", renewal: @time - Coordination::CANDIDATE_TTL - 1)
    @controller.send(:reconcile)

    assert_equal 404, request("GET", "#{LEASES}/shared").status
    assert_equal 404, request("GET", "#{CANDIDATES}/candidate").status
  end

  def test_gate_off_hides_candidates_and_discards_new_coordination_fields
    @server = api(gate: false)
    lease = object("Lease", "plain", {"strategy" => Coordination::OLDEST, "preferredHolder" => "candidate"})
    written = request("POST", LEASES, lease)

    assert_equal 201, written.status
    refute written.body.fetch("spec", {}).key?("strategy")
    refute written.body.fetch("spec", {}).key?("preferredHolder")
    assert_equal 404, request("GET", CANDIDATES).status
  end

  def test_existing_lock_migrates_legacy_transition_count_through_api
    name = Coordination::LOCK_NAME
    spec = {"holderIdentity" => "previous", "renewTime" => timestamp(@time - 30),
            "leaseDurationSeconds" => 15, "leaderTransitions" => 4}
    lease = object("Lease", name, spec)
    lease.fetch("metadata")["namespace"] = "kube-system"
    @store.create("registry/coordination.k8s.io/v1/leases/kube-system/#{name}", lease)
    @controller.send(:reconcile)

    spec = request("GET", "#{GROUP}/v1/namespaces/kube-system/leases/#{name}").body.fetch("spec")

    assert_equal 5, spec["leaseTransitions"]
    refute spec.key?("leaderTransitions")
    assert_match(/\Atest-apiserver_/, spec.fetch("holderIdentity"))
  end

  private

  def api(gate:)
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @store = Rubernetes::Storage::MemoryStore.new
    Rubernetes::API::Server.new(
      registry: registry, store: @store, feature_gates: {Coordination::GATE => gate},
      runtime_config: {"coordination.k8s.io/v1beta1" => true}
    )
  end

  def request(method, path, body = nil)
    @server.call(method: method, path: path, body: body, identity: IDENTITY)
  end

  def timestamp(time = @time) = time.utc.iso8601(6)

  def create_candidate(name, emulation: "1.35.0", binary: "1.36.0", strategy: Coordination::OLDEST, renewal: @time)
    spec = {"leaseName" => "shared", "emulationVersion" => emulation, "binaryVersion" => binary,
            "strategy" => strategy, "renewTime" => timestamp(renewal)}
    result = request("POST", CANDIDATES, object("LeaseCandidate", name, spec, version: "v1beta1"))

    assert_equal 201, result.status, result.body.inspect
  end

  def object(kind, name, spec, version: "v1")
    {"apiVersion" => "coordination.k8s.io/#{version}", "kind" => kind, "metadata" => {"name" => name}, "spec" => spec}
  end
end
