# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# RestartAllContainersOnContainerExits (KEP-5532): a container exit that
# matches a restartPolicyRules entry with action RestartAllContainers kills
# and removes every init, sidecar and regular container and starts the Pod
# again from its first init container, in the same sandbox.  Scenarios from
# test/e2e/common/node/container_restart_policy.go (v1.36.2).  The rule used
# to be matched and treated as a restart of the one container that exited.
class NodeRestartAllContainersTest < Minitest::Test
  RULES = [{"action" => "RestartAllContainers", "exitCodes" => {"operator" => "In", "values" => [42]}}].freeze

  # Containers run until the test makes them exit; init containers exit
  # with the next scripted code for their name (default 0).
  class Runtime
    attr_reader :created, :removed, :stopped, :sandboxes
    attr_accessor :startup_ready

    def initialize(init_exits: {})
      @counter = 0
      @init_exits = init_exits.transform_values(&:dup)
      @created = []
      @removed = []
      @stopped = []
      @exited = {}
      @names = {}
      @sandboxes = 0
    end

    def run_sandbox(_pod, runtime_class: nil)
      @sandboxes += 1
      "sandbox-1"
    end

    def create_container(_sandbox, spec)
      @counter += 1
      id = "c#{@counter}"
      @names[id] = spec["name"]
      @created << spec["name"]
      id
    end

    def start_container(_id) = true

    def exec(_id, _command, tty: false) = startup_ready ? 0 : 1

    def wait_container(id)
      code = Array(@init_exits[@names[id]]).shift || 0
      @exited[id] = code
      {"state" => "terminated", "exitCode" => code}
    end

    def exit!(name, code)
      id = @names.select { |_id, candidate| candidate == name }.keys.last
      @exited[id] = code
    end

    def container_status(id)
      return {"state" => "running"} unless @exited.key?(id)

      {"state" => "exited", "exit_code" => @exited[id]}
    end

    def stop_container(id, timeout:)
      @stopped << [@names[id], timeout]
      @exited[id] ||= 137
      true
    end

    def remove_container(id)
      @removed << @names[id]
      true
    end

    def remove_sandbox(_id) = true
  end

  class Reporter
    attr_reader :statuses

    def initialize = @statuses = []
    def report(_pod, status) = @statuses << status.to_h
  end

  def setup
    @reporter = Reporter.new
  end

  def lifecycle(runtime)
    Rubernetes::Node::Lifecycle.new(runtime: runtime, reporter: @reporter, sleeper: ->(_seconds) {})
  end

  def pod(init: [], containers: [], restart_policy: "Never")
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "restart-all", "namespace" => "ns", "uid" => "pod-1", "generation" => 1},
     "spec" => {"nodeName" => "node-1", "restartPolicy" => restart_policy,
                "initContainers" => init, "containers" => containers}}
  end

  def container(name, rules: nil, policy: nil)
    value = {"name" => name, "image" => "example/busybox"}
    value["restartPolicyRules"] = rules if rules
    value["restartPolicy"] = policy if policy
    value
  end

  def entry(subject, name)
    subject.send(:record, "pod-1")[:containers].find { |candidate| candidate[:name] == name }
  end

  def condition(status, type)
    Array(status["conditions"]).find { |value| value["type"] == type }
  end

  def test_regular_container_exit_restarts_every_container
    runtime = Runtime.new
    subject = lifecycle(runtime)
    spec = pod(init: [container("init"), container("sidecar", policy: "Always")],
               containers: [container("source-container", rules: RULES, policy: "Never"), container("regular")])
    subject.start(spec)

    assert_equal %w[init sidecar source-container regular], runtime.created

    runtime.exit!("source-container", 42)
    subject.observe_exits("pod-1", spec)

    assert_equal %w[init sidecar source-container regular] * 2, runtime.created
    assert_equal 1, runtime.sandboxes, "the sandbox is kept"
    # The containers that did not trigger it are killed without grace; the source goes last.
    assert_equal [["regular", 0], ["sidecar", 0]], runtime.stopped
    assert_equal %w[regular init sidecar source-container], runtime.removed
    %w[init sidecar source-container regular].each do |name|
      status = entry(subject, name)[:status]

      assert_equal 1, status["restartCount"], name
      assert_equal "RestartingAllContainers", status.dig("lastState", "terminated", "reason"), name
      assert_equal 137, status.dig("lastState", "terminated", "exitCode"), name
    end
    assert entry(subject, "source-container")[:started]
    assert entry(subject, "regular")[:started]

    during = @reporter.statuses.find { |status| condition(status, "AllContainersRestarting")&.fetch("status") == "True" }

    refute_nil during, "AllContainersRestarting=True is published while the Pod is reset"
    assert_equal "RestartAllContainersStarted", condition(during, "AllContainersRestarting")["reason"]
    assert_equal "Running", during["phase"]
    assert_equal "True", condition(during, "Initialized")["status"], "an initialized Pod stays initialized"
    waiting = Array(during["containerStatuses"]).find { |status| status["name"] == "regular" }

    assert_equal "RestartingAllContainers", waiting.dig("state", "waiting", "reason")

    final = @reporter.statuses.last

    assert_equal "False", condition(final, "AllContainersRestarting")["status"]
    assert_equal "Running", final["phase"]
  end

  def test_restartable_init_gates_following_containers_until_startup_probe_succeeds
    runtime = Runtime.new
    subject = lifecycle(runtime)
    sidecar = container("sidecar", policy: "Always").merge("startupProbe" => {"exec" => {"command" => ["check"]}})
    spec = pod(init: [container("init"), sidecar, container("following-init")], containers: [container("app")])
    subject.start(spec)

    assert_equal %w[init sidecar], runtime.created
    assert_equal "Pending", @reporter.statuses.last["phase"]
    assert_equal "False", condition(@reporter.statuses.last, "Initialized")["status"]
    assert_equal false, entry(subject, "sidecar")[:status]["started"]

    runtime.startup_ready = true
    subject.reconcile(spec)

    assert_equal %w[init sidecar following-init app], runtime.created
    assert_equal 1, runtime.sandboxes
    assert_equal "Running", @reporter.statuses.last["phase"]
    assert_equal "True", condition(@reporter.statuses.last, "Initialized")["status"]
    assert_equal true, entry(subject, "sidecar")[:status]["started"]
  end

  def test_image_update_restarts_only_the_sidecar_blocked_in_startup
    runtime = Runtime.new
    subject = lifecycle(runtime)
    sidecar = container("gated", policy: "Always").merge("startupProbe" => {"exec" => {"command" => ["check"]}, "failureThreshold" => 1})
    spec = pod(init: [container("started", policy: "Always"), sidecar], containers: [container("app")])
    subject.start(spec)

    assert_equal 1, entry(subject, "gated")[:status]["restartCount"]
    original_id = entry(subject, "started")[:id]
    spec["spec"]["initContainers"][1]["image"] = "example/alternate"
    subject.reconcile(spec)

    assert_equal 1, runtime.sandboxes
    assert_equal original_id, entry(subject, "started")[:id]
    assert_equal "example/alternate", entry(subject, "gated")[:spec]["image"]
    assert_operator entry(subject, "gated")[:status]["restartCount"], :>=, 2
    assert_equal "Pending", @reporter.statuses.last["phase"]
    refute_includes runtime.created, "app"
  end

  def test_running_image_update_preserves_the_other_container_and_sandbox
    runtime = Runtime.new
    subject = lifecycle(runtime)
    spec = pod(containers: [container("app"), container("unchanged")])
    subject.start(spec)
    original_id = entry(subject, "unchanged")[:id]
    spec["spec"]["containers"][0]["image"] = "example/alternate"
    subject.reconcile(spec)

    assert_equal %w[app unchanged app], runtime.created
    assert_equal 1, runtime.sandboxes
    assert_equal original_id, entry(subject, "unchanged")[:id]
    assert_equal 0, entry(subject, "unchanged")[:status]["restartCount"]
    assert_equal 1, entry(subject, "app")[:status]["restartCount"]
    assert_equal "example/alternate", entry(subject, "app")[:spec]["image"]
  end

  def test_sidecar_exit_restarts_every_container
    runtime = Runtime.new
    subject = lifecycle(runtime)
    spec = pod(init: [container("init"), container("sidecar", policy: "Always"),
                      container("source-sidecar", rules: RULES, policy: "Always")],
               containers: [container("regular")])
    subject.start(spec)
    runtime.exit!("source-sidecar", 42)
    subject.observe_exits("pod-1", spec)

    assert_equal %w[init sidecar source-sidecar regular] * 2, runtime.created
    %w[init sidecar source-sidecar regular].each { |name| assert_equal 1, entry(subject, name)[:status]["restartCount"], name }
    assert entry(subject, "source-sidecar")[:started]
  end

  def test_init_container_exit_restarts_init_and_sidecar_containers
    runtime = Runtime.new(init_exits: {"source-init" => [42, 0]})
    subject = lifecycle(runtime)
    spec = pod(init: [container("sidecar", policy: "Always"), container("init"),
                      container("source-init", rules: RULES, policy: "Never")],
               containers: [container("regular")])
    subject.start(spec)

    assert_equal %w[sidecar init source-init sidecar init source-init regular], runtime.created
    %w[sidecar init source-init].each { |name| assert_equal 1, entry(subject, name)[:status]["restartCount"], name }
    assert_equal 0, entry(subject, "regular")[:status]["restartCount"]
    assert_equal "Running", subject.send(:record, "pod-1")[:state]
  end

  def test_a_killed_container_with_its_own_rule_does_not_loop
    runtime = Runtime.new
    subject = lifecycle(runtime)
    spec = pod(containers: [container("source-container", rules: RULES, policy: "Never"),
                            container("regular", rules: RULES, policy: "Never")])
    subject.start(spec)
    runtime.exit!("source-container", 42)
    subject.observe_exits("pod-1", spec)
    subject.observe_exits("pod-1", spec)

    assert_equal %w[source-container regular] * 2, runtime.created, "one reset, not a loop"
    assert entry(subject, "regular")[:started]
  end

  def test_a_previously_restarted_container_counts_from_its_history
    runtime = Runtime.new
    subject = lifecycle(runtime)
    subject.instance_variable_get(:@restarts)
    spec = pod(containers: [container("source-container", rules: RULES, policy: "Always"), container("regular")],
               restart_policy: "Always")
    subject.start(spec)
    runtime.exit!("source-container", 1)
    subject.observe_exits("pod-1", spec)

    assert_equal 1, entry(subject, "source-container")[:status]["restartCount"]

    runtime.exit!("source-container", 42)
    subject.observe_exits("pod-1", spec)

    assert_equal 2, entry(subject, "source-container")[:status]["restartCount"]
    assert_equal 1, entry(subject, "regular")[:status]["restartCount"]
    assert entry(subject, "source-container")[:started]
  end

  def test_a_pod_without_the_rule_reports_no_restarting_condition
    runtime = Runtime.new
    subject = lifecycle(runtime)
    subject.start(pod(containers: [container("plain")]))

    assert_nil condition(@reporter.statuses.last, "AllContainersRestarting")
  end
end
