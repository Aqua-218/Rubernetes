# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/native"
require "rubernetes/node/cdi"

# OCI hooks from CDI container edits (runtime-spec config.md "POSIX-platform
# Hooks"): validated like CDI's Hook#Validate, run with the container state on
# stdin at their stage; a pre-start failure fails the container, poststart and
# poststop failures are warnings.
class OCIHooksTest < Minitest::Test
  Hooks = Rubernetes::Runtime::Native::Hooks
  Native = Rubernetes::Runtime::Native

  def setup
    @dir = Dir.mktmpdir("oci-hooks-")
    @log = File.join(@dir, "log")
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  # A hook that appends "<stage> <status> <pid?> <bundle-root>" to the log.
  def hook(stage, exit_code: 0, extra: "")
    script = %(read -r state; ) +
             %(status=$(printf '%s' "$state" | sed -n 's/.*"status":"\\([a-z]*\\)".*/\\1/p'); ) +
             %(pid=$(printf '%s' "$state" | grep -q '"pid":' && echo pid || echo nopid); ) +
             %(bundle=$(printf '%s' "$state" | sed -n 's/.*"bundle":"\\([^"]*\\)".*/\\1/p'); ) +
             %(root=$(sed -n 's/.*"path": "\\([^"]*\\)".*/\\1/p' "$bundle/config.json" | head -1); ) +
             %(echo "$HOOK_STAGE $status $pid $root" >> #{@log}; #{extra} exit #{exit_code})
    {"hookName" => stage, "path" => "/bin/sh", "args" => ["sh", "-c", script], "env" => ["HOOK_STAGE=#{stage}"]}
  end

  def log_lines = File.exist?(@log) ? File.readlines(@log, chomp: true) : []

  def test_normalize_validates_like_cdi
    assert_raises(Hooks::Error) { Hooks.normalize([{"hookName" => "preStart", "path" => "/bin/true"}]) }
    assert_raises(Hooks::Error) { Hooks.normalize([{"hookName" => "prestart", "path" => ""}]) }
    assert_raises(Hooks::Error) { Hooks.normalize([{"hookName" => "prestart", "path" => "bin/true"}]) }
    assert_raises(Hooks::Error) { Hooks.normalize([{"hookName" => "prestart", "path" => "/bin/true", "env" => ["NOVALUE"]}]) }
    assert_raises(Hooks::Error) { Hooks.normalize([{"hookName" => "prestart", "path" => "/bin/true", "timeout" => 0}]) }
    grouped = Hooks.normalize([{"hookName" => "poststart", "path" => "/b"},
                               {"hookName" => "createRuntime", "path" => "/a", "timeout" => 3}])

    assert_equal %w[createRuntime poststart], grouped.keys
    assert_equal({"path" => "/a", "args" => [], "env" => [], "timeout" => 3}, grouped["createRuntime"].first)
  end

  def test_cdi_rejects_an_invalid_hook_before_the_container_is_created
    edits = Rubernetes::Node::CDI::Edits.empty
    edits.merge!("hooks" => [{"hookName" => "bogus", "path" => "/bin/true"}])
    error = assert_raises(Rubernetes::Node::CDI::Error) { Rubernetes::Node::CDI.apply({"env" => []}, edits) }
    assert_includes error.message, %(invalid hook name "bogus")
  end

  def test_run_passes_state_args_and_only_the_hook_environment
    out = File.join(@dir, "out")
    hook = {"path" => "/bin/sh", "args" => ["custom-argv0", "-c", "cat > #{out}; echo \"$0 $FOO ${HOME:-nohome}\" >> #{out}"],
            "env" => ["FOO=bar"], "timeout" => nil}

    assert Hooks.run(hook, {"status" => "creating"}, stage: "prestart", index: 0)
    assert_equal [%({"status":"creating"}custom-argv0 bar nohome)], File.readlines(out, chomp: true)
  end

  def test_run_reports_exit_status_output_and_timeout
    failing = {"path" => "/bin/sh", "args" => ["sh", "-c", "echo broken >&2; exit 3"], "env" => [], "timeout" => nil}
    error = assert_raises(Hooks::Error) { Hooks.run(failing, {}, stage: "createRuntime", index: 1) }
    assert_equal "error running createRuntime hook #1: /bin/sh: exit status 3, output: broken", error.message

    slow = {"path" => "/bin/sh", "args" => ["sh", "-c", "sleep 30"], "env" => [], "timeout" => 1}
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = assert_raises(Hooks::Error) { Hooks.run(slow, {}, stage: "prestart", index: 0) }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
    assert_includes error.message, "did not finish in 1s"
  end

  def runtime
    Native.new(journal_path: File.join(@dir, "state", "journal.jsonl"), sandbox_root: File.join(@dir, "sandboxes"),
               log_root: File.join(@dir, "logs"))
  end

  def start(runtime, hooks)
    sandbox = runtime.run_sandbox({"request_id" => "hooks-#{rand(1 << 30)}"})
    container = runtime.create_container(sandbox, {"id" => "c1", "command" => ["/bin/true"], "cdi_hooks" => hooks})
    [sandbox, container]
  end

  # Without container namespaces (a supervisor that does not run hooks in
  # the child), every pre-start stage runs before the gate, in OCI order.
  def test_every_stage_runs_in_order_with_its_status
    rt = runtime
    stages = %w[poststop poststart startContainer createContainer createRuntime prestart]
    sandbox, container = start(rt, stages.map { |stage| hook(stage) })
    rt.start_container(container)

    assert_equal ["prestart creating pid /", "createRuntime creating pid /", "createContainer creating pid /",
                  "startContainer created pid /", "poststart running pid /"], log_lines
    bundle = File.join(@dir, "state", "oci-bundles", "#{sandbox}.#{container.id}")
    config = JSON.parse(File.read(File.join(bundle, "config.json")))

    assert_equal ["/bin/true"], config.dig("process", "args")
    assert_equal %w[prestart createRuntime createContainer startContainer poststart poststop], config["hooks"].keys

    rt.stop_container(container)
    rt.remove_container(container)

    assert_equal "poststop stopped nopid /", log_lines.last
    refute_path_exists bundle, "the bundle goes with the container"
    rt.remove_sandbox(sandbox)

    assert_equal 6, log_lines.length, "poststop ran once"
  end

  def test_a_failing_pre_start_hook_fails_the_container
    rt = runtime
    _sandbox, container = start(rt, [hook("createContainer", exit_code: 1, extra: "echo nope;"), hook("poststart")])
    error = assert_raises(Native::FailClosed) { rt.start_container(container) }
    assert_includes error.message, "error running createContainer hook #0: /bin/sh: exit status 1, output: nope"
    assert_equal ["createContainer creating pid /"], log_lines
  end

  def test_poststart_and_poststop_failures_are_warnings
    rt = runtime
    sandbox, container = start(rt, [hook("poststart", exit_code: 2), hook("poststop", exit_code: 2)])
    rt.start_container(container)

    assert_equal "running", rt.container_status(container)["state"]
    rt.stop_sandbox(sandbox)
    rt.remove_sandbox(sandbox)
    warnings = rt.trace.select { |event| event["event"] == "container_hook_warning" }

    assert_equal(%w[poststart poststop], warnings.map { |event| event["stage"] })
  end

  Adapters = Rubernetes::Platform::Linux::NativeAdapters

  # The bootstrap runs in-container hooks itself: a clone3 child, then
  # execve(2), state on stdin, output kept for the error.
  def test_the_bootstrap_hook_runner
    out = File.join(@dir, "child")
    pid = fork do
      runner = Adapters::ContainerHook.new(clone3: nil)
      runner.run({"path" => "/bin/sh", "args" => ["sh", "-c", "cat > #{out}"], "env" => []}, %({"status":"created"}),
                 stage: "startContainer", index: 0)
      begin
        runner.run({"path" => "/bin/sh", "args" => ["sh", "-c", "echo bad; exit 4"], "env" => []}, "{}", stage: "createContainer", index: 2)
      rescue StandardError => error
        File.write("#{out}.error", error.message)
      end
      begin
        runner.run({"path" => "/bin/sh", "args" => ["sh", "-c", "sleep 30"], "env" => [], "timeout" => 1}, "{}", stage: "startContainer",
                                                                                                                 index: 0)
      rescue StandardError => error
        File.write("#{out}.timeout", error.message)
      end
      exit!(0)
    end
    Process.wait(pid)

    assert_equal %({"status":"created"}), File.read(out)
    assert_equal "error running createContainer hook #2: /bin/sh: exit status 4, output: bad", File.read("#{out}.error")
    assert_includes File.read("#{out}.timeout"), "did not finish in 1s"
  end

  # The runtime-namespace stages are requested through the gate: "H" plus
  # the workload's host pid on the readiness pipe, answered on the reply pipe.
  def test_the_gate_answers_runtime_hook_requests
    bootstrap = Adapters::WorkloadBootstrap.allocate
    gate_reader, gate_writer = IO.pipe
    status_reader, status_writer = IO.pipe
    identity_reader, identity_writer = IO.pipe
    reply_reader, reply_writer = IO.pipe
    bootstrap.instance_variable_set(:@status, status_writer)
    bootstrap.instance_variable_set(:@hook_reply, reply_reader)
    bootstrap.instance_variable_set(:@hooks, {})
    bootstrap.instance_variable_set(:@host_pid, 4242)
    seen = []
    failing = false
    gate = Adapters::ProcessGateAdapter::Gate.new(writer: gate_writer, status_reader: status_reader, identity_reader: identity_reader,
                                                  hook_reply: reply_writer,
                                                  hook_handler: lambda { |pid|
                                                    seen << pid
                                                    raise "createRuntime broke" if failing
                                                  })
    child = Thread.new do
      gate_reader.read(1)
      bootstrap.send(:request_runtime_hooks)
      failing = true
      begin
        bootstrap.send(:request_runtime_hooks)
      rescue StandardError => error
        status_writer.write("E#{error.message}")
      end
      status_writer.close
    end
    error = assert_raises(Rubernetes::Platform::Linux::NativeAdapters::EffectError) { gate.release }
    child.join

    assert_equal [4242, 4242], seen
    assert_includes error.message, "createRuntime broke"
  ensure
    [gate_reader, identity_writer, reply_reader].each { |io| io.close unless io.nil? || io.closed? }
  end
end
