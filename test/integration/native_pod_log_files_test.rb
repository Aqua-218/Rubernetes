# frozen_string_literal: true

require "tmpdir"
require "timeout"
require_relative "../test_helper"
require "rubernetes/runtime/native"
require "rubernetes/runtime/native/pod_log_files"

class NativePodLogFilesTest < Minitest::Test
  Native = Rubernetes::Runtime::Native
  Supervisor = Rubernetes::Platform::Linux::ProcessSupervisor

  def test_log_paths_rotate_and_keep_the_current_and_previous_attempts
    with_runtime do |root, runtime, sandbox|
      pods = File.join(root, "pods")
      legacy = File.join(root, "containers")
      folder = File.join(pods, "default_p_uid", "app")
      first = start_attempt(runtime, sandbox, "one")
      log = File.join(folder, "0.log")
      first_link = File.join(legacy, "p_default_app-#{first}.log")

      assert_equal log, File.readlink(first_link)
      assert_match(/ stdout F one\n/, File.binread("#{log}.1"))
      assert_match(/ stderr F one-diagnostic\n/, File.binread(first_link))
      assert(Dir.glob("#{log}*").all? { |path| File.size(path) <= 256 })

      second = start_attempt(runtime, sandbox, "two")
      runtime.retire_container(first)

      assert_includes runtime.logs(first, sandbox_id: sandbox), "one-diagnostic"
      assert_path_exists File.join(folder, "1.log")

      third = start_attempt(runtime, sandbox, "three")
      runtime.retire_container(second, previous_id: first)

      assert_includes runtime.logs(second, sandbox_id: sandbox), "two-diagnostic"
      assert_includes runtime.logs(third, sandbox_id: sandbox), "three-diagnostic"
      refute_path_exists first_link
      assert_equal %w[1.log 1.log.1 2.log 2.log.1], Dir.children(folder).sort

      runtime.remove_sandbox(sandbox)

      assert_empty Dir.children(pods)
      assert_empty Dir.children(legacy)
    end
  end

  def test_existing_follow_and_attach_cross_the_first_stderr_write
    with_runtime do |root, runtime, sandbox|
      initial = (("x" * 31) + "\n") * 10
      code = <<~'RUBY'
        STDOUT.sync = true
        STDOUT.write(ARGV.fetch(0))
        STDIN.readline
        STDERR.write("stderr\n")
        STDIN.readline
        STDOUT.write("stdout\n")
      RUBY
      container = runtime.create_container(sandbox, {"name" => "app", "stdin" => true,
                                                     "command" => [RbConfig.ruby, "-e", code, initial]})
      runtime.start_container(container)
      wait_for_log(runtime, container, initial)

      directory = process_directory(root, sandbox, container)

      refute_path_exists File.join(directory, "container.log")
      refute_path_exists File.join(directory, "combined")
      assert_equal initial, recovered_logs(root, container, sandbox)

      follow = runtime.logs(container, follow: true, tail: 1, timestamps: true).each
      first = next_log(follow)
      stamp, text = first.split(" ", 2)

      assert_operator Time.iso8601(stamp), :<=, Time.now.utc
      assert_equal initial.lines.last, text

      attachment = runtime.attach(container, stdin: true, stdout: true, stderr: true)
      staging = File.join(directory, "combined.pending")
      Dir.mkdir(staging)
      File.write(File.join(staging, "container.log"), "interrupted copy")
      since = Time.now.utc
      attachment.fetch(:stdin).write("\n")

      assert_equal "stderr\n", next_log(attachment.fetch(:stderr).each)
      assert_match(/\A\S+ stderr\n\z/, next_log(follow))
      assert_equal "stderr\n", runtime.logs(container, since: since)
      refute_path_exists staging
      assert File.identical?(File.join(directory, "stdout.log.1"), File.join(directory, "combined", "container.log.1"))
      refute File.identical?(File.join(directory, "stdout.log"), File.join(directory, "combined", "container.log"))

      attachment.fetch(:stdin).write("\n")

      assert_equal 0, runtime.wait_container(container, timeout: 5).fetch("exitCode")
      assert_equal "stdout\n", next_log(attachment.fetch(:stdout).each)
      assert_match(/\A\S+ stdout\n\z/, next_log(follow))
      assert_equal initial + "stdout\n", runtime.logs(container, stream: :stdout)
      assert_equal initial + "stderr\nstdout\n", recovered_logs(root, container, sandbox)
    end
  end

  def test_stdin_once_delivers_eof_and_persistent_stdin_survives_an_attach_close
    with_runtime do |_, runtime, sandbox|
      service = Rubernetes::Node::AttachService.new(runtime: runtime, trusted: true)
      command = [RbConfig.ruby, "-e", 'STDOUT.sync = true; STDIN.each_line { |line| STDOUT.write(line); break if line == "stop\n" }; puts "done"']
      once = runtime.create_container(sandbox, {"name" => "once", "command" => command, "stdin" => true, "stdinOnce" => true})
      runtime.start_container(once)
      first = service.attach(once.id, stdin: true)
      first.write("hello\n")
      first.close_write

      assert_equal 0, runtime.wait_container(once, timeout: 2).fetch("exitCode"), "the child must exit after the attachment's stdin EOF"
      assert_equal "hello\ndone\n", runtime.logs(once)

      persistent = runtime.create_container(sandbox, {"name" => "persistent", "command" => command, "stdin" => true})
      runtime.start_container(persistent)
      second = service.attach(persistent.id, stdin: true)
      second.write("hello\n")
      second.close_write
      wait_for_log(runtime, persistent, "hello\n")
      Timeout.timeout(2) do
        loop { break if second.read(4096).nil? }
      end
      second.close
      third = service.attach(persistent.id, stdin: true)
      third.write("stop\n")
      third.close

      assert_equal 0, runtime.wait_container(persistent, timeout: 2).fetch("exitCode")
      assert_equal "hello\nstop\ndone\n", runtime.logs(persistent)
    end
  end

  def test_unavailable_cri_directory_keeps_stdout_stderr_and_combined_raw_logs
    with_runtime do |root, runtime, sandbox|
      code = "STDIN.readline; warn 'stderr'; STDOUT.write(\"stdout\\n\")"
      container = runtime.create_container(sandbox, {"name" => "app", "stdin" => true,
                                                     "command" => [RbConfig.ruby, "-e", code]})
      runtime.start_container(container)
      pods = File.join(root, "pods")
      File.rename(pods, "#{pods}.offline")
      runtime.attach(container, stdin: true, stdout: false).fetch(:stdin).write("\n")

      assert_equal 0, runtime.wait_container(container, timeout: 5).fetch("exitCode")
      assert_equal "stdout\n", runtime.logs(container, stream: :stdout)
      assert_equal "stderr\n", runtime.logs(container, stream: :stderr)
      assert_equal %W[stderr\n stdout\n], runtime.logs(container).lines.sort
      assert_equal runtime.logs(container), recovered_logs(root, container, sandbox)
    ensure
      File.rename("#{pods}.offline", pods) if pods && File.directory?("#{pods}.offline")
    end
  end

  def test_interrupted_promotion_retries_in_order_after_the_process_exits
    with_runtime do |root, runtime, sandbox|
      code = <<~RUBY
        STDOUT.sync = true
        puts "before"
        STDIN.readline
        warn "pending"
        STDIN.readline
        puts "after-stdout"
        warn "after-stderr"
      RUBY
      container = runtime.create_container(sandbox, {"name" => "app", "stdin" => true,
                                                     "command" => [RbConfig.ruby, "-e", code]})
      runtime.start_container(container)
      wait_for_log(runtime, container, "before\n")
      follow = runtime.logs(container, follow: true).each
      input = runtime.attach(container, stdin: true, stdout: false).fetch(:stdin)
      original = runtime.sandbox(sandbox).container_if_present(container.id).process
      directory = process_directory(root, sandbox, container)
      cri_path = File.join(root, "pods", "default_p_uid", "app", "0.log")
      rename = File.method(:rename)
      unavailable = true
      attempts = 0
      promote = lambda do |from, to|
        if unavailable && from == File.join(directory, "combined.pending")
          attempts += 1
          raise Errno::ENOSPC, to
        end
        rename.call(from, to)
      end

      assert_equal "before\n", next_log(follow)
      File.stub(:rename, promote) do
        input.write("\n")
        Timeout.timeout(5) { sleep 0.01 until runtime.logs(container, stream: :stderr) == "pending\n" }

        assert_includes File.binread(cri_path), " stderr F pending\n"
        assert_equal "before\n", runtime.logs(container)
        refute_path_exists File.join(directory, "combined")

        input.write("\n")

        assert_equal 0, runtime.wait_container(container, timeout: 5).fetch("exitCode")
        assert_predicate original.stdout, :closed?
        assert_predicate original.stderr, :closed?
        retained = original.combined_log.retained_handle

        unavailable = false
        tail = "pending\nafter-stdout\nafter-stderr\n"

        assert_equal "before\n" + tail, runtime.logs(container)
        assert_equal tail, next_log(follow)
        assert_raises(StopIteration) { next_log(follow) }
        assert_equal "before\n" + tail, recovered_logs(root, container, sandbox)
        assert_equal "before\nafter-stdout\n", runtime.logs(container, stream: :stdout)
        assert_equal "pending\nafter-stderr\n", runtime.logs(container, stream: :stderr)
        lines = File.readlines(cri_path).map { |line| line.split.last }

        assert_equal %w[before pending after-stdout after-stderr], lines
        assert_operator attempts, :>=, 2
        assert_predicate retained.stdout, :closed?
        assert_predicate retained.stderr, :closed?
      end
    end
  end

  def test_adopted_process_continues_the_existing_single_stream
    with_runtime do |root, runtime, sandbox|
      code = 'STDERR.puts("before"); STDIN.readline; STDERR.puts("after"); STDIN.readline'
      container = runtime.create_container(sandbox, {"name" => "app", "stdin" => true,
                                                     "command" => [RbConfig.ruby, "-e", code]})
      runtime.start_container(container)
      wait_for_log(runtime, container, "before\n")

      process = runtime.sandbox(sandbox).container_if_present(container.id).process
      durable = Rubernetes::Platform::Linux::DurableProcess
      evidence = durable.capture(Process.pid, {"stdin" => process.stdin, "stdout" => process.stdout, "stderr" => process.stderr})
      digest = Digest::SHA256.file("/proc/#{process.pid}/exe").hexdigest
      metadata = {id: process.id, pid: Process.pid, workload_pid: process.pid, workload_start_time: durable.birth(process.pid),
                  workload_executable_digest: "sha256:#{digest}", durable: evidence}
      supervisor = new_supervisor(root)
      adopted = supervisor.adopt(metadata: metadata)
      adopted.stdin.sync = true
      adopted.stdin.write("\n")

      Timeout.timeout(5) { sleep 0.01 until supervisor.logs(adopted, stream: :all) == "before\nafter\n" }
      directory = process_directory(root, sandbox, container)

      assert_equal "before\nafter\n", File.binread(File.join(directory, "stderr.log"))
      refute_path_exists File.join(directory, "container.log")
      refute_path_exists File.join(directory, "combined")

      adopted.stdin.write("\n")

      assert_equal 0, runtime.wait_container(container, timeout: 5).fetch("exitCode")
    ensure
      supervisor&.close(adopted) if adopted
    end
  end

  def test_durable_recovery_keeps_output_when_stdin_once_has_closed
    durable = Rubernetes::Platform::Linux::DurableProcess
    input_reader, input_writer = IO.pipe
    output_reader, output_writer = IO.pipe
    evidence = durable.capture(Process.pid, {"stdin" => input_writer, "stdout" => output_reader})
    open = durable.reopen(Process.pid, evidence.merge("stdin_once" => true))

    assert_predicate open.fetch(:stdin).stat, :pipe?

    open.each_value(&:close)
    input_writer.close
    assert_raises(Errno::ENOENT) { durable.reopen(Process.pid, evidence) }

    recovered = durable.reopen(Process.pid, evidence.merge("stdin_once" => true))
    output_writer.write("after EOF")

    refute recovered.key?(:stdin)
    assert_equal "after EOF", recovered.fetch(:stdout).readpartial(64)
  ensure
    [input_reader, input_writer, output_reader, output_writer, *recovered&.values].compact.each(&:close)
  end

  def test_new_host_reader_preserves_existing_raw_only_attempts
    with_runtime(install_logs: false) do |root, runtime, sandbox|
      attempt = start_attempt(runtime, sandbox, "legacy")
      process = "process-#{sandbox}-#{attempt}"

      assert_equal runtime.logs(attempt), new_supervisor(root).logs(process, stream: :all)
      assert_path_exists File.join(root, "private", process, "container.log")
    end
  end

  private

  def with_runtime(install_logs: true)
    Dir.mktmpdir("native-pod-log-files") do |root|
      runtime = Native.new(profile: :pure, process_adapter: Supervisor::ForkAdapter.new,
                           sandbox_root: File.join(root, "runtime"), log_root: File.join(root, "private"),
                           journal_path: File.join(root, "ledger"), max_log_bytes: 256, max_log_files: 2)
      Native::PodLogFiles.install(runtime, pod_root: File.join(root, "pods"), legacy_root: File.join(root, "containers")) if install_logs
      sandbox = runtime.run_sandbox({"metadata" => {"namespace" => "default", "name" => "p", "uid" => "uid"}}, id: "sandbox")
      yield root, runtime, sandbox
    ensure
      runtime&.remove_sandbox(sandbox) if sandbox
    end
  end

  def process_directory(root, sandbox, container)
    File.join(root, "private", "process-#{sandbox}-#{container.id}")
  end

  def recovered_logs(root, container, sandbox)
    new_supervisor(root).logs(File.basename(process_directory(root, sandbox, container)), stream: :all)
  end

  def new_supervisor(root)
    spool = File.join(root, "private")
    supervisor = Supervisor.new(log_directory: spool, max_log_bytes: 256, max_log_files: 2)
    supervisor.extend(Native::PodLogFiles::ProcessHooks).pod_log_files = Native::PodLogFiles.new(
      spool, max_bytes: 256, max_files: 2, pod_root: File.join(root, "pods"), legacy_root: File.join(root, "containers")
    )
    supervisor
  end

  def wait_for_log(runtime, container, expected)
    Timeout.timeout(5) do
      sleep 0.01 until runtime.logs(container) == expected
    end
  end

  def next_log(stream)
    Timeout.timeout(5) { stream.next }
  end

  def start_attempt(runtime, sandbox, text)
    command = [RbConfig.ruby, "-e", "6.times { puts ARGV.fetch(0) }; warn ARGV.fetch(0) + '-diagnostic'", text]
    container = runtime.create_container(sandbox, {"name" => "app", "command" => command})
    runtime.start_container(container)

    assert_equal 0, runtime.wait_container(container, timeout: 5).fetch("exitCode")

    container.id
  end
end
