# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/native"
require "rubernetes/platform/linux/native_adapters"

# runc fixStdioPermissions: a non-root container must be able to re-open its own
# stdout/stderr through /dev/stderr (-> /proc/self/fd/2).  The pipes are created
# by the runtime as root; ingress-nginx (uid 101) died with "could not open error
# log file /var/log/nginx/error.log (13: Permission denied)" until their ownership
# moved to the container user before the identity switch.
class NativeNonRootStdioTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux
  SCRIPT = "id -u; ls -lL /proc/self/fd/2; (echo via-stderr > /dev/stderr && echo REOPEN_STDERR_OK) 2>&1; " \
           "(echo via-fd1 > /proc/self/fd/1 && echo REOPEN_FD1_OK) 2>&1"

  def test_a_non_root_container_can_reopen_its_stdio
    skip "needs root and a cgroup v2 root" unless Process.euid.zero? && File.writable?("/sys/fs/cgroup/cgroup.procs")

    with_runtime do |runtime, sandbox, lower|
      container = runtime.create_container(sandbox, {"id" => "main", "rootfs_path" => lower,
                                                     "command" => ["/bin/busybox", "sh", "-c", SCRIPT],
                                                     "security_context" => {"run_as_user" => 101, "run_as_group" => 101,
                                                                            "allow_privilege_escalation" => false}})
      runtime.start_container(container)
      lines = output_lines(runtime, container, 5)

      assert_equal "101", lines.first, lines.inspect
      assert_match(/\A[p-].*\s101\s+101\s/, lines[1], "the stdio pipe is owned by the container user: #{lines[1]}")
      assert_includes lines, "REOPEN_STDERR_OK", lines.inspect
      assert_includes lines, "REOPEN_FD1_OK", lines.inspect
    end
  end

  # execveat(2) of a "#!" script through a close-on-exec descriptor fails with
  # ENOENT; an image entrypoint that is a shell script never started.
  def test_a_shell_script_entrypoint_starts_directly
    skip "needs root and a cgroup v2 root" unless Process.euid.zero? && File.writable?("/sys/fs/cgroup/cgroup.procs")

    with_runtime do |runtime, sandbox, lower|
      File.write(File.join(lower, "bin", "hello.sh"), "#!/bin/busybox sh\necho SCRIPT_RAN \"$0\" \"$@\"\n")
      File.chmod(0o755, File.join(lower, "bin", "hello.sh"))
      container = runtime.create_container(sandbox, {"id" => "script", "rootfs_path" => lower,
                                                     "command" => ["/bin/hello.sh", "arg1"],
                                                     "security_context" => {"run_as_user" => 101, "run_as_group" => 101,
                                                                            "allow_privilege_escalation" => false}})
      runtime.start_container(container)
      lines = output_lines(runtime, container, 1)

      assert_match(/\ASCRIPT_RAN .*hello\.sh arg1\z/, lines.first, lines.inspect)
    end
  end

  private

  def with_runtime
    Dir.mktmpdir("rubernetes-native-stdio-") do |directory|
      lower = File.join(directory, "lower")
      FileUtils.mkdir_p(File.join(lower, "bin"))
      FileUtils.cp("/usr/bin/busybox", File.join(lower, "bin", "busybox"), preserve: true)
      sandbox_root = File.join(directory, "sandboxes")
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true,
        adapters: Linux::NativeAdapters.for_profile(profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup"),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup", log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      sandbox_id = "stdio-#{Process.pid}-#{SecureRandom.hex(4)}"
      image_bytes = "stdio-image"
      sandbox = runtime.run_sandbox(
        {"id" => sandbox_id, "image_bytes" => image_bytes,
         "image_digest" => "sha256:#{Digest::SHA256.hexdigest(image_bytes)}", "lowerdirs" => [lower]},
        request_id: sandbox_id
      )
      begin
        yield runtime, sandbox, lower
      ensure
        begin
          runtime.stop_sandbox(sandbox, timeout: 1) if runtime.sandboxes.any?
          runtime.remove_sandbox(sandbox) if runtime.sandboxes.any?
        rescue StandardError
          nil
        end
      end
    end
  end

  def output_lines(runtime, container, count)
    Timeout.timeout(15) do
      text = +""
      text = runtime.logs(container).to_s until text.lines.length >= count || (sleep(0.1) && false)
      text.lines(chomp: true)
    end
  end
end
