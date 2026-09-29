# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/process_supervisor"
require "tmpdir"

class NativeRuntimeHostTest < Minitest::Test
  Supervisor = Rubernetes::Platform::Linux::ProcessSupervisor

  def test_host_process_gate_pid_identity_and_binary_logs
    Dir.mktmpdir("rubernetes-native-host-") do |directory|
      supervisor = Supervisor.new(log_directory: directory)
      handle = supervisor.spawn(command: ["/bin/sh", "-c", "printf out; printf err >&2"], id: "host-process")

      refute_nil(handle.pid)
      supervisor.release_gate(handle)
      result = supervisor.wait(handle, timeout: 5.0)

      assert_equal(0, result.exit_status)
      assert_equal("out", supervisor.logs(handle))
      assert_equal("err", supervisor.logs(handle, stream: :stderr))
      supervisor.close(handle)
    end
  end

  def test_log_rotation_preserves_bytes_and_file_bound
    Dir.mktmpdir("rubernetes-native-log-") do |directory|
      log = Supervisor::LogRotator.new(path: File.join(directory, "stdout.log"), max_bytes: 4, max_files: 2)
      log.append("\x00\xffab".b)
      log.append("cd".b)

      assert_equal("\x00\xffabcd".b, log.read)
      assert_operator(File.size(File.join(directory, "stdout.log")), :<=, 4)
      assert_operator(File.size(File.join(directory, "stdout.log.1")), :<=, 4)
    end
  end
end
