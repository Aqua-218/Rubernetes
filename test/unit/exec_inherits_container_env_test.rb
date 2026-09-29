# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux"

# CRI exec (runc exec) runs a command with the container's own process
# environment.  The exec session was spawned with an empty environment, so
# kubectl exec and exec probes alike ran without the Pod's env vars, PATH
# included.  "[sig-apps] Job should allow to use a pod failure policy to
# ignore failure matching on DisruptionTarget condition" probes readiness with
# `cat /data/foo-$JOB_COMPLETION_INDEX`; it read /data/foo-, never succeeded,
# and the Job's Pods never became Ready (900 s timeout, every round).
class ExecInheritsContainerEnvTest < Minitest::Test
  Connector = Rubernetes::Platform::Linux::NativeAdapters::NamespaceConnector

  Container = Struct.new(:process, :spec, :cgroup, :security_plan, keyword_init: true)
  Sandbox = Struct.new(:namespace, keyword_init: true)
  WorkloadProcess = Struct.new(:workload_pid, :workload_start_time)

  class RecordingProcess
    attr_reader :spawned

    def spawn(**options)
      @spawned = options
      raise StopIteration # enough: the spawn arguments are what is under test
    end
  end

  def connector_with(process)
    subject = Connector.allocate
    subject.instance_variable_set(:@process, process)
    subject
  end

  def container(env)
    Container.new(process: WorkloadProcess.new(4242, "123"),
                  spec: {"cwd" => "/work", "env" => env}, cgroup: nil, security_plan: nil)
  end

  def exec_capturing(env)
    process = RecordingProcess.new
    subject = connector_with(process)
    begin
      subject.exec(sandbox: Sandbox.new(namespace: nil), container: container(env), command: %w[sh -c true])
    rescue StopIteration
      nil
    end
    process.spawned
  end

  def test_an_exec_session_receives_the_containers_environment
    spawned = exec_capturing("JOB_COMPLETION_INDEX" => "2", "PATH" => "/usr/bin:/bin")

    assert_equal({"JOB_COMPLETION_INDEX" => "2", "PATH" => "/usr/bin:/bin"}, spawned.fetch(:env))
  end

  def test_an_exec_session_runs_in_the_containers_working_directory
    assert_equal "/work", exec_capturing({}).fetch(:cwd)
  end

  def test_a_container_without_env_execs_with_an_empty_one
    assert_equal({}, exec_capturing(nil).fetch(:env))
  end
end
