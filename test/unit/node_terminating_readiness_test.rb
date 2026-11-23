# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeTerminatingReadinessTest < Minitest::Test
  class Runtime
    attr_reader :calls, :in_prestop, :prestop_release, :readiness_during_prestop

    def initialize
      @calls = []
      @next_id = 0
      @in_prestop = Queue.new
      @prestop_release = Queue.new
      @readiness_during_prestop = Queue.new
    end

    def run_sandbox(_pod, runtime_class: nil)
      ["sandbox", runtime_class]
    end

    def create_container(_sandbox, spec)
      @next_id += 1
      "container-#{@next_id}-#{spec.fetch("name")}"
    end

    def start_container(_id)
      true
    end

    def wait_container(_id)
      {"state" => "running"}
    end

    def exec(id, command, tty: false)
      @calls << [:exec, id, command, tty]
      case command.first
      when "pre-stop"
        @prestop_started = true
        @in_prestop << true
        @prestop_release.pop(timeout: 8)
        0
      when "readiness"
        @readiness_during_prestop << true if @prestop_started
        0
      when "liveness"
        1
      end
    end

    def stop_container(id, timeout:)
      @calls << [:stop, id, timeout]
      true
    end

    def remove_container(_id)
      true
    end

    def remove_sandbox(_id)
      true
    end
  end

  def pod
    {
      "apiVersion" => "v1",
      "kind" => "Pod",
      "metadata" => {"name" => "terminating-readiness", "namespace" => "default", "uid" => "terminating-readiness"},
      "spec" => {
        "restartPolicy" => "Never",
        "terminationGracePeriodSeconds" => 10,
        "containers" => [{
          "name" => "app",
          "image" => "example/app",
          "livenessProbe" => {"exec" => {"command" => ["liveness"]}, "periodSeconds" => 1, "failureThreshold" => 1},
          "readinessProbe" => {"exec" => {"command" => ["readiness"]}, "periodSeconds" => 1},
          "lifecycle" => {"preStop" => {"exec" => {"command" => ["pre-stop"]}}}
        }]
      }
    }
  end

  def test_liveness_stop_keeps_readiness_probing_during_prestop
    runtime = Runtime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_seconds) {})
    object = pod
    lifecycle.start(object)
    worker = Thread.new { lifecycle.probe(object) }

    assert runtime.in_prestop.pop(timeout: 5), "the liveness failure started preStop"
    assert runtime.readiness_during_prestop.pop(timeout: 5), "readiness ran while preStop was blocked"
    runtime.prestop_release << true
    worker.value

    commands = runtime.calls.filter_map { |call| call[2] if call.first == :exec }

    assert_equal 1, commands.count(["liveness"])
    assert_operator commands.index(["pre-stop"]), :<, commands.rindex(["readiness"])
    assert_equal :stop, runtime.calls.last.first
  ensure
    runtime&.prestop_release&.push(true)
    worker&.join
  end
end
