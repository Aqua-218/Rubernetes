# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeWorkerTest < Minitest::Test
  def test_one_pod_worker_serializes_direct_calls
    started = Queue.new
    release = Queue.new
    active = 0
    maximum = 0
    mutex = Mutex.new
    worker = Rubernetes::Node::PodWorker.new("pod-1", auto_start: false) do |_pod|
      mutex.synchronize do
        active += 1
        maximum = [maximum, active].max
      end
      started << true
      release.pop
      mutex.synchronize { active -= 1 }
      :ok
    end
    first = Thread.new { worker.process({"metadata" => {"name" => "pod"}}) }
    started.pop
    second = Thread.new { worker.process({"metadata" => {"name" => "pod"}}) }
    sleep 0.01

    assert_equal 1, maximum
    release << true
    started.pop
    release << true
    [first, second].each(&:join)

    assert_equal 1, maximum
    assert_equal 2, worker.processed
  end

  def test_different_pods_run_in_parallel
    started = Queue.new
    release = Queue.new
    mutex = Mutex.new
    active = 0
    maximum = 0
    pool = Rubernetes::Node::PodWorkerPool.new do |_pod|
      mutex.synchronize do
        active += 1
        maximum = [maximum, active].max
      end
      started << true
      release.pop
      mutex.synchronize { active -= 1 }
    end
    pool.enqueue({"metadata" => {"uid" => "pod-a", "name" => "a"}})
    pool.enqueue({"metadata" => {"uid" => "pod-b", "name" => "b"}})
    2.times { started.pop }

    assert_equal 2, maximum
    2.times { release << true }

    assert pool.drain(timeout: 1)
    pool.stop
  end
end
