# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/system_oom_watcher"
require "tempfile"

class SystemOOMWatcherTest < Minitest::Test
  Watcher = Rubernetes::Node::SystemOOMWatcher

  def test_reports_only_system_ooms_and_does_not_replay_a_victim_record
    events = []
    recorder = Object.new
    recorder.define_singleton_method(:record) { |**fields| events << fields }
    node = {"kind" => "Node", "name" => "worker"}
    watcher = Watcher.new(node: node, recorder: recorder, allow_user_namespace: false)
    watcher.observe("6,200,3,-;work invoked oom-killer: gfp_mask=0")
    watcher.observe("6,201,3,-;oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),oom_memcg=/kubepods,task_memcg=/kubepods,task=app,pid=71,uid=0")
    watcher.observe("6,202,3,-;Memory cgroup out of memory: Killed process 71 (app)")
    watcher.observe("6,210,3,-;worker invoked oom-killer: gfp_mask=0")
    watcher.observe("6,211,3,-;oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),global_oom,task_memcg=/,task=web,pid=85,uid=0")
    watcher.observe("6,212,3,-;Out of memory: Killed process 85 (web)")
    watcher.observe("6,213,3,-;Out of memory: Killed process 85 (web)")

    assert_equal [{involved_object: node, type: "Warning", reason: "SystemOOM", namespace: "default",
                   message: "System OOM encountered, victim process: web, pid: 85"}], events
  end

  def test_recognizes_initial_empty_and_subordinate_uid_maps
    Tempfile.create("uid-map") do |map|
      {"0 0 4294967295" => false, "0 100000 65536" => true, "0 0 1" => true, "" => true}.each do |line, expected|
        File.write(map.path, line)

        assert_equal expected, Watcher.user_namespace?(map.path)
      end
    end
  end
end
