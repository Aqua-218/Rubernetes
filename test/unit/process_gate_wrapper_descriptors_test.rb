# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/native_adapters"

# The workload wrapper is a forked copy of the agent that lives as long as its
# container, so every pipe the agent had open at fork time -- other
# containers' stdio, every exec in flight -- stayed open in it, and their
# readers never saw EOF: "kubectl exec ss-2 -- mv ..." hung for 24 hours behind
# the wrapper of the very container it targeted.  The wrapper now closes every
# inherited pipe, socket and anonymous inode it was not handed.
class ProcessGateWrapperDescriptorsTest < Minitest::Test
  Adapter = Rubernetes::Platform::Linux::NativeAdapters::ProcessGateAdapter

  def test_inherited_pipes_are_closed_and_kept_ones_survive
    adapter = Adapter.allocate
    unrelated_reader, unrelated_writer = IO.pipe
    kept_reader, kept_writer = IO.pipe
    log = Tempfile.new("wrapper-log")
    pid = Process.fork do
      adapter.send(:close_inherited_descriptors, keep: [kept_writer])
      kept_writer.write(log.closed? ? "closed" : "ok")
      kept_writer.flush
      exit!(0)
    end
    unrelated_writer.close

    ready = unrelated_reader.wait_readable(2.0)

    refute_nil ready, "the child must have closed its copy of the unrelated pipe"
    assert_nil unrelated_reader.read(1), "EOF: nobody else holds the write end"
    kept_writer.close

    assert_equal "ok", kept_reader.read, "kept descriptors and regular files stay open"
  ensure
    Process.wait(pid) if pid
    log&.close!
  end
end

# The wrapper and its workload child are forks of the agent; a GC in them
# copies the whole heap into the container's memory cgroup.  The fork
# disables GC before the parent returns (and so before the cgroup attach).
class ProcessGateForkWithoutGCTest < Minitest::Test
  Adapter = Rubernetes::Platform::Linux::NativeAdapters::ProcessGateAdapter

  def test_the_child_runs_with_gc_disabled
    reader, writer = IO.pipe
    pid = Adapter.allocate.send(:fork_without_gc) do
      reader.close
      writer.write(GC.enable ? "disabled" : "enabled") # GC.enable returns the previous "disabled" state
      writer.close
      exit!(0)
    end
    writer.close

    assert_equal "disabled", reader.read
    refute GC.disable.tap { GC.enable }, "the parent's GC is untouched"
  ensure
    Process.wait(pid) if pid
  end
end
