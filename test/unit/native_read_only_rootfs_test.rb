# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime"

# securityContext.readOnlyRootFilesystem is a CONTAINER-level field and the
# workspace mount is what enforces it.  The runtime read it only from the top
# of the container spec, so a Pod that asked for a read-only root got a
# writable one -- "[sig-node] Kubelet when scheduling a read only busybox
# container should not write to root filesystem" writes a file and expects the
# write to be refused.
class NativeReadOnlyRootfsTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def runtime
    @runtime ||= Native.allocate
  end

  def read_only?(input)
    runtime.send(:read_only_root_filesystem?, input)
  end

  def test_the_container_security_context_is_honoured
    assert(read_only?("securityContext" => {"readOnlyRootFilesystem" => true}))
    assert(read_only?("security_context" => {"readOnlyRootFilesystem" => true}))
  end

  def test_a_top_level_flag_is_still_honoured
    assert(read_only?("read_only_root_filesystem" => true))
  end

  def test_a_writable_root_is_the_default
    refute(read_only?("securityContext" => {"runAsUser" => 1000}))
    refute(read_only?({}))
    refute(read_only?("securityContext" => {"readOnlyRootFilesystem" => false}))
  end
end
