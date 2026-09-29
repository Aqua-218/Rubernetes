# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes_linux"

class NativeExtensionTest < Minitest::Test
  def test_native_boundary_exports_only_the_clone_exec_shim
    assert_equal([:clone3_exec], Rubernetes::LinuxNative.singleton_methods(false).sort)
  end
end
