# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux"
# Rubernetes::LinuxNative comes from the C extension, and only requiring
# rubernetes/platform/linux happens to load it as a side effect.  The bounds
# check below asserted against a constant that was not defined under the
# Rakefile's load path, so it failed with NameError instead of testing the
# shim -- the bound it exists to pin was never actually verified.
require "rubernetes_linux"

class NamespaceProcessTest < Minitest::Test
  def test_namespace_process_rejects_flags_that_could_modify_the_parent_mount_namespace
    error = assert_raises(ArgumentError) do
      Rubernetes::Platform::Linux::NamespaceProcess.new.spawn(
        command: ["/bin/true"],
        output_fd: -1,
        flags: Rubernetes::Platform::Linux::Clone3::CLONE_PIDFD,
        resource_id: "sandbox:unsafe-flags"
      )
    end

    assert_match(/CLONE_PIDFD \| CLONE_NEWNS \| CLONE_NEWPID/, error.message)
  end

  def test_native_shim_repeats_the_flag_check_at_the_trust_boundary
    error = assert_raises(ArgumentError) do
      Rubernetes::LinuxNative.clone3_exec(
        Rubernetes::Platform::Linux::Clone3::CLONE_PIDFD,
        ["/bin/true"],
        "/proc",
        -1
      )
    end

    assert_match(/flags must be exactly/, error.message)
  end

  def test_native_shim_bounds_argument_pointer_storage
    error = assert_raises(ArgumentError) do
      Rubernetes::LinuxNative.clone3_exec(
        Rubernetes::Platform::Linux::Clone3::NAMESPACE_FLAGS,
        Array.new(4097, "/bin/true"),
        "/proc",
        -1
      )
    end

    assert_match(/between 1 and 4096 entries/, error.message)
  end
end
