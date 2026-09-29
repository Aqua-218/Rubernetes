# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/mount"

# `mount --make-rprivate /` (or rslave) in the INITIAL mount namespace rewrites
# the host's peer groups; the agents' shared Pod root then turns private and
# every later subPath bind becomes invisible to its sandbox.  Holders and
# workloads do this only inside their own namespaces, so the adapter refuses
# it where it would hit the host.
class MountRootPropagationGuardTest < Minitest::Test
  Mount = Rubernetes::Platform::Linux::Mount

  def test_recursive_private_or_slave_on_the_root_is_refused_in_the_initial_namespace
    skip "runs in a private mount namespace already" unless Mount.new.send(:initial_mount_namespace?)

    %i[make_private make_slave].each do |method|
      error = assert_raises(Rubernetes::Platform::Linux::Error) { Mount.new.public_send(method, target: "/", recursive: true) }
      assert_match(/initial mount namespace/, error.message)
    end
  end

  def test_shared_and_non_root_targets_are_not_affected_by_the_guard
    mount = Mount.new
    # Only the guard is exercised: a non-root target reaches the syscall
    # (EINVAL on a non-mount-point directory), never the refusal.
    error = assert_raises(Rubernetes::Platform::Linux::Error) { mount.make_private(target: Dir.mktmpdir, recursive: true) }
    refute_match(/initial mount namespace/, error.message)
  end
end
