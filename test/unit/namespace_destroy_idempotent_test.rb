# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/native_adapters"

# Teardown is retried until it succeeds, and a retry that still held the same
# Handle closed its pidfd a SECOND time.  By then the kernel had handed that
# descriptor number to something else -- usually glibc's netlink socket, which
# answers EBADF by aborting the process ("Unexpected error 9 on netlink
# descriptor 67") -- so the node agent died mid-run and took every Pod on the
# node with it.  Ownership of the pidfd is now taken exactly once.
class NamespaceDestroyIdempotentTest < Minitest::Test
  Adapter = Rubernetes::Platform::Linux::NativeAdapters::NamespaceAdapter

  class RecordingPidfd
    attr_reader :signals

    def initialize = @signals = []

    def send_signal(pidfd:, signal:, resource_id:) = @signals << [pidfd, signal]
  end

  def adapter_with(handle)
    adapter = Adapter.allocate
    adapter.instance_variable_set(:@mutex, Mutex.new)
    adapter.instance_variable_set(:@handles, {handle.id => handle})
    adapter.instance_variable_set(:@pidfd, RecordingPidfd.new)
    closed = []
    adapter.define_singleton_method(:close_fd) { |fd| closed << fd }
    adapter.define_singleton_method(:wait_for_exit) { |*_args, **_kw| true }
    adapter.define_singleton_method(:reap_supervisor) { |_pid| true }
    [adapter, closed]
  end

  def handle
    members = Adapter::Handle.members
    values = members.to_h { |name| [name, nil] }
    values.merge!(id: "ns-1", identity: "ident-1", pid: 4242, pidfd: 77, supervisor_pid: 4242,
                  namespaces: [], namespace_links: {})
    Adapter::Handle.new(**values)
  end

  def test_the_pidfd_is_closed_once_across_repeated_destroys
    value = handle
    adapter, closed = adapter_with(value)

    3.times { assert(adapter.destroy(handle: value, id: "ns-1", identity: "ident-1")) }

    assert_equal([77], closed)
  end

  def test_destroying_by_id_after_the_handle_is_gone_succeeds
    value = handle
    adapter, closed = adapter_with(value)
    adapter.destroy(handle: value, id: "ns-1", identity: "ident-1")

    assert(adapter.destroy(handle: "ns-1", id: "ns-1", identity: "ident-1"))
    assert_equal([77], closed)
  end
end
