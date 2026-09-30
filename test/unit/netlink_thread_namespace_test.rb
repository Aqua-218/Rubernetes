# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# Namespaced netlink calls used to fork the agent for every call: the child
# entered the Pod's network namespace, ran the request, and marshalled the
# answer back.  Forking a multi-GB agent copies its page tables and stalls
# every other thread on the mm lock, and a Pod attach needed about seven such
# forks; network readiness took seconds.  setns(CLONE_NEWNET) acts on the
# calling native thread only, so the thread now enters the namespace itself,
# runs the request there, and returns to the host namespace before going on.
class NetlinkThreadNamespaceTest < Minitest::Test
  Netlink = Rubernetes::Network::Netlink

  def setup
    skip "needs root and unshare(1)" unless Process.uid.zero? && File.executable?("/usr/bin/unshare")
    @holder = Process.spawn("/usr/bin/unshare", "-n", "sleep", "30", out: File::NULL, err: File::NULL)
    # unshare(1) needs a moment to create the namespace before we open it.
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2.0
    loop do
      break if File.readlink("/proc/#{@holder}/ns/net") != File.readlink("/proc/self/ns/net")

      flunk "unshare did not create a namespace" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
    end
    @namespace = File.open("/proc/#{@holder}/ns/net", File::RDONLY)
  end

  def teardown
    @namespace&.close
    return unless @holder

    begin
      Process.kill("KILL", @holder)
    rescue StandardError
      nil
    end
    begin
      Process.wait(@holder)
    rescue StandardError
      nil
    end
  end

  def link_names(messages)
    messages.filter_map do |message|
      attributes = Netlink::TLV.decode(message.payload.byteslice(16..))
      attributes.find { |attribute| attribute.fetch("type") == Netlink::IFLA_IFNAME }&.fetch("value")&.delete("\0")
    end
  end

  def test_the_calling_thread_enters_the_namespace_and_comes_back
    netlink = Netlink.new
    host_before = File.readlink("/proc/thread-self/ns/net")
    inside = nil
    names = link_names(netlink.link_dump(namespace_fd: @namespace.fileno))
    netlink.with_namespace(@namespace.fileno) { inside = File.readlink("/proc/thread-self/ns/net") }

    assert_equal ["lo"], names, "a fresh namespace holds only lo"
    assert_equal File.readlink("/proc/#{@holder}/ns/net"), inside
    assert_equal host_before, File.readlink("/proc/thread-self/ns/net")
    assert_includes link_names(netlink.link_dump), "lo"
    assert_operator link_names(netlink.link_dump).length, :>, 1, "the host has more than lo"
    refute Thread.current[Netlink::NAMESPACE_TAINT_KEY]
  end

  # The observer stamps every resource with the inode of the namespace it was
  # seen in.  /proc/self/ns/net names the process's (host) namespace even
  # from a thread that has entered a Pod's; /proc/thread-self/ns/net is the
  # thread's own, and is what the fork used to see as its /proc/self.
  def test_resources_observed_inside_a_namespace_carry_that_namespace_inode
    observer = Rubernetes::Network::NativeObserver.new(netlink: Netlink.new)
    pod_inode = File.stat("/proc/#{@holder}/ns/net").ino
    host_inode = File.stat("/proc/self/ns/net").ino

    refute_equal host_inode, pod_inode
    inside = observer.resources(namespace_fd: @namespace.fileno, kinds: %w[link])

    refute_empty inside
    assert inside.all? { |resource| resource.dig("metadata", "netns_inode") == pod_inode }, inside.first.inspect
    outside = observer.resources(kinds: %w[link])

    assert(outside.all? { |resource| resource.dig("metadata", "netns_inode") == host_inode })
  end

  def test_other_threads_never_see_the_switch
    netlink = Netlink.new
    host = File.readlink("/proc/thread-self/ns/net")
    observed = Queue.new
    entered = Queue.new
    worker = Thread.new do
      netlink.with_namespace(@namespace.fileno) do
        entered << true
        sleep 0.05
      end
    end
    entered.pop
    observed << File.readlink("/proc/thread-self/ns/net")
    worker.join

    assert_equal host, observed.pop
  end

  def test_a_failed_return_taints_the_thread
    netlink = Netlink.new
    real = netlink.send(:setns_function)
    calls = 0
    failing = lambda do |fd, flags|
      calls += 1
      calls == 2 ? -1 : real.call(fd, flags)
    end
    tainted = Thread.new do
      netlink.instance_variable_set(:@setns_function, failing)
      error = assert_raises(Rubernetes::Network::NetlinkError) { netlink.with_namespace(@namespace.fileno) { :ok } }
      assert_match(/return to the host network namespace/, error.message)
      assert Thread.current[Netlink::NAMESPACE_TAINT_KEY]
      # Still inside the Pod namespace: the thread refuses further work.
      netlink.instance_variable_set(:@setns_function, nil)
      again = assert_raises(Rubernetes::Network::NetlinkError) { netlink.with_namespace(@namespace.fileno) { :ok } }
      assert_match(/refusing/, again.message)
      # Leave the namespace for real so the test process stays sane.
      netlink.send(:enter_namespace, File.open("/proc/#{Process.pid}/ns/net", File::RDONLY).fileno, "test")
    end
    tainted.join
  end
end
