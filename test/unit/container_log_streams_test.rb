# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A container's log is BOTH of its streams.  The Pod log API's `stream`
# parameter defaults to "All", and kubelet returns whatever the container
# wrote to either -- the CRI writes one file per container, tags each line
# with the stream it came from, and ReadLogs returns them all.
#
# Serving stdout alone hid every diagnostic a workload writes to stderr:
# "[sig-node] Security Context should run the container as unprivileged when
# false" reads the container's log for the "Operation not permitted" that
# `ip link add` prints on stderr, and read an empty log.
class ContainerLogStreamsTest < Minitest::Test
  Node = Rubernetes::Node

  def service
    Node::LogService.allocate
  end

  def normalize(value)
    service.send(:normalize_log_stream, value)
  end

  def test_no_stream_means_both
    assert_equal(:all, normalize(nil))
    assert_equal(:all, normalize(""))
  end

  def test_all_is_accepted_in_the_api_spelling
    assert_equal(:all, normalize("All"))
    assert_equal(:all, normalize("all"))
  end

  def test_a_single_stream_can_still_be_asked_for
    assert_equal(:stdout, normalize("stdout"))
    assert_equal(:stderr, normalize("stderr"))
  end

  def test_an_unknown_stream_is_refused
    assert_raises(Node::InvalidRequest) { normalize("both") }
  end

  # The runtime's own default has to match, or the node would ask for one
  # stream even when the caller asked for none.
  def test_the_runtime_defaults_to_both_streams
    parameters = Rubernetes::Runtime::Native.instance_method(:logs).parameters
    stream = parameters.find { |(kind, name)| kind == :key && name == :stream }

    refute_nil(stream)
    source = File.read(File.expand_path("../../lib/rubernetes/runtime/native.rb", __dir__))

    assert_match(/def logs\([^)]*stream: :all/, source)
  end
end
