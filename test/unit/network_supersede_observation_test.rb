# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# Deciding whether a stale claim may be superseded reads only the table the
# held resource lives in -- for a link, only that link by name -- instead of
# dumping every link, address, route and neighbour on the node.
class NetworkSupersedeObservationTest < Minitest::Test
  class Observer
    attr_reader :calls

    def initialize(present: [])
      @calls = []
      @present = present
    end

    def resources(kinds: nil, link_name: nil)
      @calls << {kinds: kinds, link_name: link_name}
      @present
    end
  end

  def interface(observer)
    subject = Rubernetes::Network::Interface.allocate
    subject.instance_variable_set(:@observer, observer)
    subject
  end

  def test_a_link_is_looked_up_by_name
    observer = Observer.new

    refute interface(observer).send(:observed_identity?, "link:abc", kind: "link", link_name: "veth1")
    assert_equal [{kinds: ["link"], link_name: "veth1"}], observer.calls
  end

  def test_an_address_reads_the_address_table_only
    observer = Observer.new(present: [{"identity" => "address:x"}])

    assert interface(observer).send(:observed_identity?, "address:x", kind: "address")
    assert_equal [{kinds: ["address"], link_name: nil}], observer.calls
  end

  def test_an_unknown_kind_still_reads_everything
    observer = Observer.new
    interface(observer).send(:observed_identity?, "veth:x", kind: "veth")

    assert_equal [{kinds: nil, link_name: nil}], observer.calls
  end
end
