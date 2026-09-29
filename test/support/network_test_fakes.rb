# frozen_string_literal: true

# Shared harness extracted from unit/m4_network_test.rb; included by that
# test and by the tests that used to subclass it (a test file must not require
# another test file: its tests would run under both classes).
require "fileutils"
require "tmpdir"
require "rubernetes/network"

module NetworkTestFakes
  class RecordingAdapter
    attr_reader :operations, :swaps, :requests

    def initialize
      @operations = []
      @swaps = []
      @requests = []
    end

    def apply(operation, operation_id: nil)
      @operations << [operation, operation_id]
      true
    end

    def atomic_swap(snapshot)
      @swaps << snapshot
      true
    end

    def request(**request)
      @requests << request
      [{type: Rubernetes::Network::Netlink::NLMSG_ERROR, error: 0, sequence: request.fetch(:sequence)}]
    end

    def check(_sandbox)
      true
    end
  end

  class RollbackNetlink
    attr_reader :calls

    def initialize
      @calls = []
    end

    def link_state(name:, index:, namespace:, namespace_fd:)
      {"name" => name, "index" => index || 7, "up" => true, "mtu" => 1500,
       "master" => nil, "netns_inode" => 1234}
    end

    def link_set(**parameters)
      @calls << parameters
      if @calls.length == 2
        raise Rubernetes::Network::NetlinkError, "injected link_set failure"
      end

      true
    end
  end

  class MemoryStateStore
    def initialize(value)
      @value = value
    end

    def read
      Marshal.load(Marshal.dump(@value))
    end

    def replace(value)
      @value = Marshal.load(Marshal.dump(value))
      true
    end
  end

  class RecoveryLedger
    attr_reader :claims, :releases

    def initialize
      @claims = []
      @releases = []
    end

    def claim(**values)
      @claims << values
      true
    end

    def release(**values)
      @releases << values
      true
    end
  end

  class RecoveryObserver
    def initialize(*resources)
      @resources = resources
    end

    def resources(**_options)
      @resources + [{"kind" => "link", "id" => "link:host0", "identity" => "unrelated-host-link",
                     "metadata" => {"ifname" => "host0"}}]
    end

    def resources_for(_operation)
      @resources
    end
  end
end
