# frozen_string_literal: true

require "minitest/autorun"
require "rubernetes/consensus"

# Rubernetes::Consensus::Storage is a class of its own, so inside
# Rubernetes::Consensus::RaftStore the bare name Storage resolved to it and
# not to Rubernetes::Storage.  `raise Storage::Unavailable` therefore raised
# NameError, and the one path that turns a read-index timeout into a 503 with
# Retry-After crashed the handler instead: the apiserver logged "uninitialized
# constant Rubernetes::Consensus::Storage::Unavailable" on lease reads and the
# e2e client saw a nonsense response ("getting pod : Unauthorized").
class RaftStoreBarrierUnavailableTest < Minitest::Test
  class AlwaysTimingOutServer
    attr_reader :attempts

    def initialize
      @attempts = 0
    end

    def read_index(**_options)
      @attempts += 1
      raise Rubernetes::Consensus::Timeout, "read index"
    end
  end

  def test_a_read_index_that_keeps_timing_out_reports_unavailable
    server = AlwaysTimingOutServer.new
    store = Rubernetes::Consensus::RaftStore.new(server, timeout: 0.001)

    error = assert_raises(Rubernetes::Storage::Unavailable) { store.barrier }

    assert_match(/read index timed out/, error.message)
    assert_equal Rubernetes::Consensus::RaftStore::BARRIER_ATTEMPTS, server.attempts
  end

  def test_the_shadowing_constant_is_still_absent_so_the_bare_spelling_stays_wrong
    refute Rubernetes::Consensus::Storage.const_defined?(:Unavailable, false),
           "if Consensus::Storage ever gains Unavailable, revisit the raise in RaftStore#barrier"
  end
end
