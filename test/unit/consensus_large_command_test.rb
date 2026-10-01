# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_write_client"

# A write larger than a replication batch still commits, alone in its batch;
# only a write above max_command_bytes (etcd's --max-request-bytes, 1.5 MiB)
# is refused.  Argo Workflows' 1.28 MB `workflows` CRD was refused with
# "command exceeds 1048576 bytes" because the batch size doubled as the
# command limit.
class ConsensusLargeCommandTest < Minitest::Test
  C = Rubernetes::Consensus
  IDS = %w[n1 n2 n3].freeze

  def build(seed:)
    cluster = RaftSimulation::Cluster.new(IDS, seed: seed, timing: C::Node::Timing.default)
    cluster.run(1.0)

    assert_equal 1, cluster.leader.length, "no leader after 1 s"
    [cluster, RaftSimulation::WriteClient.new(cluster)]
  end

  def object(bytes)
    {"metadata" => {"name" => "big"}, "spec" => {"blob" => "x" * bytes}}
  end

  def test_a_command_above_the_batch_size_but_below_the_command_limit_commits
    cluster, client = build(seed: 7)
    leader = cluster.leader.first.id
    client.create(leader, "k/small-before", flush_now: true)
    client.create(leader, "k/big", object: object(1_280_000), flush_now: true)
    client.create(leader, "k/small-after", flush_now: true)
    client.settle(timeout: 20.0)

    assert_equal %w[k/big k/small-after k/small-before], client.acked.map(&:key).sort, client.failed.map { |r| [r.key, r.error] }.inspect
    assert_empty client.divergent_replicas
  ensure
    cluster&.cleanup
  end

  def test_a_command_above_the_command_limit_is_refused_as_invalid
    cluster, _client = build(seed: 8)
    leader = cluster.leader.first.id
    error = assert_raises(C::InvalidCommand) do
      cluster.processes.fetch(leader).node.propose({"type" => "create", "key" => "k/huge", "object" => object(1_600_000)})
    end

    assert_includes error.message, "exceeds 1572864 bytes"
  ensure
    cluster&.cleanup
  end
end
