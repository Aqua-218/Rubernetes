# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

# The Service watch and the EndpointSlice watch publish rules concurrently.
# Computing the diff and committing it were locked separately, so the two
# could interleave: the later diff reached the backend first, was refused as
# starting at a revision the backend had never reached, and from then on every
# diff was refused.  A node in that state programmed no further rules at all --
# one proxy of three logged 1089 consecutive "rule diff starts at revision N,
# expected 190" and every ClusterIP created after it answered nothing.
class ProxyRulePublicationRaceTest < Minitest::Test
  def service(name, cluster_ip)
    {
      "metadata" => {"name" => name, "namespace" => "default"},
      "spec" => {
        "clusterIP" => cluster_ip,
        "ports" => [{"name" => "http", "port" => 80, "targetPort" => 8080, "protocol" => "TCP"}]
      }
    }
  end

  def slice(name, service_name, address)
    {
      "metadata" => {
        "name" => name,
        "namespace" => "default",
        "labels" => {"kubernetes.io/service-name" => service_name}
      },
      "addressType" => "IPv4",
      "ports" => [{"name" => "http", "port" => 8080, "protocol" => "TCP"}],
      "endpoints" => [{"addresses" => [address], "conditions" => {"ready" => true}}]
    }
  end

  def proxy
    Rubernetes::Proxy::Proxy.new(local_node: "node-0", backend: Rubernetes::Proxy::MemoryBackend.new)
  end

  def test_concurrent_publication_keeps_the_backend_in_step_with_the_rule_set
    subject = proxy
    threads = 8.times.map do |index|
      Thread.new do
        subject.apply_service(service("svc-#{index}", "10.96.0.#{index + 10}"))
        subject.apply_endpoint_slice(slice("svc-#{index}-abc", "svc-#{index}", "10.244.0.#{index + 10}"))
      end
    end
    threads.each(&:join)

    assert_equal(subject.rule_set.revision, subject.backend.revision,
                 "the backend must not trail the compiled rule set")
    assert_equal(subject.rule_set.snapshot.map(&:key).sort,
                 subject.backend.rules.map(&:key).sort,
                 "every compiled rule must be programmed")
  end

  # Defence in depth: a backend can also roll itself back after failing to
  # commit a diff.  The next publication has to resynchronise it rather than
  # refuse every diff from then on.
  def test_a_backend_left_behind_is_resynchronised_on_the_next_publication
    subject = proxy
    subject.apply_service(service("first", "10.96.0.10"))
    subject.apply_endpoint_slice(slice("first-abc", "first", "10.244.0.10"))

    backend = subject.backend
    stranded = {rules: backend.instance_variable_get(:@rules),
                revision: backend.instance_variable_get(:@revision),
                last_diff: backend.instance_variable_get(:@last_diff)}

    subject.apply_service(service("second", "10.96.0.11"))
    subject.apply_endpoint_slice(slice("second-abc", "second", "10.244.0.11"))
    # Rewind the datapath behind the rule set, as a failed commit would.
    backend.send(:restore_backend_state, stranded)

    subject.apply_service(service("third", "10.96.0.12"))

    assert_equal(subject.rule_set.snapshot.map(&:key).sort,
                 backend.rules.map(&:key).sort,
                 "the resync must replay the whole desired rule set, not just the last diff")
    assert_equal(subject.rule_set.revision, backend.revision)
  end
end
