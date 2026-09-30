# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/schema/codec/kubernetes_protobuf"

# metav1.Time is second precision on both wires upstream: MarshalJSON writes
# RFC3339, and ProtoTime drops the nanos precisely because "our JSON only
# handled seconds".  Our protobuf already dropped them, but objects were stored
# and served as JSON with microseconds, so a protobuf client and a JSON client
# read different timestamps for the same field and never agreed.
# "[sig-node] Pod InPlace Resize Container resize pod via the replace endpoint"
# compares the Pod from the typed (protobuf) client with the Pod from the
# dynamic (JSON) client and timed out after 300 s every round.
class Metav1TimePrecisionTest < Minitest::Test
  Codec = Rubernetes::Schema::Codec::KubernetesProtobuf

  def codec = Rubernetes::API::StoreAdapter.time_codec

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "dev", "creationTimestamp" => "2026-09-18T03:45:58.843311Z",
                    "managedFields" => [{"manager" => "m", "time" => "2026-09-18T03:45:58.9Z",
                                         "fieldsV1" => {"f:spec" => {}}}]},
     "spec" => {"containers" => [{"name" => "c", "image" => "i",
                                  "resources" => {"requests" => {"cpu" => "200m"}}}]},
     "status" => {"startTime" => "2026-09-18T03:46:00.5Z",
                  "conditions" => [{"type" => "Ready", "status" => "True",
                                    "lastTransitionTime" => "2026-09-18T03:46:01.123456Z"}],
                  "containerStatuses" => [{"name" => "c",
                                           "state" => {"running" => {"startedAt" => "2026-09-18T03:46:02.7Z"}}}]}}
  end

  def test_every_metav1_time_field_is_brought_to_seconds
    out = codec.truncate_times(pod)

    assert_equal "2026-09-18T03:45:58Z", out.dig("metadata", "creationTimestamp")
    assert_equal "2026-09-18T03:45:58Z", out.dig("metadata", "managedFields", 0, "time")
    assert_equal "2026-09-18T03:46:00Z", out.dig("status", "startTime")
    assert_equal "2026-09-18T03:46:01Z", out.dig("status", "conditions", 0, "lastTransitionTime")
    assert_equal "2026-09-18T03:46:02Z", out.dig("status", "containerStatuses", 0, "state", "running", "startedAt")
  end

  def test_other_fields_are_left_exactly_as_they_were
    out = codec.truncate_times(pod)

    assert_equal "200m", out.dig("spec", "containers", 0, "resources", "requests", "cpu")
    assert_equal({"f:spec" => {}}, out.dig("metadata", "managedFields", 0, "fieldsV1"))
    assert_equal "2026-09-18T03:45:58.843311Z", pod.dig("metadata", "creationTimestamp"), "the input is not mutated"
  end

  # MicroTime keeps its microseconds on both wires.
  def test_micro_time_keeps_its_precision
    lease = {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease", "metadata" => {"name" => "l"},
             "spec" => {"renewTime" => "2026-09-18T03:46:02.123456Z"}}
    event = {"apiVersion" => "events.k8s.io/v1", "kind" => "Event", "metadata" => {"name" => "e"},
             "eventTime" => "2026-09-18T03:46:02.123456Z", "deprecatedFirstTimestamp" => "2026-09-18T03:46:02.5Z"}

    assert_equal "2026-09-18T03:46:02.123456Z", codec.truncate_times(lease).dig("spec", "renewTime")
    out = codec.truncate_times(event)

    assert_equal "2026-09-18T03:46:02.123456Z", out["eventTime"]
    assert_equal "2026-09-18T03:46:02Z", out["deprecatedFirstTimestamp"]
  end

  def test_a_kind_the_descriptors_do_not_know_is_untouched
    widget = {"apiVersion" => "example.com/v1", "kind" => "Widget",
              "metadata" => {"creationTimestamp" => "2026-09-18T03:46:02.5Z"}}

    assert_equal widget, codec.truncate_times(widget)
  end

  # Through the server: what is stored and served is second precision, and an
  # update that repeats the same instants with sub-second digits (the node
  # agent stamps status that way) is still no change.
  def server_with_pod
    server = Rubernetes::API::Server.new(registry: Rubernetes::API::Registry.new,
                                         store: Rubernetes::API::MemoryStore.new(clock: -> { Time.utc(2026, 1, 1) }),
                                         namespace_lifecycle: true)
    server.call(method: "POST", path: "/api/v1/namespaces", body: {"metadata" => {"name" => "dev"}}, headers: {})
    body = pod
    body["metadata"].delete("creationTimestamp")
    body["metadata"].delete("managedFields")
    body.delete("status")
    created = server.call(method: "POST", path: "/api/v1/namespaces/dev/pods", body: body, headers: {}).body
    [server, created]
  end

  def test_what_the_server_stores_and_serves_is_second_precision
    _server, created = server_with_pod

    refute_includes created.dig("metadata", "creationTimestamp").to_s, "."
  end

  def test_repeating_the_same_instant_with_subsecond_digits_is_not_a_write
    server, created = server_with_pod
    with_micros = Marshal.load(Marshal.dump(created))
    with_micros["metadata"]["creationTimestamp"] = created.dig("metadata", "creationTimestamp").sub("Z", ".654321Z")

    updated = server.call(method: "PUT", path: "/api/v1/namespaces/dev/pods/p", body: with_micros, headers: {}).body

    assert_equal created.dig("metadata", "resourceVersion"), updated.dig("metadata", "resourceVersion")
  end
end
