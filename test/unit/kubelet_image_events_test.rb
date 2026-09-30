# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require_relative "../support/node_lifecycle_fakes"

# kubelet's image manager (pkg/kubelet/images/image_manager.go, v1.36.2) as
# the Pod's events and /metrics show it: Pulling only when a pull starts,
# Pulled with the pull's time and size, "already present" for an image the
# node has and for every later container of the same image, Failed and
# ErrImageNeverPull, and the pull-duration / ensure-image metrics.
class KubeletImageEventsTest < Minitest::Test
  DIGEST = "sha256:#{"a" * 64}"

  class Resolver
    def initialize(cached: [], fail: [])
      @cached = cached
      @fail = fail
    end

    def resolve(reference, pull_policy: nil, on_pull: nil)
      present = @cached.include?(reference)
      on_pull&.call(:present, present)
      if pull_policy == "Never" && !present
        raise Rubernetes::Image::NeverPullError, "Container image #{reference.inspect} is not present with pull policy of Never"
      end

      unless present
        on_pull&.call(:start)
        if @fail.include?(reference)
          error = Rubernetes::Image::RegistryError.new("manifest unknown")
          on_pull&.call(:failed, error)
          raise error
        end
        on_pull&.call(:done, 1.2345, 42_000_000)
      end
      {"digest" => DIGEST, "reference" => reference}
    end
  end

  def lifecycle(resolver)
    @entries = []
    @metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "node-1")
    Rubernetes::Node::Lifecycle.new(runtime: NodeLifecycleFakes::Runtime.new, reporter: NodeLifecycleFakes::Reporter.new,
                                    sleeper: ->(_seconds) {}, image_resolver: resolver,
                                    event_sink: ->(_uid, entry) { @entries << entry }).tap { |value| value.metrics_observer = @metrics }
  end

  def pod(containers, init: [])
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
     "spec" => {"nodeName" => "node-1", "restartPolicy" => "Never", "initContainers" => init, "containers" => containers}}
  end

  def messages
    reasons = Rubernetes::Node::KubeletEventPublisher::REASONS
    @entries.filter_map do |entry|
      mapping = reasons[entry["type"]]
      next unless mapping && entry["type"].start_with?("image.")

      [entry["name"], mapping[1], mapping[2].call(entry, {})]
    end
  end

  def test_a_pull_then_a_container_sharing_the_image_then_a_present_image
    subject = lifecycle(Resolver.new(cached: ["cached:1"]))
    subject.start(pod([{"name" => "a", "image" => "new:1", "imagePullPolicy" => "IfNotPresent"},
                       {"name" => "b", "image" => "cached:1", "imagePullPolicy" => "IfNotPresent"}],
                      init: [{"name" => "i", "image" => "new:1", "imagePullPolicy" => "IfNotPresent"}]))

    assert_equal [["i", "Pulling", 'Pulling image "new:1"'],
                  ["i", "Pulled", 'Successfully pulled image "new:1" in 1.234s (1.234s including waiting). Image size: 42000000 bytes.'],
                  ["a", "Pulled", 'Container image "new:1" already present on machine and can be accessed by the pod'],
                  ["b", "Pulled", 'Container image "cached:1" already present on machine and can be accessed by the pod']], messages
    text = @metrics.registry.render

    assert_includes text, %(kubelet_image_pull_duration_seconds_count{image_size_in_bytes="10MB-100MB"} 1)
    assert_includes text,
                    %(kubelet_image_manager_ensure_image_requests_total{present_locally="false",pull_policy="ifnotpresent",pull_required="true"} 1)
    assert_includes text,
                    %(kubelet_image_manager_ensure_image_requests_total{present_locally="true",pull_policy="ifnotpresent",pull_required="false"} 2)
  end

  def test_a_failed_pull_and_a_never_policy
    subject = lifecycle(Resolver.new(fail: ["gone:1"]))
    subject.start(pod([{"name" => "a", "image" => "gone:1", "imagePullPolicy" => "Always"}]))

    assert_equal [["a", "Pulling", 'Pulling image "gone:1"'], ["a", "Failed", 'Failed to pull image "gone:1": manifest unknown']], messages
    failed = @entries.find { |entry| entry["type"] == "pod.failed" }

    assert_equal "Error: ErrImagePull", Rubernetes::Node::KubeletEventPublisher::REASONS.fetch("pod.failed")[2].call(failed, {})

    subject = lifecycle(Resolver.new)
    subject.start(pod([{"name" => "a", "image" => "local:1", "imagePullPolicy" => "Never"}]))

    assert_equal [["a", "ErrImageNeverPull", 'Container image "local:1" is not present with pull policy of Never']], messages
    assert_includes @metrics.registry.render,
                    %(kubelet_image_manager_ensure_image_requests_total{present_locally="false",pull_policy="never",pull_required="unknown"} 1)
  end

  def test_the_size_buckets_and_go_durations
    bucket = Rubernetes::Node::KubeletMetrics.method(:image_size_bucket)

    assert_equal(["N/A", "0-10MB", "0-10MB", "10MB-100MB", "GT100GB"],
                 [0, 1, 10 << 20, (10 << 20) + 1, (100 << 30) + 1].map { |size| bucket.call(size) })
    assert_equal(%w[0s 567ms 1.5s 1m2.345s 1h2m3.4s], [0, 0.567, 1.5, 62.345, 3723.4].map do |value|
      Rubernetes::Node::Helpers.go_duration(value)
    end)
  end
end
