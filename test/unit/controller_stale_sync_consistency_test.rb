# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"
require "rubernetes/observability/metrics"

# StaleControllerConsistency: a workload controller skips a sync whose
# informer copy predates its own last write, counts it, and retries.
class ControllerStaleSyncConsistencyTest < Minitest::Test
  Controller = Rubernetes::Controller
  Store = Rubernetes::Storage::MemoryStore

  def setup
    Controller::BaseController::ConsistencyStore.reset!
    @metrics = Rubernetes::Observability::Metrics.new(apiserver: false, component: "kube-controller-manager")
    Controller.metrics = @metrics
  end

  def teardown
    Controller.metrics = nil
    Controller::BaseController::ConsistencyStore.reset!
  end

  def job(name, uid:)
    {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => {"name" => name, "namespace" => "default", "uid" => uid},
     "spec" => {"parallelism" => 1}, "status" => {}}
  end

  def controller_class
    Class.new(Controller::BaseController) do
      define_method(:resource_descriptor) { Controller::ResourceDescriptor.parse("Job") }
      define_method(:plan) do |current, **_options|
        candidate = Controller::Support.deep_copy(current)
        candidate["status"] = {"active" => (current.dig("status", "active") || 0) + 1}
        Controller::ReconcileResult.new(
          operations: [operation_status(current, candidate["status"], descriptor: Controller::ResourceDescriptor.parse("Job"))],
          controller: name
        )
      end
    end
  end

  # A store adapter whose reads come from an informer cache that lags the
  # writes it made (what the controller manager's informer-backed adapter
  # does between a write and the watch event for it).
  class LaggingAdapter < Controller::StoreAdapter
    attr_accessor :cached

    def find(descriptor, name:, namespace: nil)
      cached || super
    end
  end

  def test_a_stale_informer_copy_is_skipped_until_the_cache_catches_up
    store = Store.new(history_revisions: nil, history_seconds: nil)
    descriptor = Controller::ResourceDescriptor.parse("Job")
    adapter = LaggingAdapter.new(store)
    adapter.create(job("build", uid: "j1"), descriptor: descriptor)
    controller = controller_class.new(store: store, name: "job-controller")

    fresh = adapter.find(descriptor, name: "build", namespace: "default")
    result = controller.reconcile(fresh, store: adapter, apply: true)

    assert result.applied
    written = Controller::StoreAdapter.new(store).find(descriptor, name: "build", namespace: "default")

    assert_equal 1, written.dig("status", "active")
    refute_equal fresh.dig("metadata", "resourceVersion"), written.dig("metadata", "resourceVersion")

    # The informer still holds the pre-write copy: skip, count, retry soon.
    adapter.cached = fresh
    skipped = controller.reconcile(fresh, store: adapter, apply: true)

    refute skipped.applied
    assert_in_delta 0.1, skipped.requeue_after, 0.001
    assert_equal 1, Controller::StoreAdapter.new(store).find(descriptor, name: "build", namespace: "default").dig("status", "active")
    text = @metrics.render_own

    assert_match(/job_controller_stale_sync_skips_total\{group="batch",resource="jobs"\} 1/, text)

    # Once the informer delivers the written revision the sync runs again.
    adapter.cached = nil
    result = controller.reconcile(written, store: adapter, apply: true)

    assert result.applied
    assert_equal 2, Controller::StoreAdapter.new(store).find(descriptor, name: "build", namespace: "default").dig("status", "active")
  end

  def test_other_controllers_never_skip
    store = Store.new(history_revisions: nil, history_seconds: nil)
    descriptor = Controller::ResourceDescriptor.parse("Job")
    adapter = Controller::StoreAdapter.new(store)
    adapter.create(job("other", uid: "j2"), descriptor: descriptor)
    controller = controller_class.new(store: store, name: "custom-controller")
    fresh = adapter.find(descriptor, name: "other", namespace: "default")
    controller.reconcile(fresh, store: store, apply: true)

    assert controller.reconcile(fresh, store: store, apply: true).applied
  end
end
