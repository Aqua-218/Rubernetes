# frozen_string_literal: true

# Native rollback dependency regression tests.
# Specification reference: spec/node/runtime.md §5.8.4. These L1 tests verify
# reverse cleanup, dependency blocking, durable provenance, and retry behavior
# with injectable adapters; they do not claim kernel isolation coverage.

require_relative "../test_helper"
require "rubernetes/runtime/native"

class NativeRuntimeRollbackDependencyTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  # A false response models a live or otherwise unconfirmed upper owner. The
  # handle remains available so the next cleanup attempt can retry it.
  class CgroupAdapter < Native::FakeCgroup
    attr_accessor :fail_remove

    def initialize(calls, fail_remove: false)
      super()
      @external_calls = calls
      @fail_remove = fail_remove
    end

    def remove(handle, force: false)
      @external_calls << :cgroup_release
      return false if fail_remove

      super
    end
  end

  class ContainerFailureCgroupAdapter < Native::FakeCgroup
    attr_accessor :fail_container

    def remove(handle, force: false)
      return false if fail_container && handle.container_id != "sandbox"

      super
    end
  end

  # Requirement: a failed cgroup release must not destructively release its
  # dependent namespace or workspace, and every dependent error carries the
  # failed owner as provenance.
  def test_cgroup_failure_blocks_namespace_and_workspace_cleanup
    runtime, state = rollback_runtime(cgroup_failure: true)

    error = assert_raises(RuntimeError) { runtime.run_sandbox({"id" => "rollback-cgroup"}, request_id: "rollback-cgroup") }

    assert_equal "injected rollback failure", error.message
    assert_equal [{"resource" => "cgroup:rollback-cgroup",
                   "error" => "Rubernetes::Runtime::Native::ResourceError: cgroup cleanup returned false",
                   "state" => "cleanup_pending"},
                  {"resource" => "namespace:rollback-cgroup",
                   "error" => "cleanup blocked by cgroup:rollback-cgroup",
                   "state" => "cleanup_pending", "blocked_by" => "cgroup:rollback-cgroup"},
                  {"resource" => "workspace:rollback-cgroup",
                   "error" => "cleanup blocked by cgroup:rollback-cgroup",
                   "state" => "cleanup_pending", "blocked_by" => "cgroup:rollback-cgroup"}],
                 error.cleanup_errors
    assert_equal [:cgroup_release], state.fetch(:calls)

    pending = runtime.trace.reverse.find { |entry| entry["event"] == "cleanup_pending" }

    assert_equal({"class" => "RuntimeError", "message" => "injected rollback failure"}, pending.fetch("primary_error"))
    assert_equal "cgroup:rollback-cgroup", pending.fetch("errors").fetch(1).fetch("blocked_by")

    resources = runtime.ledger.resources
    namespace = resources.find { |resource| resource.fetch(:kind) == "namespace" }
    workspace = resources.find { |resource| resource.fetch(:kind) == "workspace" }

    assert_equal true, namespace.fetch(:metadata).fetch("cleanup_pending")
    assert_equal "cgroup:rollback-cgroup", namespace.fetch(:metadata).fetch("blocked_by")
    assert_equal true, workspace.fetch(:metadata).fetch("cleanup_pending")
    assert_equal "cgroup:rollback-cgroup", workspace.fetch(:metadata).fetch("blocked_by")

    state.fetch(:cgroup).fail_remove = false

    assert_equal true, runtime.stop_sandbox("rollback-cgroup")
    assert_equal %i[cgroup_release cgroup_release namespace_release workspace_release], state.fetch(:calls)
    assert_empty runtime.ledger.resources
  end

  # Requirement: after cgroup succeeds, a namespace failure blocks only the
  # workspace; a retry starts at the first still-owned upper resource.
  def test_namespace_failure_after_cgroup_success_blocks_workspace_and_retries
    runtime, state = rollback_runtime(namespace_failure: true)

    error = assert_raises(RuntimeError) { runtime.run_sandbox({"id" => "rollback-namespace"}, request_id: "rollback-namespace") }

    assert_equal "injected rollback failure", error.message
    assert_equal %i[cgroup_release namespace_release], state.fetch(:calls)
    assert_equal(%w[namespace:rollback-namespace workspace:rollback-namespace],
                 error.cleanup_errors.map { |entry| entry.fetch("resource") })
    workspace_error = error.cleanup_errors.fetch(1)

    assert_equal "namespace:rollback-namespace", workspace_error.fetch("blocked_by")

    state[:namespace_failure] = false

    assert_equal true, runtime.stop_sandbox("rollback-namespace")

    assert_equal %i[cgroup_release namespace_release namespace_release workspace_release], state.fetch(:calls)
    assert_empty runtime.ledger.resources
    assert_equal "Stopped", runtime.ledger.operation("rollback-namespace").state
  end

  # Requirement: a fully successful rollback uses the exact reverse
  # acquisition order and reaches a terminal stopped operation.
  def test_successful_rollback_releases_cgroup_namespace_and_workspace_in_reverse_order
    runtime, state = rollback_runtime

    error = assert_raises(RuntimeError) { runtime.run_sandbox({"id" => "rollback-success"}, request_id: "rollback-success") }

    assert_equal "injected rollback failure", error.message
    assert_equal %i[cgroup_release namespace_release workspace_release], state.fetch(:calls)
    assert_empty runtime.ledger.resources
    assert_empty runtime.sandboxes
    assert_equal "Stopped", runtime.ledger.operation("rollback-success").state
  end

  # Requirement: a false container cgroup release keeps the container and
  # ledger ownership live, and the same request can retry after the adapter
  # becomes healthy.
  def test_container_cgroup_false_is_cleanup_pending_and_retryable
    cgroup = ContainerFailureCgroupAdapter.new
    cgroup.fail_container = true
    runtime = Native.new(profile: :pure, cgroup_adapter: cgroup)
    sandbox_id = runtime.run_sandbox({"id" => "remove-container"})
    container = runtime.create_container(sandbox_id, {"id" => "container-1"})

    error = assert_raises(Native::ResourceError) do
      runtime.remove_container(container, request_id: "remove-container-request")
    end
    assert_match(/cgroup cleanup returned false/, error.message)
    assert_equal "created", runtime.container_status(container).fetch("state")
    resource = runtime.ledger.resources(include_released: true).find do |entry|
      entry.fetch(:kind) == "cgroup" && entry.fetch(:id) == "remove-container:container-1"
    end

    assert_equal "Owned", resource.fetch(:state)
    assert_equal true, resource.fetch(:metadata).fetch("cleanup_pending")
    assert_equal "CleanupPending", runtime.ledger.request("remove-container-request").to_h.fetch("state")

    cgroup.fail_container = false

    assert_equal true, runtime.remove_container(container, request_id: "remove-container-request")
    assert_raises(Native::Error) { runtime.container_status(container) }
    assert_equal "Released", runtime.ledger.resources(include_released: true).find { |entry|
      entry.fetch(:kind) == "cgroup" && entry.fetch(:id) == "remove-container:container-1"
    }.fetch(:state)
  end

  # Requirement: a raised child cleanup blocks every dependent sandbox
  # resource and records the child as the dependency provenance.
  def test_child_cleanup_failure_blocks_parent_resources_until_retry
    cgroup = ContainerFailureCgroupAdapter.new
    cgroup.fail_container = true
    runtime = Native.new(profile: :pure, cgroup_adapter: cgroup)
    sandbox_id = runtime.run_sandbox({"id" => "child-block"})
    runtime.create_container(sandbox_id, {"id" => "container-1"})
    sandbox = runtime.sandbox(sandbox_id)
    operation = runtime.ledger.operation(sandbox_id)

    error = assert_raises(Native::ResourceError) do
      runtime.send(:cleanup_sandbox_resources, sandbox, operation)
    end
    assert_equal(["container:container-1", "cgroup:child-block", "namespace:child-block", "workspace:child-block"],
                 error.cleanup_errors.map { |entry| entry.fetch("resource") })
    assert_equal "container:container-1", error.cleanup_errors.fetch(1).fetch("blocked_by")
    assert_equal "container:container-1", error.cleanup_errors.fetch(2).fetch("blocked_by")
    assert_equal "container:container-1", error.cleanup_errors.fetch(3).fetch("blocked_by")

    cgroup.fail_container = false

    assert_equal true, runtime.stop_sandbox(sandbox_id)
    assert_empty runtime.ledger.resources
  end

  # Requirement: rollback preserves primary cleanup metadata and appends only
  # new, non-duplicate cleanup entries.
  def test_preserve_cleanup_errors_appends_and_deduplicates_primary_entries
    runtime = Native.new(profile: :pure)
    primary = RuntimeError.new("primary failure")
    primary.instance_variable_set(:@cleanup_errors, [{"resource" => "old", "error" => "same"}])
    primary.define_singleton_method(:cleanup_errors) { @cleanup_errors }

    runtime.send(:preserve_cleanup_errors, primary, [
                   {"resource" => "old", "error" => "same"},
                   {"resource" => "new", "error" => "cleanup"}
                 ])

    assert_equal [{"resource" => "old", "error" => "same"}, {"resource" => "new", "error" => "cleanup"}],
                 primary.cleanup_errors
  end

  private

  def rollback_runtime(cgroup_failure: false, namespace_failure: false)
    calls = []
    state = {calls: calls, namespace_failure: namespace_failure}

    namespace_adapter = Object.new
    namespace_adapter.define_singleton_method(:create) do |plan:, id:, identity:|
      "namespace-handle-#{id}"
    end
    namespace_adapter.define_singleton_method(:destroy) do |handle:, id:, identity:|
      calls << :namespace_release
      state.fetch(:namespace_failure) ? false : true
    end

    filesystem_adapter = Object.new
    filesystem_adapter.define_singleton_method(:prepare) do |workspace:, **_options|
      workspace
    end
    filesystem_adapter.define_singleton_method(:cleanup) do |workspace:|
      calls << :workspace_release
      true
    end

    cgroup_adapter = CgroupAdapter.new(calls, fail_remove: cgroup_failure)
    state[:cgroup] = cgroup_adapter
    effect_hook = lambda do |effect_point:, **_options|
      raise "injected rollback failure" if effect_point == "resources_attached"
    end

    runtime = Native.new(
      profile: :pure,
      namespace_adapter: namespace_adapter,
      filesystem_adapter: filesystem_adapter,
      cgroup_adapter: cgroup_adapter,
      adapters: {effect_hook: effect_hook}
    )
    [runtime, state]
  end
end
