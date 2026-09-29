# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

class KubernetesValidatorTest < Minitest::Test
  def test_operation_sensitive_object_metadata_uses_kubernetes_field_paths
    definition = Rubernetes::Generated.definition_for("io.k8s.api.apps.v1.Deployment")
    object = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {}, "spec" => {}}

    create = definition.validator.errors(object, operation: :create)
    update = definition.validator.errors(object, operation: :update)

    assert_includes(create.map(&:kubernetes_field), "metadata.name")
    assert_includes(create.map(&:kubernetes_field), "metadata.namespace")
    refute_includes(create.map(&:kubernetes_field), "metadata.resourceVersion")
    # apps/v1 Deployment allows an unconditional update (AllowUnconditionalUpdate
    # is true); coordination.k8s.io Lease does not and requires the version.
    refute_includes(update.map(&:kubernetes_field), "metadata.resourceVersion")
    lease = Rubernetes::Generated.definition_for("io.k8s.api.coordination.v1.Lease")
    lease_update = lease.validator.errors({"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease", "metadata" => {}, "spec" => {}}, operation: :update)
    assert_includes(lease_update.map(&:kubernetes_field), "metadata.resourceVersion")
    assert_equal("Invalid value", lease_update.find { |issue| issue.kubernetes_field == "metadata.resourceVersion" }.kubernetes_error_type)
  end

  def test_webhook_one_of_and_required_rules_replace_generic_structural_messages
    definition = Rubernetes::Generated.definition_for("io.k8s.api.admissionregistration.v1.MutatingWebhookConfiguration")
    object = {
      "apiVersion" => "admissionregistration.k8s.io/v1",
      "kind" => "MutatingWebhookConfiguration",
      "metadata" => {},
      "webhooks" => [{}]
    }

    errors = definition.validator.errors(object, operation: :create)
    signatures = errors.map { |issue| [issue.kubernetes_field, issue.kubernetes_error_type, issue.message] }

    assert_includes(signatures, ["metadata.name", "Required value", "name or generateName is required"])
    assert_includes(signatures, ["webhooks[0].clientConfig", "Required value", "exactly one of url or service is required"])
    refute(signatures.any? { |field, _type, message| field == "webhooks[0].clientConfig" && message.start_with?("field ") })
  end

  def test_probe_handlers_are_checked_at_any_nested_pod_path
    definition = Rubernetes::Generated.definition_for("io.k8s.api.batch.v1.Job")
    object = {
      "apiVersion" => "batch/v1",
      "kind" => "Job",
      "metadata" => {"name" => "job", "namespace" => "default", "uid" => "uid"},
      "spec" => {
        "template" => {
          "spec" => {
            "containers" => [{
              "name" => "main",
              "image" => "busybox",
              "readinessProbe" => {"exec" => {}, "httpGet" => {}, "tcpSocket" => {}}
            }]
          }
        }
      }
    }

    errors = definition.validator.errors(object, operation: :create)
    fields = errors.map(&:kubernetes_field)
    assert_includes(fields, "spec.template.spec.containers[0].readinessProbe.exec.command")
    assert_includes(fields, "spec.template.spec.containers[0].readinessProbe.httpGet")
    assert_includes(fields, "spec.template.spec.containers[0].readinessProbe.tcpSocket")
  end

  def test_probe_does_not_validate_value_typed_later_tcp_socket_siblings
    definition = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod")
    object = {
      "apiVersion" => "v1",
      "kind" => "Pod",
      "metadata" => {"name" => "pod", "namespace" => "default"},
      "spec" => {
        "containers" => [{
          "name" => "main",
          "image" => "busybox",
          "livenessProbe" => {"exec" => {}, "tcpSocket" => {"port" => "1"}}
        }]
      }
    }

    fields = definition.validator.errors(object, operation: :create).map(&:kubernetes_field)

    refute_includes(fields, "spec.containers[0].livenessProbe.tcpSocket.port")
  end

  def test_selected_tcp_socket_action_keeps_port_validation
    definition = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod")
    object = {
      "apiVersion" => "v1",
      "kind" => "Pod",
      "metadata" => {"name" => "pod", "namespace" => "default"},
      "spec" => {
        "containers" => [{
          "name" => "main",
          "image" => "busybox",
          "livenessProbe" => {"tcpSocket" => {"port" => "1"}}
        }]
      }
    }

    fields = definition.validator.errors(object, operation: :create).map(&:kubernetes_field)

    assert_includes(fields, "spec.containers[0].livenessProbe.tcpSocket.port")
  end

  # pkg/apis/core/validation/events.go ValidateEventCreate: a core/v1 request
  # only runs legacyValidateEvent, while an events.k8s.io request adds the
  # strict eventTime/type/ObjectMeta checks.
  def test_event_create_event_time_requirement_follows_the_request_version
    legacy = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Event")
    legacy_object = {
      "apiVersion" => "v1",
      "kind" => "Event",
      "metadata" => {"name" => "m1", "namespace" => "default"},
      "involvedObject" => {},
      "type" => ""
    }
    legacy_fields = legacy.validator.errors(legacy_object, operation: :create).map(&:kubernetes_field)

    refute_includes(legacy_fields, "eventTime")

    strict = Rubernetes::Generated.definition_for("io.k8s.api.events.v1.Event")
    strict_object = {
      "apiVersion" => "events.k8s.io/v1",
      "kind" => "Event",
      "metadata" => {},
      "regarding" => {},
      "type" => ""
    }
    strict_fields = strict.validator.errors(strict_object, operation: :create).map(&:kubernetes_field)

    assert_includes(strict_fields, "eventTime")
    assert_includes(strict_fields, "metadata.name")
  end

  def test_generic_validator_remains_opt_in_free_for_non_strategy_callers
    definition = Rubernetes::Generated.definition_for("io.k8s.api.apps.v1.Deployment")
    object = {"metadata" => {}}

    generic = definition.validator.errors(object)
    kubernetes = definition.validator.errors(object, operation: :create)

    refute(generic.any? { |issue| issue.kubernetes_field == "metadata.name" })
    assert(kubernetes.any? { |issue| issue.kubernetes_field == "metadata.name" })
  end

  def test_job_create_does_not_require_server_assigned_uid_or_owner_reference_uid
    definition = Rubernetes::Generated.definition_for("io.k8s.api.batch.v1.Job")
    object = {
      "apiVersion" => "batch/v1",
      "kind" => "Job",
      "metadata" => {
        "ownerReferences" => [{"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "owner", "uid" => "owner-uid"}]
      }
    }

    fields = definition.validator.errors(object, operation: :create).map(&:kubernetes_field)

    refute_includes(fields, "metadata.uid")
  end

  def test_job_create_does_not_require_uid_when_selector_is_present
    definition = Rubernetes::Generated.definition_for("io.k8s.api.batch.v1.Job")
    object = {
      "apiVersion" => "batch/v1",
      "kind" => "Job",
      "metadata" => {},
      "spec" => {"selector" => {}}
    }

    fields = definition.validator.errors(object, operation: :create).map(&:kubernetes_field)

    refute_includes(fields, "metadata.uid")
  end

  def test_job_uid_requirement_is_only_enabled_for_prepared_strategy_fixtures
    definition = Rubernetes::Generated.definition_for("io.k8s.api.batch.v1.Job")
    object = {
      "apiVersion" => "batch/v1",
      "kind" => "Job",
      "metadata" => {},
      "spec" => {"template" => {"spec" => {"containers" => [{"name" => "main", "image" => "busybox"}]}}}
    }

    ordinary = definition.validator.errors(object, operation: :create)
    prepared = definition.validator.errors(object, operation: :create, strategy_prepare: true)
    prepared_update = definition.validator.errors(object, operation: :update, strategy_prepare: true)

    refute_includes(ordinary.map(&:kubernetes_field), "metadata.uid")
    assert_includes(prepared.map(&:kubernetes_field), "metadata.uid")
    assert_equal(2, prepared_update.count { |issue| issue.kubernetes_field == "spec.selector" })
    assert_equal(2, prepared_update.count { |issue| issue.kubernetes_field == "spec.template.metadata.labels" })
    refute_includes(prepared_update.map(&:kubernetes_field), "metadata.uid")
  end
end
