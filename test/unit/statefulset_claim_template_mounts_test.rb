# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# apps validation volumesToAddForTemplates: a StatefulSet's volumeClaimTemplates
# are volumes of the template, so a container may mount them by name.  Gitea's
# PostgreSQL and Valkey StatefulSets were rejected with
# volumeMounts[5].name: Not found: "data".
class StatefulSetClaimTemplateMountsTest < Minitest::Test
  Validation = Rubernetes::API::ObjectValidation

  def stateful_set(mount_name:, claim_names: ["data"])
    {"apiVersion" => "apps/v1", "kind" => "StatefulSet",
     "metadata" => {"name" => "db", "namespace" => "ns"},
     "spec" => {"serviceName" => "db", "selector" => {"matchLabels" => {"app" => "db"}},
                "template" => {"metadata" => {"labels" => {"app" => "db"}},
                               "spec" => {"containers" => [{"name" => "db", "image" => "i",
                                                            "volumeMounts" => [{"name" => mount_name, "mountPath" => "/var/lib/db"}]}]}},
                "volumeClaimTemplates" => claim_names.map do |name|
                  {"metadata" => {"name" => name}, "spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}}}
                end}}
  end

  def mount_causes(object)
    Validation.validate("StatefulSet", object).select { |cause| cause.field.to_s.include?("volumeMounts") }
  end

  def test_a_mount_of_a_volume_claim_template_is_accepted
    assert_empty mount_causes(stateful_set(mount_name: "data"))
  end

  def test_a_mount_of_an_unknown_name_is_still_rejected
    causes = mount_causes(stateful_set(mount_name: "missing"))

    assert_equal ["spec.template.spec.containers[0].volumeMounts[0].name"], causes.map(&:field)
    assert_equal "FieldValueNotFound", causes.first.reason
  end

  def test_a_deployment_does_not_get_claim_template_names
    object = stateful_set(mount_name: "data").merge("kind" => "Deployment")
    causes = Validation.validate("Deployment", object).select { |cause| cause.field.to_s.include?("volumeMounts") }

    assert_equal 1, causes.length
  end
end
