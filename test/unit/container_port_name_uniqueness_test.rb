# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# A container port NAME is unique across the whole Pod
# (pkg/apis/core/validation/validation.go:2727).  A named targetPort resolves
# through it, so two ports sharing a name make a Service's target ambiguous --
# and we accepted it.  PVC access modes are likewise limited to the four
# supported values (validation.go:2470).
class ContainerPortNameUniquenessTest < Minitest::Test
  Validation = Rubernetes::API::ObjectValidation

  def pod(containers)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns"},
     "spec" => {"containers" => containers}}
  end

  def causes_for(object)
    Validation.validate("Pod", object)
  end

  def port_name_causes(containers)
    causes_for(pod(containers)).select { |cause| cause.field.to_s.end_with?(".name") }
  end

  def test_distinct_port_names_are_accepted
    assert_empty port_name_causes([{"name" => "c1", "image" => "i",
                                    "ports" => [{"name" => "http", "containerPort" => 80},
                                                {"name" => "https", "containerPort" => 443}]}])
  end

  def test_a_duplicate_port_name_in_one_container_is_rejected
    refute_empty port_name_causes([{"name" => "c1", "image" => "i",
                                    "ports" => [{"name" => "http", "containerPort" => 80},
                                                {"name" => "http", "containerPort" => 8080}]}])
  end

  def test_a_duplicate_port_name_across_containers_is_rejected
    refute_empty port_name_causes([{"name" => "c1", "image" => "i",
                                    "ports" => [{"name" => "http", "containerPort" => 80}]},
                                   {"name" => "c2", "image" => "i",
                                    "ports" => [{"name" => "http", "containerPort" => 8080}]}])
  end

  def test_unnamed_ports_never_collide
    assert_empty port_name_causes([{"name" => "c1", "image" => "i",
                                    "ports" => [{"containerPort" => 80}, {"containerPort" => 8080}]}])
  end
end
