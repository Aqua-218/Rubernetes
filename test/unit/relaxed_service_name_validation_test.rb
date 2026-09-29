# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/schema"

# RelaxedServiceNameValidation (Beta, on in v1.36, KEP-5311): Service names
# and Ingress backend Service names are DNS labels (NameIsDNSLabel), so they
# may start with a digit; the backend's port is validated as upstream's
# validateIngressBackend does.
class RelaxedServiceNameValidationTest < Minitest::Test
  Validation = Rubernetes::API::ObjectValidation
  Validator = Rubernetes::Schema::KubernetesValidator

  def service(name)
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => name, "namespace" => "default"},
     "spec" => {"ports" => [{"port" => 80}]}}
  end

  def name_causes(name)
    Validation.validate("Service", service(name), namespaced: true).select { |cause| cause["field"] == "metadata.name" }
  end

  def test_service_names_may_start_with_a_digit
    assert_empty name_causes("1abc-svc")
    assert_empty name_causes("web")
    refute_empty name_causes("-bad")
    refute_empty name_causes("Upper")
    refute_empty name_causes("a" * 64)
  end

  def backend_messages(service)
    ingress = {"spec" => {"defaultBackend" => {"service" => service}}}
    Validator.send(:ingress_errors, ingress).map do |issue|
      "#{issue.instance_variable_get(:@path).join(".")}: #{issue.instance_variable_get(:@kubernetes_type)}: #{issue.instance_variable_get(:@message)}"
    end
  end

  def test_ingress_backend_service_name_and_port
    assert_empty backend_messages({"name" => "1svc", "port" => {"number" => 80}})
    assert_empty backend_messages({"name" => "svc", "port" => {"name" => "http"}})
    assert(backend_messages({"name" => "Bad_Name", "port" => {"number" => 80}}).any? { |message| message.include?("RFC 1123") })
    assert(backend_messages({"name" => "svc", "port" => {"name" => "http", "number" => 80}})
             .any? { |message| message.include?("cannot set both port name & port number") })
    assert(backend_messages({"name" => "svc", "port" => {"name" => "1234"}}).any? { |message| message.include?("at least one letter") })
    assert(backend_messages({"name" => "svc", "port" => {"number" => 70_000}}).any? { |message| message.include?("between 1 and 65535") })
    assert(backend_messages({"name" => "svc", "port" => {}}).any? { |message| message.include?("port name or number is required") })
    assert(backend_messages({"port" => {"number" => 80}}).any? { |message| message.include?("service.name") || message.include?("Required") })
  end
end
