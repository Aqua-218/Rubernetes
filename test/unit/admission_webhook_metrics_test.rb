# frozen_string_literal: true

# The admission webhook metrics (admission/metrics, webhook dispatchers):
# webhook_request_total and webhook_admission_duration_seconds for every
# call, webhook_rejection_count for a denial (no_error with the returned
# code) or a failed call (calling_webhook_error), webhook_fail_open_count
# when failurePolicy Ignore let the request through.

require_relative "../test_helper"
require_relative "../support/admission_policy_harness"

class AdmissionWebhookMetricsTest < Minitest::Test
  include AdmissionPolicyHarness

  def test_webhook_calls_are_measured
    registry = Rubernetes::Observability::Metrics.new(apiserver: false)
    client = Object.new
    client.define_singleton_method(:call) do |config, review, timeout_seconds:|
      uid = review["request"]["uid"]
      case config["url"]
      when "https://allow.example/" then [200, {"response" => {"uid" => uid, "allowed" => true}}]
      when "https://deny.example/" then [200,
                                         {"response" => {"uid" => uid, "allowed" => false, "status" => {"message" => "no", "code" => 422}}}]
      else raise A::Plugins::WebhookTimeout, "timed out"
      end
    end
    rule = {"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}
    hook = lambda { |name, url, policy|
      {"name" => name, "clientConfig" => {"url" => url}, "rules" => [rule], "sideEffects" => "None", "admissionReviewVersions" => ["v1"],
       "failurePolicy" => policy}
    }
    @context.put("validatingwebhookconfigurations", nil, "v",
                 {"metadata" => {"name" => "v"}, "webhooks" => [hook.call("allow.example", "https://allow.example/", "Fail"),
                                                                hook.call("broken.example", "https://broken.example/", "Ignore"),
                                                                hook.call("deny.example", "https://deny.example/", "Fail")]},
                 group: "admissionregistration.k8s.io")
    validating = A::Registry.factories.fetch("ValidatingAdmissionWebhook").call(@context, {"client" => client})
    chain = A::Chain.new(plugins: [validating])
    chain.metrics = registry
    assert_raises(A::Rejected) { chain.validate(attributes("CREATE", object: deployment(replicas: 1))) }
    text = registry.render

    assert_includes text,
                    'apiserver_admission_webhook_request_total{code="200",name="allow.example",operation="CREATE",rejected="false",type="validating"} 1'
    assert_includes text,
                    'apiserver_admission_webhook_request_total{code="200",name="deny.example",operation="CREATE",rejected="true",type="validating"} 1'
    assert_includes text,
                    'apiserver_admission_webhook_rejection_count{error_type="no_error",name="deny.example",operation="CREATE",rejection_code="422",type="validating"} 1'
    assert_includes text,
                    'apiserver_admission_webhook_rejection_count{error_type="calling_webhook_error",name="broken.example",operation="CREATE",rejection_code="0",type="validating"} 1'
    assert_includes text, 'apiserver_admission_webhook_fail_open_count{name="broken.example",type="validating"} 1'
    assert_includes text,
                    'apiserver_admission_webhook_admission_duration_seconds_count{name="allow.example",operation="CREATE",rejected="false",type="validating"} 1'
    assert_includes text,
                    'apiserver_admission_controller_admission_duration_seconds_count{name="ValidatingAdmissionWebhook",operation="CREATE",rejected="true",type="validate"} 1'
  end
end
