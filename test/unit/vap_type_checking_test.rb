# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/security/admission/policy_type_checker"
require "rubernetes/controller"

# ValidatingAdmissionPolicy type checking (PolicyTypeChecker + the CEL
# checker port) and the validatingadmissionpolicy-status controller.  The
# expected warnings are what upstream's TypeChecker.Check printed for the
# same policies (test/conformance/kubernetes/cel_typecheck_oracle);
# tools/differential/vap_type_checking_differential.rb compares random ones.
class VAPTypeCheckingTest < Minitest::Test
  PTC = Rubernetes::Security::Admission::PolicyTypeChecker
  MAPPING = {["apps", "v1", "deployments"] => [["apps", "v1", "Deployment"]], ["", "v1", "pods"] => [["", "v1", "Pod"]],
             ["example.com", "v1", "widgets"] => [["example.com", "v1", "Widget"]]}.freeze

  def checker(**options)
    PTC.new(rest_mapper: ->(group, version, resource) { MAPPING.fetch([group, version, resource], []) }, type_name_suffix: -> { 7 }, **options)
  end

  def policy(rules, validations, **spec)
    {"metadata" => {"name" => "p"}, "spec" => {"matchConstraints" => {"resourceRules" => rules}, "validations" => validations}.merge(spec.transform_keys(&:to_s))}
  end

  DEPLOYMENTS = [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "resources" => ["deployments"], "operations" => ["*"]}].freeze
  BOTH = [{"apiGroups" => ["", "apps"], "apiVersions" => ["v1"], "resources" => ["pods", "deployments"], "operations" => ["*"]}].freeze

  def warnings(policy) = checker.check(policy)&.map(&:to_h)

  def test_well_typed_policies_have_no_warnings
    assert_nil warnings(policy(DEPLOYMENTS, [{"expression" => "object.spec.replicas > 1"}]))
  end

  def test_issues_are_reported_per_expression_with_location_and_caret
    assert_equal [{"fieldRef" => "spec.validations[1].expression",
                   "warning" => "apps/v1, Kind=Deployment: ERROR: <input>:1:22: found no matching overload for '_>_' applied to '(int, string)'\n" \
                                " | object.spec.replicas > '1' && object.spec.nonExisting == 1\n | .....................^\n" \
                                "ERROR: <input>:1:42: undefined field 'nonExisting'\n" \
                                " | object.spec.replicas > '1' && object.spec.nonExisting == 1\n | .........................................^\n"}],
                 warnings(policy(DEPLOYMENTS, [{"expression" => "object.spec.replicas < 100"},
                                               {"expression" => "object.spec.replicas > '1' && object.spec.nonExisting == 1"}]))
  end

  # Every matched kind is checked (core group printed "/v1"); a reserved word
  # names its escaped field; variables are typed from their expressions and
  # a messageExpression is checked like an expression.
  def test_each_kind_variables_params_and_message_expressions
    expected = "error during formatting: decimal clause can only be used on integers, was given string\n" \
               " | '%d'.format([object.metadata.name])\n | ............................^\n"
    assert_equal [{"fieldRef" => "spec.validations[0].messageExpression",
                   "warning" => "/v1, Kind=Pod: ERROR: <input>:1:29: #{expected}\napps/v1, Kind=Deployment: ERROR: <input>:1:29: #{expected}"}],
                 warnings(policy(BOTH, [{"expression" => "object.metadata.namespace == 'x' && variables.limit > '1'",
                                         "messageExpression" => "'%d'.format([object.metadata.name])"}],
                                 variables: [{"name" => "limit", "expression" => "params.data.max"}],
                                 paramKind: {"apiVersion" => "v1", "kind" => "ConfigMap"}))
  end

  def test_validators_and_macro_errors
    assert_equal "apps/v1, Kind=Deployment: ERROR: <input>:1:5: expected type 'int' but found 'string'\n" \
                 " | [1, 'a'].size() > 0 || object.spec.template.spec.containers.all(c, has(c.image))\n | ....^\n",
                 warnings(policy(DEPLOYMENTS, [{"expression" => "[1, 'a'].size() > 0 || object.spec.template.spec.containers.all(c, has(c.image))"}])).first["warning"]
    assert_equal "apps/v1, Kind=Deployment: ERROR: <input>:1:5: invalid argument to has() macro\n" \
                 " | has(object) && duration('1x') > duration('0s')\n | ....^\n",
                 warnings(policy(DEPLOYMENTS, [{"expression" => "has(object) && duration('1x') > duration('0s')"}])).first["warning"]
  end

  def test_unresolvable_rules_are_skipped
    rules = [{"apiGroups" => ["*"], "apiVersions" => ["v1"], "resources" => ["deployments"]},
             {"apiGroups" => [""], "apiVersions" => ["v1"], "resources" => ["pods/status", "nothings"]}]
    assert_nil warnings(policy(rules, [{"expression" => "object.nope"}]))
  end

  # A kind the built-in definitions do not know resolves through the served
  # OpenAPI v3 document (ClientDiscoveryResolver) -- a custom resource.
  def test_custom_resources_resolve_through_openapi_v3
    document = {"components" => {"schemas" => {
      "com.example.v1.Widget" => {"type" => "object", "x-kubernetes-group-version-kind" => [{"group" => "example.com", "version" => "v1", "kind" => "Widget"}],
                                  "properties" => {"spec" => {"$ref" => "#/components/schemas/com.example.v1.WidgetSpec"}}},
      "com.example.v1.WidgetSpec" => {"type" => "object", "properties" => {"size" => {"type" => "integer"},
                                                                           "port" => {"x-kubernetes-int-or-string" => true}, "x-y" => {"type" => "string"}}}
    }}}
    tc = checker(discovery_document: ->(gvk) { gvk == ["example.com", "v1", "Widget"] ? document : nil })
    rules = [{"apiGroups" => ["example.com"], "apiVersions" => ["v1"], "resources" => ["widgets"]}]
    assert_nil tc.check(policy(rules, [{"expression" => "object.spec.size > 1 && object.spec.port == 'http' && object.spec.x__dash__y == 'a'"}]))
    warning = tc.check(policy(rules, [{"expression" => "object.spec.size == 'a'"}])).first.warning
    assert_equal "example.com/v1, Kind=Widget: ERROR: <input>:1:18: found no matching overload for '_==_' applied to '(int, string)'\n" \
                 " | object.spec.size == 'a'\n | .................^\n", warning
  end

  def test_for_client_uses_discovery_and_openapi_v3
    client = Object.new
    client.define_singleton_method(:raw) do |_method, path|
      body = case path
             when "/apis/apps/v1" then {"resources" => [{"name" => "deployments", "kind" => "Deployment"}, {"name" => "deployments/scale", "kind" => "Scale"}]}
             else raise "no #{path}"
             end
      Struct.new(:body).new(JSON.generate(body))
    end
    tc = PTC.for_client(client)
    assert_equal [["apps", "v1", "Deployment"]], tc.types_to_check(policy(DEPLOYMENTS, []))
    assert_equal [], tc.call(policy(DEPLOYMENTS, [{"expression" => "object.spec.replicas > 1"}]))
  end

  # pkg/controller/validatingadmissionpolicystatus: observedGeneration and
  # typeChecking only ({} without warnings), nothing when up to date.
  def test_status_controller_writes_observed_generation_and_type_checking
    controller = Rubernetes::Controller::ValidatingAdmissionPolicyStatusController.new(name: "validatingadmissionpolicy-status-controller")
    resource = policy(DEPLOYMENTS, [{"expression" => "object.spec.replicas > '1'"}])
               .merge("apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "ValidatingAdmissionPolicy")
    resource["metadata"]["generation"] = 2
    result = controller.plan(resource, type_checker: checker)
    assert_equal 1, result.operations.length
    assert_equal %w[observedGeneration typeChecking], result.status.keys.sort
    assert_equal 2, result.status["observedGeneration"]
    assert_equal "spec.validations[0].expression", result.status.dig("typeChecking", "expressionWarnings", 0, "fieldRef")
    assert_empty result.events

    clean = Marshal.load(Marshal.dump(resource))
    clean["spec"]["validations"] = [{"expression" => "object.spec.replicas > 1"}]
    assert_equal({"observedGeneration" => 2, "typeChecking" => {}}, controller.plan(clean, type_checker: checker).status)

    resource["status"] = {"observedGeneration" => 2}
    assert_empty controller.plan(resource, type_checker: checker).operations
  end

  # CEL.g4 NUM_FLOAT: DIGIT+ '.' DIGIT+ EXPONENT? | DIGIT+ EXPONENT |
  # '.' DIGIT+ EXPONENT? -- a dot needs digits after it, so "2.size()" is a
  # call on the int 2.
  def test_float_literals_follow_the_cel_grammar
    lex = ->(text) { Rubernetes::Security::CEL::Lexer.new(text).tokens[0...-1].map { |token| [token.type, token.value] } }
    assert_equal [[:int, 1], [:operator, "."]], lex.call("1.")
    assert_equal [[:double, 1.0]], lex.call("1.0")
    assert_equal [[:int, 1], [:operator, "."], [:identifier, "e3"]], lex.call("1.e3")
    assert_equal [[:double, 1000.0]], lex.call("1e3")
    assert_equal [[:int, 2], [:operator, "."], [:identifier, "size"], [:operator, "("], [:operator, ")"]], lex.call("2.size()")
    assert_equal [[:double, 1.5], [:operator, "."], [:identifier, "size"], [:operator, "("], [:operator, ")"]], lex.call("1.5.size()")
    assert_equal [[:double, 0.5]], lex.call(".5")
  end
end
