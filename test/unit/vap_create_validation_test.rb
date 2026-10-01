# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"
require "rubernetes/schema/kubernetes_validator"

# The CEL compilation ValidateValidatingAdmissionPolicy runs on create and
# update (validateCELCondition).  Expected strings are what upstream's
# validation printed for the same policies (test/conformance/kubernetes/
# cel_typecheck_oracle/validation_test.go);
# tools/differential/vap_validation_differential.rb compares random ones.
class VAPCreateValidationTest < Minitest::Test
  KV = Rubernetes::Schema::KubernetesValidator

  def policy(validations, **spec)
    {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "ValidatingAdmissionPolicy", "metadata" => {"name" => "p"},
     "spec" => {"failurePolicy" => "Fail",
                "matchConstraints" => {"matchPolicy" => "Equivalent", "namespaceSelector" => {}, "objectSelector" => {},
                                       "resourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "resources" => ["deployments"],
                                                            "operations" => ["CREATE"], "scope" => "*"}]},
                "validations" => validations}.merge(spec.transform_keys(&:to_s))}
  end

  def errors(object)
    KV.validating_admission_policy_errors(object).map do |issue|
      cause = issue.to_cause(object)
      "#{cause["field"]}: #{cause["message"]}"
    end
  end

  def test_result_types_and_declarations_per_field
    assert_equal ["spec.validations[0].expression: Invalid value: \"object.spec.paused\": must evaluate to bool but got dyn"],
                 errors(policy([{"expression" => "object.spec.paused"}]))
    assert_equal ["spec.validations[0].expression: Invalid value: \"1\": must evaluate to bool but got int",
                  "spec.validations[0].messageExpression: Invalid value: \"authorizer.path('/x').check('get').reason()\": compilation failed: " \
                  "ERROR: <input>:1:1: undeclared reference to 'authorizer' (in container '')\n | authorizer.path('/x').check('get').reason()\n | ^"],
                 errors(policy([{"expression" => "1", "messageExpression" => "authorizer.path('/x').check('get').reason()"}]))
    assert_equal ["spec.validations[0].expression: Invalid value: \"params.x == 1\": compilation failed: " \
                  "ERROR: <input>:1:1: undeclared reference to 'params' (in container '')\n | params.x == 1\n | ^"],
                 errors(policy([{"expression" => "params.x == 1"}]))
    assert_equal ["spec.matchConditions[0].expression: Invalid value: \"'a'\": must evaluate to bool but got string",
                  "spec.auditAnnotations[0].valueExpression: Invalid value: \"1\": must evaluate to one of [string null_type] but got int"],
                 errors(policy([{"expression" => "true"}], auditAnnotations: [{"key" => "a", "valueExpression" => "1"}],
                                                           matchConditions: [{"name" => "m", "expression" => "'a'"}]))
  end

  # Without variables there is no composition: "variables" is undeclared;
  # with them each variable is typed for the expressions after it.
  def test_variables_compose_only_when_declared
    assert_equal ["spec.validations[0].expression: Invalid value: \"variables.x > 1\": compilation failed: " \
                  "ERROR: <input>:1:1: undeclared reference to 'variables' (in container '')\n | variables.x > 1\n | ^"],
                 errors(policy([{"expression" => "variables.x > 1"}]))
    assert_empty errors(policy([{"expression" => "variables.x > 1"}], variables: [{"name" => "x", "expression" => "object.spec.replicas"}]))
    assert_equal ["spec.validations[0].expression: Invalid value: \"variables.x > 1\": compilation failed: " \
                  "ERROR: <input>:1:13: found no matching overload for '_>_' applied to '(string, int)'\n | variables.x > 1\n | ............^"],
                 errors(policy([{"expression" => "variables.x > 1"}], variables: [{"name" => "x", "expression" => "'a'"}]))
  end

  # ValidateMutatingAdmissionPolicy: mutations compile with the patch types
  # (Object, Object.<path>, JSONPatch, jsonpatch.escapeKey) in a composition
  # compiler (variables always declared).
  def test_mutating_policy_mutations_compile_with_patch_types
    mutations = [{"patchType" => "ApplyConfiguration", "applyConfiguration" => {"expression" => "Object{metadata: Object.metadata{labels: {'a': 'b'}}}"}},
                 {"patchType" => "ApplyConfiguration", "applyConfiguration" => {"expression" => " {'a': 1} "}},
                 {"patchType" => "JSONPatch", "jsonPatch" => {"expression" => "[JSONPatch{op: 1, path: '/a'}]"}},
                 {"patchType" => "JSONPatch", "jsonPatch" => {"expression" => "[]"}},
                 {"patchType" => "JSONPatch",
                  "jsonPatch" => {"expression" => "[JSONPatch{op: 'add', path: '/metadata/labels/' + jsonpatch.escapeKey('a/b'), value: variables.x}]"}}]
    mutating = {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "MutatingAdmissionPolicy", "metadata" => {"name" => "m"},
                "spec" => policy([])["spec"].except("validations").merge("reinvocationPolicy" => "Never", "mutations" => mutations)}
    errors = KV.mutating_admission_policy_errors(mutating).map do |issue|
      cause = issue.to_cause(mutating)
      "#{cause["field"]}: #{cause["message"]}"
    end

    assert_equal ["spec.mutations[1].applyConfiguration.expression: Invalid value: \"{'a': 1}\": must evaluate to Object but got map(string, int)",
                  "spec.mutations[2].jsonPatch.expression: Invalid value: \"[JSONPatch{op: 1, path: '/a'}]\": compilation failed: ERROR: <input>:1:14: " \
                  "expected type of field 'op' is 'string' but provided type is 'int'\n | [JSONPatch{op: 1, path: '/a'}]\n | .............^",
                  "spec.mutations[3].jsonPatch.expression: Invalid value: \"[]\": must evaluate to list(JSONPatch) but got list(dyn)",
                  "spec.mutations[4].jsonPatch.expression: Invalid value: \"[JSONPatch{op: 'add', path: '/metadata/labels/' + jsonpatch.escapeKey('a/b'), " \
                  "value: variables.x}]\": compilation failed: ERROR: <input>:1:95: undefined field 'x'\n | [JSONPatch{op: 'add', path: '/metadata/labels/' " \
                  "+ " \
                  "jsonpatch.escapeKey('a/b'), value: variables.x}]\n | " \
                  "..............................................................................................^"],
                 errors
  end

  # cel.OptOptimize: a conversion of a constant is evaluated when the program
  # is planned, and its failure is an internal error.
  def test_constant_conversions_fail_program_instantiation
    assert_equal ["spec.validations[0].expression: Internal error: program instantiation failed: type conversion error from 'string' to 'bool'"],
                 errors(policy([{"expression" => "bool('10.0.0.0/8')"}]))
    assert_equal ["spec.validations[0].expression: Internal error: program instantiation failed: unsigned integer overflow"],
                 errors(policy([{"expression" => "true || (uint(-0.5) != dyn(1))"}]))
    assert_equal ["spec.validations[0].expression: Internal error: program instantiation failed: no such overload: bool(int)"],
                 errors(policy([{"expression" => "has(object.apiVersion) || bool(dyn(1))"}]))
  end
end
