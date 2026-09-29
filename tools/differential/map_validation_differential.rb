#!/usr/bin/env ruby
# frozen_string_literal: true

# MutatingAdmissionPolicy create validation's CEL compilation
# (Schema::KubernetesValidator#mutating_admission_policy_errors with
# Security::Admission::PolicyExpressionCompiler and the patch types) against
# upstream's ValidateMutatingAdmissionPolicy: random policies -- mutations
# (ApplyConfiguration Object{...} constructions, JSONPatch lists, wrong result
# and field types, jsonpatch.escapeKey), variables, matchConditions, random
# calls -- go to test/conformance/kubernetes/cel_typecheck_oracle/
# validation_test.go (TestRubernetesMutatingPolicyValidationOracle).  The
# errors of every CEL field must match exactly (free type variable indexes
# masked; syntax errors left out).
#
#   ruby tools/differential/map_validation_differential.rb [--seed N] [--cases N]

require_relative "vap_type_checking_differential"

module MAPValidationDifferential
  D = VAPTypeCheckingDifferential
  KV = Rubernetes::Schema::KubernetesValidator
  CEL_FIELD = /\A[^:]*\.expression: /
  APPLY = ["Object{metadata: Object.metadata{labels: {'a': 'b'}}}", "Object{spec: Object.spec{replicas: 3}}", "{'a': 1}",
           "Object{spec: 1}", "Object.spec{replicas: 'x'}", "Object{metadata: Object.metadata{labels: params.data}}",
           "Object{metadata: Object.metadata{annotations: {'v': string(variables.v0)}}}", "Object{}", "object",
           "Object{metadata: Object.metadata{name: object.metadata.name + 1}}", "Other{}", "JSONPatch{op: 'add'}",
           "Object{spec: Object.spec{template: Object.spec.template{spec: Object.spec.template.spec{containers: [Object.spec.template.spec.containers{name: 'c'}]}}}}"].freeze
  JSON_PATCH = ["[JSONPatch{op: 'add', path: '/metadata/labels/a', value: 'b'}]", "[JSONPatch{op: 1, path: '/a'}]", "JSONPatch{op: 'add', path: '/a'}",
                "[JSONPatch{op: 'add', path: '/metadata/labels/' + jsonpatch.escapeKey('a/b'), value: 'c'}]", "[]", "[{'op': 'add'}]",
                "[JSONPatch{op: 'test', path: '/spec/replicas', value: 1}, JSONPatch{op: 'replace', path: '/spec/replicas', value: params.x}]",
                "object.spec.containers.map(c, JSONPatch{op: 'add', path: '/x', value: c.name})", "[JSONPatch{op: 'add', path: 2}]",
                "[JSONPatch{op: 'remove', path: jsonpatch.escapeKey(1)}]"].freeze

  module_function

  def policy(random, index)
    vap = D.policy(random, index)
    spec = vap["spec"]
    rules = spec["matchConstraints"]["resourceRules"]
    rules.each { |rule| rule["operations"] = [D.pick(random, %w[CREATE UPDATE CREATE])]; rule["scope"] = "*" }
    mutations = Array.new(random.rand(1..3)) do
      if D.maybe(random, 0.5)
        {"patchType" => "ApplyConfiguration", "applyConfiguration" => {"expression" => D.maybe(random, 0.15) ? D.random_call(random) : D.pick(random, APPLY)}}
      else
        {"patchType" => "JSONPatch", "jsonPatch" => {"expression" => D.maybe(random, 0.15) ? D.random_call(random) : D.pick(random, JSON_PATCH)}}
      end
    end
    policy_spec = {"failurePolicy" => "Fail", "reinvocationPolicy" => D.pick(random, %w[Never IfNeeded]),
                   "matchConstraints" => spec["matchConstraints"].merge("matchPolicy" => "Equivalent", "namespaceSelector" => {}, "objectSelector" => {}),
                   "mutations" => mutations}
    policy_spec["paramKind"] = spec["paramKind"] if spec["paramKind"]
    policy_spec["variables"] = spec["variables"] if spec["variables"]
    if D.maybe(random, 0.3)
      policy_spec["matchConditions"] = [{"name" => "m0", "expression" => D.pick(random, ["object.metadata.name == 'a'", "'a'", "params.x == 1", "variables.v0 == 1"])}]
    end
    {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "MutatingAdmissionPolicy", "metadata" => {"name" => "m#{index}"}, "spec" => policy_spec}
  end

  def cel_errors(errors) = errors.select { |error| error.match?(CEL_FIELD) && !error.include?("Syntax error") }.map { |error| error.gsub(/\b_var\d+/, "_var#") }

  def run_port(policy)
    KV.mutating_admission_policy_errors(policy).map do |issue|
      cause = issue.to_cause(policy)
      "#{cause["field"]}: #{cause["message"]}"
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_927
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 300
    random = Random.new(seed)
    policies = Array.new(count) { |index| policy(random, index) }
    oracle = CELTypeCheckingImporter.run(CELTypeCheckingImporter::VALIDATION_PACKAGE, "TestRubernetesMutatingPolicyValidationOracle", policies)
    mismatches = policies.zip(oracle).filter_map do |policy, want|
      want = cel_errors(want)
      got = cel_errors(run_port(policy))
      [policy, want, got] unless got == want
    end
    mismatches.first(5).each do |policy, want, got|
      puts "MISMATCH #{JSON.generate(policy["spec"])[0, 1500]}"
      puts "  upstream: #{JSON.generate(want)[0, 1500]}"
      puts "  port:     #{JSON.generate(got)[0, 1500]}"
    end
    refused = oracle.count { |errors| cel_errors(errors).any? }
    puts "#{policies.length - mismatches.length}/#{policies.length} match (#{refused} with CEL errors)"
    mismatches.empty? ? 0 : 1
  end
end

exit(MAPValidationDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
