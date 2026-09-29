#!/usr/bin/env ruby
# frozen_string_literal: true

# ValidatingAdmissionPolicy create validation's CEL compilation
# (Schema::KubernetesValidator#validating_admission_policy_errors with
# Security::Admission::PolicyExpressionCompiler) against upstream's
# ValidateValidatingAdmissionPolicy: the random policies of
# vap_type_checking_differential.rb (plus matchConditions, auditAnnotations
# and variables) go to test/conformance/kubernetes/cel_typecheck_oracle/
# validation_test.go (compiled into k8s.io/kubernetes/pkg/apis/
# admissionregistration/validation through a go test overlay, v1 defaults
# applied first).  The errors of every CEL field (expression,
# messageExpression, valueExpression) must match exactly; free type variable
# indexes are masked (nondeterministic upstream).  Syntax errors are left out:
# the port does not reproduce ANTLR's recovery messages.
#
#   ruby tools/differential/vap_validation_differential.rb [--seed N] [--cases N]

require_relative "vap_type_checking_differential"

module VAPValidationDifferential
  D = VAPTypeCheckingDifferential
  KV = Rubernetes::Schema::KubernetesValidator
  CEL_FIELD = /\A[^:]*\.(expression|messageExpression|valueExpression): /

  module_function

  def policy(random, index)
    policy = D.policy(random, index)
    spec = policy["spec"]
    spec["failurePolicy"] = "Fail"
    spec["matchConstraints"].merge!("matchPolicy" => "Equivalent", "namespaceSelector" => {}, "objectSelector" => {})
    spec["matchConstraints"]["resourceRules"].each { |rule| rule["scope"] = "*" }
    if D.maybe(random, 0.3)
      spec["matchConditions"] = Array.new(random.rand(1..2)) do |i|
        {"name" => "m#{i}", "expression" => D.pick(random, [" object.metadata.name == 'a' ", "'a'", "params.x == 1", "request.operation == 'CREATE'",
                                                            "authorizer.group('').resource('pods').check('get').allowed()", "variables.v0 == 1", "object.spec"])}
      end
    end
    if D.maybe(random, 0.3)
      spec["auditAnnotations"] = [{"key" => "a", "valueExpression" => D.pick(random, ["'x'", "null", "1", " object.metadata.name ", "params.x", "variables.v0", "object.spec"])}]
    end
    policy
  end

  def cel_errors(errors) = errors.select { |error| error.match?(CEL_FIELD) && !error.include?("Syntax error") }.map { |error| error.gsub(/\b_var\d+/, "_var#") }

  def run_port(policy)
    KV.validating_admission_policy_errors(policy).map do |issue|
      cause = issue.to_cause(policy)
      "#{cause["field"]}: #{cause["message"]}"
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_927
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 300
    random = Random.new(seed)
    policies = Array.new(count) { |index| policy(random, index) }
    oracle = CELTypeCheckingImporter.run(CELTypeCheckingImporter::VALIDATION_PACKAGE, "TestRubernetesPolicyValidationOracle", policies)
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

exit(VAPValidationDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
