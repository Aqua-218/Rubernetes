#!/usr/bin/env ruby
# frozen_string_literal: true

# Import what ValidatingAdmissionPolicy type checking needs from upstream:
#
# * schema/kubernetes/v1.36.2-defaults/cel_declarations.json -- the CEL
#   environment typechecking.go compiles in: functions and overloads,
#   macros, variables, the request/namespace object types, type identifiers
#   and AST validators (test/conformance/kubernetes/cel_typecheck_oracle/
#   declarations_test.go in k8s.io/apiserver/.../policy/validating);
# * schema/kubernetes/v1.36.2-defaults/cel_type_definitions.json -- the
#   OpenAPI definitions kube-controller-manager's definitions schema resolver
#   reads for built-in kinds (GetOpenAPIDefinitions, descriptions dropped)
#   and the GVKs they map (typecheck_test.go in
#   k8s.io/kubernetes/pkg/controller/validatingadmissionpolicystatus).
#
# Both generators are compiled into the upstream packages through a go test
# overlay; the source tree stays unmodified.
#
# Usage: KUBERNETES_SOURCE_ROOT=/path/to/kubernetes-v1.36.2 ruby tools/schema/import_cel_type_checking.rb

require "json"
require "open3"
require "tmpdir"

module CELTypeCheckingImporter
  ROOT = File.expand_path("../..", __dir__)
  DEFAULTS = File.join(ROOT, "schema/kubernetes/v1.36.2-defaults")
  ORACLE_DIR = File.join(ROOT, "test/conformance/kubernetes/cel_typecheck_oracle")
  APISERVER_PACKAGE = ["k8s.io/apiserver/pkg/admission/plugin/policy/validating",
                       "staging/src/k8s.io/apiserver/pkg/admission/plugin/policy/validating", "declarations_test.go"].freeze
  KCM_PACKAGE = ["k8s.io/kubernetes/pkg/controller/validatingadmissionpolicystatus",
                 "pkg/controller/validatingadmissionpolicystatus", "typecheck_test.go"].freeze
  VALIDATION_PACKAGE = ["k8s.io/kubernetes/pkg/apis/admissionregistration/validation",
                        "pkg/apis/admissionregistration/validation", "validation_test.go"].freeze
  SCHEMA_KEYS = %w[type format properties additionalProperties items required enum default maxItems maxLength maxProperties
                   $ref allOf x-kubernetes-int-or-string x-kubernetes-embedded-resource x-kubernetes-preserve-unknown-fields
                   x-kubernetes-list-type].freeze

  module_function

  def source_root = File.realpath(ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2"))

  # Runs one generator test with RUBERNETES_ORACLE_IN/OUT; returns the
  # parsed output.  Shared with tools/differential/vap_type_checking_differential.rb.
  def run(package, test, input = nil)
    import_path, directory, file = package
    Dir.mktmpdir("cel-type-checking") do |dir|
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      env = {"RUBERNETES_ORACLE_OUT" => output}
      if input
        env["RUBERNETES_ORACLE_IN"] = File.join(dir, "in.json")
        File.write(env["RUBERNETES_ORACLE_IN"], JSON.generate(input))
      end
      target = File.join(source_root, directory, "zz_rubernetes_#{file}")
      File.write(overlay, JSON.generate("Replace" => {target => File.join(ORACLE_DIR, file)}))
      log, status = Open3.capture2e(env, "go", "test", "-overlay", overlay, import_path, "-run", "^#{test}$", "-count=1",
                                    chdir: source_root)
      abort("generator failed:\n#{log}") unless status.success?

      JSON.parse(File.read(output))
    end
  end

  # Only what SchemaDeclType and PopulateRefs read.
  def prune(schema)
    return schema unless schema.is_a?(Hash)

    out = schema.slice(*SCHEMA_KEYS)
    out["properties"] = out["properties"].transform_values { |property| prune(property) } if out["properties"].is_a?(Hash)
    out["items"] = prune(out["items"]) if out["items"].is_a?(Hash)
    out["additionalProperties"] = prune(out["additionalProperties"]) if out["additionalProperties"].is_a?(Hash)
    out["allOf"] = out["allOf"].map { |item| prune(item) } if out["allOf"].is_a?(Array)
    out
  end

  def main
    declarations = run(APISERVER_PACKAGE, "TestRubernetesCELDeclarations")
    declarations_document = {"source" => "typechecking.go buildEnvSet + NewCompositedCompilerForTypeChecking (Kubernetes v1.36.2)"}.merge(declarations)
    File.write(File.join(DEFAULTS, "cel_declarations.json"), "#{JSON.pretty_generate(declarations_document)}\n")
    definitions = run(KCM_PACKAGE, "TestRubernetesOpenAPIDefinitions")
    document = {"source" => "k8s.io/kubernetes/pkg/generated/openapi GetOpenAPIDefinitions (Kubernetes v1.36.2), descriptions dropped",
                "gvks" => definitions["gvks"].sort.to_h,
                "definitions" => definitions["definitions"].sort.to_h.transform_values { |schema| prune(schema) }}
    File.write(File.join(DEFAULTS, "cel_type_definitions.json"), "#{JSON.generate(document)}\n")
    puts "#{declarations["functions"].length} functions, #{document["definitions"].length} definitions"
  end
end

CELTypeCheckingImporter.main if $PROGRAM_NAME == __FILE__
