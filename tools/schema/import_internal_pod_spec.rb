#!/usr/bin/env ruby
# frozen_string_literal: true

# Import the layout of the internal core.PodSpec (and of v1.PodSpec) into
# schema/kubernetes/v1.36.2-defaults/internal_pod_spec_layout.json: the
# field order and keys encoding/json prints for the internal type, the v1
# json key each field is converted from, and the v1 types.  ValidatePodUpdate
# refuses a spec change with diff.Diff of the internal specs, and that text
# (line numbers included) depends on every field of the internal type.
#
# The layout comes from test/conformance/kubernetes/internal_pod_spec/
# internal_pod_spec_test.go, compiled into k8s.io/kubernetes/pkg/apis/core/v1
# through a go test overlay (the source tree stays unmodified).
#
# Usage: KUBERNETES_SOURCE_ROOT=/path/to/kubernetes-v1.36.2 ruby tools/schema/import_internal_pod_spec.rb

require "json"
require "open3"
require "tmpdir"

module InternalPodSpecImporter
  ROOT = File.expand_path("../..", __dir__)
  OUTPUT = File.join(ROOT, "schema/kubernetes/v1.36.2-defaults/internal_pod_spec_layout.json")
  GENERATOR = File.join(ROOT, "test/conformance/kubernetes/internal_pod_spec/internal_pod_spec_test.go")
  PACKAGE = "k8s.io/kubernetes/pkg/apis/core/v1"

  module_function

  def source_root = File.realpath(ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2"))

  # Runs one test of the generator with RUBERNETES_ORACLE_IN/OUT; returns the
  # parsed output.  Shared with tools/differential/pod_update_diff_differential.rb.
  def run(test, input = nil)
    Dir.mktmpdir("internal-pod-spec") do |dir|
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      env = {"RUBERNETES_ORACLE_OUT" => output}
      if input
        env["RUBERNETES_ORACLE_IN"] = File.join(dir, "in.json")
        File.write(env["RUBERNETES_ORACLE_IN"], JSON.generate(input))
      end
      target = File.join(source_root, "pkg/apis/core/v1/zz_rubernetes_internal_pod_spec_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => GENERATOR}))
      log, status = Open3.capture2e(env, "go", "test", "-overlay", overlay, PACKAGE, "-run", "^#{test}$", "-count=1",
                                    chdir: source_root)
      abort("generator failed:\n#{log}") unless status.success?

      JSON.parse(File.read(output))
    end
  end

  def main
    layout = run("TestRubernetesInternalPodSpecLayout")
    document = {"source" => "reflect over k8s.io/kubernetes/pkg/apis/core.PodSpec and k8s.io/api/core/v1.PodSpec (Kubernetes v1.36.2)"}
    document.merge!(layout.merge("types" => layout["types"].sort.to_h, "pairs" => layout["pairs"].sort.to_h))
    File.write(OUTPUT, "#{JSON.pretty_generate(document)}\n")
    puts "#{layout["types"].length} types -> #{OUTPUT}"
  end
end

InternalPodSpecImporter.main if $PROGRAM_NAME == __FILE__
