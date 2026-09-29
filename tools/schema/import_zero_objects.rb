#!/usr/bin/env ruby
# frozen_string_literal: true

# Import the live object kube-apiserver's create handler gives the field
# manager (Creater.New(kind): the Go zero value, as structured-merge-diff
# reads it by reflection) for every built-in kind of v1.36.2 into
# schema/kubernetes/v1.36.2-defaults/zero_objects.json.  A struct field
# that is not a pointer is already there in it, so a create does not own it
# with "." -- which the OpenAPI schema alone cannot tell.
#
# The values come from test/conformance/kubernetes/zero_objects/
# zero_objects_test.go, compiled into k8s.io/kubernetes/pkg/api/legacyscheme
# through a go test overlay (the source tree stays unmodified).
#
# Usage: KUBERNETES_SOURCE_ROOT=/path/to/kubernetes-v1.36.2 ruby tools/schema/import_zero_objects.rb

require "json"
require "open3"
require "tmpdir"

module ZeroObjectsImporter
  ROOT = File.expand_path("../..", __dir__)
  OUTPUT = File.join(ROOT, "schema/kubernetes/v1.36.2-defaults/zero_objects.json")
  GENERATOR = File.join(ROOT, "test/conformance/kubernetes/zero_objects/zero_objects_test.go")

  module_function

  def source_root = File.realpath(ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2"))

  def main
    Dir.mktmpdir("zero-objects") do |dir|
      output = File.join(dir, "zero.json")
      overlay = File.join(dir, "overlay.json")
      target = File.join(source_root, "pkg/api/legacyscheme/zz_rubernetes_zero_objects_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => GENERATOR}))
      log, status = Open3.capture2e({"RUBERNETES_ZERO_OBJECTS_OUT" => output}, "go", "test", "-overlay", overlay,
                                    "k8s.io/kubernetes/pkg/api/legacyscheme", "-run", "TestRubernetesZeroObjects", "-count=1",
                                    chdir: source_root)
      abort("generator failed:\n#{log}") unless status.success?

      objects = JSON.parse(File.read(output))
      document = {"source" => "Creater.New + value.NewValueReflect (Kubernetes v1.36.2)", "objects" => objects.sort.to_h}
      File.write(OUTPUT, "#{JSON.pretty_generate(document)}\n")
      puts "#{objects.length} kinds -> #{OUTPUT}"
    end
  end
end

ZeroObjectsImporter.main if $PROGRAM_NAME == __FILE__
