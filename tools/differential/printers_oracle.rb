# frozen_string_literal: true

# Runs test/conformance/kubernetes/printers_oracle (compiled into
# pkg/printers/internalversion of the pinned source through a go test
# overlay) on one input document and returns its parsed output.  Shared by
# tools/schema/import_table_columns.rb and the printer differential.

require "json"
require "open3"
require "tmpdir"

module PrintersOracle
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/printers_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")

  module_function

  def run(input)
    Dir.mktmpdir("printers-oracle") do |dir|
      source = File.realpath(SOURCE)
      in_path = File.join(dir, "in.json")
      out_path = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(in_path, JSON.generate(input))
      target = File.join(source, "pkg/printers/internalversion/zz_rubernetes_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      # The overlay applies only when go resolves the package under the real
      # path: from a symlinked checkout the test file is silently absent.
      output, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => in_path, "RUBERNETES_ORACLE_OUT" => out_path},
                                       "go", "test", "-overlay", overlay, "./pkg/printers/internalversion",
                                       "-run", "TestRubernetesPrintersOracle", "-count=1", chdir: source)
      raise "printers oracle failed:\n#{output}" unless status.success? && File.file?(out_path)

      JSON.parse(File.read(out_path))
    end
  end
end
