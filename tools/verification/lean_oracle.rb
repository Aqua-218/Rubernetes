# frozen_string_literal: true

require "json"
require "open3"

module LeanOracle
  VERSION = "4.16.0"

  module_function

  def executable
    ENV.fetch("RUBERNETES_LEAN") do
      pinned = File.expand_path("~/.elan/toolchains/leanprover--lean4---v#{VERSION}/bin/lean")
      File.executable?(pinned) ? pinned : "lean"
    end
  end

  def run(source, cases, lean:)
    stdout, stderr, status = Open3.capture3(lean, "--run", source, stdin_data: JSON.generate(cases) << "\n")
    raise "#{File.basename(source)} oracle failed (#{status.exitstatus}): #{stderr} #{stdout}" unless status.success?

    outputs = JSON.parse(stdout)
    unless outputs.is_a?(Array) && outputs.length == cases.length
      raise "#{File.basename(source)} oracle must return one result for each of the #{cases.length} inputs"
    end

    outputs
  end
end
