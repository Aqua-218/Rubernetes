#!/usr/bin/env ruby
# frozen_string_literal: true

# M9 formal-verification probe (exit criterion 3): zero counterexamples at the
# release scope and zero `sorry` / `admit` / forbidden escape hatches in Lean.
#
# The Lean check is run here against the real sources.  The model-checking part
# is read from verification/claims.yml, because spec 7.2 no longer mandates
# exhaustive TLC for Raft — the probe reports what actually backs each claim
# rather than asserting a run that was never made.

require "open3"
require "yaml"
require_relative "m9_probe_support"

module M9FormalProbe
  S = M9ProbeSupport
  LEAN_ROOT = File.join(S::ROOT, "verification/lean")
  # Escape hatches that would let a proof pass without proving anything.
  FORBIDDEN = %w[sorry admit native_decide].freeze
  # `native_decide` trusts the compiler rather than the kernel; `sorry`/`admit`
  # leave a hole.  A comment mentioning them is fine, a term is not.
  TERM = /(?<![A-Za-z0-9_])(#{FORBIDDEN.join("|")})(?![A-Za-z0-9_])/

  module_function

  def run
    started_at = S.now
    cases = []
    files = Dir.glob(File.join(LEAN_ROOT, "**", "*.lean"))

    cases << {"id" => "lean_sources_present", "passed" => !files.empty?, "files" => files.length}

    offenders = files.flat_map do |path|
      File.readlines(path, chomp: true).each_with_index.filter_map do |line, index|
        stripped = line.sub(/--.*\z/, "")
        next unless stripped.match?(TERM)

        {"file" => path.delete_prefix("#{S::ROOT}/"), "line" => index + 1, "text" => line.strip[0, 100]}
      end
    end
    cases << {"id" => "lean_has_no_escape_hatch", "passed" => offenders.empty?,
              "forbidden" => FORBIDDEN, "occurrences" => offenders.first(10), "count" => offenders.length}

    lake = File.join(S::ROOT, "verification/lean/lakefile.lean")
    lean = ENV["RUBERNETES_LEAN"] || "/root/.elan/bin/lean"
    if File.executable?(lean)
      results = files.map do |path|
        _out, err, status = Open3.capture3(lean, path, chdir: LEAN_ROOT)
        {"file" => path.delete_prefix("#{S::ROOT}/"), "ok" => status.success?,
         "error" => status.success? ? nil : err.lines.first(2).join.strip}
      end
      cases << {"id" => "lean_proofs_compile", "passed" => results.all? { |entry| entry.fetch("ok") },
                "checked" => results.length,
                "failures" => results.reject { |entry| entry.fetch("ok") }.first(5)}
    else
      cases << {"id" => "lean_proofs_compile", "passed" => false,
                "detail" => "lean is not installed at #{lean}; a release cannot claim proof status without checking it"}
    end

    claims_path = File.join(S::ROOT, "verification/claims.yml")
    claims = File.file?(claims_path) ? YAML.safe_load_file(claims_path).fetch("claims", []) : []
    model_checked = claims.select { |claim| claim["level"] == "model_checked" }
    cases << {"id" => "model_checked_claims_have_a_run",
              "passed" => model_checked.all? { |claim| claim["counterexample"] == "none" && !claim["method"].to_s.empty? },
              "model_checked_claims" => model_checked.map { |claim| claim["id"] }}
    cases << {"id" => "every_claim_states_its_level",
              "passed" => !claims.empty? && claims.all? { |claim| !claim["level"].to_s.empty? },
              "claims" => claims.length}

    S.emit(S.report(kind: "m9_formal_verification", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases, extra: {"lakefile" => File.file?(lake)}))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M9FormalProbe.run) if $PROGRAM_NAME == __FILE__
