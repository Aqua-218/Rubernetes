#!/usr/bin/env ruby
# frozen_string_literal: true

# Ruby ratio of project-authored production source
# (spec/delivery/implementation-plan.md#sec-9-3: at least 85%).
#
# "Project-authored production source" is what this project ships and wrote
# itself: lib/, exe/ and the generated platform bindings it emits.  Vendored
# upstream trees, build output, fixtures, corpora and test/tooling code are not
# production source and are excluded with the reason recorded.

require "json"
require "optparse"
require "time"

module Release
  module LOCReport
    ROOT = File.expand_path("../..", __dir__)
    # `ext` holds the native extension: it is project-authored production
    # source and is counted, so the Ruby ratio is never inflated by leaving
    # the non-Ruby part of the shipped code out of the denominator.
    PRODUCTION_ROOTS = %w[lib exe ext].freeze
    EXCLUDED_ROOTS = %w[third_party build artifacts tmp pkg vendor .git node_modules].freeze
    # Language attribution by extension; anything else is counted as "other"
    # so the denominator is never quietly shrunk.
    LANGUAGES = {
      ".rb" => "Ruby", ".rbs" => "Ruby", ".rake" => "Ruby", ".ru" => "Ruby",
      ".c" => "C", ".h" => "C", ".go" => "Go", ".sh" => "Shell", ".bash" => "Shell",
      ".py" => "Python", ".yaml" => "Data", ".yml" => "Data", ".json" => "Data",
      ".md" => "Documentation", ".tla" => "TLA+", ".cfg" => "TLA+", ".lean" => "Lean"
    }.freeze
    # Code that is production but not Ruby by necessity: the native extension
    # that reaches syscalls Ruby cannot.  Counted, never hidden.
    NATIVE_NOTE = "native extension reaching syscalls the Ruby runtime does not expose"

    module_function

    def run(argv = ARGV)
      options = {output: nil}
      OptionParser.new { |parser| parser.on("--output PATH") { |v| options[:output] = v } }.parse!(argv)
      files = production_files
      by_language = Hash.new { |hash, key| hash[key] = {"files" => 0, "lines" => 0} }
      files.each do |path|
        language = LANGUAGES.fetch(File.extname(path), "Other")
        lines = count_lines(File.join(ROOT, path))
        by_language[language]["files"] += 1
        by_language[language]["lines"] += lines
      end
      total = by_language.values.sum { |entry| entry.fetch("lines") }
      ruby = by_language.dig("Ruby", "lines").to_i
      report = {
        "schema_version" => 1,
        "kind" => "release_ruby_loc_report",
        "generated_at" => Time.now.utc.iso8601,
        "definition" => {
          "production_roots" => PRODUCTION_ROOTS,
          "excluded_roots" => EXCLUDED_ROOTS,
          "counts" => "non-empty, non-comment lines",
          "native_extension_note" => NATIVE_NOTE
        },
        "by_language" => by_language.sort_by { |_language, entry| -entry.fetch("lines") }.to_h,
        "total_lines" => total,
        "ruby_lines" => ruby,
        "ruby_ratio" => total.zero? ? 0.0 : (ruby.to_f / total).round(6),
        "required_ratio" => 0.85,
        "passed" => total.positive? && (ruby.to_f / total) >= 0.85
      }
      output = options[:output] || File.join(ROOT, "artifacts/release/ruby-loc-report.json")
      require "fileutils"
      FileUtils.mkdir_p(File.dirname(output))
      File.write(output, "#{JSON.pretty_generate(report)}\n")
      puts JSON.pretty_generate(report.reject { |key, _| key == "definition" })
      report.fetch("passed") ? 0 : 1
    end

    def production_files
      PRODUCTION_ROOTS.flat_map do |root|
        Dir.glob(File.join(ROOT, root, "**", "*")).select { |path| File.file?(path) }
      end.map { |path| path.delete_prefix("#{ROOT}/") }
        .reject { |path| EXCLUDED_ROOTS.include?(path.split("/").first) }
        .sort
    end

    # Non-empty, non-comment lines: a comment-heavy file must not inflate a
    # language's share.
    def count_lines(path)
      comment = [".c", ".h"].include?(File.extname(path)) ? %r{\A\s*(//|/\*|\*)} : /\A\s*#/
      File.readlines(path, chomp: true).count { |line| !line.strip.empty? && !line.match?(comment) }
    rescue ArgumentError
      0
    end
  end
end

exit(Release::LOCReport.run) if $PROGRAM_NAME == __FILE__
