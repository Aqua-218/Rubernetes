#!/usr/bin/env ruby
# frozen_string_literal: true

# Release security report (spec/delivery/milestones.md#milestone-m9 exit 6):
# zero critical/high findings, zero unreviewed dependencies, zero unpinned
# production or test inputs.
#
# The scan is over what this repository actually controls: the dependency set,
# the pinned upstream inputs, and the security claims in the assurance ledger.
# A check that cannot run reports itself as unavailable rather than passing.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"
require "yaml"

module Release
  module SecurityReport
    ROOT = File.expand_path("../..", __dir__)

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/release/security-report.json")}
      OptionParser.new { |parser| parser.on("--output PATH") { |v| options[:output] = v } }.parse!(argv)

      cases = [dependency_audit, dependency_review, pinned_inputs, claim_levels, unresolved_markers]
      report = {
        "schema_version" => 1,
        "kind" => "release_security_report",
        "generated_at" => Time.now.utc.iso8601,
        "cases" => cases,
        "critical_or_high" => cases.sum { |entry| entry["critical_or_high"].to_i },
        "passed" => cases.all? { |entry| entry.fetch("passed") }
      }
      FileUtils.mkdir_p(File.dirname(options[:output]))
      File.write(options[:output], "#{JSON.pretty_generate(report)}\n")
      puts JSON.pretty_generate(report)
      report.fetch("passed") ? 0 : 1
    end

    # bundler-audit against the pinned advisory database when it is available.
    def dependency_audit
      # bundler-audit may be installed into the Ruby prefix rather than onto
      # PATH, so the prefix's bin directory is searched too.
      binary = ENV["RUBERNETES_BUNDLER_AUDIT"] ||
               %w[bundler-audit bundle-audit].map { |name| which(name) }.compact.first ||
               %w[bundler-audit bundle-audit]
                 .map { |name| File.join(RbConfig::CONFIG["bindir"], name) }
                 .find { |path| File.executable?(path) }
      if binary.nil?
        return {"id" => "dependency_audit", "passed" => false, "available" => false,
                "detail" => "bundler-audit is not installed; a release cannot claim zero advisories without running it"}
      end

      stdout, stderr, status = Open3.capture3(binary, "check", "--format", "json", chdir: ROOT)
      document = JSON.parse(stdout) rescue nil
      if document.nil? && !status.success? && !stderr.empty?
        return {"id" => "dependency_audit", "passed" => false, "available" => true,
                "detail" => stderr.lines.last(3).join.strip}
      end
      results = document ? Array(document["results"]) : []
      severe = results.count { |entry| %w[critical high].include?(entry.dig("advisory", "criticality").to_s.downcase) }
      {"id" => "dependency_audit", "passed" => severe.zero?, "available" => true,
       "findings" => results.length, "critical_or_high" => severe}
    rescue Errno::ENOENT
      {"id" => "dependency_audit", "passed" => false, "available" => false,
       "detail" => "bundler is not available to run bundler-audit"}
    end

    # Every runtime dependency must be declared with an explicit version.
    def dependency_review
      gemspec = Dir.glob(File.join(ROOT, "*.gemspec")).first
      declared = gemspec ? File.read(gemspec).scan(/add_(?:runtime_)?dependency\s+["']([^"']+)["']\s*,\s*["']([^"']+)["']/) : []
      unpinned = gemspec ? File.read(gemspec).scan(/add_(?:runtime_)?dependency\s+["']([^"']+)["']\s*\)/).flatten : []
      {"id" => "dependency_review", "passed" => unpinned.empty?,
       "declared" => declared.length, "unversioned" => unpinned}
    end

    # Locks must pin by digest or commit, never by a floating tag alone.
    def pinned_inputs
      unpinned = []
      Dir.glob(File.join(ROOT, "third_party/locks/*.json")).sort.each do |path|
        document = JSON.parse(File.read(path)) rescue next
        walk(document) do |trail, value|
          next unless value.is_a?(Hash)
          next unless value.key?("reference") || value.key?("url")
          # A node is pinned when it carries a digest or commit under any of the
          # spellings the locks use, or when its reference already names a
          # digest.  Missing one of these would fail a release for an input
          # that is in fact pinned.
          next if %w[sha256 digest index_digest commit reference_by_digest digest_reference
                     tag_object image_id].any? { |key| !value[key].to_s.empty? }
          # Locks also spell digests as `<thing>_sha256` (archive_sha256,
          # executable_sha256); those pin just as firmly.
          next if value.any? { |key, child| key.to_s.end_with?("_sha256") && !child.to_s.empty? }
          next if value.values.any? { |child| child.is_a?(String) && child.include?("@sha256:") }
          next if value.dig("image", "index_digest") || value.dig("image", "reference").to_s.include?("@sha256:")

          unpinned << "#{File.basename(path)}:#{trail.join("/")}"
        end
      end
      {"id" => "pinned_inputs", "passed" => unpinned.empty?, "unpinned" => unpinned}
    end

    # Every security claim must state its assurance level.
    def claim_levels
      path = File.join(ROOT, "verification/claims.yml")
      return {"id" => "claim_levels", "passed" => false, "detail" => "verification/claims.yml is missing"} unless File.file?(path)

      claims = YAML.safe_load(File.read(path)).fetch("claims", [])
      levels = %w[proved model_checked differentially_tested integration_tested assumed_tcb]
      missing = claims.reject { |claim| levels.include?(claim["level"]) }
      {"id" => "claim_levels", "passed" => missing.empty?,
       "claims" => claims.length, "without_level" => missing.map { |claim| claim["id"] }}
    end

    # Undated TODO/FIXME markers in production source are forbidden at release.
    def unresolved_markers
      markers = []
      %w[lib exe ext].each do |root|
        Dir.glob(File.join(ROOT, root, "**", "*.rb")).sort.each do |path|
          File.readlines(path, chomp: true).each_with_index do |line, index|
            next unless line.match?(/\b(TODO|FIXME|XXX|HACK)\b/)
            next if line.match?(/\b\d{4}-\d{2}-\d{2}\b/)

            markers << "#{path.delete_prefix("#{ROOT}/")}:#{index + 1}"
          end
        end
      end
      {"id" => "unresolved_markers", "passed" => markers.empty?, "markers" => markers.first(20),
       "marker_count" => markers.length}
    end

    def which(name)
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR)
         .map { |dir| File.join(dir, name) }.find { |path| File.executable?(path) }
    end

    def walk(node, trail = [], &block)
      block.call(trail, node)
      return unless node.is_a?(Hash)

      node.each { |key, value| walk(value, trail + [key], &block) }
    end
  end
end

exit(Release::SecurityReport.run) if $PROGRAM_NAME == __FILE__
