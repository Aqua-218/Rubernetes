#!/usr/bin/env ruby
# frozen_string_literal: true

# release-manifest.json: the identity of a 1.0.0 release
# (spec/delivery/milestones.md#milestone-m9 required evidence).
#
# Binds the source input digest, the built artifacts, the SBOM, the pinned
# upstream inputs and the evidence bundles a consumer needs to re-verify the
# release from the same input SHA-256.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

module Release
  module Manifest
    ROOT = File.expand_path("../..", __dir__)
    SOURCE_ROOTS = %w[lib exe ext tools spec test verification generated schema].freeze
    EXCLUDED = %w[third_party build artifacts tmp pkg vendor .git].freeze

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/release/release-manifest.json"),
                 version: nil, artifacts: [], evidence: {}}
      OptionParser.new do |parser|
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--version VERSION") { |v| options[:version] = v }
        parser.on("--artifact PATH", "built artifact to bind (repeatable)") { |v| options[:artifacts] << v }
        parser.on("--evidence NAME=PATH", "milestone evidence manifest (repeatable)") do |v|
          name, path = v.split("=", 2)
          options[:evidence][name] = path
        end
      end.parse!(argv)

      inventory = source_inventory
      document = {
        "schema_version" => 1,
        "kind" => "release_manifest",
        "name" => "rubernetes",
        "version" => options[:version] || detect_version,
        "generated_at" => Time.now.utc.iso8601,
        "source" => {
          "input_sha256" => inventory_digest(inventory),
          "input_file_count" => inventory.length,
          "roots" => SOURCE_ROOTS,
          "excluded_roots" => EXCLUDED,
          "vcs" => vcs_identity
        },
        "build" => {
          "ruby" => RUBY_DESCRIPTION,
          "platform" => RbConfig::CONFIG["host"],
          "reproducible" => "byte-identical rebuild from the same input_sha256 is verified by tools/release/reproduce.rb"
        },
        "artifacts" => options[:artifacts].map { |path| artifact_entry(path) },
        "sbom" => artifact_entry(File.join(ROOT, "artifacts/release/sbom.cdx.json")),
        "pinned_inputs" => Dir.glob(File.join(ROOT, "third_party/locks/*.json")).sort.map { |path| artifact_entry(path) },
        "evidence" => options[:evidence].transform_values { |path| artifact_entry(path) },
        "source_inventory" => inventory
      }
      FileUtils.mkdir_p(File.dirname(options[:output]))
      File.write(options[:output], "#{JSON.pretty_generate(document)}\n")
      puts JSON.pretty_generate(document.reject { |key, _| key == "source_inventory" })
      0
    end

    def detect_version
      path = File.join(ROOT, "lib/rubernetes/version.rb")
      (File.file?(path) && File.read(path)[/VERSION\s*=\s*["']([^"']+)["']/, 1]) || "0.0.0"
    end

    def source_inventory
      SOURCE_ROOTS.flat_map do |root|
        Dir.glob(File.join(ROOT, root, "**", "*")).select { |path| File.file?(path) }
      end.map { |path| path.delete_prefix("#{ROOT}/") }
         .reject { |path| EXCLUDED.include?(path.split("/").first) }
         .sort
         .map { |path| {"path" => path, "sha256" => Digest::SHA256.file(File.join(ROOT, path)).hexdigest} }
    end

    # Same canonical form the milestone gates use: path, NUL, digest.
    def inventory_digest(entries)
      digest = Digest::SHA256.new
      entries.each do |entry|
        digest << entry.fetch("path")
        digest << "\0"
        digest << entry.fetch("sha256")
        digest << "\0"
      end
      digest.hexdigest
    end

    def artifact_entry(path)
      return nil if path.nil?

      absolute = File.absolute_path?(path) ? path : File.join(ROOT, path)
      return {"path" => path, "present" => false} unless File.file?(absolute)

      {"path" => absolute.delete_prefix("#{ROOT}/"), "present" => true,
       "bytes" => File.size(absolute), "sha256" => Digest::SHA256.file(absolute).hexdigest}
    end

    def vcs_identity
      out, _err, status = Open3.capture3("git", "-C", ROOT, "rev-parse", "HEAD")
      return {"kind" => "git", "commit" => out.strip} if status.success? && out.strip.match?(/\A[0-9a-f]{40}\z/)

      {"kind" => "content-addressed",
       "note" => "this tree has no git metadata; the release is identified by source.input_sha256"}
    end
  end
end

exit(Release::Manifest.run) if $PROGRAM_NAME == __FILE__
