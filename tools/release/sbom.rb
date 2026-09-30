#!/usr/bin/env ruby
# frozen_string_literal: true

# CycloneDX 1.5 SBOM for the release artifact
# (spec/delivery/milestones.md#milestone-m9 required evidence).
#
# Every component is described from something on disk or from a pinned lock —
# never from a network query at build time — so the same source tree always
# produces the same SBOM.

require "digest"
require "fileutils"
require "json"
require "optparse"
require "time"
require "yaml"

module Release
  module SBOM
    ROOT = File.expand_path("../..", __dir__)
    LOCK_DIR = File.join(ROOT, "third_party/locks")

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/release/sbom.cdx.json"), serial: nil}
      OptionParser.new do |parser|
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--serial UUID", "deterministic serial number") { |v| options[:serial] = v }
      end.parse!(argv)

      components = project_component_files + gem_components + locked_components
      document = {
        "bomFormat" => "CycloneDX",
        "specVersion" => "1.5",
        "serialNumber" => "urn:uuid:#{options[:serial] || deterministic_uuid(components)}",
        "version" => 1,
        "metadata" => {
          # A fixed timestamp keeps the SBOM byte-identical for the same input;
          # the release manifest carries the real build time.
          "timestamp" => "1970-01-01T00:00:00Z",
          "component" => {
            "type" => "application",
            "name" => "rubernetes",
            "version" => project_version,
            "purl" => "pkg:gem/rubernetes@#{project_version}"
          },
          "tools" => [{"vendor" => "rubernetes", "name" => "tools/release/sbom.rb", "version" => "1"}]
        },
        "components" => components
      }
      FileUtils.mkdir_p(File.dirname(options[:output]))
      File.write(options[:output], "#{JSON.pretty_generate(document)}\n")
      puts JSON.pretty_generate({"components" => components.length,
                                 "by_type" => components.group_by { |c| c["type"] }.transform_values(&:length),
                                 "output" => options[:output].delete_prefix("#{ROOT}/"),
                                 "sha256" => Digest::SHA256.file(options[:output]).hexdigest})
      0
    end

    def project_version
      gemspec = Dir.glob(File.join(ROOT, "*.gemspec")).first
      return "0.0.0" if gemspec.nil?

      File.read(gemspec)[/version\s*=\s*["']([^"']+)["']/, 1] ||
        (File.file?(File.join(ROOT, "lib/rubernetes/version.rb")) &&
         File.read(File.join(ROOT, "lib/rubernetes/version.rb"))[/VERSION\s*=\s*["']([^"']+)["']/, 1]) || "0.0.0"
    end

    # The shipped source itself, as one component per production file so a
    # consumer can verify any single file against the SBOM.
    def project_component_files
      %w[lib exe ext].flat_map do |root|
        Dir.glob(File.join(ROOT, root, "**", "*")).select { |path| File.file?(path) }
      end.sort.map do |path|
        relative = path.delete_prefix("#{ROOT}/")
        {
          "type" => "file",
          "name" => relative,
          "version" => project_version,
          "hashes" => [{"alg" => "SHA-256", "content" => Digest::SHA256.file(path).hexdigest}]
        }
      end
    end

    def gem_components
      lock = File.join(ROOT, "Gemfile.lock")
      return [] unless File.file?(lock)

      File.read(lock).scan(/^\s{4}([a-zA-Z0-9_\-.]+) \(([^)]+)\)$/).uniq.map do |name, version|
        {"type" => "library", "name" => name, "version" => version,
         "purl" => "pkg:gem/#{name}@#{version}", "scope" => "required"}
      end
    end

    # Pinned upstream inputs: tools, images and corpora the release depends on.
    def locked_components
      Dir.glob(File.join(LOCK_DIR, "*.json")).flat_map do |path|
        document = begin
          JSON.parse(File.read(path))
        rescue StandardError
          nil
        end
        next [] unless document.is_a?(Hash)

        flatten_lock(document, File.basename(path))
      end
    end

    def flatten_lock(document, source, prefix = [])
      document.flat_map do |key, value|
        case value
        when Hash
          if value["sha256"] || value["digest"] || value["index_digest"] || value["commit"]
            [{
              "type" => "library",
              "name" => (prefix + [key]).join("/"),
              "version" => value["tag"] || value["version"] || value["commit"] || "pinned",
              "hashes" => [{"alg" => "SHA-256",
                            "content" => (value["sha256"] || value["digest"] || value["index_digest"] ||
                                          value["commit"]).to_s.delete_prefix("sha256:")}].reject { |hash| hash["content"].empty? },
              "properties" => [{"name" => "lock", "value" => source}]
            }] + flatten_lock(value, source, prefix + [key])
          else
            flatten_lock(value, source, prefix + [key])
          end
        else []
        end
      end
    end

    def deterministic_uuid(components)
      digest = Digest::SHA256.hexdigest(JSON.generate(components))
      [digest[0, 8], digest[8, 4], "5#{digest[13, 3]}", "8#{digest[17, 3]}", digest[20, 12]].join("-")
    end
  end
end

exit(Release::SBOM.run) if $PROGRAM_NAME == __FILE__
