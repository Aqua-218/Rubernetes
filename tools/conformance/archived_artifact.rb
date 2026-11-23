# frozen_string_literal: true

require "digest"

module Conformance
  # The runner records paths inside its own cluster fixture. Resolve the known
  # lane-relative name next to the manifest, including after archiving it.
  module ArchivedArtifact
    class Invalid < StandardError; end
    class Missing < Invalid; end

    module_function

    def verify!(manifest, lane, directory, name)
      digests = [manifest, lane].map { |record| recorded_digests(record, name) }
      raise Missing, "missing artifact reference: #{name}" if digests.any?(&:empty?)
      unless digests.first.one? && digests.first == digests.last && /\A[0-9a-f]{64}\z/.match?(digests.first.first.to_s)
        raise Invalid, "conflicting artifact references: #{name}"
      end

      path = File.join(directory, name)
      raise Missing, "original artifact is missing: #{name}" unless File.exist?(path)
      unless File.realpath(path) == path && File.file?(path) && Digest::SHA256.file(path).hexdigest == digests.first.first
        raise Invalid, "original artifact does not match its recorded SHA-256: #{name}"
      end

      path
    end

    def verify_format!(manifest, lane, directory, name)
      original = name.delete_suffix(".gz")
      variants = [original, "#{original}.gz"].select do |variant|
        [manifest, lane].any? { |record| !references(record, variant).empty? }
      end
      raise Missing, "missing artifact reference: #{name}" if variants.empty?
      raise Invalid, "conflicting storage formats for #{original}" unless variants == [name]

      verify!(manifest, lane, directory, name)
    end

    def recorded_digests(record, name)
      references(record, name).map { |entry| entry.fetch("sha256", "").to_s }
    end

    def references(record, name)
      Array(record["artifacts"]).grep(Hash).select do |entry|
        path = entry["path"]
        path.is_a?(String) && (path == name || path.end_with?("/#{name}"))
      end
    end
  end
end
