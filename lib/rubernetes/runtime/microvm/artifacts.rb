# frozen_string_literal: true

require "digest"
require "json"
require "openssl"

require_relative "errors"

module Rubernetes
  module MicroVMArtifactDefaults
    LOCK_PATH = "third_party/locks/m7-microvm-artifacts.json"
  end

  module Runtime
    class MicroVM < Runtime
      # Pinned Firecracker/jailer, guest kernel, read-only rootfs, dm-verity
      # hash tree and root hash, and the Ruby guest bundle
      # (spec/node/runtime.md 5.8.11).  Every file's SHA-256, owner and mode
      # are verified against the lock before any effect; a mismatch is an
      # ArtifactError and nothing is started.
      class Artifacts
        REQUIRED = %w[firecracker jailer seccomp_filter kernel rootfs verity_hash].freeze
        Entry = Struct.new(:name, :path, :sha256, :bytes, keyword_init: true)

        attr_reader :lock, :root, :entries, :verity_root_hash, :firecracker_version, :guest_bundle_sha256

        def self.load(lock_path:, root:)
          document = JSON.parse(File.read(lock_path))
          new(document, root: root, lock_path: lock_path)
        end

        def initialize(document, root:, lock_path: nil)
          @lock = document
          @root = File.expand_path(root)
          @lock_path = lock_path
          raise ArtifactError, "artifact lock schema_version must be 1" unless document["schema_version"] == 1

          files = document["files"]
          raise ArtifactError, "artifact lock lists no files" unless files.is_a?(Hash) && !files.empty?

          missing = REQUIRED - files.keys
          raise ArtifactError, "artifact lock is missing #{missing.join(", ")}" unless missing.empty?

          @entries = files.to_h do |name, entry|
            unless entry.is_a?(Hash) && entry["path"].is_a?(String) && entry["sha256"].to_s.match?(/\A[0-9a-f]{64}\z/)
              raise ArtifactError,
                    "artifact #{name} entry is malformed"
            end

            [name, Entry.new(name: name, path: File.expand_path(entry["path"], @root), sha256: entry["sha256"], bytes: entry["bytes"])]
          end
          @verity_root_hash = document.dig("verity", "root_hash").to_s
          raise ArtifactError, "artifact lock has no dm-verity root hash" unless @verity_root_hash.match?(/\A[0-9a-f]{64}\z/)

          @firecracker_version = document.dig("firecracker", "version").to_s
          @guest_bundle_sha256 = document.dig("guest_bundle", "sha256").to_s
        end

        def path(name)
          entries.fetch(name.to_s) { raise ArtifactError, "unknown artifact #{name}" }.path
        end

        def sha256(name)
          entries.fetch(name.to_s).sha256
        end

        # Verifies digests, ownership (root) and modes (no group/world write)
        # of every locked file; returns the verification report.
        def verify!(expected_uid: 0)
          report = entries.map do |name, entry|
            raise ArtifactError, "artifact #{name} is missing at #{entry.path}" unless File.file?(entry.path)

            stat = File.stat(entry.path)
            raise ArtifactError, "artifact #{name} is owned by uid #{stat.uid}, expected #{expected_uid}" unless stat.uid == expected_uid
            unless stat.mode.nobits?(0o022)
              raise ArtifactError,
                    "artifact #{name} is group/world writable (mode #{format("%o", stat.mode & 0o777)})"
            end

            digest = self.class.file_digest(entry.path)
            raise ArtifactError, "artifact #{name} digest #{digest} does not match the lock #{entry.sha256}" unless digest == entry.sha256
            raise ArtifactError, "artifact #{name} size #{stat.size} does not match the lock" if entry.bytes && stat.size != entry.bytes

            parent = File.stat(File.dirname(entry.path))
            raise ArtifactError, "artifact #{name} parent directory is writable by others" unless parent.mode.nobits?(0o022)

            {"name" => name, "path" => entry.path, "sha256" => digest, "bytes" => stat.size, "uid" => stat.uid,
             "mode" => format("%o", stat.mode & 0o777)}
          end
          report.freeze
        end

        def digest
          Digest::SHA256.hexdigest(JSON.generate(entries.transform_values(&:sha256).sort.to_h.merge("verity_root_hash" => verity_root_hash)))
        end

        def self.file_digest(path, chunk: 8 * 1024 * 1024)
          digest = OpenSSL::Digest.new("SHA256")
          File.open(path, "rb") do |file|
            buffer = String.new(capacity: chunk)
            digest.update(buffer) while file.read(chunk, buffer)
          end
          digest.hexdigest
        end

        def to_h
          {"lock_path" => @lock_path, "firecracker_version" => firecracker_version, "verity_root_hash" => verity_root_hash,
           "guest_bundle_sha256" => guest_bundle_sha256,
           "files" => entries.transform_values { |entry| {"path" => entry.path, "sha256" => entry.sha256} },
           "digest" => digest}
        end
      end
    end
  end
end
