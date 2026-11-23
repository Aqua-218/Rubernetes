# frozen_string_literal: true

require "digest"
require "openssl"
require "fileutils"
require "json"
require "time"

require_relative "errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Base snapshot pool (spec/node/runtime.md 5.8.12).  A base is taken
      # only from a WorkloadStopped VM that carries no identity, no
      # workload, no secret, no token, no Pod IP and no workspace: the
      # guest supervisor has answered hello, acknowledged pause.prepare, the
      # VMM was paused and a full snapshot written.  Every base carries a
      # manifest with the SHA-256 of its memory and VM-state files, the
      # artifact digest it was built from and the drive layout; a restore
      # verifies the digests before the VMM ever opens the files, and a
      # mismatch is SnapshotCorruption (fail-closed, nothing started).
      class SnapshotPool
        SCHEMA_VERSION = 2
        MANIFEST = "manifest.json"
        ARTIFACT_BINDING = "artifact-digest.json"
        MAX_BINDING_BYTES = 512
        MEM = "mem"
        VMSTATE = "vmstate"

        Base = Struct.new(:id, :runtime_class, :directory, :manifest, :artifact_binding, keyword_init: true) do
          def mem_path = File.join(directory, MEM)
          def vmstate_path = File.join(directory, VMSTATE)
          def artifact_digest = manifest["artifact_digest"]
          def drive_layout = manifest.fetch("drive_layout")
          def machine = manifest.fetch("machine")

          def to_h
            {"id" => id, "runtime_class" => runtime_class, "directory" => directory, "manifest" => manifest}
          end
        end

        def initialize(root:, clock: -> { Time.now.utc })
          @root = File.expand_path(root)
          @clock = clock
          FileUtils.mkdir_p(@root, mode: 0o700)
        end

        attr_reader :root

        # Registers snapshot files written by the VMM: they are moved into
        # the pool with fsync and their digests recorded.
        def store(id:, runtime_class:, mem_path:, vmstate_path:, artifact_digest:, drive_layout:, machine:, guest_hello:, pause_ack:)
          validate_id!(id)
          directory = File.join(@root, runtime_class, id)
          raise Error, "base snapshot #{id} already exists" if File.exist?(directory)

          staging = "#{directory}.staging"
          FileUtils.rm_rf(staging)
          FileUtils.mkdir_p(staging, mode: 0o700)
          FileUtils.mv(mem_path, File.join(staging, MEM))
          FileUtils.mv(vmstate_path, File.join(staging, VMSTATE))
          [MEM, VMSTATE].each do |name|
            path = File.join(staging, name)
            File.chown(0, 0, path)
            File.chmod(0o644, path)
            File.open(path, File::RDONLY, &:fsync)
          end
          manifest = {
            "schema_version" => SCHEMA_VERSION,
            "id" => id,
            "runtime_class" => runtime_class,
            "created_at" => @clock.call.iso8601(6),
            "artifact_digest" => artifact_digest,
            "drive_layout" => drive_layout,
            "machine" => machine,
            "guest_hello" => guest_hello,
            "pause_ack" => pause_ack,
            "files" => {MEM => file_record(File.join(staging, MEM)), VMSTATE => file_record(File.join(staging, VMSTATE))}
          }
          write_metadata(File.join(staging, MANIFEST), manifest)
          write_metadata(File.join(staging, ARTIFACT_BINDING), artifact_digest)
          File.open(staging, File::RDONLY, &:fsync)
          FileUtils.mkdir_p(File.dirname(directory), mode: 0o700)
          File.rename(staging, directory)
          File.open(File.dirname(directory), File::RDONLY, &:fsync)
          Base.new(id: id, runtime_class: runtime_class, directory: directory, manifest: manifest, artifact_binding: artifact_digest)
        end

        def bases(runtime_class)
          directory = File.join(@root, runtime_class)
          return [] unless File.directory?(directory)

          Dir.children(directory).sort.filter_map do |id|
            next if id.end_with?(".staging")

            load_base(runtime_class, id)
          rescue SnapshotCorruption
            nil
          end
        end

        def latest(runtime_class, artifact_digest: nil)
          candidates = bases(runtime_class)
          if artifact_digest
            # A disagreement involving this release must reach verify!, so a
            # damaged current base cannot be mistaken for an older release.
            candidates.select! { |base| base.artifact_binding == artifact_digest || base.artifact_digest == artifact_digest }
          end
          candidates.max_by { |base| base.manifest.fetch("created_at") }
        end

        def load_base(runtime_class, id)
          validate_id!(id)
          directory = File.join(@root, runtime_class, id)
          manifest_path = File.join(directory, MANIFEST)
          raise SnapshotCorruption, "base snapshot #{id} has no manifest" unless File.file?(manifest_path)

          manifest = JSON.parse(File.read(manifest_path))
          unless manifest.is_a?(Hash) && [1, SCHEMA_VERSION].include?(manifest["schema_version"]) && manifest["files"].is_a?(Hash)
            raise SnapshotCorruption,
                  "base snapshot #{id} manifest is malformed"
          end

          Base.new(id: id, runtime_class: runtime_class, directory: directory, manifest: manifest, artifact_binding: read_artifact_binding(directory))
        rescue JSON::ParserError => error
          raise SnapshotCorruption, "base snapshot #{id} manifest is not JSON: #{error.message}"
        end

        # Full digest verification of both files against the manifest and of
        # the artifact binding; called before every restore.  A file whose
        # digest was verified in this process and whose inode, size and
        # mtime are unchanged since is not re-hashed (any write, even in
        # place, moves mtime); pass force: true to re-hash anyway.
        def verify!(base, artifact_digest:, force: false)
          verify_artifact_binding!(base, artifact_digest)
          @verified ||= {}
          [MEM, VMSTATE].each do |name|
            path = File.join(base.directory, name)
            record = base.manifest.fetch("files").fetch(name) do
              raise SnapshotCorruption, "base snapshot #{base.id} manifest lacks #{name}"
            end
            raise SnapshotCorruption, "base snapshot #{base.id} #{name} is missing" unless File.file?(path)

            stat = File.stat(path)
            unless stat.size == record["bytes"]
              raise SnapshotCorruption,
                    "base snapshot #{base.id} #{name} size #{stat.size} differs from manifest #{record["bytes"]}"
            end

            # ctime changes when the file is hard-linked into a jail, so the
            # key is inode + size + mtime (any write to the data moves mtime).
            key = [stat.ino, stat.size, stat.mtime.to_r, record["sha256"]]
            next if !force && @verified[path] == key

            digest = self.class.file_digest(path)
            unless digest == record["sha256"]
              raise SnapshotCorruption,
                    "base snapshot #{base.id} #{name} digest #{digest} differs from manifest #{record["sha256"]}"
            end

            @verified[path] = key
          end
          true
        end

        def remove(runtime_class, id)
          validate_id!(id)
          directory = File.join(@root, runtime_class, id)
          return false unless File.directory?(directory)

          FileUtils.rm_rf(directory)
          true
        end

        # Large-buffer SHA-256 through OpenSSL (the memory file is hundreds
        # of MiB; the digest gem's own implementation is several times slower).
        def self.file_digest(path, chunk: 8 * 1024 * 1024)
          digest = OpenSSL::Digest.new("SHA256")
          File.open(path, "rb") do |file|
            buffer = String.new(capacity: chunk)
            digest.update(buffer) while file.read(chunk, buffer)
          end
          digest.hexdigest
        end

        private

        def write_metadata(path, document)
          File.open(path, "wb") do |file|
            file.write(JSON.pretty_generate(document) + "\n")
            file.fsync
          end
        end

        def read_artifact_binding(directory)
          path = File.join(directory, ARTIFACT_BINDING)
          bytes = File.open(path, File::RDONLY | File::NONBLOCK | File::NOFOLLOW) do |file|
            file.read(MAX_BINDING_BYTES + 1) if file.stat.file?
          end
          return unless bytes && bytes.bytesize <= MAX_BINDING_BYTES

          binding = JSON.parse(bytes)
          binding if binding.is_a?(String) && !binding.empty?
        rescue SystemCallError, JSON::ParserError
          nil
        end

        def verify_artifact_binding!(base, expected)
          binding = read_artifact_binding(base.directory)
          if binding.nil? && base.manifest["schema_version"] == SCHEMA_VERSION
            raise SnapshotCorruption, "base snapshot #{base.id} is missing its artifact binding"
          end
          if binding && binding != base.artifact_digest
            raise SnapshotCorruption, "base snapshot #{base.id} manifest declares artifacts #{base.artifact_digest}, bound to #{binding}"
          end
          return if base.artifact_digest == expected

          raise SnapshotCorruption, "base snapshot #{base.id} was built from artifacts #{base.artifact_digest}, current #{expected}"
        end

        def file_record(path)
          {"sha256" => self.class.file_digest(path), "bytes" => File.size(path)}
        end

        def validate_id!(id)
          raise Error, "invalid snapshot id #{id.inspect}" unless id.is_a?(String) && id.match?(/\A[a-zA-Z0-9_-]{1,64}\z/)
        end
      end
    end
  end
end
