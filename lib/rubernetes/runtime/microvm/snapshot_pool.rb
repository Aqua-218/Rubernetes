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
        MANIFEST = "manifest.json"
        MEM = "mem"
        VMSTATE = "vmstate"

        Base = Struct.new(:id, :runtime_class, :directory, :manifest, keyword_init: true) do
          def mem_path = File.join(directory, MEM)
          def vmstate_path = File.join(directory, VMSTATE)
          def artifact_digest = manifest.fetch("artifact_digest")
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
            "schema_version" => 1,
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
          File.write(File.join(staging, MANIFEST), JSON.pretty_generate(manifest) + "\n")
          File.open(File.join(staging, MANIFEST), File::RDONLY, &:fsync)
          FileUtils.mkdir_p(File.dirname(directory), mode: 0o700)
          File.rename(staging, directory)
          File.open(File.dirname(directory), File::RDONLY, &:fsync)
          Base.new(id: id, runtime_class: runtime_class, directory: directory, manifest: manifest)
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

        def latest(runtime_class)
          bases(runtime_class).max_by { |base| base.manifest.fetch("created_at") }
        end

        def load_base(runtime_class, id)
          validate_id!(id)
          directory = File.join(@root, runtime_class, id)
          manifest_path = File.join(directory, MANIFEST)
          raise SnapshotCorruption, "base snapshot #{id} has no manifest" unless File.file?(manifest_path)

          manifest = JSON.parse(File.read(manifest_path))
          unless manifest.is_a?(Hash) && manifest["schema_version"] == 1 && manifest["files"].is_a?(Hash)
            raise SnapshotCorruption,
                  "base snapshot #{id} manifest is malformed"
          end

          Base.new(id: id, runtime_class: runtime_class, directory: directory, manifest: manifest)
        rescue JSON::ParserError => error
          raise SnapshotCorruption, "base snapshot #{id} manifest is not JSON: #{error.message}"
        end

        # Full digest verification of both files against the manifest and of
        # the artifact binding; called before every restore.
        # Full digest verification of both files against the manifest and of
        # the artifact binding; called before every restore.  A file whose
        # digest was verified in this process and whose inode, size and
        # mtime are unchanged since is not re-hashed (any write, even in
        # place, moves mtime); pass force: true to re-hash anyway.
        def verify!(base, artifact_digest:, force: false)
          unless base.artifact_digest == artifact_digest
            raise SnapshotCorruption,
                  "base snapshot #{base.id} was built from artifacts #{base.artifact_digest}, current #{artifact_digest}"
          end

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

        private

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
