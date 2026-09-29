# frozen_string_literal: true

# User namespace mapping and durable UID/GID range allocation
# (spec/node/runtime.md §5.8.6).  Mappings are written by a process in the
# parent user namespace: user_namespaces(7) permits a 65,536-wide mapping only
# from a writer that holds CAP_SETUID/CAP_SETGID in the parent namespace, so
# the sandbox init can never grant itself a range.

require "fileutils"
require "json"

module Rubernetes
  module Platform
    module Linux
      class UserNamespace
        class Error < StandardError; end
        class Exhausted < Error; end

        RANGE_SIZE = 65_536
        # 16 ranges above the conventional host account space; every Pod range
        # is a whole multiple of RANGE_SIZE so ranges can never straddle.
        DEFAULT_BASE = 1_048_576
        # kernel: uid_t is 32-bit and 0xffffffff is the invalid id.
        MAX_ID = 0xffff_fffe

        Mapping = Data.define(:uid_base, :gid_base, :size) do
          def to_h
            {"uid_base" => uid_base, "gid_base" => gid_base, "size" => size, "setgroups" => "deny"}
          end
        end

        # Write setgroups/uid_map/gid_map for `pid` from the current (parent)
        # user namespace.  Order is fixed by the kernel: setgroups must be
        # denied before gid_map is written, otherwise the write is rejected
        # once a gid_map exists (user_namespaces(7)).
        def self.write_mappings(pid:, mapping:, proc_root: "/proc")
          base = File.join(proc_root, Integer(pid).to_s)
          values = mapping.is_a?(Mapping) ? mapping.to_h : mapping.to_h.transform_keys(&:to_s)
          uid_base = Integer(values.fetch("uid_base"))
          gid_base = Integer(values.fetch("gid_base"))
          size = Integer(values.fetch("size"))
          raise Error, "user namespace mapping size must be #{RANGE_SIZE}" unless size == RANGE_SIZE
          File.binwrite(File.join(base, "setgroups"), "deny\n")
          File.binwrite(File.join(base, "uid_map"), "0 #{uid_base} #{size}\n")
          File.binwrite(File.join(base, "gid_map"), "0 #{gid_base} #{size}\n")
          verify_mappings(pid: pid, mapping: Mapping.new(uid_base: uid_base, gid_base: gid_base, size: size), proc_root: proc_root)
        rescue SystemCallError => error
          raise Error, "user namespace mapping for #{pid} failed: #{error.message}"
        end

        def self.verify_mappings(pid:, mapping:, proc_root: "/proc")
          base = File.join(proc_root, Integer(pid).to_s)
          uid_map = parse_map(File.read(File.join(base, "uid_map")))
          gid_map = parse_map(File.read(File.join(base, "gid_map")))
          expected_uid = [[0, Integer(mapping.uid_base), RANGE_SIZE]]
          expected_gid = [[0, Integer(mapping.gid_base), RANGE_SIZE]]
          raise Error, "uid_map readback mismatch for #{pid}: #{uid_map.inspect}" unless uid_map == expected_uid
          raise Error, "gid_map readback mismatch for #{pid}: #{gid_map.inspect}" unless gid_map == expected_gid
          setgroups = File.read(File.join(base, "setgroups")).strip
          raise Error, "setgroups is not denied for #{pid}" unless setgroups == "deny"

          {"uid_map" => uid_map, "gid_map" => gid_map, "setgroups" => setgroups}
        end

        def self.parse_map(contents)
          String(contents).each_line.filter_map do |line|
            fields = line.split
            next if fields.empty?

            fields.first(3).map { |value| Integer(value) }
          end
        end

        # Durable allocator for non-overlapping 65,536-wide ranges.  Each
        # allocation is bound to a sandbox identity and persisted with fsync
        # before it is handed out, so a crash between allocation and holder
        # creation can never lead to two Pods sharing host IDs.
        class Allocator
          SCHEMA = "rubernetes.userns.allocations.v1"

          def initialize(path:, base: DEFAULT_BASE, size: RANGE_SIZE, max_id: MAX_ID)
            @path = File.expand_path(String(path))
            @base = Integer(base)
            @size = Integer(size)
            @max_id = Integer(max_id)
            raise Error, "user namespace range size must be #{RANGE_SIZE}" unless @size == RANGE_SIZE
            raise Error, "user namespace base must be a multiple of the range size" unless (@base % @size).zero?
            @mutex = Mutex.new
            FileUtils.mkdir_p(File.dirname(@path), mode: 0o700)
            @allocations = load
          end

          attr_reader :path

          def allocate(identity)
            key = String(identity)
            raise Error, "user namespace allocation identity must not be empty" if key.empty?

            @mutex.synchronize do
              existing = @allocations[key]
              return mapping_for(existing) if existing

              used = @allocations.values.map { |entry| Integer(entry.fetch("uid_base")) }.sort
              candidate = @base
              candidate += @size while used.include?(candidate)
              raise Exhausted, "no free user namespace range below #{@max_id}" if candidate + @size - 1 > @max_id

              @allocations[key] = {"uid_base" => candidate, "gid_base" => candidate, "size" => @size}
              persist!
              mapping_for(@allocations[key])
            end
          end

          def lookup(identity)
            entry = @mutex.synchronize { @allocations[String(identity)] }
            entry && mapping_for(entry)
          end

          def release(identity)
            @mutex.synchronize do
              removed = @allocations.delete(String(identity))
              persist! if removed
              !removed.nil?
            end
          end

          def allocations
            @mutex.synchronize { @allocations.transform_values(&:dup).freeze }
          end

          private

          def mapping_for(entry)
            Mapping.new(uid_base: Integer(entry.fetch("uid_base")), gid_base: Integer(entry.fetch("gid_base")), size: Integer(entry.fetch("size")))
          end

          def load
            return {} unless File.file?(@path)

            document = JSON.parse(File.binread(@path))
            raise Error, "user namespace allocation file has an unknown schema" unless document.is_a?(Hash) && document["schema"] == SCHEMA
            entries = document.fetch("allocations")
            raise Error, "user namespace allocations must be an object" unless entries.is_a?(Hash)
            bases = entries.values.map { |entry| Integer(entry.fetch("uid_base")) }
            raise Error, "user namespace allocation file contains overlapping ranges" unless bases.uniq.length == bases.length
            entries.transform_values { |entry| entry.transform_keys(&:to_s) }
          rescue JSON::ParserError, KeyError, TypeError, ArgumentError => error
            raise Error, "user namespace allocation file is invalid: #{error.message}"
          end

          def persist!
            body = JSON.generate("schema" => SCHEMA, "allocations" => @allocations) << "\n"
            temporary = "#{@path}.tmp-#{Process.pid}"
            File.open(temporary, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |file|
              file.write(body)
              file.flush
              file.fsync
            end
            File.rename(temporary, @path)
            File.open(File.dirname(@path), File::RDONLY) { |directory| directory.fsync }
            true
          rescue SystemCallError => error
            raise Error, "user namespace allocation file could not be persisted: #{error.message}"
          ensure
            File.delete(temporary) if temporary && File.exist?(temporary)
          end
        end
      end
    end
  end
end
