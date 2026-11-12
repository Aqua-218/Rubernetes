# frozen_string_literal: true

# The durable map of volume id to VolumeRecord: an in-memory index over one
# record file per volume, rolled back in memory when a write does not reach
# disk.
module Rubernetes
  module Volume
    class VolumeStore
      def initialize(initial: {}, path: nil, fsync: false)
        @mutex = Monitor.new
        @path = path && File.expand_path(path.to_s)
        @fsync = fsync
        @files = @path && RecordFiles.new(path: @path, fsync: fsync)
        @values = load_values(initial)
      end

      def [](id)
        @mutex.synchronize { @values[id.to_s] }
      end

      def []=(id, value)
        @mutex.synchronize do
          key = id.to_s
          existed = @values.key?(key)
          previous = @values[key]
          @values[key] = value
          begin
            persist!(key)
          rescue StandardError
            existed ? @values[key] = previous : @values.delete(key)
            raise
          end
        end
      end

      def fetch(id, &)
        @mutex.synchronize { @values.fetch(id.to_s, &) }
      end

      def delete(id)
        @mutex.synchronize do
          key = id.to_s
          existed = @values.key?(key)
          value = @values.delete(key)
          begin
            forget!(key) if existed
          rescue StandardError
            @values[key] = value if existed
            raise
          end
          value
        end
      end

      def values
        @mutex.synchronize { @values.values.dup.freeze }
      end

      def each_value(&block)
        return enum_for(__method__) unless block

        values.each(&block)
      end

      private

      def load_values(initial)
        values = initial.dup
        return values unless @files

        legacy = @files.legacy?
        @files.load.each do |value|
          hash = value.transform_keys(&:to_s)
          id = hash.fetch("id")
          values[id] = VolumeRecord.new(id: hash.fetch("id", id), spec: hash.fetch("spec"), backend: hash.fetch("backend"),
                                        state: hash.fetch("state", "Declared"), generation: hash.fetch("generation", 0),
                                        attachments: hash.fetch("attachments", {}), stages: hash.fetch("stages", {}),
                                        publishes: hash.fetch("publishes", {}), operation: hash["operation"],
                                        capacity_bytes: hash["capacityBytes"], created_at: hash["createdAt"], updated_at: hash["updatedAt"])
        end
        @files.migrate!(values.transform_values(&:to_h)) if legacy
        values
      rescue JSON::ParserError, KeyError, TypeError => error
        raise JournalError, "volume store is corrupt: #{error.message}"
      end

      # Only the changed record is written (RecordFiles).
      def persist!(key)
        return true unless @files

        @files.write(key, @values[key].to_h)
      rescue SystemCallError, IOError => error
        raise JournalError, "volume store persist failed: #{error.message}"
      end

      def forget!(key)
        return true unless @files

        @files.delete(key)
      rescue SystemCallError, IOError => error
        raise JournalError, "volume store persist failed: #{error.message}"
      end
    end
  end
end
