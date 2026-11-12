# frozen_string_literal: true

module Rubernetes
  module Storage
    # Whole-state export and import for replication snapshots.
    class MemoryStore
      # Complete durable state for replication snapshots: revision counters,
      # per-key version history, mutation history and request memory.  Watchers
      # are connection state and are not exported.
      def export_state
        @monitor.synchronize do
          {
            "schema_version" => 1,
            "revision" => @revision,
            "compacted_revision" => @compacted_revision,
            "known_keys" => @known_keys.keys.sort,
            "versions" => @versions.keys.sort.to_h do |key|
                            [key, @versions[key].map { |(revision, object)| [revision, object] }]
                          end,
            "history" => @history.map do |mutation|
              {"type" => mutation.type.to_s, "key" => mutation.key, "revision" => mutation.revision,
               "object" => mutation.object, "old_object" => mutation.old_object, "timestamp" => mutation.timestamp}
            end,
            "requests" => @requests.keys.sort.each_with_object({}) do |uid, output|
              stored = @requests[uid]
              output[uid] = {"fingerprint" => stored.fingerprint, "operation" => stored.operation.to_s,
                             "key" => stored.key, "revision" => stored.revision, "result" => stored.result}
            end
          }
        end
      end

      # Replace the complete state with an exported document.  Only valid on a
      # store that has not been mutated; a replica restores into a fresh
      # instance so the import never mixes generations.
      def import_state(document)
        raise ArgumentError, "state document must be a Hash" unless document.is_a?(Hash)
        raise ArgumentError, "state schema_version must be 1" unless document["schema_version"] == 1

        @monitor.synchronize do
          raise ArgumentError, "import_state requires an unused store" unless @revision.zero? && @objects.empty?

          @revision = Integer(document.fetch("revision"))
          @compacted_revision = Integer(document.fetch("compacted_revision"))
          @known_keys = {}
          @sorted_keys = nil
          Array(document.fetch("known_keys")).each { |key| @known_keys[String(key)] = true }
          @versions = Hash.new { |hash, key| hash[key] = [] }
          @objects = {}
          @resource_revisions = {}
          document.fetch("versions").each do |key, entries|
            list = entries.map do |(revision, object)|
              [Integer(revision), object.nil? ? nil : MemoryStoreSupport.deep_freeze(MemoryStoreSupport.deep_dup(object))]
            end
            @versions[String(key)] = list
            @objects[String(key)] = list.last&.last
            if (latest = list.last&.first)
              bucket = resource_bucket(String(key))
              @resource_revisions[bucket] = [@resource_revisions.fetch(bucket, 0), latest].max
            end
          end
          @history = Array(document.fetch("history")).map do |entry|
            Mutation.new(type: entry.fetch("type").to_sym, key: entry.fetch("key"), revision: Integer(entry.fetch("revision")),
                         object: entry["object"].nil? ? nil : MemoryStoreSupport.deep_freeze(MemoryStoreSupport.deep_dup(entry["object"])),
                         old_object: entry["old_object"].nil? ? nil : MemoryStoreSupport.deep_freeze(MemoryStoreSupport.deep_dup(entry["old_object"])),
                         timestamp: entry["timestamp"].nil? ? nil : Float(entry["timestamp"]))
          end
          @requests = {}
          document.fetch("requests").each do |uid, stored|
            @requests[String(uid)] = RequestResult.new(fingerprint: stored.fetch("fingerprint").freeze, operation: stored.fetch("operation").to_sym,
                                                       key: stored.fetch("key").freeze, revision: stored["revision"].nil? ? nil : Integer(stored["revision"]),
                                                       result: MemoryStoreSupport.immutable_copy(stored.fetch("result")))
          end
        end
        self
      end
    end
  end
end
