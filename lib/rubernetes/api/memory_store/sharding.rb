# frozen_string_literal: true

module Rubernetes
  module API
    class MemoryStore
      # The in-process store reconstructs a sharded list's pinned snapshot and
      # tracks selector transitions through retained and live mutations.
      module Sharding
        attr_accessor :metrics

        private

        def key_for_object(object)
          metadata = object.fetch("metadata", {})
          resource = object["_rubernetes_resource"] || object.fetch("apiVersion", "v1")
          key_for("registry/#{resource}/#{metadata.fetch("namespace", "_cluster")}/#{metadata.fetch("name")}")
        end

        def sharded?(selector)
          selector.is_a?(Selectors) && selector.shard
        end

        def list_shard(prefix, gvr, namespace, selector, limit, continue_token, revision)
          compact_if_due!
          continuation = decode_continue(continue_token)
          start = continuation.fetch(:offset)
          revision = continuation[:revision] || revision
          if revision < @compacted_revision
            raise(Gone.new("The provided continue parameter is too old to display a consistent list result. " \
                           "You can start a new list without the continue parameter.",
                           resource_version: revision, compacted_revision: @compacted_revision)
              .tap { |error| error.details["continue"] = encode_continue_token(start) if error.details && start.positive? })
          end

          keys = scoped_keys(prefix, gvr, namespace)
          snapshot = @objects
          if revision < @revision
            snapshot = keys.to_h { |key| [key, @objects.fetch(key)] }
            @history.reverse_each do |event|
              break if event_revision(event) <= revision
              next unless key_matches?(event.key, prefix, gvr, namespace)

              event.old_object ? snapshot[event.key] = event.old_object : snapshot.delete(event.key)
            end
            keys = snapshot.keys
          end
          keys = keys.sort.drop(start)
          items = []
          examined = 0
          keys.each do |key|
            examined += 1
            object = snapshot.fetch(key)
            next unless selector.matches?(object)

            items << object
            break if limit && items.length == limit
          end
          more = examined < keys.length
          ListResult.new(items: items, resource_version: revision,
                         continue_token: more ? encode_continue_token(start + examined, revision) : nil,
                         remaining_item_count: more && selector.empty? ? keys.length - items.length : nil)
        end

        def shard_metric_labels(gvr, selector)
          return unless @metrics && sharded?(selector) && gvr.is_a?(GVR)

          {"group" => gvr.group.to_s, "resource" => gvr.resource.to_s}
        end

        def matching_watch_event(event, prefix, normalized_gvr, namespace, selector, &)
          return if event.type == "BOOKMARK"

          key = event.key || key_for_object(event.object)
          return unless key_matches?(key, prefix, normalized_gvr, namespace)
          return event if selector.nil?

          now = event.type != "DELETED" && selector.matches?(event.object, &)
          before = event.old_object && selector.matches?(event.old_object, &)
          return event if now && (before || event.type == "ADDED")
          return Event.new(type: "ADDED", key: key, object: event.object) if now
          return unless before
          return event if event.type == "DELETED"

          object = deep_copy(event.old_object)
          object["metadata"]["resourceVersion"] = event.object.dig("metadata", "resourceVersion")
          Event.new(type: "DELETED", key: key, object: object)
        end
      end
    end
  end
end
