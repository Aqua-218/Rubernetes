# frozen_string_literal: true

module Rubernetes
  module Storage
    # One immutable change observed by a Watcher.
    class Event
      ADDED = "ADDED"
      MODIFIED = "MODIFIED"
      DELETED = "DELETED"
      BOOKMARK = "BOOKMARK"

      attr_reader :type, :object, :revision, :key

      def initialize(type:, object:, revision:, key: nil)
        @type = String(type).upcase.freeze
        @object = MemoryStoreSupport.immutable_copy(object)
        @revision = Integer(revision)
        @key = key&.to_s&.freeze
        freeze
      end

      alias event_type type
      alias resource_version revision

      def resourceVersion
        resource_version_string
      end

      def resource_version_string
        @revision.to_s
      end

      def [](name)
        case name.to_s
        when "type"
          @type
        when "object"
          @object
        when "revision"
          @revision
        when "resourceVersion", "resource_version"
          resource_version_string
        when "key"
          @key
        end
      end

      def to_h
        {"type" => @type, "object" => @object}
      end

      def to_json(*)
        JSON.generate(to_h, *)
      end

      def ==(other)
        other.is_a?(Event) &&
          other.type == type &&
          other.object == object &&
          other.revision == revision &&
          other.key == key
      end
      alias eql? ==

      def hash
        [@type, @object, @revision, @key].hash
      end
    end

    WatchEvent = Event
  end
end
