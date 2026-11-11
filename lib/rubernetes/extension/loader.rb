# frozen_string_literal: true

require "json"
require "time"

require_relative "definition"
require_relative "resource"

module Rubernetes
  module Extension
    # Keeps one component's loaded extensions equal to the Extension objects
    # in the API, and tells the API what became of each.
    #
    # What runs is always what is stored: a source that no longer loads takes
    # its previous version out of the component instead of leaving code
    # running that no object describes.  The component hears about every
    # change through `on_change`, with the complete list of what is loaded.
    class Loader
      RETRY_SECONDS = 2
      WATCH_SECONDS = 300
      # A hook that fails on every Pod must not turn into a status write per
      # Pod: failures are counted at once and reported this often.
      FAILURE_REPORT_SECONDS = 10

      Entry = Struct.new(:uid, :generation, :compiled, :message, :failures, :last_failure, :reported_at)

      # status_writer.call(name, component_status) stores one extension's
      # status for this component; the default patches the status subresource
      # through `client`.
      def initialize(component:, on_change:, client: nil, status_writer: nil, logger: nil, clock: -> { Time.now.utc })
        @component = component
        @on_change = on_change
        @client = client
        @status_writer = status_writer || method(:patch_status)
        @logger = logger
        @clock = clock
        @entries = {}
        @mutex = Mutex.new
        @thread = nil
      end

      def loaded
        @mutex.synchronize { @entries.values.filter_map(&:compiled) }
      end

      # Follows the API until `stop`.  The CustomResourceDefinition may not be
      # there yet, and the API server may not be either: both are retried.
      def start
        @thread ||= Thread.new { follow }
        self
      end

      def stop
        @thread&.kill
        @thread = nil
        self
      end

      # Makes the loaded set equal to `objects`, the complete list.
      def sync(objects)
        names = objects.map { |object| object.dig("metadata", "name") }
        changed = objects.map { |object| load_object(object) }.any?
        removed = @mutex.synchronize { (@entries.keys - names).each { |name| @entries.delete(name) } }
        publish if changed || removed.any?
      end

      def upsert(object)
        publish if load_object(object)
      end

      def remove(name)
        publish if @mutex.synchronize { @entries.delete(name) }
      end

      # A hook of a loaded extension raised.  Counted for the status and
      # logged; what the failure means for the Pod or the request is the
      # calling component's decision.
      def failed(name, hook, error)
        report = @mutex.synchronize do
          entry = @entries[name]
          next nil unless entry

          entry.failures += 1
          entry.last_failure = "#{hook}: #{error.class}: #{error.message}"[0, 500]
          due = entry.reported_at.nil? || @clock.call - entry.reported_at >= FAILURE_REPORT_SECONDS
          entry.reported_at = @clock.call if due
          due ? status_of(entry) : nil
        end
        @logger&.warn("extension.hook_failed", extension: name, hook: hook, error: error.class.name, message: error.message.to_s[0, 300])
        write_status(name, report) if report
      end

      private

      # true when what is loaded under the object's name changed.
      def load_object(object)
        name = object.dig("metadata", "name")
        uid = object.dig("metadata", "uid")
        generation = object.dig("metadata", "generation").to_i
        entry = @mutex.synchronize { @entries[name] }
        return false if entry && entry.uid == uid && entry.generation == generation

        compiled, message = compile(name, object.dig("spec", "source"), generation)
        entry = Entry.new(uid, generation, compiled, message, 0, nil, nil)
        @mutex.synchronize { @entries[name] = entry }
        @logger&.info("extension.loaded", extension: name, generation: generation, loaded: !compiled.nil?,
                                          provides: compiled&.provides, message: message)
        write_status(name, status_of(entry))
        true
      end

      def compile(name, source, generation)
        [Definition.compile(name, source, generation: generation), nil]
      rescue CompileError => error
        [nil, error.message]
      end

      def status_of(entry)
        status = {"loaded" => !entry.compiled.nil?, "observedGeneration" => entry.generation,
                  "provides" => entry.compiled&.provides || [], "message" => entry.message.to_s,
                  "failures" => entry.failures, "time" => @clock.call.iso8601}
        status["lastFailure"] = entry.last_failure if entry.last_failure
        status
      end

      def publish
        @on_change.call(loaded)
      end

      # The status is information for whoever applied the extension; failing
      # to store it changes nothing about what is loaded.
      def write_status(name, status)
        @status_writer.call(name, status)
      rescue StandardError => error
        @logger&.warn("extension.status_failed", extension: name, error: error.class.name, message: error.message.to_s[0, 300])
      end

      def patch_status(name, status)
        @client.raw("PATCH", "#{PATH}/#{name}/status", body: JSON.generate({"status" => {"components" => {@component => status}}}),
                                                       headers: {"Content-Type" => "application/merge-patch+json"})
      end

      def follow
        loop do
          list = JSON.parse(@client.raw("GET", PATH).body)
          sync(list.fetch("items", []))
          watch(list.dig("metadata", "resourceVersion"))
        rescue StandardError => error
          @logger&.debug("extension.follow_retry", error: error.class.name, message: error.message.to_s[0, 200])
          sleep(RETRY_SECONDS)
        end
      end

      def watch(resource_version)
        query = {"resourceVersion" => resource_version.to_s, "allowWatchBookmarks" => "true", "timeoutSeconds" => WATCH_SECONDS.to_s}
        @client.watch_each(PATH, query: query, reconnect: false) do |event|
          case event["type"]
          when "ADDED", "MODIFIED" then upsert(event.fetch("object"))
          when "DELETED" then remove(event.dig("object", "metadata", "name"))
          when "ERROR" then return nil
          end
        end
      end
    end
  end
end
