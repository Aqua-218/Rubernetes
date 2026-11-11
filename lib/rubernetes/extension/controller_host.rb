# frozen_string_literal: true

require "json"
require "time"
require "timeout"

require_relative "../client"
require_relative "../watch"
require_relative "definition"

module Rubernetes
  module Extension
    # Resources as an extension names them -- "configmaps",
    # "deployments.apps", "widgets.example.com" -- turned into API paths.  A
    # group is asked for its preferred version once.
    class Resources
      def initialize(client)
        @client = client
        @versions = {}
        @mutex = Mutex.new
      end

      def collection(resource, namespace: nil)
        name, group = resource.to_s.split(".", 2)
        base = group ? "/apis/#{group_version(group)}" : "/api/v1"
        namespace ? "#{base}/namespaces/#{namespace}/#{name}" : "#{base}/#{name}"
      end

      def item(resource, name, namespace: nil)
        "#{collection(resource, namespace: namespace)}/#{name}"
      end

      private

      def group_version(group)
        @mutex.synchronize do
          @versions[group] ||= JSON.parse(@client.raw("GET", "/apis/#{group}").body).fetch("preferredVersion").fetch("groupVersion")
        end
      end
    end

    # What a controller block is given to act on the cluster.  It carries the
    # controller manager's own credentials.
    class API
      def initialize(client:, resources:, extension:, logger: nil)
        @client = client
        @resources = resources
        @extension = extension
        @logger = logger
      end

      # The object, or nil when there is none.
      def get(resource, name, namespace: nil)
        JSON.parse(@client.raw("GET", @resources.item(resource, name, namespace: namespace)).body)
      rescue Client::APIError => error
        raise unless error.status == 404
      end

      def list(resource, namespace: nil, selector: nil)
        query = selector ? {"labelSelector" => selector} : nil
        JSON.parse(@client.raw("GET", @resources.collection(resource, namespace: namespace), query: query).body).fetch("items", [])
      end

      # Server-side apply under this extension's own field manager: creates
      # the object or brings the fields the manifest names to its values.
      def apply(manifest)
        @client.apply(manifest, field_manager: "extension-#{@extension}", force: true)
      end

      def create(manifest)
        @client.create(manifest)
      end

      # A JSON merge patch.
      def patch(resource, name, changes, namespace: nil, subresource: nil)
        path = @resources.item(resource, name, namespace: namespace)
        path = "#{path}/#{subresource}" if subresource
        JSON.parse(@client.raw("PATCH", path, body: JSON.generate(changes), headers: {"Content-Type" => "application/merge-patch+json"}).body)
      end

      # false when there was nothing to delete.
      def delete(resource, name, namespace: nil)
        @client.raw("DELETE", @resources.item(resource, name, namespace: namespace))
        true
      rescue Client::APIError => error
        raise unless error.status == 404

        false
      end

      # An Event about `object`, as `kubectl describe` shows them.
      def event(object, reason:, message:, type: "Normal")
        metadata = object.fetch("metadata")
        namespace = metadata["namespace"] || "default"
        now = Time.now.utc.iso8601
        create({"apiVersion" => "v1", "kind" => "Event",
                "metadata" => {"generateName" => "#{metadata.fetch("name")}.", "namespace" => namespace},
                "involvedObject" => {"apiVersion" => object["apiVersion"], "kind" => object["kind"], "name" => metadata["name"],
                                     "namespace" => metadata["namespace"], "uid" => metadata["uid"]}.compact,
                "reason" => reason, "message" => message, "type" => type, "source" => {"component" => "extension/#{@extension}"},
                "firstTimestamp" => now, "lastTimestamp" => now, "count" => 1})
      end

      def log(message, **fields)
        @logger&.info("extension.log", extension: @extension, message: message.to_s, **fields)
      end
    end

    # One controller of one extension: a watch feeding a work queue, and a
    # worker calling the block.  Only the latest state of an object waits in
    # the queue, a block that raises is retried with backoff, and nothing is
    # delivered while this controller manager is not the leader.
    class ControllerRunner
      CALL_TIMEOUT = 30
      WATCH_SECONDS = 300
      RETRY_SECONDS = 2
      EVENTS = {"ADDED" => :added, "MODIFIED" => :modified, "DELETED" => :deleted}.freeze

      def initialize(extension:, controller:, client:, resources:, api:, leader:, on_failure:)
        @extension = extension
        @controller = controller
        @client = client
        @resources = resources
        @api = api
        @leader = leader
        @on_failure = on_failure
        @hook = "controller:#{controller.name}"
        # A block that names a third parameter wants to hear of deletions.
        @wants_deletions = controller.block.parameters.length >= 3
        @queue = Watch::WorkQueue.new(base_delay: 1.0, max_delay: 60.0)
        @pending = {}
        @mutex = Mutex.new
      end

      def start
        @threads = [Thread.new { follow }, Thread.new { work }]
        self
      end

      def stop
        @queue.shut_down
        @threads&.each(&:kill)
        self
      end

      private

      # Every pass begins with the full list -- :added the first time, :resync
      # afterwards -- so a block also sees what changed while nobody watched.
      def follow
        event = :added
        loop do
          path = @resources.collection(@controller.watch, namespace: @controller.namespace)
          query = @controller.selector ? {"labelSelector" => @controller.selector} : {}
          list = JSON.parse(@client.raw("GET", path, query: query).body)
          type_meta = {"apiVersion" => list["apiVersion"], "kind" => list["kind"].to_s.delete_suffix("List")}
          list.fetch("items", []).each { |object| enqueue(type_meta.merge(object), event) }
          event = :resync
          watch_query = query.merge("resourceVersion" => list.dig("metadata", "resourceVersion").to_s, "allowWatchBookmarks" => "true",
                                    "timeoutSeconds" => WATCH_SECONDS.to_s)
          @client.watch_each(path, query: watch_query, reconnect: false) do |change|
            enqueue(change.fetch("object"), EVENTS.fetch(change["type"])) if EVENTS.key?(change["type"])
          end
        rescue StandardError => error
          @on_failure.call(@extension, @hook, error)
          sleep(RETRY_SECONDS)
        end
      end

      def enqueue(object, event)
        return if event == :deleted && !@wants_deletions

        key = [object.dig("metadata", "namespace"), object.dig("metadata", "name")].compact.join("/")
        @mutex.synchronize { @pending[key] = [object, event] }
        @queue.add(key)
      end

      def work
        loop do
          key, shut_down = @queue.get
          break if shut_down

          deliver(key)
        end
      end

      def deliver(key)
        unless @leader.call
          @queue.add_after(key, RETRY_SECONDS)
          return
        end

        entry = @mutex.synchronize { @pending[key] }
        return if entry.nil?

        Timeout.timeout(CALL_TIMEOUT) { @controller.block.call(entry[0], @api, entry[1]) }
        @mutex.synchronize { @pending.delete(key) if @pending[key].equal?(entry) }
        @queue.forget(key)
      rescue StandardError => error
        @on_failure.call(@extension, @hook, error)
        @queue.add_rate_limited(key)
      ensure
        @queue.done(key)
      end
    end

    # The controllers of every loaded extension, kept equal to what is loaded.
    class ControllerHost
      def initialize(client:, on_failure:, leader: -> { true }, logger: nil)
        @client = client
        @resources = Resources.new(client)
        @leader = leader
        @on_failure = on_failure
        @logger = logger
        @runners = {}
        @mutex = Mutex.new
      end

      # `extensions` is everything that is loaded now.  A controller whose
      # extension changed is stopped and started anew: its block is new.
      def replace(extensions)
        wanted = extensions.flat_map do |extension|
          extension.controllers.map { |controller| [[extension.name, extension.generation, controller.name], [extension, controller]] }
        end.to_h
        @mutex.synchronize do
          (@runners.keys - wanted.keys).each { |key| @runners.delete(key).stop }
          (wanted.keys - @runners.keys).each do |key|
            extension, controller = wanted.fetch(key)
            api = API.new(client: @client, resources: @resources, extension: extension.name, logger: @logger)
            @runners[key] = ControllerRunner.new(extension: extension.name, controller: controller, client: @client, resources: @resources,
                                                 api: api, leader: @leader, on_failure: @on_failure).start
          end
        end
      end

      def stop
        @mutex.synchronize { @runners.each_value(&:stop).clear }
      end
    end
  end
end
