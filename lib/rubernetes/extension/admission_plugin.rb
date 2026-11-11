# frozen_string_literal: true

require "timeout"

require_relative "../api/registry"
require_relative "../security/admission/framework"
require_relative "loader"

module Rubernetes
  module Extension
    # What an admission hook's block is given: the request under admission,
    # and the two things a hook can do about it.
    class Request
      # Raised by #reject; never seen by the extension.
      class Rejection < StandardError
        attr_reader :code

        def initialize(message, code)
          @code = code
          super(message)
        end
      end

      attr_reader :operation, :group, :version, :resource, :subresource, :kind, :namespace, :name, :user, :object, :old_object, :warnings

      def initialize(attributes)
        @operation = attributes.operation.downcase.to_sym
        @group = attributes.group
        @version = attributes.version
        @resource = attributes.resource
        @subresource = attributes.subresource
        @kind = attributes.kind
        @namespace = attributes.namespace
        @name = attributes.name
        @user = attributes.user
        # Copies: a validating hook must not be able to change what is
        # stored, and a mutating hook that raises must leave nothing behind.
        @object = Marshal.load(Marshal.dump(attributes.object))
        @old_object = Marshal.load(Marshal.dump(attributes.old_object))
        @dry_run = attributes.dry_run
        @warnings = []
      end

      def create? = operation == :create
      def update? = operation == :update
      def delete? = operation == :delete
      def dry_run? = @dry_run

      # Refuses the request; the client sees `message`.
      def reject(message, code: 403)
        raise Rejection.new(message.to_s, code)
      end

      # Lets the request through with a warning the client prints.
      def warn(message)
        @warnings << message.to_s
      end
    end

    # The loaded extensions' validate and mutate blocks as one admission
    # plugin at the end of the chain: mutating hooks run after every built-in
    # mutating plugin and webhook, validating hooks with the validating ones.
    #
    # A hook that raises refuses the request, as a webhook with failurePolicy
    # Fail does.  Requests for Extension objects themselves never reach a
    # hook, so an extension cannot stand in the way of its own removal.
    class AdmissionPlugin < Security::Admission::Plugin
      NAME = "RubyExtension"
      # How stale the loaded set may be.  Every write passes through here, so
      # the stored extensions are listed at most this often, not per request.
      REFRESH_SECONDS = 1
      CALL_TIMEOUT = 2
      # The store keeps a custom resource under one key whatever version it
      # was written in.
      STORED = API::Resource::CUSTOM_STORAGE_VERSION

      def initialize(context:, logger: nil, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        super(NAME, context: context)
        @logger = logger
        @clock = clock
        @hooks = {mutate: [], validate: []}.freeze
        @refresh = Mutex.new
        @refreshed_at = nil
        @loader = Loader.new(component: "admission", on_change: method(:rebuild), status_writer: method(:store_status), logger: logger)
      end

      def handles?(attributes)
        return false if attributes.group == GROUP

        refresh
        !(@hooks[:mutate].empty? && @hooks[:validate].empty?)
      end

      def admit(attributes)
        request = run(:mutate, attributes)
        attributes.object = request.object if request
      end

      def validate(attributes)
        run(:validate, attributes)
      end

      private

      # One request thread at a time brings the set up to date; the others
      # go on with what is loaded.
      def refresh
        return unless @refreshed_at.nil? || @clock.call - @refreshed_at >= REFRESH_SECONDS
        return unless @refresh.try_lock

        begin
          @refreshed_at = @clock.call
          @loader.sync(@context.list!(RESOURCE, nil, group: GROUP, version: STORED))
        rescue StandardError => error
          # A list that failed says nothing about what is stored: the hooks
          # that are loaded stay.
          @logger&.warn("extension.admission_refresh_failed", error: error.class.name, message: error.message.to_s[0, 200])
        ensure
          @refresh.unlock
        end
      end

      def rebuild(loaded)
        hooks = loaded.flat_map { |extension| extension.admission_hooks.map { |hook| [extension.name, hook] } }
        @hooks = hooks.group_by { |_extension, hook| hook.phase }.then do |grouped|
          {mutate: grouped.fetch(:mutate, []), validate: grouped.fetch(:validate, [])}.freeze
        end
      end

      def run(phase, attributes)
        hooks = @hooks.fetch(phase).select { |_extension, hook| applies?(hook, attributes) }
        return nil if hooks.empty?

        request = Request.new(attributes)
        hooks.each { |extension, hook| call(extension, hook, request) }
        request.warnings.each { |warning| attributes.warn(warning) }
        request
      end

      def call(extension, hook, request)
        Timeout.timeout(CALL_TIMEOUT) { hook.block.call(request) }
      rescue Request::Rejection => error
        reason = {400 => "BadRequest", 409 => "Conflict", 422 => "Invalid"}.fetch(error.code, "Forbidden")
        raise Security::Admission::Rejected.new("extension #{extension} denied the request: #{error.message}", code: error.code,
                                                                                                               reason: reason, plugin: NAME)
      rescue StandardError => error
        @loader.failed(extension, "#{hook.phase}:#{hook.name}", error)
        raise Security::Admission::Rejected.new("extension #{extension} #{hook.phase} hook #{hook.name} failed: " \
                                                "#{error.class}: #{error.message}", code: 500, reason: "InternalError", plugin: NAME)
      end

      def applies?(hook, attributes)
        return false unless hook.operations.include?(attributes.operation.downcase.to_sym)

        hook.resources.any? { |pattern| resource_matches?(pattern, attributes) }
      end

      # "pods", "deployments.apps", "pods/status", "*" (every resource) and
      # "*/*" (every resource and subresource), as webhook rules spell them.
      def resource_matches?(pattern, attributes)
        resource, subresource = pattern.split("/", 2)
        return false unless subresource == "*" || subresource.to_s == attributes.subresource
        return true if resource == "*"

        name, group = resource.split(".", 2)
        name == attributes.resource && group.to_s == attributes.group
      end

      # The admission side has no API client: it writes its part of the
      # status where the API server keeps the object.
      def store_status(name, status)
        stored = @context.get(RESOURCE, nil, name, group: GROUP, version: STORED)
        return if stored.nil?

        updated = Marshal.load(Marshal.dump(stored))
        ((updated["status"] ||= {})["components"] ||= {})["admission"] = status
        @context.update(RESOURCE, nil, name, updated, resource_version: stored.dig("metadata", "resourceVersion"),
                                                      group: GROUP, version: STORED)
      end
    end
  end
end
