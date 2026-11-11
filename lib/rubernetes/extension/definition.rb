# frozen_string_literal: true

require "timeout"

module Rubernetes
  module Extension
    class Error < StandardError; end

    # The source of an extension could not be loaded.  `line` is the line of
    # the extension's own source the failure points at, when there is one.
    class CompileError < Error
      attr_reader :line

      def initialize(message, line: nil)
        @line = line
        super(line ? "line #{line}: #{message}" : message)
      end
    end

    SchedulerPlugin = Data.define(:name, :phase, :weight, :block)
    AdmissionHook = Data.define(:name, :phase, :resources, :operations, :block)
    Controller = Data.define(:name, :watch, :namespace, :selector, :block)

    # One loaded extension: what its source declared, ready to be wired into
    # the components.  Immutable; a changed source is a new Compiled.
    Compiled = Data.define(:name, :generation, :scheduler_plugins, :admission_hooks, :controllers) do
      # What the extension adds, as the status and the CLI list it.
      def provides
        scheduler_plugins.map { |plugin| "#{plugin.phase}:#{plugin.name}" } +
          admission_hooks.map { |hook| "#{hook.phase}:#{hook.name}" } +
          controllers.map { |controller| "controller:#{controller.name}" }
      end
    end

    # The receiver an extension's source is evaluated against: each method is
    # one thing an extension can declare.  A `def` at the top of the source
    # becomes a method of this object, so helpers are visible in every block
    # of the same extension and in no other.
    class Definition
      PLUGIN_NAME = /\A[A-Za-z][A-Za-z0-9_-]*\z/
      OPERATIONS = %i[create update delete connect].freeze
      LOAD_TIMEOUT = 5

      # Evaluates `source` and returns what it declared.
      def self.compile(name, source, generation: 0, timeout: LOAD_TIMEOUT)
        filename = "extension/#{name}.rb"
        definition = new(name)
        Timeout.timeout(timeout) { definition.instance_eval(source.to_s, filename, 1) }
        definition.compiled(generation)
      rescue Timeout::Error
        raise CompileError, "loading took longer than #{timeout}s"
      rescue SyntaxError => error
        # The parser explains each error on a line of its own, under a caret.
        reasons = error.message.scan(/^\s*\|\s*\^+ (.+)$/).flatten
        raise CompileError.new(reasons.empty? ? "syntax error" : "syntax error: #{reasons.first}",
                               line: error.message[/#{Regexp.escape(filename)}:(\d+)/, 1]&.to_i)
      rescue StandardError, ScriptError => error
        raise if error.is_a?(CompileError)

        line = error.backtrace&.filter_map { |frame| frame[/\A#{Regexp.escape(filename)}:(\d+)/, 1] }&.first
        raise CompileError.new("#{error.class}: #{error.message}", line: line&.to_i)
      end

      def initialize(name)
        @name = name
        @scheduler_plugins = []
        @admission_hooks = []
        @controllers = []
      end

      def compiled(generation)
        Compiled.new(name: @name, generation: generation, scheduler_plugins: @scheduler_plugins.freeze,
                     admission_hooks: @admission_hooks.freeze, controllers: @controllers.freeze)
      end

      # A scheduler Filter plugin: the block gets the Pod being scheduled and
      # one candidate node, and answers true to keep the node, or false or a
      # reason String to rule it out.
      def filter(name, &block)
        @scheduler_plugins << SchedulerPlugin.new(name: plugin_name(name), phase: :filter, weight: 1, block: required(block, "filter"))
      end

      # A scheduler Score plugin: the block answers an Integer from 0 to 100
      # for the node; the scheduler multiplies it by `weight` and adds it to
      # the built-in plugins' scores.
      def score(name, weight: 1, &block)
        raise ArgumentError, "score weight must be a positive Integer" unless weight.is_a?(Integer) && weight.positive?

        @scheduler_plugins << SchedulerPlugin.new(name: plugin_name(name), phase: :score, weight: weight, block: required(block, "score"))
      end

      # A validating admission hook for the named resources ("pods",
      # "deployments.apps", "*").  The block gets the request and calls
      # request.reject("why") to refuse it.
      def validate(*resources, on: %i[create update], name: nil, &block)
        admission(:validate, resources, on, name, block)
      end

      # A mutating admission hook: the block changes request.object in place.
      # It runs after the built-in mutating plugins and before validation.
      def mutate(*resources, on: %i[create update], name: nil, &block)
        admission(:mutate, resources, on, name, block)
      end

      # A controller: the block is called with every object of the watched
      # resource -- when it appears, whenever it changes, and periodically --
      # and with an API handle to act on the cluster.  A third block
      # parameter, when declared, is the event: :added, :modified, :deleted
      # or :resync.  Without it the block is not called for deletions.
      #
      # watch: "configmaps", "deployments.apps" or "widgets.example.com".
      def controller(name, watch:, namespace: nil, selector: nil, &block)
        @controllers << Controller.new(name: plugin_name(name), watch: watch.to_s, namespace: namespace&.to_s,
                                       selector: selector&.to_s, block: required(block, "controller"))
      end

      private

      def admission(phase, resources, operations, name, block)
        operations = Array(operations).map { |operation| operation.to_s.downcase.to_sym }
        unknown = operations - OPERATIONS
        raise ArgumentError, "unknown admission operation #{unknown.first.inspect}; use #{OPERATIONS.join(", ")}" unless unknown.empty?
        raise ArgumentError, "#{phase} needs at least one resource, or \"*\"" if resources.empty?

        resources = resources.map(&:to_s)
        default = resources.map { |resource| resource.gsub("*", "all").gsub(/[^A-Za-z0-9_-]/, "-") }.join("-")
        @admission_hooks << AdmissionHook.new(name: plugin_name(name || default), phase: phase,
                                              resources: resources.freeze, operations: operations.freeze,
                                              block: required(block, phase.to_s))
      end

      def plugin_name(name)
        text = name.to_s
        raise ArgumentError, "invalid name #{name.inspect}: letters, digits, _ and - only, starting with a letter" unless text.match?(PLUGIN_NAME)

        text
      end

      def required(block, what)
        block || raise(ArgumentError, "#{what} needs a block")
      end
    end
  end
end
