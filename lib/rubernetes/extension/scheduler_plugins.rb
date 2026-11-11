# frozen_string_literal: true

require "timeout"

require_relative "../scheduler"

module Rubernetes
  module Extension
    # The loaded extensions' filter and score blocks as scheduler plugins.
    module SchedulerPlugins
      # A plugin runs inside the scheduling cycle of every Pod; one that
      # hangs would stop the scheduler.
      CALL_TIMEOUT = 1

      module_function

      # A plugin is registered as "<extension>.<name>": two extensions may
      # use the same name, and neither can replace a built-in plugin.
      #
      # A block that raises fails this Pod's scheduling attempt, as an
      # upstream plugin returning an Error status does; the Pod is retried,
      # and `on_failure` hears about it for the extension's status.
      def registry(extensions, on_failure: nil)
        registry = Scheduler::PluginRegistry.new
        extensions.each do |extension|
          extension.scheduler_plugins.each do |plugin|
            name = "#{extension.name}.#{plugin.name}"
            block = guarded(plugin.block, extension.name, "#{plugin.phase}:#{plugin.name}", on_failure)
            if plugin.phase == :filter
              registry.filter(name, &block)
            else
              registry.score(name, weight: plugin.weight, &block)
            end
          end
        end
        registry
      end

      def guarded(block, extension, hook, on_failure, timeout: CALL_TIMEOUT)
        lambda do |pod, node|
          Timeout.timeout(timeout) { block.call(pod, node) }
        rescue StandardError => error
          on_failure&.call(extension, hook, error)
          raise
        end
      end
    end
  end
end
