# frozen_string_literal: true

module Rubernetes
  module Proxy
    # Recompile watched Services together when the local Node changes zone.
    module NodeTopology
      def update_node_zone(label)
        zone = label.to_s.empty? ? @configured_node_zone : label.to_s.dup.freeze
        changed = @mutex.synchronize do
          next false if zone == @node_zone || !@compiler.is_a?(RuleCompiler)

          recompile_for_node_zone(zone)
          true
        end
        schedule_publish if changed
        changed
      end

      private

      def initialize_node_zone(configured, compiler)
        configured ||= compiler.node_zone if compiler.is_a?(RuleCompiler)
        @configured_node_zone = configured.to_s.dup.freeze unless configured.nil?
        @node_zone = @configured_node_zone
        return compiler unless compiler.is_a?(RuleCompiler) && compiler.node_zone != @node_zone

        compiler.dup.tap { |copy| copy.node_zone = @node_zone }
      end

      # Watch callbacks take the same lock and cannot overwrite new rules
      # with a compilation from the old zone.
      def recompile_for_node_zone(zone)
        previous = @compiler
        @compiler = previous.dup
        @compiler.node_zone = zone
        updated = @endpoint_store.services.to_h { |service| [service.key, compile_stored_service(service)] }
        @compiled.merge!(updated)
        @last_compilation = updated.values.last unless updated.empty?
        @node_zone = zone
      rescue StandardError
        @compiler = previous
        raise
      end
    end
  end
end
