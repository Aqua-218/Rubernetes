# frozen_string_literal: true

module Rubernetes
  module Proxy
    module TopologyHints
      # pkg/proxy/topology.go chooses the most specific hint supplied by all
      # ready endpoints for which this node has a match.
      def self.preferred(ready, node:, zone:)
        [[node, :node_hints], [zone, :hints]].each do |location, field|
          next if location.to_s.empty?

          matches = []
          complete = ready.all? do |endpoint|
            hints = block_given? ? yield(endpoint, field) : endpoint.public_send(field)
            matches << endpoint if hints&.include?(location.to_s)
            hints && !hints.empty?
          end
          return matches if complete && !matches.empty?
        end
        ready
      end

      def self.names(source, key, alternate)
        values = if source.is_a?(Array)
                   source if key == "forZones"
                 else
                   ModelSupport.key(source, key) || ModelSupport.key(source, alternate)
                 end
        Array(values).map { |hint| ModelSupport.key(hint, "name", hint).to_s }.reject(&:empty?).uniq.freeze
      end
    end
  end
end
