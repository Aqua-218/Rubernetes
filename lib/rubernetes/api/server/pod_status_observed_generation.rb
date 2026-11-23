# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Compatibility with kubelets that write status without generation tracking.
      module PodStatusObservedGeneration
        FIELD = "observedGeneration"

        module_function

        def preserve!(status, previous)
          return unless status.is_a?(Hash)

          previous = {} unless previous.is_a?(Hash)
          preserve_field!(status, previous)
          old_conditions = conditions(previous).group_by { |condition| condition["type"] }
          conditions(status).each do |condition|
            # A nonzero update also consumes its occurrence of this type.
            old_condition = old_conditions[condition["type"]]&.shift
            preserve_field!(condition, old_condition)
          end
        end

        def conditions(status)
          Array(status["conditions"]).grep(Hash)
        end

        def preserve_field!(current, previous)
          requested = current[FIELD]
          return unless requested.nil? || requested.eql?(0)

          generation = previous&.fetch(FIELD, nil)
          if generation.nil? || generation.eql?(0)
            current.delete(FIELD)
          else
            current[FIELD] = generation
          end
        end

        private_class_method :conditions, :preserve_field!
      end
    end
  end
end
