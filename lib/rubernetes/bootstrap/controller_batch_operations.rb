# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    # Parallelize independent writes without crossing dependent operations.
    module ControllerBatchOperations
      CREATE_PARALLELISM = 8
      PARALLEL_ACTIONS = %i[create delete].freeze

      def apply_batch(operations, fence: nil)
        Array(operations).chunk(&:action).flat_map do |action, group|
          if group.length > 1 && PARALLEL_ACTIONS.include?(action)
            apply_in_parallel(group, fence: fence)
          else
            group.map { |operation| apply(operation, fence: fence) }
          end
        end
      end

      def apply_in_parallel(group, fence: nil)
        group.each_slice(CREATE_PARALLELISM).flat_map do |slice|
          threads = slice.map { |operation| Thread.new { apply(operation, fence: fence) } }
          failure = nil
          results = threads.map do |thread|
            thread.value
          rescue StandardError => error
            failure ||= error
            nil
          end
          # Let the requests already in flight finish before a failed
          # reconciliation can be retried.
          raise failure if failure

          results
        end
      end
    end
  end
end
