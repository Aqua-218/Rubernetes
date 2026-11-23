# frozen_string_literal: true

module Rubernetes
  module Node
    class StatsProvider
      private

      # host_stats_provider.go counts only direct entries in each log directory.
      # CRI container log directories contribute through container stats.
      def log_file_stats(directory)
        Dir.children(directory).filter_map { |name| file_stats(File.join(directory, name)) }
      rescue SystemCallError
        []
      end

      def file_stats(path)
        stat = File.lstat(path)
        {"usedBytes" => stat.blocks * 512, "inodesUsed" => 1} unless stat.directory?
      rescue SystemCallError
        nil
      end
    end
  end
end
