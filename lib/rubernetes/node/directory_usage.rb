# frozen_string_literal: true

require "find"

module Rubernetes
  module Node
    module DirectoryUsage
      # Kubelet's volume/util/fs.DiskUsage counts allocated blocks and unique
      # inodes on the filesystem containing the root of the walk.
      def self.measure(path)
        device = File.stat(path).dev
        linked = Set.new
        bytes = 0
        inodes = 0
        Find.find(path) do |entry|
          stat = File.lstat(entry)
          Find.prune if stat.dev != device
          Find.prune if stat.nlink > 1 && !linked.add?(stat.ino)

          bytes += stat.blocks * 512
          inodes += 1
        rescue SystemCallError
          Find.prune
        end
        [bytes, inodes]
      end
    end
  end
end
