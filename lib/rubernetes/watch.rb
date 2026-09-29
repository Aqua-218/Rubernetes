# frozen_string_literal: true

require_relative "watch/support"
require_relative "watch/delta_fifo"
require_relative "watch/indexer"
require_relative "watch/work_queue"
require_relative "watch/reflector"
require_relative "watch/informer"

module Rubernetes
  module Watch
    DeltaQueue = DeltaFIFO unless const_defined?(:DeltaQueue, false)
    Cache = Indexer unless const_defined?(:Cache, false)
    WatchCache = Indexer unless const_defined?(:WatchCache, false)
    ThreadSafeStore = Indexer unless const_defined?(:ThreadSafeStore, false)
  end
end
