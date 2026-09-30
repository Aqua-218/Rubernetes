# frozen_string_literal: true

module Rubernetes
  module Volume
    # Coalesced durability for state files that are rewritten on every
    # operation.  Each write renames a complete file into place (atomic, so a
    # crash never leaves a torn file); the fsync that makes it durable is
    # scheduled here and one flusher thread performs at most one fsync per
    # dirty path per interval.  A node starting 33 Pods at once used to issue
    # three fsyncs per volume operation and two per lifecycle event, all
    # serialized: a Pod with 50 ConfigMap volumes did not finish
    # MountVolume.SetUp in five minutes.  Records whose loss would make
    # recovery unsafe (a ledger entry that says a kernel effect is in flight)
    # still fsync inline; see OperationLedger#persist!.
    module DeferredFsync
      INTERVAL_SECONDS = 0.02

      @mutex = Mutex.new
      @dirty = {}
      @thread = nil

      class << self
        def schedule(path)
          return if path.nil?

          @mutex.synchronize do
            @dirty[File.expand_path(path.to_s)] = true
            start_locked
          end
        end

        # Fsync every dirty path now.  Used at shutdown and by tests.
        def flush!
          paths = @mutex.synchronize do
            taken = @dirty.keys
            @dirty.clear
            taken
          end
          paths.each { |path| sync_path(path) }
          paths.length
        end

        def sync_path(path)
          File.open(path, File::RDONLY, &:fsync)
          File.open(File.dirname(path), File::RDONLY, &:fsync)
        rescue SystemCallError, IOError
          nil
        end

        private

        def start_locked
          return if @thread&.alive?

          @thread = Thread.new do
            Thread.current.name = "deferred-fsync"
            loop do
              sleep(INTERVAL_SECONDS)
              paths = @mutex.synchronize do
                taken = @dirty.keys
                @dirty.clear
                taken
              end
              paths.each { |path| sync_path(path) }
            end
          end
        end
      end
    end
  end
end
