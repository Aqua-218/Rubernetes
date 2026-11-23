# frozen_string_literal: true

require_relative "static_pod_file_watch"

module Rubernetes
  module Node
    # Reconcile file events and complete relists in source order. Static Pods
    # with the same configuration UID must wait for their former instance.
    module StaticPodFiles
      RETIREMENT_INTERVAL = 0.25
      MAX_RETIRED_FILE_PODS = 256

      private

      def start_file_watch(token)
        stop_reader, @file_stop_writer = IO.pipe
        Thread.new { watch_files(stop_reader, token) }
      end

      def watch_files(stop_reader, token)
        watcher = StaticPodFileWatch.open(@path)
        refresh_files(token: token)
        last_refresh = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        while polling?(token)
          interval = @retiring.empty? ? @interval : [@interval, RETIREMENT_INTERVAL].min
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - last_refresh
          ready = IO.select([stop_reader, watcher&.io].compact, nil, nil, [interval - elapsed, 0].max)&.first
          break if ready&.include?(stop_reader)

          removed, lost, changed = watch_events(watcher, ready)
          if lost
            watcher.io.close
            watcher = nil
          end
          watcher ||= StaticPodFileWatch.open(@path)
          next unless changed || elapsed >= interval

          refresh_files(token: token, removed: removed)
          last_refresh = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      ensure
        watcher&.io&.close
        stop_reader.close
      end

      def watch_events(watcher, ready)
        return [[], false, true] unless watcher && ready&.include?(watcher.io)

        watcher.consume
      end

      def refresh_files(token: nil, removed: [], http: nil)
        @sync_mutex.synchronize do
          return if token && !polling?(token)

          origins = {}
          snapshot = read_manifests(origins: origins)
          withdrawn = removed.flat_map { |path| @file_origins.fetch(path, []) }.uniq
          previous = @source_pods.fetch(:file)
          capture_file_restarts(snapshot ? withdrawn | (previous.keys - snapshot.keys) : withdrawn)
          if withdrawn.any?
            apply_sources(file: previous.reject { |uid, _pod| withdrawn.include?(uid) })
            removed.each { |path| @file_origins.delete(path) }
          end
          @file_origins = origins if snapshot
          apply_sources(file: snapshot, http: http)
        end
      end

      def capture_file_restarts(uids)
        return unless @lifecycle.is_a?(Lifecycle)

        uids.each do |uid|
          counts = @lifecycle.static_restart_counts(uid)
          next if counts.empty?

          @file_restart_counts.delete(uid)
          @file_restart_counts[uid] = counts
          @file_restart_counts.shift if @file_restart_counts.size > MAX_RETIRED_FILE_PODS
        end
      end

      def seed_file_restarts(uid)
        counts = @file_restart_counts.delete(uid)
        @lifecycle.seed_static_restart_counts(uid, counts) if counts
      end
    end
  end
end
