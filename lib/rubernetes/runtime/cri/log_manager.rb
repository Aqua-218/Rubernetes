# frozen_string_literal: true

require "zlib"
require_relative "../../schema/quantity"

module Rubernetes
  module Runtime
    module CRI
      # kubelet pkg/kubelet/logs containerLogManager: with a CRI runtime the
      # kubelet rotates the container logs the runtime writes.  Every
      # interval each running container's log is checked; one of maxSize or
      # more is renamed to <log>.<YYYYMMDD-hhmmss>, the runtime is told to
      # reopen it (ReopenContainerLog; on failure the rename is undone), the
      # rotated files beyond maxFiles - 2 are removed oldest first, and the
      # older ones are gzip-compressed.
      class LogManager
        DEFAULT_MAX_SIZE = "10Mi"
        DEFAULT_WORKERS = 1
        MAX_WORKERS = (2**31) - 1
        SHUTDOWN_WAIT_SECONDS = 2
        TIMESTAMP = "%Y%m%d-%H%M%S"
        COMPRESS_SUFFIX = ".gz"
        TMP_SUFFIX = ".tmp"

        def self.parse_max_size(size) = Schema::Quantity.parse_int64(size.to_s)

        def self.clean(path)
          escaped = path.gsub(/[\\*?\[\]{}]/) { |char| "\\#{char}" }
          (Dir.glob("#{escaped}.*") << path).each do |file|
            File.unlink(file)
          rescue Errno::ENOENT
            next
          end
        end

        def initialize(client:, max_size: DEFAULT_MAX_SIZE, max_files: 5, max_workers: DEFAULT_WORKERS, interval: 10, clock: -> { Time.now },
                       error_handler: nil)
          raise ArgumentError, "max_files must be at least 2" if Integer(max_files) < 2
          unless max_workers.is_a?(Integer) && max_workers.between?(1, MAX_WORKERS)
            raise ArgumentError, "max_workers must be an int32 greater than or equal to 1"
          end

          @client = client
          @max_size = self.class.parse_max_size(max_size)
          @max_files = Integer(max_files)
          @max_workers = max_workers
          @interval = Float(interval)
          @clock = clock
          @error_handler = error_handler
          @thread = nil
          @stopped = false
          @lifecycle = Mutex.new
          @wake = ConditionVariable.new
          @scan = Mutex.new
          @paths = Mutex.new
          @log_locks = {}
          @scan_paths = nil
        end

        attr_reader :max_workers

        def clean(path)
          with_log_lock(path) do |key|
            self.class.clean(path)
          ensure
            @paths.synchronize { @scan_paths&.add(key) }
          end
        end

        def start
          return self if @max_size.negative?

          @lifecycle.synchronize do
            return self if @thread

            @stopped = false
            @thread = Thread.new { monitor_logs }
          end
          self
        end

        def stop
          monitor = @lifecycle.synchronize do
            @stopped = true
            @wake.broadcast
            @thread
          end
          # Let a rename/reopen or compression already in flight finish.
          # The monitor stays registered until its workers have exited.
          monitor&.join(SHUTDOWN_WAIT_SECONDS) unless monitor.equal?(Thread.current)
          self
        end

        def rotate_logs
          scan_logs
        end

        def process_container(id, scanning: false, cancelled: nil)
          status = @client.runtime("ContainerStatus", {"container_id" => id})["status"] || {}
          return if status["state"] && status["state"] != "CONTAINER_RUNNING"

          path = status["log_path"].to_s
          return if path.empty?

          with_log_lock(path) do |key|
            next if cancelled&.call
            next if scanning && !@paths.synchronize { @scan_paths.add?(key) }

            rotate_if_needed(id, path)
          end
        end

        def rotate(id, path)
          with_log_lock(path) { rotate_locked(id, path) }
        end

        private

        def monitor_logs
          cancelled = -> { @lifecycle.synchronize { @stopped } }
          until cancelled.call
            scan_logs(cancelled: cancelled)
            @lifecycle.synchronize { @wake.wait(@lifecycle, @interval) unless @stopped }
          end
        ensure
          @lifecycle.synchronize { @thread = nil }
        end

        def scan_logs(cancelled: nil)
          return if @max_size.negative?

          @scan.synchronize do
            next if cancelled&.call

            @paths.synchronize { @scan_paths = Set.new }
            begin
              ids = Array(@client.runtime("ListContainers", {})["containers"]).filter_map do |container|
                container["id"] if container["state"] == "CONTAINER_RUNNING"
              end.uniq
              run_workers(ids, cancelled)
            ensure
              @paths.synchronize { @scan_paths = nil }
            end
          end
        rescue StandardError => error
          report_error(error, nil)
        end

        def run_workers(ids, cancelled)
          if @max_workers == 1 || ids.length <= 1
            ids.each do |id|
              break if cancelled&.call

              rotate_scanned_container(id, cancelled)
            end
            return
          end

          jobs = Queue.new
          ids.each { |id| jobs << id }
          jobs.close
          workers = []
          [ids.length, @max_workers].min.times do
            workers << Thread.new do
              while !cancelled&.call && (id = jobs.pop)
                rotate_scanned_container(id, cancelled)
              end
            end
          end
        ensure
          workers&.each(&:join)
        end

        def rotate_scanned_container(id, cancelled)
          process_container(id, scanning: true, cancelled: cancelled)
        rescue StandardError => error
          report_error(error, id)
        end

        def report_error(error, id)
          @error_handler&.call(error, id)
        rescue StandardError => reporting_error
          warn "CRI log rotation error handler failed (#{reporting_error.class})"
        end

        def with_log_lock(path)
          key = File.expand_path(path)
          entry = @paths.synchronize do
            lock = (@log_locks[key] ||= {mutex: Mutex.new, users: 0})
            lock[:users] += 1
            lock
          end
          entry.fetch(:mutex).synchronize { yield key }
        ensure
          if entry
            @paths.synchronize do
              entry[:users] -= 1
              @log_locks.delete(key) if entry[:users].zero?
            end
          end
        end

        def rotate_if_needed(id, path)
          unless File.exist?(path)
            @client.runtime("ReopenContainerLog", {"container_id" => id})
            return unless File.exist?(path)
          end
          return if File.size(path) < @max_size

          rotate_locked(id, path)
        end

        def rotate_locked(id, path)
          logs = cleanup_unused(Dir.glob("#{glob_escape(path)}.*"))
          latest = rotate_latest(id, path, logs)
          remove_excess(logs).each { |log| compress(log) unless log.end_with?(COMPRESS_SUFFIX) }
          latest
        end

        # A temporary file, or an uncompressed one whose compressed copy
        # exists, is left over from an interrupted compression.
        def cleanup_unused(logs)
          unused = logs.select do |log|
            log.end_with?(TMP_SUFFIX) || (!log.end_with?(COMPRESS_SUFFIX) && logs.include?(log + COMPRESS_SUFFIX))
          end
          unused.each { |log| File.delete(log) }
          logs - unused
        end

        def remove_excess(logs)
          logs = logs.sort_by { |log| log.delete_suffix(COMPRESS_SUFFIX) }
          keep = [@max_files - 2, 0].max
          excess = logs.length - keep
          return logs unless excess.positive?

          logs.first(excess).each { |log| File.delete(log) }
          logs.drop(excess)
        end

        def compress(log)
          temporary = log + TMP_SUFFIX
          mode = File.stat(log).mode
          File.open(temporary, File::WRONLY | File::CREAT | File::TRUNC, mode) do |file|
            gzip = Zlib::GzipWriter.new(file)
            File.open(log, "rb") { |source| IO.copy_stream(source, gzip) }
            gzip.close
          end
          File.rename(temporary, log + COMPRESS_SUFFIX)
          File.delete(log)
        ensure
          File.delete(temporary) if temporary && File.exist?(temporary)
        end

        def rotate_latest(id, path, logs)
          rotated = archive_name(path, logs)
          File.rename(path, rotated)
          begin
            @client.runtime("ReopenContainerLog", {"container_id" => id})
          rescue StandardError
            # A runtime may reopen the path before returning an RPC error.
            # Never overwrite that file or its new bytes with the archive.
            File.rename(rotated, path) unless File.exist?(path)
            raise
          end
          rotated
        end

        def archive_name(path, logs)
          base = "#{path}.#{@clock.call.strftime(TIMESTAMP)}"
          candidate = /\A#{Regexp.escape(base)}(?:\.(\d+))?\z/
          previous = logs.filter_map do |log|
            match = candidate.match(log.delete_suffix(COMPRESS_SUFFIX))
            (match[1] || "0").to_i if match
          end.max
          suffix = format("%010d", previous + 1) if previous
          suffix ? "#{base}.#{suffix}" : base
        end

        def glob_escape(path) = path.gsub(/[\\*?\[\]{}]/) { |char| "\\#{char}" }
      end
    end
  end
end
