# frozen_string_literal: true

require "zlib"

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
        TIMESTAMP = "%Y%m%d-%H%M%S"
        COMPRESS_SUFFIX = ".gz"
        TMP_SUFFIX = ".tmp"

        def initialize(client:, max_size: 10 * 1024 * 1024, max_files: 5, interval: 10, clock: -> { Time.now },
                       error_handler: nil)
          raise ArgumentError, "max_files must be at least 2" if Integer(max_files) < 2

          @client = client
          @max_size = Integer(max_size)
          @max_files = Integer(max_files)
          @interval = Float(interval)
          @clock = clock
          @error_handler = error_handler
          @thread = nil
          @stop = false
          @mutex = Mutex.new
        end

        def start
          @thread ||= Thread.new do
            until @mutex.synchronize { @stop }
              rotate_logs
              sleep @interval
            end
          end
          self
        end

        def stop
          @mutex.synchronize { @stop = true }
          @thread&.wakeup
          @thread&.join(2)
          @thread = nil
          self
        rescue ThreadError
          self
        end

        def rotate_logs
          Array(@client.runtime("ListContainers", {})["containers"]).each do |container|
            next unless container["state"] == "CONTAINER_RUNNING"

            process_container(container["id"])
          rescue StandardError => error
            @error_handler&.call(error, container["id"])
          end
        rescue StandardError => error
          @error_handler&.call(error, nil)
        end

        def process_container(id)
          path = @client.runtime("ContainerStatus", {"container_id" => id}).dig("status", "log_path").to_s
          return if path.empty?

          unless File.exist?(path)
            @client.runtime("ReopenContainerLog", {"container_id" => id})
            return unless File.exist?(path)
          end
          return if File.size(path) < @max_size

          rotate(id, path)
        end

        def rotate(id, path)
          logs = Dir.glob("#{glob_escape(path)}.*")
          logs = cleanup_unused(logs)
          logs = remove_excess(logs)
          logs.each { |log| compress(log) unless log.end_with?(COMPRESS_SUFFIX) }
          rotate_latest(id, path)
        end

        private

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
          logs = logs.sort
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

        def rotate_latest(id, path)
          rotated = "#{path}.#{@clock.call.strftime(TIMESTAMP)}"
          File.rename(path, rotated)
          begin
            @client.runtime("ReopenContainerLog", {"container_id" => id})
          rescue StandardError
            File.rename(rotated, path)
            raise
          end
          rotated
        end

        def glob_escape(path) = path.gsub(/[\\*?\[\]{}]/) { |char| "\\#{char}" }
      end
    end
  end
end
