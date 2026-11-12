# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Small atomic state store for the node-side reconciliation cache.  The
      # runtime ledger remains the authority for kernel ownership; this store
      # preserves the request/result, container identities, probe counters and
      # restart backoff so a new agent process does not reset policy state.
      class StateStore
        MAX_BYTES = 16 * 1024 * 1024

        def initialize(path)
          @path = File.expand_path(String(path))
          FileUtils.mkdir_p(File.dirname(@path))
        end

        attr_reader :path

        def load
          return {} unless File.file?(@path)
          raise Error, "node lifecycle state exceeds #{MAX_BYTES} bytes" if File.size(@path) > MAX_BYTES

          body = File.binread(@path)
          raise Error, "node lifecycle state is not newline terminated" unless body.end_with?("\n")

          Runtime::StrictJSON.parse(body, max_bytes: MAX_BYTES, max_depth: 100, require_newline: true)
        rescue Runtime::StrictJSON::Error, JSON::ParserError, SystemCallError => error
          raise Error, "node lifecycle state could not be loaded: #{error.message}"
        end

        def save(value)
          save_body(JSON.generate(value) << "\n")
        end

        # +body+: the complete newline-terminated JSON document.
        def save_body(body)
          raise Error, "node lifecycle state exceeds #{MAX_BYTES} bytes" if body.bytesize > MAX_BYTES

          temporary = "#{@path}.tmp-#{Process.pid}-#{Thread.current.object_id}"
          File.open(temporary, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |file|
            file.write(body)
            file.flush
          end
          File.rename(temporary, @path)
          # Atomic rename keeps the file whole; durability is coalesced (see
          # Volume::DeferredFsync).  Two fsyncs per lifecycle event, some
          # thirty events per Pod, serialized 33 concurrent Pod starts behind
          # the disk.
          Volume::DeferredFsync.schedule(@path)
          true
        ensure
          File.delete(temporary) if temporary && File.exist?(temporary)
        end

        private

        def fsync_directory
          directory = File.open(File.dirname(@path), File::RDONLY)
          directory.fsync
        ensure
          directory&.close
        end
      end
    end
  end
end
