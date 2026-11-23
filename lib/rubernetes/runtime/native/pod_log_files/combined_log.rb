# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      class PodLogFiles
        # Read the sole raw stream as the combined log until the second stream writes.
        # A directory rename commits an independent combined history in one step.
        class CombinedLog < Rotator
          class DeferredPromotion < StandardError; end

          def initialize(combined, stdout:, stderr:)
            super(path: combined.path, max_bytes: combined.max_bytes, max_files: combined.max_files, create_directory: false)
            @combined_directory = File.join(File.dirname(@path), "combined")
            @combined_name = File.basename(@path)
            @append_mutex = Mutex.new
            @physical = restore_path(stdout, stderr)
          end

          def append_stream(raw, bytes, &)
            @append_mutex.synchronize do
              @mutex.synchronize do
                return append_shared_locked(raw, &) unless @physical || different_stream?(raw.path)
              end
              return append_separately(bytes, &) if @physical

              # Draining pauses at this chunk until the staged copy can commit.
              @pending = [bytes, @clock.call]
              written = yield
              raise DeferredPromotion unless finish_promotion

              written
            end
          end

          def resume
            @append_mutex.synchronize { finish_promotion }
          end

          attr_reader :retained_handle

          def retain_streams(handle)
            return if @retained_handle

            stdout = handle.stdout&.dup
            stderr = handle.stderr&.dup
            @retained_handle = handle.with(stdout: stdout, stderr: stderr, stdin: nil, gate: nil)
          rescue IOError, SystemCallError => error
            stdout&.close
            stderr&.close
            warn "could not retain native output pipes: #{error.message}"
          end

          def close_retained_streams
            return unless @retained_handle

            @retained_handle.stdout&.close
            @retained_handle.stderr&.close
            @retained_handle = nil
          end

          def discard
            @append_mutex.synchronize do
              @discarded = true
              @pending = nil
              close_retained_streams
            end
          end

          def discarded? = @discarded

          private

          def append_separately(bytes)
            written = yield
            append(bytes)
            written
          end

          def finish_promotion
            return true unless @pending

            @mutex.synchronize { materialize(*@pending) }
          end

          def restore_path(stdout, stderr)
            if File.directory?(@combined_directory)
              @path = File.join(@combined_directory, @combined_name)
              return true
            end
            return true if existing_segments(@path).any?

            sources = [stdout.path, stderr.path].select { |path| existing_segments(path).any? }
            return true if sources.size > 1

            @primary = sources.first
            @path = @primary if @primary
            false
          end

          def different_stream?(path) = @primary && @primary != path

          def append_shared_locked(raw)
            @primary = @path = raw.path
            written = yield
            record_append_time(written, @clock.call)
            written
          end

          def existing_segments(path)
            @max_files.times.filter_map do |index|
              candidate = segment_path(path, index)
              [index, candidate] if File.file?(candidate)
            end
          end

          def materialize(bytes, timestamp)
            # An interrupted promotion may leave one staged copy to replace.
            staging = "#{@combined_directory}.pending"
            FileUtils.remove_entry(staging, true)
            Dir.mkdir(staging, 0o700)
            staged_path = File.join(staging, @combined_name)
            original, copied = stage_segments(staged_path)
            Rotator.new(path: staged_path, max_bytes: @max_bytes, max_files: @max_files, create_directory: false).append(bytes)
            copied_segment = find_segment(staged_path, copied)
            File.rename(staging, @combined_directory)
            staging = nil
            @original_identity = original
            @copied_identity = copied if copied_segment
            @copied_segment = copied_segment
            @path = File.join(@combined_directory, @combined_name)
            @physical = true
            @pending = nil
            record_append_time(bytes.bytesize, timestamp)
            true
          rescue SystemCallError => error
            warn "could not separate native combined log: #{error.message}" unless @reported_promotion_error
            @reported_promotion_error = true
            false
          ensure
            FileUtils.remove_entry(staging, true) if staging
          end

          def find_segment(path, identity)
            return unless identity

            existing_segments(path).find { |_index, segment| file_identity(File.stat(segment)) == identity }&.first
          end

          def stage_segments(base)
            original = copied = nil
            existing_segments(@path).each do |index, source|
              destination = segment_path(base, index)
              if index.zero?
                FileUtils.copy_file(source, destination, true)
                original = file_identity(File.stat(source))
                copied = file_identity(File.stat(destination))
              else
                File.link(source, destination)
              end
            end
            [original, copied]
          end

          def segment_path(base, index) = index.zero? ? base : "#{base}.#{index}"

          def rotate_unlocked!
            result = super
            if @copied_segment
              @copied_segment += 1
              @copied_identity = @copied_segment = nil if @copied_segment == @max_files
            end
            result
          end

          # Existing combined followers hold the original active file's cursor.
          # Keep that identity for the copied segment even after it rotates.
          def file_identity(stat)
            identity = super
            identity == @copied_identity ? @original_identity : identity
          end
        end
      end
    end
  end
end
