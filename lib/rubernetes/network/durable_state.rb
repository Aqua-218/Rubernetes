# frozen_string_literal: true

require_relative "../volume/deferred_fsync"

require "fileutils"
require "json"
require "securerandom"

require_relative "errors"
require_relative "support"

module Rubernetes
  module Network
    # Atomic JSON state used by IPAM and the network operation journal.  It is
    # intentionally independent from the runtime WAL so the network package
    # can be used by a node agent without loading the full runtime stack.
    class DurableState
      attr_reader :path

      # fsync: true syncs the file and its directory inside every write.
      # :deferred keeps the atomic rename -- the file on disk is always a
      # whole state -- and coalesces the durability barrier through
      # Volume::DeferredFsync, which is what the node's lifecycle state
      # already does.  Attaching one Pod's network persists its operation
      # about twenty times (an effect cursor, then each claimed resource),
      # and at two fsyncs apiece that serialised every concurrent Pod start
      # on the node behind the disk: under a 16-way conformance run network
      # readiness went from 0.34 s idle to 3.45 s median.
      def initialize(path, default: {}, fsync: true)
        raise ArgumentError, "durable state requires a path" if path.nil?

        @path = safe_path(path)
        @default = Support.copy(default)
        @fsync = fsync
        @mutex = Mutex.new
        @state = load_state
      end

      def read
        @mutex.synchronize { Support.copy(@state) }
      end

      # Support.copy is a JSON round trip of the whole state, and this used to
      # do three of them per write (the input copy, the encode inside #write,
      # and the copy handed back) on top of the caller's own.  The candidate
      # is canonical the moment it is copied, so it is encoded once and that
      # same text is what lands on disk.
      def replace(value)
        # Canonical form shares every subtree sealed by an earlier write, so
        # only what changed since is rebuilt; sealed, it is both what lands
        # on disk and the caller's record of it.
        candidate = Support.freeze_canonical(Support.canonical(value))
        body = JSON.generate(candidate) << "\n"
        @mutex.synchronize do
          write_body(body)
          @state = candidate
        end
        candidate
      rescue SystemCallError, IOError, JSON::GeneratorError => error
        raise DurabilityError, "network state write failed at #{@path}: #{error.message}"
      end

      def update
        raise ArgumentError, "durable state update requires a block" unless block_given?

        @mutex.synchronize do
          candidate = Support.copy(yield(Support.copy(@state)))
          write_body(JSON.generate(candidate) << "\n")
          @state = candidate
          Support.copy(candidate)
        end
      rescue SystemCallError, IOError, JSON::GeneratorError => error
        raise DurabilityError, "network state update failed at #{@path}: #{error.message}"
      end

      private

      def safe_path(path)
        candidate = File.expand_path(String(path))
        raise ValidationError, "network state path must not be a directory" if File.directory?(candidate)
        raise ValidationError, "network state path must not be a symlink" if File.symlink?(candidate)

        validate_parent_path!(File.dirname(candidate))

        candidate
      rescue TypeError
        raise ValidationError, "network state path must be a string"
      end

      def load_state
        return Support.copy(@default) unless File.file?(@path)

        raise ValidationError, "network state path is a symlink" if File.symlink?(@path)

        value = JSON.parse(File.binread(@path))
        raise DurabilityError, "network state root must be an object" unless value.is_a?(Hash)

        value
      rescue JSON::ParserError, SystemCallError => error
        raise DurabilityError, "network state read failed at #{@path}: #{error.message}"
      end

      def write(value)
        write_body(JSON.generate(Support.canonical(value)) << "\n")
      end

      def write_body(body)
        directory = File.dirname(@path)
        FileUtils.mkdir_p(directory)
        validate_parent_path!(directory)
        temporary = "#{@path}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          file.write(body)
          file.flush
          fsync(file)
        end
        File.rename(temporary, @path)
        fsync_directory(directory)
      ensure
        File.delete(temporary) if temporary && File.exist?(temporary)
      end

      def validate_parent_path!(directory)
        absolute = File.expand_path(directory)
        components = absolute.delete_prefix("/").split("/")
        current = "/"
        components.each do |component|
          current = File.join(current, component)
          raise ValidationError, "network state parent path must not contain symlinks" if File.symlink?(current)
        end
      end

      def deferred?
        @fsync == :deferred
      end

      def fsync(file)
        case @fsync
        when false, nil, :deferred
          nil
        when true
          file.fsync
        else
          @fsync.arity.zero? ? @fsync.call : @fsync.call(file)
        end
      end

      def fsync_directory(directory)
        return Volume::DeferredFsync.schedule(@path) if deferred?

        handle = File.open(directory, File::RDONLY)
        fsync(handle)
      ensure
        handle&.close
      end
    end

    # A small append-only event log useful for tests and for operation
    # recovery.  The complete state remains in DurableState; events provide a
    # tamper-evident audit trail and a recovery boundary.
    class EventJournal
      attr_reader :path

      def initialize(path, fsync: true, clock: -> { Time.now.utc })
        @path = File.expand_path(String(path))
        raise ValidationError, "network journal path must not be a symlink" if File.symlink?(@path)

        validate_parent_path!(File.dirname(@path))
        @fsync = fsync
        @clock = clock
        @mutex = Mutex.new
        FileUtils.mkdir_p(File.dirname(@path))
        validate_parent_path!(File.dirname(@path))
        @events = load
      end

      def append(event:, payload: {})
        name = Support.string(event, "event")
        @mutex.synchronize do
          flags = File::WRONLY | File::CREAT | File::APPEND
          flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
          File.open(@path, flags, 0o600) do |file|
            file.flock(File::LOCK_EX)
            # The in-memory length is process-local. Reload under the file
            # lock so concurrent processes cannot emit duplicate sequences.
            current_events = load
            body = {
              "sequence" => current_events.length + 1,
              "event" => name,
              "payload" => Support.canonical(payload),
              "timestamp" => Support.now(@clock).iso8601(6)
            }
            line = JSON.generate(body) << "\n"
            file.write(line)
            file.flush
            fsync(file)
            file.flock(File::LOCK_UN)
            @events = current_events + [body]
            return Support.copy(body)
          end
        end
      rescue SystemCallError, IOError => error
        raise DurabilityError, "network journal append failed at #{@path}: #{error.message}"
      end

      def events
        @mutex.synchronize { Support.copy(@events) }
      end

      private

      def validate_parent_path!(directory)
        absolute = File.expand_path(directory)
        components = absolute.delete_prefix("/").split("/")
        current = "/"
        components.each do |component|
          current = File.join(current, component)
          raise ValidationError, "network journal parent path must not contain symlinks" if File.symlink?(current)
        end
      end

      def load
        return [] unless File.file?(@path)

        File.foreach(@path).with_index(1).map do |line, number|
          value = JSON.parse(line)
          raise JSON::ParserError, "event is not an object" unless value.is_a?(Hash)
          raise JSON::ParserError, "invalid event sequence" unless value.fetch("sequence") == number

          value
        rescue JSON::ParserError, KeyError, TypeError => error
          raise DurabilityError, "network journal line #{number} is invalid: #{error.message}"
        end
      rescue SystemCallError => error
        raise DurabilityError, "network journal read failed at #{@path}: #{error.message}"
      end

      def fsync(file)
        case @fsync
        when false, nil then nil
        when true then file.fsync
        else @fsync.arity.zero? ? @fsync.call : @fsync.call(file)
        end
      end
    end
  end
end
