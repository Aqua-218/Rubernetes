# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "socket"
require "thread"
require "time"

module Rubernetes
  module Controller
    # A small append-only journal for control-plane effects.
    #
    # The journal is deliberately independent from the API object store. A
    # successful API/store mutation is recorded only after the mutation
    # returns, with a deterministic semantic key and a process generation.
    # The generation is included in the attempt ID while the semantic key is
    # stable across leader replacement, allowing a verifier to distinguish a
    # retry from a second side effect.
    class EffectJournal
      PATH_ENV = "RUBERNETES_M3_EFFECT_JOURNAL".freeze
      SHA256_PATTERN = /\A[0-9a-f]{64}\z/.freeze

      class << self
        def from_env(component: nil, identity: nil)
          path = ENV[PATH_ENV].to_s.strip
          return nil if path.empty?

          new(path: path, component: component, identity: identity)
        end

        def read(path)
          return [] unless path && File.file?(path)

          File.foreach(path).map do |line|
            JSON.parse(line, create_additions: false, max_nesting: 64)
          end
        end

        def canonical(value)
          case value
          when Hash
            value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
              source = value.keys.find { |candidate| candidate.to_s == key }
              result[key] = canonical(value.fetch(source))
            end
          when Array
            value.map { |child| canonical(child) }
          when Time
            value.utc.iso8601(6)
          else
            value
          end
        end

        def digest(value)
          Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
        end
      end

      attr_reader :path, :component, :identity

      def initialize(path:, component: nil, identity: nil, clock: -> { Time.now.utc })
        @path = File.expand_path(path.to_s)
        raise ArgumentError, "effect journal path must not be empty" if @path.empty?

        @component = (component || ENV["RUBERNETES_M3_PROCESS_ROLE"] || "control-plane").to_s
        @identity = (identity || ENV["RUBERNETES_M3_PROCESS_IDENTITY"] || "#{Socket.gethostname}:#{Process.pid}").to_s
        @clock = clock
        @mutex = Mutex.new
        FileUtils.mkdir_p(File.dirname(@path))
      end

      def generation
        @generation ||= begin
          start_time = process_start_time(Process.pid)
          "#{@identity}:#{Process.pid}:#{start_time}"
        end
      end

      def effect_key(reconcile_key:, effect_type:)
        [@component, reconcile_key.to_s, effect_type.to_s].join("|")
      end

      def effect_id(reconcile_key:, effect_type:, generation: self.generation)
        key_digest = Digest::SHA256.hexdigest(reconcile_key.to_s)[0, 32]
        ["rubernetes", @component, generation.to_s, effect_type.to_s, key_digest].join(":")
      end

      def record(effect_type:, reconcile_key:, action:, object: nil, response: nil,
                 generation: self.generation, effect_id: nil, extra: {})
        normalized_key = reconcile_key.to_s
        normalized_type = effect_type.to_s
        attempt_id = effect_id || self.effect_id(reconcile_key: normalized_key, effect_type: normalized_type,
                                                  generation: generation)
        event = {
          "schema_version" => 1,
          "kind" => "api_mutation",
          "component" => @component,
          "identity" => @identity,
          "generation" => generation.to_s,
          "effect_id" => attempt_id,
          "effect_key" => effect_key(reconcile_key: normalized_key, effect_type: normalized_type),
          "reconcile_key" => normalized_key,
          "effect_type" => normalized_type,
          "action" => action.to_s,
          "mutation" => true,
          "object_sha256" => object.nil? ? nil : self.class.digest(object),
          "response_sha256" => response.nil? ? nil : self.class.digest(response),
          "observed_at" => @clock.call.utc.iso8601(6)
        }.merge(stringify_keys(extra))
        append(event)
        event
      end

      def record_controller_event(reconcile_key:, event:, generation: self.generation, extra: {})
        append({
          "schema_version" => 1,
          "kind" => "controller_event",
          "component" => @component,
          "identity" => @identity,
          "generation" => generation.to_s,
          "effect_key" => effect_key(reconcile_key: reconcile_key, effect_type: "reconcile"),
          "reconcile_key" => reconcile_key.to_s,
          "event_sha256" => self.class.digest(event),
          "observed_at" => @clock.call.utc.iso8601(6)
        }.merge(stringify_keys(extra)))
      end

      def record_provider(reconcile_key:, provider:, operation:, generation: self.generation, extra: {})
        append({
          "schema_version" => 1,
          "kind" => "provider_event",
          "component" => @component,
          "identity" => @identity,
          "generation" => generation.to_s,
          "effect_key" => effect_key(reconcile_key: reconcile_key, effect_type: "provider:#{operation}"),
          "reconcile_key" => reconcile_key.to_s,
          "provider" => provider.to_s,
          "operation" => operation.to_s,
          "observed_at" => @clock.call.utc.iso8601(6)
        }.merge(stringify_keys(extra)))
      end

      # Each record is written and flushed at once on a handle kept open;
      # the fsync that makes it durable is coalesced (one per FSYNC_INTERVAL
      # across all records written meanwhile).  Opening, locking, fsyncing and
      # closing the file for every record put a serialized 10-20 ms disk wait
      # behind every controller write -- a ReplicationController creating 100
      # Pods spent most of its 19 s here and in TLS handshakes.  A crash loses
      # at most the last interval of records, whose effects a controller
      # repeats idempotently (a deterministic create meets AlreadyExists and
      # adopts).
      FSYNC_INTERVAL_SECONDS = 0.02

      def append(event)
        normalized = self.class.canonical(event)
        line = JSON.generate(normalized)
        @mutex.synchronize do
          @io ||= File.open(@path, File::WRONLY | File::CREAT | File::APPEND, 0o600)
          @io.write("#{line}\n")
          @io.flush
          @fsync_pending = true
          start_flusher_locked
        end
        normalized
      end

      # Fsync now (shutdown, tests).
      def flush!
        @mutex.synchronize do
          @io&.fsync if @fsync_pending
          @fsync_pending = false
        end
        nil
      end

      def fsync_pending?
        @mutex.synchronize { @fsync_pending == true }
      end

      def close
        flush!
        @mutex.synchronize do
          @io&.close
          @io = nil
        end
      end

      def start_flusher_locked
        return if @flusher_running

        @flusher_running = true
        @flusher = Thread.new do
          Thread.current.name = "effect-journal-fsync"
          loop do
            sleep(FSYNC_INTERVAL_SECONDS)
            done = @mutex.synchronize do
              if @fsync_pending
                begin
                  @io&.fsync
                rescue SystemCallError, IOError
                  nil
                end
                @fsync_pending = false
                false
              else
                @flusher_running = false
                true
              end
            end
            break if done
          end
        end
      end

      private

      def stringify_keys(value)
        return {} unless value.is_a?(Hash)

        value.each_with_object({}) { |(key, child), result| result[key.to_s] = child }
      end

      def process_start_time(pid)
        text = File.read("/proc/#{pid}/stat")
        fields = text.rpartition(") ").last.split(" ")
        Integer(fields.fetch(19))
      rescue Errno::ENOENT, Errno::EACCES, IndexError, ArgumentError
        "unknown"
      end
    end
  end
end
