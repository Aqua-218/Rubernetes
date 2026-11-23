# frozen_string_literal: true

require "digest"
require "json"
require "monitor"
require "openssl"
require "securerandom"

require_relative "memory_store/errors"
require_relative "memory_store/support"
require_relative "memory_store/list_result"
require_relative "memory_store/event"
require_relative "memory_store/selector"
# MemoryStore itself, one responsibility per file.
require_relative "memory_store/arguments"
require_relative "memory_store/revisions"
require_relative "memory_store/reads"
require_relative "memory_store/requests"
require_relative "memory_store/writes"
require_relative "memory_store/watcher"
require_relative "memory_store/watching"
require_relative "memory_store/compaction"
require_relative "memory_store/snapshot"
require_relative "memory_store/metrics"

module Rubernetes
  module Storage
    # The questions the store asks about the shape of a caller's argument.
    # Each one tells real inputs apart; the storage layer cannot name the API
    # classes behind them, so it asks instead of matching on a type.
    module Shape
      module_function

      # A selector or `out:` given as a lambda, a Method or any object with #call.
      def callable?(value)
        value.respond_to?(:call)
      end

      # API::Selectors (a label and a field selector) rather than one API::Selector.
      def selector_pair?(selector)
        selector.respond_to?(:label)
      end

      # An API::Registry::Resource rather than a bare resource name or nil.
      def typed_resource?(resource)
        resource.respond_to?(:api_version)
      end
    end

    # Thread-safe MVCC store used by the single-node API and deterministic tests.
    #
    # All mutations receive one process-wide revision. Every public object is a
    # fresh recursively frozen copy, so callers cannot mutate Store state through
    # a returned Hash. The monitor makes snapshot capture and commit notification
    # one atomic operation, which is the no-gap watch invariant.
    # Lock order is Store monitor -> watcher mutex. Watcher callbacks release
    # their mutex before unregistering, so a slow consumer cannot deadlock a
    # mutation commit.
    class MemoryStore
      Error = Storage::Error
      NotFound = Storage::NotFound
      AlreadyExists = Storage::AlreadyExists
      Conflict = Storage::Conflict
      Gone = Storage::Gone
      WatchOverflow = Storage::WatchOverflow

      DEFAULT_HISTORY_REVISIONS = 100_000
      COMPATIBILITY_HISTORY_POLICY = "compatibility"
      LONGER_HISTORY_POLICY = "longer_window"
      DEFAULT_HISTORY_POLICY = LONGER_HISTORY_POLICY
      COMPATIBILITY_HISTORY_SECONDS = 5 * 60
      LIST_CONTINUE_SECONDS = 5 * 60
      DEFAULT_HISTORY_SECONDS = 24 * 60 * 60
      DEFAULT_HISTORY_SECONDS_BY_POLICY = {
        COMPATIBILITY_HISTORY_POLICY => COMPATIBILITY_HISTORY_SECONDS,
        LONGER_HISTORY_POLICY => DEFAULT_HISTORY_SECONDS
      }.freeze
      DEFAULT_WATCHER_BUFFER_EVENTS = 1_024
      DEFAULT_WATCHER_BUFFER_BYTES = 16 * 1024 * 1024
      DEFAULT_BOOKMARK_INTERVAL = 30.0
      DEFAULT_UPDATE_RETRIES = 8
      MIN_BACKOFF_SECONDS = 0.005
      MAX_BACKOFF_SECONDS = 0.640

      Mutation = Data.define(:type, :key, :revision, :object, :old_object, :timestamp)
      RequestResult = Data.define(:fingerprint, :operation, :key, :revision, :result)

      # Every spelling a caller may use for a retention or watch buffer setting.
      HISTORY_REVISIONS_OPTIONS = %i[
        compaction_revisions compaction_revision compaction_revision_limit max_history_revisions history_limit retention_revisions
      ].freeze
      HISTORY_SECONDS_OPTIONS = %i[
        compaction_seconds compaction_time compaction_time_limit compaction_age max_history_age max_history_age_seconds
        history_ttl retention_seconds
      ].freeze
      WATCHER_BUFFER_EVENTS_OPTIONS = %i[
        watcher_buffer_events watcher_max_events watch_queue_size max_watch_events max_buffer_events watcher_buffer
      ].freeze
      WATCHER_BUFFER_BYTES_OPTIONS = %i[max_watch_bytes watcher_max_bytes watcher_buffer_limit_bytes max_buffer_bytes].freeze

      def initialize(
        history_revisions: DEFAULT_HISTORY_REVISIONS,
        history_retention_policy: DEFAULT_HISTORY_POLICY,
        history_seconds: DEFAULT_HISTORY_SECONDS_BY_POLICY[history_retention_policy],
        watcher_buffer_size: DEFAULT_WATCHER_BUFFER_EVENTS,
        watcher_buffer_bytes: DEFAULT_WATCHER_BUFFER_BYTES,
        bookmark_interval: DEFAULT_BOOKMARK_INTERVAL,
        max_update_retries: DEFAULT_UPDATE_RETRIES,
        clock: -> { Time.now.utc },
        token_secret: SecureRandom.hex(32),
        legacy_token_secret: token_secret,
        sleeper: ->(seconds) { Kernel.sleep(seconds) },
        random: Random.new,
        **options
      )
        history_revisions, history_seconds = retention_options(options, history_revisions, history_seconds)
        watcher_buffer_size = option_value(options, *WATCHER_BUFFER_EVENTS_OPTIONS, default: watcher_buffer_size)
        watcher_buffer_bytes = option_value(options, *WATCHER_BUFFER_BYTES_OPTIONS, default: watcher_buffer_bytes)
        @token_secret = token_secret.nil? ? nil : token_secret.to_s.dup.freeze
        @legacy_token_secret = (legacy_token_secret || SecureRandom.hex(32)).to_s.dup.freeze
        options.delete(:strict_request_uid)
        raise ArgumentError, "unknown MemoryStore options: #{options.keys.join(", ")}" unless options.empty?

        unless DEFAULT_HISTORY_SECONDS_BY_POLICY.key?(history_retention_policy)
          raise ArgumentError, "history_retention_policy must be one of #{DEFAULT_HISTORY_SECONDS_BY_POLICY.keys.join(", ")}"
        end

        @retain_longer_window = history_retention_policy == LONGER_HISTORY_POLICY
        @history_revisions = validate_history_revisions(history_revisions)
        @history_seconds = validate_interval(history_seconds, "history_seconds", optional: true)
        raise ArgumentError, "history_seconds must be finite" if @retain_longer_window && @history_seconds && !@history_seconds.finite?

        @watcher_buffer_size = validate_positive_limit(watcher_buffer_size, "watcher_buffer_size")
        @watcher_buffer_bytes = validate_positive_limit(watcher_buffer_bytes, "watcher_buffer_bytes")
        @bookmark_interval = validate_interval(bookmark_interval, "bookmark_interval")
        @max_update_retries = validate_positive_limit(max_update_retries, "max_update_retries", allow_zero: true)
        @clock = clock
        @sleeper = sleeper
        @random = random
        initialize_state
      end

      def use_continue_token_secret(secret)
        @monitor.synchronize { @token_secret = secret }
      end

      private

      # API::Selectors and API::Selector deliberately remain outside the
      # storage layer. When StoreAdapter injects one, adapt it to the storage
      # predicate boundary without requiring the API namespace here.
      def external_selector?(value)
        value.respond_to?(:matches?) && !value.is_a?(Hash) && !value.is_a?(Array)
      end

      # The retention pair, from the `compaction:` Hash and then from the flat
      # option spellings, which win.
      def retention_options(options, history_revisions, history_seconds)
        compaction = options.delete(:compaction)
        if compaction
          raise ArgumentError, "compaction must be a Hash" unless compaction.is_a?(Hash)

          history_revisions = compaction_value(compaction, :revisions, :max_revisions, :revision_limit, default: history_revisions)
          history_seconds = compaction_value(compaction, :seconds, :max_age, :age_seconds, :time_limit, default: history_seconds)
          raise ArgumentError, "unknown compaction options: #{compaction.keys.join(", ")}" unless compaction.empty?
        end
        [
          option_value(options, *HISTORY_REVISIONS_OPTIONS, default: history_revisions),
          option_value(options, *HISTORY_SECONDS_OPTIONS, default: history_seconds)
        ]
      end

      def initialize_state
        @monitor = Monitor.new
        @revision = 0
        @compacted_revision = 0
        # Every retained key owns one version chain. Its last entry is the
        # current object, or a tombstone retained for historical reads.
        @live_versions = {}
        @deleted_versions = {}
        @sorted_keys = nil
        @resource_revisions = {}
        @history = []
        @last_full_compaction_at = nil
        @requests = {}
        @request_locks = {}
        @watchers = {}
      end
    end

    # Stable aliases keep the storage boundary convenient for API adapters while
    # leaving the concrete implementation name explicit for callers that need it.
    Store = MemoryStore unless const_defined?(:Store, false)
    Watcher = MemoryStore::Watcher unless const_defined?(:Watcher, false)
    WatchStream = MemoryStore::Watcher unless const_defined?(:WatchStream, false)
  end
end
