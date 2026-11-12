# frozen_string_literal: true

require "digest"
require "json"
require "monitor"
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
      # kube-apiserver's --etcd-compaction-interval, five minutes: etcd keeps
      # roughly one interval of history and compacts everything older, so a
      # continue token or a watch resourceVersion older than that is Gone.
      # A store that keeps a day of history never expires either, and clients
      # that are supposed to handle the expiry -- an informer relisting, a
      # chunked list resuming from an inconsistent token -- are never
      # exercised, which is what the API chunking conformance spec measures.
      DEFAULT_HISTORY_SECONDS = 5 * 60
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
        history_seconds: DEFAULT_HISTORY_SECONDS,
        watcher_buffer_size: DEFAULT_WATCHER_BUFFER_EVENTS,
        watcher_buffer_bytes: DEFAULT_WATCHER_BUFFER_BYTES,
        bookmark_interval: DEFAULT_BOOKMARK_INTERVAL,
        max_update_retries: DEFAULT_UPDATE_RETRIES,
        clock: -> { Time.now.utc },
        sleeper: ->(seconds) { Kernel.sleep(seconds) },
        random: Random.new,
        **options
      )
        history_revisions, history_seconds = retention_options(options, history_revisions, history_seconds)
        watcher_buffer_size = option_value(options, *WATCHER_BUFFER_EVENTS_OPTIONS, default: watcher_buffer_size)
        watcher_buffer_bytes = option_value(options, *WATCHER_BUFFER_BYTES_OPTIONS, default: watcher_buffer_bytes)
        @token_secret = options.delete(:token_secret)&.to_s || SecureRandom.hex(32)
        options.delete(:strict_request_uid)
        raise ArgumentError, "unknown MemoryStore options: #{options.keys.join(", ")}" unless options.empty?

        @history_revisions = validate_limit(history_revisions, "history_revisions", allow_nil: true)
        @history_seconds = validate_duration(history_seconds, "history_seconds")
        @watcher_buffer_size = validate_positive_limit(watcher_buffer_size, "watcher_buffer_size")
        @watcher_buffer_bytes = validate_positive_limit(watcher_buffer_bytes, "watcher_buffer_bytes")
        @bookmark_interval = validate_interval(bookmark_interval, "bookmark_interval")
        @max_update_retries = validate_positive_limit(max_update_retries, "max_update_retries", allow_zero: true)
        @clock = clock
        @sleeper = sleeper
        @random = random
        initialize_state
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
        @objects = {}
        @versions = Hash.new { |hash, key| hash[key] = [] }
        @known_keys = {}
        @sorted_keys = nil
        @resource_revisions = {}
        @history = []
        @last_full_compaction_at = nil
        @requests = {}
        @request_locks = {}
        @watchers = {}
        @next_watcher_id = 0
      end
    end

    # Stable aliases keep the storage boundary convenient for API adapters while
    # leaving the concrete implementation name explicit for callers that need it.
    Store = MemoryStore unless const_defined?(:Store, false)
    Watcher = MemoryStore::Watcher unless const_defined?(:Watcher, false)
    WatchStream = MemoryStore::Watcher unless const_defined?(:WatchStream, false)
  end
end
