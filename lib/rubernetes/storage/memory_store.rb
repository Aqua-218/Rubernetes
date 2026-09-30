# frozen_string_literal: true

require "digest"
require "json"
require "monitor"
require "securerandom"

module Rubernetes
  module Storage
    # Errors raised by the in-memory Store implementation.
    class Error < StandardError
      attr_reader :status, :reason, :key, :resource_version, :details, :causes

      def initialize(message = nil, status: nil, reason: nil, key: nil, resource_version: nil, details: nil, causes: nil)
        super(message)
        @status = status
        @reason = reason
        @key = key
        @resource_version = resource_version
        @details = details
        @causes = causes
      end

      alias code status
      alias http_status status
      alias http_code status
    end

    # The datastore cannot serve the request right now but nothing about it
    # is wrong: consensus is between leaders, or the quorum has not answered
    # in time.  kube-apiserver reports the same condition as a 503 with a
    # Retry-After, and every Kubernetes client retries it.
    class Unavailable < Error
      def initialize(message = "the datastore is currently unavailable", retry_after_seconds: 1)
        @retry_after_seconds = retry_after_seconds
        super(message, status: 503, reason: "ServiceUnavailable")
      end

      attr_reader :retry_after_seconds
    end

    class NotFound < Error
      def initialize(key, message = nil)
        super(message || "resource not found: #{key}", status: 404, reason: "NotFound", key: key)
      end
    end

    class AlreadyExists < Error
      def initialize(key, message = nil)
        super(message || "resource already exists: #{key}", status: 409, reason: "AlreadyExists", key: key)
      end
    end

    class Conflict < Error
      def initialize(key, message = nil, resource_version: nil)
        super(
          message || "resource version precondition failed for #{key}",
          status: 409,
          reason: "Conflict",
          key: key,
          resource_version: resource_version
        )
      end
    end

    # A request cannot be replayed with a different operation or payload.
    class RequestUIDConflict < Conflict
      attr_reader :request_uid

      def initialize(request_uid, key, message = nil)
        @request_uid = request_uid
        super(key, message || "request UID #{request_uid.inspect} was already used for a different request")
      end
    end

    class InvalidSelector < Error
      def initialize(message, field: nil)
        cause = ([{"reason" => "FieldValueInvalid", "message" => message.to_s, "field" => field.to_s}] if field)
        super(message, status: 400, reason: "BadRequest", details: cause && {"causes" => cause}, causes: cause)
      end
    end

    class InvalidContinueToken < Error
      def initialize(message = "invalid continue token")
        super(message, status: 400, reason: "BadRequest",
                       details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                               "field" => "continue"}]})
      end
    end

    class InvalidResourceVersion < Error
      def initialize(message)
        super(message, status: 400, reason: "BadRequest",
                       details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                               "field" => "resourceVersion"}]})
      end
    end

    class InvalidLimit < Error
      def initialize(message = "limit must be a positive integer")
        super(message, status: 400, reason: "BadRequest",
                       details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                               "field" => "limit"}]})
      end
    end

    # Returned when a watch starts before the retained history boundary.
    class Gone < Error
      def initialize(resource_version, compacted_revision)
        super(
          "resource version #{resource_version} is no longer available; compacted through #{compacted_revision}",
          status: 410,
          reason: "Expired",
          resource_version: resource_version,
          details: {"resourceVersion" => resource_version.to_s,
                    "compactedRevision" => compacted_revision.to_s}
        )
        @compacted_revision = compacted_revision
      end

      attr_reader :compacted_revision
    end

    Compacted = Gone
    CompactedError = Gone
    ResourceVersionTooOld = Gone
    ResourceVersionExpired = Gone
    Expired = Gone
    ConflictError = Conflict
    NotFoundError = NotFound
    AlreadyExistsError = AlreadyExists

    class WatchOverflow < Error
      def initialize
        super(
          "watch buffer exceeded its configured bound; relist before reconnecting",
          status: 410,
          reason: "Expired",
          details: {
            "causes" => [{"reason" => "WatchOverflow",
                          "message" => "watch buffer exceeded its configured bound; relist before reconnecting",
                          "field" => "resourceVersion"}]
          }
        )
      end
    end

    WatcherOverflow = WatchOverflow

    module MemoryStoreSupport
      module_function

      def deep_dup(value, seen = nil)
        case value
        when Hash
          return seen.fetch(value) if seen&.key?(value)

          duplicate = {}
          (seen ||= {}.compare_by_identity)[value] = duplicate
          value.each { |key, child| duplicate[deep_dup(key, seen)] = deep_dup(child, seen) }
          duplicate
        when Array
          return seen.fetch(value) if seen&.key?(value)

          duplicate = []
          (seen ||= {}.compare_by_identity)[value] = duplicate
          value.each { |child| duplicate << deep_dup(child, seen) }
          duplicate
        when String
          value.dup
        else
          value
        end
      end

      # Roots this module has deep-frozen itself.  An object that is known to
      # be frozen all the way down can be handed out as it is: every copy of a
      # stored object -- the response to a create, each item of a list, the
      # event for each of the watchers a write fans out to -- used to be a
      # fresh deep copy, about a quarter of a millisecond for a Pod, and a
      # write with twenty informers watching spent most of its 9 ms copying.
      DEEP_FROZEN = ObjectSpace::WeakMap.new

      def deep_freeze(value, seen = nil)
        return deep_freeze_walk(value, seen) if seen

        walked = !value.frozen? && (value.is_a?(Hash) || value.is_a?(Array))
        result = deep_freeze_walk(value, nil)
        DEEP_FROZEN[result] = true if walked
        result
      end

      def deep_frozen?(value)
        DEEP_FROZEN.key?(value)
      end

      def deep_freeze_walk(value, seen)
        return value if value.nil? || value.is_a?(Numeric) || value == true || value == false || value.frozen?
        return value if seen&.key?(value)

        (seen ||= {}.compare_by_identity)[value] = true
        case value
        when Hash
          value.each do |key, child|
            deep_freeze_walk(key, seen)
            deep_freeze_walk(child, seen)
          end
        when Array
          value.each { |child| deep_freeze_walk(child, seen) }
        end
        value.freeze
      end

      def immutable_copy(value)
        return value if DEEP_FROZEN.key?(value)

        deep_freeze(deep_dup(value))
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).zip(value.values).sort_by(&:first).to_h do |key, child|
            [key, canonical(child)]
          end
        when Array
          value.map { |child| canonical(child) }
        when Time
          value.utc.iso8601(9)
        when Proc
          {
            "__proc__" => value.source_location,
            "parameters" => value.parameters
          }
        else
          if value.respond_to?(:selector_signature)
            {"__selector__" => canonical(value.selector_signature)}
          elsif value.respond_to?(:call)
            {"__callable__" => value.class.name, "inspect" => value.inspect}
          else
            value
          end
        end
      end

      def digest(value)
        Digest::SHA256.hexdigest(canonical_json(value))
      end

      # Exactly the bytes JSON.generate(canonical(value)) produces -- digests
      # must stay comparable with those in a snapshot written before this
      # existed -- written straight into one buffer instead of through a tree
      # of sorted intermediate hashes, which cost more than the hashing did.
      def canonical_json(value, out = +"")
        case value
        when Hash
          by_key = {}
          value.each { |key, child| by_key[key.to_s] = child }
          out << "{"
          by_key.keys.sort.each_with_index do |key, index|
            out << "," unless index.zero?
            out << key.to_json << ":"
            canonical_json(by_key[key], out)
          end
          out << "}"
        when Array
          out << "["
          value.each_with_index do |child, index|
            out << "," unless index.zero?
            canonical_json(child, out)
          end
          out << "]"
        when String, Integer, Float, Symbol, true, false, nil
          out << value.to_json
        else
          out << JSON.generate(canonical(value))
        end
        out
      end

      # Array#pack is part of Ruby's core and keeps the M1 store independent of
      # the optional `base64` default gem removed from Ruby 3.4.
      def base64_url_encode(value)
        [value].pack("m0").tr("+/", "-_").delete("=")
      end

      def base64_url_decode(value)
        encoded = String(value).tr("-_", "+/")
        encoded += "=" * ((4 - (encoded.length % 4)) % 4)
        encoded.unpack1("m0")
      rescue ArgumentError, TypeError
        raise InvalidContinueToken
      end
    end

    # A tuple-compatible list response. It supports `objects, rv = list(...)`
    # while exposing Kubernetes-style metadata for callers that prefer names.
    # It intentionally is not an Array subclass: StoreAdapter must be able to
    # see `items`/`continue_token` and preserve pagination metadata instead of
    # treating the result as a bare two-element tuple.
    class ListResult
      include Enumerable

      attr_reader :items, :resource_version, :continue_token, :remaining_item_count

      def initialize(items:, resource_version:, continue_token: nil, remaining_item_count: nil)
        @items = items.freeze
        @resource_version = String(resource_version).freeze
        @continue_token = continue_token&.dup&.freeze
        @remaining_item_count = remaining_item_count
        freeze
      end

      alias resourceVersion resource_version
      alias continue continue_token
      alias remainingItemCount remaining_item_count

      def [](index, *)
        return @items if [:items, "items"].include?(index)
        return @resource_version if [:resource_version, "resourceVersion", "resource_version"].include?(index)
        return @continue_token if [:continue, "continue", "continue_token"].include?(index)
        return @remaining_item_count if [:remaining_item_count, "remainingItemCount"].include?(index)

        tuple = [@items, @resource_version]
        tuple[index, *]
      end

      def fetch(index, *args)
        return self[index] if index.is_a?(Symbol) || index.is_a?(String)

        [@items, @resource_version].fetch(index, *args)
      rescue IndexError
        return args.fetch(0) unless args.empty?

        raise
      end

      def each
        return enum_for(__method__) unless block_given?

        yield @items
        yield @resource_version
        self
      end

      def to_ary
        [@items, @resource_version]
      end

      alias to_a to_ary

      def first(count = nil)
        count.nil? ? @items : to_ary.first(count)
      end

      def last(count = nil)
        count.nil? ? @resource_version : to_ary.last(count)
      end

      def length
        2
      end
      alias size length

      def ==(other)
        to_ary == (other.respond_to?(:to_ary) ? other.to_ary : other)
      end
      alias eql? ==

      def hash
        to_ary.hash
      end

      def to_h
        {
          "items" => @items,
          "resourceVersion" => @resource_version,
          "continue" => @continue_token,
          "remainingItemCount" => @remaining_item_count
        }
      end
    end

    # One immutable change observed by a Watcher.
    class Event
      ADDED = "ADDED"
      MODIFIED = "MODIFIED"
      DELETED = "DELETED"
      BOOKMARK = "BOOKMARK"

      attr_reader :type, :object, :revision, :key

      def initialize(type:, object:, revision:, key: nil)
        @type = String(type).upcase.freeze
        @object = MemoryStoreSupport.immutable_copy(object)
        @revision = Integer(revision)
        @key = key&.to_s&.freeze
        freeze
      end

      alias event_type type
      alias resource_version revision

      def resourceVersion
        resource_version_string
      end

      def resource_version_string
        @revision.to_s
      end

      def [](name)
        case name.to_s
        when "type"
          @type
        when "object"
          @object
        when "revision"
          @revision
        when "resourceVersion", "resource_version"
          resource_version_string
        when "key"
          @key
        end
      end

      def to_h
        {"type" => @type, "object" => @object}
      end

      def to_json(*)
        JSON.generate(to_h, *)
      end

      def ==(other)
        other.is_a?(Event) &&
          other.type == type &&
          other.object == object &&
          other.revision == revision &&
          other.key == key
      end
      alias eql? ==

      def hash
        [@type, @object, @revision, @key].hash
      end
    end

    WatchEvent = Event

    # Bridges selector objects owned by API::StoreAdapter without coupling the
    # storage layer to API constants. Its stable signature keeps continue
    # tokens bound to the exact label/field query across requests.
    class ExternalSelectorPredicate
      attr_reader :selector_signature

      def initialize(selector, kind: :combined)
        @selector = selector
        @kind = kind.to_sym
        @selector_signature = MemoryStoreSupport.immutable_copy(signature_for(selector, @kind))
        freeze
      end

      def call(object)
        candidate = @kind == :label ? labels_from(object) : object
        @selector.matches?(candidate)
      end

      private

      def labels_from(object)
        metadata = object.is_a?(Hash) ? object.fetch("metadata", {}) : {}
        labels = metadata.fetch("labels", {})
        labels = labels.is_a?(Hash) ? MemoryStoreSupport.deep_dup(labels) : {}
        labels["metadata.name"] = metadata["name"] if metadata.key?("name")
        labels
      end

      def signature_for(selector, kind)
        if selector.respond_to?(:label) && selector.respond_to?(:field)
          {
            "kind" => kind.to_s,
            "label" => requirements_for(selector.label),
            "field" => requirements_for(selector.field)
          }
        elsif selector.respond_to?(:requirements)
          {"kind" => kind.to_s, "requirements" => requirements_for(selector)}
        else
          {"kind" => kind.to_s, "class" => selector.class.name, "inspect" => selector.inspect}
        end
      end

      def requirements_for(selector)
        Array(selector.respond_to?(:requirements) ? selector.requirements : selector).map do |requirement|
          {
            "key" => requirement.respond_to?(:key) ? requirement.key.to_s : requirement.to_s,
            "operator" => requirement.respond_to?(:operator) ? requirement.operator.to_s : nil,
            "values" => requirement.respond_to?(:values) ? Array(requirement.values).map(&:to_s) : []
          }
        end
      end
    end

    class Selector
      Clause = Data.define(:path, :operator, :values, :kind)

      attr_reader :signature

      def initialize(label_selector:, field_selector:)
        @label_clauses = parse(label_selector, :label)
        @field_clauses = parse(field_selector, :field)
        @signature = MemoryStoreSupport.digest(
          labels: @label_clauses.map(&:to_h),
          fields: @field_clauses.map(&:to_h)
        ).freeze
        freeze
      end

      def matches?(object)
        @label_clauses.all? { |clause| match_clause(clause, label_value(object, clause.path), object) } &&
          @field_clauses.all? { |clause| match_clause(clause, field_value(object, clause.path), object) }
      end

      def empty?
        @label_clauses.empty? && @field_clauses.empty?
      end

      private

      def parse(selector, kind)
        return [] if selector.nil? || selector == "" || selector == {}
        return [Clause.new(path: "", operator: :callable, values: [selector], kind: kind)] if selector.respond_to?(:call)

        if selector.is_a?(Hash)
          return selector.flat_map do |path, expected|
            parse_hash_clause(path, expected, kind)
          end
        end

        expressions = selector.is_a?(Array) ? selector : split_expressions(String(selector))
        expressions.flat_map { |expression| parse_expression(expression, kind) }
      rescue ArgumentError => error
        field = kind == :label ? "labelSelector" : "fieldSelector"
        raise InvalidSelector.new(error.message, field: field)
      end

      def parse_hash_clause(path, expected, kind)
        name = String(path).strip

        if name.start_with?("!")
          validate_selector_key!(name[1..].to_s)
          return [Clause.new(path: name[1..], operator: :not_exists, values: [], kind: kind)] if expected == true || expected.nil?

          raise ArgumentError, "absence selector cannot have a value: #{name}"
        end
        validate_selector_key!(name)

        case expected
        when Array
          [Clause.new(path: name, operator: :in, values: expected.map { |value| String(value) }, kind: kind)]
        when nil
          [Clause.new(path: name, operator: :exists, values: [], kind: kind)]
        else
          [Clause.new(path: name, operator: :equal, values: [String(expected)], kind: kind)]
        end
      end

      def parse_expression(expression, kind)
        text = String(expression).strip
        raise ArgumentError, "selector expression must not be empty" if text.empty?

        if text.start_with?("!") && !text.include?("=")
          path = text[1..].strip
          validate_selector_key!(path)

          return [Clause.new(path: path, operator: :not_exists, values: [], kind: kind)]
        end

        if (match = text.match(/\A(.+?)\s+(notin|in)\s*\((.*)\)\z/i))
          path = match[1].strip
          validate_selector_key!(path)
          values = split_values(match[3])
          raise ArgumentError, "set selector must contain a value" if values.empty?

          operator = match[2].downcase == "in" ? :in : :not_in
          return [Clause.new(path: path, operator: operator, values: values, kind: kind)]
        end

        if (match = text.match(/\A(.+?)\s*(!=|==|=)\s*(.*)\z/))
          path = match[1].strip
          validate_selector_key!(path)
          value = match[3].strip
          raise ArgumentError, "selector key must not be empty" if path.empty?
          raise ArgumentError, "selector value must not be empty" if value.empty?

          operator = match[2] == "!=" ? :not_equal : :equal
          return [Clause.new(path: path, operator: operator, values: [value], kind: kind)]
        end

        validate_selector_key!(text)
        [Clause.new(path: text, operator: :exists, values: [], kind: kind)]
      end

      def validate_selector_key!(value)
        raise ArgumentError, "selector key must not be empty" if value.empty?
        return value unless value.match?(/[=!,()\s]/)

        raise ArgumentError, "selector key #{value.inspect} is invalid"
      end

      def split_expressions(selector)
        expressions = []
        start = 0
        depth = 0
        selector.each_char.with_index do |char, index|
          depth += 1 if char == "("
          depth -= 1 if char == ")"
          raise ArgumentError, "unbalanced selector parentheses" if depth.negative?

          if char == "," && depth.zero?
            expressions << selector[start...index]
            start = index + 1
          end
        end
        raise ArgumentError, "unbalanced selector parentheses" unless depth.zero?

        expressions << selector[start..]
        expressions
      end

      def split_values(values)
        values.split(",").map(&:strip).reject(&:empty?)
      end

      def label_value(object, path)
        labels = object.dig("metadata", "labels")
        return nil unless labels.is_a?(Hash)

        labels[path]
      end

      def field_value(object, path)
        normalized_path = path.to_s
        normalized_path = "metadata.#{normalized_path}" if %w[name namespace uid resourceVersion].include?(normalized_path)
        normalized_path.split(".").reduce(object) do |value, segment|
          value.is_a?(Hash) ? value[segment] : nil
        end
      end

      def match_clause(clause, value, object)
        return clause.values.first.call(object) if clause.operator == :callable

        present = !value.nil?
        string_value = value.nil? ? nil : String(value)
        case clause.operator
        when :exists
          present
        when :not_exists
          !present
        when :equal
          present && string_value == clause.values.first
        when :not_equal
          !present || string_value != clause.values.first
        when :in
          present && clause.values.include?(string_value)
        when :not_in
          !present || !clause.values.include?(string_value)
        else
          false
        end
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
        compaction = options.delete(:compaction)
        if compaction
          raise ArgumentError, "compaction must be a Hash" unless compaction.is_a?(Hash)

          history_revisions = compaction_value(compaction, :revisions, :max_revisions, :revision_limit, default: history_revisions)
          history_seconds = compaction_value(compaction, :seconds, :max_age, :age_seconds, :time_limit, default: history_seconds)
          raise ArgumentError, "unknown compaction options: #{compaction.keys.join(", ")}" unless compaction.empty?
        end
        history_revisions = option_value(
          options,
          :compaction_revisions,
          :compaction_revision,
          :compaction_revision_limit,
          :max_history_revisions,
          :history_limit,
          :retention_revisions,
          default: history_revisions
        )
        history_seconds = option_value(
          options,
          :compaction_seconds,
          :compaction_time,
          :compaction_time_limit,
          :compaction_age,
          :max_history_age,
          :max_history_age_seconds,
          :history_ttl,
          :retention_seconds,
          default: history_seconds
        )
        watcher_buffer_size = option_value(
          options,
          :watcher_buffer_events,
          :watcher_max_events,
          :watch_queue_size,
          :max_watch_events,
          :max_buffer_events,
          :watcher_buffer,
          default: watcher_buffer_size
        )
        watcher_buffer_bytes = option_value(
          options,
          :max_watch_bytes,
          :watcher_max_bytes,
          :watcher_buffer_limit_bytes,
          :max_buffer_bytes,
          default: watcher_buffer_bytes
        )
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

      # The API server's registry (Observability::Metrics): this replica plays
      # kube-apiserver's watch cache -- LISTs and watches are served from it,
      # and it receives every committed event -- so it records the cacher's
      # series (apiserver_watch_cache_*, apiserver_init_events_total,
      # apiserver_terminated_watchers_total).  nil records nothing.
      attr_accessor :metrics

      # [group, resource] of a storage key or prefix.
      def self.group_resource(key)
        parts = key.to_s.delete_prefix("/").split("/", 5)
        return ["", parts[2].to_s].freeze if parts[1].to_s.match?(/\Av\d/)

        [parts[1].to_s, parts[3].to_s].freeze
      end

      def revision
        @monitor.synchronize { @revision }
      end
      alias resource_version revision
      alias current_revision revision

      def compacted_revision
        @monitor.synchronize { @compacted_revision }
      end

      # The revision of the last write under a key space -- the first two
      # path components of the prefix ("registry/clusterroles" for
      # "registry/clusterroles/_cluster/", whatever the namespace or name that
      # follow).  A reader caching a resource's objects compares this instead
      # of the global revision, which every write to any resource advances:
      # the RBAC authorizer re-listed every ClusterRole on every request
      # because something, somewhere, had always just changed.  A prefix
      # shorter than a key space answers with the global revision.
      def revision_under(prefix)
        @monitor.synchronize do
          bucket = resource_bucket(prefix)
          bucket ? @resource_revisions.fetch(bucket, 0) : @revision
        end
      end

      def resource_version_string
        revision.to_s
      end

      def resourceVersion
        resource_version_string
      end

      def compacted?
        @monitor.synchronize { @compacted_revision.positive? }
      end

      def get(key, out: nil, resource_version: nil, **options)
        resource_version = options.delete(:at_revision) if options.key?(:at_revision)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown get options: #{options.keys.join(", ")}" unless options.empty?

        normalized_key = normalize_key(key)
        @monitor.synchronize do
          snapshot_revision = resolve_read_revision(resource_version)
          object = object_at_revision(normalized_key, snapshot_revision)
          raise NotFound, normalized_key if object.nil?

          response = MemoryStoreSupport.immutable_copy(object)
          copy_to_out(out, response) if out
          response
        end
      end

      def create(key, object, request_uid: nil, request_id: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        body = options.delete(:body)
        object_keyword = options.delete(:object)
        resource_keyword = options.delete(:resource)
        object ||= body || object_keyword || resource_keyword
        discard_options(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown create options: #{options.keys.join(", ")}" unless options.empty?

        normalized_key = normalize_key(key)
        candidate = normalize_object(object)

        @monitor.synchronize do
          fingerprint = request_fingerprint(:create, normalized_key, candidate, nil)
          replay = replay_request(request_uid, fingerprint, :create, normalized_key)
          return replay unless replay.equal?(NO_REPLAY)
          raise AlreadyExists, normalized_key if @objects.key?(normalized_key) && !@objects[normalized_key].nil?

          committed = commit_locked(:added, normalized_key, candidate)
          remember_request(request_uid, fingerprint, :create, normalized_key, committed)
          immutable_response(committed)
        end
      end

      def guaranteed_update(
        key,
        prec: nil,
        precondition: nil,
        resource_version: nil,
        request_uid: nil,
        request_id: nil,
        max_retries: @max_update_retries,
        **options,
        &block
      )
        request_uid ||= request_id || options.delete(:uid)
        allow_nil_result = options.delete(:allow_nil_result) { false }
        # The replay fingerprint must identify the *client's* request. A caller
        # that recomputes the optimistic-concurrency version on every attempt
        # (RaftStore#guaranteed_update does) would otherwise produce a different
        # fingerprint for the same UID once the first attempt applied, and the
        # idempotent replay would be reported as a UID conflict instead.
        replay_precondition = options.key?(:replay_precondition) ? options.delete(:replay_precondition) : :same
        raise ArgumentError, "unknown guaranteed_update options: #{options.keys.join(", ")}" unless options.empty?
        raise ArgumentError, "guaranteed_update requires a block" unless block

        expected = normalize_precondition(
          if prec.nil?
            precondition.nil? ? resource_version : precondition
          else
            prec
          end
        )
        normalized_key = normalize_key(key)
        retries = validate_positive_limit(max_retries, "max_retries", allow_zero: true)
        request_uid = normalize_request_uid(request_uid) unless request_uid.nil?
        replay_expected = replay_precondition == :same ? expected : normalize_precondition(replay_precondition)
        with_request_lock(request_uid) do
          guaranteed_update_with_retry(
            normalized_key,
            expected,
            request_uid,
            retries,
            allow_nil_result,
            replay_expected,
            &block
          )
        end
      end

      # Replace the complete object while preserving the same optimistic CAS
      # semantics as guaranteed_update. API::StoreAdapter uses this shape for
      # PUT/PATCH paths and supplies transport-only resource metadata in
      # keywords; those keywords are intentionally ignored here.
      def update(
        key,
        object = nil,
        prec: nil,
        precondition: nil,
        resource_version: nil,
        request_uid: nil,
        request_id: nil,
        **options
      )
        request_uid ||= request_id || options.delete(:uid)
        body = options.delete(:body)
        object_keyword = options.delete(:object)
        resource_keyword = options.delete(:resource)
        object ||= body || object_keyword || resource_keyword
        discard_options(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown update options: #{options.keys.join(", ")}" unless options.empty?
        raise ArgumentError, "update requires an API object Hash" unless object.is_a?(Hash)

        expected = normalize_precondition(
          if prec.nil?
            precondition.nil? ? resource_version : precondition
          else
            prec
          end
        )
        candidate = normalize_object(object)
        guaranteed_update(key, prec: expected, request_uid: request_uid) { |_current| candidate }
      end

      alias replace update

      def delete(key, prec: nil, precondition: nil, resource_version: nil, request_uid: nil, request_id: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown delete options: #{options.keys.join(", ")}" unless options.empty?

        expected = normalize_precondition(
          if prec.nil?
            precondition.nil? ? resource_version : precondition
          else
            prec
          end
        )
        normalized_key = normalize_key(key)

        @monitor.synchronize do
          fingerprint = request_fingerprint(:delete, normalized_key, nil, expected)
          replay = replay_request(request_uid, fingerprint, :delete, normalized_key)
          return replay unless replay.equal?(NO_REPLAY)

          current = @objects[normalized_key]
          raise NotFound, normalized_key if current.nil?

          check_precondition!(normalized_key, current, expected)

          committed = commit_locked(:deleted, normalized_key, current)
          remember_request(request_uid, fingerprint, :delete, normalized_key, committed)
          immutable_response(committed)
        end
      end

      # Returns a tuple-compatible ListResult. Continue tokens pin a snapshot
      # revision, preventing mutations between pages from causing gaps/duplicates.
      def list(
        prefix = "",
        selector: nil,
        label_selector: nil,
        field_selector: nil,
        limit: nil,
        continue: nil,
        continue_token: nil,
        resource_version: nil,
        resource_version_match: nil,
        stats: nil,
        **options
      )
        resource_version = options.delete(:at_revision) if options.key?(:at_revision)
        if selector.is_a?(Hash) && (selector.key?("labels") || selector.key?(:labels) || selector.key?("fields") || selector.key?(:fields))
          label_selector ||= selector["labels"] || selector[:labels]
          field_selector ||= selector["fields"] || selector[:fields]
          selector = nil
        end
        if external_selector?(selector)
          selector = selector_callable(selector, kind: :combined)
          label_selector = nil
          field_selector = nil
        else
          label_selector = selector_callable(label_selector, kind: :label) if external_selector?(label_selector)
          field_selector = selector_callable(field_selector, kind: :field) if external_selector?(field_selector)
        end
        label_selector ||= selector
        continue ||= continue_token || options.delete(:token)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown list options: #{options.keys.join(", ")}" unless options.empty?

        normalized_prefix = String(prefix || "")
        normalized_limit = normalize_limit(limit)
        normalized_resource_version_match = normalize_resource_version_match(resource_version_match)
        selector_object = Selector.new(label_selector: label_selector, field_selector: field_selector)

        @monitor.synchronize do
          token = decode_continue_token(continue) if continue
          if token
            normalized_resource_version_match ||= token["resource_version_match"]
            validate_continue_token!(token, normalized_prefix, selector_object, normalized_limit,
                                     normalized_resource_version_match)
            token = restart_compacted_continue(token)
            snapshot_revision = token.fetch("revision")
            effective_limit = token.fetch("limit")
            last_key = token.fetch("last_key")
          else
            snapshot_revision = resolve_list_revision(resource_version, normalized_resource_version_match,
                                                      limit: normalized_limit)
            effective_limit = normalized_limit
            last_key = nil
          end

          ensure_snapshot_available!(snapshot_revision)
          keys = keys_with_prefix_locked(normalized_prefix, after: last_key)
          # One pass.  This used to resolve every key in the prefix to its
          # object at the snapshot revision, keep them all, and then -- to
          # find the key the next page starts after -- resolve every key
          # again.  A paged walk of N objects therefore cost O(N) resolutions
          # per page and O(N^2) over the walk, which is why listing a
          # thousand objects a hundred at a time took minutes.  Without a
          # selector the scan stops one object past the page; with one it
          # must go on, because remainingItemCount counts the matches behind
          # the page and only a selector can hide them.
          selected = []
          last_selected_key = nil
          more = false
          extra_matches = 0
          fetched = 0
          keys.each do |key|
            object = object_at_revision(key, snapshot_revision)
            next unless object

            fetched += 1
            next unless selector_object.matches?(object)

            if effective_limit && selected.length >= effective_limit
              more = true
              break if selector_object.empty?

              extra_matches += 1
              next
            end
            selected << object
            last_selected_key = key
          end
          # apiserver_cache_list_*: objects read from the cache to serve the
          # LIST, and objects returned.
          if stats
            stats[:fetched] = fetched
            stats[:returned] = selected.length
          end
          remaining = extra_matches.positive? && !selector_object.empty? ? extra_matches : nil
          next_key = more ? last_selected_key : nil
          token_value = if next_key
                          encode_continue_token(
                            "revision" => snapshot_revision,
                            "prefix" => normalized_prefix,
                            "selector" => selector_object.signature,
                            "limit" => effective_limit,
                            "resource_version_match" => normalized_resource_version_match,
                            "last_key" => next_key
                          )
                        end
          ListResult.new(
            items: selected.map { |object| MemoryStoreSupport.immutable_copy(object) },
            resource_version: snapshot_revision,
            continue_token: token_value,
            remaining_item_count: remaining
          )
        end
      end

      # Start a Watcher after atomically capturing retained history and registering
      # the live subscriber. This ordering is what prevents a list/watch race from
      # dropping the first mutation after a caller's resourceVersion.
      def watch(prefix = "", *positional, since: nil, resource_version: nil, label_selector: nil, field_selector: nil,
                selector: nil, allow_bookmarks: false, allow_watch_bookmarks: nil,
                bookmark_interval: @bookmark_interval, send_initial_events: false,
                resource_version_match: nil, timeout_seconds: nil, **options)
        raise ArgumentError, "watch accepts at most one positional since revision" if positional.length > 1
        raise ArgumentError, "watch since revision was supplied twice" if !positional.empty? && !since.nil?

        since = positional.first if since.nil? && !positional.empty?
        since = resource_version if since.nil? && !resource_version.nil?
        since = options.delete(:start_revision) if since.nil? && options.key?(:start_revision)
        allow_bookmarks = allow_watch_bookmarks unless allow_watch_bookmarks.nil?
        allow_bookmarks = options.delete(:allow_bookmark) unless options[:allow_bookmark].nil?
        bookmark_interval = options.delete(:bookmark_interval_seconds) if options.key?(:bookmark_interval_seconds)
        resource = options.delete(:resource)
        max_events = if options.key?(:buffer_size)
                       options.delete(:buffer_size)
                     elsif options.key?(:max_events)
                       options.delete(:max_events)
                     else
                       @watcher_buffer_size
                     end
        max_bytes = if options.key?(:buffer_bytes)
                      options.delete(:buffer_bytes)
                    elsif options.key?(:max_bytes)
                      options.delete(:max_bytes)
                    else
                      @watcher_buffer_bytes
                    end
        discard_options(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown watch options: #{options.keys.join(", ")}" unless options.empty?

        if selector.is_a?(Hash) && (selector.key?("labels") || selector.key?(:labels) || selector.key?("fields") || selector.key?(:fields))
          label_selector ||= selector["labels"] || selector[:labels]
          field_selector ||= selector["fields"] || selector[:fields]
          selector = nil
        end
        if external_selector?(selector)
          selector = selector_callable(selector, kind: :combined)
          label_selector = nil
          field_selector = nil
        else
          label_selector = selector_callable(label_selector, kind: :label) if external_selector?(label_selector)
          field_selector = selector_callable(field_selector, kind: :field) if external_selector?(field_selector)
        end
        normalized_prefix = String(prefix || "")
        selector_object = Selector.new(label_selector: label_selector || selector, field_selector: field_selector)
        normalized_since = since.nil? || since == "" ? nil : parse_revision(since)
        normalized_resource_version_match = normalize_resource_version_match(resource_version_match)

        # "Get State and Start at Any" (the resourceVersion semantics table): an
        # unset or zero resourceVersion asks for the current state as synthetic
        # ADDED events BEFORE the stream.  Starting at the current revision
        # instead delivered nothing until the object next changed, so every
        # client that watches after creating an object -- which is how most of
        # the e2e "lifecycle" specs are written -- waited out its whole timeout
        # and reported "failed to find ADDED event".
        initial_state = send_initial_events || normalized_since.nil? || normalized_since.zero?

        @monitor.synchronize do
          if normalized_resource_version_match == "NotOlderThan"
            requested_revision = normalized_since.nil? ? @revision : normalized_since
            if requested_revision > @revision
              raise InvalidResourceVersion,
                    "watch revision #{requested_revision} is ahead of current revision #{@revision}"
            end

            # A watch-list's initial state is served from the current
            # snapshot even when the lower-bound RV has already compacted.
            start_revision = @revision
          elsif initial_state
            start_revision = @revision
          else
            start_revision = normalized_since
          end
          ensure_snapshot_available!(start_revision)
          if start_revision > @revision
            raise InvalidResourceVersion,
                  "watch revision #{start_revision} is ahead of current revision #{@revision}"
          end

          @next_watcher_id += 1
          watcher = Watcher.new(
            prefix: normalized_prefix,
            selector: selector_object,
            allow_bookmarks: !!allow_bookmarks,
            bookmark_interval: bookmark_interval,
            max_events: max_events,
            max_bytes: max_bytes,
            clock: @clock,
            bookmark_provider: -> { revision },
            bookmark_callback: ->(bookmark_watcher) { enqueue_bookmark(bookmark_watcher) },
            bookmark_identity: bookmark_identity(resource),
            on_close: ->(closed_watcher) { unregister_watcher(closed_watcher) },
            timeout_seconds: timeout_seconds
          )
          init_events = 0
          if initial_state
            initial_keys = @objects.filter_map do |key, object|
              next if object.nil?
              next unless key.start_with?(normalized_prefix) && selector_object.matches?(object)

              key
            end.sort
            initial_keys.each do |key|
              object = @objects.fetch(key)

              delivered = watcher.enqueue(
                Mutation.new(
                  type: :added,
                  key: key,
                  revision: object_revision(object),
                  object: object,
                  old_object: nil,
                  timestamp: clock_value
                )
              )
              init_events += 1 if delivered
              break if watcher.closed?
            end
            # The "initial events end" bookmark belongs to sendInitialEvents
            # alone; a plain unset-resourceVersion watch never carries one.
            watcher.enqueue_bookmark(@revision, initial_events_end: true) if send_initial_events && allow_bookmarks && !watcher.closed?
          else
            @history.each do |mutation|
              next unless mutation.revision > start_revision

              init_events += 1 if watcher.enqueue(mutation)
              break if watcher.closed?
            end
          end
          record_init_events(normalized_prefix, init_events) if @metrics && init_events.positive?
          @watchers[@next_watcher_id] = watcher unless watcher.closed?
          watcher
        end
      end

      def compact!(revision: nil, to_revision: nil, before_revision: nil, before: nil, through: nil, at_time: nil, now: nil)
        requested_revision = revision || to_revision || before_revision || before || through
        @monitor.synchronize do
          target = requested_revision.nil? ? compaction_target_locked(now: at_time || now) : parse_revision(requested_revision)
          raise InvalidResourceVersion, "cannot compact beyond current revision #{@revision}" if target > @revision

          compact_locked!(target, prune_all_versions: true)
          @compacted_revision
        end
      end

      alias compact compact!

      # Complete durable state for replication snapshots: revision counters,
      # per-key version history, mutation history and request memory.  Watchers
      # are connection state and are not exported.
      def export_state
        @monitor.synchronize do
          {
            "schema_version" => 1,
            "revision" => @revision,
            "compacted_revision" => @compacted_revision,
            "known_keys" => @known_keys.keys.sort,
            "versions" => @versions.keys.sort.to_h do |key|
                            [key, @versions[key].map { |(revision, object)| [revision, object] }]
                          end,
            "history" => @history.map do |mutation|
              {"type" => mutation.type.to_s, "key" => mutation.key, "revision" => mutation.revision,
               "object" => mutation.object, "old_object" => mutation.old_object, "timestamp" => mutation.timestamp}
            end,
            "requests" => @requests.keys.sort.each_with_object({}) do |uid, output|
              stored = @requests[uid]
              output[uid] = {"fingerprint" => stored.fingerprint, "operation" => stored.operation.to_s,
                             "key" => stored.key, "revision" => stored.revision, "result" => stored.result}
            end
          }
        end
      end

      # Replace the complete state with an exported document.  Only valid on a
      # store that has not been mutated; a replica restores into a fresh
      # instance so the import never mixes generations.
      def import_state(document)
        raise ArgumentError, "state document must be a Hash" unless document.is_a?(Hash)
        raise ArgumentError, "state schema_version must be 1" unless document["schema_version"] == 1

        @monitor.synchronize do
          raise ArgumentError, "import_state requires an unused store" unless @revision.zero? && @objects.empty?

          @revision = Integer(document.fetch("revision"))
          @compacted_revision = Integer(document.fetch("compacted_revision"))
          @known_keys = {}
          @sorted_keys = nil
          Array(document.fetch("known_keys")).each { |key| @known_keys[String(key)] = true }
          @versions = Hash.new { |hash, key| hash[key] = [] }
          @objects = {}
          @resource_revisions = {}
          document.fetch("versions").each do |key, entries|
            list = entries.map do |(revision, object)|
              [Integer(revision), object.nil? ? nil : MemoryStoreSupport.deep_freeze(MemoryStoreSupport.deep_dup(object))]
            end
            @versions[String(key)] = list
            @objects[String(key)] = list.last&.last
            if (latest = list.last&.first)
              bucket = resource_bucket(String(key))
              @resource_revisions[bucket] = [@resource_revisions.fetch(bucket, 0), latest].max
            end
          end
          @history = Array(document.fetch("history")).map do |entry|
            Mutation.new(type: entry.fetch("type").to_sym, key: entry.fetch("key"), revision: Integer(entry.fetch("revision")),
                         object: entry["object"].nil? ? nil : MemoryStoreSupport.deep_freeze(MemoryStoreSupport.deep_dup(entry["object"])),
                         old_object: entry["old_object"].nil? ? nil : MemoryStoreSupport.deep_freeze(MemoryStoreSupport.deep_dup(entry["old_object"])),
                         timestamp: entry["timestamp"].nil? ? nil : Float(entry["timestamp"]))
          end
          @requests = {}
          document.fetch("requests").each do |uid, stored|
            @requests[String(uid)] = RequestResult.new(fingerprint: stored.fetch("fingerprint").freeze, operation: stored.fetch("operation").to_sym,
                                                       key: stored.fetch("key").freeze, revision: stored["revision"].nil? ? nil : Integer(stored["revision"]),
                                                       result: MemoryStoreSupport.immutable_copy(stored.fetch("result")))
          end
        end
        self
      end

      # Stored objects per resource key space ("registry/<group/version>/<resource>"),
      # for apiserver_storage_objects.  Only the key list is taken under the
      # lock; it is counted outside, and only when /metrics asks.
      def object_counts
        keys = @monitor.synchronize { @objects.filter_map { |key, object| key unless object.nil? } }
        keys.each_with_object(Hash.new(0)) do |key, counts|
          parts = key.split("/", 5)
          width = parts[1].to_s.match?(/\Av\d/) ? 3 : 4
          next if parts.length < width

          counts[parts.first(width).join("/")] += 1
        end
      end

      # apiserver_resource_size_estimate_bytes: the stored objects' encoded
      # size per resource prefix (what etcd would hold for them).
      def object_sizes
        entries = @monitor.synchronize { @objects.filter_map { |key, object| [key, object] unless object.nil? } }
        entries.each_with_object(Hash.new(0)) do |(key, object), sizes|
          parts = key.split("/", 5)
          width = parts[1].to_s.match?(/\Av\d/) ? 3 : 4
          next if parts.length < width

          sizes[parts.first(width).join("/")] += JSON.generate(object).bytesize
        rescue StandardError
          next
        end
      end

      def watcher_count
        @monitor.synchronize { @watchers.length }
      end

      # Waits (at most +timeout+ seconds) until every watcher that was handed
      # the event of +revision+ has written it to its client; see
      # Watcher#await_delivered.  Returns false if some watcher was not done.
      def await_watch_delivery(revision, timeout:)
        target = Integer(revision)
        watchers = @monitor.synchronize { @watchers.values }
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout)
        watchers.map { |watcher| watcher.await_delivered(target, deadline) }.all?
      rescue ArgumentError, TypeError
        true
      end

      # This store's state is being replaced wholesale (a raft follower
      # restoring a snapshot swaps in a new store).  Every open watch follows
      # THIS store, so it would stay healthy-looking and silent while all new
      # writes land in the replacement -- until the client's watch timed out
      # minutes later.  End each one with 410 Expired, which tells the client
      # to relist and re-watch, exactly as a compacted etcd watch does.
      def expire_watchers!
        watchers = @monitor.synchronize do
          current = @watchers.values
          @watchers.clear
          current
        end
        watchers.each { |watcher| watcher.fail_with(WatchOverflow.new) }
        self
      end

      def close
        @monitor.synchronize do
          @watchers.values.each(&:close)
          @watchers.clear
        end
        self
      end

      class Watcher
        def initialize(prefix:, selector:, allow_bookmarks:, bookmark_interval:, max_events:, max_bytes:, clock:,
                       bookmark_provider:, on_close:, bookmark_callback: nil, bookmark_identity: nil,
                       timeout_seconds: nil)
          @prefix = prefix.freeze
          @selector = selector
          @allow_bookmarks = allow_bookmarks
          @bookmark_interval = Float(bookmark_interval)
          @max_events = self.class.positive_limit(max_events, "max_events")
          @max_bytes = self.class.positive_limit(max_bytes, "max_bytes")
          @clock = clock
          @timeout_seconds = timeout_seconds.nil? ? nil : Float(timeout_seconds)
          raise ArgumentError, "timeout_seconds must be non-negative" if @timeout_seconds&.negative?

          @bookmark_provider = bookmark_provider
          @bookmark_callback = bookmark_callback
          @bookmark_identity = MemoryStoreSupport.immutable_copy(bookmark_identity || {})
          @on_close = on_close
          @mutex = Mutex.new
          @condition = ConditionVariable.new
          @queue = []
          @queue_bytes = 0
          @closed = false
          @error = nil
          @last_bookmark_at = clock_value
          @last_revision = nil
          @returned_revision = nil
          @delivered_revision = nil
        end

        # A consumer asks for the next event only after it has written the
        # previous one to its client, so the revision it was last handed is
        # "delivered" once it comes back.  #await_delivered lets a writer
        # hold its own response until the watchers it woke have sent the
        # event: a client that reads its informer cache right after a write
        # (the e2e CRUD helper polls it, then waits 2 s before looking again)
        # otherwise raced the event and lost two seconds per step.
        BACKLOG_LIMIT = 2

        def await_delivered(revision, deadline)
          @mutex.synchronize do
            loop do
              return true if @closed || @error
              return true if @last_revision.nil? || @last_revision < revision
              return true if @delivered_revision && @delivered_revision >= revision
              # A watcher already behind is a slow reader; it is not waited for.
              return true if @queue.length > BACKLOG_LIMIT

              remaining = deadline - monotonic_now
              return false if remaining <= 0

              @condition.wait(@mutex, remaining)
            end
          end
        end

        def enqueue(mutation, bytesize: nil)
          event = event_for(mutation)
          return false unless event

          size = bytesize || JSON.generate(event.to_h).bytesize
          @mutex.synchronize do
            return false if @closed

            if @queue.length >= @max_events || @queue_bytes + size > @max_bytes
              @error = WatchOverflow.new
              @closed = true
              @queue.clear
              @queue_bytes = 0
              @condition.broadcast
              return false
            end

            @queue << [event, size]
            @queue_bytes += size
            @last_revision = event.revision
            @condition.broadcast
            true
          end
        # A selector is evaluated while the Store monitor is held. Propagating a
        # user callback exception would make a committed mutation look failed, so
        # terminate only this watcher and surface the original error on next().
        rescue StandardError => error
          fail_with(error)
          false
        end

        def next(timeout: nil)
          timeout = @timeout_seconds if timeout.nil? && !@timeout_seconds.nil?
          deadline = timeout.nil? ? nil : monotonic_now + Float(timeout)
          loop do
            action = nil
            @mutex.synchronize do
              raise @error if @error

              if @returned_revision && (@delivered_revision.nil? || @delivered_revision < @returned_revision)
                @delivered_revision = @returned_revision
                @condition.broadcast
              end
              unless @queue.empty?
                event = @queue.shift.tap { |entry| @queue_bytes -= entry[1] }.first
                @returned_revision = event.revision if event.respond_to?(:revision) && event.revision
                return event
              end
              return nil if @closed

              if @allow_bookmarks && bookmark_due?
                action = :bookmark
              else
                wait_for = wait_duration(deadline)
                return nil if wait_for&.negative? || wait_for == 0.0

                @condition.wait(@mutex, wait_for)
              end
            end
            bookmark! if action == :bookmark
          end
        end

        def pop(timeout = nil, **options)
          timeout = options.fetch(:timeout, timeout)
          self.next(timeout: timeout)
        end

        def poll(timeout: 0)
          self.next(timeout: timeout)
        end

        def each(timeout: nil)
          return enum_for(__method__, timeout: timeout) unless block_given?

          loop do
            event = self.next(timeout: timeout)
            break if event.nil?

            yield event
          end
          self
        end

        def to_a(timeout: :default)
          events = []
          effective_timeout = timeout == :default ? (@timeout_seconds || 0) : timeout
          each(timeout: effective_timeout) { |event| events << event }
          events
        end

        alias events to_a

        def each_json_line(timeout: :default)
          return enum_for(__method__, timeout: timeout) unless block_given?

          effective_timeout = timeout == :default ? (@timeout_seconds || 0) : timeout
          each(timeout: effective_timeout) { |event| yield JSON.generate(event.to_h) << "\n" }
          self
        end

        def bookmark!
          return nil unless @allow_bookmarks

          return @bookmark_callback.call(self) if @bookmark_callback

          enqueue_bookmark(Integer(@bookmark_provider.call))
        end

        def enqueue_bookmark(current_revision, initial_events_end: false)
          current_revision = Integer(current_revision)
          object = MemoryStoreSupport.deep_dup(@bookmark_identity)
          metadata = object["metadata"] = MemoryStoreSupport.deep_dup(object["metadata"] || {})
          metadata["resourceVersion"] = current_revision.to_s
          if initial_events_end
            annotations = metadata["annotations"] = MemoryStoreSupport.deep_dup(metadata["annotations"] || {})
            annotations["k8s.io/initial-events-end"] = "true"
          end
          event = Event.new(
            type: Event::BOOKMARK,
            object: object,
            revision: current_revision
          )
          size = JSON.generate(event.to_h).bytesize
          @mutex.synchronize do
            return nil if @closed

            if @queue.length >= @max_events || @queue_bytes + size > @max_bytes
              @error = WatchOverflow.new
              @closed = true
              @queue.clear
              @queue_bytes = 0
              @condition.broadcast
              return nil
            end

            @queue << [event, size]
            @queue_bytes += size
            @last_revision = current_revision
            @last_bookmark_at = clock_value
            @condition.broadcast
            event
          end
        end

        def fail_with(error)
          @mutex.synchronize do
            return if @closed

            @error = error
            @closed = true
            @queue.clear
            @queue_bytes = 0
            @condition.broadcast
          end
        end

        def close
          should_unregister = @mutex.synchronize do
            next false if @closed && @error.nil?

            @closed = true
            @queue.clear
            @queue_bytes = 0
            @condition.broadcast
            true
          end
          @on_close.call(self) if should_unregister
          self
        end

        alias stop close
        alias close! close

        # A single boolean read, asked of every watcher on every commit: the
        # mutex around it was a twentieth of an apiserver's CPU.  @closed only
        # ever goes from false to true, so a stale false costs one extra
        # enqueue attempt, which checks again under the lock.
        def closed?
          @closed
        end

        alias closed closed?

        def overflowed?
          @mutex.synchronize { @error.is_a?(WatchOverflow) }
        end

        def alive?
          !closed?
        end

        attr_reader :prefix, :selector, :error, :last_revision

        def last_resource_version
          @last_revision&.to_s
        end

        private

        def event_for(mutation)
          return nil unless mutation.key.start_with?(@prefix)

          old_matches = mutation.old_object && @selector.matches?(mutation.old_object)
          new_matches = mutation.object && mutation.type != :deleted && @selector.matches?(mutation.object)
          type, object = case mutation.type
                         when :added
                           new_matches ? [Event::ADDED, mutation.object] : [nil, nil]
                         when :modified
                           if old_matches && new_matches
                             [Event::MODIFIED, mutation.object]
                           elsif !old_matches && new_matches
                             [Event::ADDED, mutation.object]
                           elsif old_matches && !new_matches
                             [Event::DELETED, mutation.old_object]
                           else
                             [nil, nil]
                           end
                         when :deleted
                           old_matches ? [Event::DELETED, mutation.object] : [nil, nil]
                         end
          return nil unless type

          Event.new(type: type, object: object, revision: mutation.revision, key: mutation.key)
        end

        def bookmark_due?
          clock_value - @last_bookmark_at >= @bookmark_interval
        end

        def wait_duration(deadline)
          durations = []
          durations << (deadline - monotonic_now) if deadline
          durations << (@bookmark_interval - (clock_value - @last_bookmark_at)) if @allow_bookmarks
          durations.compact.min
        end

        def clock_value
          value = @clock.call
          value.respond_to?(:to_f) ? value.to_f : Float(value)
        end

        def monotonic_now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        def self.positive_limit(value, name)
          number = Integer(value)
          raise ArgumentError, "#{name} must be positive" unless number.positive?

          number
        rescue TypeError, ArgumentError
          raise ArgumentError, "#{name} must be a positive integer"
        end
      end

      private

      NO_REPLAY = Object.new.freeze

      # API::Selectors and API::Selector deliberately remain outside the
      # storage layer. When StoreAdapter injects one, adapt it to the storage
      # predicate boundary without requiring the API namespace here.
      def external_selector?(value)
        value.respond_to?(:matches?) && !value.is_a?(Hash) && !value.is_a?(Array)
      end

      def selector_callable(selector, kind: :combined)
        ExternalSelectorPredicate.new(selector, kind: kind)
      end

      def discard_options(options, *names)
        names.each do |name|
          options.delete(name)
          options.delete(name.to_s)
        end
        options
      end

      def option_value(options, *names, default:)
        supplied = names.select { |name| options.key?(name) }
        return default if supplied.empty?

        first = supplied.first
        supplied.drop(1).each do |name|
          raise ArgumentError, "conflicting options: #{first} and #{name}" unless options.fetch(name) == options.fetch(first)
        end
        value = options.delete(first)
        supplied.drop(1).each { |name| options.delete(name) }
        value
      end

      def compaction_value(options, *names, default:)
        keys = names.select { |name| options.key?(name) || options.key?(name.to_s) }
        return default if keys.empty?

        first = keys.first
        value_for = ->(name) { options.key?(name) ? options.delete(name) : options.delete(name.to_s) }
        value = value_for.call(first)
        keys.drop(1).each do |name|
          candidate = value_for.call(name)
          raise ArgumentError, "conflicting compaction options: #{first} and #{name}" unless candidate == value
        end
        value
      end

      def validate_limit(value, name, allow_nil:)
        return nil if value.nil? && allow_nil

        number = Integer(value)
        raise ArgumentError, "#{name} must not be negative" if number.negative?

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a non-negative integer or nil"
      end

      def normalize_resource_version_match(value)
        return nil if value.nil? || value.to_s.empty?

        normalized = value.to_s
        return normalized if %w[Exact NotOlderThan].include?(normalized)

        raise InvalidResourceVersion, "resourceVersionMatch must be Exact or NotOlderThan"
      end

      def resolve_list_revision(resource_version, resource_version_match, limit: nil)
        # Kubernetes treats limit=0 as an unbounded list, while a resource
        # version still selects the snapshot used by the response. Exact
        # reads use that snapshot; NotOlderThan may use the latest revision.
        if resource_version_match == "NotOlderThan"
          requested = if resource_version.nil? || resource_version == "" || resource_version == 0 || resource_version == "0"
                        @revision
                      else
                        parse_revision(resource_version)
                      end
          raise InvalidResourceVersion, "resourceVersion #{requested} is ahead of current revision #{@revision}" if requested > @revision

          # NotOlderThan may safely serve the current revision even when the
          # requested lower bound has already been compacted.  Exact reads,
          # by contrast, must retain the requested snapshot and are rejected
          # by resolve_read_revision when it is gone.
          @revision
        elsif resource_version_match == "Exact" || (limit && limit.positive?)
          resolve_read_revision(resource_version)
        else
          # With no explicit match, the upstream cacher only honors an exact
          # RV for a chunked list.  An unchunked list uses the latest
          # consistent revision (including when the requested RV was compacted).
          if resource_version.nil? || resource_version == "" || resource_version == 0 || resource_version == "0"
          else
            requested = parse_revision(resource_version)
            raise InvalidResourceVersion, "resourceVersion #{requested} is ahead of current revision #{@revision}" if requested > @revision

          end
          @revision
        end
      end

      def validate_positive_limit(value, name, allow_zero: false)
        number = Integer(value)
        valid = allow_zero ? number >= 0 : number.positive?
        raise ArgumentError, "#{name} must be #{allow_zero ? "non-negative" : "positive"}" unless valid

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be an #{allow_zero ? "non-negative" : "positive"} number"
      end

      def validate_interval(value, name)
        number = Float(value)
        raise ArgumentError, "#{name} must be non-negative" if number.negative?

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a non-negative number"
      end

      def validate_duration(value, name)
        return nil if value.nil?

        number = Float(value)
        raise ArgumentError, "#{name} must be non-negative" if number.negative?

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a non-negative number or nil"
      end

      def normalize_key(key)
        normalized = String(key)
        raise ArgumentError, "key must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "key must be coercible to String"
      end

      def normalize_object(object)
        raise ArgumentError, "API object must be a Hash" unless object.is_a?(Hash)

        copy = MemoryStoreSupport.deep_dup(object)
        validate_string_keys!(copy)
        metadata = copy["metadata"]
        if metadata.nil?
          copy["metadata"] = {}
        elsif !metadata.is_a?(Hash)
          raise ArgumentError, "API object metadata must be a Hash"
        end
        copy
      end

      def validate_string_keys!(value, seen = nil)
        return unless value.is_a?(Hash) || value.is_a?(Array)

        seen ||= {}.compare_by_identity
        raise ArgumentError, "API object must not contain cycles" if seen.key?(value)

        seen[value] = true
        begin
          if value.is_a?(Hash)
            value.each do |key, child|
              raise ArgumentError, "API object Hash keys must be Strings" unless key.is_a?(String)

              validate_string_keys!(child, seen)
            end
          else
            value.each { |child| validate_string_keys!(child, seen) }
          end
        ensure
          seen.delete(value)
        end
      end

      # The object committed is normalize_object's private copy in the create
      # and update paths, so it is stamped in place; only a frozen object (the
      # stored one, on delete) is copied first.  Copying again here doubled
      # the deep copies on every write.
      def stamp_object(object, revision)
        copy = object.frozen? ? MemoryStoreSupport.deep_dup(object) : object
        metadata = copy.fetch("metadata")
        metadata["resourceVersion"] = revision.to_s
        MemoryStoreSupport.deep_freeze(copy)
      end

      def immutable_response(object)
        MemoryStoreSupport.immutable_copy(object)
      end

      def copy_to_out(out, response)
        if out.respond_to?(:replace)
          out.replace(MemoryStoreSupport.deep_dup(response))
          MemoryStoreSupport.deep_freeze(out)
        elsif out.respond_to?(:call)
          out.call(response)
        else
          raise ArgumentError, "out must respond to replace or call"
        end
      end

      def object_revision(object)
        parse_revision(object.dig("metadata", "resourceVersion"))
      end

      def parse_revision(value)
        revision = Integer(value)
        raise InvalidResourceVersion, "resourceVersion must be non-negative" if revision.negative?

        revision
      rescue TypeError, ArgumentError
        raise InvalidResourceVersion, "resourceVersion must be a non-negative integer"
      end

      def resolve_read_revision(value)
        return @revision if value.nil? || value == "" || value == 0 || value == "0"

        revision = parse_revision(value)
        raise InvalidResourceVersion, "resourceVersion #{revision} is ahead of current revision #{@revision}" if revision > @revision

        ensure_snapshot_available!(revision)
        revision
      end

      def ensure_snapshot_available!(revision)
        return if revision >= @compacted_revision

        raise Gone.new(revision, @compacted_revision)
      end

      def object_at_revision(key, revision)
        entries = @versions[key]
        return nil if entries.nil? || entries.empty?

        entry = entries.reverse_each.find { |candidate| candidate[0] <= revision }
        entry && entry[1]
      end

      def normalize_precondition(value)
        return nil if value.nil?
        return {resource_version: value} if value.is_a?(String) || value.is_a?(Numeric)

        if value.is_a?(Hash) && value["metadata"].is_a?(Hash)
          metadata = value.fetch("metadata")
          return {
            resource_version: metadata["resourceVersion"],
            uid: metadata["uid"]
          }.compact
        end
        return value if value.is_a?(Hash)

        raise ArgumentError, "precondition must be a resourceVersion or Hash"
      end

      def check_precondition!(key, object, precondition)
        return if precondition.nil?

        expected_resource_version = precondition[:resource_version] || precondition[:resourceVersion] ||
                                    precondition["resourceVersion"] || precondition["resource_version"]
        expected_uid = precondition[:uid] || precondition["uid"]
        raise ArgumentError, "precondition must include resourceVersion or uid" if expected_resource_version.nil? && expected_uid.nil?

        current_resource_version = object_revision(object)
        if !expected_resource_version.nil? && precondition_revision(expected_resource_version, current_resource_version,
                                                                    key) != current_resource_version
          raise Conflict.new(key, "expected resourceVersion #{expected_resource_version}, current is #{current_resource_version}",
                             resource_version: current_resource_version)
        end

        current_uid = object.dig("metadata", "uid")
        return unless !expected_uid.nil? && String(expected_uid) != current_uid.to_s

        raise Conflict.new(key, "expected uid #{expected_uid.inspect}, current is #{current_uid.inspect}",
                           resource_version: current_resource_version)
      end

      def precondition_revision(value, current_resource_version, key)
        parse_revision(value)
      rescue InvalidResourceVersion
        raise Conflict.new(
          key,
          "expected resourceVersion #{value.inspect}, current is #{current_resource_version}",
          resource_version: current_resource_version
        )
      end

      def request_fingerprint(operation, key, object, precondition)
        MemoryStoreSupport.digest(operation: operation.to_s, key: key, object: object, precondition: precondition)
      end

      def with_request_lock(request_uid, &)
        return yield if request_uid.nil?

        lock = @monitor.synchronize { @request_locks[request_uid] ||= Monitor.new }
        lock.synchronize(&)
      end

      def guaranteed_update_with_retry(key, expected, request_uid, retries, allow_nil_result,
                                       replay_expected = expected, &)
        fingerprint = request_fingerprint(:guaranteed_update, key, nil, replay_expected)
        @monitor.synchronize do
          replay = replay_request(request_uid, fingerprint, :guaranteed_update, key)
          return replay unless replay.equal?(NO_REPLAY)
        end

        attempt = 0
        loop do
          current, observed_revision = @monitor.synchronize do
            current_object = @objects[key]
            raise NotFound, key if current_object.nil?

            check_precondition!(key, current_object, expected)
            [MemoryStoreSupport.deep_dup(current_object), object_revision(current_object)]
          end

          candidate = yield(current)
          candidate = current if candidate.nil? && allow_nil_result
          raise ArgumentError, "guaranteed_update block must return an API object Hash" unless candidate.is_a?(Hash)

          candidate = normalize_object(candidate)

          committed = @monitor.synchronize do
            latest = @objects[key]
            latest_revision = latest && object_revision(latest)
            if latest.nil? || latest_revision != observed_revision
              nil
            else
              check_precondition!(key, latest, expected)
              commit_locked(:modified, key, candidate)
            end
          end

          unless committed.nil?
            @monitor.synchronize do
              remember_request(request_uid, fingerprint, :guaranteed_update, key, committed)
              return immutable_response(committed)
            end
          end

          raise Conflict.new(key, "guaranteed update conflicted after #{attempt + 1} attempts") if attempt >= retries

          sleep_for_retry(attempt)
          attempt += 1
        end
      end

      def replay_request(request_uid, fingerprint, operation, key)
        return NO_REPLAY if request_uid.nil?

        uid = normalize_request_uid(request_uid)
        stored = @requests[uid]
        return NO_REPLAY if stored.nil?
        unless stored.fingerprint == fingerprint && stored.operation == operation.to_sym && stored.key == key
          raise RequestUIDConflict.new(uid,
                                       key)
        end

        immutable_response(stored.result)
      end

      def remember_request(request_uid, fingerprint, operation, key, result)
        return if request_uid.nil?

        uid = normalize_request_uid(request_uid)
        @requests[uid] = RequestResult.new(
          fingerprint: fingerprint.freeze,
          operation: operation.to_sym,
          key: key.freeze,
          revision: object_revision(result),
          result: MemoryStoreSupport.immutable_copy(result)
        )
      end

      def normalize_request_uid(request_uid)
        uid = String(request_uid)
        raise ArgumentError, "request UID must not be empty" if uid.empty?

        uid
      rescue TypeError
        raise ArgumentError, "request UID must be coercible to String"
      end

      # Every key the store has ever held, sorted, memoised until a key is
      # added.  A list used to sort the whole key set and scan it for the
      # prefix on every call -- O(N log N) per list over every key ever
      # written, which put a ResourceQuota admission check at 20 ms once a
      # conformance run had created a few thousand objects.  Updates and
      # deletes leave the key set alone, so the sorted array survives them,
      # and a prefix is then a binary search plus a scan of its own keys.
      def sorted_keys_locked
        @sorted_keys ||= @known_keys.keys.sort!.freeze
      end

      # Keys starting with prefix, in order, all greater than `after` when given.
      def keys_with_prefix_locked(prefix, after: nil)
        sorted = sorted_keys_locked
        start = after && after >= prefix ? after : prefix
        index = sorted.bsearch_index { |key| key >= start } || sorted.length
        index += 1 if after && index < sorted.length && sorted[index] == after
        result = []
        while index < sorted.length && sorted[index].start_with?(prefix)
          result << sorted[index]
          index += 1
        end
        result
      end

      # "registry/<resource>" for a key or prefix; nil when it is shorter.
      def resource_bucket(key)
        parts = key.to_s.delete_prefix("/").split("/", 3)
        return nil if parts.length < 2 || parts[1].empty?

        "#{parts[0]}/#{parts[1]}"
      end

      def commit_locked(type, key, object)
        @revision += 1
        timestamp = clock_value
        old_object = @objects[key]
        committed_object = stamp_object(object, @revision)
        @sorted_keys = nil unless @known_keys.key?(key)
        @known_keys[key] = true
        @resource_revisions[resource_bucket(key)] = @revision
        @objects[key] = type == :deleted ? nil : committed_object
        @versions[key] << [@revision, type == :deleted ? nil : committed_object]
        mutation = Mutation.new(
          type: type,
          key: key,
          revision: @revision,
          # A deletion is a committed mutation too. Expose its global
          # revision on the returned/event object while retaining the prior
          # object separately for selector transition checks.
          object: committed_object,
          old_object: old_object,
          timestamp: timestamp
        )
        @history << mutation
        # One size estimate for every watcher rather than a JSON encoding each.
        bytesize = @watchers.empty? ? nil : JSON.generate(committed_object || {}).bytesize + 64
        terminated = 0
        @watchers.delete_if do |_watcher_id, watcher|
          delivered = watcher.enqueue(mutation, bytesize: bytesize)
          # A watcher whose buffer is full is closed rather than waited for
          # (cacheWatcher.add's closeFunc).
          terminated += 1 if !delivered && watcher.overflowed?
          watcher.closed?
        end
        record_commit(key, terminated) if @metrics
        # etcd auto-compaction: once per retention window every key's old
        # versions go, not only the key just written.  Pruning only the
        # written key left every version of every object that stopped
        # changing -- deleted Pods above all -- resident for ever, and a
        # conformance run grew each replica past 2 GB.
        target = compaction_target_locked(now: timestamp)
        if @history_seconds && (@last_full_compaction_at.nil? || timestamp - @last_full_compaction_at >= @history_seconds)
          @last_full_compaction_at = timestamp
          compact_locked!(target, prune_all_versions: true)
        else
          compact_locked!(target, key_to_prune: key)
        end
        mutation.object
      end

      def clock_value
        value = @clock.call
        value.respond_to?(:to_f) ? value.to_f : Float(value)
      end

      def compaction_target_locked(now: nil)
        return 0 if @revision.zero?

        timestamp = if now.nil?
                      clock_value
                    else
                      (now.respond_to?(:to_f) ? now.to_f : Float(now))
                    end
        revision_target = @history_revisions.nil? ? nil : @revision - @history_revisions
        time_target = if @history_seconds.nil?
                        nil
                      else
                        cutoff = timestamp - @history_seconds
                        first_newer_index = @history.bsearch_index { |mutation| mutation.timestamp >= cutoff }
                        if first_newer_index.nil?
                          @history.last&.revision
                        elsif first_newer_index.zero?
                          nil
                        else
                          @history[first_newer_index - 1].revision
                        end
                      end
        # Either rule on its own makes history droppable: the time window is
        # the retention promise (etcd's compaction interval) and the revision
        # count is a memory cap.  Taking the minimum let the cap veto the
        # window -- with a 100k revision cap on a young store the revision
        # target is negative, so nothing was ever compacted and no continue
        # token or watch resourceVersion ever expired.
        [[revision_target, time_target].compact.max || 0, 0].max
      end

      def compact_locked!(target, key_to_prune: nil, prune_all_versions: false)
        target = [target, @revision].min
        return @compacted_revision if target <= @compacted_revision

        @history = @history.drop_while { |mutation| mutation.revision <= target }
        if prune_all_versions
          @versions.keys.each { |key| prune_version_history_locked(key, target) }
          # Request replay memory (S6) follows the same retention as history:
          # a retry arrives within seconds, and remembering every write's
          # result for ever kept a whole run's objects resident -- the heap
          # behind the multi-second GC pauses that timed out read barriers.
          @requests.delete_if { |_uid, stored| stored.revision <= target }
        elsif key_to_prune
          prune_version_history_locked(key_to_prune, target)
        end
        @compacted_revision = target
      end

      def prune_version_history_locked(key, target)
        entries = @versions[key]
        return if entries.nil? || entries.empty?

        first_newer_index = entries.index { |entry| entry[0] > target }
        if first_newer_index.nil?
          # Everything is older than the window: a deleted key needs no
          # history at all, a live one only its current version.
          if entries.last[1].nil?
            @versions.delete(key)
          elsif entries.length > 1
            @versions[key] = [entries.last]
          end
          return
        end
        return if first_newer_index.zero? || entries.length < 2

        baseline = entries[first_newer_index - 1]
        @versions[key] = [baseline, *entries[first_newer_index..]]
      end

      def sleep_for_retry(attempt)
        ceiling = [MIN_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS].min
        jitter = if @random.respond_to?(:rand)
                   @random.rand * ceiling
                 else
                   ceiling
                 end
        @sleeper.call(jitter)
      end

      def normalize_limit(limit)
        return nil if limit.nil? || limit == ""

        value = Integer(limit)
        # ListOptions.limit=0 means no server-side limit, not an empty page.
        return nil if value.zero?
        raise ArgumentError, "limit must be positive" unless value.positive?

        value
      rescue TypeError, ArgumentError
        raise InvalidLimit, "limit must be a positive integer"
      end

      def encode_continue_token(payload)
        body = payload.merge("version" => 1)
        signed = body.merge("signature" => MemoryStoreSupport.digest(body.merge("secret" => @token_secret)))
        MemoryStoreSupport.base64_url_encode(JSON.generate(signed))
      end

      def decode_continue_token(token)
        encoded = String(token)
        decoded = MemoryStoreSupport.base64_url_decode(encoded)
        payload = JSON.parse(decoded)
        raise InvalidContinueToken unless payload.is_a?(Hash)

        signature = payload.delete("signature")
        expected = MemoryStoreSupport.digest(payload.merge("secret" => @token_secret))
        raise InvalidContinueToken unless signature == expected && payload["version"] == 1

        payload
      rescue ArgumentError, JSON::ParserError, TypeError
        raise InvalidContinueToken
      end

      def validate_continue_token!(token, prefix, selector, limit, resource_version_match)
        raise InvalidContinueToken unless token["prefix"] == prefix && token["selector"] == selector.signature
        raise InvalidContinueToken unless token["limit"] == limit
        raise InvalidContinueToken unless token["resource_version_match"] == resource_version_match
        raise InvalidContinueToken unless token["revision"].is_a?(Integer) && token["last_key"].is_a?(String)
      end

      # kube-apiserver answers a continue token whose snapshot has been
      # compacted away with 410 and hands back an "inconsistent" token: the
      # same position, resumed against the current snapshot.  A client given
      # no such token starts the listing over and re-reads every page it
      # already had, so a chunked listing returns more objects than exist.
      def restart_compacted_continue(token)
        revision = token.fetch("revision")
        return token if revision >= @compacted_revision

        inconsistent = encode_continue_token(token.merge("revision" => @revision))
        error = Gone.new(revision, @compacted_revision)
        error.details["continue"] = inconsistent if error.details.is_a?(Hash)
        raise error
      end

      def unregister_watcher(watcher)
        @monitor.synchronize do
          @watchers.delete_if { |_id, candidate| candidate.equal?(watcher) }
        end
      end

      def enqueue_bookmark(watcher)
        @monitor.synchronize do
          # Read and enqueue while holding the Store monitor so a bookmark can
          # never be placed behind a newer mutation with an older revision.
          watcher.enqueue_bookmark(@revision)
          @watchers.delete_if { |_id, candidate| candidate.equal?(watcher) && candidate.closed? }
        end
      end

      # The group and resource of a storage key, "registry/<group>/<version>/
      # <resource>/..." or "registry/<version>/<resource>/..." for the core
      # group (the version segment is "__stored__" for custom resources).
      def group_resource(key)
        cache = (@group_resources ||= {})
        parts = key.to_s.delete_prefix("/").split("/", 5)
        cache[parts.first(4)] ||= self.class.group_resource(key)
      end

      def group_resource_labels(key)
        group, resource = group_resource(key)
        {"group" => group, "resource" => resource}
      end

      # cacher.dispatchEvents / watchCache.processEvent: every committed event
      # is received and dispatched once (whatever the number of watchers),
      # and the resource's cache is now at this revision.
      def record_commit(key, terminated)
        labels = group_resource_labels(key)
        # A committed entry is what the replica receives from its storage
        # (the raft log): apiserver_storage_events_received_total, then the
        # watch cache's own receipt/dispatch.
        @metrics.increment("apiserver_storage_events_received_total", labels)
        @metrics.increment("apiserver_watch_cache_events_received_total", labels)
        @metrics.increment("apiserver_watch_cache_events_dispatched_total", labels)
        @metrics.set("apiserver_watch_cache_resource_version", @revision % 1_000_000_000_000_000, labels)
        @metrics.increment("apiserver_terminated_watchers_total", labels, by: terminated) if terminated.positive?
      rescue StandardError
        nil
      end

      # cacheWatcher.processInterval: the events a new watcher is sent
      # before it goes live (the current state, or the history after its
      # resourceVersion).
      def record_init_events(prefix, count)
        @metrics.increment("apiserver_init_events_total", group_resource_labels(prefix), by: count)
      rescue StandardError
        nil
      end

      def bookmark_identity(resource)
        return {} unless resource.respond_to?(:api_version) && resource.respond_to?(:kind)

        {"apiVersion" => resource.api_version.to_s, "kind" => resource.kind.to_s}
      end
    end

    # Stable aliases keep the storage boundary convenient for API adapters while
    # leaving the concrete implementation name explicit for callers that need it.
    Store = MemoryStore unless const_defined?(:Store, false)
    Watcher = MemoryStore::Watcher unless const_defined?(:Watcher, false)
    WatchStream = MemoryStore::Watcher unless const_defined?(:WatchStream, false)
  end
end
