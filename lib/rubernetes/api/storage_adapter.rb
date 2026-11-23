# frozen_string_literal: true

require_relative "object_copy"
require_relative "builtin_conversion"
require_relative "object_meta_wire"
require_relative "pod_wire"
require_relative "secret_data"
require_relative "storage_key_layout"
require_relative "../schema/job_selector"

module Rubernetes
  module API
    # Adapts generated or durable stores to the small contract consumed by the
    # HTTP-independent API handler. Method-shape differences stay here.
    class StoreAdapter
      include ObjectCopy

      # Every write passes through here, so this is where metav1.Time fields are
      # brought to the second precision both wires use upstream (see
      # KubernetesProtobuf#truncate_times).  One descriptor registry serves the
      # whole process.
      def self.time_codec
        @time_codec ||= begin
          require_relative "../schema/codec/kubernetes_protobuf"
          Schema::Codec::KubernetesProtobuf.new
        end
      end

      # Keeps a live watch stream behind the same storage-to-Status error
      # boundary as CRUD/list calls. Overflow happens asynchronously, so it
      # must be translated when the consumer reads the stream rather than only
      # while #watch is being opened.
      class WatchAdapter
        include Enumerable

        def initialize(stream, adapter, resource: nil, field_selector: nil, visible: nil, object_defaults: nil)
          @stream = stream
          @adapter = adapter
          @resource = resource
          @field_selector = field_selector.nil? || field_selector.empty? ? nil : field_selector
          @visible = visible || {}
          @object_defaults = object_defaults
        end

        # A resource served over another group's storage sees its own shape on
        # the watch stream too, not the stored one.  A custom resource sees the
        # version it asked for: the store holds each object in whatever version
        # it was written in, and a v2 watcher was being sent v1 objects.
        def translate(event)
          return event if @resource.nil?
          return event unless event.respond_to?(:object) && event.respond_to?(:type)

          converted = @adapter.send(:version_converted?, @resource)
          return event unless converted || @object_defaults || @adapter.send(:wire_normalized?, @resource) || ObjectMetaWire.empty_finalizers?(event.object)
          return event if %w[BOOKMARK ERROR].include?(event.type.to_s)

          object = converted ? @adapter.convert_out(@resource, event.object) : @adapter.send(:wire_out, @resource, event.object)
          object = @object_defaults.call(object) if @object_defaults
          type, object = select_event(event.type.to_s, object, event)
          return nil if type.nil?
          return event if object.equal?(event.object) && type == event.type.to_s

          MemoryStore::Event.new(type: type, object: object,
                                 key: event.respond_to?(:key) ? event.key : nil)
        end

        # The field selector of a custom resource is matched against the SERVED
        # object, so the store cannot apply it; this does, with the transitions
        # a filtered watch owes its client (apiserver cacher
        # watchCacheInterval): an object that starts matching is ADDED, one that
        # stops matching is DELETED, and one that never matched is not sent.
        def select_event(type, object, event)
          return [type, object] if @field_selector.nil?

          key = event.respond_to?(:key) && event.key ? event.key : object_identity(object)
          previous = @visible[key]
          if type != "DELETED" && @field_selector.matches?(object)
            @visible[key] = object
            return [previous ? type : "ADDED", object]
          end

          @visible.delete(key)
          return unless previous

          revision = object.dig("metadata", "resourceVersion")
          ["DELETED", previous.merge("metadata" => previous.fetch("metadata").merge("resourceVersion" => revision))]
        end

        def object_identity(object)
          metadata = object.is_a?(Hash) ? (object["metadata"] || {}) : {}
          [metadata["namespace"], metadata["name"]].compact.join("/")
        end

        def next(timeout: nil)
          with_storage_errors do
            loop do
              raw = timeout.nil? ? @stream.next : @stream.next(timeout: timeout)
              return if raw.nil?

              event = translate(raw)
              return event if event
            end
          end
        end

        def each(timeout: :default)
          return enum_for(__method__, timeout: timeout) unless block_given?

          with_storage_errors do
            stream_call(:each, timeout) do |raw|
              event = translate(raw)
              yield event if event
            end
          end
          self
        end

        def to_a(timeout: :default)
          with_storage_errors { Array(stream_call(:to_a, timeout)).filter_map { |event| translate(event) } }
        end

        alias events to_a

        def each_json_line(timeout: :default, &)
          return enum_for(__method__, timeout: timeout) unless block_given?

          if @resource
            each(timeout: timeout) { |event| yield JSON.generate(event.to_h) << "\n" }
          else
            with_storage_errors { stream_call(:each_json_line, timeout, &) }
          end
          self
        end

        def close
          @stream.close if @stream.respond_to?(:close)
          nil
        end

        def method_missing(name, *, **keywords, &)
          return super unless @stream.respond_to?(name)

          @stream.public_send(name, *, **keywords, &)
        end

        def respond_to_missing?(name, include_private = false)
          @stream.respond_to?(name, include_private) || super
        end

        private

        def stream_call(name, timeout, &)
          return @stream.public_send(name, &) if timeout == :default

          @stream.public_send(name, timeout: timeout, &)
        end

        def with_storage_errors
          yield
        rescue MemoryStore::Error, Status::Error
          raise
        rescue StandardError => error
          raise @adapter.send(:storage_status_error, error), cause: error if @adapter.send(:storage_error?, error)

          raise
        end
      end

      def metrics=(registry)
        @metrics = registry
        return unless registry

        registry.register("etcd_request_duration_seconds", type: :histogram, buckets: STORAGE_BUCKETS,
                                                           help: "Etcd request latency in seconds for each operation and object type.")
        registry.register("etcd_requests_total", type: :counter, help: "Etcd request counts for each operation and object type.")
        registry.register("etcd_request_errors_total", type: :counter,
                                                       help: "Etcd failed request counts for each operation and object type.")
        registry.register("apiserver_storage_decode_errors_total", type: :counter,
                                                                   help: "Number of stored object decode errors split by object type")
        # The store plays the watch cache and records its series.
        @store.metrics = registry if @store.respond_to?(:metrics=)
      end

      def initialize(store)
        @store = store
        @storage_key_layout = StorageKeyLayout.new(store)
      end

      attr_reader :metrics, :store

      def get(resource:, namespace:, name:, resource_version: nil, decode_job_labels: true)
        gvr = storage_gvr(resource)
        object = invoke(:get, keywords: {gvr: gvr, resource: resource, namespace: namespace, name: name,
                                         resource_version: resource_version}, positional: [key(gvr, namespace, name)])
        decode_job_labels ? convert_out(resource, object) : object
      end

      # Custom resources are written in their CRD's storage version and read
      # back in whatever version they were written in: a CRD whose storage
      # version moves leaves older objects behind in the old version, and the
      # apiserver converts each one to the version the client asked for
      # (apiextensions-apiserver converts on read, never on a schedule).  So
      # the OUTBOUND conversion is decided by the object in hand, not by the
      # CRD's current storage version -- skipping it whenever storage and
      # served version happened to agree served a v1 object as though it were
      # v2 in "should be able to convert a non homogeneous list of CRs".
      def convert_out(resource, object)
        object = wire_out(resource, object)
        converter = resource.respond_to?(:converter) ? resource.converter : nil
        return object if converter.nil? || object.nil?

        converter.convert([object], to_version: resource.version).first
      rescue CRD::Manager::ConversionError, BuiltinConversion::ConversionError => error
        raise Status::Error.new(message: "conversion failed: #{error.message}", code: 500, reason: "InternalError")
      end

      def convert_in(resource, object)
        object = wire_in(resource, object)
        if custom_resource?(resource)
          object = ObjectMetaWire.normalize_times(object)
        elsif object.is_a?(Hash)
          object = self.class.time_codec.truncate_times(object)
        end
        converter = resource.respond_to?(:converter) ? resource.converter : nil
        return object if converter.nil? || object.nil? || resource.storage_version.nil? || resource.storage_version == resource.version

        converter.convert([object], to_version: resource.storage_version).first
      rescue CRD::Manager::ConversionError, BuiltinConversion::ConversionError => error
        raise Status::Error.new(message: "conversion failed: #{error.message}", code: 500, reason: "InternalError")
      end

      def convert_list(resource, result)
        items = result.items
        items = items.map { |item| wire_out(resource, item) } if wire_normalized?(resource) || items.any? { |item| ObjectMetaWire.empty_finalizers?(item) }
        converter = resource.respond_to?(:converter) ? resource.converter : nil
        if converter
          # The CRD webhook converts a whole UnstructuredList in one request.
          options = converter.is_a?(CRD::Manager::Converter) ? {list: true} : {}
          items = converter.convert(items, to_version: resource.version, **options)
        elsif items.equal?(result.items)
          return result
        end
        MemoryStore::ListResult.new(items: items, resource_version: result.resource_version, continue_token: result.continue_token,
                                    remaining_item_count: result.remaining_item_count)
      rescue CRD::Manager::ConversionError, BuiltinConversion::ConversionError => error
        raise Status::Error.new(message: "conversion failed: #{error.message}", code: 500, reason: "InternalError")
      end

      # A custom resource's selectable fields are declared on the SERVED
      # version (CustomResourceDefinition selectableFields), so the selector
      # has to be matched against the object as that version -- not against
      # whatever version happens to be in storage.  A CRD whose storage version
      # spells the value differently (or not at all) made every field-selected
      # list come back empty: "[sig-api-machinery] CustomResourceDefinition
      # should list custom resource definition objects with field selectors"
      # lists v2 objects by `host`, which only exists after conversion from v1.
      def list(resource:, namespace:, selectors:, resource_version: nil, resource_version_match: nil,
               limit: nil, continue_token: nil)
        field = converted_field_selector(resource, selectors)
        storage_selectors = field ? label_only_selectors(selectors) : selectors
        page_options = {resource_version: resource_version, resource_version_match: resource_version_match,
                        limit: limit, continue_token: continue_token}
        stats = @metrics ? {} : nil
        consistent = consistent_read?(resource_version, resource_version_match, continue_token)
        read = ->(options, page_stats) { read_list_page(resource, namespace, storage_selectors, page_stats, **options) }
        result = begin
          field ? list_converted_matches(resource, field, page_options, stats, &read) : read.call(page_options, stats)
        rescue StandardError
          record_list(resource, nil, consistent) if stats
          raise
        end
        record_list(resource, stats, consistent) if stats
        field ? result : convert_list(resource, result)
      end

      # delegator.ShouldDelegateList: a LIST with no resourceVersion, match
      # or continue token is a consistent read.
      def consistent_read?(resource_version, resource_version_match, continue_token)
        resource_version.to_s.empty? && resource_version_match.to_s.empty? && continue_token.to_s.empty?
      end

      # Objects are stored in one version and served in another (custom
      # resources, and built-ins served in several versions).
      def version_converted?(resource)
        resource.respond_to?(:converter) && !resource.converter.nil?
      end

      # A custom resource: its field selectors are matched after conversion.
      def converted_resource?(resource)
        custom_resource?(resource) && version_converted?(resource)
      end

      def custom_resource?(resource)
        resource.respond_to?(:custom?) && resource.custom?
      end

      def label_only_selectors(selectors)
        Selectors.new(label: selectors.label, shard: selectors.shard)
      end

      def converted_field_selector(resource, selectors)
        field = selectors&.field
        field if field && !field.empty? && converted_resource?(resource)
      end

      def read_list_page(resource, namespace, selectors, stats, **options)
        gvr = storage_gvr(resource)
        result = invoke(:list, keywords: {gvr: gvr, resource: resource, namespace: namespace,
                                          selector: selectors, label_selector: selectors&.label,
                                          field_selector: selectors&.field, **options, **shard_options(selectors),
                                          **(stats ? {stats: stats} : {})},
                               positional: [collection_prefix(gvr, namespace)])
        normalize_list_result(result)
      end

      def list_converted_matches(resource, field, options, stats)
        items = []
        limit = options[:limit].to_i
        loop do
          page_stats = {} if stats
          page = convert_list(resource, yield(options, page_stats))
          items.concat(page.items.select { |item| field.matches?(item) })
          if page_stats&.key?(:fetched)
            stats[:fetched] = stats.fetch(:fetched, 0) + page_stats.fetch(:fetched)
            stats[:returned] = items.length
          end

          # Each storage page reads at most the number of results still due.
          # Its token therefore always follows the last object we examined.
          token = page.continue_token
          if limit.zero? || items.length >= limit || token.to_s.empty?
            return MemoryStore::ListResult.new(items: items, resource_version: page.resource_version, continue_token: token)
          end

          options = {limit: limit - items.length, continue_token: token}
        end
      end

      def create(resource:, namespace:, object:, related_versions: nil)
        stored = convert_in(resource, object)
        gvr = storage_gvr(resource, write: true)
        name = metadata_name(stored)
        versions = related_versions
        if resource.is_a?(Resource) && !resource.storage_key_versions.empty?
          versions = @storage_key_layout.guard_create(gvr, resource.storage_key_versions, versions) { |other| key(other, namespace, name) }
        end
        convert_out(resource, invoke(
          :create,
          keywords: {gvr: gvr, resource: resource, namespace: namespace, object: stored, body: stored, **related_version_options(versions)},
          positional: [key(gvr, namespace, name), stored]
        ))
      end

      def update(resource:, namespace:, name:, object:, resource_version: nil, related_versions: nil)
        stored = convert_in(resource, object)
        gvr = storage_gvr(resource, write: true)
        convert_out(resource, invoke(
          :update,
          keywords: {gvr: gvr, resource: resource, namespace: namespace, name: name, object: stored,
                     body: stored, resource_version: resource_version, precondition: resource_version,
                     prec: resource_version, **related_version_options(related_versions)},
          positional: [key(gvr, namespace, name), stored]
        ))
      end

      alias replace update

      def delete(resource:, namespace:, name:, resource_version: nil, related_versions: nil)
        gvr = storage_gvr(resource, write: true)
        invoke(
          :delete,
          keywords: {gvr: gvr, resource: resource, namespace: namespace, name: name,
                     resource_version: resource_version, precondition: resource_version, prec: resource_version,
                     **related_version_options(related_versions)},
          positional: [key(gvr, namespace, name)]
        )
      end

      def delete_corrupt(resource:, namespace:, name:)
        raise Rubernetes::Storage::ObjectNotCorrupt unless @store.respond_to?(:delete_corrupt)

        gvr = storage_gvr(resource, write: true)
        @store.delete_corrupt(key(gvr, namespace, name))
      rescue Rubernetes::Storage::Conflict, Rubernetes::Storage::NotFound, Rubernetes::Storage::Unavailable => error
        raise storage_status_error(error), cause: error
      end

      def delete_collection(resource:, namespace:, selectors:)
        if @store.respond_to?(:delete_collection)
          gvr = storage_gvr(resource, write: true)
          invoke(
            :delete_collection,
            keywords: {gvr: gvr, resource: resource, namespace: namespace, selector: selectors,
                       label_selector: selectors&.label, field_selector: selectors&.field},
            positional: [collection_prefix(gvr, namespace)]
          )
        else
          list(resource: resource, namespace: namespace, selectors: selectors).items.map do |object|
            delete(resource: resource, namespace: namespace, name: metadata_name(object),
                   resource_version: metadata_value(object, "resourceVersion"))
          end
        end
      end

      def watch(resource:, namespace:, selectors:, resource_version: nil, resource_version_match: nil,
                allow_bookmarks: false, send_initial_events: nil, timeout_seconds: nil, object_defaults: nil)
        field = converted_field_selector(resource, selectors)
        storage_selectors = field ? label_only_selectors(selectors) : selectors
        if field && (snapshot = watch_field_snapshot(resource, namespace, selectors, resource_version, send_initial_events))
          resource_version = snapshot.resource_version.to_s
          visible = visible_keys(resource, namespace, snapshot)
        end
        gvr = storage_gvr(resource)
        stream = invoke(
          :watch,
          keywords: {
            gvr: gvr,
            resource: resource,
            namespace: namespace,
            selector: storage_selectors,
            label_selector: storage_selectors&.label,
            field_selector: storage_selectors&.field,
            resource_version: resource_version,
            resource_version_match: resource_version_match,
            since: resource_version,
            allow_bookmarks: allow_bookmarks,
            send_initial_events: send_initial_events,
            timeout_seconds: timeout_seconds
          }.merge(shard_options(storage_selectors)),
          positional: [collection_prefix(gvr, namespace)]
        )
        return stream unless stream.respond_to?(:next)

        WatchAdapter.new(stream, self, resource: resource, field_selector: field, object_defaults: object_defaults,
                                       visible: visible)
      end

      # A watch that starts from a resourceVersion receives no initial events,
      # so the objects that ALREADY match are seeded here; their later
      # transition out of the selector is then reported as the DELETED it is.
      def watch_field_snapshot(resource, namespace, selectors, resource_version, send_initial_events)
        latest = ["", "0"].include?(resource_version.to_s)
        return if send_initial_events || (latest && send_initial_events.nil?)

        snapshot = latest ? {} : {resource_version: resource_version, resource_version_match: "Exact"}
        list(resource: resource, namespace: namespace, selectors: selectors, **snapshot)
      end

      def visible_keys(resource, namespace, snapshot)
        gvr = storage_gvr(resource)
        snapshot.items.to_h do |item|
          metadata = item["metadata"] || {}
          [key(gvr, metadata["namespace"] || namespace, metadata["name"]), item]
        end
      end

      private

      # Per-request phase accounting (API::Server request tracing): the time
      # spent inside the store, by store method.
      def invoke(method_name, keywords:, positional: [])
        phases = Thread.current[:rubernetes_request_phases]
        return invoke_untimed(method_name, keywords: keywords, positional: positional) unless phases || @metrics

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        failure = nil
        begin
          invoke_untimed(method_name, keywords: keywords, positional: positional)
        rescue StandardError => error
          failure = error
          raise
        ensure
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
          if phases
            key = "store.#{method_name}"
            phases[key] = phases.fetch(key, 0.0) + elapsed
          end
          record_storage_request(method_name, keywords[:resource], elapsed, failure) if @metrics
        end
      end

      # etcd3 store metrics (RecordEtcdRequest): the storage operation and
      # the group and resource it touched.
      STORAGE_OPERATIONS = {get: "get", list: "list", create: "create", update: "update", guaranteed_update: "update",
                            delete: "delete", delete_collection: "delete", watch: "watch"}.freeze
      STORAGE_BUCKETS = [0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 45, 60].freeze

      def record_storage_request(method_name, resource, elapsed, failure)
        operation = STORAGE_OPERATIONS[method_name.to_sym]
        return unless operation && resource

        group = resource.respond_to?(:group) ? resource.group.to_s : ""
        name = resource.respond_to?(:resource) ? resource.resource.to_s : resource.to_s
        # v1.36 labels the group-resource as group and resource (the old
        # "type" label was "<resource>.<group>").
        labels = {"operation" => operation, "group" => group, "resource" => name}
        return @metrics.increment("etcd_requests_total", labels) if operation == "watch"

        record_storage_decode_errors(labels.slice("group", "resource"), failure) if failure
        @metrics.observe("etcd_request_duration_seconds", elapsed, labels)
        @metrics.increment("etcd_requests_total", labels)
        @metrics.increment("etcd_request_errors_total", labels) if failure
      rescue StandardError
        nil
      end

      # Cacher.GetList (RecordListCacheMetrics, index "" -- the store keeps no
      # secondary indexes) and CacheDelegator.GetList's consistent read
      # count, which never falls back to etcd: the replica is brought up to
      # date by the read barrier instead.  +stats+ nil: the LIST failed.
      def record_list(resource, stats, consistent)
        gvr = storage_gvr(resource)
        labels = {"group" => gvr.group.to_s, "resource" => gvr.resource.to_s}
        if stats && stats.key?(:fetched)
          @metrics.increment("apiserver_cache_list_total", labels.merge("index" => ""))
          @metrics.increment("apiserver_cache_list_fetched_objects_total", labels.merge("index" => ""), by: stats[:fetched])
          @metrics.increment("apiserver_cache_list_returned_objects_total", labels, by: stats[:returned])
        end
        return unless consistent

        @metrics.increment("apiserver_watch_cache_consistent_read_total",
                           labels.merge("success" => stats ? "true" : "false", "fallback" => "false"))
      rescue StandardError
        nil
      end

      def invoke_untimed(method_name, keywords:, positional: [])
        raise ArgumentError, "store does not implement ##{method_name}" unless @store.respond_to?(method_name)

        method = @store.method(method_name)
        parameters = method.parameters
        accepts_keywords = parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
        if accepts_keywords
          accepted = if parameters.any? { |kind, _| kind == :keyrest }
                       keywords
                     else
                       names = parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
                       selected = keywords.select { |key, _| names.include?(key) }
                       selected[:out] = nil if names.include?(:out) && !selected.key?(:out)
                       selected
                     end
          positional_parameters = parameters.count { |kind, _| %i[req opt rest].include?(kind) }
          positional_parameters = positional.length if parameters.any? { |kind, _| kind == :rest }
          return method.call(*positional.first(positional_parameters), **accepted)
        end
        method.call(*positional.take(method.arity.negative? ? positional.length : method.arity))
      rescue NoMethodError => error
        raise ArgumentError, "store adapter could not call ##{method_name}: #{error.message}"
      rescue StandardError => error
        raise if error.is_a?(MemoryStore::Error) || error.is_a?(Status::Error)

        case error.class.name.to_s.split("::").last
        when "NotFound"
          raise MemoryStore::NotFound, error.message
        when "AlreadyExists"
          raise MemoryStore::AlreadyExists, error.message
        when "Conflict"
          raise MemoryStore::Conflict, error.message
        when "Gone", "Compacted"
          raise storage_status_error(error), cause: error if storage_error?(error)

          raise MemoryStore::Gone, error.message
        when "InvalidCommand"
          # etcd answers a write above --max-request-bytes with
          # "etcdserver: request is too large"; kube-apiserver relays it as
          # 413 RequestEntityTooLarge.  A 500 hid the limit from kubectl.
          raise Status::Error.new(message: "request is too large: #{error.message}", code: 413,
                                  reason: "RequestEntityTooLarge"), cause: error
        else
          raise storage_status_error(error), cause: error if storage_error?(error)

          raise
        end
      end

      def record_storage_decode_errors(labels, error)
        # invoke_untimed preserves the original storage error behind the API
        # Status that it hands to the handler.
        error = error.cause if error.is_a?(Status::Error)
        count = case error
                when Rubernetes::Storage::CorruptObject then error.decode_error? ? 1 : 0
                when Rubernetes::Storage::ReadErrors then error.failures.count(&:decode_error?)
                else 0
                end
        return if count.zero?

        @metrics.increment("apiserver_storage_decode_errors_total", labels, by: count)
      end

      def storage_error?(error)
        error.respond_to?(:status) && error.respond_to?(:reason) &&
          error.status.to_i.positive? && !error.reason.to_s.empty?
      end

      def storage_status_error(error)
        code = Integer(error.status)
        reason = error.reason.to_s
        details = error.respond_to?(:details) ? deep_copy(error.details) : nil
        if error.respond_to?(:causes) && error.causes && !error.causes.empty?
          details ||= {}
          details["causes"] ||= deep_copy(error.causes)
        end
        if error.respond_to?(:resource_version) && error.resource_version
          details ||= {}
          details["resourceVersion"] ||= error.resource_version.to_s
        end
        if error.respond_to?(:compacted_revision) && error.compacted_revision
          details ||= {}
          details["compactedRevision"] ||= error.compacted_revision.to_s
        end

        klass = case [code, reason]
                when [400, "BadRequest"] then Status::BadRequest
                when [410, "Expired"] then Status::Expired
                when [410, "Gone"] then Status::Gone
                when [404, "NotFound"] then Status::NotFound
                when [409, "AlreadyExists"] then Status::AlreadyExists
                when [409, "Conflict"] then Status::Conflict
                end
        return klass.new(error.message, details: details) if klass

        # A datastore that is merely unavailable is retryable, and every
        # Kubernetes client honours the Retry-After that says so.
        if code == 503
          retry_after = error.respond_to?(:retry_after_seconds) ? error.retry_after_seconds : nil
          return Status::Error.new(message: error.message, code: code, reason: reason, details: details,
                                   retry_after_seconds: retry_after || 1)
        end

        Status::Error.new(message: error.message, code: code, reason: reason, details: details)
      end

      def normalize_list_result(result)
        case result
        when MemoryStore::ListResult
          result
        when Array
          if result.length == 2 && result.first.is_a?(Array)
            MemoryStore::ListResult.new(items: result.first, resource_version: result.last || 0)
          else
            MemoryStore::ListResult.new(items: result, resource_version: 0)
          end
        when Hash
          items = result["items"] || result[:items] || []
          metadata = result["metadata"] || result[:metadata] || {}
          MemoryStore::ListResult.new(
            items: items,
            resource_version: first_present(result, metadata, "resourceVersion", :resourceVersion,
                                            "resource_version", :resource_version) || 0,
            continue_token: first_present(result, metadata, "continue", :continue,
                                          "continue_token", :continue_token),
            remaining_item_count: first_present(result, metadata, "remainingItemCount", :remainingItemCount,
                                                "remaining_item_count", :remaining_item_count)
          )
        else
          if result.respond_to?(:items)
            MemoryStore::ListResult.new(items: result.items,
                                        resource_version: result_attribute(result, :resource_version, :resourceVersion, default: 0),
                                        continue_token: result_attribute(result, :continue_token, :continue),
                                        remaining_item_count: result_attribute(result, :remaining_item_count, :remainingItemCount))
          elsif result.respond_to?(:to_ary)
            items, revision = result.to_ary
            MemoryStore::ListResult.new(items: items, resource_version: revision || 0)
          else
            MemoryStore::ListResult.new(items: [], resource_version: 0)
          end
        end
      end

      # A resource served over another group's storage (events.k8s.io/v1 Events
      # over core/v1 Events) is translated on every boundary crossing: the
      # store holds one shape, and both APIs see their own.
      def storage_alias?(resource)
        resource.respond_to?(:storage_alias?) && resource.storage_alias?
      end

      def wire_normalized?(resource)
        custom_resource?(resource) || storage_alias?(resource) || SecretData.resource?(resource) || PodWire.resource?(resource) ||
          Schema::JobSelector.resource?(resource) || PodWire.resource_selectors?(resource)
      end

      def wire_out(resource, object)
        object = PodWire.normalize_resource_selectors(resource, ObjectMetaWire.omit_empty_finalizers(object))
        return ObjectMetaWire.normalize_times(object) if custom_resource?(resource)
        return SecretData.normalize(object) if SecretData.resource?(resource)
        return PodWire.normalize(object) if PodWire.resource?(resource)
        return Schema::JobSelector.decode_labels(object) if Schema::JobSelector.resource?(resource)
        return object unless storage_alias?(resource) && object.is_a?(Hash)

        resource.wire_converter.from_storage(object)
      end

      def wire_in(resource, object)
        object = ObjectMetaWire.omit_empty_finalizers(object)
        return SecretData.normalize(object) if SecretData.resource?(resource)
        return PodWire.normalize(object) if PodWire.resource?(resource)
        return object unless storage_alias?(resource) && object.is_a?(Hash)

        resource.wire_converter.to_storage(object)
      end

      # The GVR the store indexes by, which for an aliased resource is the
      # storage group's, not the served one's.
      def storage_gvr(resource, write: false)
        return @storage_key_layout.resolve(resource.storage_gvr, resource.storage_key_versions, write: write) if resource.is_a?(Resource)

        resource.respond_to?(:storage_gvr) ? resource.storage_gvr : resource.gvr
      rescue Rubernetes::Storage::Error => error
        raise unless storage_error?(error)

        raise storage_status_error(error), cause: error
      end

      def prefix(gvr, namespace)
        base = "registry/#{gvr}"
        return base if namespace == :all || namespace.nil?

        namespace = "_cluster" if namespace == :cluster
        "#{base}/#{namespace}"
      end

      def key(gvr, namespace, name)
        "#{prefix(gvr, namespace)}/#{name}"
      end

      def object_key(resource, namespace, name)
        key(storage_gvr(resource), namespace, name)
      end
      public :object_key

      def related_version_options(versions)
        versions ? {related_versions: versions} : {}
      end

      # Raft and the storage engine scan byte prefixes. End collections on a
      # path separator so similarly named namespaces or resources stay distinct.
      def collection_prefix(gvr, namespace)
        "#{prefix(gvr, namespace)}/"
      end

      def shard_options(selectors)
        shard = selectors&.shard
        shard ? {shard_selector: shard} : {}
      end

      def metadata_name(object)
        metadata_value(object, "name").to_s
      end

      def metadata_value(object, key)
        metadata = object.is_a?(Hash) ? (object["metadata"] || object[:metadata] || {}) : {}
        metadata[key] || metadata[key.to_sym]
      end

      def result_attribute(result, name, alternate, default: nil)
        return result.public_send(name) if result.respond_to?(name)
        return result.public_send(alternate) if result.respond_to?(alternate)

        default
      end

      def first_present(primary, secondary, *keys)
        keys.each do |key|
          return primary[key] if primary.is_a?(Hash) && primary.key?(key)
          return secondary[key] if secondary.is_a?(Hash) && secondary.key?(key)
        end
        nil
      end
    end
  end
end
