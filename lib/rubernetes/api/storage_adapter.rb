# frozen_string_literal: true

require_relative "builtin_conversion"

module Rubernetes
  module API
    # Adapts generated or durable stores to the small contract consumed by the
    # HTTP-independent API handler. Method-shape differences stay here.
    class StoreAdapter
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

        def initialize(stream, adapter, resource: nil, field_selector: nil, visible: nil)
          @stream = stream
          @adapter = adapter
          @resource = resource
          @field_selector = field_selector.nil? || field_selector.empty? ? nil : field_selector
          @visible = visible || {}
        end

        # A resource served over another group's storage sees its own shape on
        # the watch stream too, not the stored one.  A custom resource sees the
        # version it asked for: the store holds each object in whatever version
        # it was written in, and a v2 watcher was being sent v1 objects.
        def translate(event)
          return event if @resource.nil?
          return event unless event.respond_to?(:object) && event.respond_to?(:type)

          converted = @adapter.send(:version_converted?, @resource)
          return event unless converted || @adapter.send(:storage_alias?, @resource)
          return event if %w[BOOKMARK ERROR].include?(event.type.to_s)

          object = converted ? @adapter.convert_out(@resource, event.object) : @adapter.send(:wire_out, @resource, event.object)
          type = select_type(event.type.to_s, object, event)
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
        def select_type(type, object, event)
          return type if @field_selector.nil?

          key = event.respond_to?(:key) && event.key ? event.key : object_identity(object)
          was = @visible.key?(key)
          now = type != "DELETED" && @field_selector.matches?(object)
          if now
            @visible[key] = true
            was ? type : "ADDED"
          else
            @visible.delete(key)
            was ? "DELETED" : nil
          end
        end

        def object_identity(object)
          metadata = object.is_a?(Hash) ? (object["metadata"] || {}) : {}
          [metadata["namespace"], metadata["name"]].compact.join("/")
        end

        def next(timeout: nil)
          loop do
            raw = timeout.nil? ? @stream.next : @stream.next(timeout: timeout)
            # nil from the store means the timeout elapsed (or the stream
            # closed) -- that is the answer, not a filtered event to skip.
            # Looping on it spun a `next(timeout: 0)` caller for ever.
            return nil if raw.nil?

            event = translate(raw)
            return event unless event.nil?
          end
        rescue MemoryStore::Error, Status::Error
          raise
        rescue StandardError => error
          raise @adapter.send(:storage_status_error, error), cause: error if @adapter.send(:storage_error?, error)

          raise
        end

        def each(timeout: :default)
          return enum_for(:each, timeout: timeout) unless block_given?

          if timeout == :default
            @stream.each { |event| (translated = translate(event)) && yield(translated) }
          else
            @stream.each(timeout: timeout) { |event| (translated = translate(event)) && yield(translated) }
          end
          self
        rescue MemoryStore::Error, Status::Error
          raise
        rescue StandardError => error
          raise @adapter.send(:storage_status_error, error), cause: error if @adapter.send(:storage_error?, error)

          raise
        end

        def to_a(timeout: :default)
          raw = if timeout == :default
                  @stream.to_a
                else
                  @stream.to_a(timeout: timeout)
                end
          Array(raw).filter_map { |event| translate(event) }
        rescue MemoryStore::Error, Status::Error
          raise
        rescue StandardError => error
          raise @adapter.send(:storage_status_error, error), cause: error if @adapter.send(:storage_error?, error)

          raise
        end

        def each_json_line(timeout: :default, &)
          return enum_for(:each_json_line, timeout: timeout) unless block_given?

          # The stream serialises the STORED object, which for an aliased
          # resource is the wrong shape; re-encode from the translated event.
          if !@resource.nil? && (@adapter.send(:storage_alias?, @resource) || @adapter.send(:version_converted?, @resource))
            each(timeout: timeout) { |event| yield JSON.generate(event.to_h) }
            return self
          end
          if timeout == :default
            @stream.each_json_line(&)
          else
            @stream.each_json_line(timeout: timeout, &)
          end
          self
        rescue MemoryStore::Error, Status::Error
          raise
        rescue StandardError => error
          raise @adapter.send(:storage_status_error, error), cause: error if @adapter.send(:storage_error?, error)

          raise
        end

        def events(timeout: :default)
          to_a(timeout: timeout)
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
      end

      def metrics=(registry)
        @metrics = registry
        return unless registry

        registry.register("etcd_request_duration_seconds", type: :histogram, buckets: STORAGE_BUCKETS,
                                                           help: "Etcd request latency in seconds for each operation and object type.")
        registry.register("etcd_requests_total", type: :counter, help: "Etcd request counts for each operation and object type.")
        registry.register("etcd_request_errors_total", type: :counter,
                                                       help: "Etcd failed request counts for each operation and object type.")
        # The store plays the watch cache and records its series.
        @store.metrics = registry if @store.respond_to?(:metrics=)
      end

      def initialize(store)
        @store = store
      end

      attr_reader :metrics, :store

      def get(resource:, namespace:, name:, resource_version: nil)
        convert_out(resource, invoke(:get, keywords: {gvr: storage_gvr(resource), resource: resource, namespace: namespace, name: name,
                                                      resource_version: resource_version}, positional: [key(resource, namespace, name)]))
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
        object = self.class.time_codec.truncate_times(object) if object.is_a?(Hash)
        converter = resource.respond_to?(:converter) ? resource.converter : nil
        return object if converter.nil? || object.nil? || resource.storage_version.nil? || resource.storage_version == resource.version

        converter.convert([object], to_version: resource.storage_version).first
      rescue CRD::Manager::ConversionError, BuiltinConversion::ConversionError => error
        raise Status::Error.new(message: "conversion failed: #{error.message}", code: 500, reason: "InternalError")
      end

      def convert_list(resource, result)
        if storage_alias?(resource)
          result = MemoryStore::ListResult.new(
            items: result.items.map { |item| wire_out(resource, item) },
            resource_version: result.resource_version, continue_token: result.continue_token,
            remaining_item_count: result.remaining_item_count
          )
        end
        converter = resource.respond_to?(:converter) ? resource.converter : nil
        return result if converter.nil?

        # A CRD's webhook converter meters single objects only (a list is
        # converted as one UnstructuredList already in the target version).
        items = if converter.is_a?(CRD::Manager::Converter)
                  converter.convert(result.items, to_version: resource.version, list: true)
                else
                  converter.convert(result.items, to_version: resource.version)
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
        storage_selectors = converted_resource?(resource) ? label_only_selectors(selectors) : selectors
        stats = @metrics ? {} : nil
        result = begin
          invoke(
            :list,
            keywords: {
              gvr: storage_gvr(resource),
              resource: resource,
              namespace: namespace,
              selector: storage_selectors,
              label_selector: storage_selectors&.label,
              field_selector: storage_selectors&.field,
              resource_version: resource_version,
              resource_version_match: resource_version_match,
              limit: limit,
              continue_token: continue_token
            }.merge(stats ? {stats: stats} : {}),
            positional: [prefix(resource, namespace)]
          )
        rescue StandardError
          record_list(resource, nil, consistent_read?(resource_version, resource_version_match, continue_token)) if stats
          raise
        end
        record_list(resource, stats, consistent_read?(resource_version, resource_version_match, continue_token)) if stats
        filter_after_conversion(resource, convert_list(resource, normalize_list_result(result)), selectors)
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
        resource.respond_to?(:custom?) && resource.custom? &&
          resource.respond_to?(:converter) && !resource.converter.nil?
      end

      def label_only_selectors(selectors)
        return selectors if selectors.nil? || selectors.field.nil? || selectors.field.empty?

        Selectors.new(label: selectors.label)
      end

      def filter_after_conversion(resource, result, selectors)
        return result unless converted_resource?(resource)
        return result if selectors.nil? || selectors.field.nil? || selectors.field.empty?

        items = result.items.select { |item| selectors.field.matches?(item) }
        MemoryStore::ListResult.new(items: items, resource_version: result.resource_version,
                                    continue_token: result.continue_token,
                                    remaining_item_count: result.remaining_item_count)
      end

      def create(resource:, namespace:, object:)
        stored = convert_in(resource, object)
        convert_out(resource, invoke(
          :create,
          keywords: {gvr: storage_gvr(resource), resource: resource, namespace: namespace, object: stored, body: stored},
          positional: [key(resource, namespace, metadata_name(stored)), stored]
        ))
      end

      def update(resource:, namespace:, name:, object:, resource_version: nil)
        stored = convert_in(resource, object)
        convert_out(resource, invoke(
          :update,
          keywords: {gvr: storage_gvr(resource), resource: resource, namespace: namespace, name: name, object: stored,
                     body: stored, resource_version: resource_version, precondition: resource_version,
                     prec: resource_version},
          positional: [key(resource, namespace, name), stored]
        ))
      end

      alias replace update

      def delete(resource:, namespace:, name:, resource_version: nil)
        invoke(
          :delete,
          keywords: {gvr: storage_gvr(resource), resource: resource, namespace: namespace, name: name,
                     resource_version: resource_version, precondition: resource_version, prec: resource_version},
          positional: [key(resource, namespace, name)]
        )
      end

      def delete_collection(resource:, namespace:, selectors:)
        if @store.respond_to?(:delete_collection)
          invoke(
            :delete_collection,
            keywords: {gvr: storage_gvr(resource), resource: resource, namespace: namespace, selector: selectors,
                       label_selector: selectors&.label, field_selector: selectors&.field},
            positional: [prefix(resource, namespace)]
          )
        else
          list(resource: resource, namespace: namespace, selectors: selectors).items.map do |object|
            delete(resource: resource, namespace: namespace, name: metadata_name(object),
                   resource_version: metadata_value(object, "resourceVersion"))
          end
        end
      end

      def watch(resource:, namespace:, selectors:, resource_version: nil, resource_version_match: nil,
                allow_bookmarks: false, send_initial_events: false, timeout_seconds: nil)
        converted = converted_resource?(resource)
        storage_selectors = converted ? label_only_selectors(selectors) : selectors
        stream = invoke(
          :watch,
          keywords: {
            gvr: storage_gvr(resource),
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
          },
          positional: [prefix(resource, namespace)]
        )
        return stream unless stream.respond_to?(:next)

        field = converted ? selectors&.field : nil
        WatchAdapter.new(stream, self, resource: resource, field_selector: field,
                                       visible: field ? visible_keys(resource, namespace, selectors, resource_version) : nil)
      end

      # A watch that starts from a resourceVersion receives no initial events,
      # so the objects that ALREADY match are seeded here; their later
      # transition out of the selector is then reported as the DELETED it is.
      def visible_keys(resource, namespace, selectors, resource_version)
        return {} if resource_version.nil? || resource_version.to_s.empty? || resource_version.to_s == "0"

        list(resource: resource, namespace: namespace, selectors: selectors).items.to_h do |item|
          metadata = item["metadata"] || {}
          [key(resource, metadata["namespace"] || namespace, metadata["name"]), true]
        end
      rescue StandardError
        {}
      end

      private

      # Per-request phase accounting (API::Server request tracing): the time
      # spent inside the store, by store method.
      def invoke(method_name, keywords:, positional: [])
        phases = Thread.current[:rubernetes_request_phases]
        return invoke_untimed(method_name, keywords: keywords, positional: positional) unless phases || @metrics

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        failed = false
        begin
          invoke_untimed(method_name, keywords: keywords, positional: positional)
        rescue StandardError
          failed = true
          raise
        ensure
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
          if phases
            key = "store.#{method_name}"
            phases[key] = phases.fetch(key, 0.0) + elapsed
          end
          record_storage_request(method_name, keywords[:resource], elapsed, failed) if @metrics
        end
      end

      # etcd3 store metrics (RecordEtcdRequest): the storage operation and
      # the group and resource it touched.
      STORAGE_OPERATIONS = {get: "get", list: "list", create: "create", update: "update", guaranteed_update: "update",
                            delete: "delete", delete_collection: "delete", watch: "watch"}.freeze
      STORAGE_BUCKETS = [0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 45, 60].freeze

      def record_storage_request(method_name, resource, elapsed, failed)
        operation = STORAGE_OPERATIONS[method_name.to_sym]
        return unless operation && resource

        group = resource.respond_to?(:group) ? resource.group.to_s : ""
        name = resource.respond_to?(:resource) ? resource.resource.to_s : resource.to_s
        # v1.36 labels the group-resource as group and resource (the old
        # "type" label was "<resource>.<group>").
        labels = {"operation" => operation, "group" => group, "resource" => name}
        return @metrics.increment("etcd_requests_total", labels) if operation == "watch"

        @metrics.observe("etcd_request_duration_seconds", elapsed, labels)
        @metrics.increment("etcd_requests_total", labels)
        @metrics.increment("etcd_request_errors_total", labels) if failed
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
        else
          raise storage_status_error(error), cause: error if storage_error?(error)

          raise
        end
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

      def deep_copy(value)
        case value
        when Hash then value.each_with_object({}) { |(key, child), copy| copy[key.to_s] = deep_copy(child) }
        when Array then value.map { |child| deep_copy(child) }
        else value
        end
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
                                        resource_version: if result.respond_to?(:resource_version)
                                                            result.resource_version
                                                          elsif result.respond_to?(:resourceVersion)
                                                            result.resourceVersion
                                                          else
                                                            0
                                                          end,
                                        continue_token: if result.respond_to?(:continue_token)
                                                          result.continue_token
                                                        elsif result.respond_to?(:continue)
                                                          result.continue
                                                        end,
                                        remaining_item_count: if result.respond_to?(:remaining_item_count)
                                                                result.remaining_item_count
                                                              elsif result.respond_to?(:remainingItemCount)
                                                                result.remainingItemCount
                                                              end)
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

      def wire_out(resource, object)
        return object unless storage_alias?(resource) && object.is_a?(Hash)

        resource.wire_converter.from_storage(object)
      end

      def wire_in(resource, object)
        return object unless storage_alias?(resource) && object.is_a?(Hash)

        resource.wire_converter.to_storage(object)
      end

      # The GVR the store indexes by, which for an aliased resource is the
      # storage group's, not the served one's.
      def storage_gvr(resource)
        resource.respond_to?(:storage_gvr) ? resource.storage_gvr : resource.gvr
      end

      def prefix(resource, namespace)
        base = "registry/#{resource.respond_to?(:storage_gvr) ? resource.storage_gvr : resource.gvr}"
        return base if namespace == :all || namespace.nil?

        namespace = "_cluster" if namespace == :cluster
        "#{base}/#{namespace}"
      end

      def key(resource, namespace, name)
        "#{prefix(resource, namespace)}/#{name}"
      end

      def metadata_name(object)
        metadata_value(object, "name").to_s
      end

      def metadata_value(object, key)
        metadata = object.is_a?(Hash) ? (object["metadata"] || object[:metadata] || {}) : {}
        metadata[key] || metadata[key.to_sym]
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
