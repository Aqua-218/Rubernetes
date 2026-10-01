# frozen_string_literal: true

require "socket"
require "openssl"

require_relative "../controller"
require_relative "../controller/service_account_credentials"
require_relative "../scheduler"
require_relative "../watch"
require_relative "../proxy"
require_relative "../client"
require_relative "component_server"

module Rubernetes
  module Bootstrap
    # Adapter for the list/watch contract used by Watch::Reflector and
    # Proxy::WatchSubscription.  Keeping REST path/query construction here
    # means the control loops only depend on their existing domain ports.
    # Shared by every control-plane loop: a transient fault is retried with a
    # bounded backoff, and anything else ends the process.  Defining it on one
    # service only left the other calling a method it did not have -- the
    # scheduler died with NoMethodError the first time a retryable API error
    # reached its rescue, and the cluster stopped scheduling Pods entirely.
    module TransientLoopErrors
      TRANSIENT_LOOP_BACKOFF_SECONDS = [0.5, 1.0, 2.0, 5.0].freeze

      def transient_loop_error?(error)
        status = error.respond_to?(:status) ? error.status.to_i : nil
        return true if status && (status >= 500 || status == 429)
        return true if error.is_a?(IOError) || error.is_a?(SystemCallError)

        error.message.to_s.match?(/HTTP 5\d\d|timed out|timeout|connection reset|broken pipe|refused|unavailable/i)
      end

      def loop_backoff(failures)
        TRANSIENT_LOOP_BACKOFF_SECONDS[[failures - 1, TRANSIENT_LOOP_BACKOFF_SECONDS.length - 1].min]
      end
    end

    class KubernetesResourceSource
      attr_reader :client, :descriptor

      def initialize(client:, descriptor: nil, resource: nil, api_version: nil,
                     namespace: :all, selector: nil)
        raise ArgumentError, "client is required" unless client

        @client = client
        @descriptor = normalize_descriptor(descriptor || resource, api_version: api_version)
        @namespace = namespace
        @selector = selector
      end

      def list(resource: nil, namespace: @namespace, selector: @selector,
               selectors: nil, resource_version: nil, **options)
        descriptor = normalize_descriptor(resource || @descriptor)
        query = build_query(selector || selectors, resource_version: resource_version, options: options)
        response = @client.get(
          descriptor.resource,
          namespace: effective_namespace(descriptor, namespace),
          api_version: descriptor.api_version,
          query: query.empty? ? nil : query
        )
        normalize_list(response, descriptor: descriptor)
      end

      def watch(resource: nil, namespace: @namespace, selector: @selector,
                selectors: nil, resource_version: nil, timeout: nil,
                timeout_seconds: nil, **options)
        descriptor = normalize_descriptor(resource || @descriptor)
        query = build_query(selector || selectors, resource_version: resource_version,
                                                   options: options)
        timeout_value = timeout_seconds || timeout
        query["timeoutSeconds"] = timeout_value.to_f.to_i.to_s if timeout_value
        # The store compacts five minutes of history.  An informer of a kind
        # that rarely changes resumed its watch with a version older than
        # that, was answered 410 and relisted -- ~75 relists in 25 minutes
        # across the controller manager.  Periodic bookmarks (the store emits
        # one every 30 s to a watch that asks) keep the resumption version
        # fresh, as client-go's reflector asks for them.
        query["allowWatchBookmarks"] = "true" unless query.key?("allowWatchBookmarks")
        namespace_value = effective_namespace(descriptor, namespace)
        if @client.respond_to?(:watch_each)
          return @client.watch_each(descriptor.resource, namespace: namespace_value,
                                                         api_version: descriptor.api_version, query: query)
        end
        @client.watch(descriptor.resource, namespace: namespace_value,
                                           api_version: descriptor.api_version, query: query)
      rescue NoMethodError => error
        raise ArgumentError, "Kubernetes client must implement watch_each or watch: #{error.message}"
      end

      # kube-apiserver omits TypeMeta from list items (only the list envelope
      # carries `kind: XList` / `apiVersion`).  client-go decodes those items
      # into typed objects whose GVK comes from the scheme, so upstream
      # controllers always know an owner's kind and apiVersion.  Hash-shaped
      # objects need the same identity restored here, from the envelope or,
      # failing that, from the resource descriptor.  Existing TypeMeta on an
      # item is never overwritten.
      def self.restore_item_type_meta(items, envelope:, descriptor:)
        envelope_kind = envelope.is_a?(Hash) ? (envelope["kind"] || envelope[:kind]).to_s : ""
        envelope_api_version = envelope.is_a?(Hash) ? (envelope["apiVersion"] || envelope[:apiVersion]).to_s : ""
        item_kind = if envelope_kind.end_with?("List") && envelope_kind.length > 4
                      envelope_kind.delete_suffix("List")
                    else
                      descriptor&.kind.to_s
                    end
        item_api_version = envelope_api_version.empty? ? descriptor&.api_version.to_s : envelope_api_version
        return items if item_kind.empty? && item_api_version.empty?

        items.map do |item|
          next item unless item.is_a?(Hash)

          has_kind = item.key?("kind") || item.key?(:kind)
          has_api_version = item.key?("apiVersion") || item.key?(:apiVersion)
          next item if has_kind && has_api_version

          restored = item.dup
          restored["kind"] = item_kind unless has_kind || item_kind.empty?
          restored["apiVersion"] = item_api_version unless has_api_version || item_api_version.empty?
          restored
        end
      end

      private

      def normalize_descriptor(value, api_version: nil)
        raise ArgumentError, "resource descriptor is required" if value.nil?

        if value.is_a?(Controller::ResourceDescriptor)
          return api_version ? Controller::ResourceDescriptor.parse(value, version: api_version) : value
        end

        Controller::ResourceDescriptor.parse(value, version: api_version)
      end

      def effective_namespace(descriptor, namespace)
        return nil if descriptor.cluster_scoped?
        # `nil` means "the client decides", and the client substitutes the
        # kubeconfig context's namespace -- so collapsing :all to nil silently
        # narrows every cluster-wide informer to the context namespace, and the
        # scheduler never sees a pod outside "default".  :all must survive.
        return :all if namespace.nil? || namespace == :all

        namespace.to_s
      end

      def build_query(selector, resource_version:, options:)
        query = {}
        unless selector.nil?
          query["labelSelector"] = selector.is_a?(Hash) ? selector_string(selector) : selector.to_s
        end
        query["resourceVersion"] = resource_version.to_s unless resource_version.nil?
        options.each do |key, value|
          next if value.nil?

          normalized = key.to_s
          normalized = "timeoutSeconds" if normalized == "timeout_seconds"
          normalized = "fieldSelector" if normalized == "field_selector"
          query[normalized] = value
        end
        query
      end

      def selector_string(selector)
        selector.to_h.sort_by { |key, _value| key.to_s }.map do |key, value|
          "#{key}=#{value}"
        end.join(",")
      end

      def normalize_list(response, descriptor: @descriptor)
        if response.is_a?(Hash)
          items = response["items"] || response[:items] || []
          metadata = response["metadata"] || response[:metadata] || {}
          version = response["resourceVersion"] || response[:resourceVersion] ||
                    response["resource_version"] || response[:resource_version] ||
                    metadata["resourceVersion"] || metadata[:resourceVersion] ||
                    metadata["resource_version"] || metadata[:resource_version]
          raise IOError, "Kubernetes list response is missing metadata.resourceVersion" if version.nil?

          items = self.class.restore_item_type_meta(Array(items), envelope: response, descriptor: descriptor)
          return {"items" => items, "metadata" => {"resourceVersion" => version.to_s}}
        end

        items = response.respond_to?(:items) ? response.items : Array(response)
        version = if response.respond_to?(:resource_version)
                    response.resource_version
                  elsif response.respond_to?(:resourceVersion)
                    response.resourceVersion
                  end
        version ||= Array(items).filter_map { |item| resource_version_for(item) }.max_by { |value| version_number(value) }
        raise IOError, "Kubernetes list response is missing resourceVersion" if version.nil?

        items = self.class.restore_item_type_meta(Array(items), envelope: nil, descriptor: descriptor)
        {"items" => items, "metadata" => {"resourceVersion" => version.to_s}}
      end

      def resource_version_for(object)
        return nil unless object.respond_to?(:to_h)

        metadata = object.to_h["metadata"] || object.to_h[:metadata] || {}
        metadata["resourceVersion"] || metadata[:resourceVersion] || metadata["resource_version"]
      end

      def version_number(value)
        Integer(value)
      rescue ArgumentError, TypeError
        -1
      end
    end

    # StoreAdapter-compatible remote store.  Controller::Manager and the
    # built-in controllers retain their optimistic write and leader-fence
    # semantics while reads/writes use the Kubernetes API client.
    # One informer's cache presented as a read source: objects only, and only
    # once the reflector has completed its initial list.
    class InformerCache
      def initialize(informer)
        @informer = informer
      end

      def synced?
        reflector = @informer.respond_to?(:reflector) ? @informer.reflector : nil
        return true if reflector.nil?
        return reflector.synced? if reflector.respond_to?(:synced?)

        !reflector.resource_version.nil?
      rescue StandardError
        false
      end

      def list
        indexer = @informer.respond_to?(:indexer) ? @informer.indexer : nil
        return [] unless indexer.respond_to?(:list)

        Array(indexer.list)
      rescue StandardError
        []
      end

      # Write-through: an object this process just created/updated/deleted is
      # visible to the next reconcile immediately instead of after the watch
      # round-trip.  client-go controllers cover the same window with
      # ControllerExpectations; without either, a ReplicationController that
      # was re-queued by its own status write created a fresh Pod on every
      # pass (49 Pods for replicas: 2).
      def add(object)
        indexer = @informer.respond_to?(:indexer) ? @informer.indexer : nil
        indexer.add(object) if indexer.respond_to?(:add)
      rescue StandardError
        nil
      end

      def update(object)
        indexer = @informer.respond_to?(:indexer) ? @informer.indexer : nil
        indexer.update(object) if indexer.respond_to?(:update)
      rescue StandardError
        nil
      end

      def delete(object)
        indexer = @informer.respond_to?(:indexer) ? @informer.indexer : nil
        indexer.delete(object) if indexer.respond_to?(:delete)
      rescue StandardError
        nil
      end
    end

    class KubernetesStoreAdapter < Controller::StoreAdapter
      # Reads served from the informer caches.  A controller reconcile that
      # reads through to the API server pays a raft read barrier per lookup,
      # and with dozens of controllers consulted per queue key the control
      # loop cannot keep up.  Upstream controllers read their informer cache
      # and never the API for this, which is what this map provides; a kind
      # with no synced informer still falls through to the API.
      attr_accessor :caches

      def initialize(client:, resource_descriptors:, field_manager: "rubernetes-controller-manager", effect_journal: nil,
                     caches: {})
        super(client, effect_journal: effect_journal)
        @client = client
        @resource_descriptors = Array(resource_descriptors).uniq.freeze
        @field_manager = field_manager.to_s.freeze
        # The SAME hash the controller manager fills as each informer is
        # built.  It was accepted and dropped, so @caches stayed nil and every
        # controller read -- each list, each find, each Pod-to-Service lookup
        # in an informer handler -- went to the API server through a raft
        # read barrier.  No-op reconciles took 0.2-0.5 s, and the Pod
        # informer, whose handlers did those reads per event, fell minutes
        # behind ("[sig-scheduling] SchedulerPreemption PreemptionExecutionPath"
        # waited for a ReplicaSet that never heard its Pod became Ready).
        @caches = caches
        raise ArgumentError, "at least one resource descriptor is required" if @resource_descriptors.empty?
      end

      attr_reader :client, :resource_descriptors, :field_manager

      # The same store read through another identity: the informer caches
      # are shared, reads that miss them and every write go through +client+.
      def with_client(client)
        self.class.new(client: client, resource_descriptors: @resource_descriptors, field_manager: @field_manager,
                       effect_journal: effect_journal, caches: @caches)
      end

      # fresh: true reads the API instead of the informer cache.  Only a
      # controller whose write must not be computed from lagging inputs pays
      # for it (the quota controller: a total computed from a cache that had
      # not yet seen an admitted Service overwrote admission's charge).
      def list(descriptor_or_kind, namespace: :all, selector: nil, fresh: false)
        descriptor = self.class.descriptor(descriptor_or_kind)
        cached = fresh ? nil : cached_objects(descriptor)
        unless cached.nil?
          objects = cached
          unless namespace == :all || namespace.nil? || descriptor.cluster_scoped?
            objects = objects.select { |object| Controller::Support.namespace(object).to_s == namespace.to_s }
          end
          objects = objects.select { |object| Controller::Support.selector_matches?(selector, object) } if selector
          return objects.sort_by { |object| [Controller::Support.namespace(object).to_s, Controller::Support.name(object)] }
        end
        # GarbageCollector is a controller-only corpus identity.  It has no
        # persisted API resource or discovery endpoint; ownership is derived
        # from the resources observed by the controller.  Treating this
        # marker as an API list would make the full production registry ask
        # the apiserver for the invented /garbage-collectors GVR.
        return [] if descriptor.kind == "GarbageCollector"

        response = KubernetesResourceSource.new(client: client, descriptor: descriptor,
                                                namespace: namespace, selector: selector).list
        objects = Array(response["items"] || response[:items])
        objects.select! { |object| Controller::Support.selector_matches?(selector, object) } if selector
        objects.sort_by { |object| [Controller::Support.namespace(object).to_s, Controller::Support.name(object)] }
      end

      # Only namespaced kinds can hold a namespace's contents, and each is
      # listed inside that namespace rather than across the cluster.  Sweeping
      # every kind cluster-wide -- which is what #all does -- turned a single
      # empty-namespace deletion into hundreds of list calls.
      # Kinds that no controller watches have no informer, so each one costs a
      # real list call against the apiserver.  There are over a hundred
      # namespaced kinds, and running them one after another made a single
      # terminating-namespace reconcile take 5-8 s -- which a conformance run,
      # deleting hundreds of namespaces, turns into the whole control plane.
      # Measured: the shared worker pool filled with namespace reconciles, the
      # queue grew to 454 keys, the average key waited 87 s, and nothing else
      # ran for thirteen minutes.  The lists are independent, so they go out
      # together, bounded the same way create batches are.
      CONTENT_LIST_PARALLELISM = 8

      def namespaced_contents(namespace, selector: nil)
        name = namespace.to_s
        descriptors = @resource_descriptors.reject { |descriptor| descriptor.cluster_scoped? || descriptor.kind == "Namespace" }
        results = []
        descriptors.each_slice(CONTENT_LIST_PARALLELISM) do |slice|
          threads = slice.map do |descriptor|
            Thread.new { list(descriptor, namespace: name, selector: selector) }
          end
          threads.each { |thread| results.concat(Array(thread.value)) }
        end
        results.uniq do |object|
          [Controller::Support.api_version(object), Controller::Support.kind(object),
           Controller::Support.namespace(object), Controller::Support.name(object)]
        end
      end

      def all(selector: nil)
        @resource_descriptors.flat_map { |descriptor| list(descriptor, namespace: :all, selector: selector) }
          .uniq do |object|
          [Controller::Support.api_version(object), Controller::Support.kind(object),
           Controller::Support.namespace(object), Controller::Support.name(object)]
        end
      end

      # A single object is fetched by name.  Listing every object of the kind
      # to pick one out of it turns each controller lookup into a full
      # collection read; with dozens of controllers consulted per queue key
      # that is the difference between a control plane that keeps up and one
      # that spends all of its time listing.
      def find(descriptor_or_kind, name:, namespace: nil)
        descriptor = self.class.descriptor(descriptor_or_kind)
        return nil if descriptor.kind == "GarbageCollector"
        return nil if name.to_s.empty?

        if descriptor.cluster_scoped?
          fetch_one(descriptor, name: name, namespace: nil)
        elsif namespace.nil? || namespace == :all
          list(descriptor, namespace: :all).find { |object| Controller::Support.name(object) == name.to_s }
        else
          fetch_one(descriptor, name: name, namespace: namespace)
        end
      end

      # nil when this kind has no synced cache, otherwise its objects.
      def cached_objects(descriptor)
        cache = @caches && (@caches[descriptor.identifier] || @caches[descriptor.to_s])
        return nil unless cache

        synced = !cache.respond_to?(:synced?) || cache.synced?
        return nil unless synced

        objects = cache.respond_to?(:list) ? cache.list : nil
        objects.is_a?(Array) ? objects : nil
      rescue StandardError
        nil
      end

      def fetch_one(descriptor, name:, namespace:)
        cached = cached_objects(descriptor)
        unless cached.nil?
          return cached.find do |object|
            Controller::Support.name(object).to_s == name.to_s &&
            (descriptor.cluster_scoped? || namespace.nil? ||
             Controller::Support.namespace(object).to_s == namespace.to_s)
          end
        end

        object = client.get(descriptor.resource, name.to_s, namespace: namespace&.to_s,
                                                            api_version: descriptor.api_version)
        object.is_a?(Hash) && !object.empty? ? object : nil
      rescue StandardError => error
        # A missing object is an ordinary answer; anything else is reported.
        return nil if error.message.to_s.match?(/404|not found|NotFound/i)

        raise
      end

      alias get find

      # A read that deliberately skips the informer cache.  The garbage
      # collector needs it: the question it asks is whether an owner is really
      # gone, and a cache that has simply not caught up yet answers that
      # question wrongly in the one direction that destroys data.
      def find_live(descriptor_or_kind, name:, namespace: nil)
        descriptor = self.class.descriptor(descriptor_or_kind)
        return nil if descriptor.kind == "GarbageCollector" || name.to_s.empty?

        object = client.get(descriptor.resource, name.to_s,
                            namespace: descriptor.cluster_scoped? ? nil : namespace&.to_s,
                            api_version: descriptor.api_version)
        object.is_a?(Hash) && !object.empty? ? object : nil
      rescue StandardError => error
        return nil if error.message.to_s.match?(/404|not found|NotFound/i)

        raise
      end

      def exists?(descriptor_or_kind, name:, namespace: nil)
        !find(descriptor_or_kind, name: name, namespace: namespace).nil?
      end

      def create(object, descriptor: nil, fence: nil)
        descriptor ||= self.class.descriptor(object)
        fence&.call
        candidate = with_api_version(object, descriptor)
        result = begin
          client.create(candidate,
                        namespace: namespace_for(descriptor, object), api_version: descriptor.api_version)
        rescue Rubernetes::Client::APIError => error
          raise unless error.respond_to?(:status) && error.status.to_i == 409

          # AlreadyExists: this object is named deterministically (an
          # EndpointSlice is "<service>-<hash>-<n>"), so a create that races
          # the informer cache finds it already there.  Upstream's controllers
          # converge by adopting the live object instead of failing the sync;
          # failing it instead re-queued the key forever -- 533 reconcile
          # failures across 426 Services in one conformance round.
          live = adopt_conflicting_object(descriptor, candidate)
          raise if live.nil?

          live
        end
        record_effect!(descriptor: descriptor, object: candidate, action: :create, response: result)
        write_through(descriptor, result, :add)
        result
      end

      # Re-read the object the create collided with and seed the cache with it,
      # so the next reconcile plans an update against what the server holds.
      def adopt_conflicting_object(descriptor, candidate)
        name = Controller::Support.name(candidate)
        return nil if name.to_s.empty?

        live = client.get(descriptor.resource, name,
                          namespace: namespace_for(descriptor, candidate), api_version: descriptor.api_version)
        live.is_a?(Hash) && !live.empty? ? live : nil
      rescue StandardError
        nil
      end

      # kube-controller-manager's slowStartBatch: the Pods a ReplicaSet/RC
      # needs go out concurrently.  One API call at a time took 45 s to
      # create 100 Pods ("[sig-api-machinery] Garbage collector should orphan
      # pods created by rc" expects them within its poll window); eight at a
      # time takes a few seconds.  Independent creates and deletes run in
      # parallel; updates keep their order.
      CREATE_PARALLELISM = 8

      # Deleting a namespace's contents is one delete per object, and the
      # conformance suite builds namespaces with hundreds: emptying the one
      # "[sig-network] Service endpoints latency" leaves behind (500 Services,
      # and an EndpointSlice and an Endpoints each) took a single reconcile
      # 177.92 s with the deletes issued one after another, and the whole
      # control plane queued behind it -- 440 keys waiting.  Deletes of
      # different objects do not depend on each other any more than creates do.
      PARALLEL_ACTIONS = %i[create delete].freeze

      def apply_batch(operations, fence: nil)
        operations = Array(operations)
        groups = PARALLEL_ACTIONS.map { |action| operations.select { |operation| operation.action == action } }
        return super if groups.none? { |group| group.length > 1 }

        results = {}
        # Creates stay ahead of deletes, exactly as they were when only the
        # creates ran together; only the work inside each group overlaps.
        groups.each { |group| apply_in_parallel(group, results, fence: fence) if group.length > 1 }
        operations.map { |operation| results.key?(operation) ? results[operation] : apply(operation, fence: fence) }
      end

      def apply_in_parallel(group, results, fence: nil)
        group.each_slice(CREATE_PARALLELISM) do |slice|
          threads = slice.map { |operation| Thread.new { apply(operation, fence: fence) } }
          slice.zip(threads).each { |operation, thread| results[operation] = thread.value }
        end
      end

      def update(object, descriptor: nil, existing: nil, fence: nil)
        descriptor ||= self.class.descriptor(object)
        current = existing || find(descriptor, name: Controller::Support.name(object), namespace: Controller::Support.namespace(object))
        ensure_uid_matches_for_remote!(current, object)
        return current if current && current == object

        fence&.call
        candidate = with_api_version(object, descriptor)
        if descriptor.kind == "Lease"
          # A lease is renewed and acquired the way client-go's leader
          # election does it (resourcelock.LeaseLock.Update): a PUT of the
          # whole Lease carrying the resourceVersion it was read at, the
          # optimistic compare-and-swap.  The bootstrap policy grants the
          # controller manager and scheduler get/update on their lease, not
          # patch, so a merge patch was refused with 403 and neither
          # component ever renewed a lease it had acquired.
          configuration = update_configuration(candidate, current)
          result = client.update(configuration, namespace: namespace_for(descriptor, candidate))
          record_effect!(descriptor: descriptor, object: candidate, action: :lease_update, response: result)
          return result
        end

        # An ordinary authoritative update, as upstream controllers issue it
        # (client-go Update): the whole object, carrying the resourceVersion
        # the controller planned from.  A stale plan fails 409 rather than
        # being forced in, and -- the reason this is not a server-side apply
        # -- a plan for an object deleted meanwhile fails 404 instead of
        # re-creating it.  The node lifecycle controller's forced apply of a
        # cached Node re-created every Node the e2e suite deleted, with its
        # old uid, and every later spec waited seven minutes for the ghost
        # node to become Ready.
        candidate = rebase_after_status_write(descriptor, update_configuration(candidate, current))
        begin
          result = client.update(candidate, namespace: namespace_for(descriptor, object))
        rescue Rubernetes::Client::APIError => error
          refresh_after_failed_update(descriptor, candidate, error)
          raise
        end
        record_successor(descriptor, candidate, candidate.dig("metadata", "resourceVersion"), result)
        record_effect!(descriptor: descriptor, object: candidate, action: :update, response: result)
        write_through(descriptor, result, :update)
        result
      end

      # The PUT body: server-owned bookkeeping stays with the server, the
      # resourceVersion of the object the plan was made from is the
      # precondition (the cache's current version only when the plan carries
      # none).
      def update_configuration(candidate, current)
        configuration = Controller::Support.deep_copy(candidate)
        metadata = (configuration["metadata"] ||= {})
        metadata.delete("managedFields")
        metadata.delete("generation")
        version = metadata["resourceVersion"].to_s
        version = Controller::Support.value(Controller::Support.metadata(current || {}), "resourceVersion", nil).to_s if version.empty?
        version.empty? ? metadata.delete("resourceVersion") : metadata["resourceVersion"] = version
        configuration
      end

      # A 409 means the informer cache lagged the server: refreshing the cache
      # from the live object lets the requeued reconcile plan from the version
      # the server will accept, instead of resending the same stale one until
      # the watch catches up.  A 404 drops the ghost from the cache.
      def refresh_after_failed_update(descriptor, candidate, error)
        status = error.respond_to?(:status) ? error.status.to_i : 0
        name = Controller::Support.name(candidate)
        namespace = namespace_for(descriptor, candidate)
        case status
        when 409
          live = client.get(descriptor.resource, name, namespace: namespace, api_version: descriptor.api_version)
          write_through(descriptor, live, :update) if live.is_a?(Hash)
        when 404
          write_through(descriptor, candidate, :delete)
        end
      rescue StandardError
        nil
      end

      # Status is a separately served Kubernetes subresource. Sending a
      # status-only operation to the primary resource URL is accepted by some
      # stores but the API server deliberately preserves the old status,
      # leaving controllers in a reconcile loop with stale observations.
      # Keep this override on the production adapter so the generic
      # StoreAdapter contract remains unchanged for in-memory stores.
      # Kinds whose status is also written by admission, so the controller's
      # write must be conditional on the version it read (see apply_status).
      CONDITIONAL_STATUS_KINDS = %w[ResourceQuota].freeze

      # How each controller's upstream counterpart writes a status, by the
      # kind written ("*" for any): UpdateStatus -- a PUT conditional on the
      # resourceVersion planned from -- unless listed.  The bootstrap RBAC
      # grants exactly these verbs, so a patch where upstream updates is
      # refused under the controllers' own identities.
      #   :patch            utilpod.PatchPodStatus, nodeutil.PatchNodeStatus,
      #                     util.PatchPVCStatus, servicehelper.PatchService
      #   [:apply, manager] ApplyStatus with FieldManager and Force
      #   :approval         UpdateApproval on the approval subresource
      STATUS_WRITES = {
        "pod-garbage-collector-controller" => {"Pod" => :patch},
        "taint-eviction-controller" => {"Pod" => :patch},
        "device-taint-eviction-controller" => {"Pod" => :patch, "DeviceTaintRule" => [:apply, "device-taint-eviction-controller"]},
        "resourceclaim-controller" => {"Pod" => [:apply, "ResourceClaimController"], "PodGroup" => [:apply, "ResourceClaimController"]},
        "validatingadmissionpolicy-status-controller" => {"*" => [:apply, "validatingadmissionpolicy-status"]},
        "service-cidr-controller" => {"*" => [:apply, "service-cidr-controller"]},
        "storage-version-migrator-controller" => {"*" => [:apply, "storage-version-migrator-controller"]},
        "persistent-volume-expander-controller" => {"PersistentVolumeClaim" => :patch},
        "service-lb-controller" => {"Service" => :patch},
        "node-route-controller" => {"Node" => :patch},
        "persistent-volume-attach-detach-controller" => {"Node" => :patch},
        "certificatesigningrequest-approving-controller" => {"CertificateSigningRequest" => :approval}
      }.freeze

      def status_write(kind)
        writes = STATUS_WRITES[Controller::Support.current_controller.to_s]
        return :update unless writes

        writes[kind] || writes["*"] || :update
      end

      def same_status?(stored, desired)
        normalize_status_zeros(stored) == normalize_status_zeros(desired)
      end

      def normalize_status_zeros(status)
        return status unless status.is_a?(Hash)

        status.reject { |_key, value| value.is_a?(Integer) && value.zero? }
      end

      def apply_status_merge(operation, fence: nil)
        descriptor = self.class.descriptor(operation.resource)
        name = Controller::Support.name(operation.object)
        namespace = Controller::Support.namespace(operation.object)
        existing = find(descriptor, name: name, namespace: namespace)
        return nil unless existing

        current = Controller::Support.status(existing)
        patch = Controller::Support.deep_copy(operation.patch || {})
        unchanged = patch.all? { |key, value| value.nil? ? !current.key?(key.to_s) : current[key.to_s] == value }
        return existing if unchanged

        fence&.call
        result = client.patch(descriptor.resource, {"status" => patch}, type: :merge, namespace: namespace_for(descriptor, existing),
                                                                        api_version: descriptor.api_version, name: name, subresource: "status")
        record_effect!(descriptor: descriptor, object: existing, action: :status_update, response: result)
        write_through(descriptor, result, :update) if result.is_a?(Hash)
        result
      end

      def apply_status(operation, fence: nil)
        descriptor = self.class.descriptor(operation.resource)
        name = Controller::Support.name(operation.object)
        namespace = Controller::Support.namespace(operation.object)
        existing = find(descriptor, name: name, namespace: namespace)
        return nil unless existing

        ensure_uid_matches_for_remote!(existing, operation.object)
        desired_status = Controller::Support.deep_copy(operation.patch || operation.object["status"] || {})
        # Informer delivery may lag a successful status write. Re-read at the
        # mutation boundary and suppress an identical status request so a
        # leader handoff cannot replay the same externally visible effect.
        # An absent status and an explicitly persisted empty status are
        # observably different through the API.  CronJob uses the latter for
        # a suspended workload, so do not suppress the first status write just
        # because both values normalize to {}.
        status_present = existing.key?("status") || existing.key?(:status)
        # Controllers write every counter, zero included, while the stored
        # status may omit zeros (Go's omitempty); absent and zero are the same
        # value, so they must compare equal or every sync would rewrite.
        return existing if status_present && same_status?(Controller::Support.status(existing), desired_status)

        fence&.call
        candidate = {
          "apiVersion" => descriptor.api_version,
          "kind" => descriptor.kind,
          "metadata" => {
            "name" => name,
            "namespace" => namespace,
            "uid" => Controller::Support.uid(existing)
          }.reject { |_key, value| value.nil? || value.to_s.empty? },
          "status" => desired_status
        }
        # resource_quota_controller.go writes status with UpdateStatus, which
        # carries the resourceVersion it computed from: a usage total that
        # went stale while it was being computed conflicts and is recomputed,
        # it never overwrites a newer one.  A forced apply has no such guard,
        # and the admission plugin's synchronous charge (status.used += the
        # admitted object) was overwritten by a recompute that had started
        # before the object existed -- a LoadBalancer then slipped past
        # services.nodeports: 1 ("capture the life of a service").
        if CONDITIONAL_STATUS_KINDS.include?(descriptor.kind)
          version = Controller::Support.value(Controller::Support.metadata(existing), "resourceVersion", nil)
          candidate["metadata"]["resourceVersion"] = version.to_s unless version.nil? || version.to_s.empty?
        end
        write = status_write(descriptor.kind)
        case write
        when :patch
          body = {"status" => desired_status}
          body["metadata"] = {"uid" => candidate["metadata"]["uid"]} if candidate["metadata"]["uid"]
          result = client.patch(descriptor.resource, body, type: :strategic, namespace: namespace_for(descriptor, existing),
                                                           api_version: descriptor.api_version, name: name, subresource: "status")
          record_effect!(descriptor: descriptor, object: candidate, action: :status_update, response: result)
          write_through(descriptor, result, :update) if result.is_a?(Hash)
          result
        when Array
          result = client.apply(candidate, namespace: namespace_for(descriptor, existing),
                                           field_manager: write.last, force: true, subresource: "status")
          record_effect!(descriptor: descriptor, object: candidate, action: :status_update, response: result)
          result
        else
          replace_status(descriptor, operation, existing, desired_status,
                         subresource: write == :approval ? "approval" : "status")
        end
      end

      # UpdateStatus: the object the plan was made from with its new status,
      # conditional on that object's resourceVersion.  The controller's next
      # write of the same object in the batch (the finalizer removal after a
      # deallocation) was planned from that version too; upstream issues it
      # from the object UpdateStatus returned, so it is rebased onto the
      # version this write produced instead of conflicting with it.
      def replace_status(descriptor, operation, existing, desired_status, subresource: "status")
        base = Controller::Support.metadata(operation.object || {})
        planned = Controller::Support.value(base, "resourceVersion", nil).to_s
        planned = Controller::Support.value(Controller::Support.metadata(existing), "resourceVersion", nil).to_s if planned.empty?
        candidate = with_api_version(Controller::Support.deep_copy(existing), descriptor)
        candidate["status"] = desired_status
        candidate["metadata"].delete("managedFields")
        sent = successor_version(descriptor, candidate, planned)
        candidate["metadata"]["resourceVersion"] = sent unless sent.empty?
        begin
          result = client.update(candidate, namespace: namespace_for(descriptor, existing), subresource: subresource)
        rescue Rubernetes::Client::APIError => error
          refresh_after_failed_update(descriptor, candidate, error)
          # Which loop chose UpdateStatus for this kind: the answer to "why a
          # PUT and not the PATCH the table promises" lives in the log line.
          issuer = Controller::Support.current_controller.inspect
          error.define_singleton_method(:message) { "#{super()} [UpdateStatus by controller #{issuer}]" }
          raise
        end
        record_effect!(descriptor: descriptor, object: candidate, action: :status_update, response: result)
        record_successor(descriptor, existing, sent, result)
        write_through(descriptor, result, :update) if result.is_a?(Hash)
        result
      end

      # A controller's writes of one object in one batch were all planned
      # from the version it read; upstream issues each from the object the
      # previous write returned (Update then UpdateStatus in the deployment
      # controller, UpdateStatus then Update in the resourceclaim one).  The
      # version each write produced is remembered against the one it was
      # sent with, and a later write planned from that one is sent with its
      # successor instead of conflicting with our own write.
      def record_successor(descriptor, object, sent, result)
        written = result.is_a?(Hash) ? Controller::Support.value(Controller::Support.metadata(result), "resourceVersion", nil).to_s : ""
        return if sent.to_s.empty? || written.empty? || written == sent.to_s

        key = [descriptor.kind, namespace_for(descriptor, object).to_s, Controller::Support.name(object), sent.to_s]
        (@status_successors_mutex ||= Mutex.new).synchronize do
          @status_successors = (@status_successors || {}).to_a.last(255).to_h
          @status_successors[key] = written
        end
      end

      def successor_version(descriptor, object, planned)
        version = planned.to_s
        return version if version.empty? || @status_successors_mutex.nil?

        @status_successors_mutex.synchronize do
          8.times do
            key = [descriptor.kind, namespace_for(descriptor, object).to_s, Controller::Support.name(object), version]
            following = @status_successors&.[](key)
            break unless following

            version = following
          end
        end
        version
      end

      def rebase_after_status_write(descriptor, candidate)
        version = candidate.dig("metadata", "resourceVersion").to_s
        return candidate if version.empty?

        successor = successor_version(descriptor, candidate, version)
        return candidate if successor == version

        candidate = Controller::Support.deep_copy(candidate)
        candidate["metadata"]["resourceVersion"] = successor
        candidate
      end

      def delete(object_or_descriptor, name: nil, namespace: nil, descriptor: nil, fence: nil, options: nil)
        if object_or_descriptor.is_a?(Hash)
          object = object_or_descriptor
          descriptor ||= self.class.descriptor(object)
          target_name = Controller::Support.name(object)
          target_namespace = Controller::Support.namespace(object)
        else
          descriptor ||= self.class.descriptor(object_or_descriptor)
          target_name = name
          target_namespace = namespace
        end
        return nil if target_name.to_s.empty?

        fence&.call
        begin
          arguments = {namespace: namespace_for(descriptor, {"metadata" => {"namespace" => target_namespace}}),
                       api_version: descriptor.api_version}
          arguments[:options] = options if options
          result = client.delete(descriptor.resource, target_name, **arguments)
        rescue Rubernetes::Client::APIError => error
          raise unless error.status.to_i == 404

          # The object went between the plan and the delete: another
          # controller, the garbage collector, or the namespace deleter got
          # there first.  Upstream's controllers treat NotFound on a delete as
          # done (client-go's IsNotFound checks everywhere); raising here made
          # the namespace controller fail a whole namespace over one
          # ControllerRevision the StatefulSet controller had already removed,
          # and 22 namespaces stayed Terminating for hours after a round.
          write_through(descriptor, object || {"metadata" => {"name" => target_name, "namespace" => target_namespace}}, :delete)
          return nil
        end
        record_effect!(descriptor: descriptor, object: object || {"metadata" => {"name" => target_name, "namespace" => target_namespace}},
                       action: :delete, response: result)
        # A graceful deletion answers with the object (deletionTimestamp set);
        # an immediate one with a Status, in which case the cache entry goes.
        if result.is_a?(Hash) && result["kind"].to_s != "Status" && result.dig("metadata", "name")
          write_through(descriptor, result, :update)
        else
          write_through(descriptor, object || {"metadata" => {"name" => target_name, "namespace" => target_namespace}}, :delete)
        end
        result
      end

      private

      def write_through(descriptor, object, action)
        return unless object.is_a?(Hash)

        cache = @caches && (@caches[descriptor.identifier] || @caches[descriptor.to_s])
        return unless cache.respond_to?(action)

        cache.public_send(action, object)
      rescue StandardError
        nil
      end

      def namespace_for(descriptor, object)
        return nil if descriptor.cluster_scoped?

        Controller::Support.namespace(object) || "default"
      end

      # An apply configuration states what this manager wants, not which
      # version of the object it last saw.  A resourceVersion carried into an
      # apply becomes an optimistic-concurrency precondition, and a controller
      # planning from a lagging informer cache can then never satisfy it: the
      # apply fails 409, the key is retried, and the same stale version is
      # sent again forever.  One such key produced 18k failed writes in a
      # single conformance run and starved every other reconcile.
      # managedFields is likewise owned by the server, never sent by a client.
      def apply_configuration(candidate)
        configuration = Controller::Support.deep_copy(candidate)
        metadata = configuration["metadata"]
        return configuration unless metadata.is_a?(Hash)

        metadata.delete("resourceVersion")
        metadata.delete("managedFields")
        metadata.delete("generation")
        configuration
      end

      def with_api_version(object, descriptor)
        candidate = Controller::Support.deep_copy(object)
        candidate["apiVersion"] ||= descriptor.api_version
        candidate["kind"] ||= descriptor.kind
        candidate
      end

      def ensure_uid_matches_for_remote!(current, candidate)
        return unless current && candidate

        current_uid = Controller::Support.uid(current)
        candidate_uid = Controller::Support.uid(candidate)
        return if current_uid.to_s.empty? || candidate_uid.to_s.empty? || current_uid == candidate_uid

        raise Controller::StoreError, "resource UID precondition failed for #{Controller::Support.kind(candidate)}/#{Controller::Support.name(candidate)}"
      end
    end

    class ControllerManagerService
      attr_reader :config, :logger, :manager, :client, :informers, :last_error

      def initialize(config:, logger:, client: nil, client_factory: nil, store: nil, manager: nil,
                     registry: nil, informers: nil, resource_sources: {}, runtime_adapters: {},
                     clock: -> { Time.now.utc }, sleeper: ->(seconds) { sleep(seconds) })
        @config = config || {}
        @logger = logger
        @client = client || runtime_adapters[:controller_client] || runtime_adapters["controller_client"]
        @client_factory = client_factory
        @store = store || runtime_adapters[:controller_store] || runtime_adapters["controller_store"]
        @manager = manager || runtime_adapters[:controller_manager] || runtime_adapters["controller_manager"]
        @registry = registry || runtime_adapters[:controller_registry] || runtime_adapters["controller_registry"]
        @runtime_adapters = runtime_adapters.to_h
        configured_options = @runtime_adapters[:controller_options] || @runtime_adapters["controller_options"] || {}
        @controller_options = if configured_options.is_a?(Hash)
                                configured_options.each_with_object({}) do |(key, value), result|
                                  result[key.is_a?(String) ? key.to_sym : key] = value
                                end
                              else
                                {}
                              end
        # kube-controller-manager --root-ca-file: the CA the root-ca
        # publisher and the token controller hand to every namespace.  It
        # defaults to the CA this process itself trusts for the API server.
        @controller_options[:root_ca] ||= root_ca_from_config
        # --feature-gates the controllers read (their defaults otherwise).
        gates = @config["feature_gates"].is_a?(Hash) ? @config["feature_gates"] : {}
        if gates.key?("MaxUnavailableStatefulSet")
          @controller_options[:max_unavailable_stateful_set] =
            gates["MaxUnavailableStatefulSet"] == true
        end
        apply_cluster_signing!(@config["cluster_signing"]) if @config["cluster_signing"]
        apply_service_account_key!(@config["service_account_private_key_file"]) if @config["service_account_private_key_file"]
        injected_provider = @runtime_adapters[:cloud_provider] || @runtime_adapters["cloud_provider"] ||
                            @runtime_adapters[:provider] || @runtime_adapters["provider"]
        if injected_provider && @controller_options[:cloud_provider].nil? && @controller_options["cloud_provider"].nil? &&
           @controller_options[:provider].nil? && @controller_options["provider"].nil?
          @controller_options[:cloud_provider] = injected_provider
        end
        informer_values = informers || runtime_adapters[:controller_informers] || runtime_adapters["controller_informers"]
        @informers = (informer_values.respond_to?(:values) ? informer_values.values : Array(informer_values)).uniq
        @resource_sources = resource_sources.to_h
        @clock = clock
        @sleeper = sleeper
        @effect_journal = runtime_adapters[:effect_journal] || runtime_adapters["effect_journal"] ||
                          Controller::EffectJournal.from_env(component: "controller-manager")
        sync = @config.fetch("sync", {})
        @interval = Float(sync.fetch("interval_seconds", sync.fetch("period_seconds", 0.05)))
        raise ArgumentError, "controller-manager sync interval must be positive" unless @interval.positive?

        @mutex = Mutex.new
        @running = false
        @thread = nil
        @last_error = nil
      end

      def start
        @mutex.synchronize { raise "rubernetes-controller-manager is already started" if @running }
        begin
          # The controllers record from their first reconcile.
          metrics = controller_manager_metrics
          build_runtime!
          @manager.step
          if @informers.empty? && @manager.respond_to?(:informers) && !@manager.informers.empty?
            source_informers = @manager.informers
            @informers = (source_informers.respond_to?(:values) ? source_informers.values : Array(source_informers)).uniq
          end
          build_informers! if @informers.empty?
          prime_informers!
          start_informers!
          start_metrics_server!
          @component_server = ComponentServer.from_config(component: "kube-controller-manager", config: @config,
                                                          metrics: metrics, ready: -> { started? }, logger: @logger)&.start
          @mutex.synchronize { @running = true }
          @thread = Thread.new { run_loop }
          log(:info, "process.ready", components: %w[controller-manager leader-election informers reconcile-loop] +
                                                  (@metrics_server ? ["metrics-server"] : []))
          self
        rescue StandardError
          stop_components(reason: "startup_failed")
          raise
        end
      end

      def stop(reason: "shutdown")
        should_stop = @mutex.synchronize do
          active = @running || (@thread && @thread.alive?) || @informers.any? do |informer|
            informer.respond_to?(:running?) && informer.running?
          end
          @running = false
          active
        end
        return self unless should_stop

        stop_components(reason: reason)
        log(:info, "process.stopped", reason: reason)
        self
      end

      def started?
        @mutex.synchronize { @running }
      end

      alias ready? started?

      def self.pv_plugin_name(pv)
        spec = pv["spec"] || {}
        return "kubernetes.io/csi:#{spec.dig("csi", "driver")}" if spec["csi"].is_a?(Hash)

        PV_PLUGINS.each { |field, plugin| return plugin if spec[field].is_a?(Hash) }
        "N/A"
      end

      private

      # The event source each upstream controller records with
      # (record.EventSource.Component) where it is not the controller name.
      CONTROLLER_EVENT_COMPONENTS = {
        "disruption-controller" => "controllermanager",
        "horizontal-pod-autoscaler-controller" => "horizontal-pod-autoscaler",
        "node-lifecycle-controller" => "node-controller",
        "persistentvolume-binder-controller" => "persistentvolume-controller",
        "persistent-volume-attach-detach-controller" => "attachdetach-controller",
        "persistent-volume-expander-controller" => "volume_expand",
        "resourceclaim-controller" => "resource_claim",
        "replicationcontroller-controller" => "replication-controller",
        "endpoints-controller" => "endpoint-controller",
        "endpointslice-controller" => "endpoint-slice-controller",
        "endpointslice-mirroring-controller" => "endpoint-slice-mirroring-controller",
        "taint-eviction-controller" => "taint-eviction-controller",
        "ttl-after-finished-controller" => "ttlafterfinished-controller",
        "pod-garbage-collector-controller" => "pod-garbage-collector"
      }.freeze

      # The controllers' Events (record.EventRecorder, core/v1): aggregated
      # and spam-filtered as client-go's correlator does, best effort.
      def publish_controller_events(resource, result)
        events = Array(result.respond_to?(:events) ? result.events : nil)
        return if events.empty? || @client.nil?

        controller = result.respond_to?(:controller) ? result.controller.to_s : ""
        component = CONTROLLER_EVENT_COMPONENTS.fetch(controller, controller.empty? ? "kube-controller-manager" : controller)
        recorder = (@controller_event_recorders ||= {})[component] ||=
          Node::EventRecorder.new(client: Node::EventSink.new(client: @client), reporting_component: component,
                                  event_time: false, source: {"component" => component}, clock: @clock, spam_filter: true)
        default_reference = controller_event_reference(resource)
        events.each do |event|
          next unless event.is_a?(Hash)

          reason = Controller::Support.value(event, "reason", "").to_s
          message = Controller::Support.value(event, "message", "").to_s
          next if reason.empty? || message.empty?

          involved = Controller::Support.value(event, "involvedObject", nil) || default_reference
          next unless involved

          type = Controller::Support.value(event, "type", "Normal").to_s
          type = "Normal" unless %w[Normal Warning].include?(type)
          recorder.record(involved_object: involved, reason: reason, message: message, type: type,
                          namespace: Controller::Support.value(involved, "namespace", nil))
        rescue StandardError => error
          log(:debug, "controller.event_failed", controller: controller, reason: reason, error: error.class.name,
                                                 message: error.message.to_s[0, 200])
        end
      end

      def controller_event_reference(resource)
        return nil unless resource.is_a?(Hash)

        name = Controller::Support.name(resource)
        return nil if name.to_s.empty?

        {"apiVersion" => Controller::Support.value(resource, "apiVersion", "v1"), "kind" => Controller::Support.kind(resource),
         "namespace" => Controller::Support.namespace(resource), "name" => name, "uid" => Controller::Support.uid(resource),
         "resourceVersion" => Controller::Support.value(Controller::Support.metadata(resource), "resourceVersion", nil)}.compact
      end

      def build_runtime!
        return if @manager

        @client ||= @client_factory&.call
        raise Config::Error, "rubernetes-controller-manager requires an API client or injected manager" unless @client

        @registry ||= configured_registry(Controller.default_registry)
        descriptors = descriptors_for_registry(@registry)
        @store ||= KubernetesStoreAdapter.new(client: @client, resource_descriptors: descriptors,
                                              effect_journal: @effect_journal, caches: @caches ||= {})
        identity = @config.fetch("identity", "#{Socket.gethostname}:#{Process.pid}")
        store_for = controller_store_resolver
        lease = symbolize(@config.fetch("lease", {}))
        lease[:clock] ||= @clock
        manager_options = @controller_options.dup
        # validatingadmissionpolicy-status-controller's TypeChecker, over this
        # manager's discovery and served OpenAPI v3.
        if @client && !manager_options.key?(:type_checker)
          require_relative "../security/admission/policy_type_checker"
          manager_options[:type_checker] = Security::Admission::PolicyTypeChecker.for_client(@client)
        end
        manager_options[:event_sink] ||= lambda do |resource, result|
          reconcile_key = [Controller::Support.namespace(resource), Controller::Support.name(resource)].compact.join("/")
          @effect_journal&.record_controller_event(reconcile_key: reconcile_key, event: result.to_h,
                                                   extra: {"resource_kind" => Controller::Support.kind(resource)})
          publish_controller_events(resource, result)
        end
        @manager = Controller::Manager.new(store: @store, identity: identity, registry: @registry, lease: lease,
                                           controller_options: manager_options, store_for: store_for,
                                           error_handler: lambda do |key, error|
                                             log(:warn, "reconcile.failed", key: key.to_s, error: error.class.name,
                                                                            controller: error.respond_to?(:rubernetes_controller) ? error.rubernetes_controller : nil,
                                                                            message: error.message.to_s[0, 500])
                                           end,
                                           slow_handler: lambda do |key, controller_name, seconds|
                                             log(:warn, "reconcile.slow", key: key.to_s,
                                                                          controller: controller_name.to_s,
                                                                          seconds: seconds.round(2))
                                           end,
                                           orphan_handler: lambda do |key, controller_name, count|
                                             log(:info, "reconcile.orphans", key: key.to_s,
                                                                             controller: controller_name.to_s, operations: count)
                                           end,
                                           # --concurrent-*-syncs, as one shared
                                           # pool rather than one per controller.
                                           worker_count: Integer(@config.fetch("sync", {}).fetch(
                                             "workers", Controller::Manager::DEFAULT_WORKER_COUNT
                                           )))
        @registry.definitions.each do |definition|
          @manager.register_definition(definition, options: manager_options)
        end
      end

      # --use-service-account-credentials: each controller reconciles through
      # a store whose client is its own kube-system ServiceAccount; the
      # informers, the leader lease and the token controller stay on the
      # controller manager's identity.
      def controller_store_resolver
        return nil unless @config["use_service_account_credentials"] == true

        @service_account_credentials ||= Controller::ServiceAccountCredentials.new(root_client: @client)
        credentials = @service_account_credentials
        store = @store
        lambda do |controller_name|
          next store if Controller::ServiceAccountCredentials.service_account_for(controller_name).nil?

          store.with_client(credentials.client_for(controller_name))
        end
      end

      # kube-controller-manager --cluster-signing-cert-file / -key-file, the
      # per-signer --cluster-signing-<signer>-{cert,key}-file and
      # --cluster-signing-duration, for the CSR signing controller.
      SIGNER_FLAGS = {"kubelet_serving" => "kubernetes.io/kubelet-serving",
                      "kubelet_client" => "kubernetes.io/kube-apiserver-client-kubelet",
                      "kube_apiserver_client" => "kubernetes.io/kube-apiserver-client",
                      "legacy_unknown" => "kubernetes.io/legacy-unknown"}.freeze

      def apply_cluster_signing!(section)
        if section["cert_file"]
          @controller_options[:ca_certificate] ||= OpenSSL::X509::Certificate.new(File.read(section.fetch("cert_file")))
          @controller_options[:ca_key] ||= OpenSSL::PKey.read(File.read(section.fetch("key_file")))
        end
        signer_cas = (section["signers"] || {}).each_with_object({}) do |(flag, files), result|
          result[SIGNER_FLAGS.fetch(flag)] = {certificate: OpenSSL::X509::Certificate.new(File.read(files.fetch("cert_file"))),
                                              key: OpenSSL::PKey.read(File.read(files.fetch("key_file")))}
        end
        @controller_options[:signer_cas] ||= signer_cas unless signer_cas.empty?
        @controller_options[:cert_ttl_seconds] ||= Integer(section["duration_seconds"]) if section["duration_seconds"]
      end

      # --service-account-private-key-file: the tokens controller signs the
      # legacy tokens of kubernetes.io/service-account-token Secrets with it
      # (serviceaccount.JWTTokenGenerator(LegacyIssuer, key)).
      def apply_service_account_key!(path)
        key = OpenSSL::PKey.read(File.read(path))
        algorithm = key.is_a?(OpenSSL::PKey::EC) ? "ES256" : "RS256"
        public_key = key.is_a?(OpenSSL::PKey::EC) ? OpenSSL::PKey::EC.new(key.public_to_der) : OpenSSL::PKey::RSA.new(key.public_to_der)
        key_id = Security::Authentication::JWT.key_id(public_key)
        prefix = Security::Authentication::ServiceAccount::LEGACY_PREFIX
        @controller_options[:token_provider] ||= lambda do |service_account, secret_name|
          namespace = Controller::Support.namespace(service_account).to_s
          name = Controller::Support.name(service_account).to_s
          claims = {"iss" => Security::Authentication::ServiceAccount::LEGACY_ISSUER, "sub" => "system:serviceaccount:#{namespace}:#{name}",
                    "#{prefix}namespace" => namespace, "#{prefix}secret.name" => secret_name.to_s,
                    "#{prefix}service-account.name" => name, "#{prefix}service-account.uid" => Controller::Support.uid(service_account).to_s}
          Security::Authentication::JWT.sign(claims, key: key, algorithm: algorithm, key_id: key_id)
        end
      end

      def root_ca_from_config
        explicit = @config["root_ca_file"]
        return File.read(explicit) if explicit && File.file?(explicit)

        path = @config["kubeconfig"]
        return nil if path.to_s.empty?

        kubeconfig = Client::Kubeconfig.load(path)
        context = kubeconfig.resolve(@config["context"])
        data = context.respond_to?(:certificate_authority_data) ? context.certificate_authority_data : nil
        return data unless data.nil? || data.to_s.empty?

        file = context.respond_to?(:certificate_authority_file) ? context.certificate_authority_file : nil
        file && File.file?(file) ? File.read(file) : nil
      rescue StandardError => error
        log(:warn, "controller.root_ca_unavailable", error: error.message)
        nil
      end

      def descriptors_for_registry(registry)
        requested = @config["resource_kinds"]
        values = registry.definitions.flat_map do |definition|
          [definition.kind] + Array(definition.watches).map(&:resource)
        end
        values << Controller::ResourceDescriptor.parse("Lease")
        values = values.select { |descriptor| requested.include?(descriptor.kind) } if requested
        values.uniq
      end

      # A control-plane process may deliberately run a named subset of the
      # built-in corpus (for example, a conformance lane exercising only the
      # rollout controllers). Build that subset through the same production
      # registry validation and Manager wiring; callers do not get to inject a
      # synthetic registry merely to hide missing implementations.
      def configured_registry(registry)
        names = Array(@config["controllers"]).map(&:to_s)
        return registry if names.empty?

        subset = Controller::ControllerRegistry.new(
          schema_registry: registry.schema_registry,
          corpus: registry.corpus,
          require_corpus: false
        )
        names.each { |name| subset.register(registry.fetch(name)) }
        subset.startup_validate!
        subset
      end

      def build_informers!
        raise Config::Error, "controller-manager requires an API client to build informers" unless @client

        grouped = Hash.new { |hash, key| hash[key] = [] }
        @manager.registry.definitions.each do |definition|
          Array(definition.watches).each { |watch| grouped[watch.resource] << definition.name }
        end
        grouped.each do |descriptor, names|
          source = resource_source_for(descriptor)
          informer = Watch::Informer.new(client: source, resource: descriptor, namespace: :all,
                                         resync_period: @config.fetch("sync", {}).fetch("resync_period", Watch::Informer::DEFAULT_RESYNC_PERIOD),
                                         error_handler: lambda { |error|
                                           log(:error, "informer.failed", resource: descriptor.to_s,
                                                                          error: error.class.name, message: error.message)
                                         })
          names.uniq.each { |name| @manager.register_informer(name, informer) }
          # Reconcile reads for this kind now come from the informer's own
          # cache instead of the API server.
          (@caches ||= {})[descriptor.identifier] = InformerCache.new(informer)
          @informers << informer
        end
        # A controller manager with no informers reconciles nothing and still
        # reports ready, which is indistinguishable from a healthy idle cluster.
        # Say how much was wired so that case is visible in the log.
        log(:info, "informers.built", informers: @informers.length,
                                      controllers: @manager.registry.definitions.length,
                                      resources: grouped.keys.map(&:to_s).sort)
      end

      def resource_source_for(descriptor)
        @resource_sources[descriptor] || @resource_sources[descriptor.identifier] ||
          @resource_sources[descriptor.kind] ||
          KubernetesResourceSource.new(client: @client, descriptor: descriptor)
      end

      # Priming warms every informer's cache before the reconcile loop starts.
      # One resource the API server does not serve (a disabled feature gate,
      # an alpha API) must not take the whole controller manager down with
      # it: the reflector retries on its own, and every other controller can
      # work meanwhile.
      def prime_informers!
        @informers.each do |informer|
          informer.reflector.list!
        rescue StandardError => error
          log(:warn, "informer.prime_failed", error: error.class.name, message: error.message)
        end
      end

      def start_informers!
        @informers.each { |informer| informer.start(thread: true) }
      end

      CONTROLLER_MANAGER_STATUS_INTERVAL = 30.0

      # A periodic one-line health summary: leadership, how deep the work queue
      # is and how much it drained.  A controller manager that has fallen
      # behind is otherwise indistinguishable from an idle one, and queue depth
      # is the only number that says which.
      def start_status_monitor
        @status_thread = Thread.new do
          reconciled = 0
          while started?
            sleep(CONTROLLER_MANAGER_STATUS_INTERVAL)
            break unless started?

            begin
              queue = @manager.respond_to?(:queue) ? @manager.queue : nil
              total = @manager.respond_to?(:reconciled_total) ? @manager.reconciled_total : nil
              # Queue depth alone cannot tell a busy manager from a stalled
              # one: a manager that is minutes behind shows a short queue
              # whenever the keys arrive slowly.  The wait is the number that
              # says which.
              waits = queue.respond_to?(:take_wait_stats) ? queue.take_wait_stats : nil
              timings = @manager.respond_to?(:take_key_time) ? @manager.take_key_time : nil
              busiest = @manager.respond_to?(:take_controller_time) ? @manager.take_controller_time : nil
              deliveries = @informers.filter_map { |informer| informer.take_delivery_stats if informer.respond_to?(:take_delivery_stats) }
              slow_informers = deliveries.select { |stats| stats[:backlog].positive? || stats[:handler_seconds] > 1.0 }
                .sort_by { |stats| -[stats[:backlog], stats[:handler_seconds]].max }.first(5)
              log(:info, "controller_manager.status",
                  leader: @manager.respond_to?(:leader?) ? @manager.leader? : nil,
                  queue_length: queue.respond_to?(:length) ? queue.length : nil,
                  reconciled: total && (total - reconciled),
                  dequeued: waits && waits[:count],
                  queue_wait_avg: waits && waits[:average].round(3),
                  queue_wait_max: waits && waits[:max].round(3),
                  orphan_seconds: timings && timings[:orphans].round(2),
                  reconcile_seconds: timings && timings[:reconcile].round(2),
                  busiest_controllers: busiest,
                  informers_behind: slow_informers,
                  # Events the informers delivered this interval.  reconciled
                  # near zero with events at zero while the suite is creating
                  # objects is a deaf watch pipeline, which informers_behind
                  # (handler backlog) cannot see.
                  informer_events: deliveries.sum { |stats| stats[:events].to_i },
                  last_error: @last_error && "#{@last_error.class}: #{@last_error.message.to_s[0, 160]}")
              reconciled = total if total
            rescue StandardError => error
              log(:warn, "controller_manager.status_failed", error: error.message)
            end
          end
        end
      end

      def run_loop
        start_status_monitor
        consecutive_failures = 0
        while started?
          begin
            # The work queue is waited on rather than polled: a fixed sleep
            # between passes adds its own latency to every reconcile, which
            # is what made a new namespace wait half a second for its default
            # ServiceAccount.  The interval only bounds how long the loop
            # blocks before re-checking shutdown and leadership.
            @manager.step(wait: @interval)
            consecutive_failures = 0
          rescue StandardError => error
            # A reconcile error (a controller bug, one poison key) must not kill
            # the controller-manager; per-key errors are already rate-limited by
            # the manager, so the loop backs off and continues.
            consecutive_failures += 1
            @mutex.synchronize { @last_error = error }
            log(transient_loop_error?(error) ? :warn : :error, "controller_manager.loop_error",
                error: error.class.name, message: error.message.to_s[0, 300],
                consecutive_failures: consecutive_failures)
            @sleeper.call(loop_backoff(consecutive_failures)) if started?
          end
        end
      rescue StandardError => error
        @mutex.synchronize do
          @last_error = error
          @running = false
        end
        log(:error, "process.failed", component: "controller-manager", error: error)
        stop_components(reason: "loop_failed")
      end

      # A control-plane loop outlives the API server it talks to: an
      # unavailable or slow API server (5xx, timeout, dropped connection) is
      # retried with backoff, exactly as the upstream components do.  Only a
      # non-transient fault ends the process, so one bad response can never
      # leave a cluster without a scheduler or controller manager.
      include TransientLoopErrors

      # The optional metrics.k8s.io component (sigs.k8s.io/metrics-server's
      # role), hosted here so a cluster needs no extra process.
      def start_metrics_server!
        options = @config["metrics_server"]
        return unless options.is_a?(Hash) && options["enabled"] == true

        require_relative "../metrics_server"
        client = @client || @client_factory&.call
        if @config["use_service_account_credentials"] == true && client
          # metrics-server runs as its own ServiceAccount (kube-system/
          # metrics-server), which is also what it presents to kubelets.
          @service_account_credentials ||= Controller::ServiceAccountCredentials.new(root_client: client)
          client = @service_account_credentials.client_for("metrics-server")
        end
        @metrics_server = Rubernetes::MetricsServer::Server.new(client: client, config: options.except("enabled"),
                                                                logger: logger, clock: @clock || -> { Time.now.utc })
        @metrics_server.start
        log(:info, "metrics_server.ready", port: @metrics_server.port)
      end

      # The controller-manager's /metrics: the process collector and its lease.
      def controller_manager_metrics
        metrics = Observability::Metrics.new(apiserver: false, component: "kube-controller-manager")
        metrics.register("leader_election_master_status", type: :gauge,
                                                          help: "Gauge of if the reporting system is master of the relevant lease, 0 indicates backup, 1 indicates master. " \
                                                                "'name' is the string used to identify the lease. Please make sure to group by name.")
        metrics.register("running_managed_controllers", type: :gauge,
                                                        help: "Indicates where instances of a controller are currently running")
        metrics.add_collector do |registry|
          leader = @manager.respond_to?(:leader?) ? @manager.leader? : false
          registry.set("leader_election_master_status", leader ? 1 : 0, {"name" => "kube-controller-manager"})
          controllers = @manager.respond_to?(:controllers) ? @manager.controllers : {}
          names = if controllers.respond_to?(:keys)
                    controllers.keys
                  else
                    Array(controllers).map do |controller|
                      controller.respond_to?(:name) ? controller.name : controller
                    end
                  end
          names.each do |name|
            registry.set("running_managed_controllers", 1, {"manager" => "kube-controller-manager", "name" => name.to_s})
          end
        end
        metrics.add_collector { |registry| collect_persistent_volumes(registry) }
        metrics.add_collector { |registry| collect_resource_claims(registry) }
        metrics.add_collector { |registry| collect_attach_detach_state(registry) }
        Controller.metrics = metrics
        metrics
      end

      PV_COUNT_METRICS = %w[pv_collector_bound_pv_count pv_collector_unbound_pv_count pv_collector_total_pv_count
                            pv_collector_bound_pvc_count pv_collector_unbound_pvc_count].freeze

      # persistentvolume/metrics pvAndPVCCountCollector, at scrape time from
      # the informer caches: bound / unbound PVs by storage class, all PVs by
      # plugin and volume mode, bound / unbound claims by namespace, class
      # and volume attributes class.
      def collect_persistent_volumes(registry)
        return unless @store.respond_to?(:list)

        PV_COUNT_METRICS.each do |name|
          registry.register(name, type: :gauge) unless registry.registered?(name)
          registry.reset(name)
        end
        volumes = Array(@store.list("PersistentVolume", namespace: :all))
        claims = Array(@store.list("PersistentVolumeClaim", namespace: :all))
        volumes.group_by do |pv|
          [pv.dig("status", "phase") == "Bound", pv.dig("spec", "storageClassName").to_s]
        end.each do |(bound, klass), members|
          registry.set(bound ? "pv_collector_bound_pv_count" : "pv_collector_unbound_pv_count", members.length, {"storage_class" => klass})
        end
        volumes.group_by do |pv|
          [self.class.pv_plugin_name(pv), (pv.dig("spec", "volumeMode") || "Filesystem").to_s]
        end.each do |(plugin, mode), members|
          registry.set("pv_collector_total_pv_count", members.length, {"plugin_name" => plugin, "volume_mode" => mode})
        end
        claims.group_by do |pvc|
          klass = (pvc.dig("metadata", "annotations") || {}).fetch("volume.beta.kubernetes.io/storage-class") do
            pvc.dig("spec", "storageClassName")
          end
          [pvc.dig("status", "phase") == "Bound", pvc.dig("metadata", "namespace").to_s, klass.to_s,
           pvc.dig("spec", "volumeAttributesClassName").to_s]
        end.each do |(bound, namespace, klass, attributes), members|
          registry.set(bound ? "pv_collector_bound_pvc_count" : "pv_collector_unbound_pvc_count", members.length,
                       {"namespace" => namespace, "storage_class" => klass, "volume_attributes_class" => attributes})
        end
      rescue StandardError
        nil
      end

      # attachdetach metrics.Register (while the attach/detach controller
      # runs): storage_count_attachable_volumes_in_use{node,volume_plugin}
      # and attachdetach_controller_total_volumes{plugin_name,state}.
      def collect_attach_detach_state(registry)
        names = %w[storage_count_attachable_volumes_in_use attachdetach_controller_total_volumes]
        return names.each { |name| registry.unregister(name) } unless running_controller?("persistent-volume-attach-detach-controller")

        names.each do |name|
          registry.register(name, type: :gauge) unless registry.registered?(name)
          registry.reset(name)
        end
        list = ->(kind) { Array(@store.list(kind, namespace: :all)) }
        counts = Controller::PersistentVolumeAttachDetachController.state_counts(
          pods: list.call("Pod"), claims: list.call("PersistentVolumeClaim"), volumes: list.call("PersistentVolume"), nodes: list.call("Node"),
          attachments: list.call("VolumeAttachment"), drivers: list.call("CSIDriver")
        )
        counts[:in_use].each { |(node, plugin), count| registry.set(names[0], count, {"node" => node, "volume_plugin" => plugin}) }
        counts[:totals].each { |(plugin, state), count| registry.set(names[1], count, {"plugin_name" => plugin, "state" => state}) }
      rescue StandardError
        nil
      end

      def running_controller?(name)
        controllers = @manager.respond_to?(:controllers) ? @manager.controllers : {}
        (controllers.respond_to?(:keys) ? controllers.keys.map(&:to_s) : []).include?(name) && @store.respond_to?(:list)
      end

      # resourceclaim customCollector: every ResourceClaim in the informer
      # cache by allocation, admin access and source -- while the
      # resourceclaim controller runs, which registers it.
      def collect_resource_claims(registry)
        name = "resourceclaim_controller_resource_claims"
        return registry.unregister(name) unless running_controller?("resourceclaim-controller")

        registry.register(name, type: :gauge) unless registry.registered?(name)
        registry.reset(name)
        Array(@store.list("ResourceClaim", namespace: :all)).map { |claim| Controller::ResourceClaimController.claim_metric_labels(claim) }
          .tally.each { |labels, count| registry.set(name, count, labels) }
      rescue StandardError
        nil
      end

      # GetFullQualifiedPluginNameForVolume: a CSI volume names its driver.
      PV_PLUGINS = {"hostPath" => "kubernetes.io/host-path", "local" => "kubernetes.io/local-volume", "nfs" => "kubernetes.io/nfs",
                    "iscsi" => "kubernetes.io/iscsi", "fc" => "kubernetes.io/fc"}.freeze

      def stop_components(reason:)
        @component_server&.stop
        @component_server = nil
        @metrics_server&.stop
        @metrics_server = nil
        @informers.each { |informer| informer.stop(join: true) if informer.respond_to?(:stop) }
        @manager.elector.release if @manager.respond_to?(:elector) && @manager.elector.respond_to?(:release) && @manager.elector.leader?
        @manager&.stop if @manager.respond_to?(:stop)
        @thread&.join if @thread && @thread != Thread.current
        @thread = nil
      rescue StandardError => error
        log(:error, "process.stop_failed", component: "controller-manager", reason: reason, error: error)
        raise
      end

      def symbolize(value)
        value.to_h.transform_keys(&:to_sym)
      end

      def log(level, event, **fields)
        logger.public_send(level, event, **fields) if logger.respond_to?(level)
      end
    end

    class SchedulerService
      include TransientLoopErrors

      DEFAULT_LEASE_NAME = "rubernetes-scheduler"

      def initialize(config:, logger:, client: nil, client_factory: nil, store: nil, framework: nil,
                     node_informer: nil, pod_informer: nil, resource_sources: {}, runtime_adapters: {},
                     clock: -> { Time.now.utc }, sleeper: ->(seconds) { sleep(seconds) })
        @config = config || {}
        @logger = logger
        @client = client || runtime_adapters[:scheduler_client] || runtime_adapters["scheduler_client"]
        @client_factory = client_factory
        @store = store || runtime_adapters[:scheduler_store] || runtime_adapters["scheduler_store"]
        @framework = framework || runtime_adapters[:scheduler_framework] || runtime_adapters["scheduler_framework"]
        @node_informer = node_informer
        @pod_informer = pod_informer
        @resource_sources = resource_sources.to_h
        @effect_journal = runtime_adapters[:effect_journal] || runtime_adapters["effect_journal"] ||
                          Controller::EffectJournal.from_env(component: "scheduler")
        @clock = clock
        @sleeper = sleeper
        sync = @config.fetch("sync", {})
        @interval = Float(sync.fetch("interval_seconds", sync.fetch("period_seconds", 0.01)))
        raise ArgumentError, "scheduler sync interval must be positive" unless @interval.positive?

        @mutex = Mutex.new
        @nodes = {}
        @pods = {}
        @cluster_informers = {}
        @cluster_objects = Hash.new { |hash, kind| hash[kind] = {} }
        @cluster_generation = 0
        @cluster_view = nil
        @running = false
        @thread = nil
        @last_result = nil
        @last_error = nil
        @scheduler_metrics = Scheduler::Metrics.new(registry: scheduler_metrics)
        @metrics = @scheduler_metrics.registry
      end

      attr_reader :config, :logger, :framework, :client, :node_informer, :pod_informer, :elector, :last_result, :last_error, :metrics

      # pkg/scheduler/metrics: the STABLE series kube-scheduler serves.
      ATTEMPT_BUCKETS = Array.new(15) { |index| 0.001 * (2**index) }.freeze
      VICTIM_BUCKETS = Array.new(7) { |index| 2**index }.freeze

      # The kube-scheduler registry: every series the v1.36.2 inventory
      # declares for the component (types, labels and buckets from there),
      # the ones Rubernetes' scheduler cannot measure left out with a reason
      # (Metrics::UNIMPLEMENTED), plus the process and client-go families.
      def scheduler_metrics
        metrics = Observability::Metrics.new(apiserver: false, component: "kube-scheduler")
        metrics.add_collector do |registry|
          registry.set("leader_election_master_status", @elector&.leader? ? 1 : 0, {"name" => "kube-scheduler"})
          observer = @scheduler_metrics
          next unless observer

          observer.cache_size("nodes", @mutex.synchronize { @nodes.length })
          observer.cache_size("pods", @mutex.synchronize { @pods.length })
          observer.cache_size("assumed_pods", @mutex.synchronize { @assumed_pods&.length || 0 })
        end
        metrics
      end

      # metrics.ExponentialBuckets(0.01, 2, 20)
      PREEMPTION_GOROUTINE_BUCKETS = Array.new(20) { |index| 0.01 * (2**index) }.freeze

      def observe_preemption_goroutine(result, seconds)
        @scheduler_metrics&.preemption_goroutine(result, seconds)
      rescue StandardError
        nil
      end

      # schedule_attempts_total / scheduling_attempt_duration_seconds and
      # the preemption series, from one ScheduleResult.
      def record_attempt(result, seconds)
        outcome = if result.respond_to?(:status) && result.status.to_s == "scheduled" then "scheduled"
                  elsif result.respond_to?(:unschedulable?) && result.unschedulable? then "unschedulable"
                  else "error"
                  end
        # A gated Pod is not attempted; a dropped one (deleted meanwhile) is
        # one upstream never pops.
        return if (result.respond_to?(:gated?) && result.gated?) || (result.respond_to?(:dropped?) && result.dropped?)

        @scheduler_metrics.attempt(outcome, seconds)
        victims = result.respond_to?(:victims) ? Array(result.victims) : []
        return if victims.empty?

        @scheduler_metrics.preemption(victims.length)
      rescue StandardError
        nil
      end

      # What kube-scheduler's informer factory also watches for its plugins:
      # namespace labels (pod affinity namespaceSelector), the claims, volumes
      # and classes VolumeBinding/VolumeZone read, and the Services and
      # controllers PodTopologySpread's system default constraints select by.
      # Without them every volume and namespace-selector check ran on nothing.
      # The DynamicResources plugin reads ResourceClaims, ResourceSlices and
      # DeviceClasses; NodeVolumeLimits (CSILimits) CSINodes, CSIDrivers and
      # VolumeAttachments; VolumeBinding also CSIStorageCapacities.
      CLUSTER_KINDS = %w[Namespace Service ReplicationController ReplicaSet StatefulSet
                         PersistentVolume PersistentVolumeClaim StorageClass
                         ResourceClaim ResourceSlice DeviceClass CSINode CSIDriver VolumeAttachment
                         CSIStorageCapacity PodGroup Workload].freeze
      # Changes that can make an unschedulable Pod schedulable.
      REQUEUE_KINDS = %w[Namespace PersistentVolume PersistentVolumeClaim StorageClass
                         ResourceClaim ResourceSlice DeviceClass CSINode CSIDriver VolumeAttachment
                         CSIStorageCapacity PodGroup].freeze

      def start
        @mutex.synchronize { raise "rubernetes-scheduler is already started" if @running }
        begin
          build_runtime!
          @elector.step
          install_handlers!
          prime_informers!
          start_informers!
          @mutex.synchronize { @running = true }
          @thread = Thread.new { run_loop }
          start_scheduler_status_monitor
          @component_server = ComponentServer.from_config(component: "kube-scheduler", config: @config, metrics: @metrics,
                                                          ready: -> { started? }, logger: @logger,
                                                          extra_paths: {"/metrics/resources" => method(:resource_metrics_body)})&.start
          log(:info, "process.ready", components: %w[scheduler framework queue informers bind-loop])
          self
        rescue StandardError
          stop_components(reason: "startup_failed")
          raise
        end
      end

      def stop(reason: "shutdown")
        should_stop = @mutex.synchronize do
          active = @running || (@thread && @thread.alive?) || [@node_informer, @pod_informer].compact.any? do |informer|
            informer.respond_to?(:running?) && informer.running?
          end
          @running = false
          active
        end
        return self unless should_stop

        stop_components(reason: reason)
        stop_bind_workers
        log(:info, "process.stopped", reason: reason)
        self
      end

      def started?
        @mutex.synchronize { @running }
      end

      alias ready? started?

      private

      def build_runtime!
        @client ||= @client_factory&.call
        if @store.nil? && @client
          @store = KubernetesStoreAdapter.new(
            client: @client,
            resource_descriptors: [Controller::ResourceDescriptor.parse("Lease"),
                                   Controller::ResourceDescriptor.parse("Pod")],
            field_manager: "rubernetes-scheduler",
            effect_journal: @effect_journal
          )
        end
        if @framework.nil?
          raise Config::Error, "rubernetes-scheduler requires an API client or injected framework" unless @client || @store

          # Preemption is inert without a delete handler: apply_preemption!
          # fails closed with "preemption requires a delete handler", so every
          # Pod that needs preemption stays Pending forever.  Upstream's
          # executor calls util.DeletePod on each victim
          # (pkg/scheduler/framework/preemption/executor.go), a plain graceful
          # delete that honours the victim's own terminationGracePeriodSeconds.
          @framework = Scheduler::Framework.new(bind: method(:bind_pod),
                                                delete_pod: method(:delete_victim_pod),
                                                nominate: method(:nominate_pod),
                                                clear_nomination: method(:clear_pod_nomination),
                                                preemption_observer: method(:observe_preemption_goroutine),
                                                metrics: @scheduler_metrics,
                                                feature_gates: @config.fetch("feature_gates", {}),
                                                pod_group_status: method(:patch_pod_group_status))
        end
        if @framework.respond_to?(:queue) && @scheduler_metrics.respond_to?(:queue=)
          @scheduler_metrics.queue = @framework.queue
          @framework.queue.metrics = @scheduler_metrics if @framework.queue.respond_to?(:metrics=)
        end
        # DynamicResources writes allocations and reservations to claims.
        if @client && @framework.respond_to?(:dynamic_resources) && @framework.dynamic_resources&.api.nil?
          @framework.dynamic_resources.api = Scheduler::DynamicResources::ClientAPI.new(@client)
        end
        # VolumeBinding writes PV claimRefs and claims' selected-node; with
        # asynchronous binding it is waited for in the binding cycle.
        if @client && @framework.respond_to?(:volume_binding) && @framework.volume_binding&.api.nil?
          @framework.volume_binding.api = Scheduler::VolumeBinding::ClientAPI.new(@client)
          @framework.volume_binding.defer_wait = async_binding? if @framework.volume_binding.respond_to?(:defer_wait=)
        end
        build_elector!
        build_cluster_informers!
        return if @node_informer && @pod_informer

        @client ||= @client_factory&.call
        raise Config::Error, "rubernetes-scheduler requires an API client to build informers" unless @client

        @node_informer ||= build_informer(Controller::ResourceDescriptor.parse("Node"))
        @pod_informer ||= build_informer(Controller::ResourceDescriptor.parse("Pod"))
      end

      def build_cluster_informers!
        CLUSTER_KINDS.each do |kind|
          next if @cluster_informers.key?(kind)

          descriptor = Controller::ResourceDescriptor.parse(kind)
          sourced = @resource_sources[descriptor] || @resource_sources[descriptor.identifier] || @resource_sources[kind]
          next unless sourced || @client

          @cluster_informers[kind] = build_informer(descriptor)
        end
      end

      def cluster_key(object)
        metadata = Controller::Support.value(object, "metadata", {}) || {}
        [Controller::Support.value(metadata, "namespace", "").to_s, Controller::Support.value(metadata, "name", "").to_s].join("/")
      end

      def observe_cluster_object(kind, object, deleted: false)
        added = false
        previous_object = nil
        changed = @mutex.synchronize do
          key = cluster_key(object)
          previous = @cluster_objects[kind][key]
          previous_object = previous
          added = previous.nil? && !deleted
          if deleted
            @cluster_objects[kind].delete(key)
          else
            @cluster_objects[kind][key] = object
          end
          (deleted || previous != object).tap { |value| @cluster_generation += 1 if value }
        end
        return unless changed

        event = "#{kind}#{if deleted
                            "Delete"
                          else
                            (added ? "Add" : "Update")
                          end}"
        timed_event(event) do
          if REQUEUE_KINDS.include?(kind)
            retry_unschedulable("#{kind.downcase}_changed", event: event, old_object: deleted ? object : previous_object,
                                                            new_object: deleted ? nil : object)
          end
        end
      end

      # The plugin inputs for one cycle, rebuilt only after an informer event.
      EMPTY_CLUSTER_VIEW = {namespace_labels: nil, volume_data: nil, workload_selectors: nil, pod_groups: nil}.freeze

      def cluster_view
        return EMPTY_CLUSTER_VIEW if @cluster_objects.nil? || @cluster_informers.nil?

        @mutex.synchronize do
          return @cluster_view if @cluster_view && @cluster_view[:generation] == @cluster_generation

          objects = @cluster_objects
          value = ->(object, *path) { path.reduce(object) { |current, key| Controller::Support.value(current, key, nil) } }
          namespaces = objects["Namespace"].values.to_h do |namespace|
            [value.call(namespace, "metadata", "name").to_s, value.call(namespace, "metadata", "labels") || {}]
          end
          controllers = {}
          {"ReplicationController" => %w[spec selector], "ReplicaSet" => %w[spec selector],
           "StatefulSet" => %w[spec selector]}.each do |kind, path|
            objects[kind].each_value do |controller|
              key = "#{kind}/#{value.call(controller, "metadata", "namespace")}/#{value.call(controller, "metadata", "name")}"
              controllers[key] = value.call(controller, *path)
            end
          end
          services = objects["Service"].values.filter_map do |service|
            selector = value.call(service, "spec", "selector")
            {"namespace" => value.call(service, "metadata", "namespace").to_s, "selector" => selector} if selector.is_a?(Hash)
          end
          track = !@cluster_informers.empty?
          @cluster_view = {
            generation: @cluster_generation,
            namespace_labels: track && @cluster_informers.key?("Namespace") ? namespaces : nil,
            volume_data: if track
                           {"persistentVolumes" => objects["PersistentVolume"].values,
                            "persistentVolumeClaims" => objects["PersistentVolumeClaim"].values,
                            "storageClasses" => objects["StorageClass"].values,
                            "resourceClaims" => objects["ResourceClaim"].values,
                            "resourceSlices" => objects["ResourceSlice"].values,
                            "deviceClasses" => objects["DeviceClass"].values,
                            "csiNodes" => objects["CSINode"].values,
                            "csiDrivers" => objects["CSIDriver"].values,
                            "volumeAttachments" => objects["VolumeAttachment"].values,
                            "csiStorageCapacities" => objects["CSIStorageCapacity"].values}
                         end,
            workload_selectors: track ? {"services" => services, "controllers" => controllers} : nil,
            pod_groups: track && @cluster_informers.key?("PodGroup") ? objects["PodGroup"].dup : nil
          }
        end
      end

      def build_informer(descriptor)
        source = @resource_sources[descriptor] || @resource_sources[descriptor.identifier] ||
                 @resource_sources[descriptor.kind] || KubernetesResourceSource.new(client: @client, descriptor: descriptor)
        # An informer whose watch dies keeps the process alive and healthy
        # looking while it observes nothing at all -- a scheduler that binds no
        # Pod and reports ready.  Surface the failure.
        Watch::Informer.new(client: source, resource: descriptor, namespace: :all,
                            resync_period: @config.fetch("sync", {}).fetch("resync_period", Watch::Informer::DEFAULT_RESYNC_PERIOD),
                            error_handler: informer_error_handler(descriptor))
      end

      def informer_error_handler(descriptor)
        lambda do |error|
          log(:error, "informer.failed", resource: descriptor.to_s,
                                         error: error.class.name, message: error.message)
        end
      end

      def install_handlers!
        @node_informer.on(%i[add update sync]) { |object, *_old| observe_node(object) }
        @node_informer.on(:delete) { |object| delete_node(object) }
        @pod_informer.on(%i[add update sync]) { |object, *_old| observe_pod(object) }
        @pod_informer.on(:delete) { |object| delete_pod(object) }
        @cluster_informers.each do |kind, informer|
          informer.on(%i[add update sync]) { |object, *_old| observe_cluster_object(kind, object) }
          informer.on(:delete) { |object| observe_cluster_object(kind, object, deleted: true) }
        end
      end

      # scheduler_event_handling_duration_seconds{event}: one informer
      # handler, labelled as framework.ClusterEvent.Label() spells the event.
      def timed_event(event)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        yield
      ensure
        @scheduler_metrics&.event_handled(event, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
      end

      # Which part of a Node changed, in ActionType terms.
      def node_event(previous, node)
        node_events(previous, node).first
      end

      # nodeSchedulingPropertiesChange: one event per changed property.
      def node_events(previous, node)
        return ["NodeAdd"] if previous.nil?

        before = node_scheduling_view(previous)
        after = node_scheduling_view(node)
        events = []
        events << "NodeUpdateNodeLabel" if before[1] != after[1]
        events << "NodeUpdateNodeAllocatable" if before[2] != after[2] || before[3] != after[3]
        events << "NodeUpdateNodeCondition" if before[4] != after[4]
        events << "NodeUpdateNodeTaint" if before[0] != after[0] && Controller::Support.value(before[0], "taints",
                                                                                              nil) != Controller::Support.value(after[0],
                                                                                                                                "taints", nil)
        events << "NodeUpdateNodeDeclaredFeature" if before[5] != after[5]
        events << "NodeUpdate" if events.empty?
        events
      end

      # podSchedulingPropertiesChange: the subtypes of a Pod update.
      def pod_events(previous, pod, assigned)
        prefix = assigned ? "assignedPod" : "Pod"
        return ["#{prefix}Add"] if previous.nil?

        events = []
        events << "#{prefix}UpdatePodLabel" if previous.labels != pod.labels
        events << "#{prefix}UpdatePodToleration" if previous.tolerations != pod.tolerations
        events << "#{prefix}UpdatePodSchedulingGatesEliminated" if !previous.scheduling_gates.empty? && pod.scheduling_gates.empty?
        events << "#{prefix}UpdatePodGeneratedResourceClaim" if previous.status["resourceClaimStatuses"] != pod.status["resourceClaimStatuses"]
        before = previous.requests
        after = pod.requests
        events << "#{prefix}UpdatePodScaleDown" if before.any? { |name, amount| after.fetch(name, 0).to_f < amount.to_f }
        events << "#{prefix}Update" if events.empty?
        events
      end

      def prime_informers!
        nodes, = @node_informer.reflector.list!
        pods, = @pod_informer.reflector.list!
        # Cluster data first: the Pods primed below may be scheduled at once.
        @cluster_informers.each do |kind, informer|
          objects, = informer.reflector.list!
          objects.each { |object| observe_cluster_object(kind, object) }
        rescue StandardError => error
          # A resource this identity may not list must not stop the scheduler;
          # the plugins that need it see nothing, as before.
          log(:warn, "scheduler.cluster_informer_unavailable", kind: kind, error: "#{error.class}: #{error.message.to_s[0, 200]}")
          @cluster_informers.delete(kind)
        end
        nodes.each { |object| observe_node(object) }
        pods.each { |object| observe_pod(object) }
      end

      def start_informers!
        @node_informer.start(thread: true)
        @pod_informer.start(thread: true)
        @cluster_informers.each_value { |informer| informer.start(thread: true) }
      end

      # kube-scheduler moves every unschedulable Pod back to the active queue
      # when a Node appears or changes in a way that can admit Pods (taints,
      # labels, allocatable, readiness, unschedulable flag): a Pod rejected
      # while the nodes carried the not-ready taint must be retried once the
      # taint clears, not sit in unschedulableQ forever.
      SCHEDULER_STATUS_INTERVAL = 30.0

      # A periodic one-line health summary: leadership, cache sizes, queue
      # state, informer/reflector liveness and their last errors.  A scheduler
      # that has stopped binding is indistinguishable from an idle one without it.
      def start_scheduler_status_monitor
        @status_thread = Thread.new do
          while started?
            sleep(SCHEDULER_STATUS_INTERVAL)
            break unless started?

            begin
              queue = @framework.respond_to?(:queue) ? @framework.queue : nil
              informers = {"nodes" => @node_informer, "pods" => @pod_informer}
              log(:info, "scheduler.status",
                  leader: @elector.respond_to?(:leader?) ? @elector.leader? : nil,
                  nodes: @mutex.synchronize { @nodes.length },
                  pods: @mutex.synchronize { @pods.length },
                  loop_alive: @thread&.alive?,
                  queue_pending: queue.respond_to?(:pending?) ? queue.pending? : nil,
                  queue_size: queue.respond_to?(:size) ? queue.size : nil,
                  queue_backoff: queue.respond_to?(:backoff_size) ? queue.backoff_size : nil,
                  last_error: @last_error && "#{@last_error.class}: #{@last_error.message.to_s[0, 200]}",
                  last_result: if @last_result.respond_to?(:status)
                                 {status: @last_result.status.to_s, pod: (@last_result.respond_to?(:pod) && @last_result.pod ? @last_result.pod.name : nil), error: (@last_result.respond_to?(:error) && @last_result.error ? @last_result.error.message.to_s[0, 200] : nil)}
                               else
                                 @last_result.inspect[0, 120]
                               end,
                  queue_items: (@framework.respond_to?(:queue) && @framework.queue.respond_to?(:snapshot) ? @framework.queue.snapshot.inspect[0, 300] : nil),
                  informers: informers.transform_values do |informer|
                    next nil unless informer

                    reflector = informer.respond_to?(:reflector) ? informer.reflector : nil
                    {running: informer.respond_to?(:running?) ? informer.running? : nil,
                     error: informer.respond_to?(:last_error) && informer.last_error ? informer.last_error.message.to_s[0, 160] : nil,
                     reflector_running: reflector.respond_to?(:running?) ? reflector.running? : nil,
                     reflector_error: if reflector.respond_to?(:last_error) && reflector.last_error
                                        reflector.last_error.message.to_s[0,
                                                                          160]
                                      end,
                     resource_version: reflector.respond_to?(:resource_version) ? reflector.resource_version : nil}
                  end)
            rescue StandardError => error
              log(:warn, "scheduler.status_failed", error: error.message)
            end
          end
        end
      end

      # status.declaredFeatures: the NodeDeclaredFeatures plugin's
      # UpdateNodeDeclaredFeature event.
      NODE_SCHEDULING_FIELDS = [%w[spec], %w[metadata labels], %w[status allocatable], %w[status capacity],
                                %w[status conditions], %w[status declaredFeatures]].freeze
      UNSCHEDULABLE_FLUSH_SECONDS = 30.0

      # The typed snapshot is what every scheduling cycle needs, so it is kept
      # rather than rebuilt: this used to normalise, deep-copy and deep-freeze
      # the object here, throw that away, store the raw one, and pay for the
      # conversion again for every Node and every Pod on every cycle -- and a
      # cycle runs per Pod scheduled.
      def observe_node(object)
        typed = Scheduler::Node.new(object)
        previous = @mutex.synchronize { @nodes[typed.name].tap { @nodes[typed.name] = typed } }
        changed = previous.nil? || node_scheduling_view(previous) != node_scheduling_view(typed)
        return unless changed

        node_events(previous, typed).each do |event|
          timed_event(event) do
            retry_unschedulable("node_changed", node: typed.name, event: event, old_object: previous, new_object: typed)
          end
        end
      end

      def delete_node(object)
        typed = Scheduler::Node.new(object)
        timed_event("NodeDelete") do
          @mutex.synchronize { @nodes.delete(typed.name) }
          retry_unschedulable("node_deleted", node: typed.name, event: "NodeDelete", old_object: typed, new_object: nil)
        end
      end

      # Accepts a raw object or a typed Node snapshot.
      def node_scheduling_view(object)
        source = object.is_a?(Scheduler::Node) ? object.to_h : object
        NODE_SCHEDULING_FIELDS.map do |path|
          path.reduce(source) { |current, key| Controller::Support.value(current, key, nil) }
        end
      end

      def retry_unschedulable(reason, event: nil, old_object: nil, new_object: nil, **fields)
        return unless @framework.respond_to?(:queue)

        queue = @framework.queue
        promoted = if event && @framework.respond_to?(:requeue_on_event)
                     @framework.requeue_on_event(event, old_object: old_object, new_object: new_object)
                   elsif event && queue.method(:promote_unschedulable).parameters.any? { |_kind, name| name == :event }
                     queue.promote_unschedulable(event: event)
                   else
                     queue.promote_unschedulable
                   end
        return if promoted.empty?

        log(:info, "scheduler.retry_unschedulable", reason: reason, pods: promoted.length, **fields)
      end

      # kube-scheduler's flushUnschedulablePodsLeftover: Pods that nothing
      # moved back are retried periodically so a missed event cannot strand them.
      def flush_unschedulable_if_due
        now = @clock.respond_to?(:call) ? @clock.call : Time.now
        now = now.to_f
        @last_unschedulable_flush ||= now
        return if now - @last_unschedulable_flush < UNSCHEDULABLE_FLUSH_SECONDS

        @last_unschedulable_flush = now
        retry_unschedulable("periodic_flush")
      end

      def observe_pod(object)
        typed = Scheduler::Pod.new(object)
        key = [typed.namespace, typed.name, typed.uid].freeze
        previous = @mutex.synchronize { @pods[key].tap { @pods[key] = typed } }
        assigned = !typed.node_name.empty?
        events = pod_events(previous, typed, assigned)
        events.each_with_index do |event, index|
          timed_event(event) do
            enqueue_if_schedulable(typed) if index.zero?
            # An assigned Pod's add/update (and an unassigned Pod's changed
            # tolerations, labels, gates or claims) may unblock other Pods.
            hinted = assigned || event.include?("UpdatePod")
            if hinted && event != "assignedPodUpdate"
              retry_unschedulable("pod_changed", pod: "#{typed.namespace}/#{typed.name}", event: event, old_object: previous,
                                                 new_object: typed)
            end
          end
        end
      end

      def delete_pod(object)
        typed = Scheduler::Pod.new(object)
        key = [typed.namespace, typed.name, typed.uid].freeze
        event = typed.node_name.empty? ? "PodDelete" : "assignedPodDelete"
        timed_event(event) do
          @mutex.synchronize { @pods.delete(key) }
          @framework.forget_nomination(typed) if @framework.respond_to?(:forget_nomination)
          retry_unschedulable("pod_deleted", pod: "#{typed.namespace}/#{typed.name}", event: event, old_object: typed, new_object: nil)
          @framework.queue.delete(typed) if @framework.respond_to?(:queue)
        end
      end

      # A scheduling cycle that failed for a Pod the informer no longer holds is
      # working on a Pod that has been deleted.  Nothing will deliver another
      # delete event for it, so drop it here rather than let it cycle forever.
      # This backs up Framework#pod_gone?, which only recognises an explicit
      # 404 from the API server.
      def forget_unknown_pod(pod)
        return unless @framework.respond_to?(:queue)

        typed = pod.is_a?(Scheduler::Pod) ? pod : Scheduler::Pod.new(pod)
        key = [typed.namespace, typed.name, typed.uid].freeze
        return if @mutex.synchronize { @pods.key?(key) }

        @framework.queue.delete(typed)
        log(:info, "scheduler.result_dropped", pod: "#{typed.namespace}/#{typed.name}",
                                               status: "unknown_pod", error: nil)
      rescue StandardError => error
        log(:warn, "scheduler.forget_failed", error: error.message)
      end

      def enqueue_if_schedulable(pod)
        return unless pod.node_name.empty?
        return unless pod.scheduler_name == "default-scheduler"
        return if pod.metadata["deletionTimestamp"] || pod.metadata[:deletionTimestamp]

        phase = pod.status["phase"] || pod.status[:phase]
        return if phase && !phase.to_s.empty? && phase.to_s != "Pending"

        @framework.enqueue(pod)
      end

      # How long an idle scheduling pass waits before looking again.  The
      # configured sync interval still bounds leadership checks and the
      # unschedulable flush; this only bounds the gap between two Pods.
      IDLE_POLL_SECONDS = 0.02

      def run_loop
        consecutive_failures = 0
        while started?
          begin
            election = @elector.step
            if @elector.leader?
              flush_unschedulable_if_due
              nodes = @mutex.synchronize { @nodes.values.dup }
              pods = @mutex.synchronize { @pods.values.dup }
              view = cluster_view
              attempt_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              result = @framework.schedule_next(nodes: nodes, pods: pods, namespace_labels: view[:namespace_labels],
                                                volume_data: view[:volume_data], workload_selectors: view[:workload_selectors],
                                                pod_groups: view[:pod_groups])
              record_attempt(result, Process.clock_gettime(Process::CLOCK_MONOTONIC) - attempt_started) if result
              @last_result = result if result
              # A result that is neither a binding nor an unschedulable verdict
              # (a bind error, a plugin failure) used to vanish silently.
              if result && ((result.respond_to?(:failed?) && result.failed?) || (result.respond_to?(:error) && result.error))
                dropped = result.respond_to?(:dropped?) && result.dropped?
                log(dropped ? :info : :warn, dropped ? "scheduler.result_dropped" : "scheduler.result_failed",
                    pod: result.respond_to?(:pod) && result.pod ? "#{result.pod.namespace}/#{result.pod.name}" : nil,
                    status: result.respond_to?(:status) ? result.status.to_s : nil,
                    error: result.respond_to?(:error) && result.error ? "#{result.error.class}: #{result.error.message.to_s[0, 300]}" : nil)
                forget_unknown_pod(result.pod) if !dropped && result.respond_to?(:pod) && result.pod
              end
              report_unschedulable(result, nodes.length) if result.respond_to?(:unschedulable?) && result.unschedulable? &&
                                                            !(result.respond_to?(:gated?) && result.gated?)
            else
              @last_result = {election: election, follower: true}.freeze
            end
            # kube-scheduler drains its queue as fast as it can bind; the
            # interval is only how long an idle loop waits before looking
            # again.  Sleeping it after every Pod too paced scheduling at one
            # Pod per interval: a 30-replica Deployment took 25 s to place.
            #
            # An idle pass waits a short time, not the whole interval: Pods
            # arrive one at a time, so a queue that is momentarily empty is
            # the normal state between two arrivals, and sleeping the
            # configured 0.5 s there put half a second between consecutive
            # Pods of the same burst.
            @sleeper.call([@interval, IDLE_POLL_SECONDS].min) if started? && result.nil?
            consecutive_failures = 0
          rescue Controller::LeadershipLostError => error
            @mutex.synchronize { @last_error = error }
            log(:warn, "scheduler.leadership_lost", message: error.message)
            @sleeper.call(@interval) if started?
          rescue StandardError => error
            # A scheduling error (a plugin bug, one poison pod) must never kill
            # the scheduler: the affected pod is requeued by the framework, and
            # the loop backs off and continues.  Only an explicit stop ends it.
            consecutive_failures += 1
            @mutex.synchronize { @last_error = error }
            log(transient_loop_error?(error) ? :warn : :error, "scheduler.loop_error",
                error: error.class.name, message: error.message.to_s[0, 300],
                consecutive_failures: consecutive_failures)
            @sleeper.call(loop_backoff(consecutive_failures)) if started?
          end
        end
      rescue StandardError => error
        @mutex.synchronize do
          @last_error = error
          @running = false
        end
        log(:error, "process.failed", component: "scheduler", error: error)
        stop_components(reason: "loop_failed")
      end

      # kube-scheduler: a Pod no node accepts gets a PodScheduled=False
      # condition with reason Unschedulable and the per-reason node counts
      # ("0/3 nodes are available: 3 Insufficient cpu.").  Clients (and the
      # conformance suite) wait on that condition, so it is written on every
      # change of the message and left alone otherwise.
      def report_unschedulable(result, node_count)
        return unless @client

        pod = result.pod
        counts = Hash.new(0)
        Array(result.filtered.respond_to?(:each_value) ? result.filtered.values : []).each do |entry|
          reason = entry.is_a?(Hash) ? (entry["reason"] || entry[:reason]) : nil
          counts[reason.to_s] += 1 unless reason.to_s.empty?
        end
        summary = counts.sort_by { |reason, count| [-count, reason] }.map { |reason, count| "#{count} #{reason}" }.join(", ")
        summary = result.reason.to_s if summary.empty?
        message = "0/#{node_count} nodes are available: #{summary}."
        key = [pod.namespace, pod.name, pod.uid].join("/")
        # updatePod: the condition and the NominatingInfo go in one status
        # write -- a preemptor is nominated to the node its victims are
        # leaving ("" clears an old nomination, nil leaves it alone).
        nominated = result.respond_to?(:nominated_node) ? result.nominated_node : nil
        report = [message, nominated]
        return if @unschedulable_reports&.fetch(key, nil) == report

        condition = {"type" => "PodScheduled", "status" => "False", "reason" => "Unschedulable", "message" => message,
                     "lastTransitionTime" => Time.now.utc.iso8601, "lastProbeTime" => nil}
        status = {"conditions" => [condition]}
        status["nominatedNodeName"] = nominated.empty? ? nil : nominated unless nominated.nil?
        timed_status_patch do
          @client.patch("pods", {"status" => status}, type: :strategic, namespace: pod.namespace,
                                                      api_version: "v1", name: pod.name, subresource: "status")
        end
        (@unschedulable_reports ||= {})[key] = report
        log(:info, "scheduler.unschedulable", pod: key, message: message)
        record_pod_event(pod, "FailedScheduling", message, type: "Warning")
      rescue StandardError => error
        log(:warn, "scheduler.unschedulable_report_failed", pod: pod && pod.name, error: error.class.name, message: error.message)
      end

      # preemption.go PrepareCandidate: a victim is told WHY it is going away
      # before it is deleted, so that everything downstream can tell an
      # involuntary disruption from a failure of its own.  We deleted victims
      # silently, so the condition never appeared: "[sig-scheduling]
      # SchedulerPreemption validates pod disruption condition is added to the
      # preempted pod" saw a victim with no DisruptionTarget, and a Job pod
      # failure policy that ignores failures matching DisruptionTarget had
      # nothing to match on.
      DISRUPTION_TARGET_MESSAGE = "DefaultPreemption: preempting to accommodate a higher priority pod"

      def mark_victim_disrupted(victim)
        condition = {"type" => "DisruptionTarget", "status" => "True",
                     "reason" => "PreemptionByScheduler", "message" => DISRUPTION_TARGET_MESSAGE,
                     "lastTransitionTime" => Time.now.utc.iso8601, "lastProbeTime" => nil}
        # Strategic merge: conditions merge by type.  A JSON merge patch
        # replaced the whole list and took Ready away from a running victim.
        @client.patch("pods", {"status" => {"conditions" => [condition]}}, type: :strategic,
                                                                           namespace: victim.namespace, api_version: "v1", name: victim.name, subresource: "status")
      rescue Client::APIError => error
        # A victim that vanished, or whose status we may not write, must not
        # stop the preemption it was chosen for.
        raise unless [404, 409, 422].include?(error.status.to_i)
      rescue StandardError => error
        log(:warn, "scheduler.victim_condition_failed", pod: "#{victim.namespace}/#{victim.name}",
                                                        error: error.class.name, message: error.message)
      end

      # NominatedNodeNameForExpectation: tell other components where a Pod
      # whose PreBind has work to do is about to be bound.
      def nominate_pod(pod, node_name)
        return true unless @client

        patch_nomination(pod, node_name)
      end

      # clearNominatedNodeName for lower-priority Pods nominated to a node a
      # preemption is freeing for a more important Pod.
      def clear_pod_nomination(pod)
        return true unless @client

        patch_nomination(pod, nil)
      end

      def patch_nomination(pod, node_name)
        timed_status_patch do
          @client.patch("pods", {"status" => {"nominatedNodeName" => node_name}}, type: :merge, namespace: pod.namespace,
                                                                                  api_version: "v1", name: pod.name, subresource: "status")
        end
        true
      rescue Client::APIError => error
        raise unless [404, 409].include?(error.status.to_i)

        false
      end

      # Evict one preemption victim.  Mirrors upstream util.DeletePod: a plain
      # graceful delete, with the victim's own grace period applied by the API
      # server.  A victim that is already gone is a success -- something else
      # freed the room preemption was trying to make.
      # scheduler_async_api_call_execution_* for a Pod status patch (the
      # nominated node, the PodScheduled condition).
      def timed_status_patch
        @scheduler_metrics&.async_call_queued(Scheduler::Metrics::CALL_POD_STATUS_PATCH)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = yield
        @scheduler_metrics&.async_call(Scheduler::Metrics::CALL_POD_STATUS_PATCH, "success",
                                       Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        result
      rescue StandardError
        @scheduler_metrics&.async_call(Scheduler::Metrics::CALL_POD_STATUS_PATCH, "error",
                                       Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        raise
      end

      # /metrics/resources: kube_pod_resource_request / kube_pod_resource_limit
      # (pkg/scheduler/metrics/resources) for every Pod the scheduler knows.
      def resource_metrics_body
        pods = @mutex.synchronize { @pods.values.dup }
        Scheduler::ResourceMetrics.render(pods)
      end

      def delete_victim_pod(victim)
        @elector.step
        raise Controller::LeadershipLostError, "scheduler leadership was lost before preempting #{victim.name}" unless @elector.leader?
        return true unless @client

        mark_victim_disrupted(victim)
        begin
          @client.delete("pods", victim.name, namespace: victim.namespace, api_version: "v1")
        rescue Client::APIError => error
          raise unless error.status.to_i == 404

          log(:info, "scheduler.victim_already_gone", pod: "#{victim.namespace}/#{victim.name}")
        end
        log(:info, "scheduler.victim_preempted", pod: "#{victim.namespace}/#{victim.name}")
        true
      end

      # updatePodGroupCondition: the PodGroupScheduled condition on the
      # PodGroup's status (a True condition is never downgraded).
      def patch_pod_group_status(namespace, name, condition)
        return unless @client

        current = @client.get("podgroups", name, namespace: namespace, api_version: "scheduling.k8s.io/v1alpha2")
        conditions = Array(current.dig("status", "conditions"))
        existing = conditions.find { |entry| entry["type"] == condition["type"] }
        return if existing && existing["status"] == "True" && condition["status"] != "True"

        stamped = condition.merge("observedGeneration" => current.dig("metadata", "generation"),
                                  "lastTransitionTime" => (existing && existing["status"] == condition["status"] ? existing["lastTransitionTime"] : Time.now.utc.iso8601))
        merged = conditions.reject { |entry| entry["type"] == condition["type"] } + [stamped]
        @client.patch({"status" => {"conditions" => merged}}, type: :merge, namespace: namespace, name: name,
                                                              api_version: "scheduling.k8s.io/v1alpha2", path: "/apis/scheduling.k8s.io/v1alpha2/namespaces/#{namespace}/podgroups/#{name}/status")
      rescue StandardError => error
        log(:warn, "scheduler.podgroup_status_failed", podgroup: "#{namespace}/#{name}", error: error.message.to_s[0, 200])
      end

      def bind_pod(pod, node)
        @elector.step
        raise Controller::LeadershipLostError, "scheduler leadership was lost before binding #{pod.name}" unless @elector.leader?
        return assume_and_bind(pod, node) if @client && async_binding?

        live_pod = if @client
                     @client.get("pods", pod.name, namespace: pod.namespace, api_version: "v1")
                   else
                     pod.to_h
                   end
        live_node_name = Controller::Support.value(Controller::Support.spec(live_pod), "nodeName", "").to_s
        return live_pod unless live_node_name.empty?

        candidate = Controller::Support.deep_copy(live_pod)
        candidate["apiVersion"] ||= "v1"
        candidate["kind"] ||= "Pod"
        candidate["spec"] ||= {}
        candidate["spec"]["nodeName"] = node.name
        if @client
          @elector.step
          raise Controller::LeadershipLostError, "scheduler leadership was lost before binding #{pod.name}" unless @elector.leader?

          # kube-scheduler binds through pods/binding; the API server sets
          # nodeName and PodScheduled=True atomically and refuses a second
          # binding, which is what makes concurrent schedulers safe.
          binding = {"apiVersion" => "v1", "kind" => "Binding",
                     "metadata" => {"name" => pod.name, "namespace" => pod.namespace, "uid" => pod.uid.to_s.empty? ? nil : pod.uid}.compact,
                     "target" => {"apiVersion" => "v1", "kind" => "Node", "name" => node.name}}
          response = bind_through_api(binding, pod, node)
          @effect_journal&.record(effect_type: "bind", reconcile_key: "v1/pods/#{pod.namespace}/#{pod.name}",
                                  action: :bind, object: candidate, response: response,
                                  extra: {"request_body" => binding})
          record_pod_event(pod, "Scheduled", "Successfully assigned #{pod.namespace}/#{pod.name} to #{node.name}")
          return candidate
        end
        if @store
          adapter = @store.is_a?(Controller::StoreAdapter) ? @store : Controller::StoreAdapter.new(@store)
          return adapter.update(candidate, descriptor: Controller::ResourceDescriptor.parse("Pod"))
        end
        raise Config::Error, "scheduler bind requires an API client or store"
      end

      # kube-scheduler assumes a Pod onto its node and binds it from a
      # separate goroutine: the next scheduling cycle starts at once and sees
      # the assumed Pod in its cache.  Binding inline -- a GET of the live
      # Pod, then the POST of the Binding, both through consensus -- held
      # every cycle for both round trips, so a 90-Pod burst was placed at
      # about five Pods a second.  The Binding subresource still refuses a
      # Pod that is already bound, which is what the GET used to check.
      BIND_WORKERS = 4

      def async_binding?
        @config.fetch("async_bind", true) != false
      end

      def assume_and_bind(pod, node)
        candidate = Controller::Support.deep_copy(pod.to_h)
        candidate["apiVersion"] ||= "v1"
        candidate["kind"] ||= "Pod"
        candidate["spec"] = (candidate["spec"] || {}).merge("nodeName" => node.name)
        assumed = Scheduler::Pod.new(candidate)
        key = [pod.namespace, pod.name, pod.uid].freeze
        @mutex.synchronize do
          @pods[key] = assumed
          (@assumed_pods ||= {})[key] = true
          start_bind_workers_locked
        end
        @scheduler_metrics&.async_call_queued(Scheduler::Metrics::CALL_POD_BINDING)
        @bind_queue << [pod, node, key, assumed]
        candidate
      end

      # An assumed Pod is forgotten once its binding call finished, either way.
      def forget_assumed(key)
        @mutex.synchronize { @assumed_pods&.delete(key) }
      end

      def start_bind_workers_locked
        @bind_queue ||= Queue.new
        @bind_workers = Array(@bind_workers).select(&:alive?)
        (BIND_WORKERS - @bind_workers.length).times do |index|
          worker = Thread.new { bind_worker_loop }
          worker.name = "scheduler-bind-#{index}"
          @bind_workers << worker
        end
      end

      def bind_worker_loop
        while (item = @bind_queue.pop)
          break if item == :stop

          @scheduler_metrics&.goroutine_started(Scheduler::Metrics::GOROUTINE_BINDING)
          begin
            complete_binding(*item)
          ensure
            @scheduler_metrics&.goroutine_finished(Scheduler::Metrics::GOROUTINE_BINDING)
          end
        end
      end

      def complete_binding(pod, node, key, assumed)
        # A Pod whose PreBind wrote volume bindings is bound once the PV
        # controller and provisioner completed them -- waited for on a thread
        # of its own, so neither the scheduling loop nor the bind workers
        # stall behind a slow provisioner.
        volume_binding = @framework.respond_to?(:volume_binding) ? @framework.volume_binding : nil
        if volume_binding.respond_to?(:pending?) && volume_binding.pending?(pod)
          waiter = Thread.new do
            volume_binding.wait_for_bindings(pod, node.name)
            @bind_queue << [pod, node, key, assumed]
          rescue StandardError => error
            binding_failed(pod, node, key, assumed, error)
          end
          waiter.name = "scheduler-volume-binding"
          return
        end
        @elector.step
        raise Controller::LeadershipLostError, "scheduler leadership was lost before binding #{pod.name}" unless @elector.leader?

        binding = {"apiVersion" => "v1", "kind" => "Binding",
                   "metadata" => {"name" => pod.name, "namespace" => pod.namespace, "uid" => pod.uid.to_s.empty? ? nil : pod.uid}.compact,
                   "target" => {"apiVersion" => "v1", "kind" => "Node", "name" => node.name}}
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          response = bind_through_api(binding, pod, node)
        rescue StandardError
          @scheduler_metrics&.async_call(Scheduler::Metrics::CALL_POD_BINDING, "error",
                                         Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          raise
        end
        @scheduler_metrics&.async_call(Scheduler::Metrics::CALL_POD_BINDING, "success",
                                       Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        forget_assumed(key)
        @effect_journal&.record(effect_type: "bind", reconcile_key: "v1/pods/#{pod.namespace}/#{pod.name}",
                                action: :bind, object: assumed.to_h, response: response,
                                extra: {"request_body" => binding})
        record_pod_event(pod, "Scheduled", "Successfully assigned #{pod.namespace}/#{pod.name} to #{node.name}")
      rescue StandardError => error
        forget_assumed(key)
        binding_failed(pod, node, key, assumed, error)
      end

      # Forget the assumption and let the Pod be scheduled again -- unless it
      # is already bound (409): the informer then delivers where it went --
      # or it is gone (404, or its delete arrived while the binding was in
      # flight).  handleSchedulingFailure requeues only a Pod the informer
      # still holds; requeueing a deleted one looped for ever: the next
      # cycle's assumption put it back into the cache, its binding failed with
      # 404 and requeued it again (two gc-* Pods, ~10,000 times each).
      def binding_failed(pod, node, key, assumed, error)
        already_bound = error.message.include?("409") || error.message.include?("already assigned")
        gone = error.message.include?("HTTP 404")
        known = @mutex.synchronize do
          if @pods[key].equal?(assumed)
            gone ? @pods.delete(key) : @pods[key] = pod
          end
          @pods.key?(key)
        end
        requeue = !already_bound && !gone && known
        log(:warn, "scheduler.bind_failed", pod: "#{pod.namespace}/#{pod.name}", node: node.name,
                                            error: "#{error.class}: #{error.message.to_s[0, 300]}", requeued: requeue)
        if requeue
          @framework.enqueue(pod) if @framework.respond_to?(:enqueue) && started?
        elsif gone && @framework.respond_to?(:queue)
          @framework.queue.delete(pod)
        end
      end

      def stop_bind_workers
        workers = @mutex.synchronize { Array(@bind_workers).dup }
        workers.length.times { @bind_queue << :stop } if @bind_queue
        workers.each { |worker| worker.join(5) }
      end

      def binding_path(pod)
        "/api/v1/namespaces/#{pod.namespace}/pods/#{pod.name}/binding"
      end

      def bind_through_api(binding, pod, node)
        # The Binding is posted to the *Pod's* binding subresource, so the
        # path names pods -- deriving it from the Binding manifest's own kind
        # produced /bindings/... , the request never reached the API server,
        # and the fallback below patched the Pod's spec instead.  That counts
        # as a spec change and bumped metadata.generation, which upstream
        # keeps at 1 through scheduling.
        @client.create(binding, path: binding_path(pod), api_version: "v1")
      rescue StandardError => error
        # A client without the binding path (tests, older adapters) falls
        # back to writing nodeName directly.
        if error.message.include?("409") || error.message.include?("already assigned")
          raise Scheduler::BindError,
                "binding #{pod.namespace}/#{pod.name} to #{node.name} failed: #{error.message}"
        end
        # The Pod is gone: patching it cannot succeed either.
        if error.message.include?("HTTP 404")
          raise Scheduler::BindError,
                "binding #{pod.namespace}/#{pod.name} to #{node.name} failed: #{error.message}"
        end

        response = @client.patch("pods", {"spec" => {"nodeName" => node.name}}, type: :merge,
                                                                                namespace: pod.namespace, api_version: "v1", name: pod.name)
        if response.is_a?(Hash)
          observed = response.dig("spec", "nodeName") || response.dig(:spec, :nodeName)
          if observed && observed.to_s != node.name
            raise Scheduler::BindError, "API server returned pod bound to #{observed.inspect}, expected #{node.name.inspect}"
          end
        end
        response
      end

      # Events with source default-scheduler (Scheduled / FailedScheduling).
      def record_pod_event(pod, reason, message, type: "Normal")
        return unless @client

        @event_recorder ||= Node::EventRecorder.new(client: Node::EventSink.new(client: @client), reporting_component: "default-scheduler",
                                                    reporting_instance: @config.fetch("identity", Socket.gethostname), event_time: false,
                                                    source: {"component" => "default-scheduler"}, clock: @clock)
        reference = {"kind" => "Pod", "apiVersion" => "v1", "namespace" => pod.namespace, "name" => pod.name, "uid" => pod.uid}.compact
        @event_recorder.record(involved_object: reference, reason: reason, message: message, type: type, namespace: pod.namespace)
      rescue StandardError => error
        log(:debug, "scheduler.event_failed", reason: reason, error: error.class.name, message: error.message)
      end

      def build_elector!
        return if @elector

        identity = @config.fetch("identity", "#{Socket.gethostname}:#{Process.pid}")
        lease = symbolize(@config.fetch("lease", {}))
        lease[:clock] ||= @clock
        lease[:name] ||= DEFAULT_LEASE_NAME
        @elector = Controller::LeaseElector.new(store: @store, identity: identity, **lease)
      end

      def stop_components(reason:)
        @component_server&.stop
        @component_server = nil
        @node_informer&.stop(join: true) if @node_informer.respond_to?(:stop)
        @pod_informer&.stop(join: true) if @pod_informer.respond_to?(:stop)
        @cluster_informers.each_value { |informer| informer.stop(join: true) if informer.respond_to?(:stop) }
        @elector.release if @elector&.leader?
        @thread&.join if @thread && @thread != Thread.current
        @thread = nil
      rescue StandardError => error
        log(:error, "process.stop_failed", component: "scheduler", reason: reason, error: error)
        raise
      end

      def log(level, event, **fields)
        logger.public_send(level, event, **fields) if logger.respond_to?(level)
      end

      def symbolize(value)
        value.to_h.transform_keys { |key| key.to_sym }
      end
    end

    class ProxyService
      def initialize(config:, logger:, client: nil, client_factory: nil, proxy: nil,
                     resource_sources: {}, runtime_adapters: {}, clock: -> { Time.now.utc })
        @config = config || {}
        @logger = logger
        @client = client || runtime_adapters[:proxy_client] || runtime_adapters["proxy_client"]
        @client_factory = client_factory
        @proxy = proxy || runtime_adapters[:proxy] || runtime_adapters["proxy"]
        @resource_sources = resource_sources.to_h
        @runtime_adapters = runtime_adapters.to_h
        @clock = clock
        @subscriptions = []
        @running = false
        @last_error = nil
        @mutex = Mutex.new
        @proxy_metrics = Proxy::Metrics.new(mode: backend_name == :iptables ? :iptables : :nftables)
        @metrics = @proxy_metrics.registry
        @started_at = nil
      end

      attr_reader :config, :logger, :proxy, :client, :subscriptions, :last_error, :metrics

      def start
        @mutex.synchronize { raise "rubernetes-proxy is already started" if @running }
        begin
          build_runtime!
          @proxy.metrics = @proxy_metrics if @proxy.respond_to?(:metrics=)
          service_source = resource_source_for(Controller::ResourceDescriptor.parse("Service"))
          endpoint_source = resource_source_for(Controller::ResourceDescriptor.parse("EndpointSlice"))
          apply_snapshot(service_source, kind: :service)
          apply_snapshot(endpoint_source, kind: :endpoint_slice)
          # healthCheckNodePort is a node-local socket contract.  Start it
          # only after the initial Service snapshot has populated readiness;
          # TC/nft datapaths deliberately leave these packets local.
          @proxy.start_health_check_responder if @proxy.respond_to?(:start_health_check_responder)
          @proxy.sync
          attach_backend_if_requested
          # The server closes each watch after PROXY_WATCH_TIMEOUT_SECONDS and
          # the client reopens it from the last resourceVersion: a quiet watch
          # no longer runs into the client's 60 s read timeout, which had been
          # counted as a failure, forced a resync, and backed the watch off.
          @subscriptions = @proxy.start_watch(service_source: service_source,
                                              endpoint_slice_source: endpoint_source,
                                              timeout_seconds: PROXY_WATCH_TIMEOUT_SECONDS,
                                              error_handler: lambda do |error|
                                                log(:warn, "proxy.watch_error", error: error.class.name,
                                                                                message: error.message.to_s[0, 500],
                                                                                cause: error.respond_to?(:cause) && error.cause ? error.cause.message.to_s[0, 300] : nil,
                                                                                backtrace: Array(error.backtrace).first(4))
                                              end)
          raise Config::Error, "rubernetes-proxy could not start Service/EndpointSlice watch loops" if @subscriptions.empty?

          @mutex.synchronize { @running = true }
          @started_at = @clock.call
          start_status_monitor
          # kube-proxy's metrics (--metrics-bind-address) and health
          # (--healthz-bind-address) servers, on one loopback port here:
          # /metrics, /healthz (the proxier's sync health) and /livez.
          @component_server = ComponentServer.from_config(component: "kube-proxy", config: @config, metrics: @metrics,
                                                          ready: -> { started? }, logger: @logger,
                                                          health: method(:proxier_health))&.start
          log(:info, "process.ready", components: %w[proxy backend service-watch endpointslice-watch] +
                                                  (@component_server ? ["serving"] : []))
          self
        rescue StandardError
          stop_components(reason: "startup_failed")
          raise
        end
      end

      def stop(reason: "shutdown")
        should_stop = @mutex.synchronize do
          next false unless @running

          @running = false
          true
        end
        return self unless should_stop

        stop_components(reason: reason)
        log(:info, "process.stopped", reason: reason)
        self
      end

      def started?
        @mutex.synchronize { @running }
      end

      alias ready? started?

      private

      STATUS_MONITOR_INTERVAL = 30.0
      PROXY_WATCH_TIMEOUT_SECONDS = 45
      PROXY_PUBLISH_COALESCE_SECONDS = 0.02

      # A periodic health line: rule count, watch liveness and the last watch
      # error.  A proxy that silently stopped programming rules is otherwise
      # indistinguishable from a healthy idle one.
      def start_status_monitor
        @status_thread = Thread.new do
          while started?
            begin
              publishes = @proxy.respond_to?(:publish_stats) ? @proxy.publish_stats(reset: true) : {}
              log(:info, "proxy.status",
                  rules: @proxy.respond_to?(:rules) ? @proxy.rules.length : nil,
                  services: @proxy.respond_to?(:services) ? @proxy.services.length : nil,
                  publishes: publishes[:count], publish_seconds: publishes[:seconds]&.round(3),
                  publish_max: publishes[:max]&.round(3),
                  backend: @proxy.respond_to?(:backend) ? @proxy.backend.class.name.to_s.split("::").last : nil,
                  publish_error: @proxy.respond_to?(:last_publish_error) && @proxy.last_publish_error ? @proxy.last_publish_error.message.to_s[0, 200] : nil,
                  watches_running: Array(@subscriptions).map do |subscription|
                    subscription.respond_to?(:running?) ? subscription.running? : nil
                  end,
                  watch_errors: Array(@subscriptions).map do |subscription|
                    subscription.respond_to?(:last_error) && subscription.last_error ? subscription.last_error.message.to_s[0, 200] : nil
                  end)
            rescue StandardError => error
              log(:warn, "proxy.status_failed", error: error.message)
            end
            sleep(STATUS_MONITOR_INTERVAL)
          end
        end
      end

      def build_runtime!
        @client ||= @client_factory&.call
        return if @proxy

        raise Config::Error, "rubernetes-proxy requires an API client or injected proxy" unless @client

        node_name = @config["node_name"]
        raise Config::Error, "rubernetes-proxy.node_name is required to start the proxy" if node_name.to_s.empty?

        backend = @runtime_adapters[:proxy_backend] || @runtime_adapters["proxy_backend"] || backend_name
        backend = Proxy::MemoryBackend.new(clock: @clock) if backend.to_s.downcase == "memory"
        @proxy = Proxy::Proxy.new(
          local_node: node_name,
          backend: backend,
          ebpf: @runtime_adapters[:ebpf] || @runtime_adapters["ebpf"],
          nftables: @runtime_adapters[:nftables] || @runtime_adapters["nftables"],
          capability_probe: @runtime_adapters[:capability_probe] || @runtime_adapters["capability_probe"],
          connection_probe: @runtime_adapters[:connection_probe] || @runtime_adapters["connection_probe"],
          connection_tracker: @runtime_adapters[:connection_tracker] || @runtime_adapters["connection_tracker"],
          attach: false,
          clock: @clock
        )
        @proxy.publish_coalescing_seconds = PROXY_PUBLISH_COALESCE_SECONDS if @proxy.respond_to?(:publish_coalescing_seconds=)
        # A memory backend programs no kernel datapath, so there are no
        # kernel conntrack entries of its making to reconcile.
        if @proxy.respond_to?(:conntrack_reconciler=) && !backend.is_a?(Proxy::MemoryBackend)
          @proxy.conntrack_reconciler = @runtime_adapters[:conntrack_reconciler] || @runtime_adapters["conntrack_reconciler"] ||
                                        Proxy::ConntrackReconciler.new(families: proxy_ip_families, metrics: @proxy_metrics,
                                                                       logger: @logger)
        end
        trace_keys = defined?(Controller::Manager::TRACE_KEYS) ? Controller::Manager::TRACE_KEYS : nil
        return unless trace_keys && @proxy.respond_to?(:trace=)

        @proxy.trace = lambda do |fields|
          log(:info, "proxy.trace", **fields) if trace_keys.match?(fields[:key].to_s) || trace_keys.match?(fields[:service_key].to_s)
        end
      end

      def backend_name
        (@config["backend"] || "auto").to_s.downcase.to_sym
      end

      # The node's address families (what --cluster-cidr / the node IPs give
      # kube-proxy): the conntrack reconciler runs once per family.
      def proxy_ip_families
        addresses = @proxy.respond_to?(:node_addresses) ? Array(@proxy.node_addresses) : []
        families = addresses.filter_map { |ip| Proxy::ModelSupport.ip_family(ip) }.uniq
        families.empty? ? ["IPv4"] : families
      end

      def resource_source_for(descriptor)
        @resource_sources[descriptor] || @resource_sources[descriptor.identifier] ||
          @resource_sources[descriptor.kind] || KubernetesResourceSource.new(client: @client, descriptor: descriptor)
      end

      def apply_snapshot(source, kind:)
        response = source.list
        objects = response.is_a?(Hash) ? (response["items"] || response[:items] || []) : Array(response)
        objects.each do |object|
          kind == :service ? @proxy.apply_service(object) : @proxy.apply_endpoint_slice(object)
        end
      end

      def attach_backend_if_requested
        return if @config.key?("attach") && @config["attach"] == false

        @proxy.attach_backend
        backend = @proxy.backend
        return unless backend.respond_to?(:ready?)
        raise Config::Error, "rubernetes-proxy backend did not reach ready state" unless backend.ready?
      end

      # proxier_health.go: /healthz is 200 while the proxier synced since it
      # was last asked to (or within the timeout of that request); /livez is
      # 200 for a running proxy.  Both are counted
      # (kubeproxy_proxy_healthz_total / kubeproxy_proxy_livez_total).
      def proxier_health(path)
        if path == "/livez"
          code = started? ? 200 : 503
          @proxy_metrics.livez(code)
          return [code, code == 200 ? "ok" : "not running"]
        end

        healthy = started? && @proxy_metrics.healthy?
        code = healthy ? 200 : 503
        @proxy_metrics.healthz(code)
        synced = @proxy_metrics.last_synced("IPv4")
        [code, JSON.generate("lastUpdated" => synced ? Time.at(synced).utc.iso8601 : "", "currentTime" => Time.now.utc.iso8601)]
      end

      def stop_components(reason:)
        @component_server&.stop
        @component_server = nil
        @proxy&.stop_watch if @proxy.respond_to?(:stop_watch)
        @proxy&.stop_health_check_responder if @proxy.respond_to?(:stop_health_check_responder)
        if @proxy.respond_to?(:detach_backend)
          @proxy.detach_backend
        elsif @proxy.respond_to?(:backend) && @proxy.backend.respond_to?(:detach)
          @proxy.backend.detach
        end
        @subscriptions = []
      rescue StandardError => error
        log(:error, "process.stop_failed", component: "proxy", reason: reason, error: error)
        raise
      end

      def log(level, event, **fields)
        logger.public_send(level, event, **fields) if logger.respond_to?(level)
      end
    end
  end
end
