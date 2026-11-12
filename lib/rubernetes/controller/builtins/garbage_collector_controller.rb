# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class GarbageCollectorController < BaseController
        def initialize(**options)
          @event_sink = options[:event_sink]
          @gc = GarbageCollector.new(store: options[:store], event_sink: @event_sink)
          @sweep_mutex = Mutex.new
          @collector_mutex = Mutex.new
          @last_sweep_at = nil
          super
        end

        def plan(resource = nil, store: nil, objects: nil, deleted: [], propagation_policy: :background, **_options)
          expedite_sweeps! if resource.is_a?(Hash) && foreground_owner?(resource)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          objects ||= adapter ? adapter.all : []
          objects = Array(objects)
          objects << resource if resource && !objects.include?(resource)
          collector(adapter).plan(objects, deleted: deleted, propagation_policy: propagation_policy)
        end

        # The planner is told which kinds the scan actually covered and how to
        # re-read an owner, so "I did not see it" can never be mistaken for "it
        # is gone".  An adapter that cannot say -- an in-memory store holding
        # the whole corpus -- keeps the unrestricted planner.
        def collector(adapter)
          return @gc unless AdapterCapability.declares_kinds?(adapter)

          @collector_mutex.synchronize do
            unless @collector && @collector_adapter.equal?(adapter)
              @collector_adapter = adapter
              @collector = GarbageCollector.new(
                store: adapter, event_sink: @event_sink,
                known_kinds: adapter.resource_descriptors,
                owner_lookup: owner_lookup_for(adapter),
                dependent_lookup: dependent_lookup_for(adapter)
              )
            end
            @collector
          end
        end

        # The live copy of a dependent the sweep is about to collect, nil if it
        # is gone, or the swept copy itself when this adapter cannot read live.
        def dependent_lookup_for(adapter)
          lambda do |object|
            next object unless AdapterCapability.live_reads?(adapter)

            descriptor = ResourceDescriptor.parse(object)
            scope = descriptor.cluster_scoped? ? nil : Support.namespace(object)
            adapter.find_live(descriptor, name: Support.name(object), namespace: scope)
          end
        end

        # true (the owner is there), false (the API server says it is gone) or
        # nil (this collector cannot tell, so the dependent stays).  Only kinds
        # the adapter already knows are looked up: guessing a plural resource
        # path for an unknown kind would turn a 404 on the path itself into a
        # verdict of "owner deleted".
        def owner_lookup_for(adapter)
          by_kind = {}
          Array(adapter.resource_descriptors).each do |descriptor|
            by_kind["#{descriptor.api_version}/#{descriptor.kind}"] ||= descriptor
            by_kind[descriptor.kind.to_s] ||= descriptor
          end
          lambda do |reference, namespace|
            kind = Support.ref_value(reference, "kind", "").to_s
            api_version = Support.ref_value(reference, "apiVersion", "").to_s
            descriptor = by_kind["#{api_version}/#{kind}"] || by_kind[kind]
            name = Support.ref_value(reference, "name", "").to_s
            next nil if descriptor.nil? || name.empty?

            scope = descriptor.cluster_scoped? ? nil : namespace
            object = if AdapterCapability.live_reads?(adapter)
                       adapter.find_live(descriptor, name: name, namespace: scope)
                     else
                       adapter.find(descriptor, name: name, namespace: scope)
                     end
            next false if object.nil?

            uid = Support.ref_value(reference, "uid", "").to_s
            Support.uid(object).to_s == uid
          end
        end

        alias reconcile plan

        # A Background/Foreground delete removes the owner immediately, so the
        # dependents' reconcile key resolves to nothing and the normal
        # reconcile above never runs.  The manager invokes plan_orphans for
        # every key regardless, so the missing-owner sweep runs here and
        # deletes dependents whose owner UID no longer exists.
        # The sweep reads EVERY object in the cluster, so running it once per
        # orphaned key -- and there is one for every deleted object -- made the
        # controller manager spend most of its time re-reading the same corpus.
        # It is a periodic sweep by nature.
        #
        # Upstream's garbage collector does not sweep at all: it keeps a graph
        # built from watch events and only re-lists when discovery changes
        # (pkg/controller/garbagecollector/graph_builder.go).  A sweep is our
        # simplification, and at a five-second period it was costing HALF of
        # all the controller manager's worker time -- measured at 59 seconds of
        # work per 30 seconds of wall clock across four workers -- which pushed
        # the average wait for every other key to 40 seconds.  Once the orphan
        # pass itself was routed rather than asked of every controller, one
        # sweep every ten seconds costs a few percent of one worker -- and ten
        # seconds is what the specs that wait for a collection allow for.
        SWEEP_INTERVAL_SECONDS = 10.0

        def plan_orphans(_key, store: nil)
          return nil unless sweep_due?

          adapter = store || (self.store && StoreAdapter.new(self.store))
          objects = begin
            adapter ? adapter.all : []
          rescue StandardError
            # GarbageCollector.Sync: the resources could not be read.
            ControllerMetrics.increment("garbagecollector_controller_resources_sync_error_total")
            raise
          end
          result = collector(adapter).plan(Array(objects), deleted: [])
          result = with_foreground_operations(result, Array(objects), live: dependent_lookup_for(adapter))
          # An owner still waiting on dependents needs the next pass soon: the
          # foreground protocol takes three (delete or release the
          # dependents, see them gone, drop the finalizer), and ten seconds
          # apart that was half a minute per foreground delete where the
          # kube-controller-manager reacts to each watch event.
          expedite_sweeps! if Array(objects).any? { |object| foreground_owner?(object) }
          # kube-controller-manager logs every collection; a sweep that finds
          # nothing is the only evidence the sweep ran at all.
          log_sweep(objects.length, result)
          result
        end

        def log_sweep(scanned, result)
          line = {"timestamp" => Time.now.utc.iso8601(6), "level" => "info", "event" => "garbage_collector.sweep",
                  "scanned" => scanned, "targets" => Array(result.operations).length}
          $stderr.write(JSON.generate(line) << "\n")
        rescue IOError, SystemCallError
          # A closed or broken stderr must not fail the sweep it reports.
          nil
        end

        # While a foreground deletion is in progress sweeps run this often.
        FOREGROUND_SWEEP_SECONDS = 1.0
        EXPEDITE_WINDOW_SECONDS = 15.0

        def expedite_sweeps!
          @sweep_mutex ||= Mutex.new
          @sweep_mutex.synchronize { @expedite_until = Process.clock_gettime(Process::CLOCK_MONOTONIC) + EXPEDITE_WINDOW_SECONDS }
        end

        def sweep_due?
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          @sweep_mutex ||= Mutex.new
          @sweep_mutex.synchronize do
            interval = @expedite_until && now < @expedite_until ? FOREGROUND_SWEEP_SECONDS : SWEEP_INTERVAL_SECONDS
            return false if @last_sweep_at && (now - @last_sweep_at) < interval

            @last_sweep_at = now
            true
          end
        end
      end
    end
  end
end
