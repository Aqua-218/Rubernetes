# frozen_string_literal: true

require "securerandom"
require "set"

require_relative "cel"
require_relative "../schema/quantity"

module Rubernetes
  module DRA
    # k8s.io/dynamic-resource-allocation/structured (v1.36.2), the
    # "incubating" allocator: the one the scheduler's DynamicResources plugin
    # selects for the default feature gates (DRAConsumableCapacity and
    # DRADeviceBindingConditions are on, which the stable variant does not
    # support).  Ported from structured/internal/incubating
    # (allocator_incubating.go, pools_incubating.go, constraint.go,
    # consumable_capacity.go): depth-first search over claims, requests and
    # devices in pool/slice/device order; first-available subrequests;
    # "All" mode; matchAttribute / distinctAttribute constraints; shared
    # counters (partitionable devices); consumable capacity with request
    # policies; device taints; binding conditions (pools with them last);
    # the node selector of each result.
    #
    # Objects are the API's JSON (resource.k8s.io/v1).  Allocate returns the
    # AllocationResult hashes, nil when the claims cannot be allocated on
    # the node, or raises Error.
    module Allocator
      Quantity = Schema::Quantity

      # resourceapi.AllocationResultsMaxSize.
      ALLOCATION_RESULTS_MAX_SIZE = 32

      class Error < StandardError; end

      # ErrFailedAllocationOnNode: allocation on this node failed for good.
      class FailedOnNode < Error; end

      DeviceID = Data.define(:driver, :pool, :device) do
        def to_s = "#{driver}/#{pool}/#{device}"
      end

      SharedDeviceID = Data.define(:driver, :pool, :device, :share_id) do
        def device_id = DeviceID.new(driver: driver, pool: pool, device: device)
        def to_s = share_id.to_s.empty? ? "#{driver}/#{pool}/#{device}" : "#{driver}/#{pool}/#{device}/#{share_id}"
      end

      Features = Data.define(:admin_access, :prioritized_list, :partitionable_devices, :device_taints,
                             :device_binding_and_status, :consumable_capacity) do
        # The default feature gates of v1.36.2 (AllocatorFeatures).
        def self.defaults
          new(admin_access: true, prioritized_list: true, partitionable_devices: true, device_taints: true,
              device_binding_and_status: true, consumable_capacity: true)
        end
      end

      # schedulerapi.AllocatedState: exclusively allocated devices, shared
      # allocations, and the capacity already consumed per device.
      AllocatedState = Data.define(:allocated_devices, :allocated_shared_device_ids, :aggregated_capacity) do
        def self.empty = new(allocated_devices: Set.new, allocated_shared_device_ids: Set.new, aggregated_capacity: {})

        # GatherAllocatedState over claims with status.allocation
        # (foreachAllocatedDevice).
        def self.from_claims(claims, consumable_capacity: true)
          devices = Set.new
          shared = Set.new
          capacity = {}
          Array(claims).each do |claim|
            Array(claim.dig("status", "allocation", "devices", "results")).each do |result|
              next if result["adminAccess"] == true

              id = DeviceID.new(driver: result["driver"].to_s, pool: result["pool"].to_s, device: result["device"].to_s)
              if consumable_capacity && result["shareID"]
                shared << SharedDeviceID.new(driver: id.driver, pool: id.pool, device: id.device, share_id: result["shareID"].to_s)
                if result["consumedCapacity"]
                  Allocator.insert_capacity(capacity, id, Allocator.quantities(result["consumedCapacity"]))
                end
                next
              end
              devices << id
            end
          end
          new(allocated_devices: devices, allocated_shared_device_ids: shared, aggregated_capacity: capacity)
        end
      end

      Pool = Struct.new(:driver, :pool, :incomplete, :invalid, :invalid_reason, :slices_targeting_node,
                        :slices_not_targeting_node, :counter_sets, keyword_init: true) do
        def id = "#{driver}/#{pool}"
      end

      module_function

      # {name => Quantity} from a JSON map of quantities.
      def quantities(map)
        (map || {}).to_h { |name, value| [name.to_s, value.is_a?(Quantity) ? value : Quantity.from_json(value)] }
      end

      # ConsumedCapacityCollection.Insert.
      def insert_capacity(collection, device_id, consumed)
        current = (collection[device_id] ||= {})
        consumed.each { |name, quantity| current[name] = add(current[name], quantity) }
        collection
      end

      # ConsumedCapacityCollection.Remove.
      def remove_capacity(collection, device_id, consumed)
        current = collection[device_id]
        return unless current

        consumed.each { |name, quantity| current[name] = sub(current[name], quantity) if current.key?(name) }
        collection.delete(device_id) if current.values.all?(&:zero?)
      end

      def add(left, right)
        return right if left.nil?

        Quantity.new(left.value + right.value, left.format)
      end

      def sub(left, right)
        Quantity.new(left.value - right.value, left.format)
      end

      # NodeMatches.
      def node_matches?(node, node_name, all_nodes, node_selector)
        if !node_name.to_s.empty?
          !node.nil? && node.dig("metadata", "name") == node_name
        elsif all_nodes
          true
        elsif node_selector
          NodeSelector.match?(node_selector, node)
        else
          false
        end
      end

      # nodeaffinity.NodeSelector: terms ORed, requirements ANDed, an empty
      # term matches nothing; matchFields only knows metadata.name.
      module NodeSelector
        module_function

        def match?(selector, node)
          return false if node.nil?

          labels = node.dig("metadata", "labels") || {}
          fields = {"metadata.name" => node.dig("metadata", "name").to_s}
          Array(selector["nodeSelectorTerms"]).any? do |term|
            expressions = Array(term["matchExpressions"])
            match_fields = Array(term["matchFields"])
            next false if expressions.empty? && match_fields.empty?

            expressions.all? { |requirement| requirement?(requirement, labels) } &&
              match_fields.all? do |requirement|
                raise Error, "not a valid field selector key: #{requirement["key"]}" unless requirement["key"] == "metadata.name"

                requirement?(requirement, fields)
              end
          end
        end

        def requirement?(requirement, labels)
          key = requirement["key"].to_s
          values = Array(requirement["values"]).map(&:to_s)
          present = labels.key?(key)
          actual = labels[key].to_s
          case requirement["operator"].to_s
          when "In" then present && values.include?(actual)
          when "NotIn" then !present || !values.include?(actual)
          when "Exists" then present
          when "DoesNotExist" then !present
          when "Gt", "Lt"
            return false unless present && values.length == 1

            left = Integer(actual, 10)
            right = Integer(values.first, 10)
            requirement["operator"] == "Gt" ? left > right : left < right
          else false
          end
        rescue ArgumentError
          false
        end
      end

      # ------------------------------------------------------------ pools

      # GatherPools: the pools with devices for +node+, complete ones sorted
      # by driver and pool name, pools with binding conditions last.
      def gather_pools(slices_for_node, node, features, all_slices)
        pools = {}
        slices_for_node.each do |slice|
          spec = slice["spec"] || {}
          counters = Array(spec["sharedCounters"])
          next if !features.partitionable_devices && (!spec["perDeviceNodeSelection"].nil? || !counters.empty?)

          relevant = if !counters.empty?
                       true
                     elsif !spec["nodeName"].to_s.empty? || spec["allNodes"] == true || spec["nodeSelector"]
                       node_matches?(node, spec["nodeName"], spec["allNodes"] == true, spec["nodeSelector"])
                     elsif spec["perDeviceNodeSelection"] == true
                       Array(spec["devices"]).any? do |device|
                         node_matches?(node, device["nodeName"], device["allNodes"] == true, device["nodeSelector"])
                       end
                     else
                       next
                     end
          add_slice(pools, slice) if relevant
        end

        result = []
        with_binding_conditions = []
        pools.each do |(driver, pool_name), slices|
          count = slices.first.dig("spec", "pool", "resourceSliceCount").to_i
          if slices.length == count
            pool = build_pool(driver, pool_name, slices, features, nil)
            (binding_conditions?(pool) ? with_binding_conditions : result) << pool
            next
          end
          obsolete, all_for_pool = slices_in_pool(all_slices, driver, pool_name, slices.first.dig("spec", "pool", "generation").to_i)
          next if obsolete

          if all_for_pool.length != count
            result << Pool.new(driver: driver, pool: pool_name, incomplete: true)
            next
          end
          pool = build_pool(driver, pool_name, slices, features, all_for_pool)
          (binding_conditions?(pool) ? with_binding_conditions : result) << pool
        end
        sort_pools(result) + sort_pools(with_binding_conditions)
      end

      def sort_pools(pools) = pools.sort_by { |pool| [pool.driver, pool.pool] }

      def add_slice(pools, slice)
        spec = slice["spec"] || {}
        key = [spec["driver"].to_s, spec.dig("pool", "name").to_s]
        existing = pools[key]
        generation = spec.dig("pool", "generation").to_i
        if existing.nil?
          pools[key] = [slice]
        elsif generation > existing.first.dig("spec", "pool", "generation").to_i
          pools[key] = [slice]
        elsif generation == existing.first.dig("spec", "pool", "generation").to_i
          existing << slice
        end
      end

      def build_pool(driver, pool_name, slices, features, all_slices_for_pool)
        slices = slices.sort_by { |slice| slice.dig("metadata", "name").to_s }
        counter_slices, device_slices = if features.partitionable_devices
                                          slices.partition { |slice| !Array(slice.dig("spec", "sharedCounters")).empty? }
                                        else
                                          [[], slices]
                                        end
        invalid = ->(reason) { Pool.new(driver: driver, pool: pool_name, invalid: true, invalid_reason: reason) }
        names = Set.new
        device_slices.each do |slice|
          Array(slice.dig("spec", "devices")).each do |device|
            return invalid.call("duplicate device name #{device["name"]}") if names.include?(device["name"])

            names << device["name"]
          end
        end
        unless features.partitionable_devices
          return Pool.new(driver: driver, pool: pool_name, slices_targeting_node: device_slices, slices_not_targeting_node: [],
                          counter_sets: {})
        end

        counter_sets = {}
        counter_slices.each do |slice|
          Array(slice.dig("spec", "sharedCounters")).each do |counter_set|
            return invalid.call("duplicate counter set name #{counter_set["name"]}") if counter_sets.key?(counter_set["name"])

            counter_sets[counter_set["name"]] = counter_set
          end
        end
        reason = counter_consumption_error(counter_sets, slices)
        return invalid.call(reason) if reason

        if all_slices_for_pool.nil? || slices.length == all_slices_for_pool.length
          return Pool.new(driver: driver, pool: pool_name, slices_targeting_node: device_slices, slices_not_targeting_node: [],
                          counter_sets: counter_sets)
        end

        targeting = slices.map { |slice| slice.dig("metadata", "name") }.to_set
        not_targeting = all_slices_for_pool.reject { |slice| targeting.include?(slice.dig("metadata", "name")) }
        reason = counter_consumption_error(counter_sets, not_targeting)
        return invalid.call(reason) if reason

        Pool.new(driver: driver, pool: pool_name, slices_targeting_node: device_slices, slices_not_targeting_node: not_targeting,
                 counter_sets: counter_sets)
      end

      # validateDeviceCounterConsumption.
      def counter_consumption_error(counter_sets, slices)
        slices.each do |slice|
          Array(slice.dig("spec", "devices")).each do |device|
            Array(device["consumesCounters"]).each do |consumption|
              counter_set = counter_sets[consumption["counterSet"]]
              return "counter set #{consumption["counterSet"]} not found" unless counter_set

              (consumption["counters"] || {}).each_key do |name|
                unless (counter_set["counters"] || {}).key?(name)
                  return "counter #{name} not found in counter set #{counter_set["name"]}"
                end
              end
            end
          end
        end
        nil
      end

      def binding_conditions?(pool)
        Array(pool.slices_targeting_node).any? do |slice|
          Array(slice.dig("spec", "devices")).any? { |device| !device["bindingConditions"].nil? }
        end
      end

      # checkSlicesInPool: [obsolete, slices of +generation+].
      def slices_in_pool(slices, driver, pool_name, generation)
        found = []
        Array(slices).each do |slice|
          spec = slice["spec"] || {}
          next unless spec["driver"] == driver && spec.dig("pool", "name") == pool_name

          current = spec.dig("pool", "generation").to_i
          return [true, nil] if current > generation

          found << slice if current == generation
        end
        [false, found]
      end

      # --------------------------------------------------------- the search

      # NewAllocator + Allocate.
      def allocate(node:, claims:, slices:, classes:, allocated_state: AllocatedState.empty, features: Features.defaults,
                   cel: nil, share_id: -> { SecureRandom.uuid })
        Search.new(node: node, claims: claims, slices: slices, classes: classes, allocated_state: allocated_state,
                   features: features, cel: cel || CEL.new(consumable_capacity: features.consumable_capacity),
                   share_id: share_id).run
      end

      RequestKey = Data.define(:claim_index, :request_index, :sub_request_index)

      # requestAccessor over a request's "exactly" or one subrequest.
      class RequestAccessor
        attr_reader :raw, :sub

        def initialize(raw, sub:)
          @raw = raw
          @sub = sub
          @spec = sub ? raw : (raw["exactly"] || {})
        end

        def name = @raw["name"].to_s
        def device_class_name = @spec["deviceClassName"].to_s
        def allocation_mode = @spec["allocationMode"].to_s
        def count = @spec["count"].to_i
        def admin_access? = !@sub && @spec["adminAccess"] == true
        def admin_access_set? = !@sub && !@spec["adminAccess"].nil?
        def selectors = Array(@spec["selectors"])
        def tolerations = @spec["tolerations"]
        def capacities = @spec["capacity"]
      end

      RequestData = Struct.new(:request, :parent_request, :klass, :num_devices, :selected_sub_request_index, :all_devices,
                               keyword_init: true) do
        def request_name
          parent_request ? "#{parent_request.name}/#{request.name}" : request.name
        end
      end

      DeviceWithID = Struct.new(:device, :id, :slice, :pool, keyword_init: true)

      DeviceResult = Struct.new(:device, :request, :parent_request, :id, :share_id, :slice, :consumed_capacity, :admin_access,
                                keyword_init: true) do
        def request_name = parent_request.to_s.empty? ? request : "#{parent_request}/#{request}"
      end

      class Stop < StandardError; end
      class MaxSizeExceeded < StandardError; end

      class Search
        def initialize(node:, claims:, slices:, classes:, allocated_state:, features:, cel:, share_id:)
          @node = node || {}
          @claims = Array(claims)
          @features = features
          @allocated = allocated_state
          @classes = Array(classes).to_h { |klass| [klass.dig("metadata", "name").to_s, klass] }
          @cel = cel
          @share_id = share_id
          @all_slices = Array(slices)
          node_name = @node.dig("metadata", "name").to_s
          @slices_for_node = @all_slices.select do |slice|
            name = slice.dig("spec", "nodeName").to_s
            !name.empty? && Array(slice.dig("spec", "sharedCounters")).empty? && name == node_name
          end + @all_slices.select do |slice|
            slice.dig("spec", "nodeName").to_s.empty? || !Array(slice.dig("spec", "sharedCounters")).empty?
          end
          @matches = {}
          @constraints = []
          @consumed_counters = {}
          @available_counters = {}
          @request_data = {}
          @allocating_devices = Hash.new { |hash, key| hash[key] = Set.new }
          @allocating_capacity = {}
          @result = Array.new(@claims.length) { [] }
        end

        def run
          @pools = Allocator.gather_pools(@slices_for_node, @node, @features, @all_slices)
          min_devices_total = 0
          @claims.each_with_index do |claim, claim_index|
            min_per_claim = 0
            Array(claim.dig("spec", "devices", "requests")).each_with_index do |request, request_index|
              sub_requests = Array(request["firstAvailable"])
              if !@features.prioritized_list && !sub_requests.empty?
                raise Error, "claim #{ref(claim)}, request #{request["name"]}: has subrequests, but the DRAPrioritizedList feature is disabled"
              end
              unless @features.consumable_capacity
                if request.dig("exactly", "capacity")
                  raise Error, "claim #{ref(claim)}, request #{request["name"]}: has capacity requests, but the DRAConsumableCapacity feature is disabled"
                end
                sub_requests.each do |sub|
                  next unless sub["capacity"]

                  raise Error, "claim #{ref(claim)}, subrequest #{sub["name"]}: has capacity requests, but the DRAConsumableCapacity feature is disabled"
                end
              end
              if sub_requests.empty?
                data = validate_request(RequestAccessor.new(request, sub: false), nil,
                                        RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: 0))
                @request_data[RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: 0)] = data
                min_per_claim += data.num_devices
              else
                min = Float::INFINITY
                sub_requests.each_with_index do |sub, sub_index|
                  key = RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: sub_index)
                  data = validate_request(RequestAccessor.new(sub, sub: true), RequestAccessor.new(request, sub: false), key)
                  @request_data[key] = data
                  min = data.num_devices if data.num_devices < min
                end
                min_per_claim += min
              end
            end
            if min_per_claim > ALLOCATION_RESULTS_MAX_SIZE
              raise Error, "claim #{ref(claim)}: number of requested devices #{min_per_claim} exceeds the claim limit of #{ALLOCATION_RESULTS_MAX_SIZE}"
            end

            @constraints[claim_index] = Array(claim.dig("spec", "devices", "constraints")).each_with_index.map do |constraint, index|
              if constraint["matchAttribute"]
                MatchAttributeConstraint.new(constraint["requests"], constraint["matchAttribute"].to_s)
              elsif constraint["distinctAttribute"]
                DistinctAttributeConstraint.new(constraint["requests"], constraint["distinctAttribute"].to_s)
              else
                raise Error, "claim #{ref(claim)}, constraint ##{index}: empty constraint (unsupported constraint type?)"
              end
            end
            min_devices_total += min_per_claim
          end
          @matches = {}

          done = begin
            allocate_one(0, 0, 0, 0, false, [0, 0, 0])
          rescue Stop
            return nil
          rescue MaxSizeExceeded
            raise Error, "allocation max size exceeded"
          end
          unless done
            if @pools.any?(&:invalid)
              raise FailedOnNode, "invalid resource pools were encountered"
            end

            return nil
          end
          @claims.each_with_index.map { |claim, claim_index| allocation_result(claim, claim_index) }
        end

        private

        def ref(claim)
          namespace = claim.dig("metadata", "namespace").to_s
          name = claim.dig("metadata", "name").to_s
          namespace.empty? ? name : "#{namespace}/#{name}"
        end

        # validateDeviceRequest.
        def validate_request(request, parent, key)
          claim = @claims[key.claim_index]
          data = RequestData.new(request: request, parent_request: parent, num_devices: 0, selected_sub_request_index: 0)
          request.selectors.each_with_index do |selector, index|
            next if selector.is_a?(Hash) && selector["cel"]

            raise Error, "claim #{ref(claim)}, request #{request.name}, selector ##{index}: CEL expression empty (unsupported selector type?)"
          end
          if !@features.admin_access && request.admin_access_set?
            raise Error, "claim #{ref(claim)}, request #{request.name}: admin access is requested, but the feature is disabled"
          end
          if request.device_class_name.empty?
            raise Error, "claim #{ref(claim)}, request #{request.name}: missing device class name (unsupported request type?)"
          end

          klass = @classes[request.device_class_name]
          unless klass
            raise Error, "claim #{ref(claim)}, request #{request.name}: could not retrieve device class #{request.device_class_name}: " \
                         "deviceclass.resource.k8s.io \"#{request.device_class_name}\" not found"
          end
          data.klass = klass
          case request.allocation_mode
          when "ExactCount"
            data.num_devices = request.count
          when "All"
            data.all_devices = []
            @pools.each do |pool|
              if pool.incomplete
                raise Error, "claim #{ref(claim)}, request #{request.name}: asks for all devices, but resource pool #{pool.id} is currently being updated"
              end
              if pool.invalid
                raise Error, "claim #{ref(claim)}, request #{request.name}: asks for all devices, but resource pool #{pool.id} is currently invalid"
              end

              pool.slices_targeting_node.each do |slice|
                Array(slice.dig("spec", "devices")).each_index do |device_index|
                  next unless selectable?(key, data, slice, device_index)

                  device = slice.dig("spec", "devices", device_index)
                  next if @features.consumable_capacity && !capacity_fits?(data.request, slice, device)

                  data.all_devices << DeviceWithID.new(device: device, id: device_id(slice, device), slice: slice, pool: pool)
                end
              end
            end
            data.num_devices = data.all_devices.length
          else
            raise Error, "claim #{ref(claim)}, request #{request.name}: unsupported count mode #{request.allocation_mode}"
          end
          data
        end

        def device_id(slice, device)
          DeviceID.new(driver: slice.dig("spec", "driver").to_s, pool: slice.dig("spec", "pool", "name").to_s, device: device["name"].to_s)
        end

        # allocateOne: depth-first over claim, request, subrequest, device.
        def allocate_one(claim_index, request_index, sub_request_index, device_index, allocate_sub_request, start)
          return true if claim_index >= @claims.length

          claim = @claims[claim_index]
          requests = Array(claim.dig("spec", "devices", "requests"))
          if request_index >= requests.length
            begin
              return allocate_one(claim_index + 1, 0, 0, 0, false, [0, 0, 0])
            rescue MaxSizeExceeded
              return false
            end
          end

          key = RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: sub_request_index)
          data = @request_data[key]
          if !allocate_sub_request && data.parent_request
            all_exceeded = true
            sub = 0
            loop do
              sub_key = RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: sub)
              unless @request_data.key?(sub_key)
                raise MaxSizeExceeded if all_exceeded

                return false
              end
              begin
                success = allocate_one(claim_index, request_index, sub, device_index, true, [0, 0, 0])
              rescue MaxSizeExceeded
                sub += 1
                next
              end
              all_exceeded = false
              if success
                parent_key = RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: sub_request_index)
                @request_data[parent_key].selected_sub_request_index = sub
                return true
              end
              sub += 1
            end
          end

          request = data.request
          all_mode = request.allocation_mode == "All"
          return false if all_mode && data.all_devices.empty?
          if device_index >= data.num_devices
            return allocate_one(claim_index, request_index + 1, 0, 0, false, [0, 0, 0])
          end

          after = @result[claim_index].length + data.num_devices - device_index
          raise MaxSizeExceeded if after > ALLOCATION_RESULTS_MAX_SIZE

          if all_mode
            device = data.all_devices[device_index]
            success, deallocate = allocate_device(claim_index, request_index, sub_request_index, device, true)
            return false unless success

            done = false
            begin
              done = allocate_one(claim_index, request_index, sub_request_index, device_index + 1, allocate_sub_request, [0, 0, 0])
            ensure
              deallocate.call unless done
            end
            return done
          end

          (start[0]...@pools.length).each do |pool_index|
            pool = @pools[pool_index]
            next if pool.incomplete || pool.invalid

            slice_start = pool_index == start[0] ? start[1] : 0
            (slice_start...pool.slices_targeting_node.length).each do |slice_index|
              slice = pool.slices_targeting_node[slice_index]
              devices = Array(slice.dig("spec", "devices"))
              device_start = pool_index == start[0] && slice_index == start[1] ? start[2] : 0
              (device_start...devices.length).each do |index|
                device = devices[index]
                id = DeviceID.new(driver: pool.driver, pool: pool.pool, device: device["name"].to_s)
                next if request.admin_access? && @allocating_devices[id].include?(claim_index)
                next if !request.admin_access? && device_in_use?(id)
                next unless selectable?(key, data, slice, index)
                next if @features.consumable_capacity && !capacity_fits?(data.request, slice, device)

                allocated, deallocate = allocate_device(claim_index, request_index, sub_request_index,
                                                        DeviceWithID.new(device: device, id: id, slice: slice, pool: pool), false)
                next unless allocated

                done = false
                begin
                  done = allocate_one(claim_index, request_index, sub_request_index, device_index + 1, allocate_sub_request,
                                      [pool_index, slice_index, index + 1])
                ensure
                  deallocate.call unless done
                end
                return true if done
              end
            end
          end
          false
        end

        # isSelectable (memoized per device and request).
        def selectable?(key, data, slice, device_index)
          device = slice.dig("spec", "devices", device_index)
          return false if !@features.device_binding_and_status && !Array(device["bindingConditions"]).empty?

          id = device_id(slice, device)
          memo = [id, key]
          return @matches[memo] if @matches.key?(memo)

          if data.klass && !selectors_match?(key, device, id, data.klass, Array(data.klass.dig("spec", "selectors")))
            return @matches[memo] = false
          end
          return @matches[memo] = false unless selectors_match?(key, device, id, nil, data.request.selectors)

          if slice.dig("spec", "perDeviceNodeSelection") == true &&
             !Allocator.node_matches?(@node, device["nodeName"], device["allNodes"] == true, device["nodeSelector"])
            return @matches[memo] = false
          end
          @matches[memo] = true
        end

        def selectors_match?(key, device, id, klass, selectors)
          selectors.each_with_index do |selector, index|
            owner = klass ? "class #{klass.dig("metadata", "name")}" : "claim #{ref(@claims[key.claim_index])}"
            compiled = @cel.get_or_compile(selector.dig("cel", "expression").to_s)
            raise Error, "#{owner}: selector ##{index}: CEL compile error: #{compiled.error}" if compiled.error?

            begin
              matches = @cel.device_matches(compiled, driver: id.driver, attributes: device["attributes"], capacity: device["capacity"],
                                                      allow_multiple_allocations: device["allowMultipleAllocations"])
            rescue CEL::Error => error
              raise Error, "#{owner}: selector ##{index}: CEL runtime error: #{error.message}"
            end
            return false unless matches
          end
          true
        end

        # allocator.CmpRequestOverCapacity; a request for a capacity the
        # device does not have is an error, which the callers treat as a
        # device that does not fit.
        def capacity_fits?(request, slice, device)
          id = device_id(slice, device)
          current = @allocated.aggregated_capacity[id] || {}
          Capacity.request_fits?(current, request.capacities, device["allowMultipleAllocations"], device["capacity"] || {},
                                 @allocating_capacity[id] || {})
        rescue Capacity::Undefined
          false
        end

        def device_in_use?(id)
          @allocated.allocated_devices.include?(id) || !@allocating_devices[id].empty?
        end

        def capacity_in_use?(id)
          @allocated.aggregated_capacity.key?(id) || @allocating_capacity.key?(id)
        end

        # allocateDevice: [allocated, deallocate].
        def allocate_device(claim_index, request_index, sub_request_index, device, must)
          claim = @claims[claim_index]
          key = RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: sub_request_index)
          data = @request_data[key]
          request = data.request
          multiple = @features.consumable_capacity && device.device["allowMultipleAllocations"] == true
          return [false, nil] if !multiple && request.admin_access? && @allocating_devices[device.id].include?(claim_index)
          return [false, nil] if !request.admin_access? && device_in_use?(device.id)

          consumes = Array(device.device["consumesCounters"])
          return [false, nil] if !@features.partitionable_devices && !consumes.empty?

          skip_counters = multiple && capacity_in_use?(device.id)
          if !skip_counters && !consumes.empty?
            return [false, nil] unless available_counters?(device)
          end

          if data.parent_request
            base_name = data.parent_request.name
            sub_name = request.name
            parent_name = base_name
          else
            base_name = request.name
            sub_name = ""
            parent_name = ""
          end
          return [false, nil] if @features.device_taints && Allocator.taint_prevents?(device.device, request)

          constraints = @constraints[claim_index]
          constraints.each_with_index do |constraint, index|
            next if constraint.add(base_name, sub_name, device.device, device.id)

            if must
              raise Error, "claim #{ref(claim)}, request #{request.name}: cannot add device #{device.id} because a claim constraint would not be satisfied"
            end

            (0...index).each { |earlier| constraints[earlier].remove(base_name, sub_name, device.device, device.id) }
            return [false, nil]
          end

          @allocating_devices[device.id] << claim_index unless multiple
          consumed = {}
          share_id = nil
          if @features.consumable_capacity
            # Upstream returns here without undoing the constraints and the
            # allocating mark; kept as is.
            return [false, nil] unless capacity_fits?(request, device.slice, device.device)

            if multiple
              consumed = Capacity.consumed_from_request(request.capacities, device.device["capacity"] || {})
              share_id = @share_id.call
              Allocator.insert_capacity(@allocating_capacity, device.id, consumed)
            end
          end
          result = DeviceResult.new(device: device.device, request: request.name, parent_request: parent_name, id: device.id,
                                    share_id: share_id, slice: device.slice, admin_access: request.admin_access? ? true : nil,
                                    consumed_capacity: consumed.empty? ? nil : consumed)
          previous = @result[claim_index].length
          @result[claim_index] << result
          deallocate = lambda do
            constraints.each { |constraint| constraint.remove(base_name, sub_name, device.device, device.id) }
            @allocating_devices[device.id].delete(claim_index)
            if multiple
              requested = @result[claim_index][previous].consumed_capacity
              Allocator.remove_capacity(@allocating_capacity, device.id, requested) if requested
            elsif @features.partitionable_devices && !consumes.empty?
              deallocate_counters(device)
            end
            @result[claim_index] = @result[claim_index][0...previous]
          end
          [true, deallocate]
        end

        # checkAvailableCounters.
        def available_counters?(device)
          pool = device.pool
          pool_name = pool.pool
          available = (@available_counters[pool_name] ||= begin
            counters = pool.counter_sets.to_h do |name, counter_set|
              [name, (counter_set["counters"] || {}).to_h { |counter, entry| [counter, Quantity.from_json(entry["value"])] }]
            end
            [pool.slices_targeting_node, pool.slices_not_targeting_node].each do |slices|
              Array(slices).each do |slice|
                Array(slice.dig("spec", "devices")).each do |candidate|
                  next unless allocated?(device_id(slice, candidate))

                  Array(candidate["consumesCounters"]).each do |consumption|
                    set = counters[consumption["counterSet"]]
                    (consumption["counters"] || {}).each do |counter, entry|
                      next unless set&.key?(counter)

                      set[counter] = Allocator.sub(set[counter], Quantity.from_json(entry["value"]))
                    end
                  end
                end
              end
            end
            counters
          end)
          consumed = (@consumed_counters[pool_name] ||= {})
          Array(device.device["consumesCounters"]).each do |consumption|
            set = (consumed[consumption["counterSet"]] ||= {})
            (consumption["counters"] || {}).each do |counter, entry|
              set[counter] = Allocator.add(set[counter], Quantity.from_json(entry["value"]))
            end
          end
          available.each do |set_name, counters|
            counters.each do |counter, quantity|
              used = consumed.dig(set_name, counter)
              next if used.nil? || quantity.value >= used.value

              deallocate_counters(device)
              return false
            end
          end
          true
        end

        def allocated?(id)
          @allocated.allocated_devices.include?(id) ||
            @allocated.allocated_shared_device_ids.any? { |shared| shared.device_id == id } ||
            @allocated.aggregated_capacity.key?(id)
        end

        def deallocate_counters(device)
          consumed = @consumed_counters[device.pool.pool] || {}
          Array(device.device["consumesCounters"]).each do |consumption|
            set = consumed[consumption["counterSet"]] || {}
            (consumption["counters"] || {}).each do |counter, entry|
              current = set[counter]
              quantity = Quantity.from_json(entry["value"])
              set[counter] = current ? Allocator.sub(current, quantity) : Quantity.new(-quantity.value, quantity.format)
            end
          end
        end

        # The AllocationResult for one claim.
        def allocation_result(claim, claim_index)
          results = @result[claim_index].map do |entry|
            request = lookup_request(claim, entry)
            value = {"request" => entry.request_name, "driver" => entry.id.driver, "pool" => entry.id.pool, "device" => entry.id.device}
            value["adminAccess"] = entry.admin_access unless entry.admin_access.nil?
            tolerations = request&.tolerations
            value["tolerations"] = tolerations if tolerations && !tolerations.empty?
            if @features.device_binding_and_status
              value["bindingConditions"] = entry.device["bindingConditions"] if entry.device["bindingConditions"] && !entry.device["bindingConditions"].empty?
              if entry.device["bindingFailureConditions"] && !entry.device["bindingFailureConditions"].empty?
                value["bindingFailureConditions"] = entry.device["bindingFailureConditions"]
              end
            end
            value["shareID"] = entry.share_id if entry.share_id
            value["consumedCapacity"] = entry.consumed_capacity.transform_values(&:canonical) if entry.consumed_capacity
            value
          end
          configs = []
          class_ranges = {}
          requests = Array(claim.dig("spec", "devices", "requests"))
          requests.each_index do |request_index|
            data = @request_data[RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: 0)]
            if data.parent_request
              data = @request_data[RequestKey.new(claim_index: claim_index, request_index: request_index,
                                                  sub_request_index: data.selected_sub_request_index)]
            end
            klass = data.klass
            next unless klass

            class_name = klass.dig("metadata", "name").to_s
            if (range = class_ranges[class_name])
              (range[0]...range[1]).each { |index| configs[index]["requests"] << data.request_name }
              next
            end
            first = configs.length
            Array(klass.dig("spec", "config")).each do |config|
              configs << {"source" => "FromClass", "requests" => [data.request_name]}.merge(config.reject { |key, _| key == "requests" })
            end
            class_ranges[class_name] = [first, configs.length]
          end
          Array(claim.dig("spec", "devices", "config")).each do |config|
            names = Array(config["requests"])
            body = config.reject { |key, _| key == "requests" }
            if names.empty?
              configs << {"source" => "FromClaim"}.merge(body)
              next
            end
            requests.each_with_index do |request, request_index|
              if names.include?(request["name"])
                configs << {"source" => "FromClaim", "requests" => names}.merge(body)
                next
              end
              data = @request_data[RequestKey.new(claim_index: claim_index, request_index: request_index, sub_request_index: 0)]
              next unless data.parent_request

              sub = Array(request["firstAvailable"])[data.selected_sub_request_index] || {}
              configs << {"source" => "FromClaim", "requests" => names}.merge(body) if names.include?("#{request["name"]}/#{sub["name"]}")
            end
          end
          devices = {}
          devices["results"] = results unless results.empty?
          devices["config"] = configs unless configs.empty?
          allocation = {"devices" => devices}
          selector = node_selector(@result[claim_index])
          allocation["nodeSelector"] = selector if selector
          allocation
        end

        def lookup_request(claim, entry)
          name = entry.parent_request.to_s.empty? ? entry.request : entry.parent_request
          request = Array(claim.dig("spec", "devices", "requests")).find { |candidate| candidate["name"] == name }
          return nil unless request
          return RequestAccessor.new(request, sub: false) if entry.parent_request.to_s.empty?

          sub = Array(request["firstAvailable"]).find { |candidate| candidate["name"] == entry.request }
          sub && RequestAccessor.new(sub, sub: true)
        end

        # createNodeSelector.
        def node_selector(results)
          node_name = @node.dig("metadata", "name").to_s
          fields = []
          expressions = []
          results.each do |entry|
            spec = entry.slice["spec"] || {}
            if spec["perDeviceNodeSelection"] == true
              name = entry.device["nodeName"]
              selector = entry.device["nodeSelector"]
            else
              name = spec["nodeName"]
              selector = spec["nodeSelector"]
            end
            if !name.nil? || entry.device["bindsToNode"] == true
              return {"nodeSelectorTerms" => [{"matchFields" => [{"key" => "metadata.name", "operator" => "In", "values" => [node_name]}]}]}
            end
            next unless selector

            terms = Array(selector["nodeSelectorTerms"])
            case terms.length
            when 0 then next
            when 1
              add_requirements(Array(terms[0]["matchFields"]), fields)
              add_requirements(Array(terms[0]["matchExpressions"]), expressions)
            else
              raise Error, "create NodeSelector for claim: unsupported ResourceSlice.NodeSelector with #{terms.length} terms"
            end
          end
          return nil if fields.empty? && expressions.empty?

          term = {}
          term["matchExpressions"] = expressions unless expressions.empty?
          term["matchFields"] = fields unless fields.empty?
          {"nodeSelectorTerms" => [term]}
        end

        def add_requirements(from, to)
          from.each do |requirement|
            values = Array(requirement["values"]).to_set
            duplicate = to.any? do |existing|
              existing["key"] == requirement["key"] && existing["operator"] == requirement["operator"] &&
                Array(existing["values"]).to_set == values
            end
            to << requirement unless duplicate
          end
        end
      end

      # taintPreventsAllocation.
      def taint_prevents?(device, request)
        Array(device["taints"]).any? do |taint|
          next false unless %w[NoExecute NoSchedule].include?(taint["effect"].to_s)

          Array(request.tolerations).none? { |toleration| tolerates?(toleration, taint) }
        end
      end

      # resourceclaim.ToleratesTaint.
      def tolerates?(toleration, taint)
        return false if !toleration["effect"].to_s.empty? && toleration["effect"] != taint["effect"]
        return false if !toleration["key"].to_s.empty? && toleration["key"] != taint["key"]

        case toleration["operator"].to_s
        when "", "Equal" then toleration["value"].to_s == taint["value"].to_s
        when "Exists" then true
        else false
        end
      end

      # matchAttributeConstraint.
      class MatchAttributeConstraint
        def initialize(requests, attribute)
          @requests = Array(requests).to_set
          @attribute_name = attribute
          @attribute = nil
          @count = 0
        end

        def add(request_name, sub_request_name, device, device_id)
          return true if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          attribute = Allocator.lookup_attribute(device, device_id, @attribute_name)
          return false if attribute.nil?

          if @count.zero?
            @attribute = attribute
            @count = 1
            return true
          end
          type = Allocator.attribute_type(attribute)
          return false if type.nil?
          return false unless @attribute.key?(type) && @attribute[type] == attribute[type]

          @count += 1
          true
        end

        def remove(request_name, sub_request_name, _device, _device_id)
          return if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          @count -= 1
        end
      end

      # distinctAttributeConstraint.
      class DistinctAttributeConstraint
        def initialize(requests, attribute)
          @requests = Array(requests).to_set
          @attribute_name = attribute
          @attributes = {}
          @count = 0
        end

        def add(request_name, sub_request_name, device, device_id)
          return true if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          attribute = Allocator.lookup_attribute(device, device_id, @attribute_name)
          return false if attribute.nil?

          if @count.zero?
            @attributes[request_name] = attribute
            @count = 1
            return true
          end
          return false unless distinct?(attribute)

          @attributes[request_name] = attribute
          @count += 1
          true
        end

        def remove(request_name, sub_request_name, _device, _device_id)
          return if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          @attributes.delete(request_name)
          @count -= 1
        end

        private

        def distinct?(attribute)
          type = Allocator.attribute_type(attribute)
          @attributes.each_value do |existing|
            return false if type.nil?
            return false if existing.key?(type) && existing[type] == attribute[type]
          end
          true
        end
      end

      def constraint_applies?(requests, request_name, sub_request_name)
        return requests.include?(request_name) if sub_request_name.to_s.empty?

        requests.include?(request_name) || requests.include?("#{request_name}/#{sub_request_name}")
      end

      # The one value field of an attribute (string / int / bool / version).
      def attribute_type(attribute)
        %w[string int bool version].find { |type| attribute.key?(type) && !attribute[type].nil? }
      end

      # lookupAttribute: the fully qualified name, or the bare name when the
      # domain is the device's driver.
      def lookup_attribute(device, device_id, name)
        attributes = device["attributes"] || {}
        return attributes[name] if attributes.key?(name)

        index = name.index("/")
        return nil if index.nil? || name[0...index] != device_id.driver

        attributes[name[(index + 1)..]]
      end

      # consumable_capacity.go.
      module Capacity
        class Undefined < StandardError; end

        Quantity = Schema::Quantity

        module_function

        # CmpRequestOverCapacity.
        def request_fits?(current, requirements, _allow_multiple, capacity, allocating)
          requests = requirements.is_a?(Hash) ? (requirements["requests"] || {}) : {}
          raise Undefined, "some requested capacity has not been defined" if requests.keys.any? { |name| !capacity.key?(name) }

          clone = current.dup
          capacity.each do |name, entry|
            requested = requests.key?(name) ? Quantity.from_json(requests[name]) : nil
            consumed = consumed_capacity(requested, entry)
            return false if violates_policy?(consumed, entry["requestPolicy"])

            clone[name] = Allocator.add(clone[name], consumed)
            clone[name] = Allocator.add(clone[name], allocating[name]) if allocating.key?(name)
            return false if clone[name].value > Quantity.from_json(entry["value"]).value
          end
          true
        end

        # GetConsumedCapacityFromRequest.
        def consumed_from_request(requirements, capacity)
          requests = requirements.is_a?(Hash) ? (requirements["requests"] || {}) : {}
          capacity.to_h do |name, entry|
            requested = requests.key?(name) ? Quantity.from_json(requests[name]) : nil
            [name, consumed_capacity(requested, entry)]
          end
        end

        # calculateConsumedCapacity.
        def consumed_capacity(requested, capacity)
          policy = capacity["requestPolicy"]
          if requested.nil?
            return Quantity.from_json(policy["default"]) if policy && policy["default"]

            return Quantity.from_json(capacity["value"])
          end
          return requested if policy.nil?

          range = policy["validRange"]
          if range && range["min"]
            return round_up_range(requested, range)
          elsif policy["validValues"]
            return round_up_valid_values(requested, policy["validValues"])
          end
          requested
        end

        def round_up_range(requested, range)
          min = Quantity.from_json(range["min"])
          return min if requested.value < min.value
          return requested if range["step"].nil?

          value = go_value(requested)
          step = go_value(Quantity.from_json(range["step"]))
          minimum = go_value(min)
          added = value - minimum
          n = go_div(added, step)
          n += 1 unless go_mod(added, step).zero?
          Quantity.new(Rational(minimum + step * n), :binary_si)
        end

        def round_up_valid_values(requested, values)
          values.each do |candidate|
            quantity = Quantity.from_json(candidate)
            return quantity if requested.value <= quantity.value
          end
          requested
        end

        # violatesPolicy.
        def violates_policy?(requested, policy)
          return false if policy.nil?
          return false if policy["default"] && go_equal?(requested, Quantity.from_json(policy["default"]))

          range = policy["validRange"]
          if range
            return true if range["max"] && requested.value > Quantity.from_json(range["max"]).value
            if range["step"]
              added = go_value(requested) - go_value(Quantity.from_json(range["min"]))
              return true unless go_mod(added, go_value(Quantity.from_json(range["step"]))).zero?
            end
            return false
          end
          values = Array(policy["validValues"])
          return false if values.empty?

          values.none? { |candidate| requested.value == Quantity.from_json(candidate).value }
        end

        # Quantity.Value(): rounded up to an integer.
        def go_value(quantity) = quantity.value.ceil

        # Go integer division and remainder truncate towards zero.
        def go_div(left, right) = (left.fdiv(right)).truncate
        def go_mod(left, right) = left - right * go_div(left, right)

        # Go struct equality of two Quantities: same value, same format and
        # the same cached string (set only when parsed in canonical form).
        def go_equal?(left, right)
          left.value == right.value && left.format == right.format && cached_string(left) == cached_string(right)
        end

        def cached_string(quantity)
          text = quantity.to_s
          text == quantity.canonical ? text : nil
        end
      end
    end
  end
end
