# frozen_string_literal: true

require "base64"
require "fileutils"
require "json"
require "set"
require "zlib"
require_relative "broker"

module Rubernetes
  module Node
    module DevicePlugins
      # pkg/kubelet/cm/devicemanager: device plugins register on
      # <directory>/kubelet.sock, their ListAndWatch devices become the Node's
      # capacity (every device) and allocatable (the healthy ones), and a
      # container that requests the resource gets devices picked as
      # devicesToAllocate picks them (its earlier allocation, devices an init
      # container left, then the plugin's GetPreferredAllocation, then any
      # healthy free one), then Allocate's environment, mounts, device nodes,
      # annotations and CDI devices.  Allocations survive restarts in
      # kubelet_internal_checkpoint (upstream's layout; the checksum is our own
      # CRC32 of the data, and AllocResp holds the response as JSON).  A plugin
      # whose stream ends has its devices marked unhealthy; after
      # endpointStopGracePeriod the resource is dropped.  Health goes to
      # containerStatuses[].allocatedResourcesStatus (ResourceHealthStatus).
      class Manager
        class Error < StandardError; end

        CHECKPOINT = "kubelet_internal_checkpoint"
        STOP_GRACE_PERIOD = 5 * 60
        HEALTHY = "Healthy"

        Endpoint = Struct.new(:name, :options, :stopped_at, keyword_init: true)

        def initialize(directory:, checkpoint_directory: directory, broker: nil, on_change: nil,
                       clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @directory = directory
          @checkpoint_path = File.join(checkpoint_directory, CHECKPOINT)
          @on_change = on_change
          @clock = clock
          @mutex = Mutex.new
          @endpoints = {}
          @endpoint_names = {}
          @devices = Hash.new { |hash, key| hash[key] = {} }
          @allocations = {} # [pod_uid, container, resource] => {"devices" => [...], "response" => {...}}
          @broker = broker || Broker.new(directory: directory, on_event: method(:handle_event))
          restore
        end

        attr_accessor :on_change

        def start
          FileUtils.mkdir_p(@directory)
          @broker.start
          self
        end

        def stop
          @broker.stop
          self
        end

        def resource?(name) = @mutex.synchronize { @endpoints.key?(name.to_s) || @devices.key?(name.to_s) }

        def resource_names = @mutex.synchronize { (@endpoints.keys | @devices.keys).sort }

        # GetCapacity: [capacity, allocatable] as integer counts per resource;
        # resources whose plugin stopped longer ago than the grace period go.
        def capacity
          now = @clock.call
          dropped = false
          result = @mutex.synchronize do
            @endpoints.each_value do |endpoint|
              next unless endpoint.stopped_at && now - endpoint.stopped_at > STOP_GRACE_PERIOD

              @endpoints.delete(endpoint.name)
              @devices.delete(endpoint.name)
              dropped = true
            end
            capacity = {}
            allocatable = {}
            @devices.each do |resource, devices|
              capacity[resource] = devices.length
              allocatable[resource] = devices.count { |_, device| device["health"] == HEALTHY }
            end
            [capacity, allocatable]
          end
          persist if dropped
          result
        end

        # The kubelet registry for kubelet_device_plugin_*.
        attr_writer :metrics

        def metric(kind, name, labels, value = nil)
          return unless @metrics

          kind == :observe ? @metrics.observe(name, value, labels) : @metrics.increment(name, labels)
        rescue StandardError
          nil
        end

        def handle_event(event)
          resource = event["resource"].to_s
          case event["event"]
          when "register_request"
            metric(:increment, "kubelet_device_plugin_registration_total", {"resource_name" => resource})
          when "registered"
            @mutex.synchronize do
              @endpoints[resource] = Endpoint.new(name: resource, options: event["options"] || {}, stopped_at: nil)
              @endpoint_names[resource] = event["endpoint"]
            end
          when "devices"
            @mutex.synchronize do
              @devices[resource] = Array(event["devices"]).to_h do |device|
                [device["ID"] || device["id"], {"health" => device["health"].to_s, "topology" => device["topology"]}]
              end
            end
            persist
          when "disconnected"
            @mutex.synchronize do
              endpoint = @endpoints[resource]
              next unless endpoint

              endpoint.stopped_at = @clock.call
              @devices[resource].each_value { |device| device["health"] = "Unhealthy" }
            end
          else
            return
          end
          @on_change&.call
        end

        # Allocate at admission: every container of the Pod, init containers
        # first (their devices go back to the pool for the app containers).
        # Raises Error with upstream's message when a request cannot be met.
        def allocate_pod(pod)
          uid = pod.dig("metadata", "uid").to_s
          reusable = Hash.new { |hash, key| hash[key] = Set.new }
          Array(pod.dig("spec", "initContainers")).each do |container|
            allocate_container(uid, container, reusable)
            next if container["restartPolicy"] == "Always"

            device_requests(container).each_key do |resource|
              reusable[resource].merge(Array(@mutex.synchronize { @allocations[[uid, container["name"], resource]] }&.fetch("devices", nil)))
            end
          end
          Array(pod.dig("spec", "containers")).each do |container|
            allocate_container(uid, container, reusable)
            device_requests(container).each_key do |resource|
              reusable[resource].subtract(Array(@mutex.synchronize { @allocations[[uid, container["name"], resource]] }&.fetch("devices", nil)))
            end
          end
          persist
          nil
        end

        # The container's allocation merged the way kubelet applies it:
        # {"envs", "mounts", "devices", "annotations", "cdi_devices"}; nil
        # when it holds no device plugin resource.
        def container_allocation(pod_uid, container_name)
          responses = @mutex.synchronize do
            @allocations.select { |(uid, name, _), _| uid == pod_uid.to_s && name == container_name.to_s }.values.map { |entry| entry["response"] }
          end
          return nil if responses.empty?

          responses.each_with_object({"envs" => {}, "mounts" => [], "devices" => [], "annotations" => {}, "cdi_devices" => []}) do |response, merged|
            merged["envs"].merge!(response["envs"] || {})
            merged["mounts"].concat(Array(response["mounts"]))
            merged["devices"].concat(Array(response["devices"]))
            merged["annotations"].merge!(response["annotations"] || {})
            merged["cdi_devices"].concat(Array(response["cdi_devices"]))
          end
        end

        # ResourceHealthStatus: containerStatuses[].allocatedResourcesStatus.
        def allocated_resources_status(pod_uid, container_name)
          entries = @mutex.synchronize do
            @allocations.select { |(uid, name, _), _| uid == pod_uid.to_s && name == container_name.to_s }
                        .map { |(_, _, resource), entry| [resource, entry["devices"], @devices[resource].dup] }
          end
          entries.sort.map do |resource, ids, devices|
            {"name" => resource, "resources" => ids.sort.map do |id|
              health = devices.dig(id, "health").to_s
              {"resourceID" => id, "health" => %w[Healthy Unhealthy].include?(health) ? health : "Unknown"}
            end}
          end
        end

        # podresources: {resource => device ids} a container holds.
        def container_devices(pod_uid, container_name)
          @mutex.synchronize do
            @allocations.select { |(uid, name, _), _| uid == pod_uid.to_s && name == container_name.to_s }
                        .to_h { |(_, _, resource), entry| [resource, entry["devices"].sort] }
          end
        end

        # podresources GetAllocatableResources: the healthy devices per resource.
        def allocatable_devices
          @mutex.synchronize do
            @devices.to_h { |resource, devices| [resource, devices.select { |_, device| device["health"] == HEALTHY }.keys.sort] }
          end
        end

        # UpdateAllocatedDevices: allocations of Pods no longer active go.
        def remove_stale(active_pod_uids)
          active = active_pod_uids.map(&:to_s).to_set
          removed = @mutex.synchronize do
            before = @allocations.length
            @allocations.select! { |(uid, _, _), _| active.include?(uid) }
            before != @allocations.length
          end
          persist if removed
        end

        private

        def device_requests(container)
          limits = container.dig("resources", "limits") || {}
          limits.each_with_object({}) do |(name, value), result|
            next unless resource?(name)

            count = Integer(value.to_s, exception: false)
            result[name.to_s] = count if count&.positive?
          end
        end

        def allocate_container(uid, container, reusable)
          device_requests(container).each do |resource, required|
            devices = devices_to_allocate(uid, container["name"], resource, required, reusable[resource])
            next if devices.nil?

            endpoint = @mutex.synchronize { @endpoint_names[resource] }
            raise Error, "unknown Device Plugin #{resource}" if endpoint.nil?

            options = @mutex.synchronize { @endpoints[resource]&.options } || {}
            begin
              if options["pre_start_required"]
                @broker.call(endpoint, "PreStartContainer", {"devices_ids" => devices})
              end
              started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              begin
                reply = @broker.call(endpoint, "Allocate", {"container_requests" => [{"devices_ids" => devices}]})
              ensure
                metric(:observe, "kubelet_device_plugin_alloc_duration_seconds", {"resource_name" => resource},
                       Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
              end
            rescue Broker::Error => error
              release(uid, container["name"], resource)
              raise Error, error.message
            end
            response = Array(reply["container_responses"]).first || {}
            @mutex.synchronize { @allocations[[uid, container["name"].to_s, resource]] = {"devices" => devices, "response" => response} }
          end
        end

        # devicesToAllocate (without topology alignment: the node has no NUMA
        # affinity for plugin devices it could honour).
        def devices_to_allocate(uid, container, resource, required, reusable)
          @mutex.synchronize do
            existing = @allocations[[uid, container.to_s, resource]]
            if existing
              count = existing["devices"].length
              raise Error, %(pod "#{uid}" container "#{container}" changed request for resource "#{resource}" from #{count} to #{required}) if count != required
            end
            healthy = @devices.key?(resource) ? @devices[resource].select { |_, device| device["health"] == HEALTHY }.keys.to_set : nil
            raise Error, "cannot allocate unregistered device #{resource}" if healthy.nil? && !@endpoints.key?(resource)
            healthy ||= Set.new
            raise Error, "no healthy devices present; cannot allocate unhealthy devices #{resource}" if healthy.empty?
            if existing && !existing["devices"].to_set.subset?(healthy)
              raise Error, "previously allocated devices are no longer healthy; cannot allocate unhealthy devices #{resource}"
            end
            return nil if existing

            in_use = @allocations.select { |(_, _, name), _| name == resource }.values.flat_map { |entry| entry["devices"] }.to_set
            chosen = (reusable.to_a & healthy.to_a).first(required)
            available = healthy - in_use - chosen.to_set
            needed = required - chosen.length
            if available.length < needed
              raise Error, "requested number of devices unavailable for #{resource}. Requested: #{needed}, Available: #{available.length}"
            end
            [chosen, available, needed]
          end.then do |chosen, available, needed|
            return chosen if needed.zero?

            preferred = preferred_allocation(resource, available.to_a | chosen, chosen, required)
            picked = (preferred & available.to_a).first(needed)
            picked += (available.to_a.sort - picked).first(needed - picked.length)
            chosen + picked
          end
        end

        def preferred_allocation(resource, available, must_include, size)
          options = @mutex.synchronize { @endpoints[resource]&.options } || {}
          return [] unless options["get_preferred_allocation_available"]

          endpoint = @mutex.synchronize { @endpoint_names[resource] }
          reply = @broker.call(endpoint, "GetPreferredAllocation",
                               {"container_requests" => [{"available_deviceIDs" => available.sort, "must_include_deviceIDs" => must_include,
                                                          "allocation_size" => size}]})
          Array(Array(reply["container_responses"]).first&.fetch("deviceIDs", nil))
        rescue Broker::Error => error
          raise Error, error.message
        end

        def release(uid, container, resource)
          @mutex.synchronize { @allocations.delete([uid, container.to_s, resource]) }
        end

        def persist
          data = @mutex.synchronize do
            {"PodDeviceEntries" => @allocations.map do |(uid, container, resource), entry|
              {"PodUID" => uid, "ContainerName" => container, "ResourceName" => resource, "DeviceIDs" => {"-1" => entry["devices"]},
               "AllocResp" => Base64.strict_encode64(JSON.generate(entry["response"]))}
            end,
             "RegisteredDevices" => @devices.transform_values { |devices| devices.keys.sort }}
          end
          FileUtils.mkdir_p(File.dirname(@checkpoint_path))
          temporary = "#{@checkpoint_path}.tmp"
          File.write(temporary, JSON.generate("Data" => data, "Checksum" => Zlib.crc32(JSON.generate(data))))
          File.rename(temporary, @checkpoint_path)
        rescue SystemCallError
          nil
        end

        # Allocations come back; registered devices come back unhealthy until
        # their plugin registers again (kubelet keeps them for the grace period).
        def restore
          return unless File.file?(@checkpoint_path)

          body = JSON.parse(File.read(@checkpoint_path))
          data = body["Data"] || {}
          return unless body["Checksum"].to_i.zero? || body["Checksum"].to_i == Zlib.crc32(JSON.generate(data))

          Array(data["PodDeviceEntries"]).each do |entry|
            devices = (entry["DeviceIDs"] || {}).values.flatten
            response = JSON.parse(Base64.decode64(entry["AllocResp"].to_s)) rescue {}
            @allocations[[entry["PodUID"].to_s, entry["ContainerName"].to_s, entry["ResourceName"].to_s]] = {"devices" => devices, "response" => response}
          end
          (data["RegisteredDevices"] || {}).each do |resource, ids|
            @devices[resource] = Array(ids).to_h { |id| [id, {"health" => "Unhealthy", "topology" => nil}] }
            @endpoints[resource] = Endpoint.new(name: resource, options: {}, stopped_at: @clock.call)
          end
        rescue JSON::ParserError, SystemCallError
          nil
        end
      end
    end
  end
end
