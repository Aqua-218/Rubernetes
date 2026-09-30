# frozen_string_literal: true

require "fileutils"
require "json"

require_relative "plugins/rpc"
require_relative "dra_health"

module Rubernetes
  module Node
    # pkg/kubelet/cm/dra (v1.36.2): the kubelet's DRA manager.
    #
    #   * plugin handler for "DRAPlugin" registrations (v1.DRAPlugin, else
    #     v1beta1.DRAPlugin); when a driver's last plugin goes away its
    #     ResourceSlices for this node are deleted after 30 s unless it comes
    #     back, and at start every slice of this node is deleted (drivers
    #     republish on registration)
    #   * prepare_resources before a Pod's containers start: each claim is
    #     read from the API, must be reserved for the Pod, and is prepared
    #     once per driver with NodePrepareResources; the CDI device IDs are
    #     kept per request
    #   * container_cdi_devices: the CDI devices of the requests a container
    #     names in resources.claims
    #   * unprepare_resources when the Pod is done: NodeUnprepareResources
    #     once no other Pod uses the claim; a reconcile pass (60 s) catches
    #     Pods that went away without it
    #
    # The claim info cache is checkpointed (dra_manager_state) so a restart
    # knows what it prepared; restored claims are prepared again when used
    # (drivers must make NodePrepareResources idempotent).
    #
    # ResourceHealthStatus: with +resource_health+ each plugin's
    # DRAResourceHealth.NodeWatchResources stream feeds a health cache
    # (dra_health_state), and allocated_resources_status reports the health
    # of the devices a container's claims hold.
    class DRAManager
      SERVICES = {"v1.DRAPlugin" => "k8s.io.kubelet.pkg.apis.dra.v1.DRAPlugin",
                  "v1beta1.DRAPlugin" => "k8s.io.kubelet.pkg.apis.dra.v1beta1.DRAPlugin"}.freeze
      WIPING_DELAY = 30.0
      RECONCILE_PERIOD = 60.0
      CALL_TIMEOUT = 45.0
      CHECKPOINT = "dra_manager_state"
      API_VERSION = "resource.k8s.io/v1"

      class Error < StandardError; end

      Plugin = Struct.new(:driver, :endpoint, :service, keyword_init: true)

      # +client+: Client::KubernetesClient (#get and #raw); +active_pods+:
      # -> the Pods on the node that may still run.
      def initialize(client:, node_name:, state_directory:, rpc: Plugins::RPC, active_pods: -> { [] },
                     monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, sleeper: ->(seconds) { sleep(seconds) },
                     error_handler: nil, wiping_delay: WIPING_DELAY, resource_health: false, on_health_change: nil,
                     health_stream: ->(endpoint, on_event) { DRAHealth::Stream.new(endpoint: endpoint, on_event: on_event) },
                     health_clock: -> { Time.now.utc })
        @client = client
        @node_name = node_name.to_s
        @state_directory = state_directory.to_s
        @rpc = rpc
        @active_pods = active_pods
        @monotonic = monotonic
        @sleeper = sleeper
        @error_handler = error_handler
        @wiping_delay = Float(wiping_delay)
        @plugins = Hash.new { |hash, key| hash[key] = [] }
        @pending_wipes = {}
        @claims = {}
        @mutex = Mutex.new
        @threads = []
        @stop = false
        @resource_health = resource_health == true
        @on_health_change = on_health_change
        @health_stream = health_stream
        @health_streams = {}
        @health = DRAHealth::Cache.new(path: @state_directory.empty? ? nil : File.join(@state_directory, DRAHealth::CHECKPOINT),
                                       clock: health_clock)
        load_checkpoint
      end

      # Pod UIDs whose device health changed (the kubelet's update channel).
      attr_accessor :on_health_change
      attr_reader :health

      # The Pods that may still run (the reconcile pass unprepares the rest).
      attr_writer :active_pods

      # ------------------------------------------------ plugin handler

      def validate_plugin(_driver, _endpoint, versions)
        choose_service(versions)
        true
      end

      def register_plugin(driver, endpoint, versions)
        service = choose_service(versions)
        @mutex.synchronize do
          plugins = @plugins[driver.to_s]
          raise Error, "endpoint #{endpoint} already registered for DRA driver plugin #{driver}" if plugins.any? do |plugin|
            plugin.endpoint == endpoint
          end

          plugins << Plugin.new(driver: driver.to_s, endpoint: endpoint.to_s, service: service)
          @pending_wipes.delete(driver.to_s)
        end
        start_health_stream(driver.to_s, endpoint.to_s) if @resource_health
        true
      end

      def deregister_plugin(driver, endpoint)
        @mutex.synchronize do
          plugins = @plugins[driver.to_s]
          plugins.reject! { |plugin| plugin.endpoint == endpoint.to_s }
          if plugins.empty?
            @plugins.delete(driver.to_s)
            @pending_wipes[driver.to_s] = @monotonic.call + @wiping_delay
          end
        end
        stop_health_stream(endpoint.to_s)
        true
      end

      def registered_drivers
        @mutex.synchronize { @plugins.keys.sort }
      end

      # GetPlugin: the most recently registered plugin of +driver+.
      def plugin(driver)
        raise Error, "DRA driver name is empty" if driver.to_s.empty?

        @mutex.synchronize { @plugins[driver.to_s]&.last } || raise(Error, "DRA driver #{driver} is not registered")
      end

      # ------------------------------------------------- pod resources

      # The kubelet registry: dra_operations_duration_seconds,
      # dra_grpc_operations_duration_seconds and the
      # dra_resource_claims_in_use collector.
      def metrics=(registry)
        @metrics = registry
        registry.register("dra_resource_claims_in_use", type: :gauge) unless registry.registered?("dra_resource_claims_in_use")
        registry.add_collector do |target|
          target.reset("dra_resource_claims_in_use")
          claims_in_use.each { |driver, count| target.set("dra_resource_claims_in_use", count, {"driver_name" => driver}) }
        end
      end

      # claimsInUse: prepared claims per driver, and all of them under "<any>".
      def claims_in_use
        @mutex.synchronize do
          counts = Hash.new(0)
          total = 0
          @claims.each_value do |entry|
            next unless entry["prepared"]

            total += 1
            entry["driver_state"].each_key { |driver| counts[driver] += 1 }
          end
          counts["<any>"] = total
          counts
        end
      end

      # PrepareResources.
      def prepare_resources(pod) = dra_operation("PrepareResources") { prepare_pod_resources(pod) }

      def dra_operation(name)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        failed = true
        result = yield
        failed = false
        result
      ensure
        begin
          @metrics&.observe("dra_operations_duration_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                            {"operation_name" => name, "is_error" => failed.to_s})
        rescue StandardError
          nil
        end
      end

      # prepareResources.
      def prepare_pod_resources(pod)
        namespace = pod.dig("metadata", "namespace").to_s
        pod_uid = pod.dig("metadata", "uid").to_s
        infos = pod_resource_claims(pod).filter_map do |pod_claim|
          name, must_check_owner = claim_name(pod, pod_claim)
          next nil if name.nil?

          claim = fetch_claim(namespace, name)
          if must_check_owner && !owned_by?(claim, pod)
            raise Error,
                  "ResourceClaim #{namespace}/#{name} was not created for Pod #{namespace}/#{pod.dig("metadata",
                                                                                                     "name")} (Pod is not owner)"
          end
          unless Array(claim.dig("status", "reservedFor")).any? { |entry| entry["uid"].to_s == pod_uid }
            raise Error,
                  "pod #{pod.dig("metadata",
                                 "name")} (#{pod_uid}) is not allowed to use ResourceClaim #{name} (#{claim.dig("metadata", "uid")})"
          end

          allocation = claim.dig("status", "allocation")
          raise Error, "ResourceClaim #{name}: not allocated" if allocation.nil?

          drivers = Array(allocation.dig("devices", "results")).map { |result| result["driver"].to_s }.uniq
          plugins = drivers.to_h { |driver| [driver, plugin(driver)] }
          {claim: claim, drivers: drivers, plugins: plugins}
        end

        batches = Hash.new { |hash, key| hash[key] = [] }
        to_prepare = {}
        @mutex.synchronize do
          infos.each do |info|
            claim = info[:claim]
            key = claim_key(claim)
            entry = @claims[key]
            if entry.nil?
              entry = @claims[key] = {"claim_uid" => claim.dig("metadata", "uid").to_s, "claim_name" => claim.dig("metadata", "name").to_s,
                                      "namespace" => claim.dig("metadata", "namespace").to_s, "pod_uids" => [],
                                      "driver_state" => info[:drivers].to_h { |driver| [driver, {"devices" => []}] }, "prepared" => false}
            elsif entry["claim_uid"] != claim.dig("metadata", "uid").to_s
              raise Error, "old ResourceClaim with same name #{claim.dig("metadata", "name")} and different UID #{entry["claim_uid"]} " \
                           "still exists (previous pod force-deleted?!)"
            end
            entry["pod_uids"] |= [pod_uid]
            next if entry["prepared"]

            # Prepared from scratch (a restored entry, a failed attempt):
            # the driver answers with the whole device list again.
            entry["driver_state"].each_value { |state| state["devices"] = [] }
            to_prepare[entry["claim_uid"]] = key
            request = {"namespace" => entry["namespace"], "uid" => entry["claim_uid"], "name" => entry["claim_name"]}
            info[:drivers].each { |driver| batches[info[:plugins].fetch(driver)] << request }
          end
          write_checkpoint
        end

        batches.each do |target, requests|
          response = call(target, "NodePrepareResources", {"claims" => requests})
          results = response["claims"] || {}
          results.each do |claim_uid, result|
            request = requests.find { |candidate| candidate["uid"] == claim_uid }
            raise Error, "NodePrepareResources returned result for unknown claim UID #{claim_uid}" unless request
            unless result["error"].to_s.empty?
              raise Error,
                    "NodePrepareResources failed for ResourceClaim #{request["name"]}: #{result["error"]}"
            end

            @mutex.synchronize do
              entry = @claims[to_prepare.fetch(claim_uid)]
              unless entry
                raise Error,
                      "internal error: unable to get claim info for ResourceClaim #{request["name"]} in namespace #{request["namespace"]}"
              end

              driver_state = (entry["driver_state"][target.driver] ||= {"devices" => []})
              Array(result["devices"]).each do |device|
                driver_state["devices"] << {"pool_name" => device["pool_name"], "device_name" => device["device_name"],
                                            "share_id" => device["share_id"], "request_names" => Array(device["request_names"]),
                                            "cdi_device_ids" => Array(device["cdi_device_ids"])}
              end
            end
          end
          unfinished = requests.length - results.length
          raise Error, "NodePrepareResources skipped #{unfinished} ResourceClaims" unless unfinished.zero?
        end
        @mutex.synchronize do
          to_prepare.each_value { |key| @claims[key]["prepared"] = true if @claims[key] }
          write_checkpoint
        end
        true
      end

      # GetResources: the CDI device IDs for +container+.
      def container_cdi_devices(pod, container)
        requests = container_claim_requests(pod, container)
        namespace = pod.dig("metadata", "namespace").to_s
        @mutex.synchronize do
          requests.flat_map do |name, request_names|
            entry = @claims["#{namespace}/#{name}"]
            raise Error, "internal error: unable to get claim info for ResourceClaim #{name} in namespace #{namespace}" unless entry

            request_names.flat_map { |request_name| cdi_devices(entry, request_name) }
          end
        end
      end

      # podresources DynamicResource: each prepared claim the container uses,
      # with the devices of the requests it asked for.
      def container_claims(pod, container)
        requests = container_claim_requests(pod, container)
        namespace = pod.dig("metadata", "namespace").to_s
        @mutex.synchronize do
          requests.filter_map do |name, request_names|
            entry = @claims["#{namespace}/#{name}"]
            next nil unless entry

            resources = entry["driver_state"].flat_map do |driver, state|
              Array(state["devices"]).filter_map do |device|
                names = Array(device["request_names"])
                next nil unless request_names.any? { |request| request.empty? || names.empty? || names.include?(request) }

                {"driver_name" => driver, "pool_name" => device["pool_name"], "device_name" => device["device_name"],
                 "cdi_devices" => Array(device["cdi_device_ids"]).map { |id| {"name" => id} }}
              end
            end
            {"claim_name" => name, "claim_namespace" => namespace, "claim_resources" => resources}
          end
        end
      end

      def container_claim_requests(pod, container)
        requests = Hash.new { |hash, key| hash[key] = [] }
        wanted = Array(container.dig("resources", "claims")).group_by { |entry| entry["name"].to_s }
        # DRAExtendedResource: the container's extended-resource requests map
        # to requests of the Pod's extended-resource claim.
        extended = pod.dig("status", "extendedResourceClaimStatus")
        if extended
          asked = (container.dig("resources", "requests") || {}).select do |name, value|
            !value.to_s.empty? && value.to_s != "0" && extended_resource_name?(name)
          end
          Array(extended["requestMappings"]).each do |mapping|
            next unless mapping["containerName"] == container["name"] && asked.key?(mapping["resourceName"].to_s)

            requests[extended["resourceClaimName"].to_s] << mapping["requestName"].to_s
          end
        end
        pod_resource_claims(pod).each do |pod_claim|
          entries = wanted[pod_claim["name"].to_s]
          next unless entries

          name, = claim_name(pod, pod_claim)
          next if name.nil?

          requests[name].concat(entries.map { |entry| entry["request"].to_s })
        end
        requests
      end

      # UnprepareResources.
      def unprepare_resources(pod) = dra_operation("UnprepareResources") { unprepare_pod_resources(pod) }

      # unprepareResourcesForPod.
      def unprepare_pod_resources(pod)
        names = pod_resource_claims(pod).filter_map do |pod_claim|
          claim_name(pod, pod_claim).first
        rescue Error
          nil
        end
        unprepare(pod.dig("metadata", "uid").to_s, pod.dig("metadata", "namespace").to_s, names)
      end

      def pod_might_need_unprepare?(pod_uid)
        @mutex.synchronize { @claims.values.any? { |entry| entry["pod_uids"].include?(pod_uid.to_s) } }
      end

      # reconcileLoop: unprepare claims of Pods that are no longer active.
      def reconcile
        active = Array(@active_pods.call).map { |pod| pod.dig("metadata", "uid").to_s }.to_set
        inactive = Hash.new { |hash, key| hash[key] = {namespace: nil, names: []} }
        @mutex.synchronize do
          @claims.each_value do |entry|
            entry["pod_uids"].each do |uid|
              next if active.include?(uid)

              inactive[uid][:namespace] = entry["namespace"]
              inactive[uid][:names] << entry["claim_name"]
            end
          end
        end
        inactive.each do |uid, work|
          unprepare(uid, work[:namespace], work[:names])
        rescue StandardError => error
          @error_handler&.call(error, :dra_reconcile)
        end
        run_due_wipes
      end

      # --------------------------------------------------- lifecycle

      def start
        @mutex.synchronize do
          return self unless @threads.empty?

          @stop = false
          @threads << Thread.new { wipe_resource_slices(nil) }
          @threads << Thread.new do
            until @mutex.synchronize { @stop }
              @sleeper.call(1.0)
              @last_reconcile ||= @monotonic.call
              begin
                run_due_wipes
                if @monotonic.call - @last_reconcile >= RECONCILE_PERIOD
                  @last_reconcile = @monotonic.call
                  reconcile
                end
              rescue StandardError => error
                @error_handler&.call(error, :dra_manager)
              end
            end
          end
        end
        self
      end

      def stop
        threads = @mutex.synchronize do
          @stop = true
          @threads.dup.tap { @threads.clear }
        end
        threads.each { |thread| thread.join(5) unless thread == Thread.current }
        @mutex.synchronize { @health_streams.keys }.each { |endpoint| stop_health_stream(endpoint) }
        self
      end

      # UpdateAllocatedResourcesStatus: for each claim (and request) the
      # container names, "claim:<name>[/<request>]" with the health of every
      # device the prepared claim holds for it; a device is identified by its
      # first CDI device ID, else driver/pool/device.
      def allocated_resources_status(pod, container)
        claims = Array(container.dig("resources", "claims"))
        return [] if claims.empty?

        namespace = pod.dig("metadata", "namespace").to_s
        pod_claims = Array(pod.dig("spec", "resourceClaims"))
        statuses = {}
        claims.each do |claim|
          pod_claim = pod_claims.find { |entry| entry["name"].to_s == claim["name"].to_s }
          next unless pod_claim

          actual = begin
            claim_name(pod, pod_claim).first
          rescue Error
            nil
          end
          next if actual.to_s.empty?

          entry = @mutex.synchronize { @claims["#{namespace}/#{actual}"] }
          next unless entry

          request = claim["request"].to_s
          name = request.empty? ? "claim:#{claim["name"]}" : "claim:#{claim["name"]}/#{request}"
          base_request = request.split("/", 2).first
          resources = []
          seen = {}
          entry["driver_state"].each do |driver, state|
            Array(state["devices"]).each do |device|
              names = Array(device["request_names"])
              next if !request.empty? && !names.empty? && !names.include?(base_request)

              ids = Array(device["cdi_device_ids"])
              id = ids.empty? ? "#{driver}/#{device["pool_name"]}/#{device["device_name"]}" : ids.first
              next if seen[id]

              seen[id] = true
              info = @health.get(driver, device["pool_name"], device["device_name"])
              health = {"resourceID" => id, "health" => info["health"]}
              health["message"] = info["message"] unless info["message"].to_s.empty?
              resources << health
            end
          end
          statuses[name] = {"name" => name, "resources" => resources} unless resources.empty?
        end
        statuses.keys.sort.map { |name| statuses[name] }
      end

      # HandleWatchResourcesStream: one message of a plugin's health stream.
      def handle_health_event(driver, message)
        case message["event"]
        when "devices"
          devices = Array(message["devices"]).map { |device| DRAHealth.device_from_wire(device) }
          changed = @health.update(driver, devices)
          return [] if changed.empty?

          pods = @mutex.synchronize do
            @claims.values.flat_map do |entry|
              devices = Array(entry.dig("driver_state", driver.to_s, "devices"))
              hit = changed.any? do |device|
                devices.any? { |held| held["pool_name"] == device["pool"] && held["device_name"] == device["device"] }
              end
              hit ? entry["pod_uids"] : []
            end.uniq
          end
          @on_health_change&.call(pods) unless pods.empty?
          pods
        when "ended"
          # The stream exited: what it reported is no longer known.
          @health.clear(driver)
          []
        else
          []
        end
      rescue StandardError => error
        @error_handler&.call(error, :dra_health)
        []
      end

      # wipeResourceSlices: this node's slices (of +driver+, or all).
      def wipe_resource_slices(driver)
        return unless @client.respond_to?(:raw)

        selector = ["spec.nodeName=#{@node_name}"]
        selector << "spec.driver=#{driver}" if driver
        @client.raw("DELETE", "/apis/#{API_VERSION}/resourceslices", query: {"fieldSelector" => selector.join(",")})
        true
      rescue StandardError => error
        @error_handler&.call(error, :dra_wipe)
        false
      end

      private

      def start_health_stream(driver, endpoint)
        stream = @mutex.synchronize do
          next nil if @health_streams.key?(endpoint)

          @health_streams[endpoint] = @health_stream.call(endpoint, ->(message) { handle_health_event(driver, message) })
        end
        stream&.start
      rescue StandardError => error
        @error_handler&.call(error, :dra_health)
      end

      def stop_health_stream(endpoint)
        stream = @mutex.synchronize { @health_streams.delete(endpoint) }
        stream&.stop
      rescue StandardError => error
        @error_handler&.call(error, :dra_health)
      end

      def run_due_wipes
        due = @mutex.synchronize do
          now = @monotonic.call
          @pending_wipes.select { |_driver, at| at <= now }.keys.each { |driver| @pending_wipes.delete(driver) }
        end
        due.each { |driver| wipe_resource_slices(driver) }
      end

      def unprepare(pod_uid, namespace, names)
        batches = Hash.new { |hash, key| hash[key] = [] }
        to_delete = []
        @mutex.synchronize do
          names.each do |name|
            entry = @claims["#{namespace}/#{name}"]
            next unless entry

            if entry["pod_uids"].length > 1
              entry["pod_uids"].delete(pod_uid)
              next
            end
            to_delete << "#{namespace}/#{name}"
            request = {"namespace" => entry["namespace"], "uid" => entry["claim_uid"], "name" => entry["claim_name"]}
            entry["driver_state"].each_key { |driver| batches[driver] << request }
          end
          write_checkpoint
        end
        batches.each do |driver, requests|
          target = plugin(driver)
          response = call(target, "NodeUnprepareResources", {"claims" => requests})
          results = response["claims"] || {}
          results.each do |claim_uid, result|
            request = requests.find { |candidate| candidate["uid"] == claim_uid }
            raise Error, "NodeUnprepareResources returned result for unknown claim UID #{claim_uid}" unless request
            unless result["error"].to_s.empty?
              raise Error,
                    "NodeUnprepareResources failed for ResourceClaim #{request["name"]}: #{result["error"]}"
            end
          end
          unfinished = requests.length - results.length
          raise Error, "NodeUnprepareResources skipped #{unfinished} ResourceClaims" unless unfinished.zero?
        end
        @mutex.synchronize do
          to_delete.each { |key| @claims.delete(key) }
          write_checkpoint
        end
        true
      end

      # grpc status codes by number (status.Code(err).String()).
      GRPC_CODES = %w[OK Canceled Unknown InvalidArgument DeadlineExceeded NotFound AlreadyExists PermissionDenied ResourceExhausted
                      FailedPrecondition Aborted OutOfRange Unimplemented Internal Unavailable DataLoss Unauthenticated].freeze

      # newMetricsInterceptor: every unary call by driver, full method name
      # and status code.
      def call(target, method, request)
        service = SERVICES.fetch(target.service)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        code = "OK"
        begin
          @rpc.call(socket: target.endpoint, service: service, method: method, request: request, timeout: CALL_TIMEOUT)
        rescue Plugins::RPC::Error => error
          code = error.code.is_a?(Integer) ? GRPC_CODES.fetch(error.code, "Code(#{error.code})") : "Unknown"
          raise Error, "#{method}: #{error.message}"
        ensure
          begin
            @metrics&.observe("dra_grpc_operations_duration_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                              {"driver_name" => target.driver.to_s, "method_name" => "/#{service}/#{method}", "grpc_status_code" => code})
          rescue StandardError
            nil
          end
        end
      end

      def choose_service(versions)
        raise Error, "empty list of supported gRPC services (aka supported versions)" if Array(versions).empty?

        chosen = Array(versions).find { |version| SERVICES.key?(version.to_s) }
        return chosen.to_s if chosen

        raise Error,
              "none of services supported by the plugin (#{Array(versions).inspect}) are supported by the kubelet (#{SERVICES.keys.inspect})"
      end

      # cdiDevicesAsList.
      def cdi_devices(entry, request_name)
        entry["driver_state"].values.flat_map do |state|
          Array(state["devices"]).flat_map do |device|
            names = Array(device["request_names"])
            next [] unless request_name.empty? || names.empty? || names.include?(request_name)

            Array(device["cdi_device_ids"])
          end
        end
      end

      # spec.resourceClaims plus, with DRAExtendedResource, the claim named
      # in status.extendedResourceClaimStatus.
      def pod_resource_claims(pod)
        claims = Array(pod.dig("spec", "resourceClaims"))
        extended = pod.dig("status", "extendedResourceClaimStatus", "resourceClaimName")
        extended ? claims + [{"name" => "", "resourceClaimName" => extended.to_s}] : claims
      end

      def extended_resource_name?(name)
        require_relative "../dra/extended_resources"
        Rubernetes::DRA::ExtendedResources.extended_resource_name?(name)
      end

      # resourceclaim.Name.
      def claim_name(pod, pod_claim)
        if pod_claim["resourceClaimName"]
          [pod_claim["resourceClaimName"].to_s, false]
        elsif pod_claim["resourceClaimTemplateName"]
          status = Array(pod.dig("status", "resourceClaimStatuses")).find { |entry| entry["name"] == pod_claim["name"] }
          unless status
            raise Error,
                  "pod \"#{pod.dig("metadata", "namespace")}/#{pod.dig("metadata", "name")}\": ResourceClaim not created yet"
          end

          [status["resourceClaimName"], true]
        else
          raise Error, "pod \"#{pod.dig("metadata", "namespace")}/#{pod.dig("metadata", "name")}\", spec.resourceClaim " \
                       "#{pod_claim["name"].to_s.dump}: none of the supported fields are set"
        end
      end

      def fetch_claim(namespace, name)
        @client.get("resourceclaims", name, namespace: namespace, api_version: API_VERSION)
      rescue StandardError => error
        raise Error, "fetch ResourceClaim #{name}: #{error.message}"
      end

      def owned_by?(claim, pod)
        Array(claim.dig("metadata", "ownerReferences")).any? do |reference|
          reference["controller"] == true && reference["uid"].to_s == pod.dig("metadata", "uid").to_s
        end
      end

      def claim_key(claim) = "#{claim.dig("metadata", "namespace")}/#{claim.dig("metadata", "name")}"

      def checkpoint_path = File.join(@state_directory, CHECKPOINT)

      def write_checkpoint
        FileUtils.mkdir_p(@state_directory)
        entries = @claims.values.map { |entry| entry.reject { |key, _| key == "prepared" } }
        payload = JSON.generate("version" => "v1", "claims" => entries)
        temporary = "#{checkpoint_path}.tmp"
        File.write(temporary, payload)
        File.rename(temporary, checkpoint_path)
      rescue SystemCallError => error
        raise Error, "checkpoint ResourceClaim state: #{error.message}"
      end

      def load_checkpoint
        return unless File.file?(checkpoint_path)

        Array(JSON.parse(File.read(checkpoint_path))["claims"]).each do |entry|
          @claims["#{entry["namespace"]}/#{entry["claim_name"]}"] = entry.merge("prepared" => false)
        end
      rescue JSON::ParserError, SystemCallError => error
        raise Error, "could not initialize checkpoint manager, please drain node and remove DRA state file, err: #{error.message}"
      end
    end
  end
end
