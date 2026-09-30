# frozen_string_literal: true

module Rubernetes
  module Volume
    require_relative "csi_uds_client"

    # Ruby boundary for a CSI controller/node plugin.  A configured socket uses
    # the real generated gRPC client; an explicitly injected adapter remains a
    # narrow lifecycle seam for built-in tests and alternate transports.
    class CSIBridge
      CONTROLLER_OPERATIONS = {
        create_volume: "CreateVolume", delete_volume: "DeleteVolume", publish: "ControllerPublishVolume",
        unpublish: "ControllerUnpublishVolume", create_snapshot: "CreateSnapshot", expand: "ControllerExpandVolume"
      }.freeze
      NODE_OPERATIONS = {
        stage: "NodeStageVolume", unstage: "NodeUnstageVolume", publish_node: "NodePublishVolume",
        unpublish_node: "NodeUnpublishVolume", stats: "NodeGetVolumeStats", expand_node: "NodeExpandVolume"
      }.freeze

      def initialize(client: nil, socket: nil, identity: nil, capabilities: nil, timeout: 30,
                     expected_socket_uid: Process.euid, expected_socket_gid: Process.egid,
                     expected_socket_mode: nil, expected_peer_uid: Process.euid,
                     expected_peer_gid: Process.egid)
        @client = client || (socket && CSIUDSClient.new(
          socket: socket, timeout: timeout,
          expected_socket_uid: expected_socket_uid, expected_socket_gid: expected_socket_gid,
          expected_socket_mode: expected_socket_mode,
          expected_peer_uid: expected_peer_uid, expected_peer_gid: expected_peer_gid
        ))
        @identity = identity
        @capabilities = capabilities
        @timeout = Float(timeout)
        raise ValidationError, "CSI timeout must be positive" unless @timeout.positive?
      end

      attr_reader :client, :timeout

      def probe
        value = if @client&.respond_to?(:probe)
                  @client.probe
                else
                  invoke("Probe", {})
                end
        AdapterSupport.result_hash(value)
      end

      def ready?
        Types.key(probe, "ready", true) == true
      end

      def identity
        value = @identity || invoke("GetPluginInfo", {})
        hash = AdapterSupport.result_hash(value)
        Identity.new(name: hash["name"] || hash["pluginName"] || "csi-plugin",
                     vendor_version: hash["vendorVersion"] || hash["vendor_version"] || "unknown",
                     plugin_version: hash["pluginVersion"] || hash["plugin_version"] || "v1",
                     supports: Array(hash["supports"] || hash["capabilities"] || []))
      end

      def capabilities
        value = @capabilities || if @client.respond_to?(:capabilities)
                                   @client.capabilities
                                 else
                                   invoke("GetPluginCapabilities", {})
                                 end
        AdapterSupport.result_hash(value)
      end

      def create_volume(spec, token:)
        request = Types.deep_copy(spec)
        request["name"] = Types.key(spec, "name", Types.key(spec, "id"))
        request["capacityRange"] = {"requiredBytes" => Types.key(spec, "capacityBytes") || Types.key(spec, "capacity")}
        request["parameters"] = Types.key(spec, "parameters", {})
        invoke(CONTROLLER_OPERATIONS.fetch(:create_volume), request, token: token)
      end

      def delete_volume(id, token:, secrets: {})
        invoke(CONTROLLER_OPERATIONS.fetch(:delete_volume), {"volumeId" => id.to_s, "secrets" => Types.deep_copy(secrets)}, token: token)
      end

      def publish(id, node, token:, readonly: false, context: {})
        request = Types.deep_copy(context).merge("volumeId" => id.to_s, "nodeId" => node.to_s,
                                                 "readonly" => readonly == true)
        invoke(CONTROLLER_OPERATIONS.fetch(:publish), request, token: token)
      end

      def unpublish(id, node, token:, context: {})
        request = Types.deep_copy(context).merge("volumeId" => id.to_s, "nodeId" => node.to_s)
        invoke(CONTROLLER_OPERATIONS.fetch(:unpublish), request, token: token)
      end

      def create_snapshot(id, token:, name: nil, secrets: {})
        request = {"sourceVolumeId" => id.to_s, "secrets" => Types.deep_copy(secrets)}
        request["name"] = name if name
        invoke(CONTROLLER_OPERATIONS.fetch(:create_snapshot), request, token: token)
      end

      def delete_snapshot(id, token: nil, secrets: {})
        invoke("DeleteSnapshot", {"snapshotId" => id.to_s, "secrets" => Types.deep_copy(secrets)}, token: token)
      end

      # ListSnapshots is part of the controller-side recovery contract.  Keep
      # it on the bridge (rather than requiring callers to reach through to
      # CSIUDSClient) so a production CSIBridge is observable after restart.
      # The manager passes source_volume_id and per-volume secrets here; they
      # must reach the actual plugin unchanged.
      def list_snapshots(token: nil, **filters)
        request = filters.each_with_object({}) { |(key, value), result| result[key.to_s] = Types.deep_copy(value) }
        invoke("ListSnapshots", request, token: token)
      end

      def list_volumes(token: nil, **filters)
        request = filters.each_with_object({}) { |(key, value), result| result[key.to_s] = Types.deep_copy(value) }
        invoke("ListVolumes", request, token: token)
      end

      def expand(id, capacity, token:, secrets: {}, volume_capability: nil)
        request = {"volumeId" => id.to_s, "capacityRange" => {"requiredBytes" => Types.parse_capacity(capacity)},
                   "secrets" => Types.deep_copy(secrets)}
        request["volumeCapability"] = Types.deep_copy(volume_capability) if volume_capability
        invoke(CONTROLLER_OPERATIONS.fetch(:expand), request, token: token)
      end

      def stage(id, path, token:, readonly: false, context: {})
        request = Types.deep_copy(context).merge(
          "volumeId" => id.to_s, "stagingTargetPath" => path.to_s, "readonly" => readonly == true
        )
        invoke(NODE_OPERATIONS.fetch(:stage), request, token: token)
      end

      def unstage(id, path, token:)
        invoke(NODE_OPERATIONS.fetch(:unstage), {"volumeId" => id.to_s, "stagingTargetPath" => path.to_s}, token: token)
      end

      def publish_node(id, stage_path, target, token:, readonly: false, context: {})
        request = Types.deep_copy(context).merge(
          "volumeId" => id.to_s, "stagingTargetPath" => stage_path.to_s,
          "targetPath" => target.to_s, "readonly" => readonly == true
        )
        invoke(NODE_OPERATIONS.fetch(:publish_node), request, token: token)
      end

      def unpublish_node(id, target, token:)
        invoke(NODE_OPERATIONS.fetch(:unpublish_node), {"volumeId" => id.to_s, "targetPath" => target.to_s}, token: token)
      end

      def stats(id, token: nil, path: nil)
        invoke(NODE_OPERATIONS.fetch(:stats), {"volumeId" => id.to_s, "volumePath" => path.to_s}, token: token)
      end

      def expand_node(id, path, token:, capacity_bytes: nil, volume_capability: nil, secrets: {}, staging_path: nil)
        request = {"volumeId" => id.to_s, "volumePath" => path.to_s}
        request["stagingTargetPath"] = staging_path.to_s if staging_path
        request["capacityRange"] = {"requiredBytes" => Types.parse_capacity(capacity_bytes)} if capacity_bytes
        request["volumeCapability"] = Types.deep_copy(volume_capability) if volume_capability
        request["secrets"] = Types.deep_copy(secrets)
        invoke(NODE_OPERATIONS.fetch(:expand_node), request, token: token)
      end

      # NodeGetInfo.
      def node_info
        invoke("NodeGetInfo", {})
      end

      # NodeGetCapabilities only: a node plugin need not serve Controller.
      def node_capabilities
        Array(invoke("NodeGetCapabilities", {})["capabilities"]).map(&:to_s)
      end

      def supports?(capability)
        caps = capabilities
        values = caps["capabilities"] || caps["rpc"] || caps["supports"] || caps.values.flatten
        values.map do |value|
          value.respond_to?(:to_h) ? value.to_h.values : value
        end.flatten.any? { |value| value.to_s.casecmp?(capability.to_s) }
      end

      # ->(driver_name, method_name, grpc_status_code, seconds) for
      # csi_operations_seconds; the driver's name as registered.

      attr_accessor :metrics_observer, :driver_name

      private

      def invoke(operation, request, token: nil)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        status = "OK"
        begin
          invoke_without_metrics(operation, request, token: token)
        rescue CSIError, CSIUnavailable => error
          details = error.respond_to?(:details) ? error.details : nil
          status = (details.is_a?(Hash) && (details["grpcCode"] || details[:grpcCode])) || "Unknown"
          raise
        ensure
          observe_csi_operation(operation, status, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        end
      end

      def observe_csi_operation(operation, status, seconds)
        observer = @metrics_observer
        return unless observer

        observer.call(@driver_name.to_s, operation.to_s, status.to_s, seconds)
      rescue StandardError
        nil
      end

      def invoke_without_metrics(operation, request, token: nil)
        raise CSIUnavailable, "CSI client is not configured" unless @client

        request = Types.deep_copy(request)
        value = if @client.respond_to?(:invoke)
                  @client.invoke(operation, request, token: token, timeout: @timeout)
                elsif @client.respond_to?(operation)
                  @client.public_send(operation, request)
                else
                  raise CSIUnavailable, "CSI client does not implement #{operation}"
                end
        normalize_response(operation, value)
      rescue CSIError, CSIUnavailable
        raise
      rescue StandardError => error
        raise CSIError.new("CSI #{operation} failed: #{error.message}", operation: operation), cause: error
      end

      def normalize_response(operation, value)
        raise CSIError.new("CSI #{operation} returned no response; outcome is unknown", operation: operation, ambiguous: true) if value.nil?

        hash = AdapterSupport.result_hash(value)
        raise CSIError.new("CSI #{operation} returned a non-map response", operation: operation) unless value.respond_to?(:to_h)
        if hash["error"] || (hash["code"] && hash["code"].to_i != 0)
          raise CSIError.new("CSI #{operation} returned an error: #{hash["message"] || hash["error"]}", operation: operation,
                                                                                                        details: hash)
        end
        hash
      end
    end

    CSI = CSIBridge unless const_defined?(:CSI, false)
    CSIBridge::Bridge = CSIBridge unless CSIBridge.const_defined?(:Bridge, false)
    CSIBridge::Controller = CSIBridge unless CSIBridge.const_defined?(:Controller, false)
  end
end
