# frozen_string_literal: true

# Real CSI transport over the Unix-domain gRPC endpoint exposed by a CSI
# plugin.  Protobuf classes and RPC descriptors are generated from the pinned
# CSI specification; this file owns only request construction and Ruby policy.
require "monitor"
require "pathname"
require "socket"
require "time"

require_relative "errors"
require_relative "types"

module Rubernetes
  module Volume
    class CSIUDSClient
      KUBERNETES_VERSION = "v1.36.2"
      KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
      CSI_SPEC_VERSION = "1.9.0"
      CSI_SPEC_COMMIT = "80d53107c70981b9da8aaf9cd1c90249562b22f0"

      ACCESS_MODE_NAMES = {
        "SINGLE_NODE_WRITER" => "SINGLE_NODE_WRITER",
        "SINGLE_NODE_READER_ONLY" => "SINGLE_NODE_READER_ONLY",
        "MULTI_NODE_READER_ONLY" => "MULTI_NODE_READER_ONLY",
        "MULTI_NODE_SINGLE_WRITER" => "MULTI_NODE_SINGLE_WRITER",
        "MULTI_NODE_MULTI_WRITER" => "MULTI_NODE_MULTI_WRITER",
        "SINGLE_NODE_SINGLE_WRITER" => "SINGLE_NODE_SINGLE_WRITER",
        "SINGLE_NODE_MULTI_WRITER" => "SINGLE_NODE_MULTI_WRITER",
        "ReadWriteOnce" => "SINGLE_NODE_WRITER",
        "ReadOnlyMany" => "MULTI_NODE_READER_ONLY",
        "ReadWriteMany" => "MULTI_NODE_MULTI_WRITER",
        "ReadWriteOncePod" => "SINGLE_NODE_SINGLE_WRITER"
      }.freeze

      AMBIGUOUS_STATUS_CODES = %i[CANCELLED UNKNOWN DEADLINE_EXCEEDED INTERNAL UNAVAILABLE DATA_LOSS].freeze

      CONTROLLER_OPERATIONS = {
        "CreateVolume" => :create_volume,
        "DeleteVolume" => :delete_volume,
        "ControllerPublishVolume" => :publish,
        "ControllerUnpublishVolume" => :unpublish,
        "CreateSnapshot" => :create_snapshot,
        "DeleteSnapshot" => :delete_snapshot,
        "ListSnapshots" => :list_snapshots,
        "ListVolumes" => :list_volumes,
        "ControllerExpandVolume" => :expand
      }.freeze

      NODE_OPERATIONS = {
        "NodeStageVolume" => :stage,
        "NodeUnstageVolume" => :unstage,
        "NodePublishVolume" => :publish_node,
        "NodeUnpublishVolume" => :unpublish_node,
        "NodeGetVolumeStats" => :stats,
        "NodeExpandVolume" => :expand_node
      }.freeze

      attr_reader :socket, :endpoint, :timeout, :endpoint_identity

      def initialize(socket:, timeout: 30, metadata: {}, expected_socket_uid: Process.euid,
                     expected_socket_gid: Process.egid, expected_socket_mode: nil,
                     expected_peer_uid: Process.euid, expected_peer_gid: Process.egid)
        self.class.load_grpc!
        @socket = normalize_socket(socket)
        @endpoint = "unix://#{@socket}"
        @timeout = Float(timeout)
        raise ValidationError, "CSI timeout must be positive" unless @timeout.positive?

        @metadata = string_map(metadata, "metadata")
        @expected_socket_uid = optional_identity(expected_socket_uid, "CSI socket uid")
        @expected_socket_gid = optional_identity(expected_socket_gid, "CSI socket gid")
        @expected_socket_mode = optional_mode(expected_socket_mode)
        @expected_peer_uid = optional_identity(expected_peer_uid, "CSI peer uid")
        @expected_peer_gid = optional_identity(expected_peer_gid, "CSI peer gid")
        @endpoint_identity = nil
        @endpoint_lock = Monitor.new
        @timeout_context_key = "rubernetes.csi.timeout.#{object_id}"
        @identity_stub = Csi::V1::Identity::Stub.new(@endpoint, :this_channel_is_insecure)
        @controller_stub = Csi::V1::Controller::Stub.new(@endpoint, :this_channel_is_insecure)
        @node_stub = Csi::V1::Node::Stub.new(@endpoint, :this_channel_is_insecure)
        @cache_lock = Monitor.new
        @plugin_info = nil
        @plugin_capabilities = nil
        @controller_capabilities = nil
        @node_capabilities = nil
        ensure_socket! if File.exist?(@socket) || File.symlink?(@socket)
      rescue ArgumentError => error
        raise CSIUnavailable, "CSI gRPC client could not initialize for #{@socket}: #{error.message}"
      end

      def socket_available?
        File.lstat(@socket).socket?
      rescue Errno::ENOENT
        false
      end

      def close
        [@identity_stub, @controller_stub, @node_stub].each do |stub|
          stub.close if stub.respond_to?(:close)
        end
        true
      end

      def probe
        response = rpc(:identity, :probe, Csi::V1::ProbeRequest.new, response_class: Csi::V1::ProbeResponse,
                                                                     operation: "Probe", mutating: false)
        {"ready" => response.ready ? response.ready.value : true}
      end

      def ready?
        probe.fetch("ready") == true
      end

      def identity
        info = plugin_info
        name = info.name.to_s
        vendor_version = info.vendor_version.to_s
        raise CSIError.new("CSI GetPluginInfo returned an empty plugin name", operation: "GetPluginInfo") if name.empty?
        raise CSIError.new("CSI GetPluginInfo returned an empty vendor version", operation: "GetPluginInfo") if vendor_version.empty?

        Identity.new(name: name, vendor_version: vendor_version, plugin_version: CSI_SPEC_VERSION,
                     supports: plugin_service_names)
      end

      def capabilities
        plugin = plugin_service_names
        controller = controller_capability_names
        node = node_capability_names
        {
          "plugin" => plugin,
          "controller" => controller,
          "node" => node,
          "specVersion" => CSI_SPEC_VERSION,
          "specCommit" => CSI_SPEC_COMMIT
        }.freeze
      end

      def controller_capabilities
        controller_capability_names
      end

      def node_capabilities
        node_capability_names
      end

      # NodeGetInfo: what the kubelet registers for the driver on this node
      # (CSINode nodeID, allocatable count, topology keys and labels).
      def node_info
        ensure_socket!
        response = rpc(:node, :node_get_info, Csi::V1::NodeGetInfoRequest.new,
                       response_class: Csi::V1::NodeGetInfoResponse, operation: "NodeGetInfo", mutating: false)
        segments = response.accessible_topology ? string_map(response.accessible_topology.segments, "topology segments") : {}
        {"nodeId" => response.node_id.to_s, "maxVolumesPerNode" => response.max_volumes_per_node.to_i, "topology" => segments}
      end

      def supports?(capability)
        capabilities.values.any? { |values| Array(values).any? { |value| value.to_s.casecmp?(capability.to_s) } }
      end

      def create_volume(spec, token:, name: nil)
        spec = hash_value(spec, "volume spec")
        token = required_token(token)
        ensure_controller_rpc!("CREATE_DELETE_VOLUME", "CreateVolume")
        request = Csi::V1::CreateVolumeRequest.new(
          name: name.to_s.empty? ? Types.key(spec, "name", Types.key(spec, "id", token)).to_s : name.to_s,
          capacity_range: capacity_range_for(spec),
          volume_capabilities: volume_capabilities_for(spec),
          parameters: string_map(Types.key(spec, "parameters", {}), "parameters"),
          secrets: string_map(Types.key(spec, "secrets", {}), "secrets")
        )
        source = content_source_for(spec)
        request.volume_content_source = source if source
        response = rpc(:controller, :create_volume, request, response_class: Csi::V1::CreateVolumeResponse,
                                                             operation: "CreateVolume")
        volume = response.volume
        raise CSIError.new("CSI CreateVolume returned no volume", operation: "CreateVolume") unless volume

        volume_hash(volume).merge("volume" => volume_hash(volume))
      end

      def delete_volume(id, token:, secrets: {})
        ensure_controller_rpc!("CREATE_DELETE_VOLUME", "DeleteVolume")
        request = Csi::V1::DeleteVolumeRequest.new(volume_id: required_identifier(id, "volume id"),
                                                   secrets: string_map(secrets, "secrets"))
        rpc(:controller, :delete_volume, request, response_class: Csi::V1::DeleteVolumeResponse,
                                                  operation: "DeleteVolume", idempotent_absent: true)
        {}
      end

      def publish(id, node, token:, readonly: false, context: {})
        ensure_controller_rpc!("PUBLISH_UNPUBLISH_VOLUME", "ControllerPublishVolume")
        context = hash_value(context, "publish context")
        readonly = effective_readonly?(context, readonly)
        request = Csi::V1::ControllerPublishVolumeRequest.new(
          volume_id: required_identifier(id, "volume id"), node_id: required_identifier(node, "node"),
          volume_capability: volume_capability_for(context, readonly: readonly), readonly: readonly == true,
          secrets: string_map(Types.key(context, "secrets", {}), "secrets"),
          volume_context: string_map(Types.key(context, "volumeContext", Types.key(context, "volume_context", {})),
                                     "volume context")
        )
        response = rpc(:controller, :controller_publish_volume, request,
                       response_class: Csi::V1::ControllerPublishVolumeResponse,
                       operation: "ControllerPublishVolume")
        {"volumeId" => id.to_s, "node" => node.to_s, "publishContext" => string_map(response.publish_context, "publish context")}
      end

      def unpublish(id, node, token:, secrets: {}, context: {})
        ensure_controller_rpc!("PUBLISH_UNPUBLISH_VOLUME", "ControllerUnpublishVolume")
        context = hash_value(context, "unpublish context")
        secrets = Types.key(context, "secrets", secrets)
        request = Csi::V1::ControllerUnpublishVolumeRequest.new(
          volume_id: required_identifier(id, "volume id"), node_id: node.to_s,
          secrets: string_map(secrets, "secrets")
        )
        rpc(:controller, :controller_unpublish_volume, request,
            response_class: Csi::V1::ControllerUnpublishVolumeResponse,
            operation: "ControllerUnpublishVolume", idempotent_absent: true)
        {}
      end

      def create_snapshot(id, token:, name: nil, secrets: {}, parameters: {})
        ensure_controller_rpc!("CREATE_DELETE_SNAPSHOT", "CreateSnapshot")
        source_id = required_identifier(id, "volume id")
        token = required_token(token)
        snapshot_name = name.to_s.empty? ? "snapshot-#{source_id}-#{token}" : name.to_s
        request = Csi::V1::CreateSnapshotRequest.new(
          source_volume_id: source_id, name: snapshot_name,
          secrets: string_map(secrets, "secrets"), parameters: string_map(parameters, "parameters")
        )
        response = rpc(:controller, :create_snapshot, request, response_class: Csi::V1::CreateSnapshotResponse,
                                                               operation: "CreateSnapshot")
        snapshot = response.snapshot
        raise CSIError.new("CSI CreateSnapshot returned no snapshot", operation: "CreateSnapshot") unless snapshot

        snapshot_hash(snapshot).merge("snapshot" => snapshot_hash(snapshot))
      end

      def delete_snapshot(id, token: nil, secrets: {})
        ensure_controller_rpc!("CREATE_DELETE_SNAPSHOT", "DeleteSnapshot")
        request = Csi::V1::DeleteSnapshotRequest.new(snapshot_id: required_identifier(id, "snapshot id"),
                                                     secrets: string_map(secrets, "secrets"))
        rpc(:controller, :delete_snapshot, request, response_class: Csi::V1::DeleteSnapshotResponse,
                                                    operation: "DeleteSnapshot", idempotent_absent: true)
        {}
      end

      def list_snapshots(token: nil, source_volume_id: nil, snapshot_id: nil, max_entries: 0, starting_token: nil,
                         secrets: {})
        ensure_controller_rpc!("LIST_SNAPSHOTS", "ListSnapshots")
        max_entries = Integer(max_entries || 0)
        raise ValidationError, "ListSnapshots max_entries must be non-negative" if max_entries.negative?

        request = Csi::V1::ListSnapshotsRequest.new(
          max_entries: max_entries, starting_token: starting_token.to_s,
          source_volume_id: source_volume_id.to_s, snapshot_id: snapshot_id.to_s,
          secrets: string_map(secrets, "secrets")
        )
        response = rpc(:controller, :list_snapshots, request, response_class: Csi::V1::ListSnapshotsResponse,
                                                              operation: "ListSnapshots", mutating: false)
        {"entries" => response.entries.map { |entry| snapshot_hash(entry.snapshot) }, "nextToken" => response.next_token.to_s}
      rescue ArgumentError, TypeError => error
        raise ValidationError, "ListSnapshots max_entries must be a non-negative integer: #{error.message}"
      end

      def list_volumes(token: nil, max_entries: 0, starting_token: nil)
        ensure_controller_rpc!("LIST_VOLUMES", "ListVolumes")
        max_entries = Integer(max_entries || 0)
        raise ValidationError, "ListVolumes max_entries must be non-negative" if max_entries.negative?

        request = Csi::V1::ListVolumesRequest.new(max_entries: max_entries,
                                                  starting_token: starting_token.to_s)
        response = rpc(:controller, :list_volumes, request, response_class: Csi::V1::ListVolumesResponse,
                                                            operation: "ListVolumes", mutating: false)
        entries = response.entries.map do |entry|
          value = volume_hash(entry.volume)
          if entry.status
            value["status"] = {
              "publishedNodeIds" => entry.status.published_node_ids.map(&:to_s),
              "volumeCondition" => entry.status.volume_condition&.to_h
            }.compact
          end
          value
        end
        {"entries" => entries, "nextToken" => response.next_token.to_s}
      rescue ArgumentError, TypeError => error
        raise ValidationError, "ListVolumes max_entries must be a non-negative integer: #{error.message}"
      end

      def expand(id, capacity, token:, secrets: {}, volume_capability: nil)
        ensure_controller_rpc!("EXPAND_VOLUME", "ControllerExpandVolume")
        request = Csi::V1::ControllerExpandVolumeRequest.new(
          volume_id: required_identifier(id, "volume id"), capacity_range: capacity_range_for("capacity" => capacity),
          secrets: string_map(secrets, "secrets"),
          volume_capability: volume_capability && volume_capability_for(volume_capability)
        )
        response = rpc(:controller, :controller_expand_volume, request,
                       response_class: Csi::V1::ControllerExpandVolumeResponse,
                       operation: "ControllerExpandVolume")
        {"capacityBytes" => response.capacity_bytes, "nodeExpansionRequired" => response.node_expansion_required}
      end

      def stage(id, path, token:, readonly: false, context: {})
        ensure_node_rpc!("STAGE_UNSTAGE_VOLUME", "NodeStageVolume")
        context = hash_value(context, "stage context")
        readonly = effective_readonly?(context, readonly)
        request = Csi::V1::NodeStageVolumeRequest.new(
          volume_id: required_identifier(id, "volume id"), staging_target_path: required_path(path, "staging target path"),
          publish_context: string_map(Types.key(context, "publishContext", Types.key(context, "publish_context", {})),
                                      "publish context"),
          volume_capability: volume_capability_for(context, readonly: readonly),
          secrets: string_map(Types.key(context, "secrets", {}), "secrets"),
          volume_context: string_map(Types.key(context, "volumeContext", Types.key(context, "volume_context", {})),
                                     "volume context")
        )
        rpc(:node, :node_stage_volume, request, response_class: Csi::V1::NodeStageVolumeResponse,
                                                operation: "NodeStageVolume")
        {"volumeId" => id.to_s, "source" => "csi://#{id}", "target" => path.to_s, "stage" => true}
      end

      def unstage(id, path, token:)
        ensure_node_rpc!("STAGE_UNSTAGE_VOLUME", "NodeUnstageVolume")
        request = Csi::V1::NodeUnstageVolumeRequest.new(volume_id: required_identifier(id, "volume id"),
                                                        staging_target_path: required_path(path, "staging target path"))
        rpc(:node, :node_unstage_volume, request, response_class: Csi::V1::NodeUnstageVolumeResponse,
                                                  operation: "NodeUnstageVolume", idempotent_absent: true)
        {}
      end

      def publish_node(id, stage_path, target, token:, readonly: false, context: {})
        context = hash_value(context, "node publish context")
        readonly = effective_readonly?(context, readonly)
        request = Csi::V1::NodePublishVolumeRequest.new(
          volume_id: required_identifier(id, "volume id"),
          staging_target_path: stage_path.to_s,
          target_path: required_path(target, "target path"), readonly: readonly == true,
          publish_context: string_map(Types.key(context, "publishContext", Types.key(context, "publish_context", {})),
                                      "publish context"),
          volume_capability: volume_capability_for(context, readonly: readonly),
          secrets: string_map(Types.key(context, "secrets", {}), "secrets"),
          volume_context: string_map(Types.key(context, "volumeContext", Types.key(context, "volume_context", {})),
                                     "volume context")
        )
        response = rpc(:node, :node_publish_volume, request, response_class: Csi::V1::NodePublishVolumeResponse,
                                                             operation: "NodePublishVolume")
        {"volumeId" => id.to_s, "source" => "csi://#{id}", "target" => target.to_s, "stage" => false,
         "readonly" => readonly == true, "response" => response.to_h}
      end

      def unpublish_node(id, target, token:)
        request = Csi::V1::NodeUnpublishVolumeRequest.new(volume_id: required_identifier(id, "volume id"),
                                                          target_path: required_path(target, "target path"))
        rpc(:node, :node_unpublish_volume, request, response_class: Csi::V1::NodeUnpublishVolumeResponse,
                                                    operation: "NodeUnpublishVolume", idempotent_absent: true)
        {}
      end

      def stats(id, token: nil, path: nil)
        ensure_node_rpc!("GET_VOLUME_STATS", "NodeGetVolumeStats")
        request = Csi::V1::NodeGetVolumeStatsRequest.new(volume_id: required_identifier(id, "volume id"),
                                                         volume_path: path.to_s)
        response = rpc(:node, :node_get_volume_stats, request, response_class: Csi::V1::NodeGetVolumeStatsResponse,
                                                               operation: "NodeGetVolumeStats", mutating: false)
        usage = response.usage.find { |entry| [:BYTES, 1].include?(entry.unit) } || response.usage.first
        inodes = response.usage.find { |entry| [:INODES, 2].include?(entry.unit) }
        result = {
          "volumeId" => id.to_s, "availableBytes" => usage&.available || 0, "capacityBytes" => usage&.total || 0,
          "usedBytes" => usage&.used || 0, "volumeCondition" => response.volume_condition&.to_h
        }
        if inodes
          result["inodesFree"] = inodes.available
          result["inodes"] = inodes.total
          result["inodesUsed"] = inodes.used
        end
        result.compact
      end

      def expand_node(id, path, token:, capacity_bytes: nil, volume_capability: nil, secrets: {}, staging_path: nil)
        ensure_node_rpc!("EXPAND_VOLUME", "NodeExpandVolume")
        capacity = capacity_bytes.nil? ? Csi::V1::CapacityRange.new : capacity_range_for("capacity" => capacity_bytes)
        request = Csi::V1::NodeExpandVolumeRequest.new(
          volume_id: required_identifier(id, "volume id"), volume_path: required_path(path, "volume path"),
          staging_target_path: (staging_path || path).to_s, capacity_range: capacity,
          volume_capability: volume_capability_for(volume_capability || {}),
          secrets: string_map(secrets, "secrets")
        )
        response = rpc(:node, :node_expand_volume, request, response_class: Csi::V1::NodeExpandVolumeResponse,
                                                            operation: "NodeExpandVolume")
        {"capacityBytes" => response.capacity_bytes}
      end

      # Compatibility entry point used by CSIBridge.  Unlike Object#call
      # dispatch, this table maps each public CSI RPC to a typed method above.
      def invoke(operation, request = {}, token: nil, timeout: nil)
        previous_timeout = Thread.current[@timeout_context_key]
        Thread.current[@timeout_context_key] = Float(timeout) if timeout
        request = hash_value(request, "CSI request")
        case operation.to_s
        when "GetPluginInfo" then identity.to_h
        when "NodeGetInfo" then node_info
        when "NodeGetCapabilities" then {"capabilities" => node_capability_names}
        when "GetPluginCapabilities" then {"capabilities" => plugin_service_names}
        when "Probe" then probe
        when "CreateVolume" then create_volume(request, token: token || Types.key(request, "name"))
        when "DeleteVolume" then delete_volume(Types.key(request, "volumeId"), token: token)
        when "ControllerPublishVolume" then publish(Types.key(request, "volumeId"), Types.key(request, "nodeId"),
                                                    token: token, readonly: Types.key(request, "readonly", false), context: request)
        when "ControllerUnpublishVolume" then unpublish(Types.key(request, "volumeId"), Types.key(request, "nodeId"),
                                                        token: token, context: request)
        when "CreateSnapshot" then create_snapshot(Types.key(request, "sourceVolumeId"), token: token || Types.key(request, "name"),
                                                                                         name: Types.key(request, "name"), secrets: Types.key(request,
                                                                                                                                              "secrets", {}))
        when "DeleteSnapshot" then delete_snapshot(Types.key(request, "snapshotId"), token: token,
                                                                                     secrets: Types.key(request, "secrets", {}))
        when "ListSnapshots"
          list_snapshots(token: token, source_volume_id: Types.key(request, "sourceVolumeId"),
                         snapshot_id: Types.key(request, "snapshotId"), max_entries: Types.key(request, "maxEntries", 0),
                         starting_token: Types.key(request, "startingToken"), secrets: Types.key(request, "secrets", {}))
        when "ListVolumes"
          list_volumes(token: token, max_entries: Types.key(request, "maxEntries", 0),
                       starting_token: Types.key(request, "startingToken"))
        when "ControllerExpandVolume" then expand(
          Types.key(request, "volumeId"), Types.key(request, "capacityRange", {})["requiredBytes"], token: token,
                                                                                                    secrets: Types.key(request, "secrets",
                                                                                                                       {}),
                                                                                                    volume_capability: Types.key(request,
                                                                                                                                 "volumeCapability")
        )
        when "NodeStageVolume" then stage(Types.key(request, "volumeId"), Types.key(request, "stagingTargetPath"), token: token,
                                                                                                                   readonly: Types.key(request, "readonly",
                                                                                                                                       false), context: request)
        when "NodeUnstageVolume" then unstage(Types.key(request, "volumeId"), Types.key(request, "stagingTargetPath"), token: token)
        when "NodePublishVolume" then publish_node(Types.key(request, "volumeId"), Types.key(request, "stagingTargetPath"),
                                                   Types.key(request, "targetPath"), token: token,
                                                                                     readonly: Types.key(request, "readonly", false), context: request)
        when "NodeUnpublishVolume" then unpublish_node(Types.key(request, "volumeId"), Types.key(request, "targetPath"), token: token)
        when "NodeGetVolumeStats" then stats(Types.key(request, "volumeId"), path: Types.key(request, "volumePath"))
        when "NodeExpandVolume" then expand_node(
          Types.key(request, "volumeId"), Types.key(request, "volumePath"), token: token,
                                                                            capacity_bytes: Types.key(Types.key(request, "capacityRange", {}), "requiredBytes"),
                                                                            volume_capability: Types.key(request, "volumeCapability"),
                                                                            secrets: Types.key(request, "secrets", {}),
                                                                            staging_path: Types.key(request, "stagingTargetPath")
        )
        else
          raise CSIUnavailable, "CSI operation #{operation} is not supported by the typed client"
        end
      ensure
        Thread.current[@timeout_context_key] = previous_timeout if timeout
      end

      private

      def plugin_info
        ensure_socket!
        @cache_lock.synchronize do
          @plugin_info ||= rpc(:identity, :get_plugin_info, Csi::V1::GetPluginInfoRequest.new,
                               response_class: Csi::V1::GetPluginInfoResponse, operation: "GetPluginInfo", mutating: false)
        end
      end

      def plugin_capability_response
        ensure_socket!
        @cache_lock.synchronize do
          @plugin_capabilities ||= rpc(:identity, :get_plugin_capabilities, Csi::V1::GetPluginCapabilitiesRequest.new,
                                       response_class: Csi::V1::GetPluginCapabilitiesResponse,
                                       operation: "GetPluginCapabilities", mutating: false)
        end
      end

      def controller_capability_response
        ensure_plugin_controller_service!
        ensure_socket!
        @cache_lock.synchronize do
          @controller_capabilities ||= rpc(:controller, :controller_get_capabilities,
                                           Csi::V1::ControllerGetCapabilitiesRequest.new,
                                           response_class: Csi::V1::ControllerGetCapabilitiesResponse,
                                           operation: "ControllerGetCapabilities", mutating: false)
        end
      end

      def node_capability_response
        ensure_socket!
        @cache_lock.synchronize do
          @node_capabilities ||= rpc(:node, :node_get_capabilities, Csi::V1::NodeGetCapabilitiesRequest.new,
                                     response_class: Csi::V1::NodeGetCapabilitiesResponse,
                                     operation: "NodeGetCapabilities", mutating: false)
        end
      end

      def plugin_service_names
        plugin_capability_response.capabilities.filter_map do |capability|
          next unless capability.has_service?

          enum_name(Csi::V1::PluginCapability::Service::Type, capability.service.type)
        end
      end

      def controller_capability_names
        controller_capability_response.capabilities.filter_map do |capability|
          next unless capability.has_rpc?

          enum_name(Csi::V1::ControllerServiceCapability::RPC::Type, capability.rpc.type)
        end
      end

      def node_capability_names
        node_capability_response.capabilities.filter_map do |capability|
          next unless capability.has_rpc?

          enum_name(Csi::V1::NodeServiceCapability::RPC::Type, capability.rpc.type)
        end
      end

      def ensure_plugin_controller_service!
        return if plugin_service_names.include?("CONTROLLER_SERVICE")

        raise CSIUnavailable, "CSI plugin does not advertise CONTROLLER_SERVICE"
      end

      def ensure_controller_rpc!(name, operation)
        return if controller_capability_names.include?(name)

        raise CSIUnavailable, "CSI plugin does not advertise #{name} for #{operation}"
      end

      def ensure_node_rpc!(name, operation)
        return if node_capability_names.include?(name)

        raise CSIUnavailable, "CSI plugin does not advertise #{name} for #{operation}"
      end

      def rpc(service, method_name, request, response_class:, operation:, idempotent_absent: false, mutating: true)
        ensure_socket!
        stub = {identity: @identity_stub, controller: @controller_stub, node: @node_stub}.fetch(service)
        metadata = @metadata.empty? ? {} : @metadata
        timeout = Thread.current[@timeout_context_key] || @timeout
        response = stub.public_send(method_name, request, metadata: metadata, deadline: Time.now + timeout)
        raise CSIError.new("CSI #{operation} returned no response", operation: operation, ambiguous: mutating) unless response

        # Reject a response if the pathname or accepting peer changed while
        # the RPC was in flight. A self-reported GetPluginInfo identity is not
        # accepted as endpoint ownership proof.
        begin
          ensure_socket!
        rescue CSIUnavailable => error
          # The server may already have applied a mutating RPC before the
          # post-response identity check detects replacement. Preserve that
          # ambiguity so the lifecycle ledger fences rather than retries it.
          raise CSIError.new(
            "CSI #{operation} endpoint identity changed while the RPC was in flight",
            operation: operation, ambiguous: mutating
          ), cause: error
        end

        response
      rescue GRPC::BadStatus => error
        code = error.code
        return response_class.new if idempotent_absent && code == GRPC::Core::StatusCodes::NOT_FOUND

        raise mapped_status_error(operation, code, error, mutating: mutating)
      rescue GRPC::Core::CallError, IOError, SystemCallError => error
        raise CSIError.new("CSI #{operation} transport failed: #{error.message}", operation: operation,
                                                                                  ambiguous: mutating), cause: error
      end

      def mapped_status_error(operation, code, error, mutating:)
        name = status_name(code)
        details = {"grpcCode" => name, "grpcCodeNumber" => code, "grpcDetails" => error.details.to_s}
        message = "CSI #{operation} failed with gRPC #{name}"
        if name == "UNIMPLEMENTED"
          CSIUnavailable.new("#{message}; plugin capability negotiation is incomplete", operation: operation, details: details)
        else
          CSIError.new(message, operation: operation, details: details,
                                ambiguous: mutating && AMBIGUOUS_STATUS_CODES.include?(name.to_sym))
        end
      end

      def status_name(code)
        GRPC::Core::StatusCodes.constants.find { |constant| GRPC::Core::StatusCodes.const_get(constant) == code }&.to_s || "UNKNOWN"
      end

      def ensure_socket!
        observed = observe_endpoint_identity
        @endpoint_lock.synchronize do
          if @endpoint_identity
            raise CSIUnavailable, "CSI Unix socket or peer identity changed after it was pinned" unless observed == @endpoint_identity
          else
            @endpoint_identity = observed.freeze
          end
        end
        true
      end

      def observe_endpoint_identity
        reject_socket_symlink_components!
        stat = File.lstat(@socket)
        raise CSIUnavailable, "CSI endpoint #{@socket} is a symlink" if stat.symlink?
        raise CSIUnavailable, "CSI endpoint #{@socket} exists but is not a Unix socket" unless stat.socket?

        mode = stat.mode & 0o7777
        if @expected_socket_uid && stat.uid != @expected_socket_uid
          raise CSIUnavailable, "CSI socket owner uid #{stat.uid} does not match pinned uid #{@expected_socket_uid}"
        end
        if @expected_socket_gid && stat.gid != @expected_socket_gid
          raise CSIUnavailable, "CSI socket owner gid #{stat.gid} does not match pinned gid #{@expected_socket_gid}"
        end
        if @expected_socket_mode && mode != @expected_socket_mode
          raise CSIUnavailable,
                "CSI socket mode #{format("%04o", mode)} does not match pinned mode #{format("%04o", @expected_socket_mode)}"
        end
        raise CSIUnavailable, "CSI socket must not be world-writable" if @expected_socket_mode.nil? && mode.anybits?(0o002)

        peer_pid, peer_uid, peer_gid = peer_credentials
        raise CSIUnavailable, "CSI peer uid #{peer_uid} does not match pinned uid #{@expected_peer_uid}" if @expected_peer_uid && peer_uid != @expected_peer_uid
        raise CSIUnavailable, "CSI peer gid #{peer_gid} does not match pinned gid #{@expected_peer_gid}" if @expected_peer_gid && peer_gid != @expected_peer_gid

        {
          "device" => stat.dev, "inode" => stat.ino, "uid" => stat.uid, "gid" => stat.gid,
          "mode" => mode, "peerPid" => peer_pid, "peerUid" => peer_uid, "peerGid" => peer_gid
        }
      rescue Errno::ENOENT
        raise CSIUnavailable, "CSI Unix socket #{@socket} is unavailable"
      rescue CSIUnavailable
        raise
      rescue SystemCallError, IOError => error
        raise CSIUnavailable, "CSI Unix socket identity could not be verified: #{error.message}"
      end

      def reject_socket_symlink_components!
        current = File::SEPARATOR
        Pathname.new(@socket).each_filename do |component|
          current = File.join(current, component)
          stat = File.lstat(current)
          raise CSIUnavailable, "CSI socket path contains a symlink component" if stat.symlink?
        rescue Errno::ENOENT
          raise CSIUnavailable, "CSI Unix socket #{@socket} is unavailable"
        end
        true
      end

      def peer_credentials
        raise CSIUnavailable, "CSI peer credentials are unavailable on this platform" unless Socket.const_defined?(:SO_PEERCRED)

        connection = UNIXSocket.new(@socket)
        payload = connection.getsockopt(Socket::SOL_SOCKET, Socket::SO_PEERCRED).to_s
        values = payload.unpack("i!I!I!")
        raise CSIUnavailable, "CSI peer credentials are incomplete" unless values.length == 3

        values
      ensure
        connection&.close
      end

      def optional_identity(value, field)
        return nil if value.nil?

        result = Integer(value)
        raise ValidationError, "#{field} must be non-negative" if result.negative?

        result
      rescue ArgumentError, TypeError
        raise ValidationError, "#{field} must be a non-negative integer"
      end

      def optional_mode(value)
        return nil if value.nil?

        result = value.is_a?(String) ? Integer(value, 8) : Integer(value)
        raise ValidationError, "CSI socket mode must be between 0000 and 07777" unless result.between?(0, 0o7777)

        result
      rescue ArgumentError, TypeError
        raise ValidationError, "CSI socket mode must be an octal string or integer"
      end

      def normalize_socket(value)
        raw = String(value).strip
        raw = raw.delete_prefix("unix://") if raw.start_with?("unix://")
        raise ValidationError, "CSI socket path must be absolute" unless raw.start_with?("/")
        raise ValidationError, "CSI socket path must not contain a NUL" if raw.include?("\0")
        raise ValidationError, "CSI socket path exceeds the Unix socket limit" if raw.bytesize >= 108

        raw.freeze
      rescue TypeError
        raise ValidationError, "CSI socket path must be a string"
      end

      def hash_value(value, field)
        hash = value.respond_to?(:to_h) ? value.to_h : nil
        raise ValidationError, "#{field} must be a map" unless hash.respond_to?(:each)

        hash.transform_keys(&:to_s)
      end

      def string_map(value, field)
        hash = hash_value(value || {}, field)
        hash.each_with_object({}) do |(key, child), result|
          result[String(key)] = String(child)
        rescue TypeError
          raise ValidationError, "#{field} values must be strings"
        end
      end

      def required_identifier(value, field)
        text = String(value)
        raise ValidationError, "#{field} must not be empty" if text.empty?
        raise ValidationError, "#{field} contains a NUL" if text.include?("\0")

        text
      rescue TypeError
        raise ValidationError, "#{field} must be a string"
      end

      def required_path(value, field)
        path = required_identifier(value, field)
        raise ValidationError, "#{field} must be absolute" unless path.start_with?("/")

        path
      end

      def required_token(value)
        required_identifier(value, "CSI operation token")
      end

      def capacity_range_for(spec)
        spec = hash_value(spec, "capacity spec")
        range = Types.key(spec, "capacityRange")
        if range
          range = hash_value(range, "capacityRange")
          required = Integer(Types.key(range, "requiredBytes", Types.key(range, "required_bytes", 0)))
          limit = Integer(Types.key(range, "limitBytes", Types.key(range, "limit_bytes", 0)))
          raise CapacityError, "capacity range values must be non-negative" if required.negative? || limit.negative?
          raise CapacityError, "capacity range limit is smaller than required capacity" if limit.positive? && required > limit

          return Csi::V1::CapacityRange.new(
            required_bytes: required,
            limit_bytes: limit
          )
        end
        value = Types.key(spec, "capacityBytes", Types.key(spec, "capacity", nil))
        return Csi::V1::CapacityRange.new if value.nil?

        bytes = Types.parse_capacity(value)
        Csi::V1::CapacityRange.new(required_bytes: bytes, limit_bytes: bytes)
      rescue ArgumentError, TypeError => error
        raise CapacityError, "CSI capacity range is invalid: #{error.message}"
      end

      def content_source_for(spec)
        snapshot_id = Types.key(spec, "sourceSnapshotId", Types.key(spec, "snapshotId"))
        if snapshot_id && !snapshot_id.to_s.empty?
          return Csi::V1::VolumeContentSource.new(
            snapshot: Csi::V1::VolumeContentSource::SnapshotSource.new(snapshot_id: snapshot_id.to_s)
          )
        end

        volume_id = Types.key(spec, "cloneSourceId", Types.key(spec, "sourceVolumeId"))
        if volume_id && !volume_id.to_s.empty?
          return Csi::V1::VolumeContentSource.new(
            volume: Csi::V1::VolumeContentSource::VolumeSource.new(volume_id: volume_id.to_s)
          )
        end

        nil
      end

      def volume_capabilities_for(spec)
        explicit = Types.key(spec, "volumeCapabilities", Types.key(spec, "volumeCapability"))
        values = if explicit
                   explicit.is_a?(Array) ? explicit : [explicit]
                 else
                   access_modes = Array(Types.key(spec, "accessModes", ["ReadWriteOnce"]))
                   access_modes.map { |mode| {"accessMode" => mode, "volumeMode" => Types.key(spec, "volumeMode", "Filesystem")} }
                 end
        values.map { |value| volume_capability_for(value) }
      end

      def volume_capability_for(value, readonly: false)
        value = hash_value(value || {}, "volume capability")
        mode = Types.key(value, "accessMode", Types.key(value, "access_mode"))
        if mode.nil?
          modes = Array(Types.key(value, "accessModes", []))
          mode = modes.first unless modes.empty?
        end
        mode ||= "ReadWriteOnce"
        mode = mode.to_h if mode.respond_to?(:to_h)
        mode = Types.key(mode, "mode", mode) if mode.is_a?(Hash)
        mode_name = ACCESS_MODE_NAMES.fetch(mode.to_s) { raise ValidationError, "unsupported CSI access mode #{mode.inspect}" }
        capability = Types.key(value, "block") || Types.key(value, "volumeMode", "Filesystem").to_s.casecmp?("Block")
        if capability
          Csi::V1::VolumeCapability.new(
            block: Csi::V1::VolumeCapability::BlockVolume.new,
            access_mode: Csi::V1::VolumeCapability::AccessMode.new(
              mode: Csi::V1::VolumeCapability::AccessMode::Mode.const_get(mode_name)
            )
          )
        else
          mount = Types.key(value, "mount", {})
          mount = hash_value(mount, "mount capability")
          flags = Array(Types.key(mount, "mountFlags", Types.key(mount, "mount_flags", []))).map(&:to_s)
          flags << "ro" if readonly == true && !flags.include?("ro")
          Csi::V1::VolumeCapability.new(
            mount: Csi::V1::VolumeCapability::MountVolume.new(
              fs_type: Types.key(mount, "fsType", Types.key(mount, "fs_type", "")).to_s,
              mount_flags: flags,
              volume_mount_group: Types.key(mount, "volumeMountGroup", Types.key(mount, "volume_mount_group", "")).to_s
            ),
            access_mode: Csi::V1::VolumeCapability::AccessMode.new(
              mode: Csi::V1::VolumeCapability::AccessMode::Mode.const_get(mode_name)
            )
          )
        end
      end

      def effective_readonly?(value, requested)
        return true if requested == true

        value = hash_value(value || {}, "volume capability context")
        modes = Array(Types.key(value, "accessModes", []))
        explicit = Types.key(value, "accessMode", Types.key(value, "access_mode"))
        modes << explicit if explicit
        capability = Types.key(value, "volumeCapability")
        if capability.respond_to?(:to_h)
          nested = capability.to_h
          modes.concat(Array(Types.key(nested, "accessModes", [])))
          nested_explicit = Types.key(nested, "accessMode", Types.key(nested, "access_mode"))
          modes << nested_explicit if nested_explicit
        end
        modes.any? do |mode|
          value = mode.respond_to?(:to_h) ? Types.key(mode.to_h, "mode", mode) : mode
          %w[ReadOnlyMany MULTI_NODE_READER_ONLY SINGLE_NODE_READER_ONLY].include?(value.to_s)
        end
      end

      def volume_hash(volume)
        {
          "volumeId" => volume.volume_id.to_s,
          "capacityBytes" => volume.capacity_bytes,
          "volumeContext" => string_map(volume.volume_context, "volume context"),
          "contentSource" => volume.content_source&.to_h,
          "accessibleTopology" => volume.accessible_topology.map(&:to_h)
        }.compact
      end

      def snapshot_hash(snapshot)
        raise CSIError.new("CSI snapshot response contained no snapshot", operation: "snapshot") unless snapshot

        {
          "snapshotId" => snapshot.snapshot_id.to_s,
          "sizeBytes" => snapshot.size_bytes,
          "sourceVolumeId" => snapshot.source_volume_id.to_s,
          "creationTime" => timestamp_string(snapshot.creation_time),
          "readyToUse" => snapshot.ready_to_use,
          "groupSnapshotId" => snapshot.group_snapshot_id.to_s
        }.compact
      end

      def timestamp_string(timestamp)
        return nil unless timestamp

        Time.at(timestamp.seconds, timestamp.nanos, :nsec).utc.iso8601(9)
      end

      def enum_name(enum_module, value)
        return value.to_s if enum_module.constants.map(&:to_s).include?(value.to_s)

        enum_module.constants.find { |constant| enum_module.const_get(constant) == value }.to_s
      end

      class << self
        def load_grpc!
          return true if defined?(Csi::V1::Identity::Stub)

          require "grpc"
          require_relative "generated/csi_services_pb"
          true
        rescue LoadError => error
          raise CSIUnavailable, "CSI gRPC dependencies are unavailable: #{error.message}"
        end
      end
    end

    CsiUdsClient = CSIUDSClient unless const_defined?(:CsiUdsClient, false)
    UDSClient = CSIUDSClient unless const_defined?(:UDSClient, false)
  end
end
