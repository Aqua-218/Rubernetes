# frozen_string_literal: true

require "json"

require_relative "../client/errors"
require_relative "../volume/csi"
require_relative "../volume/kubernetes_csi"

module Rubernetes
  module Node
    # The kubelet's CSI plugin handler (pkg/volume/csi/csi_plugin.go and
    # nodeinfomanager, v1.36.2).  A node plugin registering under the plugin
    # registry as type CSIPlugin is asked NodeGetInfo, and the node is
    # published to the cluster:
    #
    #   * CSINode <node> (owned by the Node) lists the driver with its
    #     nodeID, topologyKeys and allocatable.count
    #   * the Node's csi.volume.kubernetes.io/nodeid annotation maps the
    #     driver to its node ID
    #   * each accessible-topology segment becomes a Node label
    #
    # Deregistration removes the CSINode entry and the annotation key (the
    # topology labels stay, as upstream).  The volume manager resolves a
    # volume's driver through #for_driver.
    class CSIPlugins
      TYPE = "CSIPlugin"
      NODE_ID_ANNOTATION = "csi.volume.kubernetes.io/nodeid"
      # v1.MigratedPluginsAnnotationKey: the in-tree plugins this node serves
      # through CSI (csi_plugin.go's migratedPlugins; all migrations are GA
      # in 1.36, so every entry is on).  The attach/detach controller reads
      # it to pick the CSI path for those volumes.
      MIGRATED_PLUGINS_ANNOTATION = "storage.alpha.kubernetes.io/migrated-plugins"
      MIGRATED_PLUGINS = %w[kubernetes.io/aws-ebs kubernetes.io/azure-disk kubernetes.io/azure-file kubernetes.io/cinder
                            kubernetes.io/gce-pd kubernetes.io/portworx-volume kubernetes.io/vsphere-volume].freeze
      STORAGE_VERSION = "storage.k8s.io/v1"
      CONFLICT_RETRIES = 5
      MAX_INT32 = (2**31) - 1

      class Error < StandardError; end

      Driver = Struct.new(:name, :endpoint, :version, :adapter, keyword_init: true)

      # The narrow API the KubernetesCSIAdapter needs.
      class API
        def initialize(client)
          @client = client
        end

        def get(resource, name, namespace: nil, api_version: "v1")
          @client.get(resource, name, namespace: namespace, api_version: api_version)
        rescue Client::APIError => e
          raise unless e.status == 404

          nil
        end

        def create_token(namespace, service_account, request)
          @client.create(request, namespace: namespace, api_version: "v1",
                                  path: "/api/v1/namespaces/#{namespace}/serviceaccounts/#{service_account}/token")
        end
      end

      # +bridge_factory+: endpoint => CSIBridge-like (tests inject one).
      def initialize(client:, node_name:, bridge_factory: nil, adapter_options: {}, error_handler: nil)
        @client = client
        @api = API.new(client)
        @node_name = node_name.to_s
        @bridge_factory = bridge_factory || ->(endpoint) { Volume::CSIBridge.new(socket: endpoint, timeout: 30) }
        @adapter_options = adapter_options
        @error_handler = error_handler
        @drivers = {}
        @mutex = Mutex.new
        @csi_node_ready = false
      end

      # ------------------------------------------------ plugin handler

      # csi_plugin.go ValidatePlugin: a 1.x version must be offered.
      def validate_plugin(name, _endpoint, versions)
        raise Error, "RegisterPlugin error -- plugin name is empty" if name.to_s.empty?

        highest_supported_version(name, versions)
        true
      end

      # ->(driver_name, method_name, grpc_status_code, seconds), handed to
      # every driver's bridge (csi_operations_seconds).
      attr_accessor :metrics_observer

      def register_plugin(name, endpoint, versions)
        name = name.to_s
        version = highest_supported_version(name, versions)
        @mutex.synchronize do
          existing = @drivers[name]
          if existing && existing.version && compare_versions(existing.version, version).positive?
            raise Error, "RegisterPlugin error -- an existing CSI driver #{name} with a newer version #{existing.version} is registered"
          end
        end
        bridge = @bridge_factory.call(endpoint.to_s)
        # csi_operations_seconds: every RPC of this driver, by name.
        bridge.driver_name = name if bridge.respond_to?(:driver_name=)
        bridge.metrics_observer = @metrics_observer if bridge.respond_to?(:metrics_observer=)
        adapter = Volume::KubernetesCSIAdapter.new(driver: name, bridge: bridge, api: @api, node_name: @node_name, **@adapter_options)
        driver = Driver.new(name: name, endpoint: endpoint.to_s, version: version, adapter: adapter)
        @mutex.synchronize { @drivers[name] = driver }
        begin
          info = bridge.node_info
          node_id = info["nodeId"].to_s
          raise Error, "RegisterPlugin error -- NodeGetInfo of #{name} returned an empty node ID" if node_id.empty?

          install_driver(name, node_id, info["maxVolumesPerNode"].to_i, (info["topology"] || {}).to_h)
        rescue StandardError => e
          @mutex.synchronize { @drivers.delete(name) if @drivers[name].equal?(driver) }
          begin
            uninstall_driver(name)
          rescue StandardError => cleanup
            @error_handler&.call(cleanup, :csi_plugin_unregister)
          end
          raise Error, "RegisterPlugin error -- plugin registration failed with err: #{e.message}"
        end
        true
      end

      def deregister_plugin(name, endpoint)
        name = name.to_s
        removed = @mutex.synchronize do
          driver = @drivers[name]
          next false unless driver && (endpoint.to_s.empty? || driver.endpoint == endpoint.to_s)

          @drivers.delete(name)
          true
        end
        uninstall_driver(name) if removed
        true
      end

      # ------------------------------------------------ volume lookup

      def for_driver(name)
        driver = @mutex.synchronize { @drivers[name.to_s] }
        raise Volume::CSIUnavailable, "driver name #{name} not found in the list of registered CSI drivers" unless driver

        driver.adapter
      end

      def registered_drivers
        @mutex.synchronize { @drivers.keys.sort }
      end

      # InitializeCSINodeWithAnnotation: the kubelet makes sure its CSINode
      # exists (with no drivers, the migrated-plugins annotation set) before
      # any plugin registers.
      def initialize_csi_node
        return true if @csi_node_ready

        update_csi_node { |drivers| drivers }
        @csi_node_ready = true
      end

      # setMigrationAnnotation: the sorted, comma-joined migrated plugins;
      # true when the annotation had to change.
      def self.set_migration_annotation(csi_node, plugins = MIGRATED_PLUGINS)
        annotations = (csi_node.dig("metadata", "annotations") || {}).dup
        current = annotations[MIGRATED_PLUGINS_ANNOTATION].to_s
        old_set = current.empty? ? [] : current.split(",").sort.uniq
        new_set = plugins.map(&:to_s).sort.uniq
        return false if old_set == new_set

        if new_set.empty?
          annotations.delete(MIGRATED_PLUGINS_ANNOTATION)
        else
          annotations[MIGRATED_PLUGINS_ANNOTATION] = new_set.join(",")
        end
        (csi_node["metadata"] ||= {})["annotations"] = annotations
        true
      end

      # keepAllocatableCount: the new limit needs no CSINode update.
      def self.keep_allocatable_count?(driver, max_volumes)
        count = driver.dig("allocatable", "count")
        return count.nil? if max_volumes.zero?

        !count.nil? && Integer(count) == max_volumes
      end

      private

      def highest_supported_version(name, versions)
        candidates = Array(versions).map(&:to_s).select { |version| version.delete_prefix("v").split(".").first == "1" }
        if candidates.empty?
          raise Error,
                "RegisterPlugin error -- none of the versions specified #{Array(versions).inspect} are supported by CSI driver #{name}; supported: 1.x"
        end

        candidates.max { |left, right| compare_versions(left, right) }
      end

      def compare_versions(left, right)
        parse = ->(value) { value.to_s.delete_prefix("v").split(".").map(&:to_i) }
        parse.call(left) <=> parse.call(right)
      end

      def install_driver(name, node_id, max_volumes, topology)
        update_node do |annotations, labels|
          ids = parse_node_ids(annotations[NODE_ID_ANNOTATION])
          ids[name] = node_id
          annotations[NODE_ID_ANNOTATION] = JSON.generate(ids.sort.to_h)
          topology.each do |key, value|
            existing = labels[key.to_s]
            if existing && existing != value.to_s
              raise Error, "detected topology value collision: driver reported #{key}:#{value} but existing label is #{key}:#{existing}"
            end

            labels[key.to_s] = value.to_s
          end
        end
        update_csi_node do |drivers|
          # installDriverToCSINode: an entry that already says the same
          # (node ID, topology keys as a set, allocatable count) is kept.
          topology_keys = topology.keys.map(&:to_s).sort
          existing = drivers.find { |driver| driver["name"] == name }
          if existing && existing["nodeID"].to_s == node_id && Array(existing["topologyKeys"]).map(&:to_s).sort.uniq == topology_keys &&
             self.class.keep_allocatable_count?(existing, max_volumes)
            next drivers
          end

          entry = {"name" => name, "nodeID" => node_id, "topologyKeys" => topology_keys}
          if max_volumes.positive?
            # An attach limit beyond int32 is truncated (with a warning upstream).
            entry["allocatable"] = {"count" => [max_volumes, MAX_INT32].min}
          elsif max_volumes.negative?
            # "Invalid attach limit value %d cannot be added to CSINode object": no allocatable.
            @error_handler&.call(Error.new("Invalid attach limit value #{max_volumes} cannot be added to CSINode object for #{name.inspect}"),
                                 :csi_plugin_attach_limit)
          end
          drivers.reject { |driver| driver["name"] == name } + [entry]
        end
      end

      def uninstall_driver(name)
        update_csi_node { |drivers| drivers.reject { |driver| driver["name"] == name } }
        update_node do |annotations, _labels|
          ids = parse_node_ids(annotations[NODE_ID_ANNOTATION])
          next unless ids.key?(name)

          ids.delete(name)
          if ids.empty?
            annotations.delete(NODE_ID_ANNOTATION)
          else
            annotations[NODE_ID_ANNOTATION] = JSON.generate(ids.sort.to_h)
          end
        end
      end

      def parse_node_ids(value)
        return {} if value.to_s.empty?

        parsed = JSON.parse(value.to_s)
        parsed.is_a?(Hash) ? parsed.transform_values(&:to_s) : {}
      rescue JSON::ParserError
        {}
      end

      # Read-modify-write the Node's annotations and labels with the
      # resourceVersion as precondition.
      def update_node
        with_conflict_retries do
          node = @client.get("nodes", @node_name, api_version: "v1")
          metadata = (node["metadata"] ||= {})
          annotations = (metadata["annotations"] || {}).dup
          labels = (metadata["labels"] || {}).dup
          yield annotations, labels
          next if annotations == (metadata["annotations"] || {}) && labels == (metadata["labels"] || {})

          metadata["annotations"] = annotations
          metadata["labels"] = labels
          @client.update(node)
        end
      end

      # tryUpdateCSINode / CreateCSINode: the CSINode is created (owned by
      # this Node, annotated) when missing; one owned by another Node of the
      # same name (a recreated Node, another UID) is deleted first
      # (ensureNodeOwnsCSINode) and created again; otherwise the drivers and
      # the migration annotation are updated when they changed.
      def update_csi_node
        with_conflict_retries do
          node = @client.get("nodes", @node_name, api_version: "v1")
          node_uid = node.dig("metadata", "uid").to_s
          existing = @api.get("csinodes", @node_name, api_version: STORAGE_VERSION)
          if existing && !owned_by?(existing, node_uid)
            @client.delete("csinodes", @node_name, api_version: STORAGE_VERSION) if @client.respond_to?(:delete)
            existing = nil
          end
          if existing.nil?
            drivers = yield([])
            object = {"apiVersion" => STORAGE_VERSION, "kind" => "CSINode",
                      "metadata" => {"name" => @node_name,
                                     "ownerReferences" => [{"apiVersion" => "v1", "kind" => "Node", "name" => @node_name,
                                                            "uid" => node_uid}]},
                      "spec" => {"drivers" => drivers}}
            self.class.set_migration_annotation(object)
            @client.create(object, api_version: STORAGE_VERSION)
          else
            spec = (existing["spec"] ||= {})
            current = Array(spec["drivers"])
            drivers = yield(current)
            annotation_modified = self.class.set_migration_annotation(existing)
            next if drivers == current && !annotation_modified

            spec["drivers"] = drivers
            @client.update(existing)
          end
        end
      end

      # nodeOwnsCSINode: an owner reference to a Node of this name and UID.
      def owned_by?(csi_node, node_uid)
        Array(csi_node.dig("metadata", "ownerReferences")).any? do |reference|
          reference["kind"] == "Node" && reference["name"] == @node_name && reference["uid"].to_s == node_uid
        end
      end

      def with_conflict_retries
        attempts = 0
        begin
          yield
        rescue Client::APIError => e
          attempts += 1
          raise unless [409].include?(e.status) && attempts < CONFLICT_RETRIES

          retry
        end
      end
    end
  end
end
