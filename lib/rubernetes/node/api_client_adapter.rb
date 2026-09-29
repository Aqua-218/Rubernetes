# frozen_string_literal: true

# Kubernetes REST adapter used by the node agent.  The node layer deliberately
# speaks a small list/watch/apply/report contract; this class owns the concrete
# Kubernetes resource paths and keeps subresource writes explicit.

require "json"
require "uri"

require_relative "../client/kubernetes_client"

module Rubernetes
  module Node
    class APIClientAdapter
      POD_RESOURCE = "pods".freeze
      POD_API_VERSION = "v1".freeze
      NODE_RESOURCE = "nodes".freeze
      LEASE_API_VERSION = "coordination.k8s.io/v1".freeze
      LEASE_NAMESPACE = "kube-node-lease".freeze
      LEASE_RESOURCE = "leases".freeze
      # Kept for callers that still apply through this adapter; kubelet
      # itself sends no fieldManager, so its writes are recorded under its
      # user agent ("kubelet").
      DEFAULT_FIELD_MANAGER = "kubelet".freeze

      attr_reader :client, :node_name, :lease_namespace, :field_manager

      # Whether this adapter created the Node object (kubelet's
      # RecordRegisteredNewNode); finding it already there does not count.
      def node_created? = @state_mutex.synchronize { @state[:created] == true }

      def initialize(client:, node_name:, lease_namespace: LEASE_NAMESPACE,
                     field_manager: DEFAULT_FIELD_MANAGER)
        raise ArgumentError, "client is required" unless client

        @node_name = validate_path_segment(node_name, "node_name")
        @lease_namespace = validate_path_segment(lease_namespace, "lease_namespace")
        @field_manager = String(field_manager)
        raise ArgumentError, "field_manager must not be empty" if @field_manager.empty?

        @client = client
        # Whether the Node is known to exist and the latest Lease written
        # (the lease controller's latestLease), shared by the agent's
        # threads.
        @state = {node: false, lease: nil}
        @state_mutex = Mutex.new
        freeze
      end

      # Lists only Pods assigned to this node.  The field selector is sent to
      # the API server rather than filtering a cluster-wide response locally so
      # that watch/list resource versions retain Kubernetes ordering semantics.
      #
      # The namespace is explicitly every namespace: without it the client falls
      # back to the kubeconfig context namespace and the node would only ever
      # run the pods that happen to live in "default".
      def list(node_name: @node_name, resource_version: nil)
        ensure_node_name!(node_name)
        query = pod_query(resource_version: resource_version)
        normalize_list(@client.get(POD_RESOURCE, api_version: POD_API_VERSION, namespace: :all, query: query))
      end

      alias list_pods list

      # Generic reads for the objects a Pod start depends on (ConfigMaps,
      # Secrets, Services, claims).  Cluster-scoped resources pass a nil
      # namespace.  A 404 surfaces as the client's APIError and is turned into
      # "absent" by ResourceReader; every other failure propagates.
      def read_object(resource, name, namespace: nil, api_version: "v1")
        response = @client.get(String(resource), String(name), namespace: namespace, api_version: api_version)
        stringify_keys(response_body(response))
      end

      def list_objects(resource, namespace: nil, api_version: "v1")
        scope = namespace.nil? ? nil : (namespace == :all ? :all : String(namespace))
        response = @client.get(String(resource), api_version: api_version, namespace: scope)
        stringify_keys(response_body(response))
      end

      # Returns an Enumerator when the client supports streaming watches.  A
      # bounded parsed watch is used for small injected clients that only expose
      # KubernetesClient#watch.
      def watch(node_name: @node_name, resource_version: nil, timeout: nil)
        ensure_node_name!(node_name)
        query = pod_query(resource_version: resource_version, timeout: timeout)
        if @client.respond_to?(:watch_each)
          return @client.watch_each(POD_RESOURCE, api_version: POD_API_VERSION, namespace: :all, query: query)
        end
        unless @client.respond_to?(:watch)
          raise ArgumentError, "client must implement watch_each or watch for Pod watches"
        end

        @client.watch(POD_RESOURCE, api_version: POD_API_VERSION, namespace: :all, query: query,
                      return_response: false)
      end

      alias watch_pods watch

      # Stop a transport-owned watch that is currently being consumed by the
      # SyncLoop.  The client may expose only an Enumerator for watch_each;
      # closing the underlying client is the ownership boundary that reaches a
      # closeable streaming response in that case.
      def close
        @client.close if @client.respond_to?(:close)
        self
      end

      # kubelet registerWithAPIServer / tryUpdateNodeStatus: the Node is
      # created once; when it exists (409, or on every later report) its
      # labels, annotations and status go to the status subresource as a
      # patch (nodeutil.PatchNodeStatus), which leaves spec to its owners.
      def register_node(node)
        object = normalize_object(node, expected_kind: "Node")
        name = metadata_name(object)
        unless @state_mutex.synchronize { @state[:node] }
          begin
            created = @client.create(object, api_version: POD_API_VERSION)
            @state_mutex.synchronize do
              @state[:node] = true
              @state[:created] = true
            end
            return stringify_keys(response_body(created))
          rescue Client::APIError => error
            raise unless error.status.to_i == 409

            @state_mutex.synchronize { @state[:node] = true }
          end
        end
        patch_node(name, object)
      rescue Client::APIError => error
        # The Node was deleted under us: register it again next time.
        @state_mutex.synchronize { @state[:node] = false } if error.status.to_i == 404
        raise
      end

      alias apply_node register_node

      def patch_node(name, object)
        body = {}
        metadata = (object["metadata"] || {}).slice("labels", "annotations")
        body["metadata"] = metadata unless metadata.empty?
        body["status"] = deep_copy(object["status"]) if object["status"]
        return nil if body.empty?

        path = "/api/#{POD_API_VERSION}/#{NODE_RESOURCE}/#{escape_path(name)}/status"
        stringify_keys(response_body(@client.patch(path, body, type: :merge)))
      end

      # A merge patch of the Node's status subresource; nil values remove keys.
      def patch_node_status(name, status)
        path = "/api/#{POD_API_VERSION}/#{NODE_RESOURCE}/#{escape_path(name)}/status"
        @client.patch(path, {"status" => deep_copy(status)}, type: :merge)
      end

      # The node lease controller (component-helpers lease.controller): the
      # Lease is created when missing and otherwise renewed with an Update of
      # the latest one written, re-read after a conflict.  Leases are served
      # by the coordination API group, never the core API.
      def renew_lease(lease)
        object = normalize_object(lease, expected_kind: "Lease")
        namespace = metadata_value(object, "namespace", @lease_namespace)
        name = metadata_name(object)
        path = "/apis/#{LEASE_API_VERSION}/namespaces/#{escape_path(namespace)}/#{LEASE_RESOURCE}/#{escape_path(name)}"
        attempts = 0
        begin
          attempts += 1
          latest = @state_mutex.synchronize { @state[:lease] } || read_lease(path)
          written = if latest.nil?
                      @client.create(object, namespace: namespace, api_version: LEASE_API_VERSION)
                    else
                      renewed = latest.merge("spec" => (latest["spec"] || {}).merge(object["spec"] || {}),
                                             "metadata" => (latest["metadata"] || {}).except("managedFields"))
                      @client.update(renewed, namespace: namespace, path: path)
                    end
          written = stringify_keys(response_body(written))
          @state_mutex.synchronize { @state[:lease] = written }
          written
        rescue Client::APIError => error
          @state_mutex.synchronize { @state[:lease] = nil }
          raise unless [404, 409].include?(error.status.to_i) && attempts < 2

          retry
        end
      end

      alias apply_lease renew_lease
      alias update_lease renew_lease

      def read_lease(path)
        stringify_keys(response_body(@client.get(path)))
      rescue Client::APIError => error
        raise unless error.status.to_i == 404

        nil
      end

      # Status is a subresource.  Sending only the status document to the
      # explicit /status endpoint prevents a kubelet report from mutating Pod
      # spec or metadata fields owned by another controller.
      def report(pod, status)
        object = normalize_object(pod, expected_kind: "Pod")
        status_object = normalize_mapping(status, "Pod status")
        namespace = metadata_value(object, "namespace", "default")
        name = metadata_name(object)
        path = "/api/#{POD_API_VERSION}/namespaces/#{escape_path(namespace)}/#{POD_RESOURCE}/#{escape_path(name)}/status"
        body = {"status" => deep_copy(status_object)}
        # The report names the Pod's UID so it cannot land on a later Pod of
        # the same name (kubelet's status manager checks the UID the same
        # way); the API server answers a mismatch with 409.
        uid = metadata_value(object, "uid", nil)
        body["metadata"] = {"uid" => uid.to_s} unless uid.nil? || uid.to_s.empty?
        if @client.respond_to?(:patch)
          @client.patch(path, body, type: :merge)
        elsif @client.respond_to?(:apply)
          @client.apply(
            {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => namespace, **(body["metadata"] || {})}, "status" => body["status"]},
            path: path,
            field_manager: @field_manager
          )
        else
          raise ArgumentError, "client must implement patch or apply for Pod status reports"
        end
      end

      alias update_status report
      alias report_status report
      alias apply_pod_status report
      alias status report

      # The final delete of a Pod the API server marked for deletion.  The
      # kubelet owns this step: the API server sets a deletionTimestamp and
      # waits, and only the node can say that the containers are gone.
      # Upstream's status manager sends exactly these options once they are
      # (pkg/kubelet/status/status_manager.go): grace 0, so the request removes
      # the object instead of restarting the grace period, and a UID
      # precondition, because the name may already belong to a replacement Pod.
      #
      # Without this method the adapter had no delete at all, the agent's
      # deleter resolved to nil, and every gracefully deleted Pod was stopped
      # on the node and left Terminating in the API for ever -- every spec that
      # waits for a Pod to disappear timed out after five minutes.
      # kubelet mirror_client CreateMirrorPod: a static Pod's API object.
      def create_mirror_pod(pod)
        object = normalize_object(pod, expected_kind: "Pod")
        namespace = metadata_value(object, "namespace", "default")
        stringify_keys(response_body(@client.create(object, namespace: namespace, api_version: POD_API_VERSION)))
      end

      def delete_pod(namespace:, name:, uid: nil)
        namespace = validate_path_segment(namespace.to_s.empty? ? "default" : namespace.to_s, "namespace")
        name = validate_path_segment(name.to_s, "name")
        path = "/api/#{POD_API_VERSION}/namespaces/#{escape_path(namespace)}/#{POD_RESOURCE}/#{escape_path(name)}"
        options = {"apiVersion" => "v1", "kind" => "DeleteOptions", "gracePeriodSeconds" => 0}
        options["preconditions"] = {"uid" => uid.to_s} unless uid.nil? || uid.to_s.empty?
        if @client.respond_to?(:raw)
          @client.raw("DELETE", path, body: JSON.generate(options),
                      headers: {"content-type" => "application/json"})
        elsif @client.respond_to?(:delete)
          @client.delete(POD_RESOURCE, name, namespace: namespace, api_version: POD_API_VERSION,
                         options: options)
        else
          raise ArgumentError, "client must implement raw or delete to remove a Pod"
        end
      end

      private

      def pod_query(resource_version:, timeout: nil)
        query = {"fieldSelector" => "spec.nodeName=#{@node_name}"}
        query["resourceVersion"] = String(resource_version) unless resource_version.nil? || resource_version.to_s.empty?
        if timeout
          seconds = Float(timeout)
          raise ArgumentError, "watch timeout must be positive" unless seconds.positive?

          query["timeoutSeconds"] = [seconds.ceil, 1].max
        end
        query
      rescue ArgumentError, TypeError => error
        raise ArgumentError, "watch timeout must be a positive number: #{error.message}"
      end

      def normalize_list(value)
        value = response_body(value)
        return value if value.is_a?(Hash) && value.key?("items")
        return {"items" => Array(value), "metadata" => {}} if value.is_a?(Array)

        raise ArgumentError, "Kubernetes Pod list response must be a mapping or array"
      end

      def normalize_object(value, expected_kind:)
        object = response_body(value)
        object = object.to_h if object.respond_to?(:to_h) && !object.is_a?(Hash)
        object = stringify_keys(object)
        raise ArgumentError, "#{expected_kind} must be a mapping" unless object.is_a?(Hash)
        kind = object["kind"].to_s
        raise ArgumentError, "expected #{expected_kind}, got #{kind.inspect}" unless kind.empty? || kind == expected_kind

        object
      end

      def normalize_mapping(value, label)
        object = stringify_keys(value.respond_to?(:to_h) ? value.to_h : value)
        raise ArgumentError, "#{label} must be a mapping" unless object.is_a?(Hash)

        object
      end

      def metadata_name(object)
        name = metadata_value(object, "name", nil)
        raise ArgumentError, "Kubernetes object metadata.name is required" if name.to_s.empty?

        validate_path_segment(name, "metadata.name")
      end

      def metadata_value(object, key, default)
        metadata = object["metadata"]
        return default unless metadata.is_a?(Hash)

        value = metadata[key]
        value.nil? ? default : String(value)
      end

      def response_body(value)
        return value.json if value.respond_to?(:json)
        return value.body if value.respond_to?(:body) && !value.is_a?(Hash)

        value
      end

      def ensure_node_name!(value)
        raise ArgumentError, "node_name does not match adapter identity" unless String(value) == @node_name
      end

      def validate_path_segment(value, name)
        segment = String(value)
        raise ArgumentError, "#{name} must not be empty" if segment.empty?
        raise ArgumentError, "#{name} must not contain path separators" if segment.include?("/") || segment.include?("\\")
        raise ArgumentError, "#{name} must not contain control characters" if segment.match?(/[\x00-\x1f\x7f]/)
        raise ArgumentError, "#{name} must not be a path traversal segment" if %w[. ..].include?(segment)

        segment.freeze
      end

      def escape_path(value)
        URI::RFC2396_PARSER.escape(String(value))
      end

      def stringify_keys(value)
        case value
        when Hash
          value.to_h { |key, child| [String(key), stringify_keys(child)] }
        when Array
          value.map { |child| stringify_keys(child) }
        else
          value
        end
      end

      def deep_copy(value)
        case value
        when Hash
          value.to_h { |key, child| [key, deep_copy(child)] }
        when Array
          value.map { |child| deep_copy(child) }
        else
          value
        end
      end
    end

    KubernetesAPIAdapter = APIClientAdapter unless const_defined?(:KubernetesAPIAdapter, false)
  end
end
