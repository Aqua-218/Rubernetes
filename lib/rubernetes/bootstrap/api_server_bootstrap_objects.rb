# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    # Built-in API objects installed by the serving apiserver's post-start hooks.
    module APIServerBootstrapObjects
      private

      # kube-apiserver post-start hooks: RBAC bootstrap policy (when RBAC is
      # enabled), API Priority and Fairness bootstrap objects, and the system
      # namespaces.  Objects are created only when absent so operator edits
      # survive restarts, mirroring the upstream autoupdate annotation rule.
      def install_bootstrap_objects
        gates = @security ? @security.feature_gates : @config.dig("security", "feature_gates") || {}
        documents = SecurityAssembly.bootstrap_documents(feature_gates: gates)
        modes = Array(@config.dig("security", "authorization", "modes"))
        modes = %w[Node RBAC] if modes.empty?
        wanted = []
        wanted.push("clusterroles", "clusterrolebindings", "roles", "rolebindings") if modes.include?("RBAC")
        wanted.push("prioritylevelconfigurations", "flowschemas") unless @config.dig("security", "flow_control", "enabled") == false
        installed = 0
        wanted.each do |name|
          documents.fetch(name, []).each do |object|
            installed += 1 if install_bootstrap_object(with_type_meta(name, object))
          end
        end
        if modes.include?("RBAC")
          SecurityAssembly.feature_gate_role_rules(gates).each do |role, rules|
            install_feature_gate_rules(role, rules)
          end
        end
        # The node runtime handlers of this project (spec/node/runtime.md 5.8.1).
        Runtime::MicroVMRuntimeClasses.documents.each { |object| installed += 1 if install_bootstrap_object(object) }
        @logger.info("security.bootstrap.installed", objects: installed, kinds: wanted + ["runtimeclasses"])
        installed
      end

      # Existing default Roles receive permissions for the newly enabled gates
      # without replacing operator rules or ignoring the autoupdate opt-out.
      def install_feature_gate_rules(role_name, rules)
        path = "/apis/rbac.authorization.k8s.io/v1/clusterroles/#{role_name}"
        identity = {"username" => "system:apiserver", "groups" => ["system:masters"]}
        5.times do
          current = @api_server.call(API::Request.new(method: "GET", path: path, identity: identity))
          return unless current.status == 200

          role = current.body
          return if role.dig("metadata", "annotations", "rbac.authorization.kubernetes.io/autoupdate") == "false"

          additional = rules - Array(role["rules"])
          return if additional.empty?

          candidate = role.merge("rules" => Array(role["rules"]) + additional)
          response = @api_server.call(API::Request.new(method: "PUT", path: path, headers: {"content-type" => "application/json"},
                                                       body: JSON.generate(candidate), identity: identity))
          return unless response.status == 409
        end
      end

      # The oracle dump keeps list items without TypeMeta (as kube-apiserver
      # serves them); restore apiVersion/kind from the collection name.
      BOOTSTRAP_TYPE_META = {
        "clusterroles" => ["rbac.authorization.k8s.io/v1", "ClusterRole"],
        "clusterrolebindings" => ["rbac.authorization.k8s.io/v1", "ClusterRoleBinding"],
        "roles" => ["rbac.authorization.k8s.io/v1", "Role"],
        "rolebindings" => ["rbac.authorization.k8s.io/v1", "RoleBinding"],
        "flowschemas" => ["flowcontrol.apiserver.k8s.io/v1", "FlowSchema"],
        "prioritylevelconfigurations" => ["flowcontrol.apiserver.k8s.io/v1", "PriorityLevelConfiguration"],
        "namespaces" => %w[v1 Namespace]
      }.freeze

      def with_type_meta(collection, object)
        api_version, kind = BOOTSTRAP_TYPE_META.fetch(collection)
        object.merge("apiVersion" => object["apiVersion"] || api_version, "kind" => object["kind"] || kind)
      end

      def install_bootstrap_object(object)
        request = API::Request.new(method: "POST", path: collection_path(object), headers: {"content-type" => "application/json"},
                                   body: JSON.generate(object), identity: {"username" => "system:apiserver", "groups" => ["system:masters"]})
        response = @api_server.call(request)
        return true if response.status == 201
        return false if response.status == 409

        @logger.warn("security.bootstrap.failed", kind: object["kind"], name: object.dig("metadata", "name"), status: response.status,
                                                  message: response.body.is_a?(Hash) ? response.body["message"] : nil)
        false
      end

      def collection_path(object)
        api_version = object.fetch("apiVersion")
        resource = @registry.find_gvk(group: api_version.include?("/") ? api_version.split("/").first : "",
                                      version: api_version.split("/").last, kind: object.fetch("kind"))
        raise Config::Error, "bootstrap object kind #{object["kind"]} is not served" if resource.nil?

        base = resource.group.empty? ? "/api/#{resource.version}" : "/apis/#{resource.group}/#{resource.version}"
        namespace = object.dig("metadata", "namespace")
        namespace ? "#{base}/namespaces/#{namespace}/#{resource.resource}" : "#{base}/#{resource.resource}"
      end
    end
  end
end
