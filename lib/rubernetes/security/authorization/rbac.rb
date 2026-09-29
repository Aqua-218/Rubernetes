# frozen_string_literal: true

require_relative "attributes"

module Rubernetes
  module Security
    module Authorization
      # RBAC authorizer (plugin/pkg/auth/authorizer/rbac).  Rules come from
      # Roles / ClusterRoles bound to the user by RoleBindings /
      # ClusterRoleBindings; ClusterRole aggregation is resolved on read.
      # There are no deny rules: the first matching rule allows, otherwise
      # NoOpinion.
      class RBAC
        NAME = "RBAC"
        API_GROUP = "rbac.authorization.k8s.io"

        # source responds to cluster_roles, cluster_role_bindings, roles(namespace), role_bindings(namespace)
        # returning arrays of API objects.
        def initialize(source:)
          @source = source
        end

        def name
          NAME
        end

        def authorize(attributes)
          user = attributes.user
          matched = nil
          each_applicable_rule(user, attributes.namespace) do |rule, origin|
            next unless rule_allows?(rule, attributes)

            matched = origin
            break
          end
          return Decision.allow("RBAC: allowed by #{matched}", authorizer: NAME) if matched

          Decision.no_opinion("RBAC: no rule granted #{describe(attributes)}", authorizer: NAME)
        end

        # Rules visible to the user (SelfSubjectRulesReview).
        def rules_for(user, namespace)
          resource_rules = []
          non_resource_rules = []
          each_applicable_rule(user, namespace) do |rule, _origin|
            if Array(rule["nonResourceURLs"]).any?
              non_resource_rules << {"verbs" => Array(rule["verbs"]), "nonResourceURLs" => Array(rule["nonResourceURLs"])}
            else
              resource_rules << {"verbs" => Array(rule["verbs"]), "apiGroups" => Array(rule["apiGroups"]), "resources" => Array(rule["resources"]),
                                 "resourceNames" => Array(rule["resourceNames"])}.reject { |_key, value| value.empty? }
            end
          end
          [resource_rules, non_resource_rules]
        end

        def rule_allows?(rule, attributes)
          verbs = Array(rule["verbs"])
          return false unless verbs.include?("*") || verbs.include?(attributes.verb)

          if attributes.resource_request?
            groups = Array(rule["apiGroups"])
            return false unless groups.include?("*") || groups.include?(attributes.api_group)

            resources = Array(rule["resources"])
            resource = attributes.resource.to_s
            combined = attributes.resource_with_subresource
            resource_ok = resources.any? do |candidate|
              candidate == "*" || candidate == combined || (attributes.subresource.empty? && candidate == resource) ||
                (!attributes.subresource.empty? && candidate == "*/#{attributes.subresource}")
            end
            return false unless resource_ok

            names = Array(rule["resourceNames"])
            names.empty? || (!attributes.name.empty? && names.include?(attributes.name))
          else
            Array(rule["nonResourceURLs"]).any? do |pattern|
              pattern == "*" || pattern == attributes.path.to_s ||
                (pattern.end_with?("/*") && attributes.path.to_s.start_with?(pattern.delete_suffix("*")))
            end
          end
        end

        private

        def describe(attributes)
          if attributes.resource_request?
            "#{attributes.verb} #{attributes.resource_with_subresource} in #{attributes.api_group.empty? ? "core" : attributes.api_group}#{attributes.namespace.empty? ? "" : " namespace #{attributes.namespace}"}"
          else
            "#{attributes.verb} #{attributes.path}"
          end
        end

        def each_applicable_rule(user, namespace)
          cluster_roles = @source.respond_to?(:cluster_roles_by_name) ? @source.cluster_roles_by_name : index_by_name(@source.cluster_roles)
          @source.cluster_role_bindings.each do |binding|
            next unless subject_matches?(binding, user, nil)

            role_ref = binding["roleRef"] || {}
            next unless role_ref["kind"] == "ClusterRole"

            role = cluster_roles[role_ref["name"]]
            next if role.nil?

            effective_rules(role, cluster_roles).each { |rule| yield rule, "ClusterRoleBinding #{binding.dig("metadata", "name")}" }
          end
          return if namespace.nil? || namespace.empty?

          roles = index_by_name(@source.roles(namespace))
          @source.role_bindings(namespace).each do |binding|
            next unless subject_matches?(binding, user, namespace)

            role_ref = binding["roleRef"] || {}
            rules = case role_ref["kind"]
                    when "ClusterRole" then (role = cluster_roles[role_ref["name"]]) && effective_rules(role, cluster_roles)
                    when "Role" then roles[role_ref["name"]] && Array(roles[role_ref["name"]]["rules"])
                    end
            Array(rules).each { |rule| yield rule, "RoleBinding #{namespace}/#{binding.dig("metadata", "name")}" }
          end
        end

        def index_by_name(objects)
          Array(objects).each_with_object({}) { |object, index| index[object.dig("metadata", "name")] = object }
        end

        def effective_rules(role, cluster_roles)
          rules = Array(role["rules"])
          aggregation = role["aggregationRule"]
          return rules unless aggregation.is_a?(Hash)

          selectors = Array(aggregation["clusterRoleSelectors"])
          aggregated = cluster_roles.values.select do |candidate|
            next false if candidate.equal?(role)

            labels = candidate.dig("metadata", "labels") || {}
            selectors.any? { |selector| label_selector_matches?(selector, labels) }
          end
          rules + aggregated.flat_map { |candidate| Array(candidate["rules"]) }
        end

        def label_selector_matches?(selector, labels)
          (selector["matchLabels"] || {}).all? { |key, value| labels[key] == value } &&
            Array(selector["matchExpressions"]).all? do |expression|
              values = Array(expression["values"])
              value = labels[expression["key"]]
              case expression["operator"]
              when "In" then values.include?(value)
              when "NotIn" then !values.include?(value)
              when "Exists" then labels.key?(expression["key"])
              when "DoesNotExist" then !labels.key?(expression["key"])
              else false
              end
            end
        end

        def subject_matches?(binding, user, namespace)
          Array(binding["subjects"]).any? do |subject|
            case subject["kind"]
            when "User" then subject["name"] == user.name
            when "Group" then user.groups.include?(subject["name"])
            when "ServiceAccount"
              sa_namespace = subject["namespace"].to_s.empty? ? namespace : subject["namespace"]
              !sa_namespace.to_s.empty? && user.name == "#{UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX}#{sa_namespace}:#{subject["name"]}"
            else false
            end
          end
        end
      end

      # Reads RBAC objects from a Store contract and keeps them until an RBAC
      # object changes.  Listing them on every request copied some 70
      # ClusterRoles and 150 bindings out of the store each time: 10 ms of a
      # GET that otherwise takes 5, and 30 ms on a loaded apiserver, which was
      # most of every request's latency.  A store exposing
      # revision_under(prefix) (MemoryStore, RaftStore) lets the cache detect
      # a change by comparing four integers; any other store is listed on
      # every call as before.
      class StoreRBACSource
        RESOURCES = %w[clusterroles clusterrolebindings roles rolebindings].freeze
        # Namespaced lists are cached per namespace; past this many entries
        # the cache starts over rather than tracking every namespace ever seen.
        MAX_CACHED_ENTRIES = 4096

        def initialize(store, key_for:)
          @store = store
          @key_for = key_for
          @mutex = Mutex.new
          @cache = nil
        end

        # Cluster-scoped objects are keyed by the ClusterRole/ClusterRoleBinding
        # revisions and namespaced ones by the Role/RoleBinding revisions, so
        # the RoleBindings a test writes in its own namespace do not throw
        # away the ClusterRoles every request needs.
        CLUSTER_RESOURCES = %w[clusterroles clusterrolebindings].freeze
        NAMESPACED_RESOURCES = %w[roles rolebindings].freeze

        def cluster_roles = cached(:cluster, :cluster_roles) { list("clusterroles", nil) }
        def cluster_role_bindings = cached(:cluster, :cluster_role_bindings) { list("clusterrolebindings", nil) }
        def roles(namespace) = cached(:namespaced, [:roles, namespace]) { list("roles", namespace) }
        def role_bindings(namespace) = cached(:namespaced, [:role_bindings, namespace]) { list("rolebindings", namespace) }

        def cluster_roles_by_name
          cached(:cluster, :cluster_roles_by_name) do
            cluster_roles.each_with_object({}) { |role, index| index[role.dig("metadata", "name")] = role }.freeze
          end
        end

        # The revisions of the RBAC key spaces of one scope, or nil when the
        # store cannot report them (then nothing is cached).
        def fingerprint(scope = :all)
          return nil unless @store.respond_to?(:revision_under)

          resources = case scope
                      when :cluster then CLUSTER_RESOURCES
                      when :namespaced then NAMESPACED_RESOURCES
                      else RESOURCES
                      end
          resources.map { |resource| @store.revision_under(@key_for.call(resource, nil)) }
        rescue StandardError
          nil
        end

        private

        # The fingerprint is read before the list: a write landing between
        # the two leaves a newer value filed under an older fingerprint, which
        # the next call sees as changed and rebuilds.  Never the reverse.
        def cached(scope, key)
          fingerprint = fingerprint(scope)
          return yield if fingerprint.nil?

          @mutex.synchronize do
            @cache ||= {}
            slot = @cache[scope]
            @cache[scope] = slot = {fingerprint: fingerprint, entries: {}} if slot.nil? || slot[:fingerprint] != fingerprint
            return slot[:entries][key] if slot[:entries].key?(key)
          end
          value = yield
          @mutex.synchronize do
            slot = @cache && @cache[scope]
            if slot && slot[:fingerprint] == fingerprint
              slot[:entries].clear if slot[:entries].length >= MAX_CACHED_ENTRIES
              slot[:entries][key] = value
            end
          end
          value
        end

        def list(resource, namespace)
          prefix = @key_for.call(resource, namespace)
          @store.list(prefix).items
        rescue StandardError
          []
        end
      end
    end
  end
end
