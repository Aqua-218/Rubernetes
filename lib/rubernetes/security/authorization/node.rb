# frozen_string_literal: true

require_relative "attributes"

module Rubernetes
  module Security
    module Authorization
      # Node authorizer (plugin/pkg/auth/authorizer/node, v1.36.2).  A kubelet
      # (system:node:<name> in system:nodes) reaches the objects its Pods
      # need through the node graph -- the secrets, configmaps, claims,
      # volumes, resource claims and service accounts referenced by Pods bound
      # to it, its VolumeAttachments and ResourceSlices -- and everything
      # else through the static node rules (bootstrappolicy.NodeRules).  What
      # the graph does not connect to the node gets NoOpinion, as upstream, so
      # another authorizer may still decide.
      class Node
        NAME = "Node"
        MIRROR_POD_ANNOTATION = "kubernetes.io/config.mirror"
        NODE_RULES = [
          {"apiGroups" => ["authentication.k8s.io"], "resources" => %w[tokenreviews], "verbs" => %w[create]},
          {"apiGroups" => ["authorization.k8s.io"], "resources" => %w[subjectaccessreviews localsubjectaccessreviews],
           "verbs" => %w[create]},
          {"apiGroups" => [""], "resources" => %w[services], "verbs" => %w[get list watch]},
          {"apiGroups" => [""], "resources" => %w[nodes], "verbs" => %w[create get list watch update patch]},
          {"apiGroups" => [""], "resources" => %w[nodes/status], "verbs" => %w[update patch]},
          {"apiGroups" => ["", "events.k8s.io"], "resources" => %w[events], "verbs" => %w[create update patch]},
          {"apiGroups" => [""], "resources" => %w[pods], "verbs" => %w[get list watch create delete]},
          {"apiGroups" => [""], "resources" => %w[pods/status], "verbs" => %w[update patch]},
          {"apiGroups" => [""], "resources" => %w[pods/eviction], "verbs" => %w[create]},
          {"apiGroups" => [""], "resources" => %w[secrets configmaps], "verbs" => %w[get list watch]},
          {"apiGroups" => [""], "resources" => %w[persistentvolumeclaims persistentvolumes], "verbs" => %w[get]},
          {"apiGroups" => [""], "resources" => %w[endpoints], "verbs" => %w[get]},
          {"apiGroups" => ["certificates.k8s.io"], "resources" => %w[certificatesigningrequests], "verbs" => %w[create get list watch]},
          {"apiGroups" => ["coordination.k8s.io"], "resources" => %w[leases], "verbs" => %w[get create update patch delete]},
          {"apiGroups" => ["storage.k8s.io"], "resources" => %w[volumeattachments], "verbs" => %w[get]},
          {"apiGroups" => [""], "resources" => %w[serviceaccounts/token], "verbs" => %w[create]},
          {"apiGroups" => [""], "resources" => %w[persistentvolumeclaims/status], "verbs" => %w[get update patch]},
          {"apiGroups" => ["storage.k8s.io"], "resources" => %w[csidrivers], "verbs" => %w[get watch list]},
          {"apiGroups" => ["storage.k8s.io"], "resources" => %w[csinodes], "verbs" => %w[get create update patch delete]},
          {"apiGroups" => ["node.k8s.io"], "resources" => %w[runtimeclasses], "verbs" => %w[get list watch]},
          # DynamicResourceAllocation (GA).
          {"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceclaims], "verbs" => %w[get]},
          {"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceslices], "verbs" => %w[deletecollection]},
          # ClusterTrustBundleProjection reads bundles on the node.
          {"apiGroups" => ["certificates.k8s.io"], "resources" => %w[clustertrustbundles], "verbs" => %w[get list watch]},
          # KubeletServiceAccountTokenForCredentialProviders (Beta, on).
          {"apiGroups" => [""], "resources" => %w[serviceaccounts], "verbs" => %w[get]}
        ].freeze

        # How long a node's reference set is reused before the Pods are read
        # again; a reference the cached set lacks forces one fresh read (at
        # most every REFRESH_FLOOR seconds), so a Pod bound a moment ago is
        # never refused its objects.
        REFERENCE_TTL = 1.0
        REFRESH_FLOOR = 0.1

        # graph: pods_on_node(node_name) -> [pods]; persistent_volume_claim(namespace, name);
        # persistent_volume(name); optionally volume_attachment(name), resource_slice(name),
        # pod_certificate_request(namespace, name).
        def initialize(graph:, features: {}, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @graph = graph
          @features = features.transform_keys(&:to_s)
          @clock = clock
          @references = {}
          @mutex = Mutex.new
        end

        def name
          NAME
        end

        def authorize(attributes)
          user = attributes.user
          return no_opinion("not a node identity") unless user.node?

          node_name = user.node_name.to_s
          return no_opinion("unknown node for user #{user.name.inspect}") if node_name.empty?

          if attributes.resource_request?
            case [attributes.api_group, attributes.resource]
            when ["", "secrets"] then return authorize_read_namespaced(node_name, :secrets, attributes)
            when ["", "configmaps"] then return authorize_read_namespaced(node_name, :configmaps, attributes)
            when ["", "persistentvolumeclaims"]
              return authorize_status_update(node_name, :persistentvolumeclaims, attributes) if attributes.subresource == "status"

              return authorize_get(node_name, :persistentvolumeclaims, attributes)
            when ["", "persistentvolumes"] then return authorize_get(node_name, :persistentvolumes, attributes)
            when ["resource.k8s.io", "resourceclaims"] then return authorize_get(node_name, :resourceclaims, attributes)
            when ["storage.k8s.io", "volumeattachments"] then return authorize_get(node_name, :volumeattachments, attributes)
            when ["", "serviceaccounts"] then return authorize_service_account(node_name, attributes)
            when ["coordination.k8s.io", "leases"] then return authorize_lease(node_name, attributes)
            when ["storage.k8s.io", "csinodes"] then return authorize_csi_node(node_name, attributes)
            when ["resource.k8s.io", "resourceslices"] then return authorize_resource_slice(node_name, attributes)
            when ["", "nodes"] then return authorize_node(node_name, attributes)
            when ["", "pods"] then return authorize_pod(node_name, attributes)
            when ["certificates.k8s.io", "podcertificaterequests"]
              return authorize_pod_certificate_request(node_name, attributes) if feature?("PodCertificateRequest", false)

              return no_opinion
            end
          end

          NODE_RULES.each do |rule|
            return Decision.allow("Node: node rule", authorizer: NAME) if rule_allows?(rule, attributes)
          end
          no_opinion
        end

        private

        def no_opinion(reason = nil)
          Decision.no_opinion(reason && "Node: #{reason}", authorizer: NAME)
        end

        def allow(reason)
          Decision.allow("Node: #{reason}", authorizer: NAME)
        end

        def feature?(gate, default)
          @features.fetch(gate, default) != false
        end

        def authorize_status_update(node_name, type, attributes)
          return no_opinion("can only get/update/patch this type") unless %w[update patch].include?(attributes.verb)
          return no_opinion("can only update status subresource") unless attributes.subresource == "status"

          authorize_path(node_name, type, attributes)
        end

        def authorize_get(node_name, type, attributes)
          return no_opinion("can only get individual resources of this type") unless attributes.verb == "get"
          return no_opinion("cannot get subresource") unless attributes.subresource.empty?

          authorize_path(node_name, type, attributes)
        end

        # A list or watch reaches here only for one named object (a
        # metadata.name field selector), as the kubelet's secret/configmap
        # watch asks.
        def authorize_read_namespaced(node_name, type, attributes)
          return no_opinion("can only read resources of this type") unless %w[get list watch].include?(attributes.verb)
          return no_opinion("cannot read subresource") unless attributes.subresource.empty?
          return no_opinion("can only read namespaced object of this type") if attributes.namespace.empty?

          authorize_path(node_name, type, attributes)
        end

        def authorize_path(node_name, type, attributes)
          return no_opinion("No Object name found") if attributes.name.empty?
          return allow("#{type} related to the node") if related?(node_name, type, attributes.namespace, attributes.name)

          no_opinion("no relationship found between node '#{node_name}' and this object")
        end

        # authorizeServiceAccount / authorizeCreateToken.
        def authorize_service_account(node_name, attributes)
          if attributes.verb == "get" && attributes.subresource.empty?
            unless feature?("KubeletServiceAccountTokenForCredentialProviders", true) || feature?("PodCertificateRequest", false)
              return no_opinion("not allowed to get service accounts")
            end

            return authorize_read_namespaced(node_name, :serviceaccounts, attributes)
          end
          return no_opinion("can only create tokens for individual service accounts") if attributes.verb != "create" || attributes.name.empty?
          return no_opinion("can only create token subresource of serviceaccount") unless attributes.subresource == "token"
          return allow("token of a service account related to the node") if related?(node_name, :serviceaccounts, attributes.namespace,
                                                                                     attributes.name)

          no_opinion("no relationship found between node '#{node_name}' and this object")
        end

        def authorize_lease(node_name, attributes)
          verb = attributes.verb
          return no_opinion("can only get, create, update, patch, or delete a node lease") unless %w[get create update patch
                                                                                                     delete].include?(verb)
          return no_opinion("can only access leases in the \"kube-node-lease\" system namespace") unless attributes.namespace == "kube-node-lease"
          return no_opinion("can only access node lease with the same name as the requesting node") if verb != "create" && attributes.name != node_name

          allow("own lease")
        end

        def authorize_csi_node(node_name, attributes)
          verb = attributes.verb
          return no_opinion("can only get, create, update, patch, or delete a CSINode") unless %w[get create update patch
                                                                                                  delete].include?(verb)
          return no_opinion("cannot authorize CSINode subresources") unless attributes.subresource.empty?
          return no_opinion("can only access CSINode with the same name as the requesting node") if verb != "create" && attributes.name != node_name

          allow("own CSINode")
        end

        def authorize_resource_slice(node_name, attributes)
          return no_opinion("cannot authorize ResourceSlice subresources") unless attributes.subresource.empty?

          case attributes.verb
          when "create"
            # NodeRestriction admission checks spec.nodeName.
            allow("ResourceSlice create")
          when "get", "update", "patch", "delete"
            authorize_path(node_name, :resourceslices, attributes)
          when "watch", "list", "deletecollection"
            return allow("ResourceSlices of this node") if field_equals?(attributes, "spec.nodeName", node_name)

            no_opinion("can only list/watch/deletecollection resourceslices with nodeName field selector")
          else
            no_opinion("only the following verbs are allowed for a ResourceSlice: get, watch, list, create, update, patch, delete, deletecollection")
          end
        end

        def authorize_pod_certificate_request(node_name, attributes)
          return no_opinion("nodes may not access the status subresource of PodCertificateRequests") unless attributes.subresource.empty?

          case attributes.verb
          when "create" then allow("PodCertificateRequest create")
          when "get" then authorize_path(node_name, :podcertificaterequests, attributes)
          when "list", "watch"
            return allow("PodCertificateRequests of this node") if field_equals?(attributes, "spec.nodeName", node_name)

            no_opinion("can only list/watch podcertificaterequests with nodeName field selector")
          else
            no_opinion("nodes may not #{attributes.verb} podcertificaterequests")
          end
        end

        # AuthorizeNodeWithSelectors (GA): a node reads only its own Node.
        def authorize_node(node_name, attributes)
          case attributes.subresource
          when ""
            return allow("node write (NodeRestriction limits it)") if %w[create update patch].include?(attributes.verb)

            if %w[get list watch].include?(attributes.verb)
              return allow("own node") if attributes.name == node_name
              return no_opinion("node '#{node_name}' cannot read all nodes, only its own Node object") if attributes.name.empty?

              return no_opinion("node '#{node_name}' cannot read '#{attributes.name}', only its own Node object")
            end
          when "status"
            return allow("node status (NodeRestriction limits it)") if %w[update patch].include?(attributes.verb)
          end
          no_opinion
        end

        def authorize_pod(node_name, attributes)
          case attributes.subresource
          when ""
            case attributes.verb
            when "get"
              return authorize_get(node_name, :pods, attributes)
            when "list", "watch"
              return allow("pods of this node") if field_equals?(attributes, "spec.nodeName", node_name)
              return authorize_path(node_name, :pods, attributes) unless attributes.name.empty?

              return no_opinion("can only list/watch pods with spec.nodeName field selector")
            when "create", "delete"
              # Mirror pods; NodeRestriction limits them to this node.
              return allow("mirror pod")
            end
          when "status"
            return allow("pod status (NodeRestriction limits it)") if %w[update patch].include?(attributes.verb)
          when "eviction"
            return allow("pod eviction (NodeRestriction limits it)") if attributes.verb == "create"
          end
          no_opinion
        end

        # A field selector requirement "field=value" (or "==") in the request.
        def field_equals?(attributes, field, value)
          selector = attributes.field_selector.to_s
          return false if selector.empty?

          selector.split(",").any? do |requirement|
            key, expected = requirement.split(/==?/, 2)
            next false if expected.nil? || requirement.include?("!=")

            key.strip == field && expected.strip == value
          end
        end

        # ---------------------------------------------------------- graph

        def related?(node_name, type, namespace, name)
          return @graph.references?(node_name, type, namespace, name) if @graph.respond_to?(:references?)

          case type
          when :volumeattachments
            object = graph_call(:volume_attachment, name)
            return false unless object

            object.dig("spec", "nodeName").to_s == node_name
          when :resourceslices
            object = graph_call(:resource_slice, name)
            return false unless object

            object.dig("spec", "nodeName").to_s == node_name
          when :podcertificaterequests
            object = graph_call(:pod_certificate_request, namespace, name)
            return false unless object

            object.dig("spec", "nodeName").to_s == node_name
          when :persistentvolumes
            # pv -> pvc (spec.claimRef) -> pod -> node.
            pv = graph_call(:persistent_volume, name)
            claim = pv&.dig("spec", "claimRef")
            return false unless claim

            referenced?(node_name, [:persistentvolumeclaims, claim["namespace"].to_s, claim["name"].to_s])
          else
            referenced?(node_name, [type, namespace.to_s, name.to_s])
          end
        end

        def graph_call(method, *)
          return nil unless @graph.respond_to?(method)

          @graph.public_send(method, *)
        rescue StandardError
          nil
        end

        # The node's reference set, rebuilt once when a key is missing.
        def referenced?(node_name, key)
          now = @clock.call
          entry = @mutex.synchronize { @references[node_name] }
          if entry.nil? || now - entry[:at] > REFERENCE_TTL
            entry = rebuild(node_name, now)
          elsif !entry[:set].include?(key) && now - entry[:at] > REFRESH_FLOOR
            entry = rebuild(node_name, now)
          end
          entry[:set].include?(key)
        end

        def rebuild(node_name, now)
          entry = {at: now, set: referenced_objects(node_name)}
          @mutex.synchronize do
            @references[node_name] = entry
            @references.delete_if { |_name, cached| now - cached[:at] > REFERENCE_TTL * 60 }
          end
          entry
        end

        # graph.AddPod: the objects a Pod bound to the node references
        # (VisitPodSecretNames / VisitPodConfigmapNames, claims, ephemeral
        # claims, resource claims).  A mirror Pod references nothing, and each
        # claim's PersistentVolume is reached through its claimRef, and the
        # volume's kubelet-visible secrets through the volume.
        def referenced_objects(node_name)
          references = Set.new
          Array(graph_call(:pods_on_node, node_name)).each do |pod|
            namespace = pod.dig("metadata", "namespace").to_s
            name = pod.dig("metadata", "name").to_s
            references << [:pods, namespace, name]
            next if (pod.dig("metadata", "annotations") || {}).key?(MIRROR_POD_ANNOTATION)

            account = pod.dig("spec", "serviceAccountName").to_s
            references << [:serviceaccounts, namespace, account] unless account.empty?
            pod_secret_names(pod).each { |secret| references << [:secrets, namespace, secret] }
            pod_config_map_names(pod).each { |config_map| references << [:configmaps, namespace, config_map] }
            Array(pod.dig("spec", "volumes")).each do |volume|
              claim_name = if volume["persistentVolumeClaim"]
                             volume.dig("persistentVolumeClaim", "claimName").to_s
                           elsif volume["ephemeral"]
                             "#{name}-#{volume["name"]}"
                           end
              next if claim_name.nil? || claim_name.empty?

              references << [:persistentvolumeclaims, namespace, claim_name]
              volume_secret_names(namespace, claim_name).each { |key| references << key }
            end
            resource_claim_names(pod).each { |claim| references << [:resourceclaims, namespace, claim] }
          end
          references
        end

        # The claim's volume's kubelet-visible CSI secrets (VisitPVSecretNames).
        def volume_secret_names(namespace, claim_name)
          claim = graph_call(:persistent_volume_claim, namespace, claim_name)
          volume_name = claim&.dig("spec", "volumeName").to_s
          return [] if volume_name.nil? || volume_name.empty?

          pv = graph_call(:persistent_volume, volume_name)
          csi = pv&.dig("spec", "csi")
          return [] unless csi.is_a?(Hash)

          %w[nodePublishSecretRef nodeStageSecretRef nodeExpandSecretRef].filter_map do |field|
            ref = csi[field]
            next unless ref.is_a?(Hash) && !ref["name"].to_s.empty?

            [:secrets, (ref["namespace"] || namespace).to_s, ref["name"].to_s]
          end
        end

        SECRET_REF_VOLUMES = %w[azureFile cephfs cinder flexVolume rbd scaleIO iscsi storageos].freeze

        def pod_secret_names(pod)
          names = Array(pod.dig("spec", "imagePullSecrets")).map { |secret| secret["name"] }
          each_container(pod) do |container|
            Array(container["envFrom"]).each { |source| names << source.dig("secretRef", "name") }
            Array(container["env"]).each { |env| names << env.dig("valueFrom", "secretKeyRef", "name") }
          end
          Array(pod.dig("spec", "volumes")).each do |volume|
            names << volume.dig("secret", "secretName")
            names << volume.dig("azureFile", "secretName")
            SECRET_REF_VOLUMES.each { |kind| names << volume.dig(kind, "secretRef", "name") if volume[kind].is_a?(Hash) }
            names << volume.dig("csi", "nodePublishSecretRef", "name")
            Array(volume.dig("projected", "sources")).each { |source| names << source.dig("secret", "name") }
          end
          names.compact.map(&:to_s).reject(&:empty?).uniq
        end

        def pod_config_map_names(pod)
          names = []
          each_container(pod) do |container|
            Array(container["envFrom"]).each { |source| names << source.dig("configMapRef", "name") }
            Array(container["env"]).each { |env| names << env.dig("valueFrom", "configMapKeyRef", "name") }
          end
          Array(pod.dig("spec", "volumes")).each do |volume|
            names << volume.dig("configMap", "name")
            Array(volume.dig("projected", "sources")).each { |source| names << source.dig("configMap", "name") }
          end
          names.compact.map(&:to_s).reject(&:empty?).uniq
        end

        def each_container(pod, &)
          %w[initContainers containers ephemeralContainers].each do |field|
            Array(pod.dig("spec", field)).each(&)
          end
        end

        # resourceclaim.Name: the claim a Pod's entry names, or the one the
        # controller generated (status.resourceClaimStatuses), and the
        # extended-resource claim.
        def resource_claim_names(pod)
          statuses = Array(pod.dig("status", "resourceClaimStatuses"))
          names = Array(pod.dig("spec", "resourceClaims")).map do |claim|
            claim["resourceClaimName"] || statuses.find { |status| status["name"] == claim["name"] }&.fetch("resourceClaimName", nil)
          end
          names << pod.dig("status", "extendedResourceClaimStatus", "resourceClaimName")
          names.compact.map(&:to_s).reject(&:empty?)
        end

        def rule_allows?(rule, attributes)
          rule["apiGroups"].include?(attributes.api_group) && rule["resources"].include?(attributes.resource_with_subresource) && rule["verbs"].include?(attributes.verb)
        end
      end
    end
  end
end
