# frozen_string_literal: true

require "set"

module Rubernetes
  module Security
    module Authorization
      # plugin/pkg/auth/authorizer/node/graph.go: the graph of what a node
      # may read, maintained from Pod / PersistentVolume / VolumeAttachment /
      # ResourceSlice / PodCertificateRequest events rather than read from
      # the store per request.  Every graph action is timed in
      # node_authorizer_graph_actions_duration_seconds{operation}.
      class NodeGraph
        MIRROR_POD_ANNOTATION = "kubernetes.io/config.mirror"
        SECRET_REF_VOLUMES = %w[azureFile cephfs cinder flexVolume rbd scaleIO iscsi storageos].freeze

        class << self
          attr_accessor :metrics

          def timed(operation)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            yield
          ensure
            metrics&.observe("node_authorizer_graph_actions_duration_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                             {"operation" => operation})
          end
        end

        def initialize
          @mutex = Mutex.new
          # node -> {pod key -> Set of [type, namespace, name]} (pod -> objects edges)
          @pods = Hash.new { |hash, node| hash[node] = {} }
          @pod_node = {}          # [namespace, name] -> node
          @claim_volume = {}      # [namespace, claim] -> pv name (from claimRef)
          @volume_claim = {}      # pv name -> [namespace, claim]
          @volume_secrets = {}    # pv name -> Set of [:secrets, namespace, name]
          @attachments = {}       # volumeattachment name -> node
          @slices = {}            # resourceslice name -> node
          @pcrs = {}              # [namespace, name] -> node
        end

        # -- graph actions -------------------------------------------------------

        def add_pod(pod)
          NodeGraph.timed("AddPod") do
            node = value(pod, "spec", "nodeName").to_s
            key = [namespace(pod), name(pod)]
            @mutex.synchronize do
              previous = @pod_node[key]
              @pods[previous].delete(key) if previous && previous != node
              if node.empty?
                @pod_node.delete(key)
              else
                @pod_node[key] = node
                @pods[node][key] = pod_references(pod)
              end
            end
          end
        end

        def delete_pod(namespace, name)
          NodeGraph.timed("DeletePod") do
            key = [namespace.to_s, name.to_s]
            @mutex.synchronize do
              node = @pod_node.delete(key)
              @pods[node].delete(key) if node
              @pods.delete(node) if node && @pods[node].empty?
            end
          end
        end

        def add_pv(pv)
          NodeGraph.timed("AddPV") do
            pv_name = name(pv)
            claim = value(pv, "spec", "claimRef")
            secrets = pv_secret_references(pv)
            @mutex.synchronize do
              if (old_claim = @volume_claim[pv_name])
                @claim_volume.delete(old_claim)
              end
              if claim.is_a?(Hash) && !value(claim, "name").to_s.empty?
                claim_key = [value(claim, "namespace").to_s, value(claim, "name").to_s]
                @volume_claim[pv_name] = claim_key
                @claim_volume[claim_key] = pv_name
              else
                @volume_claim.delete(pv_name)
              end
              @volume_secrets[pv_name] = secrets
            end
          end
        end

        def delete_pv(name)
          NodeGraph.timed("DeletePV") do
            @mutex.synchronize do
              claim = @volume_claim.delete(name.to_s)
              @claim_volume.delete(claim) if claim
              @volume_secrets.delete(name.to_s)
            end
          end
        end

        def add_volume_attachment(name, node)
          NodeGraph.timed("AddVolumeAttachment") { @mutex.synchronize { node.to_s.empty? ? @attachments.delete(name.to_s) : @attachments[name.to_s] = node.to_s } }
        end

        def delete_volume_attachment(name)
          NodeGraph.timed("DeleteVolumeAttachment") { @mutex.synchronize { @attachments.delete(name.to_s) } }
        end

        def add_resource_slice(name, node)
          NodeGraph.timed("AddResourceSlice") { @mutex.synchronize { node.to_s.empty? ? @slices.delete(name.to_s) : @slices[name.to_s] = node.to_s } }
        end

        def delete_resource_slice(name)
          NodeGraph.timed("DeleteResourceSlice") { @mutex.synchronize { @slices.delete(name.to_s) } }
        end

        def add_pod_certificate_request(pcr)
          NodeGraph.timed("AddPodCertificateRequest") do
            node = value(pcr, "spec", "nodeName").to_s
            @mutex.synchronize { node.empty? ? @pcrs.delete([namespace(pcr), name(pcr)]) : @pcrs[[namespace(pcr), name(pcr)]] = node }
          end
        end

        def delete_pod_certificate_request(namespace, name)
          NodeGraph.timed("DeletePodCertificateRequest") { @mutex.synchronize { @pcrs.delete([namespace.to_s, name.to_s]) } }
        end

        # -- queries (hasPathFrom) -------------------------------------------------

        # Does a path lead from the object to the node?
        def references?(node, type, namespace, name)
          node = node.to_s
          type = type.to_sym
          key = [type, namespace.to_s, name.to_s]
          @mutex.synchronize do
            case type
            when :volumeattachments then @attachments[name.to_s] == node
            when :resourceslices then @slices[name.to_s] == node
            when :podcertificaterequests then @pcrs[[namespace.to_s, name.to_s]] == node
            when :persistentvolumes
              claim = @volume_claim[name.to_s]
              !claim.nil? && node_references_locked?(node, [:persistentvolumeclaims, *claim])
            when :secrets
              node_references_locked?(node, key) || node_volume_secret_locked?(node, key)
            else
              node_references_locked?(node, key)
            end
          end
        end

        def pods_on(node) = @mutex.synchronize { @pods[node.to_s].keys.dup }

        def stats
          @mutex.synchronize do
            {"nodes" => @pods.count { |_node, pods| !pods.empty? }, "pods" => @pod_node.length, "volumes" => @volume_claim.length,
             "attachments" => @attachments.length, "slices" => @slices.length, "podcertificaterequests" => @pcrs.length}
          end
        end

        private

        def node_references_locked?(node, key)
          pods = @pods[node]
          !pods.empty? && pods.each_value.any? { |references| references.include?(key) }
        end

        # secret -> pv -> pvc -> pod -> node
        def node_volume_secret_locked?(node, key)
          @pods[node].each_value.any? do |references|
            references.any? do |type, namespace, claim|
              next false unless type == :persistentvolumeclaims

              pv = @claim_volume[[namespace, claim]]
              pv && @volume_secrets.fetch(pv, Set.new).include?(key)
            end
          end
        end

        def value(object, *path)
          path.reduce(object) { |current, step| current.is_a?(Hash) ? (current.key?(step) ? current[step] : current[step.to_sym]) : nil }
        end

        def namespace(object) = value(object, "metadata", "namespace").to_s
        def name(object) = value(object, "metadata", "name").to_s

        # AddPod's edges: the Pod itself, its ServiceAccount, Secrets,
        # ConfigMaps, claims and ResourceClaims (a mirror Pod gets none).
        def pod_references(pod)
          references = Set.new
          ns = namespace(pod)
          references << [:pods, ns, name(pod)]
          return references if (value(pod, "metadata", "annotations") || {}).key?(MIRROR_POD_ANNOTATION)

          account = value(pod, "spec", "serviceAccountName").to_s
          references << [:serviceaccounts, ns, account] unless account.empty?
          pod_secret_names(pod).each { |secret| references << [:secrets, ns, secret] }
          pod_config_map_names(pod).each { |config_map| references << [:configmaps, ns, config_map] }
          Array(value(pod, "spec", "volumes")).each do |volume|
            claim = if value(volume, "persistentVolumeClaim") then value(volume, "persistentVolumeClaim", "claimName").to_s
                    elsif value(volume, "ephemeral") then "#{name(pod)}-#{value(volume, "name")}"
                    end
            references << [:persistentvolumeclaims, ns, claim] if claim && !claim.empty?
          end
          resource_claim_names(pod).each { |claim| references << [:resourceclaims, ns, claim] }
          references
        end

        def pv_secret_references(pv)
          csi = value(pv, "spec", "csi")
          return Set.new unless csi.is_a?(Hash)

          %w[nodePublishSecretRef nodeStageSecretRef nodeExpandSecretRef].each_with_object(Set.new) do |field, set|
            ref = csi[field]
            next unless ref.is_a?(Hash) && !value(ref, "name").to_s.empty?

            set << [:secrets, value(ref, "namespace").to_s, value(ref, "name").to_s]
          end
        end

        def each_container(pod, &block)
          %w[initContainers containers ephemeralContainers].each { |field| Array(value(pod, "spec", field)).each(&block) }
        end

        def pod_secret_names(pod)
          names = Array(value(pod, "spec", "imagePullSecrets")).map { |secret| value(secret, "name") }
          each_container(pod) do |container|
            Array(value(container, "envFrom")).each { |source| names << value(source, "secretRef", "name") }
            Array(value(container, "env")).each { |env| names << value(env, "valueFrom", "secretKeyRef", "name") }
          end
          Array(value(pod, "spec", "volumes")).each do |volume|
            names << value(volume, "secret", "secretName")
            names << value(volume, "azureFile", "secretName")
            SECRET_REF_VOLUMES.each { |kind| names << value(volume, kind, "secretRef", "name") if value(volume, kind).is_a?(Hash) }
            names << value(volume, "csi", "nodePublishSecretRef", "name")
            Array(value(volume, "projected", "sources")).each { |source| names << value(source, "secret", "name") }
          end
          names.compact.map(&:to_s).reject(&:empty?).uniq
        end

        def pod_config_map_names(pod)
          names = []
          each_container(pod) do |container|
            Array(value(container, "envFrom")).each { |source| names << value(source, "configMapRef", "name") }
            Array(value(container, "env")).each { |env| names << value(env, "valueFrom", "configMapKeyRef", "name") }
          end
          Array(value(pod, "spec", "volumes")).each do |volume|
            names << value(volume, "configMap", "name")
            Array(value(volume, "projected", "sources")).each { |source| names << value(source, "configMap", "name") }
          end
          names.compact.map(&:to_s).reject(&:empty?).uniq
        end

        def resource_claim_names(pod)
          statuses = Array(value(pod, "status", "resourceClaimStatuses"))
          names = Array(value(pod, "spec", "resourceClaims")).map do |claim|
            value(claim, "resourceClaimName") || statuses.find { |status| value(status, "name") == value(claim, "name") }&.then { |status| value(status, "resourceClaimName") }
          end
          names << value(pod, "status", "extendedResourceClaimStatus", "resourceClaimName")
          names.compact.map(&:to_s).reject(&:empty?)
        end

        # Feeds the graph from the store's watches (the informers upstream's
        # node authorizer is built on): every existing object, then changes.
        class Populator
          WATCHES = [
            ["v1/pods", :pod], ["v1/persistentvolumes", :pv], ["storage.k8s.io/v1/volumeattachments", :attachment],
            ["resource.k8s.io/v1/resourceslices", :slice], ["certificates.k8s.io/v1beta1/podcertificaterequests", :pcr]
          ].freeze

          attr_reader :graph

          def initialize(graph:, store:, prefix: "registry", logger: nil)
            @graph = graph
            @store = store
            @prefix = prefix
            @logger = logger
            @streams = []
            @threads = []
            @stop = false
          end

          def start
            @stop = false
            WATCHES.each do |gvr, kind|
              stream = @store.watch("#{@prefix}/#{gvr}/", since: 0)
              @streams << stream
              @threads << Thread.new do
                Thread.current.name = "node-graph-#{kind}"
                stream.each(timeout: nil) do |event|
                  break if @stop

                  apply(kind, event)
                end
              rescue StandardError => error
                @logger&.warn("node_authorizer.graph_watch_failed", kind: kind.to_s, error: error.message.to_s[0, 200]) if @logger.respond_to?(:warn)
              end
            end
            self
          end

          def stop
            @stop = true
            @streams.each { |stream| stream.close rescue nil }
            @threads.each { |thread| thread.join(2) }
            @threads.clear
            @streams.clear
            self
          end

          # One store mutation: :added / :modified upsert, :deleted removes.
          def apply(kind, event)
            deleted = event.type.to_s.casecmp?("deleted")
            object = event.object
            object = event.old_object if deleted && object.nil? && event.respond_to?(:old_object)
            return if object.nil?

            namespace = object.dig("metadata", "namespace").to_s
            name = object.dig("metadata", "name").to_s
            case kind
            when :pod then deleted ? @graph.delete_pod(namespace, name) : @graph.add_pod(object)
            when :pv then deleted ? @graph.delete_pv(name) : @graph.add_pv(object)
            when :attachment then deleted ? @graph.delete_volume_attachment(name) : @graph.add_volume_attachment(name, object.dig("spec", "nodeName"))
            when :slice then deleted ? @graph.delete_resource_slice(name) : @graph.add_resource_slice(name, object.dig("spec", "nodeName"))
            when :pcr then deleted ? @graph.delete_pod_certificate_request(namespace, name) : @graph.add_pod_certificate_request(object)
            end
          rescue StandardError => error
            @logger&.warn("node_authorizer.graph_event_failed", kind: kind.to_s, error: error.message.to_s[0, 200]) if @logger.respond_to?(:warn)
          end
        end
      end
    end
  end
end
