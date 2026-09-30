# frozen_string_literal: true

require "securerandom"
require_relative "../node_declared_features"

module Rubernetes
  module Scheduler
    module Filters
      module Helpers
        module_function

        def accept
          true
        end

        def reject(reason, code: nil, details: nil)
          Rejection.new(reason, code: code, details: details)
        end

        def context_pods(context, node = nil)
          node_pods = node ? Array(node.pods) : []
          context_pods = if context.respond_to?(:pods)
                           Array(context.pods)
                         elsif context.is_a?(Hash)
                           Array(context["pods"] || context[:pods])
                         else
                           []
                         end
          (node_pods + context_pods).each_with_object({}) do |pod, result|
            typed = pod.is_a?(Pod) ? pod : Pod.new(pod)
            key = typed.uid
            key = "#{typed.namespace}/#{typed.name}" if key.empty?
            result[key] ||= typed
          end.values
        end

        def context_nodes(context)
          if context.respond_to?(:nodes)
            Array(context.nodes)
          elsif context.is_a?(Hash)
            Array(context["nodes"] || context[:nodes])
          else
            []
          end
        end

        def volume_data(context)
          if context.respond_to?(:volume_data)
            return context.volume_data
          end

          if context.is_a?(Hash)
            return Support.object_hash(context["volume_data"] || context[:volume_data] || {})
          end

          {}
        end

        def collection(data, *keys)
          keys.each do |key|
            value = Support.value(data, key, nil)
            return value unless value.nil?
          end
          nil
        end

        def items(value)
          value.is_a?(Hash) ? value.values : Array(value)
        end

        def lookup_resource(collection_value, name, namespace: nil)
          return nil if collection_value.nil?
          return collection_value if collection_value.respond_to?(:name) && collection_value.name.to_s == name.to_s

          if collection_value.is_a?(Hash)
            value = collection_value[name.to_s] || collection_value[name.to_sym]
            return value unless value.nil?
            namespaced = namespace && "#{namespace}/#{name}"
            return collection_value[namespaced] if namespaced && collection_value.key?(namespaced)
            return collection_value[namespaced.to_sym] if namespaced && collection_value.key?(namespaced.to_sym)
            return nil
          end

          Array(collection_value).find do |item|
            item_name = Support.value(item, "name", Support.value(Support.value(item, "metadata", {}), "name", nil))
            item_namespace = Support.value(item, "namespace", Support.value(Support.value(item, "metadata", {}), "namespace", namespace))
            item_name.to_s == name.to_s && (namespace.nil? || item_namespace.to_s == namespace.to_s)
          end
        end

        def claim_for(volume, pod, context)
          claim_ref = Support.value(volume, "persistentVolumeClaim", nil)
          return nil unless claim_ref

          name = Support.value(claim_ref, "claimName", "").to_s
          return nil if name.empty?

          data = volume_data(context)
          claims = collection(data, "persistentVolumeClaims", "pvcs", "claims")
          lookup_resource(claims, name, namespace: pod.namespace)
        end

        def pv_for(volume, pod, context)
          claim = claim_for(volume, pod, context)
          pv_name = if claim
                      Support.value(claim, "volumeName", Support.value(Support.value(claim, "spec", {}), "volumeName", nil))
                    end
          pv_name ||= Support.value(volume, "volumeName", nil)
          return nil if pv_name.to_s.empty?

          data = volume_data(context)
          volumes = collection(data, "persistentVolumes", "pvs", "volumes")
          lookup_resource(volumes, pv_name)
        end

        def pod_volume_claim_names(pod)
          pod.volumes.filter_map do |volume|
            claim_ref = Support.value(volume, "persistentVolumeClaim", nil)
            name = Support.value(claim_ref, "claimName", nil) if claim_ref
            name&.to_s unless name.to_s.empty?
          end
        end

        def pod_volume_keys(pod, context)
          pod.volumes.filter_map do |volume|
            source = volume_source(volume, pod, context)
            source unless source.nil?
          end
        end

        def volume_source(volume, pod, context)
          pv = pv_for(volume, pod, context)
          if pv
            source = persistent_volume_source(pv)
            return source if source

            return {"kind" => "pv", "name" => Support.value(pv, "name", Support.value(Support.value(pv, "metadata", {}), "name", nil)).to_s}
          end

          claim_ref = Support.value(volume, "persistentVolumeClaim", nil)
          if claim_ref
            claim_name = Support.value(claim_ref, "claimName", "").to_s
            return {"kind" => "pvc", "name" => "#{pod.namespace}/#{claim_name}"} unless claim_name.empty?
          end

          %w[gcePersistentDisk awsElasticBlockStore iscsi rbd csi].each do |kind|
            source = Support.value(volume, kind, nil)
            next unless source

            identifier = Support.value(source, "pdName",
                                       Support.value(source, "volumeID",
                                                     Support.value(source, "iqn",
                                                                   Support.value(source, "rbdImage",
                                                                                 Support.value(source, "volumeHandle", nil)))))
            return {"kind" => kind, "name" => identifier.to_s} unless identifier.to_s.empty?
          end
          nil
        end

        def persistent_volume_source(pv)
          spec = Support.value(pv, "spec", {})
          %w[gcePersistentDisk awsElasticBlockStore iscsi rbd csi].each do |kind|
            source = Support.value(pv, kind, Support.value(spec, kind, nil))
            next unless source

            identifier = Support.value(source, "pdName",
                                       Support.value(source, "volumeID",
                                                     Support.value(source, "iqn",
                                                                   Support.value(source, "rbdImage",
                                                                                 Support.value(source, "volumeHandle", nil)))))
            return {"kind" => kind, "name" => identifier.to_s} unless identifier.to_s.empty?
          end
          nil
        end

        def volume_read_only?(volume)
          return true if Support.truthy?(Support.value(volume, "readOnly", false))

          %w[gcePersistentDisk awsElasticBlockStore iscsi rbd csi].any? do |kind|
            source = Support.value(volume, kind, nil)
            source && Support.truthy?(Support.value(source, "readOnly", false))
          end
        end

        def node_host_ports(node)
          ports = []
          node_used = node.respond_to?(:used_ports) ? node.used_ports : {}
          flatten_ports(node_used, ports)
          Array(node.pods).each { |pod| ports.concat(pod_host_ports(pod)) }
          ports.uniq
        end

        def pod_host_ports(pod)
          Array(pod.containers).dup.concat(Array(pod.init_containers)).flat_map do |container|
            Array(Support.value(container, "ports", [])).filter_map do |port|
              host_port = Integer(Support.value(port, "hostPort", 0) || 0)
              next if host_port <= 0

              {"hostIP" => Support.value(port, "hostIP", "").to_s,
               "protocol" => Support.value(port, "protocol", "TCP").to_s.upcase,
               "hostPort" => host_port}
            rescue ArgumentError, TypeError
              raise ValidationError, "pod hostPort must be an integer"
            end
          end
        end

        def flatten_ports(value, result, defaults = {})
          case value
          when Array
            value.each { |child| flatten_ports(child, result, defaults) }
          when Integer
            append_flat_port(value, result, defaults)
          when String
            append_flat_port(value, result, defaults) if value.match?(/\A\d+\z/)
          when Hash
            if Support.value(value, "hostPort", nil) || Support.value(value, "port", nil)
              port = Support.value(value, "hostPort", Support.value(value, "port", nil))
              append_flat_port(port, result, defaults.merge(
                "hostIP" => Support.value(value, "hostIP", defaults["hostIP"] || "").to_s,
                "protocol" => Support.value(value, "protocol", defaults["protocol"] || "TCP").to_s.upcase
              ))
            elsif value.keys.any? { |key| %w[TCP UDP SCTP].include?(key.to_s.upcase) }
              value.each do |key, child|
                flatten_ports(child, result, defaults.merge("protocol" => key.to_s.upcase))
              end
            else
              value.each { |key, child| flatten_ports(child, result, defaults.merge("hostIP" => key.to_s)) }
            end
          end
        rescue ArgumentError, TypeError
          raise ValidationError, "node used port must be an integer"
        end

        def append_flat_port(value, result, defaults)
          port = Integer(value)
          return if port <= 0

          result << {"hostIP" => defaults.fetch("hostIP", "").to_s,
                     "protocol" => defaults.fetch("protocol", "TCP").to_s.upcase,
                     "hostPort" => port}
        end

        def ports_conflict?(left, right)
          left.fetch("protocol") == right.fetch("protocol") && left.fetch("hostPort") == right.fetch("hostPort") &&
            (wildcard_host_ip?(left.fetch("hostIP")) || wildcard_host_ip?(right.fetch("hostIP")) ||
             left.fetch("hostIP") == right.fetch("hostIP"))
        end

        def wildcard_host_ip?(value)
          value.to_s.empty? || %w[0.0.0.0 ::].include?(value.to_s)
        end

        def node_affinity_matches?(affinity, node)
          return true if affinity.nil? || Support.object_hash(affinity).empty?
          required = Support.value(affinity, "required", Support.value(affinity, "requiredDuringSchedulingIgnoredDuringExecution", affinity))
          required = Support.object_hash(required)
          terms = Array(Support.value(required, "nodeSelectorTerms", []))
          return true if terms.empty?
          terms.any? do |term|
            Array(Support.value(term, "matchExpressions", [])).all? do |expression|
              requirement_matches?(expression, node.labels)
            end && Array(Support.value(term, "matchFields", [])).all? do |expression|
              requirement_matches?(expression, {"metadata.name" => node.name})
            end
          end
        end

        def requirement_matches?(expression, labels)
          expression = Support.object_hash(expression)
          key = Support.value(expression, "key", "").to_s
          operator = Support.value(expression, "operator", "In").to_s
          values = Array(Support.value(expression, "values", [])).map(&:to_s)
          present = labels.key?(key)
          actual = labels[key].to_s
          case operator
          when "In" then present && values.include?(actual)
          when "NotIn" then !present || !values.include?(actual)
          when "Exists" then present
          when "DoesNotExist" then !present
          when "Gt" then present && numeric_compare(actual, values.first, :>)
          when "Lt" then present && numeric_compare(actual, values.first, :<)
          else false
          end
        end

        def node_volume_counts(node, context)
          counts = Hash.new(0)
          Array(node.pods).each do |pod|
            pod.volumes.each do |volume|
              source = volume_source(volume, pod, context)
              next unless source

              driver = volume_driver(volume, pod, context)
              counts[driver] += 1 unless driver.empty?
            end
          end
          counts
        end

        def volume_driver(volume, pod, context)
          pv = pv_for(volume, pod, context)
          source = Support.value(pv, "csi", Support.value(Support.value(pv, "spec", {}), "csi", nil)) if pv
          source ||= Support.value(volume, "csi", nil)
          Support.value(source, "driver", "").to_s if source
        end

        def node_for_pod(pod, context, fallback: nil)
          node_name = pod.node_name
          return fallback if node_name.empty? && fallback

          context_nodes(context).find { |item| item.name == node_name } || fallback
        end

        def labels_for(value)
          return value.labels if value.is_a?(Pod) || value.is_a?(Node)
          raw = Support.object_hash(value)
          if raw.key?("metadata")
            Support.labels(raw)
          else
            Support.deep_freeze(raw.transform_values(&:to_s))
          end
        end

        def selector_matches?(labels, selector)
          selector = Support.object_hash(selector || {})
          labels = labels_for(labels)
          Support.object_hash(Support.value(selector, "matchLabels", {})).all? do |key, expected|
            labels[key.to_s] == expected.to_s
          end && Array(Support.value(selector, "matchExpressions", [])).all? do |expression|
            requirement_matches?(expression, labels)
          end
        end

        def numeric_compare(left, right, operator)
          left_number = Integer(left)
          right_number = Integer(right)
          left_number.public_send(operator, right_number)
        rescue ArgumentError, TypeError
          false
        end

        def topology_value(node, key)
          node.labels[key.to_s]
        end

        def namespaces_for(term, pod)
          explicit = Array(Support.value(term, "namespaces", nil)).map(&:to_s)
          return explicit unless explicit.empty?

          selector = Support.value(term, "namespaceSelector", nil)
          return ["*"] if selector && selector_matches?({}, selector)

          [pod.namespace]
        end

        def namespace_matches?(existing_pod, term, pending_pod, context)
          explicit_namespaces = Array(Support.value(term, "namespaces", nil)).map(&:to_s)
          selector = Support.value(term, "namespaceSelector", nil)
          if selector
            namespace_labels = if context.respond_to?(:namespace_labels)
                                 context.namespace_labels(existing_pod.namespace)
                               else
                                 {}
                               end
            return true if selector_matches?(namespace_labels, selector)
            return explicit_namespaces.include?(existing_pod.namespace) unless explicit_namespaces.empty?

            return false
          end

          namespaces = explicit_namespaces.empty? ? [pending_pod.namespace] : explicit_namespaces
          namespaces.include?("*") || namespaces.include?(existing_pod.namespace)
        end

        def effective_selector(term, pending_pod)
          selector = Support.object_hash(Support.value(term, "labelSelector", {}))
          labels = pending_pod.labels
          Array(Support.value(term, "matchLabelKeys", [])).each do |key|
            key = key.to_s
            next unless labels.key?(key)

            selector["matchLabels"] = Support.object_hash(Support.value(selector, "matchLabels", {}))
            selector["matchLabels"][key] = labels[key]
          end
          Array(Support.value(term, "mismatchLabelKeys", [])).each do |key|
            key = key.to_s
            next unless labels.key?(key)

            selector["matchExpressions"] = Array(Support.value(selector, "matchExpressions", []))
            selector["matchExpressions"] << {"key" => key, "operator" => "NotIn", "values" => [labels[key]]}
          end
          selector
        end

        def matching_pod?(existing_pod, term, pending_pod, context)
          namespace_matches?(existing_pod, term, pending_pod, context) &&
            selector_matches?(existing_pod.labels, effective_selector(term, pending_pod))
        end

        def in_same_domain?(existing_pod, existing_node, candidate_node, topology_key)
          existing_value = topology_value(existing_node, topology_key)
          candidate_value = topology_value(candidate_node, topology_key)
          !existing_value.nil? && !candidate_value.nil? && existing_value == candidate_value
        end

        def term_has_matching_pod?(term, pod, node, context)
          topology_key = Support.value(term, "topologyKey", "").to_s
          return false if topology_key.empty?

          context_pods(context, node).any? do |existing_pod|
            next false if existing_pod.uid == pod.uid && !pod.uid.empty?

            existing_node = node_for_pod(existing_pod, context)
            existing_node && in_same_domain?(existing_pod, existing_node, node, topology_key) &&
              matching_pod?(existing_pod, term, pod, context)
          end
        end

        # Kubernetes permits the first Pod in a self-affinity group to land
        # without an existing matching Pod.  Without this exception a group
        # whose members all require their own label would deadlock forever.
        def affinity_term_satisfied?(term, pod, node, context)
          return true if term_has_matching_pod?(term, pod, node, context)

          topology_key = Support.value(term, "topologyKey", "").to_s
          return false if topology_key.empty? || topology_value(node, topology_key).nil?
          return false unless matching_pod?(pod, term, pod, context)

          context_pods(context, node).none? do |existing_pod|
            next false if existing_pod.uid == pod.uid && !pod.uid.empty?
            next false unless node_for_pod(existing_pod, context)

            matching_pod?(existing_pod, term, pod, context)
          end
        end

        def tolerates?(toleration, taint)
          toleration = Support.object_hash(toleration)
          taint = Support.object_hash(taint)
          taint_effect = Support.value(taint, "effect", "").to_s
          tolerance_effect = Support.value(toleration, "effect", "").to_s
          return false unless tolerance_effect.empty? || tolerance_effect == taint_effect

          key = Support.value(toleration, "key", "").to_s
          operator = Support.value(toleration, "operator", "").to_s
          value = Support.value(toleration, "value", "").to_s
          taint_key = Support.value(taint, "key", "").to_s
          taint_value = Support.value(taint, "value", "").to_s
          if operator.empty?
            operator = value.empty? ? "Exists" : "Equal"
          end
          case operator
          when "Exists"
            key.empty? || key == taint_key
          when "Equal"
            !key.empty? && key == taint_key && value == taint_value
          else
            false
          end
        end
      end

      # PreEnqueue's gate check is represented as a filter in the local
      # framework so direct schedule calls and queue-driven calls share the
      # same fail-closed behavior.
      class SchedulingGates
        def call(pod, _node = nil, _context = nil)
          return true if pod.scheduling_gates.empty?

          Helpers.reject("waiting for scheduling gates: #{pod.scheduling_gates.map { |gate| Support.value(gate, 'name', '') }}",
                        code: "SchedulingGates")
        end

        alias filter call
      end

      # plugins/gangscheduling: a Pod in a gang PodGroup waits in PreEnqueue
      # until minCount members exist; Permit, run at the end of a pod-group
      # cycle, allows once minCount are assumed (the group cycle never binds
      # a partial gang, so there is nothing left to wait for).
      class GangScheduling
        PERMIT_TIMEOUT_SECONDS = 300.0

        def pre_enqueue(pod, _node = nil, context = nil)
          group_name = pod.respond_to?(:scheduling_group) ? pod.scheduling_group : nil
          return true if group_name.nil?

          group = context.respond_to?(:pod_group) ? context.pod_group(pod.namespace, group_name) : nil
          return Helpers.reject("waiting for pods's pod group #{group_name.inspect} to appear in scheduling queue", code: "GangScheduling") if group.nil?

          gang = Support.value(Support.value(Support.value(group, "spec", {}), "schedulingPolicy", {}), "gang", nil)
          return true if gang.nil?

          members = Array(context&.pods).count { |other| other.namespace == pod.namespace && other.scheduling_group == group_name && other.uid != pod.uid } + 1
          return true if members >= Support.value(gang, "minCount", 0).to_i

          Helpers.reject("waiting for minCount pods from a gang to appear in scheduling queue", code: "GangScheduling")
        end

        # Permit.
        def call(pod, _node = nil, context = nil)
          group_name = pod.respond_to?(:scheduling_group) ? pod.scheduling_group : nil
          return true if group_name.nil?

          group = context.respond_to?(:pod_group) ? context.pod_group(pod.namespace, group_name) : nil
          gang = group && Support.value(Support.value(Support.value(group, "spec", {}), "schedulingPolicy", {}), "gang", nil)
          return true if gang.nil?

          scheduled = Array(context&.pods).count { |other| other.namespace == pod.namespace && other.scheduling_group == group_name && !other.node_name.empty? } + 1
          return true if scheduled >= Support.value(gang, "minCount", 0).to_i

          Permit::Wait.new(PERMIT_TIMEOUT_SECONDS)
        end

        alias permit call
      end

      class NodeResourcesFit
        def call(pod, node, context = nil)
          requested = pod.requests
          allocatable = node.allocatable
          missing = requested.each_with_object({}) do |(resource, amount), result|
            # shouldDelegateResourceToDRA: an extended resource the node does
            # not advertise and a DeviceClass provides is DynamicResources'.
            next if dra_backed?(resource, allocatable, context)

            available = allocatable.fetch(resource, Rational(0)) - node.requested.fetch(resource, Rational(0))
            result[resource] = {"requested" => amount, "available" => [available, Rational(0)].max} if amount > available
          end
          return true if missing.empty?

          Helpers.reject("node has insufficient resources", code: "Insufficient", details: {"resources" => missing})
        end

        alias filter call

        private

        def dra_backed?(resource, allocatable, context)
          return false if allocatable.fetch(resource, Rational(0)).positive?
          return false unless Rubernetes::DRA::ExtendedResources.extended_resource_name?(resource)
          return false unless context.respond_to?(:cycle_state) && context.respond_to?(:volume_data)

          classes = Array(context.volume_data.is_a?(Hash) ? context.volume_data["deviceClasses"] : nil)
          return false if classes.empty?

          resolver = context.cycle_state[:dra_extended_resolver] ||= Rubernetes::DRA::ExtendedResources::Resolver.new(
            classes.map { |klass| Support.object_hash(klass) }
          )
          !resolver.device_class(resource).nil?
        end
      end

      class NodePorts
        def call(pod, node, _context = nil)
          requested = Helpers.pod_host_ports(pod)
          return true if requested.empty?

          used = Helpers.node_host_ports(node)
          conflict = requested.find { |wanted| used.any? { |existing| Helpers.ports_conflict?(wanted, existing) } }
          return true unless conflict

          Helpers.reject("node has no free host port #{conflict.fetch('hostPort')}/#{conflict.fetch('protocol')}",
                         code: "NodePorts", details: {"port" => conflict})
        end

        alias filter call
      end

      class VolumeRestrictions
        RESTRICTED_SOURCES = %w[gcePersistentDisk awsElasticBlockStore iscsi rbd].freeze

        def call(pod, node, context = nil)
          existing = Helpers.context_pods(context, node).reject { |candidate| candidate.uid == pod.uid && !pod.uid.empty? }
          pod.volumes.each do |volume|
            source = Helpers.volume_source(volume, pod, context)
            next unless source && RESTRICTED_SOURCES.include?(source.fetch("kind"))

            existing.each do |candidate|
              candidate.volumes.each do |existing_volume|
                next unless Helpers.volume_source(existing_volume, candidate, context) == source
                next if Helpers.volume_read_only?(volume) && Helpers.volume_read_only?(existing_volume)

                return Helpers.reject("node has a conflicting volume #{source.fetch('name')}", code: "VolumeRestrictions",
                                      details: {"volume" => source})
              end
            end
          end

          claim_names = Helpers.pod_volume_claim_names(pod)
          claims = Helpers.collection(Helpers.volume_data(context), "persistentVolumeClaims", "pvcs", "claims")
          rwop_claims = claim_names.select do |name|
            claim = Helpers.lookup_resource(claims, name, namespace: pod.namespace)
            modes = claim && Support.value(claim, "accessModes", Support.value(Support.value(claim, "spec", {}), "accessModes", []))
            Array(modes).map(&:to_s).include?("ReadWriteOncePod")
          end
          rwop_claims.each do |claim_name|
            conflict = Helpers.context_pods(context).any? do |candidate|
              next false if candidate.uid == pod.uid && !pod.uid.empty?

              candidate.namespace == pod.namespace && Helpers.pod_volume_claim_names(candidate).include?(claim_name)
            end
            if conflict
              return Helpers.reject("persistent volume claim #{claim_name.inspect} is already used by another Pod",
                                    code: "VolumeRestrictions", details: {"claimName" => claim_name})
            end
          end
          true
        end

        alias filter call
      end

      class VolumeZone
        def call(pod, node, context = nil)
          pod.volumes.each do |volume|
            pv = Helpers.pv_for(volume, pod, context)
            affinity = if pv
                         Support.value(pv, "nodeAffinity", Support.value(Support.value(pv, "spec", {}), "nodeAffinity", nil))
                       end
            unless Helpers.node_affinity_matches?(affinity, node)
              return Helpers.reject("node does not satisfy persistent volume topology", code: "VolumeZone",
                                    details: {"node" => node.name})
            end

            zones = volume_zones(volume, pv, context)
            next if zones.empty? || zones.any? { |zone| zone_matches_node?(zone, node) }

            return Helpers.reject("node is outside the volume topology", code: "VolumeZone",
                                  details: {"zones" => zones})
          end
          true
        end

        alias filter call

        private

        def volume_zones(volume, pv, context)
          source = pv || volume
          spec = Support.value(source, "spec", {})
          topology = Support.value(source, "topology", Support.value(spec, "topology", {}))
          raw = Support.value(source, "zones", Support.value(source, "zone", nil))
          raw = Support.value(spec, "zones", Support.value(spec, "zone", raw))
          raw = Support.value(topology, "zone", raw)
          raw = Support.value(topology, "zones", raw)
          if raw.nil? && context
            data = Helpers.volume_data(context)
            zone_map = Helpers.collection(data, "volumeZones", "zones")
            volume_name = Support.value(source, "name", Support.value(Support.value(source, "metadata", {}), "name", nil))
            raw = Helpers.lookup_resource(zone_map, volume_name) if volume_name
          end
          Array(raw).map(&:to_s).reject(&:empty?).uniq
        end

        def zone_matches_node?(zone, node)
          return true if node.labels.values.map(&:to_s).include?(zone.to_s)
          node.labels.any? { |key, value| key.to_s.match?(/(?:zone|region)$/) && value.to_s == zone.to_s }
        end
      end

      # nodevolumelimits.CSILimits (v1.36.2): the CSI volumes a Pod would add
      # to a node, counted per driver against the node's CSINode
      # spec.drivers[].allocatable.count.  Volumes are unique by driver and
      # volume handle -- one volume used by several Pods counts once --
      # through PVCs (bound PV, else the StorageClass provisioner), generic
      # ephemeral volumes, migrated in-tree volumes, and VolumeAttachments to
      # the node.  Without CSINode data in the cycle (an embedded framework)
      # the node's own "volumeLimits" map is used, as before.
      class NodeVolumeLimits
        REASON = "node(s) exceed max volume count"
        # csi-translation-lib: in-tree plugin => [CSI driver, inline source].
        IN_TREE = {
          "kubernetes.io/aws-ebs" => ["ebs.csi.aws.com", "awsElasticBlockStore"],
          "kubernetes.io/gce-pd" => ["pd.csi.storage.gke.io", "gcePersistentDisk"],
          "kubernetes.io/azure-disk" => ["disk.csi.azure.com", "azureDisk"],
          "kubernetes.io/cinder" => ["cinder.csi.openstack.org", "cinder"],
          "kubernetes.io/portworx-volume" => ["pxd.portworx.com", "portworxVolume"],
          "kubernetes.io/vsphere-volume" => ["csi.vsphere.vmware.com", "vsphereVolume"],
          "kubernetes.io/azure-file" => ["file.csi.azure.com", "azureFile"]
        }.freeze
        # isCSIMigrationOn: the plugins whose migration is on.
        MIGRATED = %w[kubernetes.io/aws-ebs kubernetes.io/portworx-volume kubernetes.io/gce-pd
                      kubernetes.io/azure-disk kubernetes.io/cinder].freeze

        def initialize(volume_limit_scaling: false)
          @volume_limit_scaling = volume_limit_scaling
          @random_prefix = SecureRandom.alphanumeric(32).downcase
        end

        def call(pod, node, context = nil)
          data = Helpers.volume_data(context)
          return legacy(pod, node, context) if Helpers.collection(data, "csiNodes").nil?
          # PreFilter: nothing a CSI limit could apply to.
          return true unless pod.volumes.any? { |volume| considered?(volume) }

          index = index_for(data)
          csi_node = index[:csi_nodes][node.name]
          new_volumes = {}
          begin
            filter_attachable(pod, csi_node, index, true, new_volumes)
          rescue ClaimNotFound => error
            return Helpers.reject(error.message, code: "UnschedulableAndUnresolvable")
          rescue ArgumentError => error
            return Helpers.reject(error.message, code: "NodeVolumeLimits")
          end
          return true if new_volumes.empty?

          if @volume_limit_scaling
            new_volumes.each_value do |driver|
              next if driver_installed?(driver, csi_node, index)

              return Helpers.reject("#{driver} CSI driver is not installed on the node", code: "NodeVolumeLimits")
            end
          end
          limits = volume_limits(csi_node)
          return true if limits.empty?

          attached = {}
          Array(node.pods).each do |existing|
            filter_attachable(existing, csi_node, index, false, attached)
          rescue ArgumentError
            next
          end
          counts = Hash.new(0)
          attached.each do |unique, driver|
            new_volumes.delete(unique)
            counts[driver] += 1
          end
          attachments(node.name, index).each do |unique, driver|
            counts[driver] += 1 unless attached.key?(unique)
          end
          requested = Hash.new(0)
          new_volumes.each_value { |driver| requested[driver] += 1 }
          requested.each do |driver, count|
            limit = limits[driver]
            next if limit.nil? || counts[driver] + count <= limit

            return Helpers.reject(REASON, code: "NodeVolumeLimits",
                                  details: {"driver" => driver, "used" => counts[driver], "requested" => count, "limit" => limit})
          end
          true
        end

        alias filter call

        class ClaimNotFound < StandardError; end

        private

        def considered?(volume)
          !Support.value(volume, "persistentVolumeClaim", nil).nil? || !Support.value(volume, "ephemeral", nil).nil? ||
            IN_TREE.values.any? { |_driver, key| !Support.value(volume, key, nil).nil? }
        end

        # Name-keyed lookups built once per cluster view.
        def index_for(data)
          return @index if @index_key.equal?(data)

          name = ->(object) { Support.value(Support.value(object, "metadata", {}), "name", Support.value(object, "name", "")).to_s }
          namespace = ->(object) { Support.value(Support.value(object, "metadata", {}), "namespace", Support.value(object, "namespace", "")).to_s }
          items = ->(*keys) { Helpers.items(Helpers.collection(data, *keys)) }
          @index = {
            csi_nodes: items.call("csiNodes").to_h { |object| [name.call(object), object] },
            csi_drivers: items.call("csiDrivers").to_h { |object| [name.call(object), object] },
            claims: items.call("persistentVolumeClaims", "pvcs", "claims").to_h { |object| ["#{namespace.call(object)}/#{name.call(object)}", object] },
            volumes: items.call("persistentVolumes", "pvs", "volumes").to_h { |object| [name.call(object), object] },
            classes: items.call("storageClasses").to_h { |object| [name.call(object), object] },
            attachments: items.call("volumeAttachments").group_by { |object| Support.value(Support.value(object, "spec", {}), "nodeName", "").to_s }
          }
          @index_key = data
          @index
        end

        # filterAttachableVolumes: unique volume name => driver.
        def filter_attachable(pod, csi_node, index, new_pod, result)
          pod.volumes.each do |volume|
            claim_name = nil
            ephemeral = false
            if (claim = Support.value(volume, "persistentVolumeClaim", nil))
              claim_name = Support.value(claim, "claimName", "").to_s
            elsif Support.value(volume, "ephemeral", nil)
              # ephemeral.VolumeClaimName
              claim_name = "#{pod.name}-#{Support.value(volume, "name", "")}"
              ephemeral = true
            else
              inline(volume, csi_node, result)
              next
            end
            raise ArgumentError, "PersistentVolumeClaim had no name" if claim_name.empty?

            pvc = index[:claims]["#{pod.namespace}/#{claim_name}"]
            if pvc.nil?
              raise ClaimNotFound, %(looking up PVC #{pod.namespace}/#{claim_name}: persistentvolumeclaim "#{claim_name}" not found) if new_pod

              next
            end
            owned_by_pod!(pod, pvc) if ephemeral
            driver, handle = driver_info(csi_node, pvc, index)
            next if driver.to_s.empty? || handle.to_s.empty?

            result["#{driver}/#{handle}"] = driver
          end
        end

        # ephemeral.VolumeIsForPod.
        def owned_by_pod!(pod, pvc)
          metadata = Support.value(pvc, "metadata", {})
          owner = Array(Support.value(metadata, "ownerReferences", [])).find { |reference| Support.value(reference, "controller", false) == true }
          return if owner && Support.value(owner, "uid", "").to_s == pod.uid.to_s

          raise ArgumentError, "PVC #{Support.value(metadata, "namespace", "")}/#{Support.value(metadata, "name", "")} was not created for pod " \
                               "#{pod.namespace}/#{pod.name} (pod is not owner)"
        end

        # checkAttachableInlineVolume.
        def inline(volume, csi_node, result)
          plugin, (driver, key) = IN_TREE.find { |_plugin, (_driver, source)| Support.value(volume, source, nil) }
          return unless plugin && migration_on?(csi_node, plugin)

          handle = in_tree_handle(key, Support.value(volume, key, {}), nil)
          result["#{driver}/#{handle}"] = driver if handle
        end

        # getCSIDriverInfo.
        def driver_info(csi_node, pvc, index)
          pv_name = Support.value(Support.value(pvc, "spec", {}), "volumeName", "").to_s
          return driver_from_class(csi_node, pvc, index) if pv_name.empty?

          pv = index[:volumes][pv_name]
          return driver_from_class(csi_node, pvc, index) if pv.nil?

          spec = Support.value(pv, "spec", {})
          csi = Support.value(spec, "csi", nil)
          return [Support.value(csi, "driver", "").to_s, Support.value(csi, "volumeHandle", "").to_s] if csi

          plugin, (driver, key) = IN_TREE.find { |_plugin, (_driver, source)| Support.value(spec, source, nil) }
          return [nil, nil] unless plugin && MIGRATED.include?(plugin) && migration_on?(csi_node, plugin)

          [driver, in_tree_handle(key, Support.value(spec, key, {}), pv)]
        end

        # getCSIDriverInfoFromSC.
        def driver_from_class(csi_node, pvc, index)
          spec = Support.value(pvc, "spec", {})
          class_name = Support.value(spec, "storageClassName", nil)
          class_name ||= Support.value(Support.value(Support.value(pvc, "metadata", {}), "annotations", {}), "volume.beta.kubernetes.io/storage-class", nil)
          return [nil, nil] if class_name.to_s.empty?

          storage_class = index[:classes][class_name.to_s]
          return [nil, nil] if storage_class.nil?

          metadata = Support.value(pvc, "metadata", {})
          handle = "#{@random_prefix}-#{Support.value(metadata, "namespace", "")}/#{Support.value(metadata, "name", "")}"
          provisioner = Support.value(storage_class, "provisioner", "").to_s
          if IN_TREE.key?(provisioner) && MIGRATED.include?(provisioner)
            return [nil, nil] unless migration_on?(csi_node, provisioner)

            return [IN_TREE[provisioner].first, handle]
          end
          [provisioner, handle]
        end

        def migration_on?(csi_node, plugin) = !csi_node.nil? && MIGRATED.include?(plugin)

        # The volume handle csi-translation-lib gives each in-tree source.
        def in_tree_handle(key, source, pv)
          case key
          when "awsElasticBlockStore"
            id = Support.value(source, "volumeID", "").to_s
            id.start_with?("aws://") ? id.split("/").last : id
          when "gcePersistentDisk"
            labels = Support.value(Support.value(pv, "metadata", {}), "labels", {}) if pv
            zone = pv && (Support.value(labels, "topology.kubernetes.io/zone", nil) || Support.value(labels, "failure-domain.beta.kubernetes.io/zone", nil))
            zones = zone.to_s.split("__")
            disk = Support.value(source, "pdName", "")
            if zones.length > 1
              "projects/UNSPECIFIED/regions/#{zones.first.sub(/-[^-]+\z/, "")}/disks/#{disk}"
            else
              "projects/UNSPECIFIED/zones/#{zones.first || "UNSPECIFIED"}/disks/#{disk}"
            end
          when "azureDisk" then Support.value(source, "diskURI", "").to_s
          when "cinder", "portworxVolume" then Support.value(source, "volumeID", "").to_s
          when "vsphereVolume" then Support.value(source, "volumePath", "").to_s
          when "azureFile" then Support.value(source, "shareName", "").to_s
          end
        end

        # getVolumeLimits.
        def volume_limits(csi_node)
          return {} if csi_node.nil?

          Array(Support.value(Support.value(csi_node, "spec", {}), "drivers", [])).each_with_object({}) do |driver, limits|
            count = Support.value(Support.value(driver, "allocatable", {}), "count", nil)
            limits[Support.value(driver, "name", "").to_s] = Integer(count) unless count.nil?
          end
        end

        # checkCSIDriverOnNode (VolumeLimitScaling).
        def driver_installed?(driver, csi_node, index)
          csi_driver = index[:csi_drivers][driver]
          return true if csi_driver.nil?
          return true unless Support.value(Support.value(csi_driver, "spec", {}), "preventPodSchedulingIfMissing", false) == true
          return false if csi_node.nil?

          Array(Support.value(Support.value(csi_node, "spec", {}), "drivers", [])).any? { |entry| Support.value(entry, "name", "").to_s == driver }
        end

        # getNodeVolumeAttachmentInfo.
        def attachments(node_name, index)
          Array(index[:attachments][node_name.to_s]).each_with_object({}) do |attachment, result|
            spec = Support.value(attachment, "spec", {})
            attacher = Support.value(spec, "attacher", "").to_s
            pv_name = Support.value(Support.value(spec, "source", {}), "persistentVolumeName", nil)
            next if attacher.empty? || pv_name.nil?

            csi = Support.value(Support.value(index[:volumes][pv_name.to_s], "spec", {}), "csi", nil)
            next if csi.nil?

            result["#{attacher}/#{Support.value(csi, "volumeHandle", "")}"] = attacher
          end
        end

        # The pre-CSINode form: a "volumeLimits" map on the node.
        def legacy(pod, node, context)
          limits = node.volume_limits
          return true if limits.empty?

          requested = Hash.new(0)
          pod.volumes.each do |volume|
            driver = Helpers.volume_driver(volume, pod, context)
            next if driver.empty?
            requested[driver] += 1
          end
          counts = Helpers.node_volume_counts(node, context)
          requested.each do |driver, amount|
            limit = legacy_limit(limits, driver)
            next if limit.nil? || counts.fetch(driver, 0) + amount <= limit

            return Helpers.reject(REASON, code: "NodeVolumeLimits",
                                  details: {"driver" => driver, "used" => counts.fetch(driver, 0),
                                            "requested" => amount, "limit" => limit})
          end
          true
        end

        def legacy_limit(limits, driver)
          direct = Support.value(limits, driver, nil)
          direct ||= Support.value(limits, "default", nil)
          direct = Support.value(direct, "limit", nil) if direct.respond_to?(:to_h)
          return nil if direct.nil? || direct.to_s.empty?

          Integer(direct)
        rescue ArgumentError, TypeError
          raise ValidationError, "volume attach limit for #{driver} must be an integer"
        end
      end

      class VolumeBinding
        def call(pod, node, context = nil)
          claims = Helpers.collection(Helpers.volume_data(context), "persistentVolumeClaims", "pvcs", "claims")
          volumes = Helpers.collection(Helpers.volume_data(context), "persistentVolumes", "pvs", "volumes")
          pod.volumes.each do |volume|
            claim_ref = Support.value(volume, "persistentVolumeClaim", nil)
            next unless claim_ref

            claim_name = Support.value(claim_ref, "claimName", "").to_s
            next if claim_name.empty?
            claim = Helpers.lookup_resource(claims, claim_name, namespace: pod.namespace)
            return Helpers.reject("persistent volume claim #{claim_name.inspect} was not found", code: "VolumeBinding",
                                  details: {"claimName" => claim_name}) if claim.nil?

            bound_name = Support.value(claim, "volumeName", Support.value(Support.value(claim, "spec", {}), "volumeName", nil))
            if bound_name && !bound_name.to_s.empty?
              pv = Helpers.lookup_resource(volumes, bound_name)
              return Helpers.reject("persistent volume #{bound_name.inspect} is unavailable", code: "VolumeBinding") unless pv
              phase = Support.value(pv, "phase", Support.value(Support.value(pv, "status", {}), "phase", "Available")).to_s
              return Helpers.reject("persistent volume #{bound_name.inspect} is not bound", code: "VolumeBinding") if phase == "Released" || phase == "Failed"
              next
            end

            next if matching_volume?(claim, volumes, node)
            mode = storage_binding_mode(claim, Helpers.volume_data(context))
            next if mode == "WaitForFirstConsumer" && dynamic_provisioning_available?(claim, Helpers.volume_data(context))

            return Helpers.reject("no persistent volume matches claim #{claim_name.inspect}", code: "VolumeBinding",
                                  details: {"claimName" => claim_name})
          end
          true
        end

        alias filter call

        def reserve(pod, node, context = nil)
          call(pod, node, context)
        end

        def pre_bind(pod, node, context = nil)
          call(pod, node, context)
        end

        def unreserve(_pod, _node, _context = nil)
          true
        end

        private

        def matching_volume?(claim, volumes, node)
          Helpers.items(volumes).any? do |pv|
            phase = Support.value(pv, "phase", Support.value(Support.value(pv, "status", {}), "phase", "Available")).to_s
            next false unless phase == "Available"
            pv_spec = Support.value(pv, "spec", {})
            capacity = Support.value(pv, "capacityBytes",
                                     Support.value(pv, "capacity",
                                                   Support.value(pv_spec, "capacity", {})))
            capacity = Support.value(capacity, "storage", 0) if capacity.respond_to?(:to_h)
            claim_spec = Support.value(claim, "spec", {})
            resources = Support.value(claim, "resources", Support.value(claim_spec, "resources", {}))
            requests = Support.value(resources, "requests", {})
            request = Support.value(claim, "requestedBytes", Support.value(requests, "storage", 0))
            claim_class = Support.value(claim, "storageClassName", Support.value(claim_spec, "storageClassName", "")).to_s
            pv_class = Support.value(pv, "storageClassName", Support.value(pv_spec, "storageClassName", "")).to_s
            class_matches = claim_class.empty? || pv_class == claim_class
            class_matches && Support.quantity(capacity, "memory") >= Support.quantity(request, "memory") &&
              Helpers.node_affinity_matches?(Support.value(pv, "nodeAffinity", Support.value(pv_spec, "nodeAffinity", nil)), node)
          rescue ArgumentError
            false
          end
        end

        def storage_binding_mode(claim, data)
          class_name = Support.value(claim, "storageClassName", Support.value(Support.value(claim, "spec", {}), "storageClassName", "")).to_s
          classes = Helpers.collection(data, "storageClasses", "classes")
          klass = Helpers.lookup_resource(classes, class_name)
          Support.value(klass, "volumeBindingMode", Support.value(klass && Support.value(klass, "spec", {}), "volumeBindingMode", "Immediate")).to_s
        end

        def dynamic_provisioning_available?(claim, data)
          class_name = Support.value(claim, "storageClassName", Support.value(Support.value(claim, "spec", {}), "storageClassName", "")).to_s
          classes = Helpers.collection(data, "storageClasses", "classes")
          klass = Helpers.lookup_resource(classes, class_name)
          provisioner = Support.value(klass, "provisioner", Support.value(Support.value(klass, "spec", {}), "provisioner", "")).to_s
          !provisioner.empty? && provisioner != "kubernetes.io/no-provisioner"
        end
      end

      class PodTopologySpread
        def call(pod, node, context = nil)
          pod.topology_spread_constraints.each do |raw_constraint|
            constraint = Support.object_hash(raw_constraint)
            next unless Support.value(constraint, "whenUnsatisfiable", "DoNotSchedule").to_s == "DoNotSchedule"

            topology_key = Support.value(constraint, "topologyKey", "").to_s
            next if topology_key.empty?
            candidate_domain = node.labels[topology_key]
            return Helpers.reject("node lacks topology key #{topology_key.inspect}", code: "PodTopologySpread") if candidate_domain.nil?

            domains = Helpers.context_nodes(context).filter_map { |item| item.labels[topology_key] }.uniq
            domains = [candidate_domain] if domains.empty?
            selector = Helpers.effective_selector(constraint, pod)
            counts = domains.to_h { |domain| [domain, matching_count(domain, topology_key, selector, pod, context)] }
            counts[candidate_domain] ||= 0
            min_domains = Integer(Support.value(constraint, "minDomains", 1) || 1)
            minimum = domains.length < min_domains ? 0 : counts.values.min
            max_skew = Integer(Support.value(constraint, "maxSkew", 1) || 1)
            if counts.fetch(candidate_domain) + 1 - minimum > max_skew
              return Helpers.reject("node would violate topology spread maxSkew", code: "PodTopologySpread",
                                    details: {"topologyKey" => topology_key, "domain" => candidate_domain,
                                              "skew" => counts.fetch(candidate_domain) + 1 - minimum,
                                              "maxSkew" => max_skew})
            end
          rescue ArgumentError, TypeError
            return Helpers.reject("pod topology spread constraint is invalid", code: "PodTopologySpread")
          end
          true
        end

        alias filter call

        private

        def matching_count(domain, topology_key, selector, pod, context)
          Helpers.context_pods(context).count do |existing|
            next false if existing.uid == pod.uid && !pod.uid.empty?
            existing_node = Helpers.node_for_pod(existing, context)
            existing_node && existing_node.labels[topology_key] == domain &&
              Helpers.namespace_matches?(existing, {"labelSelector" => selector}, pod, context) &&
              Helpers.selector_matches?(existing.labels, selector)
          end
        end
      end

      # Kubernetes v1.36.2 keeps node unschedulability as a distinct default
      # plugin.  Readiness is checked here as well because this Ruby pipeline
      # has no separate node-condition plugin; the resulting rejection stays
      # observable at the same Filter boundary.
      class NodeUnschedulable
        def call(_pod, node, _context = nil)
          return Helpers.reject("node is unschedulable", code: "Unschedulable") if node.unschedulable?
          return true if node.ready?

          Helpers.reject("node is not Ready", code: "NodeNotReady")
        end

        alias filter call
      end

      class NodeName
        def call(pod, node, _context = nil)
          requested = pod.node_name
          return true if requested.empty? || requested == node.name

          Helpers.reject("pod nodeName #{requested.inspect} does not match node #{node.name.inspect}", code: "NodeName")
        end

        alias filter call
      end

      class NodeSelector
        def call(pod, node, _context = nil)
          pod.node_selector.all? do |key, expected|
            next true if node.labels[key.to_s] == expected.to_s

            return Helpers.reject("node does not match nodeSelector #{key}=#{expected}", code: "NodeSelector")
          end
          true
        end

        alias filter call
      end

      class NodeAffinity
        def call(pod, node, _context = nil)
          pod.node_selector.each do |key, expected|
            next if node.labels[key.to_s] == expected.to_s

            return Helpers.reject("node does not match nodeSelector #{key}=#{expected}", code: "NodeSelector")
          end
          required = Support.value(pod.node_affinity, "requiredDuringSchedulingIgnoredDuringExecution", nil)
          return true if required.nil?

          selector = Support.object_hash(required)
          terms = Array(Support.value(selector, "nodeSelectorTerms", []))
          return Helpers.reject("node affinity has no matching selector term", code: "NodeAffinity") if terms.empty?
          return true if terms.any? { |term| term_matches?(Support.object_hash(term), node) }

          Helpers.reject("node does not satisfy required node affinity", code: "NodeAffinity")
        end

        alias filter call

        private

        def term_matches?(term, node)
          expressions = Array(Support.value(term, "matchExpressions", []))
          fields = Array(Support.value(term, "matchFields", []))
          expressions.all? { |item| requirement_matches?(item, node.labels) } &&
            fields.all? { |item| requirement_matches?(item, {"metadata.name" => node.name}) }
        end

        def requirement_matches?(requirement, labels)
          requirement = Support.object_hash(requirement)
          key = Support.value(requirement, "key", "").to_s
          operator = Support.value(requirement, "operator", "").to_s
          values = Array(Support.value(requirement, "values", [])).map(&:to_s)
          present = labels.key?(key)
          actual = labels[key]
          case operator
          when "In" then present && values.include?(actual.to_s)
          when "NotIn" then !present || !values.include?(actual.to_s)
          when "Exists" then present
          when "DoesNotExist" then !present
          when "Gt" then present && Helpers.numeric_compare(actual, values.first, :>)
          when "Lt" then present && Helpers.numeric_compare(actual, values.first, :<)
          else false
          end
        end
      end

      class TaintToleration
        def call(pod, node, _context = nil)
          untolerated = node.taints.select do |taint|
            effect = Support.value(taint, "effect", "").to_s
            %w[NoSchedule NoExecute].include?(effect) &&
              !pod.tolerations.any? { |toleration| Helpers.tolerates?(toleration, taint) }
          end
          return true if untolerated.empty?

          Helpers.reject("pod does not tolerate node taint #{Support.value(untolerated.first, 'key', '')}", code: "TaintToleration",
                         details: {"taints" => untolerated})
        end

        alias filter call
      end

      class PodAffinity
        def call(pod, node, context = nil)
          terms = Array(Support.value(pod.pod_affinity, "requiredDuringSchedulingIgnoredDuringExecution", []))
          return true if terms.empty?
          return true if terms.all? { |term| Helpers.affinity_term_satisfied?(Support.object_hash(term), pod, node, context) }

          Helpers.reject("node does not satisfy required pod affinity", code: "PodAffinity")
        end

        alias filter call
      end

      class PodAntiAffinity
        def call(pod, node, context = nil)
          terms = Array(Support.value(pod.pod_anti_affinity, "requiredDuringSchedulingIgnoredDuringExecution", []))
          return true if terms.empty?
          return true if terms.none? { |term| Helpers.term_has_matching_pod?(Support.object_hash(term), pod, node, context) }

          Helpers.reject("node violates required pod anti-affinity", code: "PodAntiAffinity")
        end

        alias filter call
      end

      # InterPodAffinity is one upstream MultiPoint plugin.  The local
      # pipeline exposes a single Filter phase, so it composes the upstream
      # required affinity and anti-affinity checks in their deterministic
      # order rather than registering two look-alike plugin names.
      class InterPodAffinity
        def initialize
          @affinity = PodAffinity.new
          @anti_affinity = PodAntiAffinity.new
          freeze
        end

        def call(pod, node, context = nil)
          affinity = @affinity.call(pod, node, context)
          return affinity unless affinity == true

          @anti_affinity.call(pod, node, context)
        end

        alias filter call
      end

      class Ready
        def call(_pod, node, _context = nil)
          return true if node.ready?

          Helpers.reject("node is not Ready", code: "NodeNotReady")
        end

        alias filter call
      end

      # pkg/scheduler/framework/plugins/nodedeclaredfeatures: a Pod whose
      # spec needs a node-declared feature (RestartAllContainers restart
      # rules, user namespaces with host network) only fits Nodes whose
      # status.declaredFeatures include it.  PreFilter's inference is cached
      # per Pod spec; a Pod with no requirement is skipped outright.
      class NodeDeclaredFeatures
        REASON = "node(s) didn't match Pod's required features"
        CACHE_LIMIT = 1024

        def initialize(framework: Rubernetes::NodeDeclaredFeatures::DEFAULT_FRAMEWORK,
                       version: Rubernetes::NodeDeclaredFeatures::KUBERNETES_VERSION, enabled: true)
          @framework = framework
          @version = version
          @enabled = enabled
          @requirements = {}
          @mutex = Mutex.new
        end

        def call(pod, node, _context = nil)
          return true unless @enabled

          required = requirements(pod)
          return true if required.empty?
          return true if required.subset?(@framework.try_map(Array(node.status["declaredFeatures"])))

          Helpers.reject(REASON, code: "UnschedulableAndUnresolvable")
        end

        alias filter call

        # PreFilter: the Pod's requirements, as a FeatureSet.
        def requirements(pod)
          spec = pod.respond_to?(:spec) ? pod.spec : Support.snapshot((pod["spec"] || {}))
          @mutex.synchronize do
            cached = @requirements[spec]
            return cached if cached

            @requirements.clear if @requirements.size >= CACHE_LIMIT
            @requirements[spec] = @framework.infer_for_pod_scheduling({"spec" => spec}, @version)
          end
        end
      end

      NodeResourceFit = NodeResourcesFit unless const_defined?(:NodeResourceFit, false)
      TaintTolerations = TaintToleration unless const_defined?(:TaintTolerations, false)
      NodeReady = Ready unless const_defined?(:NodeReady, false)
    end
  end
end
