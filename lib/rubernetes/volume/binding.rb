# frozen_string_literal: true

require "monitor"

module Rubernetes
  module Volume
    class StorageClass
      attr_reader :name, :provisioner, :parameters, :reclaim_policy, :volume_binding_mode,
                  :allow_volume_expansion, :mount_options

      def initialize(value = nil, **kwargs)
        hash = (value.respond_to?(:to_h) ? value.to_h : {}).merge(kwargs)
        @name = Types.identifier(Types.key(hash, "name", Types.key(hash, "metadata", {}).then do |metadata|
          Types.key(metadata, "name")
        end), "storage class name")
        @provisioner = Types.identifier(Types.key(hash, "provisioner", "kubernetes.io/no-provisioner"), "storage class provisioner")
        @parameters = Types.deep_copy(Types.key(hash, "parameters", {})).freeze
        @reclaim_policy = normalize_reclaim(Types.key(hash, "reclaimPolicy", "Delete"))
        @volume_binding_mode = normalize_binding_mode(Types.key(hash, "volumeBindingMode", "Immediate"))
        @allow_volume_expansion = Types.bool(Types.key(hash, "allowVolumeExpansion", false))
        @mount_options = Array(Types.key(hash, "mountOptions", [])).map(&:to_s).freeze
        freeze
      end

      def to_h
        {"metadata" => {"name" => name}, "provisioner" => provisioner, "parameters" => Types.deep_copy(parameters),
         "reclaimPolicy" => reclaim_policy, "volumeBindingMode" => volume_binding_mode,
         "allowVolumeExpansion" => allow_volume_expansion, "mountOptions" => mount_options}
      end

      private

      def normalize_reclaim(value)
        text = value.to_s
        raise ValidationError, "unsupported reclaimPolicy #{value.inspect}" unless %w[Delete Retain].include?(text)

        text.freeze
      end

      def normalize_binding_mode(value)
        text = value.to_s
        raise ValidationError, "unsupported volumeBindingMode #{value.inspect}" unless %w[Immediate WaitForFirstConsumer].include?(text)

        text.freeze
      end
    end

    class PersistentVolume
      attr_reader :name, :capacity_bytes, :access_modes, :reclaim_policy, :storage_class,
                  :volume_mode, :node_affinity, :source, :phase, :claim_ref, :annotations, :labels

      def initialize(value = nil, **kwargs)
        hash = (value.respond_to?(:to_h) ? value.to_h : {}).merge(kwargs)
        metadata = Types.key(hash, "metadata", {})
        @name = Types.identifier(Types.key(hash, "name", Types.key(metadata, "name")), "PV name")
        capacity = Types.key(hash, "capacity", {})
        @capacity_bytes = Types.parse_capacity(Types.key(hash, "capacityBytes", Types.key(capacity, "storage", Types.key(hash, "size"))))
        @access_modes = Types.normalize_access_modes(Types.key(hash, "accessModes", ["ReadWriteOnce"]))
        @reclaim_policy = Types.key(hash, "reclaimPolicy", Types.key(hash, "persistentVolumeReclaimPolicy", "Retain")).to_s
        raise ValidationError, "unsupported PV reclaimPolicy #{@reclaim_policy.inspect}" unless %w[Delete Retain].include?(@reclaim_policy)

        @storage_class = Types.key(hash, "storageClassName", Types.key(hash, "storageClass", "")).to_s
        @volume_mode = Types.key(hash, "volumeMode", "Filesystem").to_s
        raise ValidationError, "unsupported PV volumeMode #{@volume_mode.inspect}" unless %w[Filesystem Block].include?(@volume_mode)

        @node_affinity = Types.deep_copy(Types.key(hash, "nodeAffinity"))
        @source = Types.deep_copy(Types.key(hash, "source", hash))
        @phase = Types.key(hash, "phase", "Available").to_s
        @claim_ref = Types.deep_copy(Types.key(hash, "claimRef"))
        @annotations = Types.deep_copy(Types.key(metadata, "annotations", {})).freeze
        @labels = Types.deep_copy(Types.key(hash, "labels", Types.key(metadata, "labels", {}))).freeze
        raise ValidationError, "unsupported PV phase #{@phase.inspect}" unless %w[Available Bound Released Failed].include?(@phase)

        freeze
      end

      def available?
        phase == "Available" && claim_ref.nil?
      end

      def bound?
        phase == "Bound" && !claim_ref.nil?
      end

      def to_h
        {"metadata" => {"name" => name, "annotations" => Types.deep_copy(annotations), "labels" => Types.deep_copy(labels)},
         "capacity" => {"storage" => capacity_bytes}, "accessModes" => access_modes,
         "persistentVolumeReclaimPolicy" => reclaim_policy, "storageClassName" => storage_class,
         "volumeMode" => volume_mode, "nodeAffinity" => Types.deep_copy(node_affinity),
         "source" => Types.deep_copy(source), "phase" => phase, "claimRef" => Types.deep_copy(claim_ref),
         "labels" => Types.deep_copy(labels)}
      end

      def with(**changes)
        self.class.new(to_h.merge(changes))
      end
    end

    class PersistentVolumeClaim
      attr_reader :name, :namespace, :requested_bytes, :access_modes, :storage_class,
                  :volume_mode, :selector, :volume_name, :phase, :bound_volume, :annotations

      def initialize(value = nil, **kwargs)
        hash = (value.respond_to?(:to_h) ? value.to_h : {}).merge(kwargs)
        metadata = Types.key(hash, "metadata", {})
        spec = Types.key(hash, "spec", {})
        status = Types.key(hash, "status", {})
        @name = Types.identifier(Types.key(hash, "name", Types.key(metadata, "name")), "PVC name")
        @namespace = Types.identifier(Types.key(hash, "namespace", Types.key(metadata, "namespace", "default")), "PVC namespace")
        resources = Types.key(hash, "resources", Types.key(spec, "resources", {}))
        requests = Types.key(resources, "requests", {})
        @requested_bytes = Types.parse_capacity(Types.key(hash, "requestedBytes", Types.key(hash, "size", Types.key(requests, "storage"))))
        @access_modes = Types.normalize_access_modes(Types.key(hash, "accessModes", Types.key(spec, "accessModes", ["ReadWriteOnce"])))
        @storage_class = Types.key(hash, "storageClassName", Types.key(spec, "storageClassName", Types.key(hash, "storageClass", ""))).to_s
        @volume_mode = Types.key(hash, "volumeMode", Types.key(spec, "volumeMode", "Filesystem")).to_s
        raise ValidationError, "unsupported PVC volumeMode #{@volume_mode.inspect}" unless %w[Filesystem Block].include?(@volume_mode)

        @selector = Types.deep_copy(Types.key(hash, "selector", Types.key(spec, "selector")))
        @volume_name = Types.key(hash, "volumeName", Types.key(spec, "volumeName"))&.to_s
        @phase = Types.key(hash, "phase", Types.key(status, "phase", "Pending")).to_s
        @bound_volume = Types.key(hash, "boundVolume", Types.key(status, "boundVolume"))&.to_s
        @annotations = Types.deep_copy(Types.key(metadata, "annotations", {})).freeze
        freeze
      end

      def key
        "#{namespace}/#{name}"
      end

      def pending?
        phase == "Pending"
      end

      def bound?
        phase == "Bound" && !bound_volume.nil?
      end

      def to_h
        {"metadata" => {"name" => name, "namespace" => namespace, "annotations" => Types.deep_copy(annotations)},
         "spec" => {"resources" => {"requests" => {"storage" => requested_bytes}}, "accessModes" => access_modes,
                    "storageClassName" => storage_class, "volumeMode" => volume_mode,
                    "selector" => Types.deep_copy(selector), "volumeName" => volume_name},
         "status" => {"phase" => phase, "boundVolume" => bound_volume}}
      end

      def with(**changes)
        self.class.new(to_h.merge(changes))
      end
    end

    class BindingResult
      attr_reader :status, :pvc, :pv, :reason, :message

      def initialize(status:, pvc:, pv: nil, reason: nil, message: nil)
        @status = status.to_s.freeze
        @pvc = pvc
        @pv = pv
        @reason = reason&.to_s
        @message = message&.to_s
        freeze
      end

      def bound?
        status == "Bound" && pv
      end

      def pending?
        status == "Pending"
      end

      def to_h
        {"status" => status, "pvc" => pvc.to_h, "pv" => pv&.to_h, "reason" => reason, "message" => message}
      end

      def [](key)
        to_h[key.to_s]
      end
    end

    # PV/PVC binder with deterministic matching and topology checks.  Dynamic
    # provisioning is an injected callback; the binder never shells out to a
    # storage plugin or fabricates a PV after an ambiguous callback result.
    class Binder
      def initialize(provisioner: nil, reclaimer: nil, clock: -> { Time.now.utc })
        @provisioner = provisioner
        @reclaimer = reclaimer
        @clock = clock
        @mutex = Monitor.new
        @pvs = {}
        @classes = {}
        @claims = {}
        @bindings = {}
      end

      attr_reader :pvs, :claims, :classes

      def register_storage_class(value)
        storage_class = value.is_a?(StorageClass) ? value : StorageClass.new(value)
        @mutex.synchronize { @classes[storage_class.name] = storage_class }
        storage_class
      end

      def register_pv(value)
        pv = value.is_a?(PersistentVolume) ? value : PersistentVolume.new(value)
        @mutex.synchronize { @pvs[pv.name] = pv }
        pv
      end

      def register_pvc(value)
        pvc = value.is_a?(PersistentVolumeClaim) ? value : PersistentVolumeClaim.new(value)
        @mutex.synchronize { @claims[pvc.key] = pvc }
        pvc
      end

      def find_storage_class(name)
        @mutex.synchronize { @classes[name.to_s] }
      end

      def bind(pvc, node: nil, node_labels: {}, selected_node: nil, token: nil)
        claim = pvc.is_a?(PersistentVolumeClaim) ? pvc : PersistentVolumeClaim.new(pvc)
        node ||= selected_node
        storage_class = claim.storage_class.empty? ? nil : find_storage_class(claim.storage_class)
        if storage_class && storage_class.volume_binding_mode == "WaitForFirstConsumer" && !node
          return BindingResult.new(status: "Pending", pvc: claim, reason: "WaitForFirstConsumer",
                                   message: "binding is deferred until a node is selected")
        end

        @mutex.synchronize do
          existing = @bindings[claim.key]
          return existing if existing && existing.bound?

          candidate = @pvs.values.select { |pv| match?(claim, pv, storage_class: storage_class, node: node, node_labels: node_labels) }
            .sort_by { |pv| [pv.capacity_bytes, pv.name] }.first
          if candidate.nil? && @provisioner
            candidate = dynamic_provision(claim, storage_class, node: node, token: token)
            @pvs[candidate.name] = candidate if candidate
          end
          unless candidate
            return BindingResult.new(status: "Pending", pvc: claim, reason: "NoMatchingVolume",
                                     message: "no available PV satisfies capacity, access mode, class, and topology")
          end

          bound_pv = PersistentVolume.new(candidate.to_h.merge("phase" => "Bound",
                                                               "claimRef" => {
                                                                 "name" => claim.name, "namespace" => claim.namespace
                                                               }))
          bound_pvc = PersistentVolumeClaim.new(claim.to_h.merge("phase" => "Bound", "boundVolume" => bound_pv.name))
          @pvs[bound_pv.name] = bound_pv
          @claims[bound_pvc.key] = bound_pvc
          result = BindingResult.new(status: "Bound", pvc: bound_pvc, pv: bound_pv)
          @bindings[bound_pvc.key] = result
          result
        end
      end

      def expand(pvc, capacity:, storage_class: nil)
        claim = pvc.is_a?(PersistentVolumeClaim) ? pvc : PersistentVolumeClaim.new(pvc)
        result = @bindings.fetch(claim.key) { raise BindingError, "PVC #{claim.key} is not bound" }
        pv = result.pv
        klass = storage_class || find_storage_class(claim.storage_class)
        unless klass&.allow_volume_expansion
          raise UnsupportedError,
                "online expansion is not enabled for storage class #{claim.storage_class.inspect}"
        end

        bytes = Types.parse_capacity(capacity)
        raise CapacityError, "requested capacity must be greater than current claim request" unless bytes > claim.requested_bytes

        expanded = PersistentVolume.new(pv.to_h.merge("capacityBytes" => [pv.capacity_bytes, bytes].max))
        expanded_claim = PersistentVolumeClaim.new(claim.to_h.merge("requestedBytes" => bytes, "phase" => "Bound",
                                                                    "boundVolume" => pv.name))
        @mutex.synchronize do
          @pvs[expanded.name] = expanded
          @claims[expanded_claim.key] = expanded_claim
          @bindings[claim.key] = BindingResult.new(status: "Bound", pvc: expanded_claim, pv: expanded)
        end
      end

      def release(pvc, token: nil)
        claim = pvc.is_a?(PersistentVolumeClaim) ? pvc : PersistentVolumeClaim.new(pvc)
        result = @bindings.fetch(claim.key) { raise BindingError, "PVC #{claim.key} is not bound" }
        pv = result.pv
        policy = pv.reclaim_policy
        released = PersistentVolume.new(pv.to_h.merge("phase" => "Released", "claimRef" => pv.claim_ref))
        @mutex.synchronize do
          @pvs[pv.name] = released
          @bindings.delete(claim.key)
        end
        return released if policy == "Retain"

        if policy == "Delete"
          if @reclaimer
            if @reclaimer.respond_to?(:call)
              @reclaimer.call(pv: pv, token: token)
            elsif @reclaimer.respond_to?(:delete)
              @reclaimer.delete(pv: pv, token: token)
            else
              raise UnsupportedError, "reclaimer must implement call or delete"
            end
          elsif @provisioner.respond_to?(:delete)
            @provisioner.delete(pv: pv, token: token)
          end
          @mutex.synchronize { @pvs.delete(pv.name) }
          nil
        else
          released
        end
      end

      private

      def match?(claim, pv, storage_class:, node:, node_labels:)
        return false unless pv.available?
        return false if pv.capacity_bytes < claim.requested_bytes
        return false unless (claim.access_modes - pv.access_modes).empty?
        return false if !claim.storage_class.empty? && pv.storage_class != claim.storage_class
        return false if claim.volume_mode != pv.volume_mode
        return false if claim.volume_name && claim.volume_name != pv.name
        return false unless selector_matches?(pv, claim.selector)
        return false if node && !node_affinity_matches?(pv.node_affinity, node, node_labels)

        true
      end

      def selector_matches?(pv, selector)
        return true unless selector

        labels = pv.labels
        match_labels = Types.key(selector, "matchLabels", {})
        return false unless match_labels.all? { |key, value| labels[key.to_s].to_s == value.to_s }

        Array(Types.key(selector, "matchExpressions", [])).all? do |expression|
          key = Types.key(expression, "key").to_s
          operator = Types.key(expression, "operator", "In").to_s
          values = Array(Types.key(expression, "values", [])).map(&:to_s)
          case operator
          when "In" then values.include?(labels[key].to_s)
          when "NotIn" then !values.include?(labels[key].to_s)
          when "Exists" then labels.key?(key)
          when "DoesNotExist" then !labels.key?(key)
          else false
          end
        end
      end

      def node_affinity_matches?(affinity, node, labels)
        return true unless affinity

        required = Types.key(affinity, "required", affinity)
        terms = Array(Types.key(required, "nodeSelectorTerms", []))
        return true if terms.empty?

        terms.any? do |term|
          expressions = Array(Types.key(term, "matchExpressions", []))
          fields = Array(Types.key(term, "matchFields", []))
          expressions.all? { |expr| requirement_matches?(expr, node, labels) } && fields.all? do |expr|
            requirement_matches?(expr, node, labels, fields: true)
          end
        end
      end

      def requirement_matches?(expression, node, labels, fields: false)
        key = Types.key(expression, "key").to_s
        operator = Types.key(expression, "operator", "In").to_s
        values = Array(Types.key(expression, "values", [])).map(&:to_s)
        actual = if fields
                   key == "metadata.name" ? node.to_s : nil
                 else
                   labels[key] || (["kubernetes.io/hostname", "hostname"].include?(key) ? node.to_s : nil)
                 end
        case operator
        when "In" then values.include?(actual.to_s)
        when "NotIn" then !values.include?(actual.to_s)
        when "Exists" then !actual.nil?
        when "DoesNotExist" then actual.nil?
        when "Gt" then actual && actual.to_i > values.first.to_i
        when "Lt" then actual && actual.to_i < values.first.to_i
        else false
        end
      end

      def dynamic_provision(claim, storage_class, node:, token:)
        raise BindingError, "PVC #{claim.key} requires a StorageClass for dynamic provisioning" unless storage_class
        unless @provisioner.respond_to?(:call) || @provisioner.respond_to?(:provision)
          raise UnsupportedError, "dynamic provisioner must implement call or provision"
        end

        value = if @provisioner.respond_to?(:provision)
                  @provisioner.provision(claim: claim, storage_class: storage_class, node: node, token: token)
                else
                  @provisioner.call(claim: claim, storage_class: storage_class, node: node, token: token)
                end
        return nil if value.nil?

        candidate = if value.is_a?(PersistentVolume)
                      value
                    else
                      hash = value.respond_to?(:to_h) ? value.to_h : nil
                      raise BindingError, "dynamic provisioner returned a non-volume result" unless hash

                      PersistentVolume.new(hash.merge("capacityBytes" => claim.requested_bytes,
                                                      "accessModes" => claim.access_modes,
                                                      "storageClassName" => storage_class.name,
                                                      "reclaimPolicy" => storage_class.reclaim_policy,
                                                      "phase" => "Available"))
                    end
        raise BindingError, "dynamic provisioner returned an unavailable PV" unless candidate.available?

        candidate
      end
    end

    PV = PersistentVolume unless const_defined?(:PV, false)
    PVC = PersistentVolumeClaim unless const_defined?(:PVC, false)
  end
end
