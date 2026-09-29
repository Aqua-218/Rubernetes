# frozen_string_literal: true

module Rubernetes
  module Scheduler
    # The VolumeBinding plugin (pkg/scheduler/framework/plugins/volumebinding,
    # v1.36.2, with component-helpers/storage/volume): a Pod's PVCs are
    # resolved once per cycle (PreFilter), each node is checked for the bound
    # PVs' node affinity, static PVs that can be bound to the unbound
    # WaitForFirstConsumer claims (smallest fit, node affinity, access modes,
    # class, selector, volume mode, VAC), and dynamic provisioning of the rest
    # (provisioner, allowedTopologies, CSIStorageCapacity when the CSIDriver
    # opts in).  Reserve assumes the chosen bindings (the PV's claimRef, the
    # claim's volume.kubernetes.io/selected-node); PreBind writes them and
    # waits until the PV controller and provisioner completed the binding;
    # Unreserve reverts the assumptions.
    #
    # The cycle's volume data comes from the scheduler's informers; the
    # assumed objects overlay it until the informers catch up (AssumeCache).
    # Without claim data in the cycle (an embedded framework), the legacy
    # Filters::VolumeBinding check is used.
    class VolumeBinding
      ANN_SELECTED_NODE = "volume.kubernetes.io/selected-node"
      ANN_BIND_COMPLETED = "pv.kubernetes.io/bind-completed"
      ANN_BOUND_BY_CONTROLLER = "pv.kubernetes.io/bound-by-controller"
      BETA_STORAGE_CLASS = "volume.beta.kubernetes.io/storage-class"
      NOT_SUPPORTED_PROVISIONER = "kubernetes.io/no-provisioner"
      REASON_BIND_CONFLICT = "node(s) didn't find available persistent volumes to bind"
      REASON_NODE_CONFLICT = "node(s) didn't match PersistentVolume's node affinity"
      REASON_NOT_ENOUGH_SPACE = "node(s) did not have enough free storage"
      REASON_PV_NOT_EXIST = "node(s) unavailable due to one or more pvc(s) bound to non-existent pv(s)"
      REASON_UNBOUND_IMMEDIATE = "pod has unbound immediate PersistentVolumeClaims"
      BIND_TIMEOUT = 600
      MAX_STATES = 4096
      # csi-translation-lib: the in-tree PV sources and their CSI drivers.
      MIGRATED = {"awsElasticBlockStore" => ["kubernetes.io/aws-ebs", "ebs.csi.aws.com"],
                  "gcePersistentDisk" => ["kubernetes.io/gce-pd", "pd.csi.storage.gke.io"],
                  "azureDisk" => ["kubernetes.io/azure-disk", "disk.csi.azure.com"],
                  "cinder" => ["kubernetes.io/cinder", "cinder.csi.openstack.org"],
                  "portworxVolume" => ["kubernetes.io/portworx-volume", "pxd.portworx.com"]}.freeze
      MIGRATED_PLUGINS_ANNOTATION = "storage.alpha.kubernetes.io/migrated-plugins"

      class BindingError < StandardError; end

      # The PVCs a Pod uses, sorted into GetPodVolumeClaims' groups.
      Claims = Struct.new(:bound, :delay, :immediate, :volumes_by_class, keyword_init: true)
      # PodVolumes: static bindings [pv, pvc] and claims to provision.
      PodVolumes = Struct.new(:bindings, :provisions, keyword_init: true)
      State = Struct.new(:key, :rejection, :claims, :by_node, :all_bound, keyword_init: true)

      # Reads and writes the API objects PreBind needs.
      class ClientAPI
        def initialize(client) = @client = client

        def get_pv(name) = fetch { @client.get("persistentvolumes", name, api_version: "v1") }
        def get_pvc(namespace, name) = fetch { @client.get("persistentvolumeclaims", name, namespace: namespace, api_version: "v1") }
        def get_pod(namespace, name) = fetch { @client.get("pods", name, namespace: namespace, api_version: "v1") }
        def get_node(name) = fetch { @client.get("nodes", name, api_version: "v1") }
        def get_csi_node(name) = fetch { @client.get("csinodes", name, api_version: "storage.k8s.io/v1") }
        def update_pv(pv) = @client.update(pv.merge("apiVersion" => "v1", "kind" => "PersistentVolume"))

        def update_pvc(pvc)
          @client.update(pvc.merge("apiVersion" => "v1", "kind" => "PersistentVolumeClaim"))
        end

        private

        def fetch
          yield
        rescue Rubernetes::Client::APIError => error
          raise unless error.status == 404

          nil
        end
      end

      attr_accessor :api
      # Scheduler::Metrics: scheduler_volume_binder_cache_requests_total and
      # scheduler_volume_scheduling_stage_error_total.
      attr_accessor :metrics
      # When set, PreBind returns once the bindings are written and the
      # binding cycle waits for them (#wait_for_bindings) off the scheduling
      # thread -- upstream's binding cycle is a goroutine of its own.
      attr_accessor :defer_wait

      def initialize(api: nil, bind_timeout: BIND_TIMEOUT, poll_interval: 1.0, sleeper: ->(seconds) { sleep(seconds) },
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, legacy: nil)
        @api = api
        @bind_timeout = Float(bind_timeout)
        @poll_interval = Float(poll_interval)
        @sleeper = sleeper
        @clock = clock
        @legacy = legacy || Filters::VolumeBinding.new
        @mutex = Mutex.new
        @cache_mutex = Mutex.new
        @states = {}
        @assumed_pvs = {}
        @assumed_pvcs = {}
        @pending = {}
        @defer_wait = false
        @index = nil
        @index_key = nil
      end

      # ------------------------------------------------------------ Filter

      def call(pod, node, context = nil)
        data = Filters::Helpers.volume_data(context)
        return @legacy.call(pod, node, context) if Filters::Helpers.collection(data, "persistentVolumeClaims", "pvcs", "claims").nil?

        state = state_for(pod, data)
        return state.rejection if state.rejection
        return true if state.claims.nil?

        podvolumes, reasons = find_pod_volumes(pod, state.claims, node, data)
        unless reasons.empty?
          return Filters::Helpers.reject(reasons.first, code: "UnschedulableAndUnresolvable", details: {"reasons" => reasons})
        end

        @mutex.synchronize { state.by_node[node.name] = podvolumes }
        true
      rescue BindingError => error
        Filters::Helpers.reject(error.message, code: "Error")
      end

      alias filter call

      # ----------------------------------------------------------- Reserve

      def reserve(pod, node, context = nil)
        data = Filters::Helpers.volume_data(context)
        return @legacy.reserve(pod, node, context) if Filters::Helpers.collection(data, "persistentVolumeClaims", "pvcs", "claims").nil?

        state = @mutex.synchronize { @states[pod_key(pod)] }
        return true if state.nil? || state.claims.nil?

        podvolumes = state.by_node[node.name]
        if podvolumes.nil?
          state.all_bound = true
          return true
        end
        state.all_bound = assume(pod, node.name, podvolumes, data)
        true
      rescue BindingError => error
        Filters::Helpers.reject(error.message, code: "Error")
      end

      # ----------------------------------------------------------- PreBind

      # PreBindPreFlight: PreBind has volumes to bind for this Pod.
      def pre_bind_preflight?(pod, _node = nil, context = nil)
        data = Filters::Helpers.volume_data(context)
        return false if Filters::Helpers.collection(data, "persistentVolumeClaims", "pvcs", "claims").nil?

        state = @mutex.synchronize { @states[pod_key(pod)] }
        !(state.nil? || state.claims.nil? || state.all_bound)
      end

      def pre_bind(pod, node, context = nil)
        data = Filters::Helpers.volume_data(context)
        return @legacy.pre_bind(pod, node, context) if Filters::Helpers.collection(data, "persistentVolumeClaims", "pvcs", "claims").nil?

        state = @mutex.synchronize { @states[pod_key(pod)] }
        return true if state.nil? || state.claims.nil? || state.all_bound

        podvolumes = state.by_node[node.name]
        raise BindingError, "no pod volume found for node #{node.name.inspect}" if podvolumes.nil?
        raise BindingError, "binding volumes: no API is configured" if @api.nil?

        bind_api_update(podvolumes)
        forget(pod)
        if @defer_wait
          @mutex.synchronize { @pending[pod_key(pod)] = [node.name, podvolumes] }
          return true
        end
        wait_until_bound(pod, node.name, podvolumes)
        true
      rescue StandardError => error
        revert(podvolumes) if podvolumes
        message = error.message.start_with?("binding volumes") ? error.message : "binding volumes: #{error.message}"
        Filters::Helpers.reject(message, code: "Error")
      end

      # The Pod's PreBind wrote bindings that are still to complete.
      def pending?(pod) = @mutex.synchronize { @pending.key?(pod_key(pod)) }

      # Waits (on the caller's thread) until the Pod's written bindings are
      # complete; raises BindingError when they fail or time out, after
      # reverting what was assumed.
      def wait_for_bindings(pod, node_name)
        entry = @mutex.synchronize { @pending.delete(pod_key(pod)) }
        return true if entry.nil?

        wait_until_bound(pod, entry.first || node_name, entry.last)
        true
      rescue StandardError => error
        revert(entry.last) if entry
        raise BindingError, error.message.start_with?("binding volumes") ? error.message : "binding volumes: #{error.message}"
      end

      # --------------------------------------------------------- Unreserve

      def unreserve(pod, node, _context = nil)
        state = @mutex.synchronize { @states.delete(pod_key(pod)) }
        podvolumes = state&.by_node&.[](node.name)
        revert(podvolumes) if podvolumes
        true
      end

      private

      def wait_until_bound(pod, node_name, podvolumes)
        deadline = @clock.call + @bind_timeout
        loop do
          @sleeper.call(@poll_interval)
          return true if check_bindings(pod, node_name, podvolumes)
          raise BindingError, "binding volumes: context deadline exceeded" if @clock.call >= deadline
        end
      end

      def pod_key(pod) = pod.uid.to_s.empty? ? "#{pod.namespace}/#{pod.name}" : pod.uid.to_s

      def forget(pod)
        @mutex.synchronize { @states.delete(pod_key(pod)) }
      end

      # PreFilter, once per scheduling cycle (a new cycle brings new data).
      def state_for(pod, data)
        key = [pod_key(pod), data.object_id]
        current = @mutex.synchronize { @states[pod_key(pod)] }
        return current if current && current.key == key

        state = build_state(pod, data, key)
        @mutex.synchronize do
          @states.shift while @states.length >= MAX_STATES
          @states[pod_key(pod)] = state
        end
      end

      def build_state(pod, data, key)
        has_claims = pod_has_pvcs(pod, data)
        return State.new(key: key, claims: nil, by_node: {}) unless has_claims

        claims = pod_volume_claims(pod, data)
        unless claims.immediate.empty?
          rejection = Filters::Helpers.reject(REASON_UNBOUND_IMMEDIATE, code: "UnschedulableAndUnresolvable")
          return State.new(key: key, rejection: rejection, by_node: {})
        end
        State.new(key: key, claims: claims, by_node: {})
      rescue BindingError => error
        State.new(key: key, rejection: Filters::Helpers.reject(error.message, code: "UnschedulableAndUnresolvable"), by_node: {})
      end

      # podHasPVCs.
      def pod_has_pvcs(pod, data)
        found = false
        pod.volumes.each do |volume|
          name, ephemeral = claim_name(pod, volume)
          next if name.nil?

          found = true
          claim = pvc(pod.namespace, name, data)
          if claim.nil?
            raise BindingError, %(waiting for ephemeral volume controller to create the persistentvolumeclaim "#{name}") if ephemeral

            raise BindingError, %(persistentvolumeclaim "#{name}" not found)
          end
          if value(claim, "status", "phase").to_s == "Lost"
            raise BindingError, %(persistentvolumeclaim "#{name}" bound to non-existent persistentvolume "#{value(claim, "spec", "volumeName")}")
          end
          raise BindingError, %(persistentvolumeclaim "#{name}" is being deleted) if value(claim, "metadata", "deletionTimestamp")

          owned_by_pod!(pod, claim) if ephemeral
        end
        found
      end

      def claim_name(pod, volume)
        if (claim = Support.value(volume, "persistentVolumeClaim", nil))
          [Support.value(claim, "claimName", "").to_s, false]
        elsif Support.value(volume, "ephemeral", nil)
          ["#{pod.name}-#{Support.value(volume, "name", "")}", true]
        end
      end

      def owned_by_pod!(pod, claim)
        owner = Array(value(claim, "metadata", "ownerReferences")).find { |reference| Support.value(reference, "controller", false) == true }
        return if owner && Support.value(owner, "uid", "").to_s == pod.uid.to_s

        raise BindingError, "PVC #{value(claim, "metadata", "namespace")}/#{value(claim, "metadata", "name")} was not created for pod " \
                            "#{pod.namespace}/#{pod.name} (pod is not owner)"
      end

      # GetPodVolumeClaims.
      def pod_volume_claims(pod, data)
        claims = Claims.new(bound: [], delay: [], immediate: [], volumes_by_class: {})
        pod.volumes.each do |volume|
          name, = claim_name(pod, volume)
          next if name.nil?

          claim = pvc(pod.namespace, name, data)
          raise BindingError, %(error getting PVC "#{pod.namespace}/#{name}") if claim.nil?

          if fully_bound?(claim)
            claims.bound << claim
          elsif delay_binding?(claim, data) && value(claim, "spec", "volumeName").to_s.empty?
            claims.delay << claim
          else
            claims.immediate << claim
          end
        end
        claims.delay.each do |claim|
          name = claim_class(claim)
          claims.volumes_by_class[name] ||= pvs(data).select { |volume| volume_class(volume) == name }
        end
        claims
      end

      def fully_bound?(claim)
        !value(claim, "spec", "volumeName").to_s.empty? && (value(claim, "metadata", "annotations") || {}).key?(ANN_BIND_COMPLETED)
      end

      # IsDelayBindingMode.
      def delay_binding?(claim, data)
        name = claim_class(claim)
        return false if name.empty?

        storage_class = index(data)[:classes][name]
        return false if storage_class.nil?

        mode = Support.value(storage_class, "volumeBindingMode", nil)
        raise BindingError, %(VolumeBindingMode not set for StorageClass "#{name}") if mode.nil?

        mode.to_s == "WaitForFirstConsumer"
      end

      # FindPodVolumes: [PodVolumes, reasons].
      def find_pod_volumes(pod, claims, node, data)
        reasons = []
        podvolumes = PodVolumes.new(bindings: [], provisions: [])
        unless claims.bound.empty?
          satisfied, found = check_bound_claims(claims.bound, node, data)
          reasons << REASON_NODE_CONFLICT unless satisfied
          reasons << REASON_PV_NOT_EXIST unless found
        end
        return [podvolumes, reasons] if claims.delay.empty?

        to_match = []
        to_provision = []
        claims.delay.each do |claim|
          selected = (value(claim, "metadata", "annotations") || {})[ANN_SELECTED_NODE]
          if selected
            return [podvolumes, reasons + [REASON_BIND_CONFLICT]] if selected != node.name

            to_provision << claim
          else
            to_match << claim
          end
        end
        unbound_satisfied = true
        sufficient = true
        unless to_match.empty?
          unbound_satisfied, podvolumes.bindings, unmatched = find_matching_volumes(to_match, claims.volumes_by_class, node, data)
          to_provision.concat(unmatched)
        end
        unless to_provision.empty?
          unbound_satisfied, sufficient, podvolumes.provisions = check_volume_provisions(to_provision, node, data)
        end
        reasons << REASON_BIND_CONFLICT unless unbound_satisfied
        reasons << REASON_NOT_ENOUGH_SPACE unless sufficient
        [podvolumes, reasons]
      end

      # checkBoundClaims: [node affinity satisfied, PVs found].
      def check_bound_claims(claims, node, data)
        csi_node = index(data)[:csi_nodes][node.name]
        claims.each do |claim|
          volume = pv(value(claim, "spec", "volumeName").to_s, data)
          return [true, false] if volume.nil?
          return [false, true] unless node_affinity_matches?(translate(volume, csi_node), node.labels)
        end
        [true, true]
      end

      # findMatchingVolumes: [found all, bindings, unbound claims].
      def find_matching_volumes(claims, volumes_by_class, node, data)
        chosen = {}
        bindings = []
        unbound = []
        claims.sort_by { |claim| storage(value(claim, "spec", "resources", "requests", "storage")) }.each do |claim|
          volume = find_matching_volume(claim, Array(volumes_by_class[claim_class(claim)]).map { |item| pv(name_of(item), data) || item },
                                        node, chosen)
          if volume.nil?
            unbound << claim
            next
          end
          chosen[name_of(volume)] = true
          bindings << [volume, claim]
        end
        [unbound.empty?, bindings, unbound]
      end

      # volume.FindMatchingVolume (scheduler path: node set, delayBinding).
      def find_matching_volume(claim, volumes, node, excluded)
        requested = storage(value(claim, "spec", "resources", "requests", "storage"))
        requested_class = claim_class(claim)
        selector = value(claim, "spec", "selector")
        smallest = nil
        volumes.each do |volume|
          next if excluded.key?(name_of(volume))

          reference = value(volume, "spec", "claimRef")
          next if reference && !bound_to_claim?(volume, claim)

          size = storage(value(volume, "spec", "capacity", "storage"))
          next if size < requested
          next if volume_mode(claim) != volume_mode(volume)
          next if value(claim, "spec", "volumeAttributesClassName").to_s != value(volume, "spec", "volumeAttributesClassName").to_s
          next if value(volume, "metadata", "deletionTimestamp")

          affinity = node_affinity_matches?(volume, node.labels)
          return affinity ? volume : nil if bound_to_claim?(volume, claim)
          next unless value(volume, "status", "phase").to_s == "Available"
          next if selector && !label_selector_matches?(selector, value(volume, "metadata", "labels") || {})
          next if volume_class(volume) != requested_class
          next unless affinity
          next unless access_modes(claim).all? { |mode| access_modes(volume).include?(mode) }

          smallest = [volume, size] if smallest.nil? || smallest.last > size
        end
        smallest&.first
      end

      # checkVolumeProvisions: [provision satisfied, sufficient storage, provisions].
      def check_volume_provisions(claims, node, data)
        provisions = []
        claims.each do |claim|
          class_name = claim_class(claim)
          raise BindingError, %(no class for claim "#{value(claim, "metadata", "namespace")}/#{value(claim, "metadata", "name")}") if class_name.empty?

          storage_class = index(data)[:classes][class_name]
          raise BindingError, %(failed to find storage class "#{class_name}") if storage_class.nil?

          provisioner = Support.value(storage_class, "provisioner", "").to_s
          return [false, true, []] if provisioner.empty? || provisioner == NOT_SUPPORTED_PROVISIONER
          return [false, true, []] unless topology_matches?(Support.value(storage_class, "allowedTopologies", nil), node.labels)
          return [true, false, []] unless enough_capacity?(provisioner, claim, class_name, node, data)

          provisions << claim
        end
        [true, true, provisions]
      end

      # hasEnoughCapacity.
      def enough_capacity?(provisioner, claim, class_name, node, data)
        request = value(claim, "spec", "resources", "requests", "storage")
        return true if request.nil?

        driver = index(data)[:csi_drivers][provisioner]
        return true if driver.nil? || value(driver, "spec", "storageCapacity") != true

        size = storage(request)
        index(data)[:capacities].any? do |capacity|
          limit = Support.value(capacity, "maximumVolumeSize", nil) || Support.value(capacity, "capacity", nil)
          topology = Support.value(capacity, "nodeTopology", nil)
          Support.value(capacity, "storageClassName", "").to_s == class_name && !limit.nil? && storage(limit) >= size &&
            !topology.nil? && label_selector_matches?(topology, node.labels)
        end
      end

      # AssumePodVolumes: true when everything is already bound.
      def assume(pod, node_name, podvolumes, data)
        return true if pod_volumes_bound?(pod, data)

        assumed_pvs = []
        podvolumes.bindings = podvolumes.bindings.map do |volume, claim|
          bound, dirty = bind_volume_to_claim(volume, claim)
          if dirty
            @cache_mutex.synchronize { @assumed_pvs[name_of(bound)] = bound }
            assumed_pvs << bound
          end
          [bound, claim]
        end
        podvolumes.provisions = podvolumes.provisions.map do |claim|
          clone = deep_copy(claim)
          clone["metadata"]["annotations"] = (clone["metadata"]["annotations"] || {}).merge(ANN_SELECTED_NODE => node_name)
          @cache_mutex.synchronize { @assumed_pvcs[claim_key(clone)] = clone }
          clone
        end
        false
      end

      def pod_volumes_bound?(pod, data)
        pod.volumes.all? do |volume|
          name, = claim_name(pod, volume)
          next true if name.nil?

          claim = pvc(pod.namespace, name, data)
          claim && fully_bound?(claim)
        end
      end

      # GetBindVolumeToClaim: [volume, dirty].
      def bind_volume_to_claim(volume, claim)
        clone = deep_copy(volume)
        dirty = false
        reference = value(volume, "spec", "claimRef")
        already = bound_to_claim?(volume, claim)
        unless reference && Support.value(reference, "name", "") == value(claim, "metadata", "name") &&
               Support.value(reference, "namespace", "") == value(claim, "metadata", "namespace") &&
               Support.value(reference, "uid", "").to_s == value(claim, "metadata", "uid").to_s
          clone["spec"]["claimRef"] = {"kind" => "PersistentVolumeClaim", "namespace" => value(claim, "metadata", "namespace"),
                                       "name" => value(claim, "metadata", "name"), "uid" => value(claim, "metadata", "uid"),
                                       "apiVersion" => "v1", "resourceVersion" => value(claim, "metadata", "resourceVersion")}.compact
          dirty = true
        end
        annotations = clone["metadata"]["annotations"] || {}
        if !already && !annotations.key?(ANN_BOUND_BY_CONTROLLER)
          clone["metadata"]["annotations"] = annotations.merge(ANN_BOUND_BY_CONTROLLER => "yes")
          dirty = true
        end
        [clone, dirty]
      end

      def revert(podvolumes)
        @cache_mutex.synchronize do
          podvolumes.bindings.each { |volume, _claim| @assumed_pvs.delete(name_of(volume)) }
          podvolumes.provisions.each { |claim| @assumed_pvcs.delete(claim_key(claim)) }
        end
      end

      # bindAPIUpdate: the PVs, then the claims to provision.  What was not
      # written is reverted.
      def bind_api_update(podvolumes)
        written_pvs = 0
        written_claims = 0
        podvolumes.bindings.each_with_index do |(volume, claim), position|
          podvolumes.bindings[position] = [@api.update_pv(volume), claim]
          written_pvs += 1
        end
        podvolumes.provisions.each_with_index do |claim, position|
          podvolumes.provisions[position] = @api.update_pvc(claim)
          written_claims += 1
        end
      ensure
        @cache_mutex.synchronize do
          Array(podvolumes.bindings[written_pvs..]).each { |volume, _claim| @assumed_pvs.delete(name_of(volume)) }
          Array(podvolumes.provisions[written_claims..]).each { |claim| @assumed_pvcs.delete(claim_key(claim)) }
        end
      end

      # checkBindings against the API objects.
      def check_bindings(pod, node_name, podvolumes)
        node = @api.get_node(node_name)
        raise BindingError, %(failed to get node "#{node_name}") if node.nil?

        labels = value(node, "metadata", "labels") || {}
        csi_node = @api.respond_to?(:get_csi_node) ? @api.get_csi_node(node_name) : nil
        raise BindingError, "pod does not exist any more" if @api.get_pod(pod.namespace, pod.name).nil?

        podvolumes.bindings.each do |written, claim|
          volume = @api.get_pv(name_of(written))
          current = @api.get_pvc(value(claim, "metadata", "namespace"), value(claim, "metadata", "name"))
          raise BindingError, %(failed to check binding: PersistentVolume "#{name_of(written)}" not found) if volume.nil?
          raise BindingError, %(failed to check binding: PersistentVolumeClaim "#{claim_key(claim)}" not found) if current.nil?
          return false if newer?(written, volume)
          unless node_affinity_matches?(translate(volume, csi_node), labels)
            raise BindingError, %(pv "#{name_of(volume)}" node affinity doesn't match node "#{node_name}": no matching NodeSelectorTerms)
          end

          reference = value(volume, "spec", "claimRef")
          raise BindingError, %(ClaimRef got reset for pv "#{name_of(volume)}") if reference.nil? || Support.value(reference, "uid", "").to_s.empty?
          return false unless fully_bound?(current)
        end
        podvolumes.provisions.each do |written|
          current = @api.get_pvc(value(written, "metadata", "namespace"), value(written, "metadata", "name"))
          raise BindingError, %(failed to check provisioning pvc: PersistentVolumeClaim "#{claim_key(written)}" not found) if current.nil?
          return false if newer?(written, current)

          annotations = value(current, "metadata", "annotations")
          raise BindingError, %(selectedNode annotation reset for PVC "#{value(current, "metadata", "name")}") if annotations.nil?
          raise BindingError, %(provisioning failed for PVC "#{value(current, "metadata", "name")}") if annotations[ANN_SELECTED_NODE] != node_name

          volume_name = value(current, "spec", "volumeName").to_s
          unless volume_name.empty?
            volume = @api.get_pv(volume_name)
            return false if volume.nil?
            unless node_affinity_matches?(translate(volume, csi_node), labels)
              raise BindingError, %(pv "#{volume_name}" node affinity doesn't match node "#{node_name}": no matching NodeSelectorTerms)
            end
          end
          return false unless fully_bound?(current)
        end
        true
      end

      # The written object is newer than what the API returned.
      def newer?(written, current)
        mine = Integer(value(written, "metadata", "resourceVersion").to_s, exception: false)
        theirs = Integer(value(current, "metadata", "resourceVersion").to_s, exception: false)
        !mine.nil? && !theirs.nil? && mine > theirs
      end

      # The CSI topology key csi-translation-lib gives each migrated plugin's
      # zone.
      CSI_ZONE_KEYS = {"kubernetes.io/aws-ebs" => "topology.ebs.csi.aws.com/zone",
                       "kubernetes.io/gce-pd" => "topology.gke.io/zone",
                       "kubernetes.io/azure-disk" => "topology.disk.csi.azure.com/zone",
                       "kubernetes.io/cinder" => "topology.cinder.csi.openstack.org/zone"}.freeze
      ZONE_KEYS = %w[topology.kubernetes.io/zone failure-domain.beta.kubernetes.io/zone].freeze

      # tryTranslatePVToCSI: an in-tree PV whose plugin the node lists as
      # migrated (CSINode storage.alpha.kubernetes.io/migrated-plugins) is
      # checked with the CSI driver's topology: zone requirements (from its
      # node affinity, else its zone labels) move to the driver's zone key.
      def translate(volume, csi_node)
        source = MIGRATED.keys.find { |key| value(volume, "spec", key) }
        return volume if source.nil? || csi_node.nil?

        plugin = MIGRATED.fetch(source).first
        migrated = (value(csi_node, "metadata", "annotations") || {})[MIGRATED_PLUGINS_ANNOTATION].to_s.split(",")
        zone_key = CSI_ZONE_KEYS[plugin]
        return volume unless migrated.include?(plugin) && zone_key

        clone = deep_copy(volume)
        terms = value(clone, "spec", "nodeAffinity", "required", "nodeSelectorTerms")
        if terms.nil?
          labels = value(volume, "metadata", "labels") || {}
          zone = ZONE_KEYS.lazy.map { |key| labels[key] }.find { |item| !item.to_s.empty? }
          return volume if zone.nil?

          clone["spec"]["nodeAffinity"] = {"required" => {"nodeSelectorTerms" => [
            {"matchExpressions" => [{"key" => zone_key, "operator" => "In", "values" => zone.to_s.split("__")}]}
          ]}}
          return clone
        end
        terms.each do |term|
          Array(term["matchExpressions"]).each { |expression| expression["key"] = zone_key if ZONE_KEYS.include?(expression["key"]) }
        end
        clone
      end

      # ------------------------------------------------------ cache access

      def index(data)
        return @index if @index_key.equal?(data)

        items = ->(*keys) { Filters::Helpers.items(Filters::Helpers.collection(data, *keys)) }
        @index = {
          claims: items.call("persistentVolumeClaims", "pvcs", "claims").to_h { |object| [claim_key(object), object] },
          volumes: items.call("persistentVolumes", "pvs", "volumes").to_h { |object| [name_of(object), object] },
          classes: items.call("storageClasses").to_h { |object| [name_of(object), object] },
          csi_nodes: items.call("csiNodes").to_h { |object| [name_of(object), object] },
          csi_drivers: items.call("csiDrivers").to_h { |object| [name_of(object), object] },
          capacities: items.call("csiStorageCapacities")
        }
        @index_key = data
        @index
      end

      # AssumeCache.Get: the assumed object until the informer has a newer one.
      def pvc(namespace, name, data)
        key = "#{namespace}/#{name}"
        latest = index(data)[:claims][key]
        overlay(@assumed_pvcs, key, latest)
      end

      def pv(name, data)
        overlay(@assumed_pvs, name, index(data)[:volumes][name])
      end

      def pvs(data)
        index(data)[:volumes].map { |name, volume| overlay(@assumed_pvs, name, volume) }
      end

      def overlay(assumed, key, latest)
        @cache_mutex.synchronize do
          candidate = assumed[key]
          return latest if candidate.nil?
          return candidate if latest.nil?

          mine = Integer(value(candidate, "metadata", "resourceVersion").to_s, exception: false)
          theirs = Integer(value(latest, "metadata", "resourceVersion").to_s, exception: false)
          if mine && theirs && theirs > mine
            assumed.delete(key)
            return latest
          end
          candidate
        end
      end

      # ------------------------------------------------------------ helpers

      def value(object, *path)
        path.reduce(object) do |current, key|
          break nil if current.nil?

          Support.value(current, key, nil)
        end
      end

      def name_of(object) = value(object, "metadata", "name").to_s
      def claim_key(claim) = "#{value(claim, "metadata", "namespace")}/#{value(claim, "metadata", "name")}"

      def claim_class(claim)
        annotations = value(claim, "metadata", "annotations") || {}
        return annotations[BETA_STORAGE_CLASS].to_s if annotations.key?(BETA_STORAGE_CLASS)

        value(claim, "spec", "storageClassName").to_s
      end

      def volume_class(volume)
        annotations = value(volume, "metadata", "annotations") || {}
        return annotations[BETA_STORAGE_CLASS].to_s if annotations.key?(BETA_STORAGE_CLASS)

        value(volume, "spec", "storageClassName").to_s
      end

      def volume_mode(object) = (value(object, "spec", "volumeMode") || "Filesystem").to_s
      def access_modes(object) = Array(value(object, "spec", "accessModes")).map(&:to_s)

      # IsVolumeBoundToClaim.
      def bound_to_claim?(volume, claim)
        reference = value(volume, "spec", "claimRef")
        return false if reference.nil?
        return false unless Support.value(reference, "name", "") == value(claim, "metadata", "name") &&
                            Support.value(reference, "namespace", "") == value(claim, "metadata", "namespace")

        uid = Support.value(reference, "uid", "").to_s
        uid.empty? || uid == value(claim, "metadata", "uid").to_s
      end

      def storage(quantity)
        return 0 if quantity.nil?

        Schema::Quantity.from_json(quantity.to_s).value
      rescue StandardError
        0
      end

      # volume.CheckNodeAffinity: node labels only (metadata.name is empty).
      def node_affinity_matches?(volume, labels)
        required = value(volume, "spec", "nodeAffinity", "required")
        return true if required.nil?

        Array(Support.value(required, "nodeSelectorTerms", [])).any? do |term|
          expressions = Array(Support.value(term, "matchExpressions", []))
          fields = Array(Support.value(term, "matchFields", []))
          next false if expressions.empty? && fields.empty?

          expressions.all? { |requirement| requirement_matches?(requirement, labels) } &&
            fields.all? { |requirement| requirement_matches?(requirement, {"metadata.name" => ""}) }
        end
      end

      def requirement_matches?(requirement, labels)
        key = Support.value(requirement, "key", "").to_s
        values = Array(Support.value(requirement, "values", [])).map(&:to_s)
        present = labels.key?(key)
        actual = labels[key].to_s
        case Support.value(requirement, "operator", "").to_s
        when "In" then present && values.include?(actual)
        when "NotIn" then !present || !values.include?(actual)
        when "Exists" then present
        when "DoesNotExist" then !present
        when "Gt" then present && Filters::Helpers.numeric_compare(actual, values.first, :>)
        when "Lt" then present && Filters::Helpers.numeric_compare(actual, values.first, :<)
        else false
        end
      end

      # v1helper.MatchTopologySelectorTerms.
      def topology_matches?(terms, labels)
        terms = Array(terms)
        return true if terms.empty?

        terms.any? do |term|
          Array(Support.value(term, "matchLabelExpressions", [])).all? do |expression|
            key = Support.value(expression, "key", "").to_s
            labels.key?(key) && Array(Support.value(expression, "values", [])).map(&:to_s).include?(labels[key].to_s)
          end
        end
      end

      # metav1.LabelSelectorAsSelector(...).Matches.
      def label_selector_matches?(selector, labels)
        labels = labels.transform_keys(&:to_s)
        (Support.value(selector, "matchLabels", {}) || {}).all? { |key, expected| labels[key.to_s] == expected.to_s } &&
          Array(Support.value(selector, "matchExpressions", [])).all? do |expression|
            key = Support.value(expression, "key", "").to_s
            values = Array(Support.value(expression, "values", [])).map(&:to_s)
            case Support.value(expression, "operator", "").to_s
            when "In" then labels.key?(key) && values.include?(labels[key].to_s)
            when "NotIn" then !labels.key?(key) || !values.include?(labels[key].to_s)
            when "Exists" then labels.key?(key)
            when "DoesNotExist" then !labels.key?(key)
            else false
            end
          end
      end

      def deep_copy(object)
        case object
        when Hash then object.each_with_object({}) { |(key, item), copy| copy[key.to_s] = deep_copy(item) }
        when Array then object.map { |item| deep_copy(item) }
        else object
        end
      end
    end
  end
end
