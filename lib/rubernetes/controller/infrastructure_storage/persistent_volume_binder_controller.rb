# frozen_string_literal: true

module Rubernetes
  module Controller
    # PersistentVolume binder. It applies class, access-mode, selector, volume
    # mode, and capacity matching before writing the PV claimRef and PVC
    # volumeName pair.
    # pkg/controller/volume/persistentvolume (v1.36.2): syncClaim binds a
    # claim to the smallest matching Available volume (or its pre-bound
    # one), leaves WaitForFirstConsumer claims to the scheduler, hands
    # dynamic provisioning to the external provisioner, and marks claims
    # Lost when their volume goes; syncVolume keeps volume phases, unbinds
    # volumes whose claim went elsewhere, and reclaims Released volumes
    # (Retain; Delete -- the in-tree hostPath deleter or the external
    # provisioner; Recycle -- a recycler Pod).
    class PersistentVolumeBinderController < BaseController
      include InfrastructureStorageSupport

      PV = ResourceDescriptor.parse("PersistentVolume")
      PVC = ResourceDescriptor.parse("PersistentVolumeClaim")
      POD = ResourceDescriptor.parse("Pod")
      STORAGE_CLASS = ResourceDescriptor.parse("StorageClass")

      ANN_BIND_COMPLETED = "pv.kubernetes.io/bind-completed"
      ANN_BOUND_BY_CONTROLLER = "pv.kubernetes.io/bound-by-controller"
      ANN_SELECTED_NODE = "volume.kubernetes.io/selected-node"
      ANN_DYNAMICALLY_PROVISIONED = "pv.kubernetes.io/provisioned-by"
      ANN_MIGRATED_TO = "pv.kubernetes.io/migrated-to"
      ANN_STORAGE_PROVISIONER = "volume.kubernetes.io/storage-provisioner"
      ANN_BETA_STORAGE_PROVISIONER = "volume.beta.kubernetes.io/storage-provisioner"
      ANN_BETA_STORAGE_CLASS = "volume.beta.kubernetes.io/storage-class"
      ANN_PRE_RESIZE_CAPACITY = "volume.alpha.kubernetes.io/pre-resize-capacity"
      ANN_DEFAULT_CLASS = "storageclass.kubernetes.io/is-default-class"
      ANN_BETA_DEFAULT_CLASS = "storageclass.beta.kubernetes.io/is-default-class"
      IN_TREE_FINALIZER = "kubernetes.io/pv-controller"
      EXTERNAL_FINALIZER = "external-provisioner.volume.kubernetes.io/finalizer"
      # CSI migration (on for every migratable in-tree plugin in v1.36).
      MIGRATED_PLUGINS = {
        "kubernetes.io/aws-ebs" => "ebs.csi.aws.com", "kubernetes.io/gce-pd" => "pd.csi.storage.gke.io",
        "kubernetes.io/azure-disk" => "disk.csi.azure.com", "kubernetes.io/azure-file" => "file.csi.azure.com",
        "kubernetes.io/cinder" => "cinder.csi.openstack.org", "kubernetes.io/vsphere-volume" => "csi.vsphere.vmware.com",
        "kubernetes.io/portworx-volume" => "pxd.portworx.com"
      }.freeze
      ACCESS_MODE_ORDER = %w[ReadWriteOnce ReadOnlyMany ReadWriteMany ReadWriteOncePod].freeze
      RECYCLER_IMAGE = "registry.k8s.io/build-image/debian-base:bookworm-v1.0.6"
      RECYCLER_SCRIPT = "test -e /scrub && find /scrub -mindepth 1 -delete && test -z \"$(ls -A /scrub)\" || exit 1"
      # A pending operation's recheck (the upstream operation executor and
      # 15 s resync).
      RECHECK_SECONDS = 5.0
      NODE = ResourceDescriptor.parse("Node")
      # pkg/volume/hostpath: the one in-tree plugin that can still provision,
      # for a cluster whose nodes share one filesystem.
      HOST_PATH_PLUGIN = "kubernetes.io/host-path"
      HOST_PATH_BASE = "/tmp/hostpath_pv"
      ANN_CREATED_BY = "kubernetes.io/createdby"

      def initialize(*, host_path_deleter: nil, host_path_provisioner: nil, **)
        super(*, **)
        # hostPathProvisioner.Provision: os.MkdirAll(path, 0750).
        @host_path_provisioner = host_path_provisioner || ->(path) { FileUtils.mkdir_p(path, mode: 0o750) }
        @host_path_deleter = host_path_deleter
      end

      def plan(object, store: nil, persistent_volumes: nil, volumes: nil, claims: nil, pods: nil, storage_classes: nil,
               enable_hostpath_provisioner: false, hostpath_provisioner_root: HOST_PATH_BASE, **_options)
        adapter = adapter_for(store)
        context = {
          adapter: adapter, hostpath_provisioner: enable_hostpath_provisioner, hostpath_root: File.expand_path(hostpath_provisioner_root),
          volumes: persistent_volumes || volumes || list_storage_objects(adapter, PV, namespace: :all),
          claims: claims,
          pods: pods,
          classes: storage_classes || list_storage_objects(adapter, STORAGE_CLASS, namespace: :all),
          events: [], operations: [], requeue: nil
        }
        case Support.kind(object)
        when "PersistentVolume" then sync_volume(object, context)
        when "PersistentVolumeClaim" then sync_claim(object, context)
        else return ReconcileResult.new(operations: [], controller: name, key: name_key(object))
        end
        ReconcileResult.new(operations: context[:operations].compact,
                            events: once_per_state("#{Support.kind(object)}/#{name_key(object)}", context[:events]),
                            controller: name, key: name_key(object), requeue_after: context[:requeue])
      end

      private

      def event(context, type, reason, message, involved: nil)
        entry = {"type" => type, "reason" => reason, "message" => message}
        if involved
          entry["involvedObject"] = {"apiVersion" => "v1", "kind" => Support.kind(involved), "namespace" => Support.namespace(involved),
                                     "name" => Support.name(involved), "uid" => Support.uid(involved)}.compact
        end
        context[:events] << entry
      end

      def annotation?(object, key) = (Support.value(Support.metadata(object), "annotations", {}) || {}).key?(key)

      def set_annotation(object, key, value)
        object["metadata"] ||= {}
        object["metadata"]["annotations"] = (object["metadata"]["annotations"] || {}).merge(key => value)
      end

      def claim_ref(volume)
        reference = Support.value(Support.spec(volume), "claimRef", nil)
        reference.is_a?(Hash) ? reference : nil
      end

      # IsVolumeBoundToClaim.
      def bound_to_claim?(volume, claim)
        reference = claim_ref(volume)
        return false unless reference
        return false unless Support.value(reference, "name", "") == Support.name(claim) &&
                            Support.value(reference, "namespace", "") == Support.namespace(claim)

        uid = Support.value(reference, "uid", "").to_s
        uid.empty? || uid == Support.uid(claim).to_s
      end

      def claim_class(claim)
        annotations = Support.value(Support.metadata(claim), "annotations", {}) || {}
        return annotations[ANN_BETA_STORAGE_CLASS].to_s if annotations.key?(ANN_BETA_STORAGE_CLASS)

        Support.value(Support.spec(claim), "storageClassName", "").to_s
      end

      def claim_has_class?(claim)
        annotations = Support.value(Support.metadata(claim), "annotations", {}) || {}
        annotations.key?(ANN_BETA_STORAGE_CLASS) || !Support.spec(claim)["storageClassName"].nil?
      end

      def volume_class(volume)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        return annotations[ANN_BETA_STORAGE_CLASS].to_s if annotations.key?(ANN_BETA_STORAGE_CLASS)

        Support.value(Support.spec(volume), "storageClassName", "").to_s
      end

      def vac(object) = Support.value(Support.spec(object), "volumeAttributesClassName", "").to_s
      def volume_mode(object) = (Support.value(Support.spec(object), "volumeMode", nil) || "Filesystem").to_s
      def access_modes(object) = Array(Support.value(Support.spec(object), "accessModes", [])).map(&:to_s)
      def access_modes_contain?(available, requested) = requested.all? { |mode| available.include?(mode) }
      def mode_key(modes) = ACCESS_MODE_ORDER.select { |mode| modes.include?(mode) }.join(",")
      def reclaim_policy(volume) = Support.value(Support.spec(volume), "persistentVolumeReclaimPolicy", "").to_s
      def volume_capacity(volume) = Support.value(Support.value(Support.spec(volume), "capacity", {}) || {}, "storage", nil)

      def claim_request(claim)
        Support.value(Support.value(Support.value(Support.spec(claim), "resources", {}) || {}, "requests", {}) || {}, "storage", nil)
      end

      def storage(quantity) = quantity.nil? ? 0 : quantity_base(quantity)

      def find_volume(context, name) = Array(context[:volumes]).find { |volume| Support.name(volume) == name.to_s }

      def find_claim(context, namespace, claim_name)
        if context[:claims]
          return Array(context[:claims]).find do |claim|
            Support.namespace(claim) == namespace.to_s && Support.name(claim) == claim_name.to_s
          end
        end

        context[:adapter]&.find(PVC, name: claim_name.to_s, namespace: namespace.to_s)
      end

      def live_claim(context, namespace, claim_name)
        adapter = context[:adapter]
        return nil unless InfrastructureCapability.live_reads?(adapter)

        adapter.find_live(PVC, name: claim_name.to_s, namespace: namespace.to_s)
      end

      def find_class(context, class_name) = Array(context[:classes]).find { |item| Support.name(item) == class_name.to_s }

      # GetDefaultClass: the newest default class, then by name.
      def default_class(classes)
        defaults = Array(classes).select do |item|
          annotations = Support.value(Support.metadata(item), "annotations", {}) || {}
          annotations[ANN_DEFAULT_CLASS] == "true" || annotations[ANN_BETA_DEFAULT_CLASS] == "true"
        end
        defaults.min_by do |item|
          created = Support.parse_time(Support.value(Support.metadata(item), "creationTimestamp", nil))
          [-(created ? created.to_r : 0), Support.name(item)]
        end
      end

      def pods_using(claim, context) = pods_by_claim(context, Support.namespace(claim), Support.name(claim))

      def pods_by_claim(context, namespace, claim_name, fresh: false)
        pods = context[:pods] || context[:adapter]&.list(POD, namespace: namespace, fresh: fresh)
        Array(pods).select do |pod|
          Support.namespace(pod).to_s == namespace.to_s &&
            Array(Support.value(Support.spec(pod), "volumes", [])).any? do |volume|
              Support.value(Support.value(volume, "persistentVolumeClaim", {}) || {}, "claimName", nil).to_s == claim_name.to_s ||
                (volume.is_a?(Hash) && volume["ephemeral"] && "#{Support.name(pod)}-#{volume["name"]}" == claim_name.to_s)
            end
        end
      end

      # util.IsPodTerminated: terminal phase, or deleted with no running container.
      def pod_terminated?(pod)
        phase = Support.value(Support.status(pod), "phase", "").to_s
        return true if %w[Succeeded Failed].include?(phase)
        return false if Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?

        Array(Support.value(Support.status(pod), "containerStatuses", [])).none? do |status|
          (Support.value(status, "state", {}) || {}).key?("running")
        end
      end
    end
  end
end

require_relative "persistent_volume_binder/claims"
require_relative "persistent_volume_binder/provisioning"
require_relative "persistent_volume_binder/binding"
require_relative "persistent_volume_binder/volumes"
require_relative "persistent_volume_binder/recycling"
