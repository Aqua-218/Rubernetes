# frozen_string_literal: true

# Public entry point for the storage data plane.  The volume package keeps
# lifecycle policy, ownership, and security checks in Ruby while delegating
# kernel/filesystem/CSI effects to explicitly injected adapters.
require_relative "volume/errors"
require_relative "volume/types"
require_relative "volume/state_machine"
require_relative "volume/ledger"
require_relative "volume/path_security"
require_relative "volume/projection"
require_relative "volume/service_account_token_provider"
require_relative "volume/backends"
require_relative "volume/native_mount_adapter"
require_relative "volume/native_device_adapter"
require_relative "volume/binding"
require_relative "volume/csi_uds_client"
require_relative "volume/csi"
require_relative "volume/snapshot"
require_relative "volume/manager"
require_relative "volume/selinux"

module Rubernetes
  module Volume
    STATES = StateMachine::STATES unless const_defined?(:STATES, false)
    # Compatibility aliases used by callers that name the manager after the
    # Kubernetes node/controller split.
    VolumeManager = Manager unless const_defined?(:VolumeManager, false)
    ControllerService = Controller unless const_defined?(:ControllerService, false)
    NodeService = Node unless const_defined?(:NodeService, false)
    StorageController = Binder unless const_defined?(:StorageController, false)

    module Builtins
      EmptyDir = EmptyDirBackend unless const_defined?(:EmptyDir, false)
      HostPath = HostPathBackend unless const_defined?(:HostPath, false)
      ConfigMap = ConfigMapBackend unless const_defined?(:ConfigMap, false)
      Secret = SecretBackend unless const_defined?(:Secret, false)
      DownwardAPI = DownwardAPIBackend unless const_defined?(:DownwardAPI, false)
      Projected = ProjectedBackend unless const_defined?(:Projected, false)
      Image = ImageBackend unless const_defined?(:Image, false)
      Local = LocalBackend unless const_defined?(:Local, false)
      LoopDM = LoopDMBackend unless const_defined?(:LoopDM, false)
    end

    module Projection
      AtomicWriter = Rubernetes::Volume::AtomicWriter unless const_defined?(:AtomicWriter, false)
      TokenRotator = Rubernetes::Volume::TokenRotator unless const_defined?(:TokenRotator, false)
      Projector = Rubernetes::Volume::Projector unless const_defined?(:Projector, false)
    end

    module Storage
      Binder = Rubernetes::Volume::Binder unless const_defined?(:Binder, false)
      PersistentVolume = Rubernetes::Volume::PersistentVolume unless const_defined?(:PersistentVolume, false)
      PersistentVolumeClaim = Rubernetes::Volume::PersistentVolumeClaim unless const_defined?(:PersistentVolumeClaim, false)
      StorageClass = Rubernetes::Volume::StorageClass unless const_defined?(:StorageClass, false)
    end

    module Mount
      IdentityLedger = Rubernetes::Volume::MountIdentityLedger unless const_defined?(:IdentityLedger, false)
      NativeMountAdapter = Rubernetes::Volume::NativeMountAdapter unless const_defined?(:NativeMountAdapter, false)
    end

    NativeMountAdapter = Rubernetes::Volume::NativeMountAdapter unless const_defined?(:NativeMountAdapter, false)
    NativeMount = Rubernetes::Volume::NativeMount unless const_defined?(:NativeMount, false)
    NativeDevice = Rubernetes::Volume::NativeDeviceAdapter unless const_defined?(:NativeDevice, false)
    NativeDeviceAdapter = Rubernetes::Volume::NativeDeviceAdapter unless const_defined?(:NativeDeviceAdapter, false)
    FilesystemUuidResolver = Rubernetes::Volume::NativeDeviceAdapter::FilesystemUuidResolver unless const_defined?(:FilesystemUuidResolver, false)

    module Path
      Openat2 = Rubernetes::Volume::PathSecurity unless const_defined?(:Openat2, false)
    end
  end
end
