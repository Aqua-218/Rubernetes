# frozen_string_literal: true

# Production Linux effects used by Native host profiles.  These adapters are
# deliberately separate from the runtime policy/state machine: they own only
# kernel-facing operations and expose a read-only capability preflight.  A
# failed preflight or effect is fatal; no adapter silently falls back to a
# recording implementation.
#
# No adapter shells out to nsenter(1), unshare(1), or any other external
# binary.  Namespace transitions are direct setns(2)/unshare(2) calls made by
# a freshly created, single-threaded clone3 child (spec/node/runtime.md
# §5.8.6, §5.8.10), and the workload bootstrap runs in that child until it
# execveat(2)s the verified executable.

require "digest"
# Digest::SHA256 autoloads on first use; the workload bootstrap first uses it
# after the pivot into the container root, where the library is not there.
require "digest/sha2"
require "fileutils"
require "fiddle"
require "io/console"
require "pty"
require "json"
require "openssl"
require "rbconfig"
require "socket"

require_relative "capabilities"
require_relative "cgroup_v2"
require_relative "clone3"
require_relative "landlock"
require_relative "mount"
require_relative "openat2"
require_relative "pidfd"
require_relative "pivot_root"
require_relative "security"
require_relative "setns"
require_relative "userns"

# The error classes, the capability contract and process identity helpers.
require_relative "native_adapters/contract"

# The namespace holder: the Pod's PID 1 and the owner of its namespaces.
require_relative "native_adapters/namespace_adapter"
require_relative "native_adapters/namespace_adapter/holder"
require_relative "native_adapters/namespace_adapter/exec_supervisor"
require_relative "native_adapters/namespace_adapter/helper"

# The OverlayFS workspace mounted inside the holder's mount namespace.
require_relative "native_adapters/overlay_filesystem_adapter"
require_relative "native_adapters/overlay_filesystem_adapter/cleanup"
require_relative "native_adapters/overlay_filesystem_adapter/mount_table"

require_relative "native_adapters/cgroup_adapter"

# The security plan applied in the process that execs the workload.
require_relative "native_adapters/security_adapter"
require_relative "native_adapters/security_adapter/rootfs"
require_relative "native_adapters/security_adapter/bind_mounts"
require_relative "native_adapters/security_adapter/executable"
require_relative "native_adapters/security_adapter/steps"

# Workload creation: agent -> wrapper (fork) -> workload (clone3).
require_relative "native_adapters/process_gate_adapter"
require_relative "native_adapters/process_gate_adapter/pty_input"
require_relative "native_adapters/process_gate_adapter/gate"
require_relative "native_adapters/process_gate_adapter/spawn"
require_relative "native_adapters/process_gate_adapter/wrapper"
require_relative "native_adapters/container_hook"
require_relative "native_adapters/workload_bootstrap"

# exec, port-forward, probes and sysctls inside a live Pod.
require_relative "native_adapters/namespace_connector"
require_relative "native_adapters/namespace_connector/streams"
require_relative "native_adapters/namespace_connector/probes"
require_relative "native_adapters/namespace_connector/port_forward_multiplexer"

require_relative "native_adapters/pidfd_adapter"

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        module_function

        def for_profile(profile:, sandbox_root:, cgroup_root:, architecture: nil, landlock_roots: [])
          namespace = NamespaceAdapter.new
          filesystem = OverlayFilesystemAdapter.new(root: sandbox_root, namespace_adapter: namespace)
          cgroup = CgroupAdapter.new(root: cgroup_root)
          security = SecurityAdapter.new(landlock_roots: landlock_roots)
          process = ProcessGateAdapter.new(namespace_adapter: namespace)
          streams = NamespaceConnector.new(process_adapter: process, cgroup_adapter: cgroup, namespace_adapter: namespace)
          pidfd = PidfdAdapter.new
          probe = Security::CapabilityProbe.new(architecture: architecture)
          {
            namespace_adapter: namespace,
            filesystem_adapter: filesystem,
            cgroup_adapter: cgroup,
            security_adapter: security,
            security_probe: probe,
            process_adapter: process,
            pidfd_adapter: pidfd,
            exec_adapter: streams,
            port_forward_adapter: streams,
            http_probe_adapter: streams,
            tcp_probe_adapter: streams,
            sysctl_adapter: streams
          }.freeze
        end
      end

      # rubocop:disable-next Lint/SelfAssignment -- re-exports the outer constant into this scope when it is missing
      NativeAdapters = NativeAdapters unless const_defined?(:NativeAdapters, false)
    end
  end
end
