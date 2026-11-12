# frozen_string_literal: true

# Ruby Native Runtime backend.  It owns validation, state ordering, resource
# ownership, and workload gates; Linux-specific effects are delegated to the
# typed adapters under Platform::Linux and are injectable for L0/L1 tests.

require "digest"
require "json"
require "securerandom"
require "time"

# The native ownership implementation predates the common Runtime contract and
# uses a few top-level constants with the same names.  Keep those primitives
# private to this backend when the common contract was loaded first: capture
# the common definitions, load the native implementation, and restore the
# common definitions after retaining the native classes under Native::Support.
# This also makes `require "rubernetes/runtime"` followed by
# `require "rubernetes/runtime/native"` safe and warning-free.
module Rubernetes
  module Runtime
    NATIVE_LOADER_CONSTANTS = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache) unless const_defined?(:NATIVE_LOADER_CONSTANTS, false)
    %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired
       RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      NATIVE_LOADER_CONSTANTS[name] = const_get(name, false) if const_defined?(name, false)
    end
    NATIVE_LOADER_CONSTANTS.each_key { |name| remove_const(name) }
    generic_runtime = const_get(:Runtime, false) if const_defined?(:Runtime, false)
    remove_const(:Native) if const_defined?(:Native, false) && generic_runtime && const_get(:Native, false).equal?(generic_runtime)
    remove_const(:Backend) if const_defined?(:Backend, false) && generic_runtime && const_get(:Backend, false).equal?(generic_runtime)
    class Native
      EFFECT_POINTS = %i[
        workspace_allocated isolation_created resources_attached workload_stopped
      ].freeze

      module Support
      end
    end
  end
end

require_relative "ownership"

module Rubernetes
  module Runtime
    %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired
       RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      Native::Support.const_set(name, const_get(name, false)) unless Native::Support.const_defined?(name, false)
    end
    NATIVE_LOADER_CONSTANTS.each do |name, value|
      remove_const(name) if const_defined?(name, false)
      const_set(name, value)
    end
    remove_const(:NATIVE_LOADER_CONSTANTS)
  end
end

require_relative "../platform/linux/cgroup_v2"
require_relative "../platform/linux/device_cgroup"
require_relative "../platform/linux/landlock"
require_relative "../platform/linux/openat2"
require_relative "../platform/linux/process_supervisor"
require_relative "../platform/linux/security"
require_relative "../platform/linux/native_adapters"
require_relative "native/errors"
require_relative "native/config"
require_relative "native/namespace"
require_relative "native/filesystem"
require_relative "native/sandbox"
require_relative "native/adapters"
require_relative "native/resources"
require_relative "native/kernel_observer"
require_relative "native/hooks"
require_relative "native/memory_journal"
require_relative "native/assembly"
require_relative "native/ledger_requests"
require_relative "native/images"
require_relative "native/container_spec"
require_relative "native/resource_limits"
require_relative "native/device_filter"
require_relative "native/sandbox_lifecycle"
require_relative "native/container_lifecycle"
require_relative "native/container_start"
require_relative "native/container_hooks"
require_relative "native/connectors"
require_relative "native/inventory"
require_relative "native/resource_cleanup"
require_relative "native/crash_recovery"
require_relative "native/teardown"
require_relative "native/cleanup_errors"
require_relative "../platform/linux/userns"

module Rubernetes
  module Runtime
    class Native
      OwnershipLedger = Support::OwnershipLedger unless const_defined?(:OwnershipLedger, false)
      RollbackJournal = Support::RollbackJournal unless const_defined?(:RollbackJournal, false)
      JournalCorruption = Support::JournalCorruption unless const_defined?(:JournalCorruption, false)
      OwnershipConflict = Support::OwnershipConflict unless const_defined?(:OwnershipConflict, false)
      InvalidTransition = Support::InvalidTransition unless const_defined?(:InvalidTransition, false)
      # Native is part of the public Runtime contract.  Its own recovery
      # failures must be catchable through Runtime::RecoveryRequired even
      # though the legacy ownership helpers retain private Support errors.
      RecoveryRequired = Rubernetes::Runtime::RecoveryRequired unless const_defined?(:RecoveryRequired, false)

      # Every way the process supervisor reports that a workload process
      # could not be signalled, waited for or read: its own errors (unknown
      # handle, no exit confirmation, timeout), a failed pidfd syscall, errno
      # from kill/wait on a pid that is gone, a closed stream.  The paths
      # that tolerate a process being already gone name exactly these.
      PROCESS_ERRORS = [
        Platform::Linux::ProcessSupervisor::Error, Platform::Linux::Error, SystemCallError, IOError
      ].freeze

      # An attach client borrows the supervisor-owned stdio descriptors. Its
      # HTTP/WebSocket lifecycle must never close the sole read end and send
      # SIGPIPE to the container. Each request gets an independently closable
      # view while the underlying descriptor remains owned by the process
      # supervisor until container teardown.
      class BorrowedProcessStream
        def initialize(endpoint)
          @endpoint = endpoint
          @closed = false
          @mutex = Mutex.new
        end

        def read(length = nil)
          ensure_open!
          length.nil? ? @endpoint.read : @endpoint.read(length)
        end

        def readpartial(length)
          ensure_open!
          @endpoint.readpartial(length)
        end

        def read_nonblock(length, exception: true)
          ensure_open!
          @endpoint.read_nonblock(length, exception: exception)
        end

        def write(value)
          ensure_open!
          @endpoint.write(value)
        end

        def write_nonblock(value, exception: true)
          ensure_open!
          @endpoint.write_nonblock(value, exception: exception)
        end

        # A TTY's input endpoint (the PTY master wrapper) has nothing to
        # flush and does not define it; pipes do.
        def flush
          ensure_open!
          @endpoint.flush if @endpoint.respond_to?(:flush)
          self
        end

        def close
          @mutex.synchronize { @closed = true }
          self
        end

        alias close_write close

        def closed?
          @mutex.synchronize { @closed }
        end

        private

        def ensure_open!
          raise IOError, "borrowed process stream is closed" if closed?
        end
      end

      # The runtime's behaviour lives in the mixins under native/, one
      # responsibility each; they share this object's state (@sandboxes,
      # @ledger, the adapters) and the helpers at the bottom of this file.
      include Assembly           # constructor wiring of adapters and collaborators
      include LedgerRequests     # idempotent requests, claims and identities in the ledger
      include Images             # image resolution, pinning and image-derived container config
      include ContainerSpec      # validation and normalization of caller input
      include ResourceLimits     # cgroup limits, deferred ceilings, OOM, resize, usage
      include DeviceFilter       # the cgroup device allowlist
      include SandboxLifecycle   # run / stop / remove sandbox
      include ContainerLifecycle # create / stop / remove / status / wait
      include ContainerStart     # the gated start
      include ContainerHooks     # OCI hooks at the stages this process owns
      include Connectors         # exec, attach, port-forward, probes, sysctls, logs
      include Inventory          # what the adapters hold, in canonical shape
      include ResourceCleanup    # cleanup of one observed resource
      include CrashRecovery      # recovery and reconstruction after a restart
      include Teardown           # rollback and reverse-order release
      include CleanupErrors      # structured cleanup failures

      def initialize(config: nil, profile: nil, adapters: {}, journal: nil, clock: -> { Time.now.utc },
                     namespace_adapter: nil, cgroup_adapter: nil, filesystem_adapter: nil,
                     security_adapter: nil, security_probe: nil, process_adapter: nil,
                     pidfd_adapter: nil, exec_adapter: nil, attach_adapter: nil,
                     port_forward_adapter: nil, http_probe_adapter: nil, tcp_probe_adapter: nil,
                     image_resolver: nil,
                     **config_options)
        @config = Configuration.from(config, profile: profile, **config_options)
        @clock = clock
        @adapters = collect_adapters(
          adapters,
          namespace: namespace_adapter, cgroup: cgroup_adapter, filesystem: filesystem_adapter,
          security_adapter: security_adapter, security_probe: security_probe, process_adapter: process_adapter,
          pidfd: pidfd_adapter, exec: exec_adapter, attach: attach_adapter, port_forward: port_forward_adapter,
          http_probe: http_probe_adapter, tcp_probe: tcp_probe_adapter, image_resolver: image_resolver
        )
        @image_resolver = @adapters[:image_resolver]
        @mutex = Mutex.new
        @events = []
        @sandboxes = {}
        @requests = {}
        @oom_baselines = {}
        @oom_reported = {}
        @deferred_memory_limits = {}
        @userns_allocator = nil
        validate_host_adapters! if @config.host_profile?
        @journal = journal || default_journal
        @ledger = OwnershipLedger.new(journal: @journal, clock: @clock)
        @namespace = build_namespace
        @filesystem = build_filesystem
        @cgroup = build_cgroup
        @device_filter = build_device_filter
        @security = build_security
        @security_plans = {}
        @security_plan_mutex = Mutex.new
        @process_supervisor = build_process_supervisor
        validate_profile_capabilities! if @config.l3
      rescue Platform::Linux::CgroupV2::Error, Platform::Linux::Landlock::Error => error
        raise CapabilityError, "Native profile capability probe failed closed: #{error.message}"
      end

      def profile
        config.profile
      end

      def runtime_class
        config.runtime_class
      end

      def host_integration?
        config.host_profile?
      end

      def l3?
        config.l3
      end

      attr_reader :capability_probe, :config, :ledger, :namespace, :filesystem, :security, :process_supervisor, :events, :image_resolver

      def validate_config!
        config.validate!
      end

      def trace
        @mutex.synchronize { @events.map(&:dup).freeze }
      end

      private

      # ------------------------------------------------ collaborator protocols
      #
      # The runtime is wired from injected collaborators: production adapters
      # under Platform::Linux, in-memory adapters for the pure profile, and
      # callables in tests and probes.  What such a collaborator is asked
      # about its own shape is asked here, once, under a name; the mixins
      # under native/ call these and never inspect an object themselves.

      # An adapter is either an object with the named operation or a callable
      # that takes the operation as its first argument.
      def invoke(adapter, operation = :call, **arguments)
        if adapter.respond_to?(operation)
          adapter.public_send(operation, **arguments)
        elsif adapter.respond_to?(:call)
          adapter.call(operation, **arguments)
        else
          raise CapabilityError, "adapter cannot perform #{operation}"
        end
      end

      def invoke_observer(source)
        return source.call if source.is_a?(Proc) || source.is_a?(Method)
        return source.list_resources if source.respond_to?(:list_resources)
        return source.observe if source.respond_to?(:observe)
        return source.resources if source.respond_to?(:resources)
        return source.call(:call) if source.respond_to?(:call)

        raise CapabilityError, "native resource observer must expose a callable inventory"
      end

      def invoke_cleaner(source, resource)
        if source.is_a?(Proc) || source.is_a?(Method)
          parameters = source.parameters
          keyword_resource = parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :resource } ||
                             parameters.any? { |kind, _name| kind == :keyrest }
          return keyword_resource ? source.call(resource: resource) : source.call(resource)
        end
        return source.cleanup_resource(resource) if source.respond_to?(:cleanup_resource)
        return source.release_resource(resource) if source.respond_to?(:release_resource)
        return source.call(:cleanup_resource, resource: resource) if source.respond_to?(:call)

        raise CapabilityError, "native resource cleaner must expose a cleanup contract"
      end

      # An observer that declares itself and says it only mirrors this
      # process's memory (see #recover); callables and plain inventories make
      # no such declaration.
      def in_process_observer?(observer)
        observer.respond_to?(:external_observer?) && !observer.external_observer?
      end

      # Sysctl writes and gRPC health checks are optional operations of the
      # namespace connector: the production NamespaceConnector has both, an
      # in-memory connector implements only the probes it is used for.
      def connector_performs?(connector, operation)
        connector.respond_to?(operation)
      end

      # An image resolver is the Node's resolver object or a callable.
      def resolve_image_reference(reference)
        if @image_resolver.respond_to?(:resolve)
          @image_resolver.resolve(reference)
        elsif @image_resolver.respond_to?(:call)
          @image_resolver.call(reference)
        else
          raise CapabilityError, "image resolver must implement resolve or call"
        end
      end

      # A security probe is a callable or an object with #probe.
      def run_security_probe(probe)
        probe.respond_to?(:call) ? probe.call : probe.probe
      end

      # The production gate adapter applies the plan in the workload child and
      # therefore needs the Security it was planned with; the in-memory
      # process adapters apply nothing and take none.
      def share_security_with_process_adapter(security)
        process_adapter = @adapters[:process_adapter]
        process_adapter.security = security if process_adapter.respond_to?(:security=)
      end

      # Only an adapter that can re-verify a live holder (the production
      # NamespaceAdapter) lets a restarted runtime rebuild its sandboxes; the
      # recording adapter of the pure profile has nothing to adopt.
      def namespace_adoption_supported?
        @namespace.adapter.respond_to?(:adopt)
      end

      # cpu.stat/memory.stat accounting exists for real cgroups only; the
      # pure profile's FakeCgroup has no usage to report.
      def cgroup_reports_usage?
        @cgroup.respond_to?(:usage)
      end

      # The hierarchy root this runtime's cgroups live under, or "" for a
      # cgroup collaborator that does not expose one.
      def cgroup_hierarchy_root
        @cgroup.respond_to?(:root) ? @cgroup.root.to_s : ""
      end

      # ----------------------------------------------------------- value shapes

      # Callers name a sandbox or a container by its handle or by its id.
      def reference_id(value)
        value.respond_to?(:id) ? value.id : String(value)
      end

      def container_reference?(value)
        value.respond_to?(:id) && value.class.name.to_s.end_with?("::Container")
      end

      # Hashes, immutable value objects, and nil all convert with #to_h.
      def mapping?(value)
        value.respond_to?(:to_h)
      end

      # ResourceError carries structured cleanup failures; so does any error
      # #preserve_cleanup_errors attached them to.
      def carries_cleanup_errors?(error)
        error.respond_to?(:cleanup_errors)
      end

      # A cleanup failure is reported as an exception or as plain text.
      def reports_message?(value)
        value.respond_to?(:message)
      end

      def byte_source?(value)
        value.respond_to?(:read)
      end

      def byte_sink?(value)
        value.respond_to?(:write)
      end

      # ----------------------------------------------------------- shared helpers

      def normalize_hash(value)
        hash = mapping?(value) ? value.to_h : {}
        hash.each_with_object({}) { |(key, child), normalized| normalized[String(key)] = child }
      end

      def digest(value)
        Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
            source = value.key?(key) ? key : value.keys.find { |candidate| candidate.to_s == key }
            result[key] = canonical(value.fetch(source))
          end
        when Array then value.map { |child| canonical(child) }
        else value
        end
      end

      def immutable(value)
        case value
        when Hash then value.to_h { |key, child| [String(key), immutable(child)] }.freeze
        when Array then value.map { |child| immutable(child) }.freeze
        else value
        end
      end

      def record(event, **payload)
        entry = {"event" => event.to_s, "timestamp" => @clock.call.utc.iso8601(6), **immutable(payload)}.freeze
        @mutex.synchronize { @events << entry }
        entry
      end
    end

    # The support classes retain the native implementation's lexical error
    # constants after their legacy top-level names are hidden.  Hiding only
    # constants that still point at Support keeps common Runtime definitions
    # intact when common code was loaded before this file.
    support_errors = %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired]
    %i[RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      support_class = Native::Support.const_get(name, false)
      support_errors.each do |error_name|
        support_class.const_set(error_name, Native::Support.const_get(error_name, false)) unless support_class.const_defined?(error_name,
                                                                                                                              false)
      end
    end
    %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired
       RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      remove_const(name) if const_defined?(name,
                                           false) && Native::Support.const_defined?(name,
                                                                                    false) && const_get(name,
                                                                                                        false).equal?(Native::Support.const_get(
                                                                                                          name, false
                                                                                                        ))
    end

    NativeRuntime = Native unless const_defined?(:NativeRuntime, false)
    Backend = Native unless const_defined?(:Backend, false)
  end
end
