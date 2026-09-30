# frozen_string_literal: true

# Landlock capability detection and ruleset syscalls.  The adapter does not
# decide which paths a workload may use; callers provide an explicit rights
# set and the operation fails closed when the host cannot enforce it.

require "fiddle"
require "rbconfig"
require_relative "error"
require_relative "syscall"
require_relative "openat2"

module Rubernetes
  module Platform
    module Linux
      class Landlock
        class Error < StandardError; end
        class Unsupported < Error; end

        # Values from include/uapi/linux/landlock.h.
        LANDLOCK_CREATE_RULESET_VERSION = 1
        LANDLOCK_CREATE_RULESET_ERRATA = 1 << 0
        LANDLOCK_RULE_TYPE_PATH_BENEATH = 1
        LANDLOCK_RULE_TYPE_NET_PORT = 2
        ACCESS_FS_EXECUTE = 1 << 0
        ACCESS_FS_WRITE_FILE = 1 << 1
        ACCESS_FS_READ_FILE = 1 << 2
        ACCESS_FS_READ_DIR = 1 << 3
        ACCESS_FS_REMOVE_DIR = 1 << 4
        ACCESS_FS_REMOVE_FILE = 1 << 5
        ACCESS_FS_MAKE_CHAR = 1 << 6
        ACCESS_FS_MAKE_DIR = 1 << 7
        ACCESS_FS_MAKE_REG = 1 << 8
        ACCESS_FS_MAKE_SOCK = 1 << 9
        ACCESS_FS_MAKE_FIFO = 1 << 10
        ACCESS_FS_MAKE_BLOCK = 1 << 11
        ACCESS_FS_MAKE_SYM = 1 << 12
        ACCESS_FS_REFER = 1 << 13
        ACCESS_FS_TRUNCATE = 1 << 14
        ACCESS_FS_ALL = (1 << 15) - 1
        SYS_LANDLOCK_CREATE_RULESET = 444
        SYS_LANDLOCK_ADD_RULE = 445
        SYS_LANDLOCK_RESTRICT_SELF = 446

        Probe = Data.define(:available, :abi_version, :reason, :details) do
          def available?
            available
          end

          def to_h
            {
              "available" => available,
              "abi_version" => abi_version,
              "reason" => reason,
              "details" => details
            }
          end
        end
        Ruleset = Data.define(:fd, :handled_access_fs, :handled_access_net, :identity) do
          def close
            IO.for_fd(fd).close
          end

          def to_i
            fd
          end

          def to_h
            {
              "fd" => fd,
              "handled_access_fs" => handled_access_fs,
              "handled_access_net" => handled_access_net,
              "identity" => identity
            }
          end
        end

        class SystemAdapter
          def initialize(syscall: Syscall)
            @syscall = syscall
          end

          def create_ruleset(handled_access_fs:, handled_access_net:, flags:, resource_id:)
            attributes = Fiddle::Pointer[[
              Integer(handled_access_fs), Integer(handled_access_net), 0
            ].pack("Q<3")]
            result = @syscall.call(SYS_LANDLOCK_CREATE_RULESET, attributes, 24, Integer(flags))
            raise_error(result, "landlock_create_ruleset", resource_id)
          end

          # The VERSION query is explicitly read-only: a NULL attributes
          # pointer and zero size ask the kernel for the highest supported ABI
          # without allocating a ruleset or changing process state.
          def probe
            result = @syscall.call(SYS_LANDLOCK_CREATE_RULESET, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
            raise_error(result, "landlock_create_ruleset", "landlock:probe")
          end

          def add_path_rule(ruleset_fd:, path_fd:, allowed_access:, resource_id:)
            # landlock_path_beneath_attr is u64 + s32 + four bytes padding.
            # In Ruby pack syntax the padding count belongs after x; `l<4x`
            # means four signed longs and therefore demanded too many values.
            rule = Fiddle::Pointer[[Integer(allowed_access), Integer(path_fd)].pack("Q<l<x4")]
            result = @syscall.call(SYS_LANDLOCK_ADD_RULE, Integer(ruleset_fd), LANDLOCK_RULE_TYPE_PATH_BENEATH, rule, 0)
            raise_error(result, "landlock_add_rule", resource_id)
          end

          def restrict_self(ruleset_fd:, resource_id:)
            result = @syscall.call(SYS_LANDLOCK_RESTRICT_SELF, Integer(ruleset_fd), 0)
            raise_error(result, "landlock_restrict_self", resource_id)
          end

          private

          def raise_error(result, operation, resource_id)
            return result.value if result.value != -1

            raise Linux::Error.new(errno: result.errno, operation: operation, resource_id: resource_id)
          end
        end

        def initialize(adapter: SystemAdapter.new, architecture: nil, no_new_privs: nil)
          @adapter = adapter
          @architecture = architecture
          @no_new_privs = no_new_privs
        end

        def probe(required_abi: nil, resource_id: "landlock:probe")
          version = if @adapter.respond_to?(:probe)
                      @adapter.probe
                    elsif @adapter.respond_to?(:version)
                      @adapter.version
                    elsif @adapter.respond_to?(:call)
                      @adapter.call(operation: :probe, resource_id: resource_id)
                    else
                      @adapter.create_ruleset(handled_access_fs: 0, handled_access_net: 0, flags: LANDLOCK_CREATE_RULESET_VERSION,
                                              resource_id: resource_id)
                    end
          version = version.to_h.fetch(:abi_version) { version.to_h.fetch("abi_version") } if version.respond_to?(:to_h)
          version = Integer(version)
          if required_abi && version < Integer(required_abi)
            return Probe.new(available: false, abi_version: version, reason: "Landlock ABI #{version} is below required #{required_abi}",
                             details: {}.freeze)
          end

          Probe.new(available: version.positive?, abi_version: version, reason: nil, details: {"architecture" => architecture}.freeze)
        rescue Linux::Error => error
          Probe.new(available: false, abi_version: nil, reason: "#{error.operation}: #{error.message}", details: error.to_h.freeze)
        rescue SystemCallError, ArgumentError => error
          Probe.new(available: false, abi_version: nil, reason: "#{error.class}: #{error.message}", details: {}.freeze)
        end

        alias capability_probe probe

        def probe!
          result = probe
          raise Unsupported, result.reason || "Landlock is unavailable" unless result.available?

          result
        end

        def create_ruleset(handled_access_fs:, handled_access_net: 0, identity: "landlock:ruleset", resource_id: identity)
          fs_rights = Integer(handled_access_fs)
          net_rights = Integer(handled_access_net)
          raise ArgumentError, "Landlock filesystem rights must be non-negative" if fs_rights.negative? || net_rights.negative?

          fd = if @adapter.respond_to?(:create_ruleset)
                 @adapter.create_ruleset(handled_access_fs: fs_rights, handled_access_net: net_rights, flags: 0, resource_id: resource_id)
               elsif @adapter.respond_to?(:call)
                 @adapter.call(operation: :create_ruleset, handled_access_fs: fs_rights, handled_access_net: net_rights,
                               resource_id: resource_id)
               else
                 raise Unsupported, "Landlock adapter does not expose create_ruleset"
               end
          Ruleset.new(fd: Integer(fd), handled_access_fs: fs_rights, handled_access_net: net_rights, identity: String(identity).freeze)
        end

        def add_path_rule(ruleset, path_fd:, allowed_access:, resource_id: "landlock:path")
          rights = Integer(allowed_access)
          unless (rights & ~ruleset.handled_access_fs).zero?
            raise ArgumentError, "path rights must be a subset of the ruleset handled rights"
          end

          result = if @adapter.respond_to?(:add_path_rule)
                     @adapter.add_path_rule(ruleset_fd: ruleset.fd, path_fd: Integer(path_fd), allowed_access: rights,
                                            resource_id: resource_id)
                   elsif @adapter.respond_to?(:call)
                     @adapter.call(operation: :add_path_rule, ruleset_fd: ruleset.fd, path_fd: Integer(path_fd), allowed_access: rights,
                                   resource_id: resource_id)
                   else
                     raise Unsupported, "Landlock adapter does not expose add_path_rule"
                   end
          [true, 0].include?(result)
        end

        def restrict_self(ruleset, resource_id: "landlock:restrict")
          if @no_new_privs
            if @no_new_privs.respond_to?(:call)
              @no_new_privs.call(resource_id: resource_id)
            elsif @no_new_privs.respond_to?(:set)
              @no_new_privs.set(resource_id: resource_id)
            else
              raise Unsupported, "no_new_privs adapter cannot set the required process state"
            end
          elsif @adapter.respond_to?(:set_no_new_privs)
            @adapter.set_no_new_privs(resource_id: resource_id)
          end
          result = if @adapter.respond_to?(:restrict_self)
                     @adapter.restrict_self(ruleset_fd: ruleset.fd, resource_id: resource_id)
                   elsif @adapter.respond_to?(:call)
                     @adapter.call(operation: :restrict_self, ruleset_fd: ruleset.fd, resource_id: resource_id)
                   else
                     raise Unsupported, "Landlock adapter does not expose restrict_self"
                   end
          [true, 0].include?(result)
        end

        def apply(ruleset, paths:, openat2:, read_only: false, resource_id: "landlock:apply")
          rights = read_only ? ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR : ruleset.handled_access_fs
          paths.each do |path|
            handle = openat2.open(path, flags: Openat2::O_PATH, resource_id: "#{resource_id}:#{path}")
            begin
              add_path_rule(ruleset, path_fd: handle.fd, allowed_access: rights, resource_id: "#{resource_id}:#{path}")
            ensure
              handle.close
            end
          end
          restrict_self(ruleset, resource_id: resource_id)
        end

        private

        def architecture
          value = @architecture || RbConfig::CONFIG.fetch("host_cpu")
          return "x86_64" if %w[x86_64 amd64].include?(value)
          return "aarch64" if %w[aarch64 arm64].include?(value)

          value
        end
      end
    end
  end
end
