# frozen_string_literal: true

# Namespace entry primitives.  The runtime never shells out to nsenter(1) or
# unshare(1): every namespace transition is a direct setns(2)/unshare(2)
# performed by the process that will own the resulting state, so the caller
# can pair each transition with the identity it verified beforehand.

require "fiddle"
require "rbconfig"
require_relative "error"
require_relative "syscall"

module Rubernetes
  module Platform
    module Linux
      class Setns
        class Unsupported < StandardError; end

        # Values from include/uapi/linux/sched.h (CLONE_* namespace flags).
        CLONE_NEWNS = 0x0002_0000
        CLONE_NEWCGROUP = 0x0200_0000
        CLONE_NEWUTS = 0x0400_0000
        CLONE_NEWIPC = 0x0800_0000
        CLONE_NEWUSER = 0x1000_0000
        CLONE_NEWPID = 0x2000_0000
        CLONE_NEWNET = 0x4000_0000

        # Namespace name (as exposed under /proc/<pid>/ns) -> nstype flag.
        NAMESPACE_TYPES = {
          mount: [CLONE_NEWNS, "mnt"],
          uts: [CLONE_NEWUTS, "uts"],
          ipc: [CLONE_NEWIPC, "ipc"],
          user: [CLONE_NEWUSER, "user"],
          pid: [CLONE_NEWPID, "pid"],
          network: [CLONE_NEWNET, "net"],
          cgroup: [CLONE_NEWCGROUP, "cgroup"]
        }.freeze

        # Syscall numbers from arch/x86/entry/syscalls/syscall_64.tbl and
        # include/uapi/asm-generic/unistd.h (arm64).  They are keyed by the
        # host architecture so a manifest for the wrong CPU cannot be applied.
        SYSCALLS = {
          "x86_64" => {setns: 308, unshare: 272},
          "aarch64" => {setns: 268, unshare: 97}
        }.freeze

        def self.architecture
          key = RbConfig::CONFIG.fetch("host_cpu").downcase
          return "x86_64" if %w[x86_64 amd64].include?(key)
          return "aarch64" if %w[aarch64 arm64].include?(key)

          raise Unsupported, "unsupported Linux architecture #{key.inspect}"
        end

        def initialize(architecture: self.class.architecture, proc_root: "/proc")
          @numbers = SYSCALLS.fetch(String(architecture)) do
            raise Unsupported, "setns/unshare numbers are unknown for #{architecture.inspect}"
          end
          @proc_root = File.expand_path(String(proc_root))
        end

        # Open a namespace descriptor and prove that it is the namespace the
        # caller already recorded (the `<name>:[inode]` link text).  A PID can
        # be recycled between the identity read and the open; the link text
        # comparison is the only stable defense.
        def open_namespace(pid:, name:, expected_link: nil, resource_id: "ns:#{pid}:#{name}")
          proc_name = NAMESPACE_TYPES.fetch(name.to_sym) { raise ArgumentError, "unknown namespace #{name.inspect}" }.fetch(1)
          path = File.join(@proc_root, Integer(pid).to_s, "ns", proc_name)
          io = File.open(path, File::RDONLY)
          begin
            actual = File.readlink(path)
            if expected_link && actual != String(expected_link)
              raise Linux::Error.new(errno: Errno::ESTALE::Errno, operation: "open(#{path})", resource_id: resource_id,
                                     details: {expected: expected_link, actual: actual})
            end
            # The link is re-read through the descriptor so the identity that
            # is returned is the identity that will be entered.
            via_fd = File.readlink("/proc/self/fd/#{io.fileno}")
            unless via_fd == actual
              raise Linux::Error.new(errno: Errno::ESTALE::Errno, operation: "readlink(fd)", resource_id: resource_id,
                                     details: {expected: actual, actual: via_fd})
            end
          rescue StandardError
            io.close
            raise
          end
          io
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "open(#{path})", resource_id: resource_id), cause: error
        end

        def setns(fd:, name:, resource_id: "setns:#{name}")
          nstype = NAMESPACE_TYPES.fetch(name.to_sym) { raise ArgumentError, "unknown namespace #{name.inspect}" }.fetch(0)
          descriptor = fd.respond_to?(:fileno) ? fd.fileno : Integer(fd)
          result = Syscall.call(@numbers.fetch(:setns), descriptor, nstype)
          # R-1.1/R-1.2: the errno captured inside Syscall.call belongs to this exact call.
          raise Linux::Error.new(errno: result.errno, operation: "setns(#{name})", resource_id: resource_id) if result.value == -1

          true
        end

        def unshare(flags:, resource_id: "unshare")
          result = Syscall.call(@numbers.fetch(:unshare), Integer(flags))
          if result.value == -1
            raise Linux::Error.new(errno: result.errno, operation: "unshare(0x#{Integer(flags).to_s(16)})",
                                   resource_id: resource_id)
          end

          true
        end

        # Read the namespace link text of a live process without opening it.
        def link(pid:, name:)
          proc_name = NAMESPACE_TYPES.fetch(name.to_sym).fetch(1)
          File.readlink(File.join(@proc_root, Integer(pid).to_s, "ns", proc_name))
        end

        def self.inode(link_text)
          value = String(link_text)[/\[(\d+)\]\z/, 1]
          value && Integer(value)
        end
      end
    end
  end
end
