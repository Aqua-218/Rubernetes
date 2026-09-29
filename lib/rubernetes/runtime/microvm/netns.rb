# frozen_string_literal: true

require "fileutils"
require "socket"

require_relative "errors"
require_relative "../../platform/linux/setns"
require_relative "../../platform/linux/mount"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Persistent network namespaces for microVMs: a child unshares
      # CLONE_NEWNET, the parent bind-mounts /proc/<child>/ns/net to a file
      # under the namespace root so the jailer (--netns) and the network
      # layer can enter it after the child has exited.  The file's inode is
      # the stable identity recorded in the resource ledger.
      class Netns
        CLONE_NEWNET = 0x40000000
        MS_BIND = 4096
        MNT_DETACH = 2

        Handle = Struct.new(:name, :path, :inode, keyword_init: true) do
          def to_h
            {"name" => name, "path" => path, "inode" => inode}
          end
        end

        def initialize(root: "/run/rubernetes/netns")
          @root = root
        end

        attr_reader :root

        def create(name)
          validate_name!(name)
          FileUtils.mkdir_p(@root, mode: 0o700)
          path = File.join(@root, name)
          raise NetworkError, "network namespace #{name} already exists" if File.exist?(path)

          File.write(path, "")
          reader, writer = IO.pipe
          pid = Process.fork do
            reader.close
            unshare_network!
            writer.write("ready")
            writer.close
            sleep 3600
          end
          writer.close
          raise NetworkError, "network namespace holder failed to start" unless reader.read == "ready"

          mount_bind("/proc/#{pid}/ns/net", path)
          Handle.new(name: name, path: path, inode: File.stat(path).ino)
        rescue StandardError
          File.delete(path) if File.exist?(path) && !mounted?(path)
          raise
        ensure
          reader&.close
          if pid
            Process.kill("KILL", pid)
            Process.wait(pid)
          end
        end

        def destroy(name)
          validate_name!(name)
          path = File.join(@root, name)
          return false unless File.exist?(path)

          umount(path) if mounted?(path)
          File.delete(path)
          true
        end

        def handle(name)
          validate_name!(name)
          path = File.join(@root, name)
          return nil unless File.exist?(path)

          Handle.new(name: name, path: path, inode: File.stat(path).ino)
        end

        def list
          return [] unless File.directory?(@root)

          Dir.children(@root).sort.filter_map { |name| handle(name) }
        end

        # Runs the block inside the namespace (in a forked child so the
        # caller's namespace never changes); returns the block's result
        # marshalled back.  Exceptions are re-raised in the parent.
        def within(name)
          path = File.join(@root, name)
          raise NetworkError, "network namespace #{name} does not exist" unless File.exist?(path)

          reader, writer = IO.pipe
          pid = Process.fork do
            reader.close
            begin
              fd = File.open(path, File::RDONLY)
              Platform::Linux::Setns.new.setns(fd: fd, name: :network)
              result = yield
              writer.write(Marshal.dump(["ok", result]))
            rescue Exception => error # rubocop:disable Lint/RescueException
              writer.write(Marshal.dump(["error", error.class.name, error.message]))
            ensure
              writer.close
            end
            exit!(0)
          end
          writer.close
          payload = reader.read
          Process.wait(pid)
          status, *rest = Marshal.load(payload)
          raise NetworkError, "#{rest[0]}: #{rest[1]}" if status == "error"

          rest.first
        ensure
          reader&.close
        end

        private

        def unshare_network!
          Platform::Linux::Setns.new.unshare(flags: CLONE_NEWNET)
          # bring loopback up inside the new namespace
          Tap.set_flags("lo") { |flags| flags | Tap::IFF_UP }
        end

        def mount_bind(source, target)
          Platform::Linux::Mount.new.mount(source: source, target: target, filesystem: nil, flags: MS_BIND, data: nil)
        rescue StandardError => error
          raise NetworkError, "cannot bind network namespace #{source} to #{target}: #{error.message}"
        end

        def umount(path)
          Platform::Linux::Mount.new.unmount(target: path, flags: MNT_DETACH)
        rescue StandardError => error
          raise NetworkError, "cannot unmount network namespace #{path}: #{error.message}"
        end

        def mounted?(path)
          File.read("/proc/self/mountinfo").lines.any? { |line| line.split(" ")[4] == path }
        end

        def validate_name!(name)
          raise NetworkError, "invalid network namespace name #{name.inspect}" unless name.is_a?(String) && name.match?(/\A[a-zA-Z0-9_.-]{1,64}\z/)
        end
      end
    end
  end
end
