# frozen_string_literal: true

require "fileutils"
require "json"
require "tempfile"
require_relative "../../platform/linux/openat2"
require_relative "../../platform/linux/process_supervisor"

module Rubernetes
  module Runtime
    class Native
      # The host kubelet's CRI log view of the native runtime's process pipes.
      # The private raw log remains the source for the Pod log API. The
      # descriptor in its process directory also survives supervisor adoption.
      class PodLogFiles
        Rotator = Platform::Linux::ProcessSupervisor::LogRotator
        COMPONENT = /\A[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\z/
        PROCESS_NAME = /\A[A-Za-z0-9][A-Za-z0-9_.-]*\z/
        DESCRIPTOR = "pod-log.json"
        ROOT = "/var/log/pods"
        LEGACY = "/var/log/containers"

        def self.install(runtime, **paths)
          supervisor = runtime.process_supervisor
          return unless supervisor.is_a?(Platform::Linux::ProcessSupervisor)

          files = new(runtime.config.log_root, max_bytes: runtime.config.max_log_bytes, max_files: runtime.config.max_log_files, **paths)
          runtime.extend(RuntimeHooks).pod_log_files = files
          supervisor.extend(ProcessHooks).pod_log_files = files
        end

        def initialize(spool, max_bytes:, max_files:, pod_root: ROOT, legacy_root: LEGACY, clock: -> { Time.now.utc })
          @spool = spool
          @pod_root = pod_root
          @legacy_root = legacy_root
          @max_bytes = max_bytes
          @max_files = max_files
          @clock = clock
          @mutex = Mutex.new
          @locks = {}
        end

        def prepare(key, metadata, name, id)
          namespace, pod, uid = metadata.values_at("namespace", "name", "uid")
          return unless PROCESS_NAME.match?(key) && [namespace, pod, uid, name].all? { |part| COMPONENT.match?(part.to_s) }

          @mutex.synchronize do
            return if read_descriptor(key)

            components = ["#{namespace}_#{pod}_#{uid}", name]
            with_container_directory(components, create: true) do |directory|
              filename = allocate_attempt(directory)
              legacy = "#{pod}_#{namespace}_#{name}-#{id}".byteslice(0, 251) + ".log"
              descriptor = {"directory" => components, "file" => filename, "legacy" => legacy,
                            "identity" => [directory.stat.dev, directory.stat.ino], "shared_combined" => true}
              write_descriptor(key, descriptor)
              registered = true
              add_legacy_link(descriptor)
              true
            rescue StandardError
              File.unlink(File.join(fd_path(directory), filename)) if filename && !registered
              raise
            end
          end
        end

        def shared_combined?(key)
          read_descriptor(key)&.fetch("shared_combined", false) == true
        end

        def with_writer(key)
          descriptor = read_descriptor(key)
          return yield unless descriptor

          lock = @mutex.synchronize { @locks[key] ||= Mutex.new }
          lock.synchronize do
            directory = verified_directory(descriptor)
            return yield unless directory

            path = File.join(fd_path(directory), descriptor.fetch("file"))
            return yield unless regular_log_file?(path)

            rotator = Rotator.new(path: path, max_bytes: @max_bytes, max_files: @max_files, create_directory: false)
            yield Writer.new(rotator, @clock)
          ensure
            directory&.close
          end
        end

        def remove(key)
          descriptor = read_descriptor(key)
          return unless descriptor

          @mutex.synchronize do
            lock = @locks[key] ||= Mutex.new
            lock.synchronize do
              remove_legacy_link(descriptor)
              remove_attempt_files(descriptor)
            end
            @locks.delete(key)
          end
        end

        private

        def regular_log_file?(path)
          File.lstat(path).file?
        rescue SystemCallError
          false
        end

        def remove_attempt_files(descriptor)
          directory = verified_directory(descriptor)
          return unless directory

          name = descriptor.fetch("file")
          rotated = /\A#{Regexp.escape(name)}\.\d+\z/
          Dir.each_child(fd_path(directory)) do |entry|
            File.unlink(File.join(fd_path(directory), entry)) if entry == name || rotated.match?(entry)
          rescue Errno::ENOENT
            next
          end
          remove_empty_parents(descriptor)
        ensure
          directory&.close
        end

        def open_directory(path, create: false)
          begin
            Dir.mkdir(path, 0o755) if create
          rescue Errno::EEXIST
            nil
          end
          directory = File.open(path, File::RDONLY | File::NOFOLLOW | Platform::Linux::Openat2::O_DIRECTORY)
          return directory if directory.stat.uid == Process.euid && directory.stat.mode.nobits?(0o022)

          directory.close
          raise Errno::EACCES, path
        end

        def with_container_directory(components, create: false)
          FileUtils.mkdir_p(@pod_root) if create
          root = open_directory(@pod_root)
          pod = open_directory(File.join(fd_path(root), components.fetch(0)), create: create)
          directory = open_directory(File.join(fd_path(pod), components.fetch(1)), create: create)
          yield directory
        ensure
          [directory, pod, root].compact.each(&:close)
        end

        def verified_directory(descriptor)
          with_container_directory(descriptor.fetch("directory")) do |directory|
            directory.dup if [directory.stat.dev, directory.stat.ino] == descriptor.fetch("identity")
          end
        rescue SystemCallError
          nil
        end

        def allocate_attempt(directory)
          root = fd_path(directory)
          attempts = Dir.each_child(root).filter_map { |name| Integer(name[/\A(\d+)\.log\z/, 1], exception: false) }
          name = "#{(attempts.max || -1) + 1}.log"
          File.open(File.join(root, name), File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o640, &:close)
          name
        end

        def add_legacy_link(descriptor)
          FileUtils.mkdir_p(@legacy_root)
          open_directory(@legacy_root).tap do |root|
            File.symlink(target_path(descriptor), File.join(fd_path(root), descriptor.fetch("legacy")))
          ensure
            root.close
          end
        end

        def remove_legacy_link(descriptor)
          open_directory(@legacy_root).tap do |root|
            path = File.join(fd_path(root), descriptor.fetch("legacy"))
            File.unlink(path) if File.readlink(path) == target_path(descriptor)
          ensure
            root.close
          end
        rescue Errno::ENOENT, Errno::EINVAL
          nil
        end

        def remove_empty_parents(descriptor)
          parts = descriptor.fetch("directory")
          directory = File.join(@pod_root, *parts)
          [directory, File.dirname(directory)].each do |path|
            Dir.rmdir(path)
          rescue Errno::ENOENT, Errno::ENOTEMPTY, Errno::EEXIST
            break
          end
        end

        def descriptor_path(key) = File.join(@spool, key, DESCRIPTOR)
        def target_path(descriptor) = File.join(@pod_root, *descriptor.fetch("directory"), descriptor.fetch("file"))
        def fd_path(io) = "/proc/self/fd/#{io.fileno}"

        def write_descriptor(key, value)
          path = descriptor_path(key)
          Tempfile.create([".pod-log-", ".json"], File.dirname(path)) do |file|
            file.write(JSON.generate(value))
            file.flush
            File.link(file.path, path)
          end
        end

        def read_descriptor(key)
          return unless PROCESS_NAME.match?(key)

          value = File.open(descriptor_path(key), File::RDONLY | File::NOFOLLOW) { |file| JSON.parse(file.read) }
          return unless value.is_a?(Hash)

          directory, file, legacy, identity = value.values_at("directory", "file", "legacy", "identity")
          return unless directory.is_a?(Array) && directory.length == 2 && directory.all? { |name| name.is_a?(String) && PROCESS_NAME.match?(name) }
          return unless /\A\d+\.log\z/.match?(file.to_s) && /\A[a-z0-9][a-zA-Z0-9_.-]*\.log\z/.match?(legacy.to_s)

          value if identity.is_a?(Array) && identity.size == 2 && identity.all?(Integer)
        rescue SystemCallError, JSON::ParserError
          nil
        end
      end
    end
  end
end

require_relative "pod_log_files/hooks"
require_relative "pod_log_files/writer"
require_relative "pod_log_files/combined_log"
