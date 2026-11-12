# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # The executable the workload runs: resolved, validated and hashed inside
        # the container root.
        class SecurityAdapter
          DEFAULT_EXEC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

          # Resolve a bare program name on PATH.  This runs after pivot_root, so
          # the lookup happens in the container's own filesystem -- the only
          # place it can be done correctly, and the reason the host-side layers
          # pass the name through untouched.
          def resolve_executable(path, search_path = nil)
            value = String(path)
            return value if value.include?("/")

            search = (search_path.to_s.empty? ? DEFAULT_EXEC_PATH : search_path.to_s).split(":")
            resolved = search.filter_map do |directory|
              next if directory.empty?

              candidate = File.join(directory, value)
              candidate if File.file?(candidate) && File.executable?(candidate)
            end.first
            raise EffectError, "exec: #{value.inspect}: executable file not found in $PATH" unless resolved

            resolved
          end

          def validate_executable!(path)
            value = String(path)
            unless value.start_with?("/") && File.file?(value) && File.executable?(value)
              raise EffectError, "workload executable is unavailable: #{value.inspect}"
            end

            true
          rescue SystemCallError => error
            raise EffectError, "workload executable validation failed: #{error.message}"
          end

          # The descriptor directory is opened right after the rootfs exists
          # and before Landlock restricts reads outside the allowed roots; the
          # close step later enumerates it through this descriptor.
          def prepare_fd_directory
            @fd_directory = Dir.open("/proc/self/fd")
            true
          rescue SystemCallError => error
            raise EffectError, "cannot open the descriptor directory: #{error.message}"
          end

          # Open the executable inside the new root and hash the bytes that
          # will be executed.  The descriptor, not the pathname, is what
          # execveat(2) later runs.
          def open_executable(path, search_path = nil)
            path = resolve_executable(path, search_path)
            validate_executable!(path)
            io = File.open(path, File::RDONLY)
            digest = Digest::SHA256.new
            script = nil
            while (chunk = io.read(1024 * 1024))
              script = chunk.start_with?("#!") if script.nil?
              digest.update(chunk)
            end
            io.rewind
            # A "#!" script cannot run through the descriptor: execveat(2) with
            # AT_EMPTY_PATH starts the interpreter on /dev/fd/N, which is ENOENT
            # once the close-on-exec descriptor is gone and, kept open, makes $0
            # "/dev/fd/N" instead of the script path runc would pass.  Scripts
            # are therefore executed by their resolved pathname inside the new
            # root (see WorkloadBootstrap#exec_workload); ELF binaries keep the
            # verified-descriptor exec.  Every image entrypoint that is a shell
            # script (Gitea's init containers, "command: [/script.sh]") failed
            # with ENOENT before this.
            [io, digest.hexdigest, {path: path, script: script == true}]
          rescue SystemCallError => error
            raise EffectError, "workload executable could not be opened: #{error.message}"
          end
        end
      end
    end
  end
end
