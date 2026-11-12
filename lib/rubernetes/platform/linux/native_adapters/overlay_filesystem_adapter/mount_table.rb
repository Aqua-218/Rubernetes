# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Readback of the holder's mount table: the proof that the overlay is,
        # or is no longer, mounted at the workspace root.
        class OverlayFilesystemAdapter
          private

          # A successful mount(2) return only proves that the syscall was
          # accepted.  Read the target namespace's mount table and require an
          # OverlayFS entry for the exact target before recording ownership.
          def mount_readback(namespace_handle, target)
            pid = namespace_handle.pid
            raise EffectError, "overlay mount readback requires a namespace holder pid" unless pid

            line = mountinfo_for(pid, target)
            raise EffectError, "overlay mount was not observed at #{target}" unless line

            separator = line.split(" - ", 2)
            filesystem = separator.fetch(1, "").split.first
            raise EffectError, "mount at #{target} is not OverlayFS" unless filesystem == "overlay"

            fields = separator.fetch(0).split
            {
              "mount_id" => Integer(fields.fetch(0)),
              "parent_id" => Integer(fields.fetch(1)),
              "root" => unescape_mountinfo(fields.fetch(3)),
              "mountpoint" => unescape_mountinfo(fields.fetch(4)),
              "filesystem" => filesystem,
              "super_options" => separator.fetch(1).split(" ", 3).fetch(2, "")
            }.freeze
          rescue KeyError, ArgumentError => error
            raise EffectError, "overlay mount readback was malformed: #{error.message}"
          rescue SystemCallError => error
            raise EffectError, "overlay mount readback failed: #{error.message}"
          end

          def mount_present?(namespace_handle, target)
            pid = namespace_handle.pid
            pid && !mountinfo_for(pid, target).nil?
          rescue SystemCallError
            false
          end

          def mountinfo_for(pid, target)
            escaped = String(target).gsub("\\", "\\134").gsub(" ", "\\040").gsub("\t", "\\011")
            File.readlines("/proc/#{Integer(pid)}/mountinfo", chomp: true).find do |line|
              line.split.fetch(4, nil) == escaped
            end
          end

          def unescape_mountinfo(value)
            String(value).gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
          end

          def same_mount_identity?(left, right)
            left.is_a?(Hash) && right.is_a?(Hash) &&
              left["mount_id"].to_i == right["mount_id"].to_i &&
              left["mountpoint"].to_s == right["mountpoint"].to_s &&
              left["filesystem"].to_s == right["filesystem"].to_s
          end
        end
      end
    end
  end
end
