# frozen_string_literal: true

require "json"

module Rubernetes
  module Platform
    module Linux
      # A committed wrapper can outlive the agent. Its retained pipes allow a
      # successor to resume the same streams; its exit report substitutes for
      # waitid after the wrapper has been reparented.
      module DurableProcess
        COMMIT = "C"
        STDIN_EOF_SIGNAL = Signal.list.fetch("USR1")

        module_function

        # Helpers report through their own pipes. Redirect descriptors 0–2
        # even when the launcher's Ruby stream globals have been reassigned.
        def redirect_standard_io
          # rubocop:disable Style/GlobalStdStream
          STDIN.reopen(File::NULL, "r")
          STDOUT.reopen(File::NULL, "w")
          STDERR.reopen(File::NULL, "w")
          # rubocop:enable Style/GlobalStdStream
        end

        def capture(pid, streams)
          streams.compact.transform_values do |io|
            stat = io.stat
            {"fd" => io.fileno, "inode" => stat.ino, "device" => stat.dev}
          end.merge("start_time" => birth(pid)).freeze
        end

        def reopen(pid, evidence)
          return {} unless evidence

          expected = Integer(evidence.fetch("start_time"))
          raise ProcessSupervisor::Error, "wrapper identity changed during adoption" unless birth(pid) == expected

          streams = {}
          evidence.each do |name, resource|
            next unless %w[stdin stdout stderr].include?(name)

            io = open_stream(pid, name, resource, stdin_once: evidence["stdin_once"] == true)
            next unless io

            streams[name.to_sym] = io
            stat = io.stat
            unless stat.pipe? && stat.ino == resource.fetch("inode") && stat.dev == resource.fetch("device")
              raise ProcessSupervisor::Error, "wrapper stream #{name} identity changed during adoption"
            end
          end
          raise ProcessSupervisor::Error, "wrapper identity changed during adoption" unless birth(pid) == expected

          streams
        rescue IOError, SystemCallError, ProcessSupervisor::Error
          streams&.each_value(&:close)
          raise
        end

        def open_stream(pid, name, resource, stdin_once:)
          flags = name == "stdin" ? File::WRONLY : File::RDONLY
          File.open("/proc/#{Integer(pid)}/fd/#{Integer(resource.fetch("fd"))}", flags | File::NONBLOCK)
        rescue Errno::ENOENT
          # The exact wrapper may already have closed this single-use pipe.
          raise unless name == "stdin" && stdin_once

          nil
        end

        def publish_exit(path, status)
          return unless path

          File.open(path, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
            file.write(JSON.generate(status))
            file.fsync
          end
        end

        def exit_status(path)
          File.open(path, File::RDONLY | File::NOFOLLOW) { |file| JSON.parse(file.read(1024)) }
        rescue Errno::ENOENT
          nil
        end

        def birth(pid)
          stat = File.read("/proc/#{Integer(pid)}/stat")
          Integer(stat[(stat.rindex(")") + 1)..].split.fetch(19))
        end
      end
    end
  end
end
