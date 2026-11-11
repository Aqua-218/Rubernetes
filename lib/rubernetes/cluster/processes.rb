# frozen_string_literal: true

module Rubernetes
  module Cluster
    # What a remembered pid still means.  Stateless: `rubectl cluster down`
    # and the conformance tools ask about processes of clusters they did not
    # start.
    module Processes
      module_function

      def terminate(pid, name, marker)
        return nil unless owned?(pid, marker)

        Process.kill("TERM", pid)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
        sleep(0.05) while alive?(pid) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        Process.kill("KILL", pid) if alive?(pid)
        begin
          Process.waitpid(pid, Process::WNOHANG)
        rescue Errno::ECHILD, Errno::ESRCH
          nil
        end
        {"name" => name, "pid" => pid}
      end

      # A child this process has not reaped yet still answers kill(0); it
      # is a zombie, not a running component (an `up` that fails and tears
      # its own children down otherwise waits the full grace period for
      # each of them).
      def alive?(pid)
        Process.kill(0, pid)
        state = File.binread("/proc/#{pid}/stat").split(") ").last.to_s[0]
        state != "Z"
      rescue Errno::ESRCH, Errno::EPERM
        false
      rescue SystemCallError, IOError
        true
      end

      # A pid remembered in cluster.json or a pid file outlives the process:
      # after a reboot (or once the counter wraps) the same number belongs to
      # whatever happens to run now.  Treating it as ours made `start` refuse
      # a cluster that was down and would have had `down` TERMinate a
      # stranger.  Ours carry their configuration path (or at least their
      # cluster directory) on the command line.
      def owned?(pid, marker)
        return false unless alive?(pid)

        File.binread("/proc/#{pid}/cmdline").split("\0").any? { |argument| argument.start_with?(marker) }
      rescue SystemCallError, IOError
        false
      end

      # ------------------------------------------------------------- readiness
    end
  end
end
