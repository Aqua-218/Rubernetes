# frozen_string_literal: true

require "io/wait"
require_relative "../platform/linux/pidfd"

module Rubernetes
  module Cluster
    # What a remembered pid still means.  Stateless: `rubectl cluster down`
    # and the conformance tools ask about processes of clusters they did not
    # start.
    module Processes
      module_function

      def terminate(pid, name, marker)
        return nil unless owned?(pid, marker)

        stopped = {"name" => name, "pid" => pid}
        resource = "cluster-process:#{name}:#{pid}"
        probe = Platform::Linux::Pidfd.new
        descriptor = probe.open(pid: pid, resource_id: resource)
        watcher = IO.for_fd(descriptor)
        return stopped unless owned?(pid, marker)

        # Bind both signals to the process we identified. Another process can
        # acquire the same numeric PID while this command waits out TERM.
        probe.send_signal(pidfd: descriptor, signal: Signal.list.fetch("TERM"), resource_id: resource)
        unless watcher.wait_readable(15)
          probe.send_signal(pidfd: descriptor, signal: Signal.list.fetch("KILL"), resource_id: resource)
          raise Error, "could not confirm exit of #{resource}" unless watcher.wait_readable(5)
        end
        reap(probe, descriptor, resource)
        stopped
      rescue Platform::Linux::Error => error
        raise unless error.errno == Errno::ESRCH::Errno

        stopped
      ensure
        watcher&.close
      end

      def reap(probe, descriptor, resource)
        probe.wait(pidfd: descriptor, timeout: 0, resource_id: resource)
      rescue Platform::Linux::Error => error
        raise unless error.errno == Errno::ECHILD::Errno
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
