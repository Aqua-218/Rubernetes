#!/usr/local/bin/ruby
# frozen_string_literal: true

# Guest PID 1 entry point.  The rootfs is read-only (dm-verity on the
# host side); everything writable lives on tmpfs or the injected
# workspace.  Failures here are fatal for the VM: the host observes the
# missing hello and never opens the workload gate.
require "English"
$LOAD_PATH.unshift("/opt/rubernetes/lib")
$LOAD_PATH.unshift("/opt/rubernetes/ext")

require "rubernetes/runtime"
require "rubernetes/runtime/microvm/guest/supervisor"

$stdout.sync = true
ENV["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV["HOME"] = "/root"
# PID 1 stays a minimal orphan reaper; the supervisor runs as its child so
# the Native backend inside the guest owns the wait status of its helpers.
supervisor = Process.fork do
  Rubernetes::Runtime::MicroVM::Guest::Supervisor.new(prepare_filesystem: true).run!
rescue Exception => error # rubocop:disable Lint/RescueException
  warn "[rubernetes-guest] fatal: #{error.class}: #{error.message}\n#{error.backtrace.first(10).join("\n")}"
  exit!(1)
end
loop do
  pid = Process.wait(-1)
  if pid == supervisor
    warn "[rubernetes-guest] supervisor exited (#{$CHILD_STATUS.inspect}); halting"
    sleep 2
    exit 1
  end
rescue Errno::ECHILD
  sleep 0.5
end
