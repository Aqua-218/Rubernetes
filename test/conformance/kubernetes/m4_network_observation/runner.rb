#!/usr/bin/env ruby
# frozen_string_literal: true

# Independent M4 network observation runner.
#
# The M4 gate accepts network evidence only when the observed network
# namespace is still alive while the gate runs: the namespace keeper and the
# runner process that owns it must both exist with the recorded PIDs and
# start times, every kernel object must be re-readable through rtnetlink in
# that namespace, and the packet trace must be a real capture whose bytes are
# copied into the evidence bundle.
#
# This runner therefore detaches a long-lived daemon (the "runner" of record)
# that:
#   1. spawns a keeper child holding a fresh network namespace,
#   2. wires a veth pair between the daemon namespace and the keeper namespace
#      with iproute2 (independent of Rubernetes' netlink writer),
#   3. captures the traffic it generates (tcpdump inside the keeper namespace)
#      into a pcap that survives until the daemon exits,
#   4. reads back every kernel object of the keeper namespace through the
#      native rtnetlink observer and binds it to the namespace identity,
#   5. answers the probe on stdout and then stays alive (holding the veth,
#      the pcap, and the keeper) until its TTL expires or it is killed.
#
# Request (stdin): {"scenario", "required_families", "required_observations"}.
# Cleanup of leftover daemons: ruby runner.rb --reap

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "socket"
require "time"

ROOT = File.expand_path("../../../..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
require "rubernetes/network"
require "rubernetes/platform/linux/pidfd"

module M4NetworkObservationRunner
  RUNNER_PATH = File.expand_path(__FILE__)
  IMPLEMENTATION = "iproute2 wiring + tcpdump capture + native rtnetlink readback in a live keeper namespace"
  STATE_ROOT = "/tmp/rubernetes-m4-network-observation"
  DEFAULT_TTL_SECONDS = 6 * 60 * 60
  REQUIRED_FAMILIES = %w[ipv4 ipv6 dual_stack].freeze
  HOST_V4 = "10.253.7.1"
  POD_V4 = "10.253.7.2"
  V4_PREFIX = 30
  HOST_V6 = "fd00:253:7::1"
  POD_V6 = "fd00:253:7::2"
  V6_PREFIX = 64

  module_function

  def canonical(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        original = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical(value.fetch(original))
      end
    when Array then value.map { |child| canonical(child) }
    when Symbol then value.to_s
    else value
    end
  end

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
  end

  def iso8601_now
    Time.now.utc.iso8601(6)
  end

  # Set by the TERM trap of a detached daemon; Daemon#hold polls it so a
  # reap request ends the hold promptly and runs the normal cleanup path.
  def request_terminate!
    @terminate = true
  end

  def terminate_requested?
    @terminate == true
  end

  def proc_start_time_ticks(pid)
    value = File.binread("/proc/#{Integer(pid)}/stat", 16 * 1024)
    closing = value.rindex(")")
    Integer(value.byteslice(closing + 2..).to_s.split.fetch(19))
  end

  def run_command(*command, allow_failure: false, timeout: 60)
    stdout, stderr, status = Open3.capture3(*command)
    raise "#{command.join(" ")} failed (#{status.exitstatus}): #{stderr.strip}" unless status.success? || allow_failure

    [stdout, stderr, status]
  end

  def in_namespace(pid, *command)
    ["nsenter", "--net=/proc/#{Integer(pid)}/ns/net", "--", *command]
  end

  def pcap_packet_count(path)
    bytes = File.binread(path)
    return 0 if bytes.bytesize < 24

    magic = bytes.byteslice(0, 4).unpack1("L<")
    little = [0xA1B2C3D4, 0xA1B23C4D].include?(magic)
    raise "unsupported pcap magic 0x#{magic.to_s(16)}" unless little || [0xD4C3B2A1, 0x4D3CB2A1].include?(magic)

    format = little ? "L<" : "L>"
    offset = 24
    count = 0
    while offset + 16 <= bytes.bytesize
      captured = bytes.byteslice(offset + 8, 4).unpack1(format)
      offset += 16 + captured
      break if offset > bytes.bytesize

      count += 1
    end
    count
  end

  # The native observer only enters a namespace through a verified lease
  # (pidfd-bound holder identity); the same lease shape the gate uses.
  def with_namespace_lease(pid, path, inode)
    pidfd = Rubernetes::Platform::Linux::Pidfd.new.open(pid: pid, resource_id: "m4-network-observation:#{pid}")
    lease = Rubernetes::Network::Netlink::NamespaceLease.open(
      "handle" => "m4-network-observation:#{pid}", "path" => path, "inode" => inode,
      "pid" => pid, "pidfd" => pidfd, "start_time" => proc_start_time_ticks(pid)
    )
    yield lease
  ensure
    lease&.close
    begin
      IO.for_fd(pidfd).close if pidfd
    rescue IOError, SystemCallError
      nil
    end
  end

  # ------------------------------------------------------------ daemon --

  class Daemon
    def initialize(request, ttl:)
      @request = request
      @ttl = ttl
      @errors = []
      @keeper_pid = nil
      @host_link = nil
      @directory = nil
    end

    def observe
      started_at = M4NetworkObservationRunner.iso8601_now
      @directory = File.join(STATE_ROOT, Process.pid.to_s)
      FileUtils.mkdir_p(@directory)
      FileUtils.mkdir_p(STATE_ROOT)
      File.binwrite(File.join(STATE_ROOT, "#{Process.pid}.json"),
                    JSON.generate("pid" => Process.pid, "start_time_ticks" => M4NetworkObservationRunner.proc_start_time_ticks(Process.pid),
                                  "started_at" => started_at, "ttl_seconds" => @ttl))
      spawn_keeper!
      keeper = keeper_identity
      netns = namespace_identity(keeper)
      wire_namespace!
      packet = capture_traffic!
      objects = kernel_objects(netns)
      families = observed_families(objects)
      REQUIRED_FAMILIES.each do |family|
        @errors << "address family #{family} is not present in the keeper namespace" unless families.fetch(family)
      end
      finished_at = M4NetworkObservationRunner.iso8601_now
      runner = {
        "runner_sha256" => Digest::SHA256.file(RUNNER_PATH).hexdigest,
        "command" => [RbConfig.ruby, RUNNER_PATH.delete_prefix("#{ROOT}/")] + ARGV,
        "argv" => [RbConfig.ruby, RUNNER_PATH] + ARGV,
        "process_id" => Process.pid,
        "start_time_ticks" => M4NetworkObservationRunner.proc_start_time_ticks(Process.pid),
        "mode" => "external", "self_comparison" => false, "implementation" => IMPLEMENTATION,
        "started_at" => started_at, "finished_at" => finished_at,
        "keeper_pid" => keeper.fetch("pid"), "keeper_start_time_ticks" => keeper.fetch("start_time_ticks"),
        "keeper_identity_sha256" => keeper.fetch("identity_sha256"),
        "ttl_seconds" => @ttl, "state_directory" => @directory
      }
      {
        "schema_version" => 1, "suite" => "m4-network-observation", "scenario" => @request["scenario"],
        "executed" => true, "runner" => runner, "runner_sha256" => runner.fetch("runner_sha256"),
        "request_sha256" => M4NetworkObservationRunner.digest(@request),
        "netns" => netns.merge("keeper" => keeper), "keeper" => keeper,
        "kernel_objects" => objects, "packet_trace" => packet,
        "address_families" => families, "measurement_source" => "external_kernel_observation",
        "kernel_backed" => true, "errors" => @errors, "failure_count" => @errors.length, "passed" => @errors.empty?
      }
    end

    def hold
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @ttl
      while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        break unless keeper_alive?
        break if M4NetworkObservationRunner.terminate_requested?

        sleep 0.5
      end
    ensure
      cleanup
    end

    def cleanup
      if @keeper_pid
        begin
          Process.kill("KILL", @keeper_pid)
          Process.waitpid(@keeper_pid)
        rescue Errno::ESRCH, Errno::ECHILD
          nil
        end
      end
      M4NetworkObservationRunner.run_command("ip", "link", "delete", @host_link, allow_failure: true) if @host_link
      FileUtils.rm_rf(@directory) if @directory
      FileUtils.rm_f(File.join(STATE_ROOT, "#{Process.pid}.json"))
    end

    private

    def keeper_alive?
      return false unless @keeper_pid

      Process.waitpid(@keeper_pid, Process::WNOHANG).nil?
    rescue Errno::ECHILD
      false
    end

    # The keeper is a direct child of the daemon (the gate requires the keeper
    # to be the runner or a runner descendant) holding a fresh netns.
    def spawn_keeper!
      @keeper_pid = Process.spawn("unshare", "--net", "--", "sleep", (@ttl + 60).to_s, in: File::NULL, out: File::NULL, err: File::NULL)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      host_inode = File.stat("/proc/self/ns/net").ino
      loop do
        inode = begin
          File.stat("/proc/#{@keeper_pid}/ns/net").ino
        rescue Errno::ENOENT
          nil
        end
        break if inode && inode != host_inode
        raise "keeper did not enter a private network namespace" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.02
      end
    end

    def keeper_identity
      path = "/proc/#{@keeper_pid}/ns/net"
      identity = {
        "path" => path, "pid" => @keeper_pid, "runner_pid" => Process.pid,
        "start_time_ticks" => M4NetworkObservationRunner.proc_start_time_ticks(@keeper_pid),
        "netns_inode" => File.stat(path).ino
      }
      identity.merge("identity" => identity.dup, "identity_sha256" => M4NetworkObservationRunner.digest(identity))
    end

    def namespace_identity(keeper)
      identity = {
        "path" => keeper.fetch("path"), "pid" => keeper.fetch("pid"), "runner_pid" => Process.pid,
        "start_time_ticks" => keeper.fetch("start_time_ticks"), "inode" => keeper.fetch("netns_inode"),
        "keeper_identity_sha256" => keeper.fetch("identity_sha256")
      }
      {
        "path" => keeper.fetch("path"), "pid" => keeper.fetch("pid"), "inode" => keeper.fetch("netns_inode"),
        "start_time_ticks" => keeper.fetch("start_time_ticks"), "runner_pid" => Process.pid,
        "identity" => identity, "identity_sha256" => M4NetworkObservationRunner.digest(identity)
      }
    end

    def wire_namespace!
      suffix = Process.pid.to_s(36)
      @host_link = "m4no#{suffix}"[0, 15]
      pod_link = "eth0"
      run = ->(*command) { M4NetworkObservationRunner.run_command(*command) }
      run.call("ip", "link", "add", @host_link, "type", "veth", "peer", "name", pod_link, "netns", @keeper_pid.to_s)
      run.call("ip", "addr", "add", "#{HOST_V4}/#{V4_PREFIX}", "dev", @host_link)
      run.call("ip", "-6", "addr", "add", "#{HOST_V6}/#{V6_PREFIX}", "dev", @host_link, "nodad")
      run.call("ip", "link", "set", @host_link, "up")
      run.call(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "link", "set", "lo", "up"))
      run.call(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "addr", "add", "#{POD_V4}/#{V4_PREFIX}", "dev", pod_link))
      run.call(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "-6", "addr", "add", "#{POD_V6}/#{V6_PREFIX}", "dev", pod_link, "nodad"))
      run.call(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "link", "set", pod_link, "up"))
      run.call(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "route", "add", "default", "via", HOST_V4, "dev", pod_link))
      run.call(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "-6", "route", "add", "default", "via", HOST_V6, "dev", pod_link))
      # IPv6 link-local addresses finish duplicate address detection
      # asynchronously; wait until nothing is tentative so the readback is
      # the steady state the gate will observe later.
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      loop do
        stdout, = M4NetworkObservationRunner.run_command(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "-6", "addr", "show", "dev", pod_link))
        break unless stdout.include?("tentative")
        raise "IPv6 duplicate address detection did not finish" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.1
      end
    end

    def capture_traffic!
      pcap_path = File.join(@directory, "network.pcap")
      log_path = File.join(@directory, "tcpdump.log")
      command = M4NetworkObservationRunner.in_namespace(@keeper_pid, "tcpdump", "--immediate-mode", "-U", "-n", "-i", "eth0",
                                                        "-w", pcap_path, "icmp or icmp6 or tcp")
      pid = Process.spawn(*command, in: File::NULL, out: File::NULL, err: log_path)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      until File.file?(pcap_path) && File.size(pcap_path) >= 24
        raise "tcpdump did not start: #{File.file?(log_path) ? File.binread(log_path).strip : "no log"}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.05
      end
      sleep 0.2
      results = {}
      results["ipv4_ping"] = M4NetworkObservationRunner.run_command(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ping", "-c", "2", "-W", "2", HOST_V4), allow_failure: true)[2].success?
      results["ipv6_ping"] = M4NetworkObservationRunner.run_command(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ping", "-6", "-c", "2", "-W", "2", HOST_V6), allow_failure: true)[2].success?
      results["ipv4_tcp"] = tcp_exchange(HOST_V4, Socket::AF_INET)
      results["ipv6_tcp"] = tcp_exchange(HOST_V6, Socket::AF_INET6)
      results.each { |name, passed| @errors << "traffic case #{name} failed inside the keeper namespace" unless passed }
      sleep 0.3
      begin
        Process.kill("INT", pid)
        Process.waitpid(pid)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
      # The traffic left neighbour cache entries whose state decays over time;
      # flush them so the namespace readback below is the steady state the
      # gate re-reads later.
      M4NetworkObservationRunner.run_command(*M4NetworkObservationRunner.in_namespace(@keeper_pid, "ip", "neigh", "flush", "dev", "eth0"), allow_failure: true)
      M4NetworkObservationRunner.run_command("ip", "neigh", "flush", "dev", @host_link, allow_failure: true)
      count = M4NetworkObservationRunner.pcap_packet_count(pcap_path)
      @errors << "packet capture is empty" unless count.positive?
      {
        "format" => "pcap", "path" => pcap_path, "capture_path" => pcap_path,
        "sha256" => Digest::SHA256.file(pcap_path).hexdigest, "bytes" => File.size(pcap_path),
        "packet_count" => count, "command" => command, "interface" => "eth0",
        "namespace_path" => "/proc/#{@keeper_pid}/ns/net", "traffic" => results
      }
    end

    # A TCP exchange from the keeper namespace to a listener in the daemon
    # namespace: the listener runs here, the client runs via nsenter.
    def tcp_exchange(address, family)
      server = TCPServer.new(address, 0)
      port = server.addr[1]
      payload = "m4-network-observation-#{Process.pid}"
      client = Thread.new do
        M4NetworkObservationRunner.run_command(*M4NetworkObservationRunner.in_namespace(@keeper_pid, RbConfig.ruby, "-rsocket", "-e",
                                                                                            "s = TCPSocket.new(ARGV[0], Integer(ARGV[1])); s.write(ARGV[2]); s.close_write; print s.read; s.close",
                                                                                            address, port.to_s, payload), allow_failure: true)
      end
      connection = nil
      begin
        ready = IO.select([server], nil, nil, 5)
        return false unless ready

        connection = server.accept
        received = connection.read
        connection.write(received)
        connection.close
        stdout, = client.value
        received == payload && stdout == payload
      ensure
        connection&.close unless connection&.closed?
        server.close
        client.join(5)
      end
    rescue SystemCallError => error
      @errors << "tcp exchange over #{address} failed: #{error.message}"
      false
    end

    def kernel_objects(netns)
      observer = Rubernetes::Network::NativeObserver.new
      raise "native rtnetlink observer is unavailable" unless observer.external_observer?

      resources = M4NetworkObservationRunner.with_namespace_lease(netns.fetch("pid"), netns.fetch("path"), netns.fetch("inode")) do |lease|
        observer.resources(namespace_fd: lease.fileno)
      end
      namespace_resource = {
        "kind" => "netns", "id" => "netns:#{netns.fetch("inode")}", "identity" => netns.fetch("identity"),
        "owner" => "procfs-observer", "state" => "observed",
        "metadata" => {"netns_inode" => netns.fetch("inode"), "pid" => netns.fetch("pid"),
                       "start_time_ticks" => netns.fetch("start_time_ticks"), "path" => netns.fetch("path")}
      }
      [namespace_resource, *resources].map do |resource|
        resource = M4NetworkObservationRunner.canonical(resource)
        {
          "kind" => resource.fetch("kind"), "id" => resource.fetch("id"), "observed" => true,
          "netns_inode" => netns.fetch("inode"), "netns_identity_sha256" => netns.fetch("identity_sha256"),
          "readback" => resource, "readback_sha256" => M4NetworkObservationRunner.digest(resource),
          "identity" => resource.fetch("identity"), "identity_sha256" => M4NetworkObservationRunner.digest(resource.fetch("identity")),
          "ifindex" => resource.dig("metadata", "ifindex"), "owner" => resource["owner"], "state" => resource["state"]
        }
      end
    end

    def observed_families(objects)
      addresses = objects.select { |object| object["kind"] == "address" }.map { |object| object.dig("readback", "metadata", "family") }
      ipv4 = addresses.include?("ipv4")
      ipv6 = addresses.include?("ipv6")
      {"ipv4" => ipv4, "ipv6" => ipv6, "dual_stack" => ipv4 && ipv6}
    end
  end

  # -------------------------------------------------------------- entry --

  REAP_GRACE_SECONDS = 15

  # Terminate every recorded daemon (TERM, then KILL of its session after the
  # grace period), remove its state, and sweep host-side veth links that a
  # killed daemon could not delete.  Two live observations would otherwise
  # both hold 10.253.7.1/30 on the host and break IPv4 for each other.
  def reap
    removed = []
    killed = []
    Dir.glob(File.join(STATE_ROOT, "*.json")).each do |path|
      record = JSON.parse(File.binread(path)) rescue next
      pid = record["pid"]
      alive = lambda do
        proc_start_time_ticks(pid) == record["start_time_ticks"]
      rescue StandardError
        false
      end
      if alive.call
        Process.kill("TERM", pid) rescue nil
        removed << pid
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + REAP_GRACE_SECONDS
        sleep 0.2 while alive.call && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        if alive.call
          # The daemon is its own session leader (setsid); the keeper is in it.
          Process.kill("KILL", -Integer(pid)) rescue (Process.kill("KILL", pid) rescue nil)
          killed << pid
          sleep 0.2 while alive.call && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline + 5
        end
      end
      FileUtils.rm_f(path)
      FileUtils.rm_rf(File.join(STATE_ROOT, pid.to_s))
    end
    swept = sweep_orphaned_host_links
    puts JSON.generate("reaped" => removed, "killed" => killed, "swept_links" => swept)
  end

  def sweep_orphaned_host_links
    output, = run_command("ip", "-o", "link", "show", allow_failure: true)
    output = output.to_s
    names = output.each_line.filter_map do |line|
      name = line.split(":")[1].to_s.strip.split("@").first.to_s
      name if name.start_with?("m4no")
    end
    names.each { |name| run_command("ip", "link", "delete", name, allow_failure: true) }
    names
  end

  def main(options)
    request = begin
      JSON.parse(options[:request_json].to_s)
    rescue JSON::ParserError
      {}
    end
    request = {} unless request.is_a?(Hash)
    result_read, result_write = IO.pipe
    daemon_pid = fork do
      result_read.close
      Process.setsid
      $stdin.reopen(File::NULL)
      log = File.join(STATE_ROOT, "daemon-#{Process.pid}.log")
      FileUtils.mkdir_p(STATE_ROOT)
      $stdout.reopen(log, "a")
      $stderr.reopen(log, "a")
      Signal.trap("TERM") { M4NetworkObservationRunner.request_terminate! }
      daemon = Daemon.new(request, ttl: options[:ttl])
      document = begin
        daemon.observe
      rescue StandardError => error
        daemon.cleanup
        {"executed" => true, "passed" => false, "errors" => ["#{error.class}: #{error.message}"],
         "backtrace" => Array(error.backtrace).first(10)}
      end
      result_write.write(JSON.generate(document))
      result_write.close
      if document["passed"]
        daemon.hold
      else
        # A failed observation must not leave its keeper namespace and host
        # veth behind; only a passing observation is held for the gate.
        daemon.cleanup
      end
      exit!(0)
    end
    result_write.close
    document = result_read.read
    result_read.close
    Process.detach(daemon_pid)
    puts document
    parsed = JSON.parse(document) rescue nil
    exit(parsed.is_a?(Hash) && parsed["passed"] == true ? 0 : 1)
  end
end

options = {ttl: M4NetworkObservationRunner::DEFAULT_TTL_SECONDS}
mode = :observe
OptionParser.new do |parser|
  parser.on("--ttl SECONDS") { |value| options[:ttl] = Integer(value) }
  parser.on("--reap") { mode = :reap }
end.parse!(ARGV)

if $PROGRAM_NAME == __FILE__
  case mode
  when :reap then M4NetworkObservationRunner.reap
  else
    input = $stdin.read.to_s
    options[:request_json] = input.strip.empty? ? "{}" : input
    M4NetworkObservationRunner.main(options)
  end
end
