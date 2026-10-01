# frozen_string_literal: true

# Independent kernel observation helpers shared by the M4 volume, CSI, and
# mount-attack runners.  Everything here reads kernel state through /proc,
# /sys, statfs(2), and strace; nothing consults the probe's own claims except
# to compare them against what the kernel reports.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "time"

module M4ObserverSupport
  ROOT = File.expand_path("../../../..", __dir__).freeze
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  STRACE_SYSCALLS = %w[mount umount2 openat2 open_tree move_mount mount_setattr fsopen fsconfig fsmount].freeze
  # include/uapi/linux/magic.h
  STATFS_MAGIC = {0xEF53 => "ext4", 0x58465342 => "xfs", 0x01021994 => "tmpfs", 0x9fa0 => "proc"}.freeze

  module_function

  def canonical_value(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical_value(value.fetch(source))
      end
    when Array
      value.map { |child| canonical_value(child) }
    when Time
      value.utc.iso8601(6)
    when Symbol
      value.to_s
    else
      value
    end
  end

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical_value(value)))
  end

  def iso8601_now
    Time.now.utc.iso8601(6)
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # Content-bound comparison record in the shape the M4 gate validates:
  # expected/actual observables with digests and a passed flag derived only
  # from digest equality.
  def comparison(id, expected, actual, extra = {})
    expected = canonical_value(expected)
    actual = canonical_value(actual)
    expected_sha256 = digest(expected)
    actual_sha256 = digest(actual)
    {
      "id" => id, "expected" => expected, "actual" => actual,
      "expected_sha256" => expected_sha256, "actual_sha256" => actual_sha256,
      "passed" => expected_sha256 == actual_sha256
    }.merge(extra)
  end

  def proc_start_time_ticks(pid)
    value = File.binread("/proc/#{Integer(pid)}/stat", 16 * 1024)
    closing = value.rindex(")")
    raise ArgumentError, "process stat has no closing command name" unless closing

    Integer(value.byteslice((closing + 2)..).to_s.split.fetch(19))
  end

  def process_identity(pid)
    pid = Integer(pid)
    {
      "pid" => pid,
      "start_time_ticks" => proc_start_time_ticks(pid),
      "mount_namespace_inode" => File.stat("/proc/#{pid}/ns/mnt").ino,
      "path" => "/proc/#{pid}/ns/mnt",
      "argv" => File.binread("/proc/#{pid}/cmdline").split("\0")
    }
  end

  def process_alive?(identity)
    return false unless identity.is_a?(Hash)

    proc_start_time_ticks(identity.fetch("pid")) == identity.fetch("start_time_ticks")
  rescue SystemCallError, ArgumentError, KeyError
    false
  end

  def decode_mountinfo_field(value)
    String(value).gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
  end

  def parse_mountinfo_line(line)
    before, after = line.strip.split(" - ", 2)
    return nil unless before && after

    fields = before.split
    return nil if fields.length < 6

    filesystem, source, super_options = after.split(" ", 3)
    options = decode_mountinfo_field(fields[5])
    {
      "mountId" => fields[0], "parentId" => fields[1], "deviceId" => fields[2],
      "root" => decode_mountinfo_field(fields[3]), "target" => decode_mountinfo_field(fields[4]),
      "options" => options, "optionalFields" => fields.drop(6),
      "filesystem" => decode_mountinfo_field(filesystem), "kernelSource" => decode_mountinfo_field(source),
      "superOptions" => decode_mountinfo_field(super_options.to_s),
      "readonly" => options.split(",").include?("ro"),
      "line" => line.strip
    }
  end

  def read_mountinfo(pid)
    File.binread("/proc/#{Integer(pid)}/mountinfo").lines.map(&:chomp).reject(&:empty?)
  end

  def mountinfo_entries(pid)
    read_mountinfo(pid).filter_map { |line| parse_mountinfo_line(line) }
  end

  def mounts_under(pid, root)
    prefix = root.end_with?("/") ? root : "#{root}/"
    mountinfo_entries(pid).select { |entry| entry.fetch("target") == root || entry.fetch("target").start_with?(prefix) }
  end

  # The stable identity of the mount covering target, or nil.
  def mount_identity(pid, target)
    entry = mountinfo_entries(pid).find { |candidate| candidate.fetch("target") == target }
    return nil unless entry

    stable_identity(entry)
  end

  def stable_identity(entry)
    {
      "target" => entry.fetch("target"), "mountId" => entry.fetch("mountId"), "deviceId" => entry.fetch("deviceId"),
      "root" => entry.fetch("root"), "filesystem" => entry.fetch("filesystem"),
      "kernelSource" => entry.fetch("kernelSource"), "readonly" => entry.fetch("readonly")
    }
  end

  # /proc/<pid>/root resolves through the observed process's mount namespace,
  # so file digests and statfs reflect what that process actually sees.
  def namespaced_path(pid, path)
    File.join("/proc/#{Integer(pid)}/root", path)
  end

  def file_digest(pid, path)
    bytes = File.binread(namespaced_path(pid, path))
    {"path" => path, "sha256" => Digest::SHA256.hexdigest(bytes), "bytes" => bytes.bytesize}
  end

  def statfs(pid, path)
    require File.join(ROOT, "lib", "rubernetes", "platform", "linux", "statfs")
    result = Rubernetes::Platform::Linux::Statfs.statfs(namespaced_path(pid, path))
    {"path" => path, "typeName" => result.type_name, "type" => format("0x%x", result.type),
     "fsid" => result.fsid, "capacityBytes" => result.capacity_bytes, "blockSize" => result.block_size}
  end

  def loop_devices
    Dir.glob("/sys/block/loop*").filter_map do |sys|
      backing = File.join(sys, "loop", "backing_file")
      next unless File.file?(backing)

      name = File.basename(sys)
      dev = File.read(File.join(sys, "dev")).strip
      {"kind" => "loop", "path" => "/dev/#{name}", "deviceId" => dev, "backingPath" => File.read(backing).strip,
       "offset" => File.read(File.join(sys, "loop", "offset")).strip.to_i,
       "sizeLimit" => File.read(File.join(sys, "loop", "sizelimit")).strip.to_i}
    end
  end

  def dm_devices
    Dir.glob("/sys/block/dm-*").filter_map do |sys|
      name_path = File.join(sys, "dm", "name")
      next unless File.file?(name_path)

      {"kind" => "device-mapper", "path" => "/dev/mapper/#{File.read(name_path).strip}",
       "name" => File.read(name_path).strip, "uuid" => File.read(File.join(sys, "dm", "uuid")).strip,
       "deviceId" => File.read(File.join(sys, "dev")).strip}
    end
  end

  def wait_for(timeout:, interval: 0.02)
    deadline = monotonic + timeout
    loop do
      value = yield
      return value if value
      return nil if monotonic >= deadline

      sleep interval
    end
  end

  # Runs a reader inside the observed process's mount namespace.  nsenter
  # execs the command in place, so the reported pid is the reader itself.
  def read_in_namespace(pid, paths)
    script = <<~SH
      ns=$(stat -Lc %i /proc/self/ns/mnt)
      printf '{"pid":%s,"mount_namespace_inode":%s,"files":[' "$$" "$ns"
      first=1
      for path in "$@"; do
        if [ $first -eq 0 ]; then printf ','; fi
        first=0
        if [ -r "$path" ]; then
          sum=$(sha256sum "$path" | cut -d' ' -f1)
          bytes=$(stat -Lc %s "$path")
          printf '{"path":"%s","sha256":"%s","bytes":%s}' "$path" "$sum" "$bytes"
        else
          printf '{"path":"%s","error":"unreadable"}' "$path"
        fi
      done
      printf ']}'
    SH
    stdout, stderr, status = Open3.capture3("nsenter", "-m", "-t", Integer(pid).to_s, "--", "sh", "-c", script, "reader", *paths)
    raise "namespace reader failed: #{stderr.strip}" unless status.success?

    JSON.parse(stdout)
  end

  # Attach strace to a running process.  Output lines are parsed lazily by
  # parse_strace so the runner can bind syscalls to the phase during which
  # they were observed (by timestamp windows).
  class SyscallTrace
    attr_reader :output_path, :pid, :command

    def initialize(target_pid, output_path, syscalls: STRACE_SYSCALLS)
      @target_pid = Integer(target_pid)
      @output_path = output_path
      @command = ["strace", "-f", "-qq", "-ttt", "-s", "256", "-e", "trace=#{syscalls.join(",")}",
                  "-o", output_path, "-p", @target_pid.to_s]
      @pid = nil
    end

    def start
      @pid = Process.spawn(*@command, in: File::NULL, out: File::NULL, err: File::NULL)
      # strace reports attachment on stderr (suppressed); the tracee is
      # stopped for a moment while ptrace attaches.  Wait until the tracee
      # shows a tracer in /proc so no syscall of the first phase is missed.
      attached = M4ObserverSupport.wait_for(timeout: 10) do
        File.foreach("/proc/#{@target_pid}/status").any? { |line| line.start_with?("TracerPid:") && line.split.last.to_i == @pid }
      rescue Errno::ENOENT
        nil
      end
      raise "strace did not attach to #{@target_pid}" unless attached

      @pid
    end

    def stop
      return [] unless @pid

      begin
        Process.kill("INT", @pid)
      rescue Errno::ESRCH
        nil
      end
      begin
        Process.wait(@pid)
      rescue Errno::ECHILD
        nil
      end
      @pid = nil
      M4ObserverSupport.parse_strace(File.exist?(@output_path) ? File.binread(@output_path) : "")
    end
  end

  # rubocop:disable-next Layout/LineLength -- the pattern reads better whole
  STRACE_LINE = /\A(?:(?<pid>\d+)\s+)?(?<ts>\d+\.\d+)\s+(?<name>[a-z_0-9]+)\((?<args>.*)\)\s+=\s+(?<ret>-?\d+|0x[0-9a-fA-F]+|\?)(?:\s+(?<errno>E[A-Z0-9]+)\s+\((?<errmsg>[^)]*)\))?/
  STRACE_RESUMED = /\A(?:(?<pid>\d+)\s+)?(?<ts>\d+\.\d+)\s+<\.\.\.\s+(?<name>[a-z_0-9]+)\s+resumed>\s*(?<args>.*)\)\s+=\s+(?<ret>-?\d+|0x[0-9a-fA-F]+|\?)(?:\s+(?<errno>E[A-Z0-9]+)\s+\((?<errmsg>[^)]*)\))?/

  def parse_strace(text)
    unfinished = {}
    records = []
    text.each_line do |raw|
      line = raw.chomp
      if line.include?("<unfinished ...>")
        match = line.match(/\A(?:(?<pid>\d+)\s+)?(?<ts>\d+\.\d+)\s+(?<name>[a-z_0-9]+)\((?<args>.*)<unfinished \.\.\.>/)
        unfinished[match[:pid].to_s] = match if match
        next
      end
      if (match = line.match(STRACE_RESUMED))
        started = unfinished.delete(match[:pid].to_s)
        records << strace_record(match, started ? "#{started[:args]}#{match[:args]}" : match[:args], line)
        next
      end
      match = line.match(STRACE_LINE)
      records << strace_record(match, match[:args], line) if match
    end
    records
  end

  def strace_record(match, args, line)
    ret = match[:ret]
    value = if ret.start_with?("0x")
              ret.hex
            else
              (ret == "?" ? nil : ret.to_i)
            end
    {
      "name" => match[:name], "pid" => match[:pid]&.to_i, "timestamp" => Float(match[:ts]),
      "args" => args.to_s, "return" => value, "errno" => match[:errno], "line" => line,
      "return_class" => (if match[:errno]
                           "-1 #{match[:errno]}"
                         else
                           (if value.nil?
                              "unknown"
                            else
                              (value.negative? ? "error" : "success")
                            end)
                         end)
    }
  end

  def runner_provenance(runner_path, implementation:, started_at:, mode: "external", finished_at: iso8601_now)
    {
      "runner_sha256" => Digest::SHA256.file(runner_path).hexdigest,
      "command" => [RbConfig.ruby] + [runner_path.delete_prefix("#{ROOT}/")] + ARGV,
      "argv" => [RbConfig.ruby, runner_path] + ARGV,
      "process_id" => Process.pid,
      "start_time_ticks" => proc_start_time_ticks(Process.pid),
      "mode" => mode,
      "self_comparison" => false,
      "implementation" => implementation,
      "started_at" => started_at,
      "finished_at" => finished_at,
      "kernel" => File.read("/proc/sys/kernel/osrelease").strip,
      "host_mount_namespace_inode" => File.stat("/proc/self/ns/mnt").ino
    }
  end
end

module M4ObserverSupport
  # Drives a phase-marked worker: waits for each phase-NNN.json marker the
  # worker writes, observes the kernel from outside the worker's mount
  # namespace, then writes phase-NNN.release so the worker continues.  The
  # worker never sees the observation; it only claims, the kernel confirms.
  class PhaseObserver
    MARKER_PATTERN = /\Aphase-(\d{3})\.json\z/
    READER_SCRIPT = <<~'RUBY_READER'
      require "digest"
      require "json"
      root = ARGV.shift
      files = ARGV
      stop = false
      Signal.trap("TERM") { stop = true }
      reads = 0
      partial = 0
      missing = 0
      generations = {}
      errors = Hash.new(0)
      namespace = File.stat("/proc/self/ns/mnt").ino
      until stop
        files.each do |name|
          begin
            bytes = File.binread(File.join(root, "..data", name))
            reads += 1
            header, payload = bytes.split("\n", 2)
            if header.nil? || payload.nil? || !header.start_with?("gen=")
              partial += 1
              next
            end
            body, trailer = payload.rpartition("\nsha256=")[0], payload.rpartition("\nsha256=")[2]
            if trailer.strip != Digest::SHA256.hexdigest(body)
              partial += 1
              next
            end
            generations[header.delete_prefix("gen=")] = true
          rescue Errno::ENOENT
            missing += 1
          rescue SystemCallError => error
            errors[error.class.name] += 1
          end
        end
      end
      puts JSON.generate({"pid" => Process.pid, "mount_namespace_inode" => namespace, "reads" => reads,
                          "partial_generation_observed_count" => partial, "missing_count" => missing,
                          "generations_observed" => generations.keys.length, "errors" => errors})
    RUBY_READER

    attr_reader :phases, :errors

    def initialize(control_dir:, worker:, root:, marker_timeout: 120, trace: true)
      @control_dir = control_dir
      @worker = worker
      @root = root
      @marker_timeout = marker_timeout
      @trace = trace
      @phases = []
      @errors = []
      @mountinfo = []
      @files = []
      @statfs = []
      @devices = []
      @containers = []
      @syscalls = []
      @reader = nil
      @reader_result = nil
      @windows = []
    end

    def run
      pid = @worker.fetch("pid")
      raise "worker #{pid} is not alive with the declared start time" unless M4ObserverSupport.process_alive?(@worker)

      trace = nil
      if @trace
        trace = SyscallTrace.new(pid, File.join(@control_dir, "strace.log"))
        trace.start
      end
      # strace -ttt prints wall-clock seconds; phases are bounded with the
      # monotonic clock.  Capture both at the same instant so syscalls can be
      # attributed to the phase window in which the kernel executed them.
      @clock_offset = Time.now.to_f - M4ObserverSupport.monotonic
      window_start = M4ObserverSupport.monotonic
      number = 1
      loop do
        marker = wait_for_marker(number)
        break unless marker

        observed_at = M4ObserverSupport.monotonic
        phase = observe_phase(marker, number, window: [window_start, observed_at])
        @phases << phase
        release(number)
        window_start = M4ObserverSupport.monotonic
        number += 1
        break if marker["final"] == true
      end
      records = trace ? trace.stop : []
      bind_syscalls(records)
      final_cleanup
      {
        "phases" => @phases, "mountinfo" => @mountinfo, "files" => @files, "statfs" => @statfs,
        "devices" => @devices, "container_observation" => @containers, "syscalls" => @syscalls,
        "projected_rotation" => @reader_result, "errors" => @errors,
        "strace_command" => trace&.command,
        "strace_log_sha256" => (trace && File.exist?(trace.output_path) ? Digest::SHA256.file(trace.output_path).hexdigest : nil)
      }
    ensure
      stop_reader if @reader
    end

    private

    def marker_path(number)
      File.join(@control_dir, format("phase-%03d.json", number))
    end

    def release(number)
      File.open(File.join(@control_dir, format("phase-%03d.release", number)), File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
        file.write(JSON.generate("released_at" => M4ObserverSupport.iso8601_now, "observer_pid" => Process.pid))
      end
    end

    def wait_for_marker(number)
      path = marker_path(number)
      M4ObserverSupport.wait_for(timeout: @marker_timeout) do
        unless M4ObserverSupport.process_alive?(@worker)
          @errors << "worker exited before phase #{number} marker"
          break nil
        end
        next nil unless File.file?(path)

        begin
          JSON.parse(File.binread(path))
        rescue JSON::ParserError
          nil
        end
      end
    end

    def observe_phase(marker, number, window:)
      pid = @worker.fetch("pid")
      phase = {"phase" => number, "name" => marker["name"], "final" => marker["final"] == true,
               "observed_at" => M4ObserverSupport.iso8601_now, "window" => window, "comparisons" => []}
      declared_worker = marker["worker"]
      unless declared_worker.is_a?(Hash) && declared_worker["pid"] == pid &&
             declared_worker["start_time_ticks"] == @worker["start_time_ticks"] &&
             declared_worker["mount_namespace_inode"] == File.stat("/proc/#{pid}/ns/mnt").ino
        @errors << "phase #{number} marker does not carry the observed worker identity"
      end
      expected = marker["expected"].is_a?(Hash) ? marker["expected"] : {}
      entries = M4ObserverSupport.mountinfo_entries(pid)
      Array(expected["mounts"]).each do |claim|
        target = claim["target"].to_s
        entry = entries.find { |candidate| candidate.fetch("target") == target }
        actual = entry ? M4ObserverSupport.stable_identity(entry) : {"target" => target, "mounted" => false}
        record = M4ObserverSupport.comparison("mount:#{number}:#{target}", claim, actual,
                                              "phase" => number, "target" => target,
                                              "line" => entry ? entry.fetch("line") : "",
                                              "line_sha256" => Digest::SHA256.hexdigest(entry ? entry.fetch("line") : ""),
                                              "kernel_backed" => true)
        @errors << "phase #{number}: mount #{target} does not match the kernel mount table" unless record["passed"]
        @mountinfo << record
        phase["comparisons"] << record["id"]
      end
      Array(expected["absent"]).each do |target|
        entry = entries.find { |candidate| candidate.fetch("target") == target.to_s }
        # An absent mount is still bound to kernel content: the mountinfo line
        # of the mount that covers the target (longest matching prefix) is the
        # line that proves nothing more specific is mounted there.
        covering = entry || entries.select do |candidate|
          target.to_s == candidate.fetch("target") || target.to_s.start_with?(candidate.fetch("target").chomp("/") + "/")
        end
          .max_by { |candidate| candidate.fetch("target").length }
        line = covering ? covering.fetch("line") : ""
        record = M4ObserverSupport.comparison("absent:#{number}:#{target}", {"target" => target.to_s, "mounted" => false},
                                              entry ? M4ObserverSupport.stable_identity(entry) : {"target" => target.to_s, "mounted" => false},
                                              "phase" => number, "target" => target.to_s, "line" => line,
                                              "line_sha256" => Digest::SHA256.hexdigest(line),
                                              "covering_mount_id" => covering && covering.fetch("mountId"),
                                              "kernel_backed" => true)
        @errors << "phase #{number}: #{target} is still mounted" unless record["passed"]
        @mountinfo << record
      end
      Array(expected["files"]).each do |claim|
        actual = begin
          M4ObserverSupport.file_digest(pid, claim["path"].to_s)
        rescue SystemCallError => error
          {"path" => claim["path"].to_s, "error" => error.class.name}
        end
        record = M4ObserverSupport.comparison("file:#{number}:#{claim["path"]}", claim, actual, "phase" => number)
        @errors << "phase #{number}: file #{claim["path"]} digest differs inside the worker namespace" unless record["passed"]
        @files << record
      end
      Array(expected["statfs"]).each do |claim|
        actual = begin
          observed = M4ObserverSupport.statfs(pid, claim["path"].to_s)
          claim.keys.to_h { |key| [key, observed.key?(key) ? observed[key] : nil] }
        rescue StandardError => error
          {"path" => claim["path"].to_s, "error" => error.class.name}
        end
        record = M4ObserverSupport.comparison("statfs:#{number}:#{claim["path"]}", claim, actual, "phase" => number,
                                                                                                  "kernel_backed" => true)
        @errors << "phase #{number}: statfs of #{claim["path"]} differs from the claim" unless record["passed"]
        @statfs << record
      end
      Array(expected["devices"]).each do |claim|
        live = (M4ObserverSupport.loop_devices + M4ObserverSupport.dm_devices)
        observed = live.find { |device| device["path"] == claim["path"] }
        actual = if observed
                   claim.keys.to_h { |key| [key, observed.key?(key) ? observed[key] : nil] }
                 else
                   {"path" => claim["path"], "present" => false}
                 end
        record = M4ObserverSupport.comparison("device:#{number}:#{claim["path"]}", claim, actual, "phase" => number,
                                                                                                  "kernel_backed" => true)
        @errors << "phase #{number}: device #{claim["path"]} differs from sysfs" unless record["passed"]
        @devices << record
      end
      Array(expected["absent_devices"]).each do |path|
        live = (M4ObserverSupport.loop_devices + M4ObserverSupport.dm_devices).find { |device| device["path"] == path }
        record = M4ObserverSupport.comparison("device-absent:#{number}:#{path}", {"path" => path, "present" => false},
                                              live ? live.merge("present" => true) : {"path" => path, "present" => false},
                                              "phase" => number, "kernel_backed" => true)
        @errors << "phase #{number}: device #{path} was not released" unless record["passed"]
        @devices << record
      end
      if (paths = expected["reader"]).is_a?(Array) && !paths.empty?
        actual_reader = begin
          M4ObserverSupport.read_in_namespace(pid, paths)
        rescue StandardError => error
          {"error" => error.message}
        end
        expected_files = Array(expected["files"]).select { |claim| paths.include?(claim["path"]) }
        expected_view = {"mount_namespace_inode" => @worker["mount_namespace_inode"], "files" => expected_files}
        actual_view = {"mount_namespace_inode" => actual_reader["mount_namespace_inode"], "files" => Array(actual_reader["files"])}
        record = M4ObserverSupport.comparison("reader:#{number}", expected_view, actual_view,
                                              "phase" => number, "id" => "reader-#{number}",
                                              "container_id" => "m4-namespace-reader-#{number}",
                                              "pid" => actual_reader["pid"], "mount_namespace_inode" => actual_reader["mount_namespace_inode"],
                                              "observed" => true)
        @errors << "phase #{number}: an independent reader in the worker namespace saw different content" unless record["passed"]
        @containers << record
      end
      phase["syscall_claims"] = Array(expected["syscalls"])
      rotation = marker["rotation"]
      if rotation.is_a?(Hash) && rotation["start"].is_a?(Hash)
        start_reader(rotation["start"])
      elsif rotation.is_a?(Hash) && rotation["stop"] == true
        @reader_result = stop_reader
        phase["rotation_reader"] = @reader_result
      end
      @windows << [number, window, phase["syscall_claims"]]
      phase
    end

    def start_reader(spec)
      root = spec.fetch("root")
      files = Array(spec.fetch("files"))
      out_read, out_write = IO.pipe
      pid = Process.spawn("nsenter", "-m", "-t", @worker.fetch("pid").to_s, "--", RbConfig.ruby, "-e", READER_SCRIPT, root, *files,
                          in: File::NULL, out: out_write, err: File::NULL)
      out_write.close
      @reader = {"pid" => pid, "out" => out_read, "started_at" => M4ObserverSupport.iso8601_now}
    end

    def stop_reader
      return nil unless @reader

      pid = @reader.fetch("pid")
      # Let the reader observe the final generation before it is stopped.
      sleep 0.2
      begin
        Process.kill("TERM", pid)
      rescue Errno::ESRCH
        nil
      end
      _, status = Process.wait2(pid)
      output = @reader.fetch("out").read
      @reader.fetch("out").close
      @reader = nil
      result = begin
        JSON.parse(output)
      rescue JSON::ParserError
        {"error" => "reader produced no JSON", "raw" => output}
      end
      result.merge("exit_status" => status.exitstatus, "reader_pid" => pid,
                   "expected_mount_namespace_inode" => @worker["mount_namespace_inode"])
    end

    def bind_syscalls(records)
      offset = @clock_offset
      @windows.each do |number, window, claims|
        first = window[0] + offset
        last = window[1] + offset
        phase_records = records.select { |record| record["timestamp"].between?(first - 0.001, last + 0.001) }
        remaining = Hash.new(0)
        claims.each do |claim|
          count = claim["count"]
          remaining[[claim["name"], claim["return_class"]]] = count == "any" ? Float::INFINITY : Integer(count)
        end
        phase_records.each do |record|
          key = [record["name"], record["return_class"]]
          key = [record["name"], "success"] if record["return_class"] == "success" && !remaining.key?(key)
          expected = if remaining[key].positive?
                       remaining[key] -= 1 unless remaining[key] == Float::INFINITY
                       {"name" => record["name"], "return_class" => record["return_class"]}
                     else
                       {"name" => record["name"], "return_class" => "unclaimed"}
                     end
          actual = {"name" => record["name"], "return_class" => record["return_class"]}
          comparison = M4ObserverSupport.comparison("syscall:#{number}:#{record["timestamp"]}", expected, actual,
                                                    "phase" => number, "name" => record["name"], "return" => record["return"],
                                                    "errno" => record["errno"], "args" => record["args"], "pid" => record["pid"],
                                                    "timestamp" => record["timestamp"], "line" => record["line"],
                                                    "line_sha256" => Digest::SHA256.hexdigest(record["line"]), "kernel_backed" => true)
          @errors << "phase #{number}: unclaimed #{record["name"]} syscall observed (#{record["return_class"]})" unless comparison["passed"]
          @syscalls << comparison
        end
        unmet = remaining.select { |_key, count| count.is_a?(Integer) && count.positive? }
        unmet.each do |(name, klass), count|
          @errors << "phase #{number}: claimed #{count} more #{name} (#{klass}) syscalls than strace observed"
          @syscalls << M4ObserverSupport.comparison("syscall-missing:#{number}:#{name}:#{klass}",
                                                    {"name" => name, "return_class" => klass, "missing" => count},
                                                    {"name" => name, "return_class" => "not_observed", "missing" => count},
                                                    "phase" => number, "name" => name, "return" => nil, "kernel_backed" => true)
        end
      end
    end

    def final_cleanup
      pid = @worker.fetch("pid")
      return unless M4ObserverSupport.process_alive?(@worker)

      remaining = M4ObserverSupport.mounts_under(pid, @root)
      @errors << "worker namespace still has #{remaining.length} mounts under #{@root} after the final phase" unless remaining.empty?
      @cleanup = {"mounts_under_root_after_final_phase" => remaining.length,
                  "lines" => remaining.map { |entry| entry.fetch("line") }}
      @phases << {"phase" => "cleanup", "name" => "worker_namespace_cleanup", "cleanup" => @cleanup}
    end
  end
end
