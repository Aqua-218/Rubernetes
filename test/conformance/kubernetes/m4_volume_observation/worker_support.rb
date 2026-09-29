# frozen_string_literal: true

# Helpers shared by the M4 volume observation workers (crash worker and
# lifecycle worker).  A worker runs the production Volume::Manager with the
# production NativeMountAdapter/NativeDeviceAdapter inside a private mount
# namespace; the observer reads kernel state independently and compares it
# with the identities the worker claims from adapter readback.

require "digest"
require "fileutils"
require "json"

module M4WorkerSupport
  module_function

  def proc_start_time_ticks(pid = Process.pid)
    value = File.binread("/proc/#{pid}/stat", 16 * 1024)
    closing = value.rindex(")")
    Integer(value.byteslice(closing + 2..).to_s.split.fetch(19))
  end

  def identity
    {"pid" => Process.pid, "start_time_ticks" => proc_start_time_ticks,
     "mount_namespace_inode" => File.stat("/proc/self/ns/mnt").ino, "path" => "/proc/#{Process.pid}/ns/mnt"}
  end

  # Atomic JSON publication: the observer only ever sees complete files.
  def write_json(path, payload)
    temporary = "#{path}.tmp-#{Process.pid}"
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(JSON.generate(payload))
      file.flush
      file.fsync
    end
    File.rename(temporary, path)
    path
  end

  def wait_for_file(path, timeout: nil, interval: 0.02)
    deadline = timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until File.file?(path)
      return false if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep interval
    end
    true
  end

  def mount_lines_under(root)
    File.binread("/proc/self/mountinfo").lines.map(&:chomp).select do |line|
      target = line.split(" ")[4].to_s.gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
      target == root || target.start_with?("#{root}/")
    end
  end

  # The stable mount identity fields the observer compares against
  # /proc/<pid>/mountinfo, taken from a production adapter readback entry.
  def mount_claim(entry, target: nil)
    hash = entry.respond_to?(:to_h) ? entry.to_h.transform_keys(&:to_s) : {}
    {
      "target" => target || hash["target"], "mountId" => hash["mountId"].to_s, "deviceId" => hash["deviceId"].to_s,
      "root" => hash["root"], "filesystem" => hash["filesystem"], "kernelSource" => hash["kernelSource"],
      "readonly" => hash["readonly"] == true
    }
  end

  def file_claim(path)
    bytes = File.binread(path)
    {"path" => path, "sha256" => Digest::SHA256.hexdigest(bytes), "bytes" => bytes.bytesize}
  end

  def build_manager(data_dir, mount_adapter: nil, device_adapter: nil, path_security: nil, root: nil)
    Rubernetes::Platform::Linux::Mount.new.make_private(target: "/", recursive: true, resource_id: "m4-worker:private")
    unless path_security
      openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
      path_security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
    end
    uuid_resolver = Rubernetes::Volume::FilesystemUuidResolver.new
    mount_adapter ||= Rubernetes::Volume::NativeMountAdapter.new(filesystem_uuid_resolver: uuid_resolver)
    device_adapter ||= Rubernetes::Volume::NativeDeviceAdapter.new
    Rubernetes::Volume::Manager.new(
      data_dir: data_dir, root: root || File.join(data_dir, "volumes"), adapter: mount_adapter,
      mount_adapter: mount_adapter, device_adapter: device_adapter, path_security: path_security,
      require_real_readback: true, fsync: true
    )
  end
end
