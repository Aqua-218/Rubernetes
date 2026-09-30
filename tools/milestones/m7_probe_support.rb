# frozen_string_literal: true

# Shared helpers for the M7 MicroVM probes: the production MicroVM backend
# on the real host (KVM, jailer, dm-verity, vsock), the pinned busybox test
# image, a probe-owned Pod network attachment (a veth pair leased into the
# sandbox namespace, standing in for the M4 network layer), and fault
# injection primitives that act on the real VMM process.

require "digest"
require "fileutils"
require "json"
require "socket"
require "time"
require "tmpdir"

require_relative "m5_probe_support"
require_relative "m2_probe_support"
$LOAD_PATH.unshift File.join(M5ProbeSupport::ROOT, "lib")
require "rubernetes/runtime/microvm"
require "rubernetes/runtime/microvm/runtime_classes"

module M7ProbeSupport
  ROOT = M5ProbeSupport::ROOT
  LOCK = File.join(ROOT, "third_party/locks/m7-microvm-artifacts.json")
  PROBE_ROOT = ENV.fetch("RUBERNETES_M7_PROBE_ROOT", "/srv/rbn-m7")
  IMAGE_CACHE_ROOT = File.join(PROBE_ROOT, "image-disks")
  M = Rubernetes::Runtime::MicroVM

  module_function

  def now = M5ProbeSupport.now
  def monotonic = M5ProbeSupport.monotonic

  def report(kind:, measurement_level:, started_at:, cases:, extra: {})
    document = M5ProbeSupport.report(kind: kind, measurement_level: measurement_level, started_at: started_at, cases: cases, extra: extra)
    document.merge("milestone" => "M7",
                   "input_sha256" => ENV.fetch("RUBERNETES_M7_INPUT_SHA256", document["input_sha256"]),
                   "input_file_count" => ENV["RUBERNETES_M7_INPUT_FILE_COUNT"] ? Integer(ENV["RUBERNETES_M7_INPUT_FILE_COUNT"]) : document["input_file_count"])
  end

  def emit(document)
    M5ProbeSupport.emit(document)
  end

  def require_root!
    raise "M7 probes require root on an x86_64 KVM host" unless Process.uid.zero?
    raise "/dev/kvm is unavailable" unless File.exist?("/dev/kvm")
    raise "/dev/vhost-vsock is unavailable" unless File.exist?("/dev/vhost-vsock")
  end

  def artifacts
    @artifacts ||= M::Artifacts.load(lock_path: LOCK, root: ROOT)
  end

  def pinned_image
    M2ProbeSupport.pinned_image
  end

  def host_facts
    {"kernel" => File.read("/proc/sys/kernel/osrelease").strip, "kvm" => File.exist?("/dev/kvm"), "vhost_vsock" => File.exist?("/dev/vhost-vsock"),
     "cpu_virtualization" => File.read("/proc/cpuinfo")[/\b(vmx|svm)\b/, 1], "artifacts" => artifacts.to_h.slice("firecracker_version", "verity_root_hash", "digest")}
  end

  # A fresh MicroVM backend under a per-run directory.  Image disks are
  # cached across runs (they are content-addressed); everything else is
  # unique to the run.
  def build_runtime(label, restricted: false, use_base_snapshot: true, machine: {"vcpu_count" => 1, "mem_size_mib" => 512})
    require_root!
    root = File.join(PROBE_ROOT, "#{label[0, 12]}-#{Process.pid % 100_000}")
    FileUtils.rm_rf(root)
    FileUtils.mkdir_p(root, mode: 0o700)
    FileUtils.mkdir_p(IMAGE_CACHE_ROOT, mode: 0o700)
    klass = restricted ? Rubernetes::Runtime::MicroVMRestricted : Rubernetes::Runtime::MicroVM
    # Each runtime owns its workspaces (so list_resources is scoped to it);
    # image disks are content-addressed and cost one mkfs per digest per run.
    adapter = M::Adapter.new(runtime_class: klass.runtime_class, data_dir: File.join(root, "data"), artifacts: artifacts, chroot_base: File.join(root, "jail"),
                             netns_root: File.join(root, "netns"), run_root: File.join(root, "run"), parent_cgroup: "rubernetes-m7/#{label[0, 12]}",
                             clock: lambda {
                               Time.now.utc
                             }, machine: machine, use_base_snapshot: use_base_snapshot, network_device: klass.network_device?)
    runtime = klass.new(data_dir: File.join(root, "data"), artifacts: artifacts, adapter: adapter)
    [runtime, root]
  end

  def cleanup_runtime_root(root)
    FileUtils.rm_rf(root)
  rescue SystemCallError
    nil
  end

  # Probe-owned Pod network: a veth pair whose peer becomes eth0 inside the
  # sandbox namespace with a leased address, exactly what the network layer
  # produces before the runtime bridges it to the TAP.
  class ProbeNetwork
    def initialize(subnet_index)
      @subnet_index = subnet_index
      @counter = 1
      @attached = {}
    end

    def gateway = "10.#{200 + @subnet_index}.0.1"

    def attach(runtime, sandbox_id)
      context = runtime.network_sandbox_context(sandbox_id)
      netns_path = context.fetch("netns").fetch("path")
      @counter += 1
      ip = "10.#{200 + @subnet_index}.0.#{@counter}"
      host_link = "vm7#{@subnet_index}#{@counter}"[0, 15]
      peer = "#{host_link}p"[0, 15]
      alias_name = "m7-#{File.basename(netns_path)}"[0, 40]
      FileUtils.mkdir_p("/var/run/netns")
      File.symlink(netns_path, "/var/run/netns/#{alias_name}") unless File.exist?("/var/run/netns/#{alias_name}")
      shell!("ip", "link", "add", host_link, "type", "veth", "peer", "name", peer)
      shell!("ip", "link", "set", peer, "netns", alias_name)
      shell!("ip", "-n", alias_name, "link", "set", peer, "name", "eth0")
      shell!("ip", "-n", alias_name, "addr", "add", "#{ip}/24", "dev", "eth0")
      shell!("ip", "-n", alias_name, "link", "set", "eth0", "up")
      shell!("ip", "-n", alias_name, "route", "add", "default", "via", gateway)
      shell!("ip", "addr", "add", "#{gateway}/24", "dev", host_link) unless system("ip", "addr", "show", "dev", host_link, out: File::NULL,
                                                                                                                           err: File::NULL) && `ip addr show dev #{host_link}`.include?(gateway)
      shell!("ip", "link", "set", host_link, "up")
      @attached[sandbox_id] = {"ip" => ip, "host_link" => host_link, "alias" => alias_name}
      {"ip" => ip, "gateway" => gateway, "host_link" => host_link}
    end

    def detach(sandbox_id)
      entry = @attached.delete(sandbox_id)
      return unless entry

      system("ip", "link", "del", entry["host_link"], out: File::NULL, err: File::NULL)
      File.delete("/var/run/netns/#{entry["alias"]}") if File.symlink?("/var/run/netns/#{entry["alias"]}")
    end

    def detach_all
      @attached.keys.each { |sandbox_id| detach(sandbox_id) }
    end

    def ip_of(sandbox_id) = @attached.dig(sandbox_id, "ip")

    def reachable?(ip, timeout: 2)
      system("ping", "-c", "1", "-W", timeout.to_s, ip, out: File::NULL, err: File::NULL)
    end

    private

    def shell!(*arguments)
      raise "#{arguments.join(" ")} failed" unless system(*arguments, out: File::NULL, err: File::NULL)
    end
  end

  # Runs one Pod through the backend: sandbox, network, container, start.
  # Returns the session and a hash of per-phase seconds.
  def start_pod(runtime, network, label, command: ["/bin/busybox", "sh", "-c", "echo m7-ready; while :; do /bin/busybox sleep 1; done"],
                workspace_mib: 512)
    image = pinned_image
    timings = {}
    started = monotonic
    input = image.runtime_input(id: label, lowerdirs: [image.rootfs]).merge("workspace_mib" => workspace_mib)
    sandbox = runtime.run_sandbox(input, runtime_class: runtime.runtime_class, request_id: "#{label}-sandbox")
    timings["run_sandbox"] = (monotonic - started).round(4)
    net_started = monotonic
    lease = network ? network.attach(runtime, sandbox) : nil
    timings["network_attach"] = (monotonic - net_started).round(4)
    create_started = monotonic
    container = runtime.create_container(sandbox, image.container_spec(id: "main", command: command), request_id: "#{label}-create")
    timings["create_container"] = (monotonic - create_started).round(4)
    start_started = monotonic
    runtime.start_container(container, request_id: "#{label}-start")
    timings["start_container"] = (monotonic - start_started).round(4)
    timings["total"] = (monotonic - started).round(4)
    {"sandbox" => sandbox, "container" => container, "lease" => lease, "timings" => timings, "session" => runtime.session(sandbox)}
  end

  # Reconcile a sandbox whose VM died/hung during a fault: force host-side
  # teardown (the runtime's crash-recovery path) and detach the probe network.
  def force_teardown(runtime, network, pod)
    errors = runtime.force_teardown(pod["sandbox"])
    network&.detach(pod["sandbox"])
    errors
  end

  def stop_pod(runtime, network, pod, timeout: 5)
    errors = []
    begin
      runtime.stop_container(pod["container"], timeout: timeout, request_id: "#{pod["container"]}-stop") if pod["container"]
      runtime.remove_container(pod["container"], request_id: "#{pod["container"]}-remove") if pod["container"]
    rescue StandardError => error
      errors << "container: #{error.class}: #{error.message}"
    end
    begin
      runtime.stop_sandbox(pod["sandbox"], timeout: timeout, request_id: "#{pod["sandbox"]}-stop")
      runtime.remove_sandbox(pod["sandbox"], request_id: "#{pod["sandbox"]}-remove")
    rescue StandardError => error
      errors << "sandbox: #{error.class}: #{error.message}"
    end
    network&.detach(pod["sandbox"])
    errors
  end

  # Kernel/host-side residue for one VM after removal: nothing may remain.
  def residue(runtime, session)
    adapter = runtime.adapter
    {
      "jail_exists" => File.exist?(adapter.instance_variable_get(:@jailer).chroot_for(session.jail_id)),
      "vmm_alive" => session.alive? == true,
      "netns_exists" => !adapter.instance_variable_get(:@netns).handle(session.netns_name).nil?,
      "verity_active" => adapter.instance_variable_get(:@verity).active?("rbn-#{session.vm_id}"),
      "workspace_exists" => adapter.instance_variable_get(:@disks).workspaces.include?(session.identity.fields["workspace_id"]),
      "cgroup_exists" => session.instance ? File.directory?(session.instance.cgroup_path) : false,
      "identity_live" => runtime.identity_ledger.record(session.vm_id)&.state == "live",
      "resources_listed" => adapter.list_resources.select do |resource|
        resource["id"].to_s.include?(session.vm_id) || resource["id"] == session.jail_id
      end
    }
  end

  def residue_clean?(value)
    value.reject { |key, _| key == "resources_listed" }.values.none? && value["resources_listed"].empty?
  end

  def operation_state(runtime, id)
    runtime.operation_state(id)
  rescue StandardError => error
    "error: #{error.message}"
  end

  def percentile(values, fraction)
    return nil if values.empty?

    sorted = values.sort
    index = ((sorted.length - 1) * fraction).round
    sorted[index]
  end
end
