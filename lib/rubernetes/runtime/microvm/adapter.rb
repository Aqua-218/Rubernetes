# frozen_string_literal: true

require "fileutils"
require "json"
require "securerandom"
require "socket"

require_relative "artifacts"
require_relative "broker"
require_relative "errors"
require_relative "identity"
require_relative "image_disks"
require_relative "jailer"
require_relative "netns"
require_relative "session"
require_relative "snapshot_pool"
require_relative "tap"
require_relative "verity"
require_relative "../../network/netlink"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Backend adapter behind the common lifecycle façade: one VMSession per
      # sandbox.  The façade owns the durable state machine and ledger; this
      # adapter performs the effects in the fixed order and reports the
      # resources it acquired so the ledger can release them in reverse
      # order on rollback, removal and crash recovery.
      class Adapter
        BRIDGE_NAME = "vmbr0"
        POD_IFNAME = "eth0"

        attr_reader :artifacts, :identity_ledger, :pool, :broker, :sessions, :runtime_class

        def initialize(runtime_class:, data_dir:, artifacts:, chroot_base:, netns_root:, run_root:, parent_cgroup:, clock:, logger: nil, machine: nil,
                       use_base_snapshot: true, network_device: true, workspace_mib: 2048, broker: nil, verity: nil, image_disks: nil, netlink: nil)
          @runtime_class = runtime_class
          @data_dir = data_dir
          @artifacts = artifacts
          @clock = clock
          @logger = logger
          @machine = machine
          @use_base_snapshot = use_base_snapshot
          @network_device = network_device
          @run_root = run_root
          FileUtils.mkdir_p(run_root, mode: 0o700)
          @jailer = Jailer.new(artifacts: artifacts, chroot_base: chroot_base, parent_cgroup: parent_cgroup, logger: logger)
          @verity = verity || Verity.new
          @netns = Netns.new(root: netns_root)
          @disks = image_disks || ImageDisks.new(root: File.join(data_dir, "disks"), workspace_mib: workspace_mib)
          @pool = SnapshotPool.new(root: File.join(data_dir, "snapshots"), clock: clock)
          @identity_ledger = IdentityLedger.new(File.join(data_dir, "identity.jsonl"), clock: clock)
          @broker = broker || Broker.new(clock: clock, revocation_epoch: -> { @identity_ledger.revocation_epoch })
          @netlink = netlink
          @sessions = {}
          @containers = {}
          @networks = {}
          @mutex = Mutex.new
          @verified = nil
        end

        # ----------------------------------------------------------- lifecycle

        def verify_image(config:, runtime_class:)
          @verified ||= @artifacts.verify!
          Array(config["resolved_images"]).each do |image|
            raise ArtifactError, "resolved image has no digest" unless image["digest"].to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
            unless image["rootfs"] && File.directory?(image["rootfs"])
              raise ArtifactError,
                    "resolved image #{image["digest"]} has no extracted rootfs"
            end
          end
          true
        end

        # Each effect step is transactional for the session: a failure inside
        # it releases everything the session acquired so far (in reverse
        # order, VMM killed first) before the error reaches the façade, so
        # no jail, VMM, namespace, mapping, workspace or identity outlives a
        # failed step.
        def allocate_workspace(sandbox_id:, config:, runtime_class:, gate:)
          raise GateError, "workload gate must be closed during allocation" unless gate == :closed

          identity = @identity_ledger.allocate(sandbox_id: sandbox_id, runtime_class: runtime_class, artifact_digest: @artifacts.digest,
                                               policy_digest: policy_digest(config), request_id: config["request_id"])
          session = VMSession.new(sandbox_id: sandbox_id, identity: identity, artifacts: @artifacts, jailer: @jailer, verity: @verity, netns: @netns,
                                  disks: @disks, pool: @pool, broker: @broker, clock: @clock, logger: @logger, machine: machine_for(config),
                                  network_device: @network_device, run_root: @run_root)
          @mutex.synchronize { @sessions[sandbox_id] = session }
          transactional(session) do
            images = Array(config["resolved_images"]).map { |image| {"digest" => image["digest"], "rootfs" => image["rootfs"]} }.uniq
            session.allocate_workspace(images: images, workspace_mib: config["workspace_mib"])
            @broker.bind(vm_id: identity.vm_id, identity: identity.fields, policy: broker_policy(config))
            {"resources" => session.resources.select { |resource| %w[workspace identity].include?(resource["kind"]) }}
          end
        end

        def create_isolation(sandbox_id:, config:, runtime_class:, gate:)
          session = session!(sandbox_id)
          transactional(session) do
            base = @use_base_snapshot ? @pool.latest(runtime_class) : nil
            # A corrupt base is refused before any jail or VMM exists.
            @pool.verify!(base, artifact_digest: @artifacts.digest) if base
            session.create_isolation(base: base)
            {"resources" => session.resources.select { |resource| %w[netns tap verity jail vmm].include?(resource["kind"]) }}
          end
        end

        def attach_resources(sandbox_id:, config:, runtime_class:, gate:)
          session = session!(sandbox_id)
          transactional(session) do
            session.attach_resources(files: injected_files(config))
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            guest = session.sandbox_run(sandbox_input(config, sandbox_id))
            session.timings["guest_sandbox_run"] = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(4)
            session.timings["guest_sandbox_run_inner"] = guest["timings"] if guest.is_a?(Hash) && guest["timings"]
            session.timings["guest_sandbox_trace"] = guest["trace"] if guest.is_a?(Hash) && guest["trace"]
            session.timings["guest_sandbox_profile"] = guest["profile"] if guest.is_a?(Hash) && guest["profile"]
            {"resources" => [{"kind" => "guest_sandbox", "id" => sandbox_id, "identity" => "guest_sandbox:#{session.vm_id}:#{sandbox_id}"}]}
          end
        end

        def hold_workload(sandbox_id:, config:, runtime_class:, gate:)
          session = session!(sandbox_id)
          transactional(session) { session.hold_workload }
          true
        end

        def transactional(session)
          yield
        rescue Exception => error # rubocop:disable Lint/RescueException
          cleanup_errors = begin
            session.cleanup!(identity_ledger: @identity_ledger)
          rescue StandardError => cleanup_error
            [{"error" => "#{cleanup_error.class}: #{cleanup_error.message}"}]
          end
          @mutex.synchronize { @sessions.delete(session.sandbox_id) }
          unless cleanup_errors.empty?
            log("session #{session.vm_id} rolled back after #{error.class}: #{error.message}; cleanup errors: #{cleanup_errors.inspect}")
          end
          raise error
        end

        def create_container(id:, sandbox_id:, spec:, gate:)
          session = session!(sandbox_id)
          result = session.container_create(id, spec)
          @mutex.synchronize { @containers[id] = sandbox_id }
          {"resources" => [{"kind" => "guest_container", "id" => id, "identity" => "guest_container:#{session.vm_id}:#{id}",
                            "metadata" => result}]}
        end

        # The first container start of a sandbox closes the network loop:
        # bridge the Pod veth to the TAP, hand the leased address to the
        # guest with a signed ACK, then open the gate with another one.
        def start_container(id:, gate:)
          session = session_for_container!(id)
          unless session.gate_open?
            network = @network_device ? finalize_network(session) : nil
            session.open_gate!(network: network)
          end
          result = session.container_start(id)
          session.timings["guest_container_start_profile"] = result["profile"] if result.is_a?(Hash) && result["profile"]
          true
        end

        def release_workload_gate(id:, sandbox_id:)
          true
        end

        # A container in a microVM cannot outlive its VM: if the VMM is gone
        # the container is already stopped (nothing to ask the guest); a
        # hung/unreachable guest raises AmbiguousResult so the façade marks
        # the container StateUnknown for host-side reconciliation.
        def stop_container(id:, timeout:)
          session = session_for_container!(id)
          return true unless session.alive?

          session.container_stop(id, timeout: timeout)
          true
        end

        def remove_container(id:)
          session = session_for_container!(id)
          session.container_remove(id) if session.alive?
          @mutex.synchronize { @containers.delete(id) }
          true
        end

        def container_status(id:)
          session = session_for_container!(id)
          raise Error, "microVM for container #{id} is not running" unless session.alive?

          session.container_status(id)
        end

        # Crash-recovery reconciliation for a sandbox whose VM is dead, hung
        # or unreachable (spec 5.8.14 State=Unknown => CleanupOrObserve):
        # kill the VMM through the pidfd and release every owned host
        # resource in reverse order, bypassing the guest.  Returns the
        # cleanup errors (empty on success).
        def force_teardown(sandbox_id)
          session = @mutex.synchronize { @sessions[sandbox_id] }
          return [] if session.nil?

          errors = session.cleanup!(identity_ledger: @identity_ledger)
          @mutex.synchronize do
            @sessions.delete(sandbox_id)
            @containers.delete_if { |_container, owner| owner == sandbox_id }
            @networks.delete(sandbox_id)
          end
          errors
        end

        def stats(id:)
          session_for_container!(id).container_stats(id)
        end

        def exec(id:, cmd:, tty:, request_id:)
          session_for_container!(id).open_stream("exec", id, cmd: cmd, tty: tty, stdin: true)
        end

        def attach(id:, tty:, request_id:)
          session_for_container!(id).open_stream("attach", id, tty: tty, stdin: true)
        end

        def logs(id:, follow:, since:, tail:, request_id:)
          session = session_for_container!(id)
          return session.open_stream("logs", id, since: since, tail: tail) if follow

          StringIO.new(session.logs(id, since: since, tail: tail))
        end

        def stop_sandbox(id:, timeout:)
          session = session!(id)
          begin
            session.sandbox_stop(timeout: timeout) if session.alive?
          rescue Error, ::Rubernetes::Runtime::AmbiguousResult => error
            log("sandbox.stop guest call failed: #{error.message}")
          end
          session.kill!
          true
        end

        def remove_sandbox(id:)
          session = session!(id)
          errors = begin
            session.cleanup!(identity_ledger: @identity_ledger)
          rescue StandardError => error
            [{"error" => "#{error.class}: #{error.message}", "backtrace" => error.backtrace.first(4)}]
          end
          @mutex.synchronize do
            @sessions.delete(id)
            @containers.delete_if { |_container, sandbox| sandbox == id }
            @networks.delete(id)
          end
          raise Error, "sandbox #{id} cleanup errors: #{errors.map { |entry| entry["error"] }.join("; ")}" unless errors.empty?

          true
        end

        # Base snapshot: a fresh VM with no identity and placeholder drives,
        # quiesced through pause.prepare, paused and snapshotted.
        def checkpoint_base(runtime_class:, state:)
          raise Error, "checkpoint_base requires WorkloadStopped" unless state == "WorkloadStopped"

          @verified ||= @artifacts.verify!
          base_id = "base-#{@clock.call.strftime("%Y%m%dT%H%M%S")}-#{SecureRandom.hex(4)}"
          identity = @identity_ledger.allocate(sandbox_id: "base:#{base_id}", runtime_class: runtime_class,
                                               artifact_digest: @artifacts.digest, policy_digest: "base")
          session = VMSession.new(sandbox_id: "base:#{base_id}", identity: identity, artifacts: @artifacts, jailer: @jailer, verity: @verity, netns: @netns,
                                  disks: @disks, pool: @pool, broker: nil, clock: @clock, logger: @logger, machine: @machine,
                                  network_device: @network_device, run_root: @run_root)
          begin
            session.allocate_workspace(images: [], workspace_mib: ImageDisks::PLACEHOLDER_MIB)
            session.create_isolation(base: nil)
            base = session.snapshot_base!(id: base_id, runtime_class: runtime_class)
            {"snapshot_id" => base.id, "artifact_digest" => @artifacts.digest, "manifest" => base.manifest, "timings" => session.timings}
          ensure
            session.cleanup!(identity_ledger: @identity_ledger)
          end
        end

        # -------------------------------------------------------- observation

        def network_sandbox_context(sandbox_id)
          session!(sandbox_id).network_context
        end

        def session(sandbox_id)
          @mutex.synchronize { @sessions[sandbox_id] }
        end

        # Kernel/host-side inventory used by crash recovery: jails, network
        # namespaces, verity mappings, workspaces and live identities, each
        # with its stable identity.
        def list_resources
          resources = []
          @jailer.list_jails.each do |jail|
            chroot = @jailer.chroot_for(jail)
            resources << {"kind" => "jail", "id" => jail, "identity" => "jail:#{File.stat(chroot).ino}"} if File.directory?(chroot)
          end
          @netns.list.each { |handle| resources << {"kind" => "netns", "id" => handle.name, "identity" => "netns:#{handle.inode}"} }
          @disks.workspaces.each do |workspace|
            path = File.join(@disks.root, "workspaces", "#{workspace}.ext4")
            resources << {"kind" => "workspace", "id" => workspace, "identity" => "workspace:#{workspace}:#{File.stat(path).ino}"}
          end
          @identity_ledger.live.each do |record|
            resources << {"kind" => "identity", "id" => record.vm_id, "identity" => "identity:#{record.vm_id}"}
            name = "rbn-#{record.vm_id}"
            resources << {"kind" => "verity", "id" => name, "identity" => "verity:#{@verity.uuid_for(name)}"} if @verity.active?(name)
          end
          resources
        end

        def cleanup_resource(resource)
          kind = resource["kind"] || resource[:kind]
          id = resource["id"] || resource[:id]
          case kind
          when "jail" then @jailer.remove_jail(id)
          when "netns" then @netns.destroy(id)
          when "tap"
            netns_name, tap = id.to_s.split("/", 2)
            @netns.within(netns_name) { Tap.destroy(tap) } if @netns.handle(netns_name)
          when "verity" then @verity.close(id)
          when "workspace" then @disks.remove_workspace(id)
          when "identity" then @identity_ledger.release(id)
          when "vmm"
            session = @sessions.values.find { |candidate| candidate.vm_id == id }
            session&.kill!
          end
          true
        end

        private

        def session!(sandbox_id)
          session = @mutex.synchronize { @sessions[sandbox_id] }
          raise Error, "unknown microVM sandbox #{sandbox_id}" if session.nil?

          session
        end

        def session_for_container!(id)
          sandbox_id = @mutex.synchronize { @containers[id] }
          raise Error, "unknown microVM container #{id}" if sandbox_id.nil?

          session!(sandbox_id)
        end

        def machine_for(config)
          machine = (@machine || {}).dup
          overhead = config["microvm"] || {}
          machine["vcpu_count"] = Integer(overhead["vcpu_count"]) if overhead["vcpu_count"]
          machine["mem_size_mib"] = Integer(overhead["mem_size_mib"]) if overhead["mem_size_mib"]
          machine
        end

        def policy_digest(config)
          Digest::SHA256.hexdigest(JSON.generate(broker_policy(config)))
        end

        def broker_policy(config)
          policy = config["broker_policy"] || config.dig("metadata", "annotations", "rubernetes.io/broker-policy")
          policy = JSON.parse(policy) if policy.is_a?(String)
          policy.is_a?(Hash) ? policy : {"operations" => [], "allowed_hosts" => [], "allowed_cidrs" => [], "allowed_ports" => []}
        end

        def injected_files(config)
          Array(config["injected_files"]).map do |entry|
            {"path" => "/run/rubernetes/files/#{entry.fetch("name")}", "content" => entry.fetch("content"),
             "mode" => entry["mode"] || 0o600}
          end
        end

        def sandbox_input(config, sandbox_id)
          input = JSON.parse(JSON.generate(config))
          input["id"] = sandbox_id
          input.delete("injected_files")
          input.delete("broker_policy")
          input
        end

        # Bridge the veth peer (pod_ifname) to the TAP inside the sandbox
        # namespace and hand the leased address to the guest.  The lease is
        # read from inside the namespace (getifaddrs and the routing table
        # are namespace-scoped); the bridge, master and address changes go
        # through rtnetlink targeted at the namespace FD.
        def finalize_network(session)
          handle = session.netns_handle
          lease = @netns.within(handle.name) { read_pod_lease(POD_IFNAME) }
          raise NetworkError, "sandbox namespace has no #{POD_IFNAME}: the network layer did not connect the Pod" unless lease["present"]
          raise NetworkError, "#{POD_IFNAME} carries no leased IPv4 address" if lease["ip"].nil?

          netlink = @netlink || Network::Netlink.new
          File.open(handle.path, File::RDONLY) do |ns|
            bridge = begin
              netlink.link_state(name: BRIDGE_NAME, namespace_fd: ns)
            rescue StandardError
              nil
            end
            netlink.link_add(name: BRIDGE_NAME, kind: "bridge", up: true, namespace_fd: ns) if bridge.nil?
            netlink.address_delete(address: lease["ip"], prefix: lease["prefix_length"], name: POD_IFNAME, namespace_fd: ns)
            netlink.link_set(name: POD_IFNAME, master: BRIDGE_NAME, up: true, namespace_fd: ns)
            netlink.link_set(name: session.tap_name, master: BRIDGE_NAME, up: true, namespace_fd: ns)
          end
          network = {"interface" => "eth0", "ip" => lease["ip"], "prefix_length" => lease["prefix_length"], "gateway" => lease["gateway"],
                     "mac_address" => session.identity.fields["mac_address"], "dns" => Array(@networks.dig(session.sandbox_id, "dns")), "routes" => []}
          @identity_ledger.bind_network(session.vm_id, ip: lease["ip"], gateway: lease["gateway"], prefix_length: lease["prefix_length"])
          network
        end

        # Runs inside the sandbox namespace: the interface's IPv4 lease and
        # the default gateway from the namespace's own routing table.
        def read_pod_lease(ifname)
          entries = Socket.getifaddrs.select { |entry| entry.name == ifname }
          return {"present" => false} if entries.empty?

          ipv4 = entries.find { |entry| entry.addr&.ipv4? }
          ip = ipv4&.addr&.ip_address
          prefix = ipv4&.netmask&.ip_address&.then { |mask| mask.split(".").map(&:to_i).sum { |octet| octet.to_s(2).count("1") } }
          gateway = nil
          File.foreach("/proc/net/route").drop(1).each do |line|
            fields = line.split
            next unless fields[0] == ifname && fields[1] == "00000000"

            gateway = [fields[2].to_i(16)].pack("L<").unpack("C4").join(".")
          end
          {"present" => true, "ip" => ip, "prefix_length" => prefix, "gateway" => gateway}
        end

        def log(message)
          @logger&.warn("microvm", message: message)
        end
      end
    end
  end
end
