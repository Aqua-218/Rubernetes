# frozen_string_literal: true

require "base64"
require "digest"
require "fileutils"
require "json"
require "securerandom"
require "socket"
require "time"

require_relative "api_client"
require_relative "errors"
require_relative "framing"
require_relative "jailer"
require_relative "vsock_client"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # One microVM instance on the host: its jail, VMM, vsock control
      # channel, identity record and owned resources.  The session performs
      # every effect in the order the specification fixes and keeps the
      # workload gate closed until the guest's signed ACKs for the identity
      # and for the gate have been verified.
      class VMSession
        CONTROL_PORT = 5000
        STREAM_PORT = 5001
        BROKER_PORT = 7000
        DEFAULT_MACHINE = {"vcpu_count" => 1, "mem_size_mib" => 512}.freeze
        BOOT_ARGS = "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/rubernetes-init root=/dev/vda ro"

        Stream = Struct.new(:socket, :kind, :container_id, keyword_init: true) do
          def read(_length = nil, _outbuf = nil)
            frame = next_frame
            return nil if frame.nil?

            frame.last
          end

          def readpartial(_length = nil)
            frame = next_frame
            raise EOFError, "stream closed" if frame.nil?

            frame.last
          end

          def write(bytes)
            socket.write([bytes.bytesize + 1].pack("N") + [0].pack("C") + bytes.b)
            bytes.bytesize
          end

          def close_write
            socket.write([1].pack("N") + [0].pack("C"))
          end

          def close
            socket.close unless socket.closed?
          end

          attr_reader :exit_code

          def next_frame
            header = socket.read(4)
            return nil if header.nil?

            length = header.unpack1("N")
            raise FramingError, "stream frame exceeds #{Framing::MAX_FRAME_BYTES} bytes" if length > Framing::MAX_FRAME_BYTES

            body = socket.read(length)
            return nil if body.nil?

            channel = body.getbyte(0)
            payload = body.byteslice(1, body.bytesize)
            if channel == 3
              @exit_code = CBOR.decode(payload)["exit_code"]
              return nil
            end
            [channel, payload]
          end

          def to_h
            {"kind" => kind, "container_id" => container_id}
          end
        end

        attr_reader :sandbox_id, :identity, :instance, :resources, :phase, :base, :machine, :drive_layout, :netns_handle, :tap_name,
                    :verity_mapping, :guest_hello, :log_path, :acks, :timings

        def initialize(sandbox_id:, identity:, artifacts:, jailer:, verity:, netns:, disks:, pool:, broker:, clock:, run_root:, logger: nil,
                       machine: DEFAULT_MACHINE,
                       network_device: true)
          @sandbox_id = sandbox_id
          @identity = identity
          @artifacts = artifacts
          @jailer = jailer
          @verity = verity
          @netns = netns
          @disks = disks
          @pool = pool
          @broker = broker
          @clock = clock
          @logger = logger
          @machine = DEFAULT_MACHINE.merge(machine || {})
          @network_device = network_device
          @run_root = run_root
          @resources = []
          @phase = "new"
          @control = nil
          @control_mutex = Mutex.new
          @acks = {}
          @timings = {}
          @broker_thread = nil
          @broker_listener = nil
          @drive_layout = nil
          @workspace_path = nil
          @image_disks = []
          @tap_name = "tap0"
        end

        # Unix socket paths are limited to 108 bytes: the jail id and the
        # vsock socket name stay short (the VM id keeps them unique).
        MAX_UNIX_PATH_BYTES = 107

        def vm_id = identity.vm_id
        def jail_id = "j#{identity.fields.fetch("jail_uid")}-#{vm_id.delete_prefix("vm-")[0, 8]}"
        def uid = identity.fields.fetch("jail_uid")
        def gid = identity.fields.fetch("jail_gid")
        def vsock_jail_path = "/run/v.sock"
        def vsock_host_path = instance.host_path(vsock_jail_path)
        def netns_name = "vm-#{vm_id}"

        # ------------------------------------------------------- workspace

        def allocate_workspace(images:, workspace_mib: nil)
          measure(:workspace) do
            @workspace_path = @disks.workspace_disk(identity.fields.fetch("workspace_id"),
                                                    **(workspace_mib ? {size_mib: workspace_mib} : {}))
            claim("workspace", identity.fields.fetch("workspace_id"), "workspace:#{identity.fields.fetch("workspace_id")}:#{File.stat(@workspace_path).ino}",
                  {"path" => @workspace_path})
            raise Error, "at most #{ImageDisks::MAX_IMAGE_DRIVES} distinct images per microVM" if images.length > ImageDisks::MAX_IMAGE_DRIVES

            @image_disks = images.map do |image|
              {"digest" => image.fetch("digest"), "path" => @disks.image_disk(image.fetch("digest"), image.fetch("rootfs"))}
            end
            @image_disks.each { |disk| @disks.grant_read(disk["path"], uid) }
            unless @image_disks.empty?
              claim("image_grants", vm_id, "image_grants:#{vm_id}", {"paths" => @image_disks.map do |disk|
                disk["path"]
              end})
            end
            claim("identity", vm_id, "identity:#{vm_id}", {"jail_uid" => uid, "guest_cid" => identity.fields["guest_cid"]})
            @phase = "workspace"
          end
        end

        # ------------------------------------------------------- isolation

        # Creates the network namespace, TAP, verity mapping and jail, then
        # restores the base snapshot (or cold-boots when none exists) and
        # waits for the guest supervisor's hello.
        def create_isolation(base: nil)
          measure(:isolation) do
            @base = base
            handle = measure(:netns) { @netns.create(netns_name) }
            @netns_handle = handle
            claim("netns", netns_name, "netns:#{handle.inode}", handle.to_h)
            if @network_device
              measure(:tap) do
                @netns.within(netns_name) do
                  Tap.create(@tap_name, owner_uid: uid, owner_gid: gid)
                  Tap.up!(@tap_name)
                end
              end
              claim("tap", "#{netns_name}/#{@tap_name}", "tap:#{handle.inode}:#{@tap_name}", {"netns" => netns_name})
            end
            mapping = measure(:verity) do
              @verity.open(verity_name, @artifacts.path(:rootfs), @artifacts.path(:verity_hash), @artifacts.verity_root_hash)
            end
            @verity_mapping = mapping
            claim("verity", verity_name, "verity:#{mapping.uuid}", mapping.to_h)
            @drive_layout = build_drive_layout
            inputs = {"/vmlinux" => @artifacts.path(:kernel), "/drives/rootfs" => mapping.device}
            @drive_layout.each do |drive|
              next if drive["id"] == "rootfs"

              inputs[drive["jail_path"]] = {"path" => drive["host_path"], "writable" => drive["writable"] || drive["placeholder"]}
            end
            if base
              inputs["/snapshot/mem"] = base.mem_path
              inputs["/snapshot/vmstate"] = base.vmstate_path
            end
            candidate = File.join(@jailer.chroot_for(jail_id), "run", "v.sock_#{BROKER_PORT}")
            if candidate.bytesize > MAX_UNIX_PATH_BYTES
              raise JailerError,
                    "jail path #{candidate} exceeds the Unix socket path limit; use a shorter chroot base"
            end

            measure(:jail_prepare) { @jailer.prepare(id: jail_id, uid: uid, gid: gid, inputs: inputs) }
            claim("jail", jail_id, "jail:#{File.stat(@jailer.chroot_for(jail_id)).ino}", {"chroot" => @jailer.chroot_for(jail_id)})
            @log_path = File.join(@run_root, "#{vm_id}.log")
            @instance = measure(:jailer_launch) do
              @jailer.launch(id: jail_id, uid: uid, gid: gid, netns_path: handle.path, cgroup_limits: cgroup_limits, log_path: @log_path)
            end
            claim("vmm", vm_id, @instance.identity, @instance.to_h.slice("vmm_pid", "vmm_start_time", "cgroup_path"))
            api = APIClient.new(@instance.api_socket)
            if base
              restore_from_base!(api, base)
            else
              cold_boot!(api)
            end
            measure(:seccomp_verify) { @jailer.verify_seccomp!(@instance) }
            @phase = "booted"
            start_broker_listener
            if base
              # A restored guest is the base's guest: its hello is the one
              # recorded in the manifest, and the identity ACK that follows
              # proves liveness and phase.
              @guest_hello = base.manifest.fetch("guest_hello")
            else
              @guest_hello = measure(:hello) { control.call("hello") }
              unless @guest_hello["phase"] == "base"
                raise ProtocolError,
                      "guest supervisor answered from phase #{@guest_hello["phase"]}, expected base"
              end
            end

            @phase = "hello"
            @guest_hello
          end
        end

        # ------------------------------------------------------- resources

        # Injects the identity (everything except the network address, which
        # the network layer leases later) and verifies the signed ACK.
        def attach_resources(files: [], host_time: nil)
          measure(:identity) do
            nonce = SecureRandom.hex(16)
            payload = {
              "identity" => guest_identity_view,
              "session_key" => identity.fields.fetch("vsock_session_key"),
              "nonce" => nonce,
              "host_time" => (host_time || @clock.call).to_f,
              "workspace" => {"device" => "/dev/vdb"},
              "images" => @image_disks.each_with_index.map do |disk, index|
                {"digest" => disk["digest"], "device" => "/dev/vd#{(99 + index).chr}"}
              end,
              "files" => files
            }
            response = measure(:identity_call) { control.call("identity.apply", payload) }
            @timings["identity_guest"] = response["timings"] if response.is_a?(Hash) && response["timings"]
            verify_ack!(response, "identity.apply", nonce)
            raise ProtocolError, "guest applied the identity from phase #{response.dig("ack", "phase")}" unless response.dig("ack",
                                                                                                                             "phase") == "identified"

            @acks["identity.apply"] = response
            @phase = "identified"
            response["ack"]
          end
        end

        def hold_workload
          control.call("gate.hold")
          @phase = "workload_stopped"
          {"gate" => "closed"}
        end

        # Binds the leased Pod address to the guest (second signed ACK) and
        # then opens the gate (third signed ACK).  The bridge in the sandbox
        # namespace hands the veth traffic to the TAP.
        def open_gate!(network: nil)
          measure(:gate) do
            if @network_device
              raise NetworkError, "the Pod network was not connected before the first container start" if network.nil?

              nonce = SecureRandom.hex(16)
              response = control.call("identity.network", {"nonce" => nonce, "network" => network})
              verify_ack!(response, "identity.network", nonce)
              @acks["identity.network"] = response
            end
            nonce = SecureRandom.hex(16)
            response = control.call("gate.open", {"nonce" => nonce, "policy_digest" => identity.fields.fetch("policy_digest"),
                                                  "revocation_epoch" => identity.fields.fetch("revocation_epoch")})
            verify_ack!(response, "gate.open", nonce)
            raise GateError, "guest reports gate #{response.dig("ack", "gate")}" unless response.dig("ack", "gate") == "open"

            @acks["gate.open"] = response
            @phase = "running"
            response["ack"]
          end
        end

        def gate_open?
          @phase == "running"
        end

        # ------------------------------------------------------- workloads

        def sandbox_run(input)
          control.call("sandbox.run",
                       {"sandbox_id" => sandbox_id, "input" => input, "request_id" => "sandbox:#{sandbox_id}", "profile" => profile?})
        end

        def profile?
          ENV["RUBERNETES_MICROVM_PROFILE"] == "1"
        end

        def container_create(id, spec)
          control.call("container.create", {"sandbox_id" => sandbox_id, "id" => id, "spec" => spec, "request_id" => "create:#{id}"})
        end

        def container_start(id)
          control.call("container.start", {"id" => id, "request_id" => "start:#{id}", "profile" => profile?})
        end

        def container_stop(id, timeout:)
          control.call("container.stop", {"id" => id, "timeout" => timeout, "request_id" => "stop:#{id}"})
        end

        def container_remove(id)
          control.call("container.remove", {"id" => id, "request_id" => "remove:#{id}"})
        end

        def container_status(id)
          control.call("container.status", {"id" => id})
        end

        def container_stats(id)
          control.call("container.stats", {"id" => id})
        end

        def container_wait(id, timeout: nil)
          control.call("container.wait", {"id" => id, "timeout" => timeout}, timeout: timeout ? timeout + 5 : 3600)
        end

        def sandbox_stop(timeout:)
          control.call("sandbox.stop", {"sandbox_id" => sandbox_id, "timeout" => timeout})
        end

        def logs(id, since: nil, tail: nil, stream: "stdout")
          response = control.call("logs", {"id" => id, "since" => since, "tail" => tail, "stream" => stream})
          Base64.strict_decode64(response.fetch("bytes"))
        end

        def open_stream(kind, id, cmd: nil, tty: false, stdin: false, since: nil, tail: nil)
          response = control.call("stream.open",
                                  {"kind" => kind, "id" => id, "cmd" => cmd, "tty" => tty, "stdin" => stdin, "since" => since,
                                   "tail" => tail})
          socket = VsockClient.connect(vsock_host_path, STREAM_PORT)
          Framing.write_frame(socket, {"token" => response.fetch("token")})
          Stream.new(socket: socket, kind: kind, container_id: id)
        end

        def probe_http(url, timeout: 1.0)
          control.call("probe.http", {"url" => url, "timeout" => timeout})
        end

        def probe_tcp(host, port, timeout: 1.0)
          control.call("probe.tcp", {"host" => host, "port" => port, "timeout" => timeout})
        end

        def attack_matrix(targets)
          control.call("attack.matrix", {"targets" => targets})
        end

        # -------------------------------------------------------- snapshot

        # Base snapshot: pause.prepare must be acknowledged before the VMM
        # is paused; a lost connection in between is SnapshotPauseUnknown.
        def snapshot_base!(id:, runtime_class:)
          nonce = SecureRandom.hex(16)
          ack = begin
            control.call("pause.prepare", {"nonce" => nonce})
          rescue ResponseLost, VsockError, FramingError => error
            @phase = "pause_unknown"
            raise SnapshotPauseUnknown, "pause ACK was not received: #{error.message}"
          end
          raise SnapshotPauseUnknown, "pause ACK nonce mismatch" unless ack.is_a?(Hash) && ack.dig("ack", "nonce") == nonce

          close_control
          api = APIClient.new(@instance.api_socket)
          api.pause!
          api.snapshot_create!(snapshot_path: "/snapshot/vmstate", mem_file_path: "/snapshot/mem")
          @phase = "snapshotted"
          @pool.store(id: id, runtime_class: runtime_class, mem_path: @instance.host_path("/snapshot/mem"),
                      vmstate_path: @instance.host_path("/snapshot/vmstate"),
                      artifact_digest: @artifacts.digest,
                      drive_layout: @drive_layout.map { |drive| drive.slice("id", "jail_path", "read_only", "root") },
                      machine: @machine, guest_hello: @guest_hello, pause_ack: ack["ack"])
        end

        # ---------------------------------------------------------- teardown

        def alive?
          @instance && @jailer.alive?(@instance)
        end

        def kill!
          return false unless @instance

          close_control
          stop_broker_listener
          @jailer.kill(@instance)
          @phase = "stopped"
          true
        end

        # Releases every owned resource in reverse acquisition order and
        # returns the cleanup errors without hiding the first failure.
        def cleanup!(identity_ledger: nil)
          errors = []
          begin
            kill! if alive?
          rescue StandardError => error
            errors << {"resource" => {"kind" => "vmm"}, "error" => "#{error.class}: #{error.message}"}
          end
          stop_broker_listener
          @resources.reverse_each do |resource|
            release_resource(resource)
          rescue StandardError => error
            errors << {"resource" => resource.slice("kind", "id"), "error" => "#{error.class}: #{error.message}"}
          end
          @broker&.unbind(vm_id)
          identity_ledger&.release(vm_id)
          @phase = "removed"
          errors
        end

        def release_resource(resource)
          case resource["kind"]
          when "vmm"
            @jailer.kill(@instance) if @instance && @jailer.alive?(@instance)
            @jailer.remove_cgroup(@instance) if @instance
          when "jail" then @jailer.remove_jail(jail_id)
          when "verity" then @verity.close(verity_name)
          when "tap" then @netns.within(netns_name) { Tap.destroy(@tap_name) } if @netns.handle(netns_name)
          when "netns" then @netns.destroy(netns_name)
          when "workspace" then @disks.remove_workspace(identity.fields.fetch("workspace_id"))
          when "image_grants" then @image_disks.each { |disk| @disks.revoke_read(disk["path"], uid) }
          when "identity" then nil
          end
        end

        def to_h
          {"vm_id" => vm_id, "sandbox_id" => sandbox_id, "phase" => @phase, "jail_id" => jail_id, "instance" => @instance&.to_h, "resources" => @resources,
           "base" => @base&.id, "timings" => @timings, "acks" => @acks.transform_values { |value| value["ack"] }}
        end

        def network_context
          return {"sandbox_id" => sandbox_id} unless @netns_handle

          {"sandbox_id" => sandbox_id,
           "netns" => {"handle" => @netns_handle.name, "path" => @netns_handle.path, "inode" => @netns_handle.inode}}
        end

        def confinement_report
          @instance ? @jailer.confinement_report(@instance) : nil
        end

        private

        def verity_name = "rbn-#{vm_id}"

        def cgroup_limits
          limits = {"pids.max" => 512}
          limits["memory.max"] = (@machine["mem_size_mib"] + 256) * 1024 * 1024
          limits
        end

        def build_drive_layout
          layout = [{"id" => "rootfs", "jail_path" => "/drives/rootfs", "host_path" => nil, "read_only" => true, "root" => true}]
          layout << {"id" => "workspace", "jail_path" => "/drives/workspace.ext4", "host_path" => @workspace_path, "read_only" => false,
                     "root" => false, "writable" => true}
          ImageDisks::MAX_IMAGE_DRIVES.times do |index|
            disk = @image_disks[index]
            layout << {"id" => "image#{index}", "jail_path" => "/drives/image#{index}.ext4", "host_path" => disk ? disk["path"] : @disks.placeholder(index),
                       "read_only" => true, "root" => false, "placeholder" => disk.nil?}
          end
          layout
        end

        def cold_boot!(api)
          api.machine_config(vcpu_count: @machine["vcpu_count"], mem_size_mib: @machine["mem_size_mib"])
          api.boot_source(kernel_image_path: "/vmlinux", boot_args: BOOT_ARGS)
          @drive_layout.each do |drive|
            api.drive(drive_id: drive["id"], path_on_host: drive["jail_path"], is_root_device: drive["root"],
                      is_read_only: drive["read_only"])
          end
          api.vsock(guest_cid: identity.fields.fetch("guest_cid"), uds_path: vsock_jail_path)
          if @network_device
            api.network_interface(iface_id: "eth0", host_dev_name: @tap_name,
                                  guest_mac: identity.fields.fetch("mac_address"))
          end
          measure(:vmm_start) { api.start! }
        end

        def restore_from_base!(api, _base)
          overrides = @network_device ? [{"iface_id" => "eth0", "host_dev_name" => @tap_name}] : []
          measure(:snapshot_load) do
            api.snapshot_load!(snapshot_path: "/snapshot/vmstate", mem_file_path: "/snapshot/mem", resume_vm: false,
                               network_overrides: overrides, vsock_uds_path: vsock_jail_path)
          end
          # The drive files behind the snapshot's slots were replaced with
          # this VM's workspace and images; refresh their capacity.  Slots
          # that still carry the base placeholder are left untouched.
          measure(:drive_patch) do
            @drive_layout.each do |drive|
              next if drive["root"] || drive["placeholder"]

              started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              api.patch_drive(drive_id: drive["id"], path_on_host: drive["jail_path"])
              @timings["drive_patch_#{drive["id"]}"] = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(4)
            end
          end
          # Open the control connection while the VM is still paused: the
          # CONNECT handshake completes as soon as the guest runs again, so
          # no polling delay follows the resume.
          pending = measure(:vsock_preconnect) { VsockClient.preconnect(vsock_host_path, CONTROL_PORT) }
          measure(:vmm_resume) { api.resume! }
          @control_mutex.synchronize { @control = Channel.new(VsockClient.complete(pending, CONTROL_PORT, timeout: 30.0), timeout: Framing::RESPONSE_TIMEOUT) }
        end

        def guest_identity_view
          identity.fields.slice("vm_id", "sandbox_id", "runtime_class", "subject_id", "capability_id", "request_id", "entropy", "hostname", "machine_id",
                                "mac_address", "workspace_id", "credential_id", "policy_digest", "policy_generation", "artifact_digest", "revocation_epoch")
        end

        def control
          @control_mutex.synchronize do
            raise VsockError, "VM #{vm_id} is not booted" if @instance.nil?

            @control = nil if @control&.closed?
            @control ||= VsockClient.channel(vsock_host_path, CONTROL_PORT, timeout: 30.0)
          end
        end

        def close_control
          @control_mutex.synchronize do
            @control&.close
            @control = nil
          end
        end

        def verify_ack!(response, kind, nonce)
          raise ProtocolError, "#{kind}: guest returned no ACK" unless response.is_a?(Hash) && response["ack"].is_a?(Hash)

          fields = response["ack"]
          key = [identity.fields.fetch("vsock_session_key")].pack("H*")
          raise IdentityError, "#{kind}: ACK signature invalid" unless Signature.valid?(key, fields, response["signature"])
          raise IdentityError, "#{kind}: ACK nonce mismatch" unless fields["nonce"] == nonce
          raise IdentityError, "#{kind}: ACK VM identity mismatch (#{fields["vm_id"]})" unless fields["vm_id"] == vm_id
          unless fields["policy_digest"] == identity.fields.fetch("policy_digest")
            raise IdentityError,
                  "#{kind}: ACK policy digest mismatch"
          end
          raise IdentityError, "#{kind}: ACK kind mismatch" unless fields["kind"] == kind

          true
        end

        def start_broker_listener
          return if @broker.nil?

          @broker_listener = VsockClient.listener(vsock_host_path, BROKER_PORT)
          @broker_thread = Thread.new { @broker.serve(@broker_listener, vm_id) }
        end

        def stop_broker_listener
          @broker_listener&.close
          @broker_listener = nil
          @broker_thread&.kill
          @broker_thread = nil
        rescue IOError
          nil
        end

        def claim(kind, id, identity_value, metadata = {})
          @resources << {"kind" => kind, "id" => id, "identity" => identity_value, "metadata" => metadata}
        end

        def measure(name)
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = yield
          @timings[name.to_s] = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(4)
          result
        end
      end
    end
  end
end
