# frozen_string_literal: true

# The Ruby guest supervisor: PID 1 inside a Rubernetes microVM
# (spec/node/runtime.md 5.8.11-5.8.13).  It owns the guest side of the
# vsock protocol, applies the identity the host injects after a restore,
# keeps the workload gate closed until the host verifies the signed ACK,
# and runs the Pod's containers with the Native backend (namespaces,
# cgroup v2, seccomp, Landlock) inside the guest.  It never holds host,
# registry or cluster credentials; everything it knows arrives through the
# identity injection and is discarded on the next one.

require "English"
require "base64"
require "digest"
require "fiddle"
require "fileutils"
require "json"
require "securerandom"
require "socket"
require "stringio"
require "timeout"

require_relative "../cbor"
require_relative "../framing"
require_relative "../errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      module Guest
        class Supervisor
          VERSION = "1"
          CONTROL_PORT = 5000
          STREAM_PORT = 5001
          BROKER_PORT = 7000
          HOST_CID = 2
          VMADDR_CID_ANY = 0xFFFFFFFF
          STREAM_STDIN = 0
          STREAM_STDOUT = 1
          STREAM_STDERR = 2
          STREAM_EXIT = 3
          MAX_STREAM_CHUNK = 64 * 1024
          RNDADDENTROPY = 0x40085203
          SYS_CLOCK_SETTIME = 227
          CLOCK_REALTIME = 0

          State = Struct.new(:phase, :identity, :session_key, :gate, :policy_digest, :network, keyword_init: true)

          # +prepare_filesystem+ mounts the base pseudo filesystems (guest
          # boot); +reap+ is only for a PID 1 that owns no runtime children
          # (the guest init keeps PID 1 as a plain orphan reaper and runs the
          # supervisor as its child so the Native backend's waitpid calls are
          # never raced by a generic reaper).
          def initialize(state_root: "/var/lib/rubernetes", log: $stdout, native_factory: nil, images_root: nil,
                         prepare_filesystem: Process.pid == 1, reap: false)
            @state_root = state_root
            @images_root = images_root || File.join(state_root, "images")
            @log = log
            @native_factory = native_factory
            @pid1 = prepare_filesystem
            @reap = reap
            @state = State.new(phase: "base", identity: nil, session_key: nil, gate: "closed", policy_digest: nil, network: nil)
            @boot_nonce = SecureRandom.hex(16)
            @mutex = Mutex.new
            @native = nil
            @sandboxes = {}
            @streams = {}
            @mounted = []
            @isolation_profile = nil
          end

          attr_reader :state, :boot_nonce

          # ------------------------------------------------------------ boot

          def run!
            prepare_root_filesystem! if @pid1
            log("boot ruby=#{RUBY_VERSION} kernel=#{kernel_release} pid=#{Process.pid}")
            prewarm_native
            Thread.new { reap_loop } if @reap
            Thread.new { serve_streams }
            Thread.new { serve_broker_endpoint }
            log("vsock listening control=#{CONTROL_PORT} stream=#{STREAM_PORT}")
            serve_control
          end

          def prepare_root_filesystem!
            mount("proc", "/proc", "proc")
            mount("sysfs", "/sys", "sysfs")
            mount("devtmpfs", "/dev", "devtmpfs") unless File.exist?("/dev/vsock")
            FileUtils.mkdir_p("/dev/pts")
            mount("devpts", "/dev/pts", "devpts", "gid=5,mode=620,ptmxmode=666")
            FileUtils.mkdir_p("/dev/shm")
            mount("tmpfs", "/dev/shm", "tmpfs")
            mount("tmpfs", "/run", "tmpfs")
            mount("tmpfs", "/tmp", "tmpfs")
            FileUtils.mkdir_p("/sys/fs/cgroup")
            mount("cgroup2", "/sys/fs/cgroup", "cgroup2", "nsdelegate") unless File.exist?("/sys/fs/cgroup/cgroup.controllers")
            enable_cgroup_controllers
            mount("securityfs", "/sys/kernel/security", "securityfs") unless File.exist?("/sys/kernel/security/lsm")
            mount("tmpfs", "/var/lib", "tmpfs") unless File.writable?("/var/lib")
            FileUtils.mkdir_p(@state_root)
            FileUtils.mkdir_p("/run/rubernetes")
          end

          def enable_cgroup_controllers
            controllers = File.read("/sys/fs/cgroup/cgroup.controllers").split
            File.write("/sys/fs/cgroup/cgroup.subtree_control", controllers.map { |name| "+#{name}" }.join(" ")) unless controllers.empty?
          rescue SystemCallError => error
            log("cgroup subtree_control: #{error.message}")
          end

          # ---------------------------------------------------------- servers

          def vsock_listener(port)
            socket = Socket.new(Socket::AF_VSOCK, Socket::SOCK_STREAM, 0)
            socket.bind([Socket::AF_VSOCK, 0, port, VMADDR_CID_ANY, 0].pack("SSLLL"))
            socket.listen(16)
            socket
          end

          def serve_control
            listener = vsock_listener(CONTROL_PORT)
            loop do
              client, = listener.accept
              Thread.new(client) do |connection|
                Server.new(connection, method(:handle)).serve
              rescue StandardError => error
                log("control connection error: #{error.class}: #{error.message}")
              ensure
                connection.close unless connection.closed?
              end
            end
          end

          def serve_streams
            listener = vsock_listener(STREAM_PORT)
            loop do
              client, = listener.accept
              Thread.new(client) do |connection|
                hello = Framing.read_frame(connection, timeout: 10)
                stream = @mutex.synchronize { @streams.delete(hello.is_a?(Hash) ? hello["token"] : nil) }
                if stream.nil?
                  Framing.write_frame(connection, {"error" => "unknown stream token"})
                else
                  pump_stream(connection, stream)
                end
              rescue StandardError => error
                log("stream error: #{error.class}: #{error.message}")
              ensure
                connection.close unless connection.closed?
              end
            end
          end

          # ---------------------------------------------------------- handler

          def handle(name, params)
            case name
            when "hello" then hello
            when "identity.apply" then identity_apply(params)
            when "identity.network" then identity_network(params)
            when "gate.open" then gate_open(params)
            when "gate.hold" then gate_hold
            when "pause.prepare" then pause_prepare(params)
            when "sandbox.run" then sandbox_run(params)
            when "sandbox.stop" then sandbox_stop(params)
            when "sandbox.remove" then sandbox_remove(params)
            when "container.create" then container_create(params)
            when "container.start" then container_start(params)
            when "container.stop" then container_stop(params)
            when "container.remove" then container_remove(params)
            when "container.status" then container_status(params)
            when "container.stats" then container_stats(params)
            when "container.wait" then container_wait(params)
            when "logs" then logs(params)
            when "stream.open" then stream_open(params)
            when "probe.http" then probe_http(params)
            when "probe.tcp" then probe_tcp(params)
            when "attack.matrix" then attack_matrix(params)
            else raise ProtocolError, "unknown request #{name}"
            end
          end

          def hello
            {"supervisor_version" => VERSION, "boot_nonce" => @boot_nonce, "phase" => @state.phase, "gate" => @state.gate,
             "isolation_profile" => detect_isolation_profile, "kernel" => kernel_release, "ruby" => RUBY_VERSION,
             "capabilities" => guest_capabilities, "vm_id" => @state.identity && @state.identity["vm_id"]}
          end

          # The host delivers a complete fresh identity.  Every element of the
          # previous identity is discarded first: containers stopped,
          # workspace unmounted, injected files removed, hostname reset.
          def identity_apply(params)
            identity = require_hash(params, "identity")
            session_key = require_string(params, "session_key")
            nonce = require_string(params, "nonce")
            @mutex.synchronize do
              handler_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              timings = {}
              timed = lambda do |name, &block|
                started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
                block.call
                timings[name] = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(4)
              end
              timed.call("discard") { discard_identity! }
              timed.call("time") { apply_time(params["host_time"]) if params["host_time"] }
              timed.call("entropy") { credit_entropy(identity["entropy"]) if identity["entropy"] }
              timed.call("hostname") do
                set_hostname(identity["hostname"]) if identity["hostname"]
                File.write("/run/machine-id", "#{identity["machine_id"]}\n") if identity["machine_id"]
              end
              timed.call("workspace") { mount_workspace(params["workspace"]) if params["workspace"] }
              timed.call("images") { mount_images(Array(params["images"])) }
              timed.call("files") { write_files(Array(params["files"])) }
              @last_identity_timings = timings
              @state.identity = identity
              @state.session_key = [session_key].pack("H*")
              @state.policy_digest = identity["policy_digest"]
              @state.phase = "identified"
              @state.gate = "closed"
              @state.network = nil
              response = nil
              timed.call("ack") { response = ack("identity.apply", nonce) }
              timings["handler_total"] = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - handler_started).round(4)
              response.merge("timings" => timings)
            end
          end

          def identity_network(params)
            nonce = require_string(params, "nonce")
            network = require_hash(params, "network")
            @mutex.synchronize do
              require_phase!(%w[identified networked])
              apply_network(network)
              @state.network = network
              @state.phase = "networked"
              ack("identity.network", nonce)
            end
          end

          def gate_open(params)
            nonce = require_string(params, "nonce")
            @mutex.synchronize do
              require_phase!(%w[identified networked])
              raise GateError, "policy digest mismatch" unless params["policy_digest"] == @state.policy_digest
              raise GateError, "revocation epoch mismatch" unless params["revocation_epoch"] == @state.identity["revocation_epoch"]

              @state.gate = "open"
              ack("gate.open", nonce)
            end
          end

          def gate_hold
            @mutex.synchronize do
              @state.gate = "closed"
              {"gate" => "closed"}
            end
          end

          # Quiesce before the host pauses the VMM for a snapshot: sync every
          # filesystem and close our side after answering.  The host treats a
          # missing ACK as SnapshotPauseUnknown.
          def pause_prepare(params)
            nonce = require_string(params, "nonce")
            @mutex.synchronize do
              raise GateError, "snapshots are taken from the base state only" unless @state.phase == "base" && @sandboxes.empty?

              sync_filesystems
              {"ack" => {"kind" => "pause.prepare", "nonce" => nonce, "boot_nonce" => @boot_nonce}, "close" => true}
            end
          end

          # -------------------------------------------------------- workloads

          def sandbox_run(params)
            input = require_hash(params, "input")
            @mutex.synchronize do
              require_phase!(%w[identified networked])
              started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              runtime = native
              built = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              translated = translate_sandbox_input(input)
              request_id = params["request_id"] || "sandbox:#{params["sandbox_id"]}"
              trace_before = runtime.respond_to?(:trace) ? runtime.trace.length : 0
              profile = nil
              key = with_profile(params["profile"] == true, ->(result) { profile = result }) do
                runtime.run_sandbox(translated, request_id: request_id, id: params["sandbox_id"])
              end
              sandbox = runtime.sandbox(key)
              @sandboxes[params["sandbox_id"]] = sandbox.id
              steps = runtime.respond_to?(:trace) ? runtime.trace.drop(trace_before).map { |event| plain(event) } : []
              {"sandbox_id" => sandbox.id, "state" => sandbox.state.to_s,
               "timings" => {"native_build" => (built - started).round(4), "run_sandbox" => (Process.clock_gettime(Process::CLOCK_MONOTONIC) - built).round(4)},
               "trace" => steps.first(40), "profile" => profile}
            end
          end

          def sandbox_stop(params)
            @mutex.synchronize do
              id = @sandboxes.fetch(params["sandbox_id"]) { return {"sandbox_id" => params["sandbox_id"], "state" => "absent"} }
              native.stop_sandbox(id, timeout: (params["timeout"] || 5).to_f)
              {"sandbox_id" => id, "state" => "stopped"}
            end
          end

          def sandbox_remove(params)
            @mutex.synchronize do
              id = @sandboxes.delete(params["sandbox_id"]) { return {"sandbox_id" => params["sandbox_id"], "state" => "absent"} }
              native.remove_sandbox(id)
              {"sandbox_id" => id, "state" => "removed"}
            end
          end

          def container_create(params)
            @mutex.synchronize do
              require_phase!(%w[identified networked])
              sandbox_id = @sandboxes.fetch(params["sandbox_id"]) { raise ProtocolError, "unknown sandbox #{params["sandbox_id"]}" }
              spec = translate_container_spec(require_hash(params, "spec"))
              container = native.create_container(sandbox_id, spec, id: params["id"], request_id: params["request_id"])
              {"id" => container.id, "state" => container.state.to_s}
            end
          end

          def container_start(params)
            @mutex.synchronize do
              raise GateError, "workload gate is closed" unless @state.gate == "open"

              profile = nil
              container = with_profile(params["profile"] == true, ->(result) { profile = result }) do
                native.start_container(params["id"], request_id: params["request_id"])
              end
              {"id" => container.id, "state" => container.state.to_s, "profile" => profile}
            end
          end

          # Method self-time profile (TracePoint) of one guest operation,
          # returned to the host on request; a diagnostic for latency work.
          def with_profile(enabled, sink)
            return yield unless enabled

            stack = []
            totals = Hash.new(0.0)
            tracer = TracePoint.new(:call, :return) do |event|
              if event.event == :call
                stack << ["#{event.defined_class}##{event.method_id}", Process.clock_gettime(Process::CLOCK_MONOTONIC), 0.0]
              else
                name, started, child = stack.pop
                next unless name

                elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
                totals[name] += elapsed - child
                stack.last[2] += elapsed if stack.last
              end
            end
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            tracer.enable
            begin
              result = yield
            ensure
              tracer.disable
            end
            sink.call({"total" => (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(4),
                       "top" => totals.sort_by { |_, value| -value }.first(15).map { |name, value| [name, value.round(4)] }})
            result
          end

          def container_stop(params)
            @mutex.synchronize do
              container = native.stop_container(params["id"], timeout: (params["timeout"] || 5).to_f, request_id: params["request_id"])
              {"id" => container.respond_to?(:id) ? container.id : params["id"],
               "state" => container.respond_to?(:state) ? container.state.to_s : "stopped"}
            end
          end

          def container_remove(params)
            @mutex.synchronize do
              native.remove_container(params["id"], request_id: params["request_id"])
              {"id" => params["id"], "state" => "removed"}
            end
          end

          def container_status(params)
            @mutex.synchronize { plain(native.container_status(params["id"])) }
          end

          def container_stats(params)
            @mutex.synchronize { plain(native.stats(params["id"])) }
          end

          def container_wait(params)
            timeout = params["timeout"]&.to_f
            result = native.wait_container(params["id"], timeout: timeout)
            plain(result)
          end

          def logs(params)
            content = native.logs(params["id"], follow: false, since: params["since"], tail: params["tail"],
                                                stream: (params["stream"] || "stdout").to_sym)
            content = content.respond_to?(:read) ? content.read : content.to_s
            {"id" => params["id"], "bytes" => Base64.strict_encode64(content.b[0, Framing::MAX_FRAME_BYTES - 4096])}
          end

          def stream_open(params)
            kind = require_string(params, "kind")
            token = SecureRandom.hex(16)
            stream = case kind
                     when "exec"
                       raise GateError, "workload gate is closed" unless @state.gate == "open"

                       native.exec(params["id"], Array(params["cmd"]), tty: params["tty"] == true, stdin: params["stdin"] == true,
                                                                       stdout: true, stderr: params["tty"] != true)
                     when "attach" then native.attach(params["id"], tty: params["tty"] == true, stdin: params["stdin"] == true,
                                                                    stdout: true, stderr: params["tty"] != true)
                     when "logs" then native.logs(params["id"], follow: true, since: params["since"], tail: params["tail"],
                                                                stream: (params["stream"] || "stdout").to_sym)
                     else raise ProtocolError, "unknown stream kind #{kind}"
                     end
            @mutex.synchronize { @streams[token] = {"kind" => kind, "stream" => stream, "id" => params["id"]} }
            {"token" => token, "port" => STREAM_PORT}
          end

          def probe_http(params)
            require "net/http"
            uri = URI.parse(require_string(params, "url"))
            http = Net::HTTP.new(uri.host, uri.port, nil)
            http.use_ssl = uri.scheme == "https"
            http.open_timeout = (params["timeout"] || 1).to_f
            http.read_timeout = (params["timeout"] || 1).to_f
            response = http.get(uri.request_uri, params["headers"] || {})
            {"status" => response.code.to_i, "body" => response.body.to_s[0, 4096]}
          rescue StandardError => error
            {"status" => nil, "error" => "#{error.class}: #{error.message}"}
          end

          def probe_tcp(params)
            Socket.tcp(require_string(params, "host"), Integer(params["port"]), connect_timeout: (params["timeout"] || 1).to_f).close
            {"open" => true}
          rescue StandardError => error
            {"open" => false, "error" => "#{error.class}: #{error.message}"}
          end

          # L5 evidence: the guest attempts, from inside, to reach things it
          # must not reach; every attempt is reported with its outcome.
          def attack_matrix(params)
            targets = require_hash(params, "targets")
            results = {}
            results["rootfs_write"] = attempt do
              File.write("/etc/rubernetes-attack", "x")
              "wrote"
            end
            results["raw_block_write"] = attempt do
              File.binwrite("/dev/vda", "x")
              "wrote"
            end
            # Host paths that exist on the host but never inside the guest
            # image; and the mount table must show only the guest's own
            # block devices and pseudo filesystems (no shared host filesystem).
            results["host_filesystem"] = attempt do
              readable = Array(targets["host_paths"]).select { |path| File.exist?(path) }
              raise Errno::ENOENT, "host paths are absent: #{Array(targets["host_paths"]).join(", ")}" if readable.empty?

              "readable: #{readable.join(", ")}"
            end
            shared = File.read("/proc/mounts").lines.map(&:split).select { |fields| %w[9p virtiofs nfs nfs4 cifs fuse].include?(fields[2]) }
            results["shared_host_mounts"] = {"outcome" => shared.empty? ? "denied" : "allowed", "detail" => shared.map do |fields|
              fields.first(3).join(" ")
            end.join("; ")}
            results["jailer_root"] = attempt do
              File.read("/proc/1/root/firecracker.pid")
              "read"
            end
            results["other_vm_vsock"] = attempt do
              socket = Socket.new(Socket::AF_VSOCK, Socket::SOCK_STREAM, 0)
              socket.connect([Socket::AF_VSOCK, 0, CONTROL_PORT, Integer(targets["other_cid"] || 99), 0].pack("SSLLL"))
              "connected"
            end
            results["host_vsock_unlisted_port"] = attempt do
              socket = Socket.new(Socket::AF_VSOCK, Socket::SOCK_STREAM, 0)
              socket.connect([Socket::AF_VSOCK, 0, Integer(targets["unlisted_port"] || 9999), HOST_CID, 0].pack("SSLLL"))
              "connected"
            end
            if targets["other_tenant_ip"]
              results["other_tenant_network"] = attempt do
                Socket.tcp(targets.fetch("other_tenant_ip"), Integer(targets.fetch("other_tenant_port", 80)), connect_timeout: 1.0).close
                "connected"
              end
            end
            if targets["host_ip"]
              results["host_network"] = attempt do
                Socket.tcp(targets.fetch("host_ip"), Integer(targets.fetch("host_port", 22)), connect_timeout: 1.0).close
                "connected"
              end
            end
            results["network_interfaces"] = Dir.children("/sys/class/net").sort
            results
          end

          # ------------------------------------------------------------ guest→host

          # Workloads reach the restricted broker through a loopback HTTP
          # endpoint; each request is forwarded over a guest-initiated vsock
          # connection to the host broker, which re-authorizes it.
          def serve_broker_endpoint
            server = TCPServer.new("127.0.0.1", 3128)
            loop do
              client = server.accept
              Thread.new(client) do |connection|
                request_line = connection.gets
                headers = {}
                while (line = connection.gets) && line != "\r\n"
                  key, value = line.split(":", 2)
                  headers[key.to_s.strip.downcase] = value.to_s.strip
                end
                body = headers["content-length"] ? connection.read(headers["content-length"].to_i) : ""
                document = body.empty? ? {} : JSON.parse(body)
                operation = document["operation"] || request_line.to_s.split[1].to_s.delete_prefix("/")
                result = broker_call(operation, document["params"] || {})
                payload = JSON.generate(result)
                connection.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
              rescue StandardError => error
                payload = JSON.generate({"error" => "#{error.class}: #{error.message}"})
                begin
                  connection.write("HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
                rescue StandardError
                  nil
                end
              ensure
                connection.close unless connection.closed?
              end
            end
          rescue StandardError => error
            log("broker endpoint stopped: #{error.class}: #{error.message}")
          end

          def broker_call(operation, params)
            raise PolicyError, "no identity" unless @state.identity

            socket = Socket.new(Socket::AF_VSOCK, Socket::SOCK_STREAM, 0)
            socket.connect([Socket::AF_VSOCK, 0, BROKER_PORT, HOST_CID, 0].pack("SSLLL"))
            channel = Channel.new(socket)
            channel.call("broker.request", {"operation" => operation, "params" => params, "subject_id" => @state.identity["subject_id"],
                                            "capability_id" => @state.identity["capability_id"], "policy_digest" => @state.policy_digest,
                                            "revocation_epoch" => @state.identity["revocation_epoch"]})
          ensure
            socket&.close
          end

          # ---------------------------------------------------------- helpers

          private

          def ack(kind, nonce)
            fields = {"kind" => kind, "vm_id" => @state.identity["vm_id"], "policy_digest" => @state.policy_digest, "nonce" => nonce,
                      "boot_nonce" => @boot_nonce, "identity_digest" => identity_digest, "phase" => @state.phase, "gate" => @state.gate}
            {"ack" => fields, "signature" => Signature.sign(@state.session_key, fields)}
          end

          def identity_digest
            Digest::SHA256.hexdigest(CBOR.encode(@state.identity))
          end

          def require_phase!(phases)
            raise GateError, "operation requires phase #{phases.join("/")}, current #{@state.phase}" unless phases.include?(@state.phase)
          end

          def require_hash(params, key)
            value = params[key]
            raise ProtocolError, "#{key} must be a map" unless value.is_a?(Hash)

            value
          end

          def require_string(params, key)
            value = params[key]
            raise ProtocolError, "#{key} must be a string" unless value.is_a?(String) && !value.empty?

            value
          end

          def discard_identity!
            @sandboxes.each_value do |id|
              native.stop_sandbox(id, timeout: 2.0)
              native.remove_sandbox(id)
            rescue StandardError => error
              log("discard sandbox #{id}: #{error.message}")
            end
            @sandboxes.clear
            @streams.clear
            Dir.glob(File.join("/run/rubernetes/files", "**", "*")).select { |path| File.file?(path) }.each { |path| File.delete(path) }
            @mounted.reverse_each do |target|
              mount_adapter.unmount(target: target, flags: 2) # MNT_DETACH
            rescue StandardError => error
              log("umount #{target}: #{error.message}")
            end
            @mounted.clear
            FileUtils.rm_f("/run/machine-id")
            set_hostname("rubernetes-base")
            @state.identity = nil
            @state.session_key = nil
            @state.policy_digest = nil
            @state.network = nil
            @state.gate = "closed"
          end

          MS_RDONLY = 1
          MS_NOSUID = 2
          MS_NODEV = 4
          MS_NOATIME = 1024

          def mount_adapter
            @mount_adapter ||= begin
              require "rubernetes/platform/linux/mount"
              Rubernetes::Platform::Linux::Mount.new
            end
          end

          # mount(2) directly (no busybox exec, no filesystem probing).
          def mount_block!(device, target, flags)
            mount_adapter.mount(source: device, target: target, filesystem: "ext4", flags: flags, data: nil)
          rescue StandardError => error
            raise Error, "#{device} could not be mounted at #{target}: #{error.message}"
          end

          def mount_workspace(workspace)
            device = require_string(workspace, "device")
            target = @state_root
            FileUtils.mkdir_p(target)
            mount_block!(device, target, MS_NOATIME)
            @mounted << target
            FileUtils.mkdir_p(File.join(target, "sandboxes"))
            FileUtils.mkdir_p(File.join(target, "logs"))
            FileUtils.mkdir_p(@images_root)
          end

          def mount_images(images)
            images.each do |image|
              device = require_string(image, "device")
              digest = require_string(image, "digest")
              target = image_mount_path(digest)
              FileUtils.mkdir_p(target)
              mount_block!(device, target, MS_RDONLY | MS_NOATIME | MS_NOSUID | MS_NODEV)
              @mounted << target
            end
          end

          def image_mount_path(digest)
            File.join(@images_root, digest.delete_prefix("sha256:"))
          end

          def write_files(files)
            files.each do |entry|
              path = require_string(entry, "path")
              unless path.start_with?("/run/rubernetes/files/")
                raise ProtocolError,
                      "injected file path must be under /run/rubernetes/files"
              end

              FileUtils.mkdir_p(File.dirname(path))
              File.binwrite(path, Base64.strict_decode64(entry["content"].to_s))
              File.chmod(Integer(entry["mode"] || 0o600), path)
            end
          end

          def translate_sandbox_input(input)
            translated = JSON.parse(JSON.generate(input))
            # Inside the guest the Pod is isolated by the Native backend and
            # shares the guest's network namespace (the Pod's namespace).
            translated["runtime_class"] = "rubernetes-native"
            translated["hostNetwork"] = true
            translated["host_network"] = true
            Array(translated["resolved_images"]).each do |image|
              image["rootfs"] = image_mount_path(image.fetch("digest")) if image["digest"]
            end
            if translated["resolved_images"]
              translated["lowerdirs"] = Array(translated["resolved_images"]).filter_map do |image|
                image["rootfs"]
              end
            end
            translated
          end

          def translate_container_spec(spec)
            JSON.parse(JSON.generate(spec))
          end

          def native
            @native ||= build_native
          end

          # Loading the Native backend and its platform adapters happens in
          # the base VM, before the snapshot, so a restored VM pays nothing
          # for it.
          PRESPAWNED_SUPERVISORS = 2

          def prewarm_native
            require "rubernetes/runtime/native"
            require "rubernetes/platform/linux/native_adapters"
            require "rubernetes/image"
            detect_isolation_profile
            instrument_namespace_adapter
            @image_verifier = Rubernetes::Image::PinnedImageVerifier.new
            count = Rubernetes::Platform::Linux::NativeAdapters::NamespaceAdapter.prespawn_exec_supervisors(PRESPAWNED_SUPERVISORS,
                                                                                                            ruby_library_root: "/opt/rubernetes/lib")
            # The Native backend itself is built in the base VM: its adapters
            # keep paths, not descriptors, so the workspace mounted later at
            # the state root becomes the sandbox/log root transparently.  Its
            # rollback journal lives on tmpfs: the guest never recovers across
            # a VM restart (the host ledger is the durable record).
            @native = build_native
            # First use of OpenSSL (provider/config initialization) and of
            # the clock/sync Fiddle bindings costs hundreds of milliseconds
            # on one vCPU; pay it in the base VM, not in every clone.
            Signature.sign("k" * 32, {"warm" => true})
            Digest::SHA256.hexdigest("warm")
            CBOR.decode(CBOR.encode({"warm" => [1, "x"]}))
            clock_settime_function
            sync_function
            mount_adapter
            netlink
            require "base64"
            require "net/http"
            log("prewarm: native loaded, #{count} namespace supervisors idle, backend built, crypto warm")
          rescue LoadError, StandardError => error
            log("prewarm: #{error.class}: #{error.message}")
          end

          # Keep the idle pool topped up after each sandbox (off the critical path).
          def replenish_supervisors
            adapter = Rubernetes::Platform::Linux::NativeAdapters::NamespaceAdapter
            missing = PRESPAWNED_SUPERVISORS - adapter.exec_supervisor_pool_size
            adapter.prespawn_exec_supervisors(missing, ruby_library_root: "/opt/rubernetes/lib") if missing.positive?
          rescue StandardError => error
            log("replenish: #{error.message}")
          end

          def build_native
            return @native_factory.call(@state_root) if @native_factory

            require "rubernetes/runtime/native"
            require "rubernetes/platform/linux/native_adapters"
            profile = detect_isolation_profile == "l3" ? :l3 : :kernel_isolation
            sandbox_root = File.join(@state_root, "sandboxes")
            adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(profile: profile, sandbox_root: sandbox_root,
                                                                               cgroup_root: "/sys/fs/cgroup")
            adapters = adapters.merge(image: @image_verifier) if @image_verifier
            FileUtils.mkdir_p("/run/rubernetes")
            Rubernetes::Runtime::Native.new(profile: profile, l3: profile == :l3, adapters: adapters, sandbox_root: sandbox_root,
                                            cgroup_root: "/sys/fs/cgroup", log_root: File.join(@state_root, "logs"),
                                            journal_path: "/run/rubernetes/native.wal",
                                            security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"})
          end

          # Guest console timing of the namespace holder creation (the
          # dominant cost of the inner sandbox); read by the latency work.
          def instrument_namespace_adapter
            adapter = Rubernetes::Platform::Linux::NativeAdapters::NamespaceAdapter
            return if adapter.method_defined?(:__rubernetes_timed_create)

            log_io = @log
            adapter.class_eval do
              alias_method :__rubernetes_timed_create, :create
              define_method(:create) do |*arguments, **options, &block|
                started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
                result = __rubernetes_timed_create(*arguments, **options, &block)
                log_io.puts("[rubernetes-guest] namespace.create #{(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(4)}s")
                result
              end
            end
          rescue StandardError => error
            log("instrument: #{error.message}")
          end

          def detect_isolation_profile
            @isolation_profile ||= begin
              lsm = File.exist?("/sys/kernel/security/lsm") ? File.read("/sys/kernel/security/lsm") : ""
              landlock = lsm.include?("landlock")
              seccomp = File.exist?("/proc/sys/kernel/seccomp/actions_avail")
              cgroup = File.exist?("/sys/fs/cgroup/cgroup.controllers")
              landlock && seccomp && cgroup ? "l3" : "kernel_isolation"
            end
          end

          def guest_capabilities
            {"landlock" => detect_isolation_profile == "l3", "cgroup_controllers" => begin
              File.read("/sys/fs/cgroup/cgroup.controllers").split
            rescue StandardError
              []
            end,
             "seccomp_actions" => begin
               File.read("/proc/sys/kernel/seccomp/actions_avail").split
             rescue StandardError
               []
             end,
             "filesystems" => begin
               File.read("/proc/filesystems").split.reject { |word| word == "nodev" }
             rescue StandardError
               []
             end,
             "interfaces" => begin
               Dir.children("/sys/class/net").sort
             rescue StandardError
               []
             end}
          end

          def netlink
            @netlink ||= begin
              require "rubernetes/network/netlink"
              Rubernetes::Network::Netlink.new
            end
          end

          # rtnetlink directly: MAC (link down first, virtio-net requires
          # it), address, link up, default route and extra routes.
          def apply_network(network)
            ip = require_string(network, "ip")
            prefix = Integer(network["prefix_length"] || 24)
            interface = network["interface"] || "eth0"
            unless File.directory?("/sys/class/net/#{interface}")
              raise NetworkError,
                    "guest has no #{interface} (restricted runtime class?)"
            end

            begin
              if network["mac_address"]
                netlink.link_set(name: interface, up: false)
                netlink.link_set(name: interface, mac: network["mac_address"])
              end
              netlink.address_add(address: ip, prefix: prefix, name: interface)
              netlink.link_set(name: interface, up: true)
              netlink.route_add(destination: "0.0.0.0/0", via: network["gateway"], dev: interface) if network["gateway"]
              Array(network["routes"]).each do |route|
                netlink.route_add(destination: route.fetch("destination"), via: route["via"], dev: interface)
              end
            rescue StandardError => error
              raise NetworkError, "network configuration failed: #{error.class}: #{error.message}"
            end
            if network["dns"]
              File.write("/run/resolv.conf", Array(network["dns"]).map do |server|
                "nameserver #{server}"
              end.join("\n") + "\n")
            end
            File.write("/proc/sys/net/ipv4/ip_forward", "0") rescue nil # rubocop:disable Style/RescueModifier
          end

          def set_hostname(name)
            File.write("/proc/sys/kernel/hostname", name)
          rescue SystemCallError => error
            log("hostname: #{error.message}")
          end

          def clock_settime_function
            @clock_settime_function ||= Fiddle::Function.new(Fiddle.dlopen(nil)["syscall"],
                                                             [Fiddle::TYPE_LONG, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP], Fiddle::TYPE_LONG)
          end

          def sync_function
            @sync_function ||= Fiddle::Function.new(Fiddle.dlopen(nil)["sync"], [], Fiddle::TYPE_VOID)
          end

          def apply_time(unix_time)
            seconds = unix_time.to_f
            timespec = [seconds.floor, ((seconds - seconds.floor) * 1_000_000_000).to_i].pack("q!l!")
            clock_settime_function.call(SYS_CLOCK_SETTIME, CLOCK_REALTIME, Fiddle::Pointer[timespec])
          rescue StandardError => error
            log("clock: #{error.message}")
          end

          def credit_entropy(hex)
            bytes = [hex].pack("H*")
            File.open("/dev/urandom", File::WRONLY) do |io|
              payload = [bytes.bytesize * 8, bytes.bytesize].pack("l!l!") + bytes
              io.ioctl(RNDADDENTROPY, payload)
            end
          rescue StandardError => error
            begin
              File.binwrite("/dev/urandom", [hex].pack("H*"))
            rescue StandardError
              nil
            end
            log("entropy: #{error.message}")
          end

          def sync_filesystems
            sync_function.call
          end

          def pump_stream(connection, stream)
            handle = stream["stream"]
            if stream["kind"] == "logs"
              # A follow stream is an Enumerator that yields until the
              # process exits; stream each chunk as it arrives (never
              # materialize it).
              if handle.respond_to?(:each) && !handle.is_a?(String)
                handle.each { |chunk| write_stream_frame(connection, STREAM_STDOUT, chunk.to_s.b) }
              else
                write_stream_frame(connection, STREAM_STDOUT, handle.to_s.b)
              end
              write_stream_frame(connection, STREAM_EXIT, CBOR.encode({"exit_code" => 0}))
              return
            end
            streams = handle.respond_to?(:to_h) ? handle.to_h : {}
            stdin = streams[:stdin] || streams["stdin"]
            stdout = streams[:stdout] || streams["stdout"] || (handle.respond_to?(:read) ? handle : nil)
            stderr = streams[:stderr] || streams["stderr"]
            status = streams[:status] || streams["status"]
            outputs = []
            outputs << Thread.new { copy_out(stdout, connection, STREAM_STDOUT) } if stdout
            outputs << Thread.new { copy_out(stderr, connection, STREAM_STDERR) } if stderr
            input = Thread.new do
              loop do
                frame = read_stream_frame(connection)
                break if frame.nil?

                channel, bytes = frame
                next unless channel == STREAM_STDIN && stdin

                bytes.empty? ? stdin.close : stdin.write(bytes)
              end
            rescue IOError, SystemCallError
              nil
            end
            exit_code = wait_exit_code(status, handle)
            outputs.each { |thread| thread.join(5) }
            write_stream_frame(connection, STREAM_EXIT, CBOR.encode({"exit_code" => exit_code}))
            connection.close unless connection.closed?
            input.join(1)
          rescue IOError, SystemCallError
            nil
          end

          def wait_exit_code(status, handle)
            result = if status.respond_to?(:pop)
                       status.pop
                     elsif handle.respond_to?(:wait)
                       handle.wait
                     end
            return nil if result.nil? || result.is_a?(Exception)
            return result.exit_status if result.respond_to?(:exit_status) && !result.exit_status.nil?
            return 128 + result.term_signal if result.respond_to?(:term_signal) && result.term_signal
            return result.exitstatus if result.respond_to?(:exitstatus)

            result.is_a?(Integer) ? result : nil
          end

          def copy_out(io, connection, channel)
            loop do
              chunk = io.readpartial(MAX_STREAM_CHUNK)
              write_stream_frame(connection, channel, chunk)
            end
          rescue IOError, SystemCallError
            nil
          end

          def write_stream_frame(connection, channel, bytes)
            @stream_write_mutex ||= Mutex.new
            @stream_write_mutex.synchronize { connection.write([bytes.bytesize + 1].pack("N") + [channel].pack("C") + bytes) }
          end

          def read_stream_frame(connection)
            header = connection.read(4)
            return nil if header.nil?

            length = header.unpack1("N")
            raise FramingError, "stream frame too large" if length > Framing::MAX_FRAME_BYTES

            body = connection.read(length)
            return nil if body.nil?

            [body.getbyte(0), body.byteslice(1, body.bytesize)]
          end

          def plain(value)
            JSON.parse(JSON.generate(value))
          end

          def attempt
            result = yield
            {"outcome" => "allowed", "detail" => result.to_s}
          rescue StandardError => error
            {"outcome" => "denied", "detail" => "#{error.class}: #{error.message}"[0, 200]}
          end

          def mount(source, target, type, options = nil)
            FileUtils.mkdir_p(target)
            arguments = ["mount", "-t", type]
            arguments.push("-o", options) if options
            arguments.push(source, target)
            system(*arguments, out: File::NULL, err: File::NULL)
          end

          def shell!(*arguments)
            output = IO.popen(arguments, err: %i[child out], &:read)
            raise NetworkError, "#{arguments.join(" ")} failed: #{output.to_s.strip}" unless $CHILD_STATUS.success?
          rescue SystemCallError => error
            raise NetworkError, "#{arguments.join(" ")} could not run: #{error.message}"
          end

          def kernel_release
            File.read("/proc/sys/kernel/osrelease").strip
          rescue SystemCallError
            "unknown"
          end

          def reap_loop
            loop do
              Process.wait(-1)
            rescue Errno::ECHILD
              sleep 0.2
            rescue StandardError
              sleep 0.2
            end
          end

          def log(message)
            @log.puts("[rubernetes-guest] #{message}")
            @log.flush if @log.respond_to?(:flush)
          rescue IOError
            nil
          end
        end
      end
    end
  end
end
