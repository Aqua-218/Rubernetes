# frozen_string_literal: true

require "fileutils"
require "json"
require "stringio"
require "time"
require_relative "client"
require_relative "logs"

module Rubernetes
  module Runtime
    module CRI
      # A runtime backend (Runtime::Multiplexer handler) that runs a
      # RuntimeClass's Pods in a CRI runtime -- containerd, CRI-O -- the way
      # kubelet's kuberuntime manager does: RunPodSandbox, then per container
      # PullImage (when absent) / CreateContainer / StartContainer, status
      # from ContainerStatus, logs from the CRI log files, exec / attach /
      # port-forward through the runtime's streaming server.
      #
      # The node keeps its own Pod networking: the runtime is configured
      # with a CNI network that does nothing (see #cni_config), and
      # #network_sandbox_context hands the node the sandbox's network
      # namespace (through its pause process), which the node's network sets
      # up exactly as for a native sandbox.
      class Backend
        class Error < StandardError; end

        STATES = {"CONTAINER_CREATED" => "created", "CONTAINER_RUNNING" => "running",
                  "CONTAINER_EXITED" => "terminated", "CONTAINER_UNKNOWN" => "unknown"}.freeze
        # A no-op CNI network for the runtime's configuration directory: the
        # sandbox gets a namespace and no interfaces; the node attaches it.
        # containerd insists on an eth0 with an address in the result, so it
        # is told of a placeholder (loopback) one: the Pod's real addresses
        # are the node network's, never the runtime's report.
        CNI_NETWORK_NAME = "rubernetes-node-network"
        CNI_PLUGIN = <<~SH
          #!/bin/sh
          # CNI plugin that attaches nothing: rubernetes wires the sandbox's
          # network namespace itself.  ADD answers a placeholder eth0.
          cat >/dev/null
          case "$CNI_COMMAND" in
            ADD) printf '{"cniVersion":"1.0.0","interfaces":[{"name":"eth0","sandbox":"%s"}],"ips":[{"address":"127.0.0.1/8","interface":0}],"dns":{}}' "$CNI_NETNS" ;;
            VERSION) printf '{"cniVersion":"1.0.0","supportedVersions":["0.4.0","1.0.0","1.1.0"]}' ;;
          esac
          exit 0
        SH

        attr_reader :handler, :client
        # (pod, image) -> {"registry", "username", "password", "identity_token"}
        # or nil: the Pod's imagePullSecrets for a pull (the node sets it).
        attr_accessor :credential_provider

        CGROUP_CONTROLLERS = %w[cpu memory pids].freeze

        # +handler+: the CRI runtime handler (containerd's runtime name; ""
        # for its default).  +log_root+: kubelet's /var/log/pods.
        # +cgroup_parent+: where each Pod gets its cgroup (pod<uid>, the
        # runtime's cgroupfs driver puts the containers below it); nil leaves
        # placement to the runtime.
        def initialize(client:, handler: "", log_root: "/var/log/pods", cgroup_parent: nil, clock: -> { Time.now.utc },
                       stop_timeout: 30, cgroup_root: "/sys/fs/cgroup", log_manager: nil)
          @client = client
          # Rotation is the kubelet's with a CRI runtime; started with the
          # first sandbox.
          @log_manager = log_manager
          @handler = handler.to_s
          @log_root = log_root
          @cgroup_parent = cgroup_parent
          @cgroup_root = cgroup_root
          @clock = clock
          @stop_timeout = Integer(stop_timeout)
          @mutex = Mutex.new
          @sandboxes = {}
          @containers = {}
        end

        def profile = :cri

        # A CNI configuration list and plugin that leave networking to the
        # node (#network_sandbox_context), for the runtime's conf/bin dirs.
        # The CRI plugin also runs the standard "loopback" plugin in every
        # sandbox (it only brings lo up): the host's copy when there is one.
        def self.install_cni(conf_dir:, bin_dir:, loopback: "/opt/cni/bin/loopback")
          FileUtils.mkdir_p([conf_dir, bin_dir])
          plugin = File.join(bin_dir, "rubernetes-noop")
          File.write(plugin, CNI_PLUGIN, perm: 0o755)
          target = File.join(bin_dir, "loopback")
          if File.executable?(loopback)
            FileUtils.cp(loopback, target) unless File.expand_path(loopback) == File.expand_path(target)
          else
            File.write(target, CNI_PLUGIN, perm: 0o755)
          end
          config = {"cniVersion" => "1.0.0", "name" => CNI_NETWORK_NAME, "plugins" => [{"type" => "rubernetes-noop"}]}
          File.write(File.join(conf_dir, "10-rubernetes.conflist"), JSON.pretty_generate(config))
          [conf_dir, plugin]
        end

        def version
          @client.runtime("Version", {"version" => "v1"})
        end

        # Multiplexer ownership after a restart: ids this backend's runtime
        # knows (and that this handler created).
        def owns_sandbox?(id)
          return true if @mutex.synchronize { @sandboxes.key?(id.to_s) }

          status = @client.runtime("PodSandboxStatus", {"pod_sandbox_id" => id.to_s})["status"] || {}
          (status["runtime_handler"].to_s == @handler).tap { |mine| remember_sandbox(id.to_s, status) if mine }
        rescue Client::Error
          false
        end

        def owns_container?(id)
          return true if @mutex.synchronize { @containers.key?(id.to_s) }

          status = @client.runtime("ContainerStatus", {"container_id" => id.to_s})["status"] || {}
          sandbox = status.dig("labels", "io.kubernetes.pod.sandbox").to_s
          sandbox = find_sandbox_of(id.to_s) if sandbox.empty?
          return false if sandbox.nil? || !owns_sandbox?(sandbox)

          @mutex.synchronize do
            @containers[id.to_s] = {sandbox: sandbox, log_path: status["log_path"].to_s, name: status.dig("metadata", "name")}
          end
          true
        rescue Client::Error
          false
        end

        # A restarted agent's view of what the runtime runs for it.
        def recover(**_options)
          sandboxes = Array(@client.runtime("ListPodSandbox", {})["items"]).select { |item| item["runtime_handler"].to_s == @handler }
          sandboxes.each { |item| remember_sandbox(item["id"], item) }
          ids = sandboxes.to_h { |item| [item["id"], true] }
          Array(@client.runtime("ListContainers", {})["containers"]).each do |item|
            next unless ids.key?(item["pod_sandbox_id"])

            @mutex.synchronize do
              @containers[item["id"]] ||= {sandbox: item["pod_sandbox_id"], log_path: nil, name: item.dig("metadata", "name")}
            end
          end
          {"sandboxes" => sandboxes.length}
        end

        # ---------------------------------------------------------- sandboxes

        def run_sandbox(pod, runtime_class: nil, **_options)
          pod = stringify(pod)
          @log_manager&.start
          config = sandbox_config(pod)
          FileUtils.mkdir_p(config["log_directory"])
          cgroup = create_pod_cgroup(pod)
          config["linux"]["cgroup_parent"] = cgroup if cgroup
          response = @client.runtime("RunPodSandbox", {"config" => config, "runtime_handler" => @handler}, timeout: 240)
          id = response.fetch("pod_sandbox_id")
          @mutex.synchronize { @sandboxes[id] = {config: config, pod: pod, cgroup: cgroup} }
          id
        end

        def stop_sandbox(sandbox, timeout: nil)
          @client.runtime("StopPodSandbox", {"pod_sandbox_id" => key(sandbox)})
          true
        end

        def remove_sandbox(sandbox)
          id = key(sandbox)
          @client.runtime("StopPodSandbox", {"pod_sandbox_id" => id})
          @client.runtime("RemovePodSandbox", {"pod_sandbox_id" => id})
          entry = @mutex.synchronize do
            @containers.delete_if { |_container, value| value[:sandbox] == id }
            @sandboxes.delete(id)
          end
          remove_pod_cgroup(entry[:cgroup]) if entry && entry[:cgroup]
          true
        rescue Client::Error => error
          raise unless error.code == Client::NOT_FOUND

          true
        end

        # The sandbox's network namespace, held by its pause process -- the
        # shape Native::Sandbox#network_sandbox_context has.
        def network_sandbox_context(sandbox)
          id = key(sandbox)
          status = @client.runtime("PodSandboxStatus", {"pod_sandbox_id" => id, "verbose" => true})
          info = JSON.parse(status.dig("info", "info") || "{}")
          pid = Integer(info["pid"] || 0)
          raise Error, "sandbox #{id} reports no pause process" unless pid.positive?

          path = "/proc/#{pid}/ns/net"
          {"sandbox_id" => id,
           "netns" => {"handle" => "cri:#{id}", "path" => path, "inode" => File.stat(path).ino, "pid" => pid}}
        rescue JSON::ParserError, SystemCallError, ArgumentError => error
          raise Error, "sandbox #{id} network namespace is unavailable: #{error.message}"
        end

        # --------------------------------------------------------- containers

        def create_container(sandbox, spec, **_options)
          id = key(sandbox)
          entry = @mutex.synchronize { @sandboxes[id] } or raise Error, "unknown sandbox #{id}"
          spec = stringify(spec)
          image = spec.fetch("image").to_s
          ensure_image(image, spec, pod: entry[:pod])
          config = container_config(spec, entry[:pod], entry[:config])
          response = @client.runtime("CreateContainer", {"pod_sandbox_id" => id, "config" => config, "sandbox_config" => entry[:config]},
                                     timeout: 240)
          container = response.fetch("container_id")
          @mutex.synchronize do
            @containers[container] = {sandbox: id, log_path: File.join(entry[:config]["log_directory"], config["log_path"]),
                                      name: config.dig("metadata", "name")}
          end
          container
        end

        def start_container(container, **_options)
          @client.runtime("StartContainer", {"container_id" => key(container)}, timeout: 240)
          true
        end

        def stop_container(container, timeout: nil, **_options)
          seconds = timeout.nil? ? @stop_timeout : Integer(timeout.ceil)
          @client.runtime("StopContainer", {"container_id" => key(container), "timeout" => seconds}, timeout: seconds + 30)
          true
        rescue Client::Error => error
          raise unless error.code == Client::NOT_FOUND

          true
        end

        def remove_container(container, **_options)
          @client.runtime("RemoveContainer", {"container_id" => key(container)})
          @mutex.synchronize { @containers.delete(key(container)) }
          true
        rescue Client::Error => error
          raise unless error.code == Client::NOT_FOUND

          @mutex.synchronize { @containers.delete(key(container)) }
          true
        end

        # The node's status Hash from ContainerStatus.
        def container_status(container)
          status = @client.runtime("ContainerStatus", {"container_id" => key(container)}).fetch("status")
          state = STATES.fetch(status["state"].to_s, "unknown")
          result = {"id" => status["id"], "state" => state, "image" => status.dig("image", "image"),
                    "imageRef" => status["image_ref"], "reason" => status["reason"], "message" => status["message"]}
          started = timestamp(status["started_at"])
          case state
          when "running"
            result["running"] = {"startedAt" => started}
          when "terminated"
            finished = timestamp(status["finished_at"])
            result["exitCode"] = Integer(status["exit_code"] || 0)
            result["oom_killed"] = status["reason"] == "OOMKilled"
            result["terminated"] = {"exitCode" => result["exitCode"], "reason" => status["reason"].to_s.empty? ? nil : status["reason"],
                                    "message" => status["message"].to_s.empty? ? nil : status["message"],
                                    "startedAt" => started, "finishedAt" => finished, "containerID" => status["id"]}.compact
          end
          result.compact
        end

        def wait_container(container, timeout: nil)
          deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout))
          loop do
            status = container_status(container)
            return status unless %w[running created].include?(status["state"])
            return status if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

            sleep 0.2
          end
        end

        def logs(container, follow: false, since: nil, tail: nil, stream: :all, timestamps: false)
          path = log_path(container)
          Logs.read(path, follow: follow, since: since, tail: tail, stream: stream, timestamps: timestamps,
                          running: -> { container_status(container)["state"] == "running" })
        end

        # ExecSync for commands that need no streams (exec probes).
        # CheckpointContainer: the runtime (CRIU underneath) writes the
        # archive to +location+ on this host.
        def checkpoint_container(container, location:, timeout: nil)
          request = {"container_id" => key(container), "location" => location.to_s}
          request["timeout"] = Integer(timeout) if timeout
          @client.runtime("CheckpointContainer", request, timeout: [Integer(timeout || 0), 0].max + 120)
          location
        end

        def exec_sync(container, command, timeout: 10)
          response = @client.runtime("ExecSync", {"container_id" => key(container), "cmd" => Array(command).map(&:to_s),
                                                  "timeout" => Integer(timeout)}, timeout: Integer(timeout) + 10)
          {"stdout" => decode(response["stdout"]), "stderr" => decode(response["stderr"]),
           "exitCode" => Integer(response["exit_code"] || 0)}
        end

        ExecStatus = Struct.new(:exit_status, :term_signal)

        # The node's exec shape for callers without a stream (exec probes,
        # lifecycle hooks): ExecSync on a thread, output then the exit on the
        # status queue.  Interactive exec goes through #streaming_url.
        def exec(container, command, tty: false, timeout: nil, **_options)
          stdout = StringIO.new(+"")
          stderr = StringIO.new(+"")
          status = Queue.new
          Thread.new do
            result = exec_sync(container, command, timeout: timeout ? [Float(timeout).ceil, 1].max : 60)
            stdout.write(result["stdout"])
            stderr.write(result["stderr"])
            stdout.rewind
            stderr.rewind
            status << ExecStatus.new(result["exitCode"], nil)
          rescue StandardError => error
            status << error
          end
          {stdin: nil, stdout: stdout, stderr: stderr, status: status}
        end

        # The runtime streaming server's URLs; the node proxies the upgraded
        # connection to them (kubelet's proxyStream).
        def exec_url(container, command, tty: false, stdin: false, stdout: true, stderr: true)
          @client.runtime("Exec", {"container_id" => key(container), "cmd" => Array(command).map(&:to_s), "tty" => tty,
                                   "stdin" => stdin, "stdout" => stdout, "stderr" => stderr && !tty}).fetch("url")
        end

        def attach_url(container, tty: false, stdin: false, stdout: true, stderr: true)
          @client.runtime("Attach", {"container_id" => key(container), "tty" => tty, "stdin" => stdin, "stdout" => stdout,
                                     "stderr" => stderr && !tty}).fetch("url")
        end

        def port_forward_url(sandbox, ports)
          @client.runtime("PortForward", {"pod_sandbox_id" => key(sandbox), "port" => Array(ports).map do |port|
            Integer(port)
          end}).fetch("url")
        end

        # Multiplexer#streaming_url: where the node relays a stream to.
        def streaming_url(operation, container, command: [], tty: false, stdin: false, stdout: true, stderr: true, **_options)
          case operation.to_sym
          when :exec then exec_url(container, command, tty: tty, stdin: stdin, stdout: stdout, stderr: stderr)
          when :attach then attach_url(container, tty: tty, stdin: stdin, stdout: stdout, stderr: stderr)
          when :port_forward then port_forward_url(sandbox_of(container), [])
          end
        end

        def sandbox_of(container)
          entry = @mutex.synchronize { @containers[key(container)] }
          return entry[:sandbox] if entry

          @client.runtime("ContainerStatus", {"container_id" => key(container), "verbose" => true})
            .dig("status", "labels", "io.kubernetes.pod.sandbox") || key(container)
        end

        def update_container_resources(container, resources, **_options)
          @client.runtime("UpdateContainerResources", {"container_id" => key(container), "linux" => linux_resources(stringify(resources))})
          true
        end

        # The node's usage shape (Native#pod_usage) from the Pod's cgroup and
        # its containers' (cgroupfs: <pod cgroup>/<container id>).
        def pod_usage(sandbox)
          entry = @mutex.synchronize { @sandboxes[key(sandbox)] }
          cgroup = entry && entry[:cgroup]
          return nil if cgroup.nil?

          containers = @mutex.synchronize { @containers.select { |_id, value| value[:sandbox] == key(sandbox) }.to_a }
          {"pod" => cgroup_usage(cgroup),
           "containers" => containers.filter_map do |id, value|
             path = File.join(cgroup, id)
             next unless File.directory?(File.join(@cgroup_root, path))

             {"id" => id, "name" => value[:name].to_s, "usage" => cgroup_usage(path),
              "logs" => value[:log_path] && File.dirname(value[:log_path])}
           end}
        end

        def stats(container)
          @client.runtime("ContainerStats", {"container_id" => key(container)}).fetch("stats")
        end

        # -------------------------------------------------------------- probes

        # HTTP, TCP and gRPC probes from inside the Pod's network namespace
        # (its pause process's), as the native connector runs them.
        def http_get(container, definition, timeout: 1.0, **_options)
          definition = stringify(definition)
          path = definition["path"].to_s
          path = "/#{path}" unless path.start_with?("/")
          headers = Array(definition["httpHeaders"]).to_h { |header| [header["name"].to_s, header["value"].to_s] }
          tls = definition["scheme"].to_s.casecmp("HTTPS").zero?
          result = within_netns(container, timeout) do
            connector.blocking_http_get(definition["host"] || "127.0.0.1", Integer(definition["port"] || 80), path, headers,
                                        Float(timeout), tls: tls)
          end
          status = Integer(result.fetch("status"))
          {"status" => status, "success" => status.between?(200, 399), "message" => "HTTP #{status}",
           "body_bytes" => Integer(result.fetch("body_bytes"))}
        end

        def tcp_socket(container, definition, timeout: 1.0, **_options)
          definition = stringify(definition)
          result = within_netns(container, timeout) do
            connector.blocking_tcp_connect(definition["host"] || "127.0.0.1", Integer(definition["port"]), Float(timeout))
          end
          {"success" => result.fetch("connected") == true, "message" => result.fetch("message")}
        end

        def grpc_check(container, definition, timeout: 1.0, **_options)
          definition = stringify(definition)
          result = within_netns(container, timeout) do
            connector.blocking_grpc_check(definition["host"] || "127.0.0.1", Integer(definition["port"]), definition["service"].to_s,
                                          Float(timeout))
          end
          {"success" => result.fetch("success") == true, "message" => result.fetch("message").to_s}
        end

        # ------------------------------------------------------------- images

        # Node::Agent builds the kubelet's image GC over the runtime from it.
        def image_gc_source = true

        def ensure_image(image, spec = {}, pod: nil)
          present = @client.image("ImageStatus", {"image" => {"image" => image}})["image"]
          policy = spec["imagePullPolicy"].to_s
          return present if present && !present.fetch("id", "").to_s.empty? && policy != "Always"

          request = {"image" => {"image" => image}}
          auth = pull_auth(pod, image)
          request["auth"] = auth if auth
          @client.image("PullImage", request, timeout: 600)
        end

        private

        # kubelet's pod container manager + ResourceConfigForPod: the Pod's
        # cgroup with its requests as CPU weight and, when every container
        # declares them (or the Pod does), its CPU quota and memory limit.
        def create_pod_cgroup(pod)
          return nil if @cgroup_parent.nil?

          uid = pod.dig("metadata", "uid").to_s
          raise Error, "a Pod without a uid has no cgroup" if uid.empty?

          relative = File.join(@cgroup_parent, "pod#{uid}")
          enable_controllers(relative)
          pod_cgroup_settings(pod).each do |file, value|
            path = File.join(@cgroup_root, relative, file)
            File.write(path, value) if File.exist?(path)
          end
          relative
        end

        def pod_cgroup_settings(pod)
          qos = ResourceHelpers.qos_class(pod)
          return {"cpu.weight" => "1"} if qos == "BestEffort"

          requests = ResourceHelpers.pod_requests(pod)
          limits = ResourceHelpers.pod_limits(pod)
          cpu_request = requests["cpu"] ? (value_of(requests["cpu"]) * 1000).ceil : 0
          shares = cpu_request.zero? ? 2 : [[(cpu_request * 1024) / 1000, 2].max, 262_144].min
          settings = {"cpu.weight" => (1 + (((shares - 2) * 9999) / 262_142)).to_s}
          if qos == "Guaranteed" || declared_for_all?(pod, "cpu")
            quota = limits["cpu"] ? [(value_of(limits["cpu"]) * 100_000).ceil, 1000].max : nil
            settings["cpu.max"] = "#{quota} 100000" if quota
          end
          settings["memory.max"] = value_of(limits["memory"]).ceil.to_s if (qos == "Guaranteed" || declared_for_all?(pod, "memory")) && limits["memory"]
          settings
        end

        def declared_for_all?(pod, resource)
          return true if pod.dig("spec", "resources", "limits", resource)

          containers = ResourceHelpers.containers(pod, "containers") + ResourceHelpers.containers(pod, "initContainers")
          !containers.empty? && containers.all? { |container| container.dig("resources", "limits", resource) }
        end

        def value_of(quantity) = quantity.respond_to?(:value) ? quantity.value : Schema::Quantity.from_json(quantity.to_s).value

        # The root and every cgroup down to +relative+ (created as needed)
        # delegate cpu, memory and pids to their children.
        def enable_controllers(relative)
          parts = relative.split("/").reject(&:empty?)
          directories = [@cgroup_root] + parts.each_index.map { |index| File.join(@cgroup_root, *parts[0..index]) }
          directories.each do |directory|
            FileUtils.mkdir_p(directory)
            control = File.join(directory, "cgroup.subtree_control")
            next unless File.exist?(control)

            missing = CGROUP_CONTROLLERS - File.read(control).split
            File.write(control, missing.map { |name| "+#{name}" }.join(" ")) unless missing.empty?
          end
        rescue SystemCallError => error
          raise Error, "cannot delegate cgroup controllers to #{relative}: #{error.message}"
        end

        def remove_pod_cgroup(relative)
          path = File.join(@cgroup_root, relative)
          5.times do
            return true unless File.directory?(path)

            Dir.rmdir(path)
            return true
          rescue Errno::EBUSY, Errno::ENOTEMPTY
            sleep 0.2
          end
          false
        rescue SystemCallError
          false
        end

        def cgroup_usage(relative)
          directory = File.join(@cgroup_root, relative)
          read = lambda { |name|
            begin
              File.read(File.join(directory, name))
            rescue StandardError
              nil
            end
          }
          key_values = lambda { |text|
            text&.lines.to_h do |line|
              name, value = line.split
              [name, Integer(value, exception: false) || value]
            end
          }
          scalar = ->(text) { text && Integer(text.strip, exception: false) }
          {"cpu" => key_values.call(read.call("cpu.stat")), "memory" => key_values.call(read.call("memory.stat")),
           "memory.current" => scalar.call(read.call("memory.current")), "pids.current" => scalar.call(read.call("pids.current"))}
        end

        def connector
          require "rubernetes/platform/linux"
          Rubernetes::Platform::Linux::NativeAdapters::NamespaceConnector
        end

        # Runs the block in a fork joined to the container's sandbox network
        # namespace; its JSON-able result, or raises Error.
        def within_netns(container, timeout)
          require "rubernetes/platform/linux"
          path = network_sandbox_context(sandbox_of(container)).dig("netns", "path")
          reader, writer = IO.pipe
          pid = Process.fork do
            reader.close
            File.open(path) { |namespace| Rubernetes::Platform::Linux::Setns.new.setns(fd: namespace, name: :network) }
            writer.write(JSON.generate("ok" => true, "value" => yield))
            exit!(0)
          rescue StandardError => error
            writer.write(JSON.generate("ok" => false, "error" => "#{error.class}: #{error.message}"))
            exit!(1)
          end
          writer.close
          payload = nil
          waiter = Thread.new { payload = reader.read }
          unless waiter.join(Float(timeout) + 5.0)
            Process.kill(:KILL, pid)
            waiter.join(1)
          end
          Process.wait(pid)
          document = payload.to_s.empty? ? {} : JSON.parse(payload)
          raise Error, "probe helper failed: #{document["error"] || "no answer"}" unless document["ok"] == true

          document.fetch("value")
        ensure
          reader&.close unless reader.nil? || reader.closed?
        end

        # PullImageRequest.auth (AuthConfig) from the Pod's credentials.
        def pull_auth(pod, image)
          return nil if @credential_provider.nil? || pod.nil?

          credential = @credential_provider.call(pod, image)
          return nil if credential.nil?

          credential = credential.to_h.transform_keys(&:to_s)
          {"username" => credential["username"].to_s, "password" => credential["password"].to_s,
           "server_address" => credential["registry"].to_s, "identity_token" => credential["identity_token"].to_s}
            .reject { |_name, value| value.empty? }
        end

        def key(value) = value.respond_to?(:id) ? value.id.to_s : value.to_s

        def stringify(value)
          case value
          when Hash then value.to_h { |name, item| [name.to_s, stringify(item)] }
          when Array then value.map { |item| stringify(item) }
          else value
          end
        end

        # A sandbox learned from the runtime (after a restart): its config is
        # rebuilt from what CreateContainer needs.
        def remember_sandbox(id, status)
          metadata = status["metadata"] || {}
          @mutex.synchronize do
            @sandboxes[id] ||= {config: {"metadata" => metadata, "labels" => status["labels"] || {},
                                         "log_directory" => File.join(@log_root, "#{metadata["namespace"]}_#{metadata["name"]}_#{metadata["uid"]}")},
                                pod: {"metadata" => metadata}}
          end
        end

        def find_sandbox_of(container)
          item = Array(@client.runtime("ListContainers", {"filter" => {"id" => container}})["containers"]).first
          item && item["pod_sandbox_id"]
        end

        def log_path(container)
          entry = @mutex.synchronize { @containers[key(container)] }
          return entry[:log_path] if entry && !entry[:log_path].to_s.empty?

          status = @client.runtime("ContainerStatus", {"container_id" => key(container)}).fetch("status")
          status["log_path"].to_s
        end

        def decode(value) = value.to_s.unpack1("m").to_s

        def timestamp(nanoseconds)
          value = Integer(nanoseconds || 0)
          return nil if value.zero?

          Time.at(Rational(value, 1_000_000_000)).utc.iso8601
        end

        # kuberuntime generatePodSandboxConfig.
        def sandbox_config(pod)
          metadata = pod["metadata"] || {}
          spec = pod["spec"] || {}
          uid = metadata["uid"].to_s
          namespace = metadata["namespace"].to_s
          name = metadata["name"].to_s
          host_network = spec["hostNetwork"] == true
          config = {
            "metadata" => {"name" => name, "uid" => uid, "namespace" => namespace, "attempt" => 0},
            "hostname" => host_network ? "" : (pod["hostname"] || spec["hostname"] || name).to_s,
            "log_directory" => File.join(@log_root, "#{namespace}_#{name}_#{uid}"),
            "labels" => (metadata["labels"] || {}).merge("io.kubernetes.pod.name" => name, "io.kubernetes.pod.namespace" => namespace,
                                                         "io.kubernetes.pod.uid" => uid),
            "annotations" => metadata["annotations"] || {},
            "port_mappings" => port_mappings(spec),
            "linux" => {
              "security_context" => {
                "namespace_options" => {"network" => host_network ? "NODE" : "POD", "pid" => pid_mode(spec),
                                        "ipc" => spec["hostIPC"] == true ? "NODE" : "POD"},
                "privileged" => Array(spec["containers"]).any? { |container| container.dig("securityContext", "privileged") == true }
              },
              "sysctls" => Array(spec.dig("securityContext", "sysctls")).to_h { |sysctl| [sysctl["name"].to_s, sysctl["value"].to_s] }
            }
          }
          dns = dns_config(spec)
          config["dns_config"] = dns if dns
          config
        end

        def pid_mode(spec)
          return "NODE" if spec["hostPID"] == true
          return "POD" if spec["shareProcessNamespace"] == true

          "CONTAINER"
        end

        def port_mappings(spec)
          Array(spec["containers"]).flat_map do |container|
            Array(container["ports"]).filter_map do |port|
              next unless port["hostPort"]

              {"protocol" => (port["protocol"] || "TCP").to_s.upcase, "container_port" => Integer(port["containerPort"]),
               "host_port" => Integer(port["hostPort"]), "host_ip" => port["hostIP"].to_s}
            end
          end
        end

        def dns_config(spec)
          config = spec["dnsConfig"] || {}
          return nil if config.empty?

          {"servers" => Array(config["nameservers"]), "searches" => Array(config["searches"]),
           "options" => Array(config["options"]).map do |option|
             option["value"] ? "#{option["name"]}:#{option["value"]}" : option["name"].to_s
           end}
        end

        # kuberuntime generateContainerConfig from the node's built spec:
        # the final argv, the environment, the host-side mounts the node
        # prepared, the effective security context, the resources.
        def container_config(spec, pod, sandbox)
          name = spec["name"].to_s
          attempt = spec["restart_count"] ? Integer(spec["restart_count"]) : next_attempt(sandbox["log_directory"], name)
          argv = Array(spec["command"]) + Array(spec["args"])
          # KeyValue.value is bytes (an environment value need not be UTF-8):
          # base64 in protobuf JSON.
          env = Array(spec["env"]).map { |entry| {"key" => entry["name"].to_s, "value" => [entry["value"].to_s].pack("m0")} }
          config = {
            "metadata" => {"name" => name, "attempt" => attempt},
            "image" => {"image" => spec["image"].to_s},
            "command" => argv,
            "args" => [],
            "working_dir" => spec["cwd"].to_s,
            "envs" => env,
            "mounts" => Array(spec["mounts"]).filter_map { |mount| mount_for(mount) },
            "labels" => sandbox["labels"].slice("io.kubernetes.pod.name", "io.kubernetes.pod.namespace", "io.kubernetes.pod.uid")
              .merge("io.kubernetes.container.name" => name),
            "annotations" => {},
            "log_path" => "#{name}/#{attempt}.log",
            "stdin" => spec["stdin"] == true,
            "stdin_once" => spec["stdinOnce"] == true,
            "tty" => spec["tty"] == true,
            "linux" => {"resources" => linux_resources(spec["resources"] || {}), "security_context" => security_context(spec, pod)}
          }
          config["command"] = [] if argv.empty?
          config
        end

        # Each attempt of a container logs to <name>/<attempt>.log (kubelet
        # BuildContainerLogsDirectory): the next number after the ones there.
        def next_attempt(log_directory, name)
          existing = Dir.glob(File.join(log_directory.to_s, name, "*.log")).filter_map do |path|
            Integer(File.basename(path, ".log"), exception: false)
          end
          existing.empty? ? 0 : existing.max + 1
        end

        def mount_for(mount)
          source = mount["source"] || mount["host_path"]
          destination = mount["destination"] || mount["target"]
          return nil if source.to_s.empty? || destination.to_s.empty?

          propagation = case mount["propagation"].to_s
                        when "Bidirectional" then "PROPAGATION_BIDIRECTIONAL"
                        when "HostToContainer" then "PROPAGATION_HOST_TO_CONTAINER"
                        else "PROPAGATION_PRIVATE"
                        end
          readonly = mount["readonly"] == true
          {"container_path" => destination.to_s, "host_path" => source.to_s, "readonly" => readonly,
           "propagation" => propagation,
           "recursive_read_only" => readonly && %w[Enabled IfPossible].include?(mount["recursive_readonly"].to_s)}
        end

        # kuberuntime's CPU shares/quota and memory limit.
        def linux_resources(resources)
          requests = resources["requests"] || {}
          limits = resources["limits"] || {}
          result = {}
          cpu_request = milli(requests["cpu"] || limits["cpu"])
          result["cpu_shares"] = cpu_request.nil? ? 2 : [[(cpu_request * 1024) / 1000, 2].max, 262_144].min
          if (cpu_limit = milli(limits["cpu"]))
            result["cpu_period"] = 100_000
            result["cpu_quota"] = [(cpu_limit * 100_000) / 1000, 1000].max
          end
          if (memory = bytes(limits["memory"]))
            result["memory_limit_in_bytes"] = memory
          end
          result
        end

        def security_context(spec, pod)
          context = spec["security_context"] || spec["securityContext"] || {}
          result = {}
          result["privileged"] = true if context["privileged"] == true
          result["run_as_user"] = {"value" => Integer(context["runAsUser"])} unless context["runAsUser"].nil?
          result["run_as_group"] = {"value" => Integer(context["runAsGroup"])} unless context["runAsGroup"].nil?
          result["readonly_rootfs"] = true if context["readOnlyRootFilesystem"] == true
          result["no_new_privs"] = true if context["allowPrivilegeEscalation"] == false
          capabilities = context["capabilities"] || {}
          unless capabilities.empty?
            result["capabilities"] = {"add_capabilities" => Array(capabilities["add"]), "drop_capabilities" => Array(capabilities["drop"])}
          end
          groups = Array(pod.dig("spec", "securityContext", "supplementalGroups"))
          result["supplemental_groups"] = groups.map { |group| Integer(group) } unless groups.empty?
          seccomp = context.dig("seccompProfile", "type") || pod.dig("spec", "securityContext", "seccompProfile", "type")
          result["seccomp"] = {"profile_type" => seccomp == "Unconfined" ? "Unconfined" : "RuntimeDefault"} if seccomp
          result
        end

        def milli(value)
          return nil if value.nil?

          (Schema::Quantity.from_json(value.to_s).value * 1000).ceil
        end

        def bytes(value)
          return nil if value.nil?

          Schema::Quantity.from_json(value.to_s).value.ceil
        end
      end
    end
  end
end
