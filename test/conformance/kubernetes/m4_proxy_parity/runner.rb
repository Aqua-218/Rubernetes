#!/usr/bin/env ruby
# frozen_string_literal: true

# External M4 proxy backend parity runner.
#
# The production proxy process (tools/milestones/m4_proxy_probe.rb) owns a
# private node network namespace, two pod namespaces, the veth topology, and
# the eBPF/nftables datapaths.  This runner is the independent observer: it
# enters those namespaces with nsenter(1), generates the packet corpus with
# plain sockets, captures every packet with tcpdump(8), reads the kernel back
# with bpftool(8), tc(8), and nft(8), and derives the expected observable of
# every case from the shared corpus definition and Kubernetes Service
# semantics alone.  It never calls the production model and it never runs a
# milestone probe.
#
# Protocol: the probe writes one JSON object per line to stdin and reads one
# JSON object per line from stdout.  Phases: init, corpus, connections_open,
# connections_check, measure, finish.  The final line is the complete
# evidence document; every earlier line is the runner's stdout provenance.
#
# The same file also implements the in-namespace agents (`--agent client`
# and `--agent backend`) so the traffic endpoints depend only on the Ruby
# standard library.

require "digest"
require "ipaddr"
require "json"
require "open3"
require "rbconfig"
require "securerandom"
require "socket"
require "time"
require "timeout"
require "tmpdir"

require_relative "corpus"

module M4ProxyParityRunner
  RUNNER_IDENTITY = "rubernetes-m4-proxy-parity-runner"
  RUNNER_MODE = "external_isolated_netns"
  SOURCE_PATH = File.expand_path(__FILE__)
  IPPROTO_SCTP = 132
  TCP = Socket::IPPROTO_TCP
  UDP = Socket::IPPROTO_UDP
  CASE_TIMEOUT = 4.0
  FRAGMENT_TIMEOUT = 1.5
  FRAGMENT_PAYLOAD_BYTES = 3000

  # ---------------------------------------------------------------------
  # In-namespace agent: plain sockets, JSON lines on stdin/stdout.
  # ---------------------------------------------------------------------
  class Agent
    def initialize(role)
      @role = role
      @servers = []
      @threads = []
      @received = {}
      @received_mutex = Mutex.new
      @connections = {}
    end

    def run
      STDOUT.sync = true
      while (line = STDIN.gets)
        request = JSON.parse(line)
        response = begin
          handle(request)
        rescue StandardError => error
          {"ok" => false, "error" => "#{error.class}: #{error.message}"}
        end
        STDOUT.puts(JSON.generate(response.merge("cmd" => request["cmd"], "seq" => request["seq"])))
      end
    ensure
      @servers.each { |socket| socket.close rescue nil }
      @connections.each_value { |socket| socket.close rescue nil }
    end

    def handle(request)
      case request.fetch("cmd")
      when "serve" then serve(request)
      when "received" then received(request)
      when "stream" then stream(request)
      when "datagram" then datagram(request)
      when "http" then http(request)
      when "dig" then dig(request)
      when "open" then open_connection(request)
      when "check" then check_connection(request)
      when "close_all" then close_all
      when "ping" then {"ok" => true, "pid" => Process.pid, "netns" => File.stat("/proc/self/ns/net").ino}
      else raise ArgumentError, "unknown agent command #{request["cmd"].inspect}"
      end
    end

    # --- backend side -----------------------------------------------------

    def serve(request)
      ports = request.fetch("ports")
      request.fetch("addresses").each do |family, addresses|
        af = family == "ipv6" ? Socket::AF_INET6 : Socket::AF_INET
        addresses.each do |address|
          start_stream_server(af, address, Integer(ports.fetch("tcp")), TCP, "tcp")
          start_stream_server(af, address, Integer(ports.fetch("sctp")), IPPROTO_SCTP, "sctp")
          start_datagram_server(af, address, Integer(ports.fetch("udp")))
        end
      end
      {"ok" => true, "servers" => @servers.length}
    end

    def start_stream_server(af, address, port, protocol, label)
      socket = Socket.new(af, Socket::SOCK_STREAM, protocol)
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 1) if af == Socket::AF_INET6
      socket.bind(Socket.sockaddr_in(port, address))
      socket.listen(64)
      @servers << socket
      @threads << Thread.new do
        loop do
          client, = socket.accept
          Thread.new(client) { |connection| serve_stream(connection, label) }
        rescue IOError, SystemCallError
          break
        end
      end
    end

    def serve_stream(connection, label)
      peer = connection.remote_address
      local = connection.local_address
      while (line = connection.gets)
        payload = line.chomp
        record = {"peer" => [peer.ip_address, peer.ip_port], "local" => [local.ip_address, local.ip_port],
                  "payload" => payload, "protocol" => label}
        @received_mutex.synchronize { @received[payload] = record }
        connection.puts(JSON.generate(record))
      end
    rescue IOError, SystemCallError
      nil
    ensure
      connection.close rescue nil
    end

    def start_datagram_server(af, address, port)
      socket = UDPSocket.new(af)
      socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 1) if af == Socket::AF_INET6
      socket.bind(address, port)
      @servers << socket
      @threads << Thread.new do
        loop do
          payload, sender = socket.recvfrom(65_535)
          record = {"peer" => [sender[3], sender[1]], "local" => [address, port], "payload" => payload,
                    "protocol" => "udp"}
          @received_mutex.synchronize { @received[payload] = record }
          socket.send(JSON.generate(record), 0, sender[3], sender[1])
        rescue IOError, SystemCallError
          break
        end
      end
    end

    def received(request)
      record = @received_mutex.synchronize { @received[request.fetch("payload")] }
      {"ok" => true, "received" => !record.nil?, "record" => record}
    end

    # --- client side ------------------------------------------------------

    def family_of(address)
      address.include?(":") ? Socket::AF_INET6 : Socket::AF_INET
    end

    def stream(request)
      protocol = request.fetch("protocol") == "SCTP" ? IPPROTO_SCTP : TCP
      address = request.fetch("address")
      socket = Socket.new(family_of(address), Socket::SOCK_STREAM, protocol)
      timeout = Float(request.fetch("timeout", CASE_TIMEOUT))
      begin
        Timeout.timeout(timeout) { socket.connect(Socket.sockaddr_in(Integer(request.fetch("port")), address)) }
        socket.puts(request.fetch("payload"))
        reply = Timeout.timeout(timeout) { socket.gets }
        peer = socket.remote_address
        local = socket.local_address
        {"ok" => true, "connected" => true, "peer" => [peer.ip_address, peer.ip_port],
         "local" => [local.ip_address, local.ip_port], "reply" => reply && JSON.parse(reply)}
      rescue Timeout::Error, SystemCallError, JSON::ParserError, IOError => error
        {"ok" => true, "connected" => false, "error" => "#{error.class}: #{error.message}"}
      ensure
        socket.close rescue nil
      end
    end

    def datagram(request)
      address = request.fetch("address")
      socket = UDPSocket.new(family_of(address))
      timeout = Float(request.fetch("timeout", CASE_TIMEOUT))
      payload = request.fetch("payload")
      payload = payload.ljust(Integer(request["size"]), "x") if request["size"]
      begin
        socket.send(payload, 0, address, Integer(request.fetch("port")))
        local = socket.local_address
        ready = IO.select([socket], nil, nil, timeout)
        return {"ok" => true, "replied" => false, "local" => [local.ip_address, local.ip_port]} unless ready

        reply, sender = socket.recvfrom(65_535)
        {"ok" => true, "replied" => true, "from" => [sender[3], sender[1]],
         "local" => [local.ip_address, local.ip_port], "reply" => JSON.parse(reply)}
      rescue SystemCallError, JSON::ParserError, IOError => error
        {"ok" => true, "replied" => false, "error" => "#{error.class}: #{error.message}"}
      ensure
        socket.close rescue nil
      end
    end

    def http(request)
      address = request.fetch("address")
      socket = Socket.new(family_of(address), Socket::SOCK_STREAM, TCP)
      begin
        Timeout.timeout(CASE_TIMEOUT) { socket.connect(Socket.sockaddr_in(Integer(request.fetch("port")), address)) }
        socket.write("GET #{request.fetch("path", "/healthz")} HTTP/1.1\r\nHost: #{address}\r\nConnection: close\r\n\r\n")
        response = Timeout.timeout(CASE_TIMEOUT) { socket.read }
        status_line, rest = response.to_s.split("\r\n", 2)
        body = rest.to_s.split("\r\n\r\n", 2)[1].to_s
        {"ok" => true, "connected" => true, "status" => status_line.to_s.split(" ")[1].to_i, "body" => body.strip,
         "status_line" => status_line}
      rescue Timeout::Error, SystemCallError, IOError => error
        {"ok" => true, "connected" => false, "error" => "#{error.class}: #{error.message}"}
      ensure
        socket.close rescue nil
      end
    end

    def dig(request)
      command = ["dig", "@#{request.fetch("server")}", "-p", request.fetch("port").to_s, request.fetch("name"),
                 request.fetch("type", "A"), "+noall", "+answer", "+comments", "+time=2", "+tries=1"]
      command << "+tcp" if request["tcp"]
      output, error, status = Open3.capture3(*command)
      answers = output.lines.map(&:strip).reject { |line| line.empty? || line.start_with?(";") }.map { |line| line.split(/\s+/) }
      rcode = output[/status: ([A-Z]+)/, 1]
      {"ok" => true, "status" => status.exitstatus, "rcode" => rcode, "answers" => answers, "command" => command,
       "raw" => output, "stderr" => error}
    end

    def open_connection(request)
      id = request.fetch("id")
      address = request.fetch("address")
      socket = Socket.new(family_of(address), Socket::SOCK_STREAM, TCP)
      Timeout.timeout(CASE_TIMEOUT) { socket.connect(Socket.sockaddr_in(Integer(request.fetch("port")), address)) }
      socket.puts("open #{id}")
      reply = Timeout.timeout(CASE_TIMEOUT) { socket.gets }
      @connections[id] = socket
      peer = socket.remote_address
      local = socket.local_address
      {"ok" => true, "id" => id, "peer" => [peer.ip_address, peer.ip_port], "local" => [local.ip_address, local.ip_port],
       "reply" => reply && JSON.parse(reply)}
    rescue Timeout::Error, SystemCallError, IOError, JSON::ParserError => error
      socket&.close rescue nil
      {"ok" => true, "id" => id, "opened" => false, "error" => "#{error.class}: #{error.message}"}
    end

    def check_connection(request)
      id = request.fetch("id")
      socket = @connections.fetch(id)
      nonce = SecureRandom.hex(4)
      socket.puts("check #{id} #{nonce}")
      reply = Timeout.timeout(CASE_TIMEOUT) { socket.gets }
      parsed = reply && JSON.parse(reply)
      alive = parsed.is_a?(Hash) && parsed["payload"] == "check #{id} #{nonce}"
      {"ok" => true, "id" => id, "alive" => alive, "reply" => parsed}
    rescue Timeout::Error, SystemCallError, IOError, JSON::ParserError => error
      {"ok" => true, "id" => id, "alive" => false, "error" => "#{error.class}: #{error.message}"}
    end

    def close_all
      @connections.each_value { |socket| socket.close rescue nil }
      count = @connections.length
      @connections.clear
      {"ok" => true, "closed" => count}
    end
  end

  # ---------------------------------------------------------------------
  # Runner: protocol with the probe, agents, capture, kernel readback.
  # ---------------------------------------------------------------------
  class AgentHandle
    attr_reader :pid

    def initialize(netns_path, role)
      @stdin, @stdout, @stderr, @thread = Open3.popen3(
        "nsenter", "--net=#{netns_path}", "--", RbConfig.ruby, SOURCE_PATH, "--agent", role
      )
      @pid = @thread.pid
      @seq = 0
      ready = call("ping")
      raise "#{role} agent did not start in #{netns_path}: #{ready.inspect}" unless ready["ok"]
      @netns_inode = ready["netns"]
    end

    attr_reader :netns_inode

    def call(command, **arguments)
      @seq += 1
      @stdin.puts(JSON.generate({"cmd" => command, "seq" => @seq}.merge(arguments.transform_keys(&:to_s))))
      @stdin.flush
      line = @stdout.gets
      raise "agent #{command} produced no reply: #{@stderr.read}" if line.nil?

      response = JSON.parse(line)
      raise "agent #{command} failed: #{response["error"]}" if response["ok"] == false

      response
    end

    def close
      @stdin.close rescue nil
      if @thread.alive?
        Process.kill("TERM", @pid) rescue nil
        @thread.join(3) || (Process.kill("KILL", @pid) rescue nil)
      end
      @stdout.close rescue nil
      @stderr.close rescue nil
    end
  end

  class Runner
    attr_reader :started_at, :stdout_lines

    def initialize(input: STDIN, output: STDOUT)
      @input = input
      @output = output
      @started_at = Time.now.utc.iso8601(6)
      @stdout_lines = []
      @directory = Dir.mktmpdir("m4-proxy-parity-")
      @capture = nil
      @agents = {}
      @backends = {}
      @connection_ids = []
      @connection_observations = {}
      @topology = nil
      @objects = nil
      @cases = nil
    end

    def run
      @output.sync = true
      while (line = @input.gets)
        request = JSON.parse(line)
        phase = request.fetch("phase")
        response = handle(phase, request)
        if phase == "finish"
          @output.puts(JSON.generate(response))
          break
        end
        emit(response)
      end
    ensure
      cleanup
    end

    def emit(response)
      text = JSON.generate(response)
      @stdout_lines << text
      @output.puts(text)
    end

    def handle(phase, request)
      case phase
      when "init" then init(request)
      when "corpus" then corpus(request)
      when "connections_open" then connections_open(request)
      when "connections_check" then connections_check(request)
      when "measure" then measure(request)
      when "finish" then finish(request)
      else {"phase" => phase, "ok" => false, "error" => "unknown phase"}
      end
    rescue StandardError => error
      {"phase" => phase, "ok" => false, "error" => "#{error.class}: #{error.message}", "backtrace" => error.backtrace.first(6)}
    end

    # --- phases -----------------------------------------------------------

    def init(request)
      @topology = request.fetch("topology")
      @objects = request.fetch("objects")
      @cases = request.fetch("cases")
      @namespaces = request.fetch("namespaces")
      corpus_sha256 = M4ProxyParityCorpus.digest(@objects.merge("cases" => @cases, "topology" => @topology))
      unless corpus_sha256 == M4ProxyParityCorpus.corpus_sha256
        raise "probe corpus digest #{corpus_sha256} differs from the shared corpus #{M4ProxyParityCorpus.corpus_sha256}"
      end

      %w[node client backend].each do |role|
        path = @namespaces.fetch(role)
        raise "#{role} namespace #{path} is not live" unless File.exist?(path)
      end
      @agents["client"] = AgentHandle.new(@namespaces.fetch("client"), "client")
      @agents["backend"] = AgentHandle.new(@namespaces.fetch("backend"), "backend")
      @agents.fetch("backend").call("serve", addresses: {"ipv4" => @topology.dig("backend", "ipv4"),
                                                         "ipv6" => @topology.dig("backend", "ipv6")},
                                             ports: @topology.fetch("ports"))
      start_capture
      {
        "phase" => "init", "ok" => true,
        "runner" => provenance,
        "corpus_sha256" => corpus_sha256,
        "agents" => @agents.transform_values { |agent| {"pid" => agent.pid, "netns_inode" => agent.netns_inode} },
        "capture" => {"path" => @capture.fetch(:path), "pid" => @capture.fetch(:pid)}
      }
    end

    def corpus(request)
      backend = request.fetch("backend")
      raise "unknown backend #{backend}" unless %w[ebpf nftables].include?(backend)

      results = @cases.map { |kase| run_case(kase, backend) }
      readback = backend == "ebpf" ? ebpf_readback(request.fetch("kernel")) : nftables_readback(request.fetch("kernel"))
      @backends[backend] = {"cases" => results, "readback" => readback, "kernel_input" => request.fetch("kernel")}
      {"phase" => "corpus", "ok" => true, "backend" => backend,
       "passed" => results.all? { |entry| entry["passed"] } && readback["readback"] == true,
       "case_count" => results.length, "failed_cases" => results.reject { |entry| entry["passed"] }.map { |entry| entry["id"] },
       "cases" => results, "readback" => readback}
    end

    def connections_open(request)
      count = Integer(request.fetch("count", 4))
      service = find_service(request.fetch("service", "clusterip-tcp"))
      vip = service.dig("spec", "clusterIPs").find { |ip| !ip.include?(":") }
      port = service.dig("spec", "ports").first.fetch("port")
      @agents.fetch("client").call("close_all")
      @connection_ids = count.times.map { |index| "conn-#{index}-#{SecureRandom.hex(3)}" }
      opened = @connection_ids.map do |id|
        @agents.fetch("client").call("open", id: id, address: vip, port: port)
      end
      failures = opened.select { |entry| entry["opened"] == false }
      raise "could not open all connections: #{failures.inspect}" unless failures.empty?

      observation = {"backend" => request["backend"], "connection_ids" => @connection_ids.sort,
                     "connections" => opened.map { |entry| entry.slice("id", "peer", "local") },
                     "observed_at" => Time.now.utc.iso8601(6)}
      @connection_observations["before"] = observation
      {"phase" => "connections_open", "ok" => true}.merge(observation)
    end

    def connections_check(request)
      checks = @connection_ids.map { |id| @agents.fetch("client").call("check", id: id) }
      observation = {"backend" => request["backend"], "connection_ids" => @connection_ids.sort,
                     "checks" => checks.map { |entry| entry.slice("id", "alive", "error") },
                     "alive_count" => checks.count { |entry| entry["alive"] },
                     "observed_at" => Time.now.utc.iso8601(6)}
      @connection_observations["after"] = observation
      {"phase" => "connections_check", "ok" => true}.merge(observation)
    end

    def measure(request)
      before = @connection_observations.fetch("before")
      after = @connection_observations.fetch("after")
      active = before.fetch("connection_ids").length
      lost = after.fetch("checks").count { |entry| entry["alive"] != true }
      raw = {"before" => before, "after" => after, "fromBackend" => request["from_backend"],
             "toBackend" => request["to_backend"], "activeConnections" => active, "lostConnections" => lost}
      @agents.fetch("client").call("close_all")
      @connection_observations["measurement"] = raw
      {"phase" => "measure", "ok" => true, "active_connections" => active, "lost_connections" => lost,
       "connection_ids" => before.fetch("connection_ids"), "raw_observation" => raw,
       "raw_observation_digest" => M4ProxyParityCorpus.digest(raw),
       "runner_identity" => RUNNER_IDENTITY, "runner_digest" => runner_digest}
    end

    def finish(_request)
      stop_capture
      stdout = @stdout_lines.join("\n") + "\n"
      runner = provenance.merge("stdout" => stdout, "stdoutSha256" => Digest::SHA256.hexdigest(stdout),
                                "finishedAt" => Time.now.utc.iso8601(6))
      packet_count = pcap_packet_count(@capture.fetch(:path))
      pcap_sha = Digest::SHA256.file(@capture.fetch(:path)).hexdigest
      packet_capture = {"format" => "pcap", "sha256" => pcap_sha, "packetCount" => packet_count,
                        "source" => @capture.fetch(:path), "interface" => "any",
                        "command" => @capture.fetch(:command), "bytes" => File.size(@capture.fetch(:path))}
      raw_trace = {"packetCapture" => packet_capture,
                   "backends" => @backends.transform_values { |entry| entry.fetch("cases").map { |kase| kase.fetch("observation") } }}
      {
        "phase" => "finish", "ok" => true,
        "runnerIdentity" => RUNNER_IDENTITY, "runnerDigest" => runner_digest, "mode" => RUNNER_MODE,
        "measurementSource" => "external_isolated_netns_packet_corpus_and_kernel_readback",
        "runner" => runner,
        "packetCapture" => packet_capture,
        "rawPacketTrace" => raw_trace,
        "packetTraceSha256" => M4ProxyParityCorpus.digest(raw_trace),
        "backends" => @backends,
        "connectionSwitch" => @connection_observations,
        "corpusSha256" => M4ProxyParityCorpus.corpus_sha256,
        "namespaces" => @namespaces,
        "tools" => tool_versions
      }
    end

    # --- case execution ---------------------------------------------------

    def run_case(kase, backend)
      expected = expected_for(kase, backend)
      observation, actual = observe(kase, backend, expected)
      passed = M4ProxyParityCorpus.canonical(expected) == M4ProxyParityCorpus.canonical(actual)
      {
        "id" => kase.fetch("id"), "case" => kase.fetch("id"), "backend" => backend, "kind" => kase.fetch("kind"),
        "service" => kase.fetch("service"), "family" => kase.fetch("family"), "protocol" => kase.fetch("protocol"),
        "expected" => expected, "actual" => actual,
        "expectedSha256" => M4ProxyParityCorpus.digest(expected), "actualSha256" => M4ProxyParityCorpus.digest(actual),
        "passed" => passed, "observation" => observation
      }
    rescue StandardError => error
      {"id" => kase.fetch("id"), "case" => kase.fetch("id"), "backend" => backend, "passed" => false,
       "expected" => expected, "actual" => {"error" => "#{error.class}: #{error.message}"},
       "expectedSha256" => M4ProxyParityCorpus.digest(expected), "actualSha256" => M4ProxyParityCorpus.digest({"error" => error.message}),
       "observation" => {"error" => "#{error.class}: #{error.message}", "backtrace" => error.backtrace.first(5)}}
    end

    def find_service(name)
      @objects.fetch("services").find { |service| service.dig("metadata", "name") == name } ||
        raise("service #{name} is not in the corpus")
    end

    def endpoints_for(service_name, family, protocol)
      address_type = family == "ipv6" ? "IPv6" : "IPv4"
      @objects.fetch("endpoint_slices").select do |slice|
        slice.dig("metadata", "labels", "kubernetes.io/service-name") == service_name &&
          slice.fetch("addressType") == address_type &&
          slice.fetch("ports").any? { |port| port.fetch("protocol") == protocol }
      end.flat_map do |slice|
        port = slice.fetch("ports").find { |entry| entry.fetch("protocol") == protocol }.fetch("port")
        slice.fetch("endpoints").map { |endpoint| endpoint.merge("port" => port, "address" => endpoint.fetch("addresses").first) }
      end
    end

    # Kubernetes endpoint selection: ready endpoints; if none, terminating
    # endpoints that are still serving (KEP-1672); traffic policy Local keeps
    # only endpoints on this node.
    def candidate_endpoints(kase, family)
      service = find_service(kase.fetch("service"))
      endpoints = endpoints_for(kase.fetch("service"), family, kase.fetch("protocol"))
      ready = endpoints.select { |endpoint| condition(endpoint, "ready") && condition(endpoint, "serving") && !condition(endpoint, "terminating") }
      selected = ready.any? ? ready : endpoints.select { |endpoint| condition(endpoint, "terminating") && condition(endpoint, "serving") }
      internal_local = service.dig("spec", "internalTrafficPolicy") == "Local"
      external_local = service.dig("spec", "externalTrafficPolicy") == "Local"
      external_kinds = %w[node_port external_ip load_balancer]
      local = (external_kinds.include?(kase.fetch("kind")) && external_local) || (kase.fetch("kind") == "vip" && internal_local)
      selected = selected.select { |endpoint| endpoint["nodeName"] == M4ProxyParityCorpus::NODE_NAME } if local
      selected
    end

    def condition(endpoint, name)
      value = endpoint.dig("conditions", name)
      value.nil? ? (name == "ready") : value == true
    end

    def destination_for(kase, family)
      service = find_service(kase.fetch("service"))
      spec = service.fetch("spec")
      port_spec = spec.fetch("ports").first
      v6 = family == "ipv6"
      case kase.fetch("kind")
      when "vip", "affinity", "fragments", "dual_stack"
        [spec.fetch("clusterIPs").find { |ip| ip.include?(":") == v6 }, port_spec.fetch("port")]
      when "node_port"
        [@topology.fetch("node_port_addresses").fetch(family), port_spec.fetch("nodePort")]
      when "external_ip"
        [spec.fetch("externalIPs").find { |ip| ip.include?(":") == v6 }, port_spec.fetch("port")]
      when "load_balancer"
        [spec.fetch("loadBalancerIPs").find { |ip| ip.include?(":") == v6 }, port_spec.fetch("port")]
      when "headless"
        endpoint = candidate_endpoints(kase, family).first
        [endpoint.fetch("address"), endpoint.fetch("port")]
      when "health_check"
        [@topology.fetch("node_port_addresses").fetch(family), spec.fetch("healthCheckNodePort")]
      else
        raise ArgumentError, "no destination for #{kase.fetch("kind")}"
      end
    end

    # Masquerade rule (kube-proxy): traffic entering through a NodePort,
    # ExternalIP, or LoadBalancer IP with externalTrafficPolicy Cluster is
    # SNATed to the node; ClusterIP and Local-policy traffic keeps the client
    # source.
    def expected_client_source(kase, family)
      service = find_service(kase.fetch("service"))
      external = %w[node_port external_ip load_balancer].include?(kase.fetch("kind"))
      if external && service.dig("spec", "externalTrafficPolicy") != "Local"
        node = @topology.fetch("node_addresses").find { |ip| ip.include?(":") == (family == "ipv6") }
        "masqueraded:#{node}"
      else
        "preserved"
      end
    end

    def vip_expectation(kase, family)
      destination = destination_for(kase, family)
      {"verdict" => "dnat", "delivered" => true, "destination_in_endpoint_set" => true,
       "client_source" => expected_client_source(kase, family),
       "reply_source" => "#{destination[0]}|#{destination[1]}", "protocol" => kase.fetch("protocol"),
       "reply_source_distinct_from_endpoint" => true}
    end

    def expected_for(kase, _backend)
      family = kase.fetch("family")
      case kase.fetch("kind")
      when "vip", "node_port", "external_ip", "load_balancer"
        vip_expectation(kase, family)
      when "headless"
        destination = destination_for(kase, family)
        {"verdict" => "passthrough", "delivered" => true, "destination" => "#{destination[0]}|#{destination[1]}",
         "client_source" => "preserved", "reply_source" => "#{destination[0]}|#{destination[1]}", "protocol" => kase.fetch("protocol")}
      when "fragments"
        {"verdict" => "dropped", "delivered" => false, "backend_received" => false, "protocol" => "UDP"}
      when "health_check"
        {"verdict" => "local_health_check", "http_status" => 200, "body" => "OK"}
      when "dns_cname"
        target = find_service(kase.fetch("target_service"))
        {"verdict" => "cname", "cname" => "#{kase.fetch("target_service")}.#{M4ProxyParityCorpus::NAMESPACE}.svc.#{M4ProxyParityCorpus::CLUSTER_DOMAIN}.",
         "addresses" => target.dig("spec", "clusterIPs").select { |ip| !ip.include?(":") }.sort, "rcode" => "NOERROR"}
      when "affinity"
        {"verdict" => "affinity", "connections" => kase.fetch("connections"), "all_delivered" => true, "distinct_endpoints" => 1,
         "client_source" => "preserved"}
      when "dual_stack"
        {"ipv4" => vip_expectation(kase, "ipv4"), "ipv6" => vip_expectation(kase, "ipv6"), "verdict" => "dual_stack"}
      else
        raise ArgumentError, "unknown case kind #{kase.fetch("kind")}"
      end
    end

    def observe(kase, backend, expected)
      family = kase.fetch("family")
      case kase.fetch("kind")
      when "vip", "node_port", "external_ip", "load_balancer"
        observe_vip(kase, family, backend)
      when "headless"
        destination = destination_for(kase, family)
        observation = exchange(kase, destination, backend)
        reply = observation["reply"]
        actual = {"verdict" => "passthrough", "delivered" => observation["delivered"],
                  "destination" => reply.is_a?(Hash) ? "#{reply.dig("local", 0)}|#{reply.dig("local", 1)}" : nil,
                  "client_source" => observed_client_source(reply, family),
                  "reply_source" => observation["reply_source"], "protocol" => kase.fetch("protocol")}
        [observation, actual]
      when "fragments"
        destination = destination_for(kase, family)
        payload = "m4:#{backend}:#{kase.fetch("id")}:#{SecureRandom.hex(4)}"
        result = @agents.fetch("client").call("datagram", address: destination[0], port: destination[1], payload: payload,
                                                          size: FRAGMENT_PAYLOAD_BYTES, timeout: FRAGMENT_TIMEOUT)
        received = @agents.fetch("backend").call("received", payload: payload.ljust(FRAGMENT_PAYLOAD_BYTES, "x"))
        observation = {"client" => result, "backend" => received, "destination" => destination, "payload_bytes" => FRAGMENT_PAYLOAD_BYTES}
        actual = {"verdict" => result["replied"] || received["received"] ? "delivered" : "dropped",
                  "delivered" => result["replied"] == true, "backend_received" => received["received"] == true, "protocol" => "UDP"}
        [observation, actual]
      when "health_check"
        destination = destination_for(kase, family)
        result = @agents.fetch("client").call("http", address: destination[0], port: destination[1], path: "/healthz")
        actual = {"verdict" => result["connected"] ? "local_health_check" : "unreachable", "http_status" => result["status"],
                  "body" => result["body"]}
        [result.merge("destination" => destination), actual]
      when "dns_cname"
        dns = @topology.fetch("dns")
        name = "#{kase.fetch("service")}.#{M4ProxyParityCorpus::NAMESPACE}.svc.#{M4ProxyParityCorpus::CLUSTER_DOMAIN}"
        udp = @agents.fetch("client").call("dig", server: dns.fetch("address"), port: dns.fetch("port"), name: name, type: "A")
        tcp = @agents.fetch("client").call("dig", server: dns.fetch("address"), port: dns.fetch("port"), name: name, type: "A", tcp: true)
        cname = udp["answers"].find { |fields| fields[3] == "CNAME" }
        addresses = udp["answers"].select { |fields| fields[3] == "A" }.map(&:last).sort
        actual = {"verdict" => cname ? "cname" : "no_cname", "cname" => cname&.last, "addresses" => addresses, "rcode" => udp["rcode"]}
        actual["rcode"] = "tcp_mismatch" unless tcp["answers"] == udp["answers"]
        [{"udp" => udp, "tcp" => tcp, "name" => name}, actual]
      when "affinity"
        destination = destination_for(kase, family)
        results = kase.fetch("connections").times.map { exchange(kase, destination, backend) }
        endpoints = results.map { |entry| entry["observed_endpoint"] }.compact.uniq
        actual = {"verdict" => "affinity", "connections" => results.length, "all_delivered" => results.all? { |entry| entry["delivered"] },
                  "distinct_endpoints" => endpoints.length, "client_source" => observed_client_source(results.first["reply"], family)}
        [{"exchanges" => results, "destination" => destination}, actual]
      when "dual_stack"
        v4_observation, v4_actual = observe_vip(kase, "ipv4", backend)
        v6_observation, v6_actual = observe_vip(kase, "ipv6", backend)
        [{"ipv4" => v4_observation, "ipv6" => v6_observation}, {"ipv4" => v4_actual, "ipv6" => v6_actual, "verdict" => "dual_stack"}]
      else
        raise ArgumentError, "unknown case kind #{kase.fetch("kind")}"
      end
    end

    def observe_vip(kase, family, backend)
      destination = destination_for(kase, family)
      observation = exchange(kase, destination, backend)
      endpoint_set = candidate_endpoints(kase, family).map { |endpoint| "#{endpoint.fetch("address")}|#{endpoint.fetch("port")}" }
      observed = observation["observed_endpoint"]
      reply = observation["reply"]
      actual = {"verdict" => observation["delivered"] ? "dnat" : "undelivered", "delivered" => observation["delivered"],
                "destination_in_endpoint_set" => !observed.nil? && endpoint_set.include?(observed),
                "client_source" => observed_client_source(reply, family),
                "reply_source" => observation["reply_source"], "protocol" => kase.fetch("protocol"),
                "reply_source_distinct_from_endpoint" => !observed.nil? && observation["reply_source"] != observed}
      [observation.merge("endpoint_set" => endpoint_set), actual]
    end

    # One request/response exchange from the client namespace.  The reply is
    # the backend agent's JSON record naming the peer (what the backend saw as
    # the client) and the local socket (which endpoint served the request).
    def exchange(kase, destination, backend)
      payload = "m4:#{backend}:#{kase.fetch("id")}:#{SecureRandom.hex(4)}"
      result = if kase.fetch("protocol") == "UDP"
                 @agents.fetch("client").call("datagram", address: destination[0], port: destination[1], payload: payload)
               else
                 @agents.fetch("client").call("stream", protocol: kase.fetch("protocol"), address: destination[0],
                                                        port: destination[1], payload: payload)
               end
      reply = result["reply"]
      delivered = reply.is_a?(Hash) && reply["payload"] == payload
      reply_source = if kase.fetch("protocol") == "UDP"
                       result["from"] && "#{result["from"][0]}|#{result["from"][1]}"
                     else
                       result["peer"] && "#{result["peer"][0]}|#{result["peer"][1]}"
                     end
      result.merge("payload" => payload, "delivered" => delivered, "reply_source" => reply_source,
                   "observed_endpoint" => reply.is_a?(Hash) ? "#{reply.dig("local", 0)}|#{reply.dig("local", 1)}" : nil,
                   "destination" => destination)
    end

    def observed_client_source(reply, family)
      return nil unless reply.is_a?(Hash)

      peer = reply.dig("peer", 0).to_s
      client = @topology.fetch("client").fetch(family)
      return "preserved" if canonical_ip(peer) == canonical_ip(client)

      "masqueraded:#{peer}"
    end

    def canonical_ip(value)
      IPAddr.new(value.to_s).to_s
    rescue IPAddr::InvalidAddressError
      value.to_s
    end

    # --- kernel readback (independent tools inside the node namespace) -----

    def node_command(*command)
      output, error, status = Open3.capture3("nsenter", "--net=#{@namespaces.fetch("node")}", "--", *command)
      raise "#{command.join(" ")} failed: #{error.strip}" unless status.success?

      output
    end

    def ebpf_readback(kernel)
      program_id = Integer(kernel.fetch("program_id"))
      program = JSON.parse(node_command("bpftool", "-j", "prog", "show", "id", program_id.to_s))
      maps = kernel.fetch("map_ids").to_h do |name, id|
        [name, JSON.parse(node_command("bpftool", "-j", "map", "show", "id", id.to_s))]
      end
      filters = kernel.fetch("interfaces").flat_map do |interface|
        %w[ingress egress].flat_map do |direction|
          # tc prints a chain header entry without options before each
          # filter; only entries that carry the attached program are filters.
          JSON.parse(node_command("tc", "-j", "filter", "show", "dev", interface, direction)).select { |entry| entry["options"].is_a?(Hash) }.map do |entry|
            entry.merge("interface" => interface, "direction" => direction)
          end
        end
      end
      service_dump = JSON.parse(node_command("bpftool", "-j", "map", "dump", "id", kernel.fetch("map_ids").fetch("service_rules").to_s))
      present_keys = service_dump.map { |entry| Array(entry["key"]).map { |byte| byte.sub("0x", "").rjust(2, "0") }.join }
      bindings = kernel.fetch("service_keys").map do |binding|
        binding.merge("present" => present_keys.include?(binding.fetch("key_hex").downcase))
      end
      # iproute2 reports the attached program either as options.id (older
      # tc) or nested under options.prog.id (tc >= 6.x); accept both.
      filter_program_id = ->(entry) { entry.dig("options", "id") || entry.dig("options", "prog", "id") }
      filter_program_ids = filters.filter_map { |entry| filter_program_id.call(entry) }.uniq
      verifier_log_sha256 = kernel["verifier_log_sha256"]
      readback = filters.any? && bindings.all? { |entry| entry["present"] } && program["id"] == program_id &&
                 filter_program_ids.include?(program_id)
      {
        "readback" => readback, "backend" => "ebpf",
        "program" => {"id" => program["id"], "tag" => program["tag"], "type" => program["type"], "name" => program["name"],
                      "bytes_xlated" => program["bytes_xlated"], "bytes_jited" => program["bytes_jited"],
                      "map_ids" => program["map_ids"], "verified_insns" => program["verified_insns"]},
        "maps" => maps.map { |name, info| {"name" => name, "id" => info["id"], "kernel_name" => info["name"], "type" => info["type"],
                                            "key_size" => info["bytes_key"], "value_size" => info["bytes_value"],
                                            "max_entries" => info["max_entries"]} },
        "filters" => filters.map { |entry| {"ifindex" => ifindex_of(entry.fetch("interface")), "interface" => entry.fetch("interface"),
                                             "direction" => entry.fetch("direction"), "handle" => entry["options"] && entry["options"]["handle"],
                                             "programId" => filter_program_id.call(entry), "program_id" => filter_program_id.call(entry),
                                             "pref" => entry["pref"], "kind" => entry["kind"]} },
        "filter_program_ids" => filter_program_ids,
        "service_rule_bindings" => bindings,
        "service_rule_entry_count" => service_dump.length,
        "verifier_log_sha256" => verifier_log_sha256,
        "tools" => {"bpftool" => tool_version("bpftool", "--version"), "tc" => tool_version("tc", "-V")}
      }
    end

    # sysfs inside nsenter still shows the mounting namespace's devices, so
    # the ifindex is read through rtnetlink (ip -j) in the node namespace.
    def ifindex_of(interface)
      entries = JSON.parse(node_command("ip", "-j", "link", "show", "dev", interface))
      Integer(entries.first.fetch("ifindex"))
    end

    def nftables_readback(kernel)
      table = kernel.fetch("table")
      json = JSON.parse(node_command("nft", "-j", "list", "table", "inet", table))
      text = node_command("nft", "list", "table", "inet", table)
      entries = json.fetch("nftables")
      chains = entries.filter_map { |entry| entry["chain"] }
      sets = entries.filter_map { |entry| entry["set"] || entry["map"] }
      rules = entries.filter_map { |entry| entry["rule"] }
      chain_names = chains.map { |chain| chain["name"] }
      set_names = sets.map { |set| set["name"] }
      bindings = kernel.fetch("chain_bindings").map do |binding|
        binding.merge("present" => chain_names.include?(binding.fetch("chain")) &&
                                   Array(binding["sets"]).all? { |set| set_names.include?(set) })
      end
      {
        "readback" => bindings.all? { |entry| entry["present"] } && rules.any?,
        "backend" => "nftables", "family" => "inet", "table" => table,
        "table_identity" => entries.filter_map { |entry| entry["table"] }.first,
        "chains" => chains.map { |chain| chain.slice("name", "handle", "type", "hook", "prio", "policy") },
        "sets" => sets.map { |set| set.slice("name", "handle", "type", "flags", "elem") },
        "rule_count" => rules.length,
        "rule_handles" => rules.map { |rule| rule["handle"] },
        "chain_bindings" => bindings,
        "ruleset_text_sha256" => Digest::SHA256.hexdigest(text),
        "ruleset_json_sha256" => Digest::SHA256.hexdigest(JSON.generate(json)),
        "tools" => {"nft" => tool_version("nft", "--version")}
      }
    end

    # --- capture ----------------------------------------------------------

    def start_capture
      path = File.join(@directory, "proxy-parity.pcap")
      log = File.join(@directory, "tcpdump.log")
      command = ["nsenter", "--net=#{@namespaces.fetch("node")}", "--", "tcpdump", "--immediate-mode", "-U", "-n",
                 "-i", "any", "-w", path]
      pid = Process.spawn(*command, out: File::NULL, err: log)
      200.times do
        break if File.file?(log) && File.read(log).include?("listening on")

        sleep(0.02)
      end
      @capture = {path: path, pid: pid, command: command, log: log}
    end

    def stop_capture
      return unless @capture && @capture[:pid]

      pid = @capture.delete(:pid)
      Process.kill("TERM", pid)
      50.times do
        break if Process.waitpid(pid, Process::WNOHANG)

        sleep(0.05)
      end
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end

    def pcap_packet_count(path)
      output, _error, status = Open3.capture3("tcpdump", "-n", "-r", path)
      raise "tcpdump could not read #{path}" unless status.success?

      output.lines.count
    end

    # --- provenance -------------------------------------------------------

    def runner_digest
      @runner_digest ||= Digest::SHA256.file(SOURCE_PATH).hexdigest
    end

    def provenance
      {"pid" => Process.pid, "startedAt" => @started_at, "source" => SOURCE_PATH, "argv" => [RbConfig.ruby, SOURCE_PATH, *ARGV],
       "identity" => RUNNER_IDENTITY, "digest" => runner_digest, "mode" => RUNNER_MODE,
       "start_time_ticks" => proc_start_time_ticks(Process.pid), "corpus_source" => File.expand_path("corpus.rb", __dir__),
       "corpus_source_sha256" => Digest::SHA256.file(File.expand_path("corpus.rb", __dir__)).hexdigest}
    end

    def proc_start_time_ticks(pid)
      stat = File.binread("/proc/#{pid}/stat")
      Integer(stat[(stat.rindex(")") + 2)..].split.fetch(19))
    end

    def tool_version(*command)
      output, error, = Open3.capture3(*command)
      (output + error).lines.first.to_s.strip
    end

    def tool_versions
      {"bpftool" => tool_version("bpftool", "--version"), "tc" => tool_version("tc", "-V"), "nft" => tool_version("nft", "--version"),
       "tcpdump" => tool_version("tcpdump", "--version"), "dig" => tool_version("dig", "-v"), "ruby" => RUBY_DESCRIPTION}
    end

    def cleanup
      stop_capture
      @agents.each_value(&:close)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  if ARGV[0] == "--agent"
    M4ProxyParityRunner::Agent.new(ARGV.fetch(1)).run
  else
    M4ProxyParityRunner::Runner.new.run
  end
end
