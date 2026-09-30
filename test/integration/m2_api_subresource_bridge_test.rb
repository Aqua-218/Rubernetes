# frozen_string_literal: true

require "fileutils"
require "base64"
require "net/http"
require "socket"
require "stringio"
require "timeout"

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"
require "rubernetes/runtime/native"
require "rubernetes/transport"

class M2APISubresourceBridgeTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  class NonblockingIO
    def initialize(value)
      @io = StringIO.new(String(value).b)
    end

    def read_nonblock(length)
      value = @io.read(length)
      raise EOFError if value.nil? || value.empty?

      value
    end

    def close
      @io.close
    end
  end

  class ProcessAdapter
    def initialize(stdout: "native-log\xFF\n".b, stderr: "native-error\xFE\n".b)
      @stdout = stdout
      @stderr = stderr
      @pid = 40_000
    end

    def spawn(**_options)
      @pid += 1
      {
        pid: @pid,
        pidfd: nil,
        gate: nil,
        stdout: NonblockingIO.new(@stdout),
        stderr: NonblockingIO.new(@stderr),
        cgroup: nil
      }
    end

    def wait(pid:, timeout: nil)
      {exit_status: 0, term_signal: nil, code: 0}
    end

    def signal(pid:, signal:)
      true
    end

    def release_gate(_gate)
      true
    end
  end

  class Connector
    attr_reader :calls

    def initialize
      @calls = []
    end

    def exec(**arguments)
      @calls << [:exec, arguments]
      {stdin: StringIO.new, stdout: "native-exec\xFF".b, stderr: "native-exec-error".b, status: 0}
    end

    def attach(**arguments)
      @calls << [:attach, arguments]
      {stdin: StringIO.new, stdout: "native-attach\xFE".b, stderr: "native-attach-error".b, status: 0}
    end

    def port_forward(**arguments)
      @calls << [:port_forward, arguments]
      {stdin: StringIO.new, stdout: "native-forward\xFD".b, stderr: nil, status: 0}
    end
  end

  class LifecycleRecord
    def initialize(container_id)
      @container_id = container_id
    end

    def record(_pod)
      {containers: [{id: @container_id, name: "app", state: "running"}]}
    end
  end

  def setup
    @directory = Dir.mktmpdir("m2-api-subresource-bridge-")
    @connector = Connector.new
    @runtime = Native.new(
      profile: :pure,
      process_adapter: ProcessAdapter.new,
      exec_adapter: @connector,
      attach_adapter: @connector,
      port_forward_adapter: @connector,
      sandbox_root: File.join(@directory, "sandboxes"),
      log_root: File.join(@directory, "logs"),
      journal_path: File.join(@directory, "journal.wal")
    )
    @sandbox = @runtime.run_sandbox({}, request_id: "bridge-sandbox")
    @container = @runtime.create_container(@sandbox, {"id" => "bridge-container", "command" => ["/bin/true"]})
    @runtime.start_container(@container)

    node_agent = Struct.new(:lifecycle).new(LifecycleRecord.new(@container.id))
    @agent = Rubernetes::Bootstrap::AgentService.new(
      config: {},
      logger: Object.new,
      runtime: @runtime,
      node_agent: node_agent,
      authorizer: ->(**_context) { true }
    )
    @authorization_contexts = []
    authorizer = lambda { |**context|
      @authorization_contexts << context
      true
    }
    @api = Rubernetes::API::Server.new(
      node_resolver: {"node-a" => @agent},
      authorizer: authorizer,
      identity_resolver: ->(request) { request.header("x-rubernetes-identity") }
    )
    @http = Rubernetes::Transport::HTTPServer.new(@api, port: 0, max_response_bytes: 2 * 1024 * 1024)
    @http.start
  end

  def teardown
    @http&.stop
    @runtime&.remove_sandbox(@sandbox) if @sandbox && @runtime
    FileUtils.remove_entry(@directory) if @directory && File.exist?(@directory)
  rescue StandardError
    FileUtils.remove_entry(@directory) if @directory && File.exist?(@directory)
  end

  def test_apply_then_reaches_native_runtime_for_all_four_pod_subresources
    discovery = request("GET", "/api/v1")

    assert_equal "200", discovery.code
    discovered = JSON.parse(discovery.body).fetch("resources")
    %w[pods/log pods/exec pods/attach pods/portforward].each do |name|
      entry = discovered.find { |resource| resource.fetch("name") == name }

      refute_nil entry, name
      assert_includes entry.fetch("verbs"), "get"
    end

    manifest = {
      "apiVersion" => "v1",
      "kind" => "Pod",
      "metadata" => {"name" => "bridge-pod"},
      "spec" => {
        "nodeName" => "node-a",
        "containers" => [{"name" => "app", "image" => "example/app:latest"}]
      }
    }
    applied = request(
      "PATCH",
      "/api/v1/namespaces/default/pods/bridge-pod?fieldManager=m2-e2e",
      body: JSON.generate(manifest),
      content_type: "application/apply-patch+yaml"
    )

    assert_equal "201", applied.code

    expected = {
      # A container's log is both streams, as the CRI records them.
      "log" => "native-log\xFF\nnative-error\xFE\n".b,
      "exec" => "native-exec\xFF".b,
      "attach" => "native-attach\xFE".b,
      "portforward" => "native-forward\xFD".b
    }
    paths = {
      "log" => "/api/v1/namespaces/default/pods/bridge-pod/log",
      "exec" => "/api/v1/namespaces/default/pods/bridge-pod/exec?command=%2Fbin%2Fecho&command=hello",
      "attach" => "/api/v1/namespaces/default/pods/bridge-pod/attach",
      "portforward" => "/api/v1/namespaces/default/pods/bridge-pod/portforward?ports=8080"
    }
    paths.each do |subresource, path|
      response = request("GET", path)

      assert_equal "200", response.code, subresource
      assert_equal expected.fetch(subresource), response.body.b, subresource
    end

    calls = @connector.calls

    assert_equal %i[exec attach port_forward], calls.map(&:first)
    calls.each do |_operation, arguments|
      assert_equal @container.id, arguments.fetch(:container).id
      assert_equal "e2e-user", arguments.fetch(:identity)
    end
    assert_equal 4, @authorization_contexts.length
    duplex_contexts = @authorization_contexts.reject { |context| context.fetch(:subresource) == "log" }

    duplex_contexts.zip(calls).each do |context, (_operation, arguments)|
      assert_equal arguments.fetch(:request_id), context.fetch(:request_id)
    end

    stored = request("GET", "/api/v1/namespaces/default/pods/bridge-pod")

    assert_equal "200", stored.code
    assert_equal manifest.fetch("spec"), JSON.parse(stored.body).fetch("spec")
  end

  def test_public_streaming_subresources_fail_closed_without_identity_and_policy
    manifest = {
      "apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "closed"},
      "spec" => {"nodeName" => "node-a", "containers" => [{"name" => "app", "image" => "x"}]}
    }

    assert_equal "201", request(
      "PATCH", "/api/v1/namespaces/default/pods/closed?fieldManager=closed",
      body: JSON.generate(manifest), content_type: "application/apply-patch+yaml"
    ).code

    no_identity_api = Rubernetes::API::Server.new(store: @api.store, node_resolver: {"node-a" => @agent})
    no_identity_response = no_identity_api.call(
      method: "GET", path: "/api/v1/namespaces/default/pods/closed/log"
    )

    assert_equal 401, no_identity_response.status

    no_policy_api = Rubernetes::API::Server.new(
      store: @api.store,
      node_resolver: {"node-a" => @agent},
      identity_resolver: ->(_request) { "authenticated" }
    )
    no_policy_response = no_policy_api.call(
      method: "GET", path: "/api/v1/namespaces/default/pods/closed/log"
    )

    assert_equal 503, no_policy_response.status

    no_node_api = Rubernetes::API::Server.new(
      store: @api.store,
      authorizer: ->(**_context) { true },
      identity_resolver: ->(_request) { "authenticated" }
    )
    no_node_response = no_node_api.call(
      method: "GET", path: "/api/v1/namespaces/default/pods/closed/log"
    )

    assert_equal 503, no_node_response.status

    denied_api = Rubernetes::API::Server.new(
      store: @api.store,
      node_resolver: {"node-a" => @agent},
      authorizer: ->(**_context) { false },
      identity_resolver: ->(_request) { "authenticated" }
    )
    denied_response = denied_api.call(
      method: "GET", path: "/api/v1/namespaces/default/pods/closed/log"
    )

    assert_equal 403, denied_response.status
  end

  def test_exec_websocket_upgrade_preserves_binary_duplex_framing
    manifest = {
      "apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "bridge-pod"},
      "spec" => {"nodeName" => "node-a", "containers" => [{"name" => "app", "image" => "x"}]}
    }

    assert_equal "201", request(
      "PATCH", "/api/v1/namespaces/default/pods/bridge-pod?fieldManager=websocket",
      body: JSON.generate(manifest), content_type: "application/apply-patch+yaml"
    ).code
    key = Base64.strict_encode64("0123456789abcdef")
    socket = TCPSocket.new("127.0.0.1", @http.port)
    request = [
      "GET /api/v1/namespaces/default/pods/bridge-pod/exec?command=%2Fbin%2Fecho HTTP/1.1",
      "Host: 127.0.0.1",
      "Connection: Upgrade",
      "Upgrade: websocket",
      "Sec-WebSocket-Version: 13",
      "Sec-WebSocket-Key: #{key}",
      "Sec-WebSocket-Protocol: v5.channel.k8s.io",
      "X-Rubernetes-Identity: e2e-user",
      ""
    ].join("\r\n") + "\r\n"
    socket.write(request + websocket_frame("stdin\xFF".b, opcode: 0x2))
    headers = Timeout.timeout(2) { read_until(socket, "\r\n\r\n") }

    assert_match(%r{HTTP/1\.1 101 Switching Protocols}, headers)
    assert_match(/Sec-WebSocket-Protocol: v5\.channel\.k8s\.io/i, headers)
    assert_match(/Sec-WebSocket-Accept:/i, headers)

    opcode, payload = Timeout.timeout(2) { read_websocket_frame(socket) }

    assert_equal 0x2, opcode
    assert_equal "native-exec\xFF".b, payload

    socket.write(websocket_frame("", opcode: 0x8))
  ensure
    socket&.close
  end

  private

  def request(method, path, body: nil, content_type: nil)
    uri = URI("http://127.0.0.1:#{@http.port}#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    klass = Net::HTTP.const_get(method.capitalize)
    request = klass.new(uri.request_uri)
    request["X-Rubernetes-Identity"] = "e2e-user" unless method == "PATCH"
    request["Content-Type"] = content_type if content_type
    request.body = body if body
    http.start { |connection| connection.request(request) }
  end

  def read_until(socket, delimiter)
    result = +"".b
    result << socket.readpartial(1024) until result.include?(delimiter)
    result
  end

  def websocket_frame(payload, opcode:)
    bytes = String(payload).b
    mask = "\x01\x02\x03\x04".b
    header = [0x80 | opcode]
    if bytes.bytesize < 126
      header << (0x80 | bytes.bytesize)
    elsif bytes.bytesize <= 0xffff
      header << (0x80 | 126)
      header.concat([bytes.bytesize].pack("n").bytes)
    else
      header << (0x80 | 127)
      header.concat([bytes.bytesize].pack("Q>").bytes)
    end
    masked = bytes.bytes.each_with_index.map { |byte, index| byte ^ mask.getbyte(index % 4) }.pack("C*")
    header.pack("C*") + mask + masked
  end

  def read_websocket_frame(socket)
    first, second = socket.read(2).bytes
    length = second & 0x7f
    length = socket.read(2).unpack1("n") if length == 126
    length = socket.read(8).unpack1("Q>") if length == 127
    [first & 0x0f, socket.read(length)]
  end
end
