# frozen_string_literal: true

require "json"
require "net/http"
require "open3"
require "openssl"
require "socket"
require "stringio"
require "tempfile"

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/transport"

class HTTPTransportTest < Minitest::Test
  def setup
    @requests = Queue.new
    @handler = lambda do |request|
      @requests << request
      case request.path
      when "/get"
        Rubernetes::Transport::Response.json({"method" => request.method, "query" => request.query}, status: 200)
      when "/echo"
        {status: 201, headers: {"Content-Type" => "text/plain"}, body: request.body}
      when "/watch"
        events = Enumerator.new do |yielder|
          yielder << {"type" => "ADDED", "object" => {"metadata" => {"name" => "one"}}}
          yielder << {"type" => "MODIFIED", "object" => {"metadata" => {"name" => "one"}}}
        end
        Rubernetes::Transport::Response.new(body: events)
      when "/bad-response"
        {status: 200, headers: {"X-Unsafe" => "ok\r\nInjected: yes"}, body: "unsafe"}
      when "/error"
        raise "handler failure"
      else
        {status: 404, body: {"message" => "not found"}}
      end
    end
    @server = Rubernetes::Transport::HTTPServer.new(@handler, host: "127.0.0.1", port: 0, shutdown_timeout: 1)
    @server.start
    wait_for_port
  end

  def teardown
    @server&.stop(timeout: 1)
  end

  def test_get_passes_request_to_handler_and_returns_json
    response = request(Net::HTTP::Get.new("/get?watch=false"))

    assert_equal "200", response.code
    assert_equal({"method" => "GET", "query" => {"watch" => ["false"]}}, JSON.parse(response.body))
    received = @requests.pop

    assert_instance_of Rubernetes::Transport::Request, received
    assert_equal "/get", received.path
    assert_equal "false", received.query.fetch("watch").first
  end

  def test_post_content_length_and_chunked_request_are_supported
    request = Net::HTTP::Post.new("/echo")
    request["Content-Type"] = "text/plain"
    request.body = "hello"
    response = request(request)

    assert_equal "201", response.code
    assert_equal "hello", response.body

    socket = TCPSocket.new("127.0.0.1", @server.port)
    socket.write(
      "POST /echo HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Transfer-Encoding: chunked\r\n" \
      "Connection: close\r\n\r\n" \
      "4\r\nWiki\r\n" \
      "5\r\npedia\r\n" \
      "0\r\n\r\n"
    )
    raw_response = socket.read
    socket.close

    assert_includes raw_response, "HTTP/1.1 201 Created"
    assert_includes raw_response, "Wikipedia"
  end

  def test_handler_error_is_isolated_as_json_500
    response = request(Net::HTTP::Get.new("/error"))

    assert_equal "500", response.code
    body = JSON.parse(response.body)

    assert_equal "Failure", body.fetch("status")
    refute_includes body.fetch("message"), "handler failure"
  end

  def test_duplicate_content_length_and_transfer_encoding_are_rejected
    socket = TCPSocket.new("127.0.0.1", @server.port)
    socket.write(
      "POST /echo HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Content-Length: 1\r\n" \
      "Content-Length: 1\r\n" \
      "Connection: close\r\n\r\n" \
      "x"
    )
    response = socket.read
    socket.close

    assert_includes response, "HTTP/1.1 400 Bad Request"

    socket = TCPSocket.new("127.0.0.1", @server.port)
    socket.write(
      "POST /echo HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Content-Length: 1\r\n" \
      "Transfer-Encoding: chunked\r\n" \
      "Connection: close\r\n\r\n" \
      "1\r\nx\r\n0\r\n\r\n"
    )
    response = socket.read
    socket.close

    assert_includes response, "HTTP/1.1 400 Bad Request"

    response = raw_http(
      "POST /echo HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Content-Length: 1\r\n" \
      "Content-Length: 2\r\n" \
      "Connection: close\r\n\r\n" \
      "x"
    )

    assert_includes response, "HTTP/1.1 400 Bad Request"
  end

  def test_obs_fold_bare_lf_and_invalid_header_bytes_fail_closed
    response = raw_http(
      "GET /get HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "X-Test: first\r\n " \
      "folded\r\n" \
      "Connection: close\r\n\r\n"
    )

    assert_includes response, "HTTP/1.1 400 Bad Request"

    response = raw_http("GET /get HTTP/1.1\nHost: localhost\n\n")

    assert_includes response, "HTTP/1.1 400 Bad Request"

    response = raw_http(
      "GET /get HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Bad Header: value\r\n" \
      "Connection: close\r\n\r\n"
    )

    assert_includes response, "HTTP/1.1 400 Bad Request"

    response = raw_http(
      "GET /get HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "X-Test: value\x7f\r\n" \
      "Connection: close\r\n\r\n"
    )

    assert_includes response, "HTTP/1.1 400 Bad Request"
  end

  def test_chunk_extensions_and_trailers_are_validated
    response = raw_http(
      "POST /echo HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Transfer-Encoding: chunked\r\n" \
      "Connection: close\r\n\r\n" \
      "4;note=\"a;b\"\r\nWiki\r\n" \
      "5;flag=yes\r\npedia\r\n" \
      "0;done\r\nX-Stream-End: ok\r\n\r\n"
    )

    assert_includes response, "HTTP/1.1 201 Created"
    assert_includes response, "Wikipedia"

    response = raw_http(
      "POST /echo HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Transfer-Encoding: chunked\r\n" \
      "Connection: close\r\n\r\n" \
      "1;broken=\r\nx\r\n0\r\n\r\n"
    )

    assert_includes response, "HTTP/1.1 400 Bad Request"

    response = raw_http(
      "POST /echo HTTP/1.1\r\n" \
      "Host: localhost\r\n" \
      "Transfer-Encoding: chunked\r\n" \
      "Connection: close\r\n\r\n" \
      "0\r\nContent-Length: 0\r\n\r\n"
    )

    assert_includes response, "HTTP/1.1 400 Bad Request"
  end

  def test_slowloris_header_times_out_with_408
    limited = Rubernetes::Transport::HTTPServer.new(
      @handler,
      port: 0,
      read_timeout: 0.05,
      shutdown_timeout: 1
    )
    limited.start
    wait_for_port(limited)
    socket = TCPSocket.new("127.0.0.1", limited.port)
    socket.write("GET /get HTTP/1.1\r\nHost: ")
    response = socket.read

    assert_includes response, "HTTP/1.1 408 Request Timeout"
  ensure
    socket&.close
    limited&.stop(timeout: 1)
  end

  def test_connection_limit_closes_excess_socket_without_creating_unbounded_workers
    limited = Rubernetes::Transport::HTTPServer.new(
      @handler,
      port: 0,
      max_connections: 1,
      shutdown_timeout: 1
    )
    limited.start
    wait_for_port(limited)
    first = TCPSocket.new("127.0.0.1", limited.port)
    first.write("GET /get HTTP/1.1\r\nHost: ")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
    sleep 0.01 while limited.active_connections < 1 && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    assert_equal 1, limited.active_connections

    second = TCPSocket.new("127.0.0.1", limited.port)
    ready = IO.select([second], nil, nil, 1)

    refute_nil ready, "connection limit did not close the excess socket"
    result = second.read_nonblock(128, exception: false)

    assert(result.nil? || result == :wait_readable || result.start_with?("HTTP/1.1 503"))
  ensure
    first&.close
    second&.close
    limited&.stop(graceful: false, timeout: 1)
  end

  def test_response_header_injection_is_rejected_and_server_name_is_validated
    response = request(Net::HTTP::Get.new("/bad-response"))

    assert_equal "500", response.code
    refute_includes response.to_hash.values.flatten.join("\n"), "Injected:"

    assert_raises(Rubernetes::Transport::ConfigurationError) do
      Rubernetes::Transport::HTTPServer.new(@handler, port: 0, server_name: "bad\r\nInjected: yes")
    end
  end

  def test_disconnect_closes_a_watch_body_without_a_second_response
    closed = Queue.new
    stream = Class.new do
      define_method(:initialize) { |queue| @queue = queue }
      define_method(:each) do |&block|
        loop { block.call("x" * 16_384) }
      ensure
        @queue << :enumeration_finished
      end
      define_method(:close) { @queue << :closed }
    end.new(closed)
    server = Rubernetes::Transport::HTTPServer.new(
      ->(_request) { Rubernetes::Transport::Response.new(body: stream) },
      port: 0,
      max_response_bytes: 64 * 1024 * 1024,
      write_timeout: 0.2,
      shutdown_timeout: 1
    )
    server.start
    wait_for_port(server)
    socket = TCPSocket.new("127.0.0.1", server.port)
    socket.write("GET /watch HTTP/1.1\r\nHost: localhost\r\n\r\n")
    socket.readpartial(256)
    socket.close

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep 0.01 while closed.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    refute_empty closed, "stream body was not closed after client disconnect"
  ensure
    socket&.close
    server&.stop(graceful: false, timeout: 1)
  end

  def test_watch_backpressure_times_out_without_appending_an_error_response
    closed = Queue.new
    stream = Class.new do
      define_method(:initialize) { |queue| @queue = queue }
      define_method(:each) { |&block| loop { block.call("y" * 16_384) } }
      define_method(:close) { @queue << :closed }
    end.new(closed)
    server = Rubernetes::Transport::HTTPServer.new(
      ->(_request) { Rubernetes::Transport::Response.new(body: stream) },
      port: 0,
      max_response_bytes: 64 * 1024 * 1024,
      write_timeout: 0.05,
      shutdown_timeout: 1
    )
    server.start
    wait_for_port(server)
    socket = TCPSocket.new("127.0.0.1", server.port)
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 1024)
    socket.write("GET /watch HTTP/1.1\r\nHost: localhost\r\n\r\n")

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep 0.01 while closed.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    refute_empty closed, "stream body was not closed after a blocked response write"
    response = +"".b
    read_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
    while response.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < read_deadline
      chunk = socket.read_nonblock(128 * 1024, exception: false)
      response << chunk if chunk.is_a?(String)
      sleep 0.01 if chunk == :wait_readable
    end

    assert_equal 1, response.scan("HTTP/1.1").length
  ensure
    socket&.close
    server&.stop(graceful: false, timeout: 1)
  end

  def test_enumerable_response_uses_json_lines_and_chunked_framing
    response = request(Net::HTTP::Get.new("/watch"))

    assert_equal "200", response.code
    assert_equal "chunked", response["transfer-encoding"]
    events = response.body.lines.map { |line| JSON.parse(line) }

    assert_equal(%w[ADDED MODIFIED], events.map { |event| event.fetch("type") })
  end

  def test_body_limit_returns_413
    limited = Rubernetes::Transport::HTTPServer.new(@handler, port: 0, max_body_bytes: 3, shutdown_timeout: 1)
    limited.start
    wait_for_port(limited)
    client = Net::HTTP.new("127.0.0.1", limited.port)
    request = Net::HTTP::Post.new("/echo")
    request["Content-Type"] = "text/plain"
    request.body = "four"
    response = client.request(request)

    assert_equal "413", response.code
  ensure
    limited&.stop(timeout: 1)
  end

  def test_graceful_shutdown_closes_listener_and_reports_state
    port = @server.port
    @server.stop(timeout: 1)

    assert_predicate @server, :stopped?
    assert_nil @server.port
    assert_raises(Errno::ECONNREFUSED, Errno::ECONNRESET) do
      TCPSocket.new("127.0.0.1", port)
    end
  end

  def test_tls_is_enabled_only_when_certificate_and_key_are_given
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = OpenSSL::X509::Name.parse("/CN=localhost")
    certificate.issuer = certificate.subject
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 300
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))

    cert_file = Tempfile.new(["rubernetes", ".crt"])
    key_file = Tempfile.new(["rubernetes", ".key"])
    cert_file.write(certificate.to_pem)
    key_file.write(key.to_pem)
    cert_file.close
    key_file.close
    tls_server = Rubernetes::Transport::HTTPServer.new(
      @handler,
      port: 0,
      cert_file: cert_file.path,
      key_file: key_file.path,
      shutdown_timeout: 1
    )
    tls_server.start
    wait_for_port(tls_server)
    client = Net::HTTP.new("127.0.0.1", tls_server.port)
    client.use_ssl = true
    client.verify_mode = OpenSSL::SSL::VERIFY_NONE
    response = client.get("/get")

    assert_equal "200", response.code
    assert_predicate tls_server, :tls?
    if tls_server.instance_variable_get(:@ssl_context)&.respond_to?(:min_version)
      assert_equal OpenSSL::SSL::TLS1_2_VERSION, tls_server.instance_variable_get(:@ssl_context).min_version

      if OpenSSL::SSL.const_defined?(:TLS1_1_VERSION)
        legacy_context = OpenSSL::SSL::SSLContext.new
        legacy_context.min_version = OpenSSL::SSL::TLS1_1_VERSION
        legacy_context.max_version = OpenSSL::SSL::TLS1_1_VERSION
        raw_socket = TCPSocket.new("127.0.0.1", tls_server.port)
        legacy_socket = OpenSSL::SSL::SSLSocket.new(raw_socket, legacy_context)
        assert_raises(OpenSSL::SSL::SSLError) { legacy_socket.connect }
      end
    end
  ensure
    legacy_socket&.close
    raw_socket&.close
    tls_server&.stop(timeout: 1)
    cert_file&.unlink
    key_file&.unlink
  end

  def test_tls_handshake_is_bounded_for_a_peer_that_sends_no_client_hello
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 2
    certificate.subject = OpenSSL::X509::Name.parse("/CN=localhost")
    certificate.issuer = certificate.subject
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 300
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))

    cert_file = Tempfile.new(["rubernetes-hostile", ".crt"])
    key_file = Tempfile.new(["rubernetes-hostile", ".key"])
    cert_file.write(certificate.to_pem)
    key_file.write(key.to_pem)
    cert_file.close
    key_file.close
    tls_server = Rubernetes::Transport::HTTPServer.new(
      @handler,
      port: 0,
      cert_file: cert_file.path,
      key_file: key_file.path,
      read_timeout: 0.05,
      shutdown_timeout: 1
    )
    tls_server.start
    wait_for_port(tls_server)
    socket = TCPSocket.new("127.0.0.1", tls_server.port)
    sleep 0.15
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    tls_server.stop(timeout: 1)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_operator elapsed, :<, 1.0
  ensure
    socket&.close
    tls_server&.stop(timeout: 1)
    cert_file&.unlink
    key_file&.unlink
  end

  def test_tls_idle_watches_release_watcher_monitor_and_connection_on_all_terminal_paths
    config = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-apiserver").process.merge("port" => 0)
    logger = Rubernetes::Bootstrap::StructuredLogger.new(io: StringIO.new, process_name: "rubernetes-apiserver")
    service = Rubernetes::Bootstrap::APIServerService.new(config: config, logger: logger)
    cert_file, key_file = create_tls_material(serial: 4)
    tls_server = Rubernetes::Transport::HTTPServer.new(
      service.api_server,
      port: 0,
      cert_file: cert_file.path,
      key_file: key_file.path,
      read_timeout: 1,
      write_timeout: 1,
      shutdown_timeout: 0.2
    )
    tls_server.start
    wait_for_port(tls_server)

    disconnect_socket, disconnect_response = open_tls_watch(tls_server, "/api/v1/pods?watch=true", timeout: 2)

    assert_includes disconnect_response, "HTTP/1.1 200 OK"
    assert_includes disconnect_response.downcase, "transfer-encoding: chunked"
    wait_until(timeout: 1) do
      store_watcher_count(service.store) == 1 && tls_server.active_connections == 1 &&
        tls_server.active_stream_monitors == 1
    end
    disconnect_socket.close
    disconnect_socket = nil
    wait_until(timeout: 2) do
      store_watcher_count(service.store).zero? && tls_server.active_connections.zero? &&
        tls_server.active_stream_monitors.zero?
    end

    assert_equal 0, store_watcher_count(service.store), "TLS disconnect did not unregister the server watcher"
    assert_equal 0, tls_server.active_stream_monitors
    assert_equal 0, tls_server.active_connections

    timeout_socket, timeout_response = open_tls_watch(
      tls_server,
      "/api/v1/pods?watch=true&timeoutSeconds=1",
      timeout: 2
    )
    wait_until(timeout: 1) do
      store_watcher_count(service.store) == 1 && tls_server.active_stream_monitors == 1
    end
    timeout_response << read_tls_to_close(timeout_socket, timeout: 3)
    wait_until(timeout: 1) do
      store_watcher_count(service.store).zero? && tls_server.active_connections.zero? &&
        tls_server.active_stream_monitors.zero?
    end

    assert_includes timeout_response, "0\r\n\r\n"
    assert_equal 0, store_watcher_count(service.store), "timed-out TLS watch remained registered"
    assert_equal 0, tls_server.active_stream_monitors
    assert_equal 0, tls_server.active_connections
    timeout_socket.close
    timeout_socket = nil

    shutdown_socket, shutdown_response = open_tls_watch(tls_server, "/api/v1/pods?watch=true", timeout: 2)

    assert_includes shutdown_response, "HTTP/1.1 200 OK"
    wait_until(timeout: 1) do
      store_watcher_count(service.store) == 1 && tls_server.active_connections == 1 &&
        tls_server.active_stream_monitors == 1
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    tls_server.stop(timeout: 0.2)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_operator elapsed, :<, 1.0
    wait_until(timeout: 2) do
      store_watcher_count(service.store).zero? && tls_server.active_connections.zero? &&
        tls_server.active_stream_monitors.zero?
    end

    assert_equal 0, store_watcher_count(service.store), "TLS shutdown did not unregister the server watcher"
    assert_equal 0, tls_server.active_stream_monitors
    assert_equal 0, tls_server.active_connections
  ensure
    [disconnect_socket, timeout_socket, shutdown_socket].compact.each do |socket|
      socket.close unless socket.closed?
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil
    end
    tls_server&.stop(graceful: false, timeout: 0.2)
    service&.store&.close
    cert_file&.unlink
    key_file&.unlink
  end

  def test_bootstrap_service_supports_kubectl_crud_apply_patch_delete_and_watch
    kubectl = File.expand_path("../../build/tools/kubectl-v1.36.2", __dir__)
    skip "official kubectl v1.36.2 is unavailable" unless File.executable?(kubectl)

    config = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-apiserver").process.merge("port" => 0)
    logger = Rubernetes::Bootstrap::StructuredLogger.new(io: StringIO.new, process_name: "rubernetes-apiserver")
    service = Rubernetes::Bootstrap::APIServerService.new(config: config, logger: logger)
    service.start
    wait_for_port(service.http_server)

    Tempfile.create(["rubernetes-kubectl", ".yaml"]) do |manifest|
      manifest.write(<<~YAML)
        apiVersion: v1
        kind: Pod
        metadata:
          name: web
          namespace: default
        spec:
          containers:
            - name: app
              image: registry.k8s.io/pause:3.10
      YAML
      manifest.flush

      assert_includes kubectl_run(service, "apply", "--validate=false", "-f", manifest.path), "pod/web created"
      pod = JSON.parse(kubectl_run(service, "get", "pod", "web", "-n", "default", "-o", "json"))

      assert_equal "web", pod.dig("metadata", "name")

      assert_includes kubectl_run(
        service,
        "patch", "pod", "web", "-n", "default", "--type=merge",
        "-p", '{"metadata":{"labels":{"app":"transport"}}}'
      ), "pod/web patched"
      patched = JSON.parse(kubectl_run(service, "get", "pod", "web", "-n", "default", "-o", "json"))

      assert_equal "transport", patched.dig("metadata", "labels", "app")

      assert_includes kubectl_run(service, "delete", "pod", "web", "-n", "default"), "pod \"web\" deleted"
    end

    # The API server keeps watches of its own (CustomResourceDefinitions and
    # APIServices, to serve dynamic APIs), so the kubectl watch is counted on
    # top of whatever was registered before it started.
    baseline_watchers = store_watcher_count(service.store)
    watch_input, watch_output, watch_error, watch_wait = Open3.popen3(*kubectl_args(
      service,
      "get", "pods", "-A", "-w", "-o", "json"
    ))
    watch_input.close
    wait_until(timeout: 5) { store_watcher_count(service.store) == baseline_watchers + 1 }

    Tempfile.create(["rubernetes-kubectl-watch", ".yaml"]) do |manifest|
      manifest.write(<<~YAML)
        apiVersion: v1
        kind: Pod
        metadata:
          name: watch-web
          namespace: default
        spec:
          containers:
            - name: app
              image: registry.k8s.io/pause:3.10
      YAML
      manifest.flush
      kubectl_run(service, "apply", "--validate=false", "-f", manifest.path)
    end

    watch_transcript = read_until(watch_output, "watch-web", timeout: 5)

    assert_includes watch_transcript, "watch-web"
    Process.kill("TERM", watch_wait.pid)
    watch_wait.value
    wait_until(timeout: 5) { store_watcher_count(service.store) == baseline_watchers }

    assert_equal baseline_watchers, store_watcher_count(service.store)

    service.stop(reason: "integration test")

    assert_predicate service.http_server, :stopped?
    assert_equal 0, service.http_server.active_connections
  ensure
    if watch_wait && watch_wait.alive?
      begin
        Process.kill("TERM", watch_wait.pid)
      rescue StandardError
        nil
      end
      begin
        watch_wait.value
      rescue StandardError
        nil
      end
    end
    [watch_input, watch_output, watch_error].compact.each { |io| io.close unless io.closed? }
    service&.stop(reason: "integration test")
  end

  private

  def request(http_request)
    client = Net::HTTP.new("127.0.0.1", @server.port)
    client.request(http_request)
  end

  def kubectl_args(service, *arguments)
    [
      File.expand_path("../../build/tools/kubectl-v1.36.2", __dir__),
      "--server", service.http_server.endpoint,
      "--insecure-skip-tls-verify",
      "--request-timeout=5s",
      *arguments
    ]
  end

  def kubectl_run(service, *)
    command = kubectl_args(service, *)
    output = IO.popen(command, err: %i[child out], &:read)
    status = $?.exitstatus

    assert_equal 0, status, "kubectl failed: #{command.join(" ")}\n#{output}"
    output
  end

  def read_until(io, marker, timeout:)
    output = +"".b
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until output.include?(marker) || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      ready = IO.select([io], nil, nil, 0.1)
      next unless ready

      chunk = io.read_nonblock(16 * 1024, exception: false)
      output << chunk if chunk.is_a?(String)
      break if chunk.nil?
    end
    output
  end

  def wait_until(timeout:)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      raise "condition did not become true within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.01
    end
  end

  def store_watcher_count(store)
    return store.watcher_count if store.respond_to?(:watcher_count)

    watchers = store.instance_variable_get(:@watchers)
    watchers.respond_to?(:length) ? watchers.length : 0
  end

  def create_tls_material(serial:)
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = serial
    certificate.subject = OpenSSL::X509::Name.parse("/CN=localhost")
    certificate.issuer = certificate.subject
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 300
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))

    cert_file = Tempfile.new(["rubernetes-idle-watch", ".crt"])
    key_file = Tempfile.new(["rubernetes-idle-watch", ".key"])
    cert_file.write(certificate.to_pem)
    key_file.write(key.to_pem)
    cert_file.close
    key_file.close
    [cert_file, key_file]
  end

  def open_tls_watch(server, path, timeout:)
    raw_socket = TCPSocket.new("127.0.0.1", server.port)
    context = OpenSSL::SSL::SSLContext.new
    context.verify_mode = OpenSSL::SSL::VERIFY_NONE
    context.min_version = OpenSSL::SSL::TLS1_2_VERSION if context.respond_to?(:min_version=)
    socket = OpenSSL::SSL::SSLSocket.new(raw_socket, context)
    socket.sync_close = true
    tls_connect(socket, timeout: timeout)
    tls_write(
      socket,
      "GET #{path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
      timeout: timeout
    )
    [socket, tls_read_until(socket, "\r\n\r\n", timeout: timeout)]
  rescue StandardError
    socket&.close
    raw_socket&.close
    raise
  end

  def tls_connect(socket, timeout:)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      result = socket.connect_nonblock(exception: false)
      case result
      when :wait_readable
        wait_tls_io(socket, readable: true, deadline: deadline)
      when :wait_writable
        wait_tls_io(socket, readable: false, deadline: deadline)
      else
        return
      end
    end
  end

  def tls_write(socket, data, timeout:)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    offset = 0
    while offset < data.bytesize
      result = socket.write_nonblock(data.byteslice(offset..), exception: false)
      case result
      when :wait_readable
        wait_tls_io(socket, readable: true, deadline: deadline)
      when :wait_writable
        wait_tls_io(socket, readable: false, deadline: deadline)
      when Integer
        offset += result
      else
        raise "TLS write returned an invalid result"
      end
    end
  end

  def tls_read_until(socket, marker, timeout:)
    output = +"".b
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until output.include?(marker)
      result = socket.read_nonblock(16 * 1024, exception: false)
      case result
      when :wait_readable
        wait_tls_io(socket, readable: true, deadline: deadline)
      when :wait_writable
        wait_tls_io(socket, readable: false, deadline: deadline)
      when String
        output << result
      when nil
        raise "TLS peer closed before #{marker.inspect}"
      end
    end
    output
  end

  def read_tls_to_close(socket, timeout:)
    output = +"".b
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      result = socket.read_nonblock(16 * 1024, exception: false)
      case result
      when :wait_readable
        wait_tls_io(socket, readable: true, deadline: deadline)
      when :wait_writable
        wait_tls_io(socket, readable: false, deadline: deadline)
      when String
        output << result
      when nil
        return output
      end
    end
  rescue OpenSSL::SSL::SSLError
    output
  end

  def wait_tls_io(socket, readable:, deadline:)
    remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    raise "TLS operation exceeded its fixed deadline" if remaining <= 0

    readers = readable ? [socket] : nil
    writers = readable ? nil : [socket]
    ready = IO.select(readers, writers, nil, remaining)
    raise "TLS operation exceeded its fixed deadline" unless ready
  end

  def raw_http(payload, server = @server)
    socket = TCPSocket.new("127.0.0.1", server.port)
    socket.write(payload)
    socket.read
  ensure
    socket&.close
  end

  def wait_for_port(server = @server)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    loop do
      return if server.port
      raise "server did not bind an ephemeral port" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.01
    end
  end
end
