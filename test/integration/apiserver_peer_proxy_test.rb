# frozen_string_literal: true

require "net/http"
require "open3"
require "socket"
require "stringio"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/cluster"

class APIServerPeerProxyTest < Minitest::Test
  API = Rubernetes::API
  BOOTSTRAP = Rubernetes::Bootstrap
  CONSENSUS = Rubernetes::Consensus
  DISCOVERY = API::PeerTransport::DISCOVERY_ACCEPT
  REVIEW = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
  DEPLOYMENTS = "/apis/apps/v1/namespaces/default/deployments"
  LEASES = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases"

  def setup
    @directory = Dir.mktmpdir
    @services = []
    @store = Rubernetes::Storage::MemoryStore.new
    issuer = Object.new.extend(Rubernetes::Cluster::Pki)
    ca = issue(issuer, "ca", "/CN=client-and-serving-ca")
    front = issue(issuer, "front-ca", "/CN=front-proxy-ca")
    @unrelated_ca, = issue(issuer, "unrelated-ca", "/CN=unrelated-serving-ca")
    @ca = ca.first
    @front_ca = front.first
    @server = issue(issuer, "server", "/CN=apiserver", ca: ca, san: ["DNS:kubernetes.default.svc", "IP:127.0.0.1"])
    @proxy = issue(issuer, "proxy", "/CN=front-proxy-client", ca: front, client: true)
    @client = issue(issuer, "user", "/O=system:masters/O=engineering/CN=alice", ca: ca, client: true)
  end

  def teardown
    @services.reverse_each { |service| service.stop(reason: "test") }
    @raft_servers&.each_value(&:stop)
    FileUtils.remove_entry(@directory)
  end

  def test_real_clients_use_peer_discovery_and_the_forwarded_identity
    stores = start_raft_replicas
    source = start_server(disable_review: true, disable_apps: true, store: stores.fetch("a"))
    target = start_server(store: stores.fetch("b"))
    direct = request(target, "/apis", headers: {"X-Remote-User" => "system:apiserver", "Accept" => DISCOVERY}, credentials: @proxy)

    assert_equal "200", direct.code, direct.body
    wait_for_peer_discovery(source)

    merged = request(source, "/apis", headers: {"Accept" => DISCOVERY})
    groups = JSON.parse(merged.body).fetch("items").map { |group| group.dig("metadata", "name") }

    assert_includes groups, "authentication.k8s.io"
    assert_equal "304", request(source, "/apis", headers: {"Accept" => DISCOVERY, "If-None-Match" => merged["etag"]}).code

    local = request(source, "/apis", headers: {"Accept" => "#{DISCOVERY};profile=nopeer,#{DISCOVERY}"})

    refute_includes JSON.parse(local.body).fetch("items").map { |group| group.dig("metadata", "name") }, "authentication.k8s.io"
    refute_equal local["etag"], merged["etag"]
    local_priority = request(source, "/apis", headers: {"Accept" => "application/json,#{DISCOVERY};q=0.1"})

    assert_equal "APIGroupList", JSON.parse(local_priority.body)["kind"]
    protobuf = request(source, "/apis", headers: {"Accept" => DISCOVERY.sub("application/json", "application/vnd.kubernetes.protobuf")})

    assert_match(%r{application/vnd.kubernetes.protobuf;g=apidiscovery.k8s.io}, protobuf["content-type"])
    decoded = Rubernetes::Schema::Codec::KubernetesProtobuf.new.decode(protobuf.body)

    assert_includes decoded.fetch("items").map { |group| group.dig("metadata", "name") }, "authentication.k8s.io"

    response = request(source, REVIEW, method: "POST", body: review_body, headers: {"X-Remote-User" => "mallory"})

    assert_equal "201", response.code
    assert_equal "alice", JSON.parse(response.body).dig("status", "userInfo", "username")
    assert_equal %w[system:masters engineering system:authenticated].sort, JSON.parse(response.body).dig("status", "userInfo", "groups").sort
    assert_equal "401", request(source, REVIEW, method: "POST", body: review_body, credentials: nil).code
    assert_equal "404", request(source, REVIEW, method: "POST", body: review_body,
                                                headers: {"X-Kubernetes-Peer-Proxied" => "true"}).code

    identity = {"X-Remote-User" => "bob", "X-Remote-Uid" => "uid-1",
                "X-Remote-Group" => %w[engineering system:authenticated],
                "X-Remote-Extra-example.com%2Fscope" => %w[read write]}
    proxied = request(source, REVIEW, method: "POST", body: review_body, headers: identity, credentials: @proxy)

    assert_equal "201", proxied.code
    assert_equal({"username" => "bob", "uid" => "uid-1", "groups" => %w[engineering system:authenticated],
                  "extra" => {"example.com/scope" => %w[read write]}}, JSON.parse(proxied.body).dig("status", "userInfo"))

    leases = JSON.parse(request(target, LEASES).body).fetch("items")

    assert_includes leases.map { |lease| lease.dig("metadata", "annotations", "kubernetes.io/peer-advertise-address") },
                    "127.0.0.1:#{target.http_server.port}"
    assert_includes source.api_server.metrics.render_own,
                    'apiserver_rerouted_request_total{code="201",group="authentication.k8s.io",resource="selfsubjectreviews",version="v1"} 2'
    assert_match(/^aggregator_discovery_nopeer_requests_total [1-9]\d*/, source.api_server.metrics.render_own)
    assert_match(/^aggregator_discovery_peer_aggregated_cache_hits_total [1-9]\d*/, source.api_server.metrics.render_own)
    verify_watch(source, target)
    verify_kubectl(source) if ENV["KUBECTL"]
  end

  def test_disabled_proxy_and_untrusted_peer_serving_ca_do_not_advertise_remote_resources
    source = start_server(disable_review: true, peer_ca: @unrelated_ca)
    target = start_server
    disabled = start_server(disable_review: true, gate: false, peer_ca: nil)
    eventually { source.api_server.metrics.render_own.include?('apiserver_peer_discovery_sync_errors_total{type="fetch_discovery"}') }

    [source, disabled].each do |service|
      response = request(service, "/apis", headers: {"Accept" => DISCOVERY})

      refute_includes JSON.parse(response.body).fetch("items").map { |group| group.dig("metadata", "name") }, "authentication.k8s.io"
      assert_equal "404", request(service, REVIEW, method: "POST", body: review_body).code
    end
    assert_equal "201", request(target, REVIEW, method: "POST", body: review_body).code
  end

  def test_the_transport_relays_a_websocket_upgrade_over_verified_tls
    websocket = Rubernetes::Transport::WebSocket
    target = upgrade_server do |incoming|
      handshake = websocket.handshake_headers(incoming, protocol: "v5.channel.k8s.io")
      upgrade = lambda do |socket, _request|
        connection = websocket::Connection.new(socket)
        connection.write_binary(connection.read_message.payload)
      end
      Rubernetes::Transport::Response.new(status: 101, headers: handshake, upgrade: upgrade)
    end
    transport = API::PeerTransport.new(ca_file: @ca, certificate: @proxy[2], key: @proxy[3])
    endpoint = BOOTSTRAP::PeerDirectory::Endpoint.new("127.0.0.1", target.port, Time.now.to_f + 15, "test")
    proxy = upgrade_server do |incoming|
      request = API::Request.new(method: incoming.method, path: incoming.path, headers: incoming.headers)
      transport.forward(endpoint, request, {"username" => "alice"})
    end
    tcp = TCPSocket.new("127.0.0.1", proxy.port)
    context = OpenSSL::SSL::SSLContext.new
    context.set_params(ca_file: @ca)
    tls = OpenSSL::SSL::SSLSocket.new(tcp, context)
    tls.hostname = "kubernetes.default.svc"
    tls.sync_close = true
    tls.connect

    key = "MDEyMzQ1Njc4OWFiY2RlZg=="
    request = ["GET / HTTP/1.1", "Host: kubernetes.default.svc", "Connection: Upgrade", "Upgrade: websocket",
               "Sec-WebSocket-Key: #{key}", "Sec-WebSocket-Version: 13", "Sec-WebSocket-Protocol: v5.channel.k8s.io"]
    Timeout.timeout(5) do
      tls.write(request.join("\r\n") + "\r\n\r\n")

      assert_match(%r{HTTP/1.1 101}, tls.gets)
      headers = {}
      until (line = tls.gets) == "\r\n"
        name, value = line.split(":", 2)
        headers[name.downcase] = value.strip
      end

      assert_equal "v5.channel.k8s.io", headers["sec-websocket-protocol"]
      assert_equal websocket.accept_key(key), headers["sec-websocket-accept"]
      client = websocket::Connection.new(tls, client: true)
      client.write_binary("\x01hello\x00".b)

      assert_equal "\x01hello\x00".b, client.read_message.payload
    end
  ensure
    tls&.close
    proxy&.stop
    target&.stop
  end

  private

  def issue(issuer, filename, subject, ca: nil, client: false, san: nil)
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = issuer.send(:certificate, subject: subject, key: key, issuer_key: ca ? ca[3] : key,
                                            issuer: ca && ca[2], ca: ca.nil?, client: client, alt_names: san)
    certificate_path = File.join(@directory, "#{filename}.crt")
    key_path = File.join(@directory, "#{filename}.key")
    File.write(certificate_path, certificate.to_pem)
    File.write(key_path, key.to_pem)
    [certificate_path, key_path, certificate, key]
  end

  def start_raft_replicas
    ids = %w[a b c]
    root_ca = CONSENSUS::Identity.generate_ca("peer-test")
    @raft_servers = ids.to_h do |id|
      bundle = CONSENSUS::Identity.issue_node(*root_ca, cluster_id: "peer-test", node_id: id)
      [id, CONSENSUS::Server.new(id: id, cluster_id: "peer-test", data_directory: File.join(@directory, "raft-#{id}"),
                                 bundle: bundle, initial_voters: ids)]
    end
    @raft_servers.each_value(&:start)
    @raft_servers.each_value do |server|
      @raft_servers.each { |id, peer| server.add_peer(id, peer.address) unless peer.equal?(server) }
    end
    eventually { @raft_servers.each_value.any?(&:leader?) }
    @raft_servers.transform_values { |server| CONSENSUS::RaftStore.new(server) }
  end

  def start_server(disable_review: false, disable_apps: false, gate: true, peer_ca: @ca, store: @store)
    socket = TCPServer.new("127.0.0.1", 0)
    port = socket.addr[1]
    socket.close
    process = {
      "bind_address" => "127.0.0.1", "port" => port, "max_body_bytes" => 3_145_728, "watch_history_limit" => 1000,
      "tls" => {"cert_file" => @server[0], "key_file" => @server[1]},
      "proxy_client" => {"cert_file" => @proxy[0], "key_file" => @proxy[1]},
      "security" => {"feature_gates" => {"UnknownVersionInteroperabilityProxy" => gate},
                     "authorization" => {"modes" => ["AlwaysAllow"]},
                     "authentication" => {"client_ca_file" => @ca, "anonymous" => {"enabled" => false},
                                          "request_header" => {"ca_file" => @front_ca, "allowed_names" => ["front-proxy-client"]}},
                     "flow_control" => {"enabled" => false}},
      "runtime_config" => {"authentication.k8s.io/v1" => !disable_review, "apps/v1" => !disable_apps}
    }
    process["peer_ca_file"] = peer_ca if peer_ca
    config = BOOTSTRAP::Config.new(process_name: "rubernetes-apiserver",
                                   data: {"version" => 1, "logging" => {"level" => "info"}, "processes" => {"rubernetes-apiserver" => process}})
    logger = BOOTSTRAP::StructuredLogger.new(process_name: "rubernetes-apiserver", level: "error", io: StringIO.new)
    service = BOOTSTRAP::APIServerService.new(config: config.process, logger: logger, store: store)
    @services << service
    service.start
  end

  def request(service, path, method: "GET", body: nil, headers: {}, credentials: @client)
    http = Net::HTTP.new("127.0.0.1", service.http_server.port, nil)
    http.use_ssl = true
    http.ca_file = @ca
    if credentials
      http.cert = credentials[2]
      http.key = credentials[3]
    end
    outbound = Net::HTTPGenericRequest.new(method, !body.nil?, true, path).extend(API::Request::RepeatedHeaderLines)
    outbound["Content-Type"] = "application/json" if body
    outbound.body = JSON.generate(body) if body
    headers.each { |name, values| Array(values).each { |value| outbound.add_field(name, value) } }
    http.request(outbound)
  end

  def review_body
    {"apiVersion" => "authentication.k8s.io/v1", "kind" => "SelfSubjectReview"}
  end

  def wait_for_peer_discovery(service)
    eventually do
      response = request(service, "/apis", headers: {"Accept" => DISCOVERY})
      names = JSON.parse(response.body).fetch("items").map { |group| group.dig("metadata", "name") }
      %w[authentication.k8s.io apps].all? { |name| names.include?(name) }
    end
  end

  def verify_watch(source, target)
    labels = {"app" => "peer-proxy"}
    deployment = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "peer-watch"},
                  "spec" => {"selector" => {"matchLabels" => labels},
                             "template" => {"metadata" => {"labels" => labels},
                                            "spec" => {"containers" => [{"name" => "test", "image" => "example.invalid/test"}]}}}}
    created = request(target, DEPLOYMENTS, method: "POST", body: deployment)

    assert_equal "201", created.code, created.body

    watched = request(source, "#{DEPLOYMENTS}?watch=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan&timeoutSeconds=2")

    assert_equal "200", watched.code, watched.body
    events = watched.body.lines.map { |event| JSON.parse(event) }

    assert_includes events.select { |event| event["type"] == "ADDED" }.map { |event| event.dig("object", "metadata", "name") }, "peer-watch"
  end

  def upgrade_server(&handler)
    server = Rubernetes::Transport::HTTPServer.new(handler, host: "127.0.0.1", port: 0,
                                                            cert_file: @server[0], key_file: @server[1])
    server.start
    server
  end

  def eventually
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
    until yield
      flunk "peer discovery did not converge" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.1
    end
  end

  def verify_kubectl(source)
    command = [ENV.fetch("KUBECTL"), "--server=https://127.0.0.1:#{source.http_server.port}",
               "--certificate-authority=#{@ca}", "--client-certificate=#{@client[0]}", "--client-key=#{@client[1]}"]
    resources, discovery_error, discovery_status = Open3.capture3(*command, "api-resources", "--api-group=authentication.k8s.io")

    assert_predicate discovery_status, :success?, discovery_error
    assert_match(/^selfsubjectreviews\s/, resources)

    output, error, status = Open3.capture3(*command, "create", "--raw", REVIEW, "-f", "-", stdin_data: JSON.generate(review_body))

    assert_predicate status, :success?, error
    assert_equal "alice", JSON.parse(output).dig("status", "userInfo", "username")
  end
end
