# frozen_string_literal: true

require "json"
require "socket"
require "tmpdir"
require "time"
require_relative "../test_helper"
require "rubernetes/runtime/microvm"

class MicroVMProtocolTest < Minitest::Test
  M = Rubernetes::Runtime::MicroVM

  def test_cbor_is_canonical_and_rejects_non_canonical_documents
    value = {"z" => 1, "a" => [1, -2, "bytes".b, "text", true, nil, 2.5], "aa" => {"k" => 2**40}}
    encoded = M::CBOR.encode(value)
    assert_equal value, M::CBOR.decode(encoded)
    assert_equal encoded, M::CBOR.encode(M::CBOR.decode(encoded)), "round trip is byte-stable"
    assert_raises(M::ProtocolError, "indefinite length") { M::CBOR.decode("\x9f".b) }
    assert_raises(M::ProtocolError, "non-shortest integer") { M::CBOR.decode("\x18\x05".b) }
    assert_raises(M::ProtocolError, "unsorted keys") { M::CBOR.decode("\xa2\x61b\x01\x61a\x02".b) }
    assert_raises(M::ProtocolError, "tags") { M::CBOR.decode("\xc0\x00".b) }
    assert_raises(M::FramingError, "truncated") { M::CBOR.decode("\x62a".b) }
    assert_raises(M::FramingError) { M::CBOR.decode("\x00".b * 2, max_bytes: 1) }
  end

  def test_framing_bounds_length_before_allocation_and_round_trips
    reader, writer = IO.pipe
    M::Framing.write_frame(writer, {"id" => 1, "request" => "hello", "params" => {}})
    assert_equal({"id" => 1, "request" => "hello", "params" => {}}, M::Framing.read_frame(reader))
    writer.write([M::Framing::MAX_FRAME_BYTES + 1].pack("N"))
    writer.close
    assert_raises(M::FramingError) { M::Framing.read_frame(reader) }
    reader.close
    huge = {"x" => "y" * (M::Framing::MAX_FRAME_BYTES + 10)}
    assert_raises(M::FramingError) { M::Framing.write_frame(StringIO.new, huge) }
  end

  def test_channel_and_server_exchange_requests_and_reject_unrequested_frames
    host, guest = UNIXSocket.pair
    handler = ->(name, params) { name == "echo" ? {"echo" => params} : raise(M::ProtocolError, "unknown #{name}") }
    thread = Thread.new { M::Server.new(guest, handler).serve }
    channel = M::Channel.new(host, timeout: 2)
    assert_equal({"echo" => {"a" => 1}}, channel.call("echo", {"a" => 1}))
    error = assert_raises(M::ProtocolError) { channel.call("nope") }
    assert_includes error.message, "unknown nope"
    host.close
    thread.join(2)
    # A response with a foreign id is unrequested.
    host2, guest2 = UNIXSocket.pair
    Thread.new { M::Framing.read_frame(guest2); M::Framing.write_frame(guest2, {"id" => 99, "result" => {}}) }
    assert_raises(M::ProtocolError) { M::Channel.new(host2, timeout: 2).call("x") }
    # A closed connection after the request is ambiguous (ResponseLost).
    host3, guest3 = UNIXSocket.pair
    Thread.new { M::Framing.read_frame(guest3); guest3.close }
    assert_raises(M::ResponseLost) { M::Channel.new(host3, timeout: 2).call("x") }
  end

  def test_channel_enforces_the_outstanding_request_bound
    host, _guest = UNIXSocket.pair
    channel = M::Channel.new(host, timeout: 0.2, max_outstanding: 1)
    channel.instance_variable_get(:@outstanding)[1] = "held"
    assert_raises(M::VsockError) { channel.call("x") }
  end

  def test_signature_binds_fields_to_the_session_key
    key = "k" * 32
    fields = {"kind" => "gate.open", "nonce" => "n1"}
    signature = M::Signature.sign(key, fields)
    assert M::Signature.valid?(key, fields, signature)
    refute M::Signature.valid?(key, fields.merge("nonce" => "n2"), signature)
    refute M::Signature.valid?("other" * 6, fields, signature)
    refute M::Signature.valid?(key, fields, nil)
  end

  def test_api_client_rejects_malformed_and_unrequested_http_responses
    Dir.mktmpdir do |dir|
      path = File.join(dir, "fc.sock")
      responses = [
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra",
        "HTTP/1.1 200 OK\r\nContent-Length: #{M::APIClient::MAX_RESPONSE_BYTES + 1}\r\n\r\n",
        "garbage\r\n\r\n",
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 28\r\n\r\n{\"fault_message\":\"nope now\"}",
        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"state\":\"x\"}"
      ]
      server = UNIXServer.new(path)
      thread = Thread.new do
        responses.each do |response|
          client = server.accept
          client.readpartial(65_536)
          client.write(response)
          client.close
        end
      end
      client = M::APIClient.new(path, timeout: 2)
      assert_raises(M::APIError) { client.describe } # duplicate content-length
      assert_raises(M::APIError) { client.describe } # CL + TE
      assert_raises(M::APIError) { client.describe } # unrequested bytes
      assert_raises(M::APIError) { client.describe } # too large
      assert_raises(M::APIError) { client.describe } # malformed status line
      error = assert_raises(M::APIError) { client.describe }
      assert_includes error.message, "nope now"
      assert_equal({"state" => "x"}, client.describe)
      thread.join(2)
      server.close
      oversized = M::APIClient.new(path, timeout: 1)
      assert_raises(M::APIError) { oversized.put("/x", {"a" => "b" * (M::APIClient::MAX_REQUEST_BODY_BYTES + 1)}) }
    end
  end

  def test_api_client_enforces_the_configuration_order
    Dir.mktmpdir do |dir|
      path = File.join(dir, "fc.sock")
      server = UNIXServer.new(path)
      Thread.new do
        loop do
          client = server.accept
          client.readpartial(65_536)
          client.write("HTTP/1.1 204 No Content\r\n\r\n")
          client.close
        end
      rescue IOError
        nil
      end
      client = M::APIClient.new(path, timeout: 2)
      client.machine_config(vcpu_count: 1, mem_size_mib: 128)
      client.vsock(guest_cid: 3, uds_path: "/run/v.sock")
      assert_raises(M::APIError, "boot source after vsock") { client.boot_source(kernel_image_path: "/vmlinux", boot_args: "x") }
      server.close
    end
  end

  def test_identity_ledger_never_reissues_generated_values_and_survives_replay
    Dir.mktmpdir do |dir|
      path = File.join(dir, "identity.jsonl")
      ledger = M::IdentityLedger.new(path)
      first = ledger.allocate(sandbox_id: "s1", runtime_class: "rubernetes-firecracker", artifact_digest: "a", policy_digest: "p")
      second = ledger.allocate(sandbox_id: "s2", runtime_class: "rubernetes-firecracker", artifact_digest: "a", policy_digest: "p")
      refute_equal first.fields["jail_uid"], second.fields["jail_uid"]
      refute_equal first.fields["guest_cid"], second.fields["guest_cid"]
      refute_equal first.fields["policy_digest"], second.fields["policy_digest"], "policy digest is bound to the VM generation"
      assert_raises(M::IdentityError) { ledger.allocate(sandbox_id: "s1", runtime_class: "rubernetes-firecracker", artifact_digest: "a", policy_digest: "p") }
      ledger.bind_network(first.vm_id, ip: "10.0.0.5", gateway: "10.0.0.1", prefix_length: 24)
      assert_raises(M::IdentityError, "live IP conflict") { ledger.bind_network(second.vm_id, ip: "10.0.0.5") }
      ledger.release(first.vm_id)
      replayed = M::IdentityLedger.new(path)
      third = replayed.allocate(sandbox_id: "s1", runtime_class: "rubernetes-firecracker", artifact_digest: "a", policy_digest: "p")
      assert_operator third.fields["jail_uid"], :>, second.fields["jail_uid"], "UIDs are never reused after replay"
      assert_equal 0, replayed.reuse_report.values.sum { |entry| entry["reused"] }
      assert_equal 1, replayed.revoke!
      assert_raises(M::IdentityError, "released identities are immutable") { replayed.bind_network(first.vm_id, ip: "10.0.0.9") }
    end
  end

  def test_snapshot_pool_verifies_digests_before_restore
    Dir.mktmpdir do |dir|
      pool = M::SnapshotPool.new(root: File.join(dir, "pool"))
      mem = File.join(dir, "mem")
      vmstate = File.join(dir, "vmstate")
      File.binwrite(mem, "M" * 4096)
      File.binwrite(vmstate, "V" * 512)
      base = pool.store(id: "base-1", runtime_class: "rubernetes-firecracker", mem_path: mem, vmstate_path: vmstate, artifact_digest: "art",
                        drive_layout: [], machine: {"vcpu_count" => 1}, guest_hello: {"phase" => "base"}, pause_ack: {"nonce" => "n"})
      assert pool.verify!(base, artifact_digest: "art")
      assert_raises(M::SnapshotCorruption) { pool.verify!(base, artifact_digest: "other") }
      File.binwrite(base.mem_path, "M" * 4095 + "X")
      assert_raises(M::SnapshotCorruption) { pool.verify!(pool.load_base("rubernetes-firecracker", "base-1"), artifact_digest: "art") }
      File.truncate(base.vmstate_path, 100)
      assert_raises(M::SnapshotCorruption) { pool.verify!(pool.load_base("rubernetes-firecracker", "base-1"), artifact_digest: "art") }
      File.write(File.join(base.directory, "manifest.json"), "{not json")
      assert_raises(M::SnapshotCorruption) { pool.load_base("rubernetes-firecracker", "base-1") }
      assert_empty pool.bases("rubernetes-firecracker")
    end
  end

  def test_broker_reauthorizes_every_call_and_fails_closed
    resolver = Object.new
    resolver.define_singleton_method(:getaddresses) { |name| name == "api.example.com" ? ["10.1.0.5", "10.1.0.6"] : ["203.0.113.9"] }
    audit = []
    epoch = 0
    broker = M::Broker.new(resolver: resolver, audit: ->(entry) { audit << entry }, revocation_epoch: -> { epoch })
    identity = {"capability_id" => "cap-1", "subject_id" => "subj-1", "policy_digest" => "pd", "revocation_epoch" => 0}
    broker.bind(vm_id: "vm-1", identity: identity, policy: {"operations" => %w[dns.resolve http.get], "allowed_hosts" => ["api.example.com", "*.internal"],
                                                            "allowed_cidrs" => ["10.1.0.0/16"], "allowed_ports" => [443], "expires_at" => (Time.now + 60).utc.iso8601})
    assert_equal({"name" => "api.example.com", "addresses" => ["10.1.0.5", "10.1.0.6"]}, broker.handle("vm-1", "broker.request", {"operation" => "dns.resolve", "params" => {"name" => "api.example.com"}}))
    assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "dns.resolve", "params" => {"name" => "evil.example.com"}}) }
    assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "dns.resolve", "params" => {"name" => "api.example.com", "extra" => 1}}) }
    assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "time.now", "params" => {}}) }
    assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "shell.exec", "params" => {}}) }
    assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "dns.resolve", "params" => {"name" => "api.example.com"}, "subject_id" => "spoofed"}) }
    assert_raises(M::PolicyError) { broker.handle("vm-2", "broker.request", {"operation" => "dns.resolve", "params" => {"name" => "api.example.com"}}) }
    # All answers must satisfy the policy: a mixed answer is rejected as a whole.
    resolver.define_singleton_method(:getaddresses) { |_name| ["10.1.0.5", "203.0.113.9"] }
    assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "dns.resolve", "params" => {"name" => "api.example.com"}}) }
    epoch = 1
    assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "time.now", "params" => {}}) }
    assert_equal %w[allowed denied denied denied denied denied denied denied denied], audit.map { |entry| entry["outcome"] }
  end

  def test_broker_http_redirects_are_reauthorized_per_hop
    resolver = Object.new
    resolver.define_singleton_method(:getaddresses) { |name| name == "a.internal" ? ["10.1.0.5"] : ["198.51.100.7"] }
    hops = []
    factory = lambda do |uri, address, _headers|
      hops << [uri.host, address]
      if uri.host == "a.internal"
        response = Net::HTTPFound.new("1.1", "302", "Found")
        response["location"] = "https://b.external/secret"
        response
      else
        Net::HTTPOK.new("1.1", "200", "OK")
      end
    end
    broker = M::Broker.new(resolver: resolver, http_factory: factory)
    broker.bind(vm_id: "vm-1", identity: {"capability_id" => "c", "subject_id" => "s", "policy_digest" => "p", "revocation_epoch" => 0},
                policy: {"operations" => ["http.get"], "allowed_hosts" => ["a.internal"], "allowed_cidrs" => ["10.1.0.0/16"], "allowed_ports" => [443]})
    error = assert_raises(M::PolicyError) { broker.handle("vm-1", "broker.request", {"operation" => "http.get", "params" => {"url" => "https://a.internal/start"}}) }
    assert_includes error.message, "b.external"
    assert_equal [["a.internal", "10.1.0.5"]], hops, "the redirect target was never fetched"
  end

  def test_multiplexer_routes_by_runtime_class_and_remembers_owners
    native = fake_backend("native")
    firecracker = fake_backend("firecracker")
    mux = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "rubernetes-firecracker" => firecracker})
    sandbox = mux.run_sandbox({"id" => "p1"}, runtime_class: "rubernetes-firecracker")
    assert_equal "firecracker:sandbox", sandbox
    container = mux.create_container(sandbox, {"image" => "x"})
    assert_equal "firecracker:container", container
    assert_equal "firecracker:start", mux.start_container(container)
    assert_equal "native:sandbox", mux.run_sandbox({"id" => "p2"})
    assert_raises(ArgumentError) { mux.run_sandbox({"id" => "p3"}, runtime_class: "gvisor") }
    assert_equal %w[rubernetes-native rubernetes-firecracker], mux.handlers
  end

  def test_artifacts_lock_verification_fails_closed
    Dir.mktmpdir do |dir|
      file = File.join(dir, "firecracker")
      File.write(file, "binary")
      File.chmod(0o755, file)
      digest = Digest::SHA256.file(file).hexdigest
      files = M::Artifacts::REQUIRED.to_h { |name| [name, {"path" => "firecracker", "sha256" => digest, "bytes" => 6}] }
      document = {"schema_version" => 1, "files" => files, "verity" => {"root_hash" => "a" * 64}, "firecracker" => {"version" => "1.16.1"}}
      artifacts = M::Artifacts.new(document, root: dir)
      assert_equal 6, artifacts.verify!(expected_uid: Process.uid).length
      File.write(file, "tampered")
      assert_raises(M::ArtifactError) { artifacts.verify!(expected_uid: Process.uid) }
      File.write(file, "binary")
      File.chmod(0o777, file)
      assert_raises(M::ArtifactError) { artifacts.verify!(expected_uid: Process.uid) }
      assert_raises(M::ArtifactError) { M::Artifacts.new(document.merge("files" => files.reject { |key, _| key == "kernel" }), root: dir) }
    end
  end

  private

  def fake_backend(name)
    backend = Object.new
    backend.define_singleton_method(:run_sandbox) { |_config, **_options| "#{name}:sandbox" }
    backend.define_singleton_method(:create_container) { |_sandbox, _spec, **_options| "#{name}:container" }
    backend.define_singleton_method(:start_container) { |_id, **_options| "#{name}:start" }
    backend.define_singleton_method(:profile) { name.to_sym }
    backend
  end
end
