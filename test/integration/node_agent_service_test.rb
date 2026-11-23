# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
require "net/http"
require "tmpdir"
require "rubernetes/bootstrap"

class NodeAgentServiceTest < Minitest::Test
  class Logger
    attr_reader :events

    def initialize
      @events = []
    end

    %i[debug info warn error fatal].each do |level|
      define_method(level) do |event, **fields|
        @events << [level, event, fields]
        true
      end
    end
  end

  class Runtime
    attr_reader :events

    def initialize(events)
      @events = events
    end

    def start(config:)
      @events << [:runtime_start, config]
      true
    end

    def reconcile
      @events << :runtime_reconcile
      true
    end

    def stop(reason:)
      @events << [:runtime_stop, reason]
      true
    end

    def logs(_container_id, follow:, since:, tail:)
      "logs:#{follow}:#{since}:#{tail}".b
    end
  end

  class SyncLoop
    attr_reader :events

    def initialize(events)
      @events = events
    end

    def start(runtime:, config:)
      @events << [:loop_start, runtime.class.name, config]
      true
    end

    def stop(reason:)
      @events << [:loop_stop, reason]
      true
    end
  end

  class CloseableAPIAdapter
    attr_reader :events

    def initialize
      @events = []
    end

    def close
      @events << :close
      self
    end
  end

  # The streaming server binds a real socket.  Its production default is the
  # kubelet port, which any kubelet on the host (this one runs k3s) already
  # owns, so tests ask the kernel for an ephemeral port instead of racing for
  # a well-known one.
  STREAMING_ON_EPHEMERAL_PORT = {"streaming" => {"port" => 0}}.freeze

  def setup
    @events = []
    @logger = Logger.new
    @runtime = Runtime.new(@events)
    @loop = SyncLoop.new(@events)
    # An agent with no image config reclaims abandoned stages from Dir.tmpdir,
    # which in a full-suite run holds other tests' leftovers: it then logs
    # image.stages_reclaimed before process.ready.  That is correct production
    # behaviour, so the fixture gets a staging root of its own.
    @staging_root = Dir.mktmpdir("agent-staging")
  end

  def teardown
    FileUtils.remove_entry(@staging_root) if @staging_root && File.directory?(@staging_root)
  end

  def agent_config(extra = {})
    {"image" => {"staging_root" => @staging_root}}.merge(STREAMING_ON_EPHEMERAL_PORT).merge(extra)
  end

  def test_agent_starts_runtime_reconciles_then_starts_loop_and_stops_in_reverse_order
    service = Rubernetes::Bootstrap::AgentService.new(
      config: agent_config("node_name" => "worker-a"),
      logger: @logger,
      runtime: @runtime,
      sync_loop: @loop,
      trusted_subresources: true,
      request_id_generator: -> { "agent-request" }
    )

    assert_same(service, service.start)
    assert_predicate(service, :started?)
    assert_equal(:runtime_reconcile, @events.fetch(1))
    assert_equal(:loop_start, @events.fetch(2).first)
    assert_equal("logs:true::", service.log_service.logs("container", follow: true).read)
    assert_equal(service.log_service, service.subresource(:logs))
    assert_equal(service.exec_service, service.subresource("exec"))
    assert_equal(service.port_forward_service, service.subresource("port-forward"))

    ready_port = @logger.events.find { |_, event, _| event == "process.ready" }.last.fetch(:streaming_port)
    response = Net::HTTP.new("127.0.0.1", ready_port, nil).get("/configz")

    assert_equal ready_port, JSON.parse(response.body).dig("kubeletconfig", "port")

    assert_same(service, service.stop(reason: "TERM"))
    refute_predicate(service, :started?)
    assert_equal([:loop_stop, "TERM"], @events.fetch(3))
    assert_equal([:runtime_stop, "TERM"], @events.fetch(4))
    lifecycle = @logger.events.map { |event| event.fetch(1) }.select do |name|
      %w[process.ready process.stopped].include?(name)
    end

    assert_equal(%w[process.ready process.stopped], lifecycle)
  end

  def test_runtime_log_rotation_is_started_and_quiesced_by_the_agent_service
    @runtime.define_singleton_method(:start_log_rotation) { events << :log_rotation_started }
    @runtime.define_singleton_method(:stop_log_rotation) { events << :log_rotation_stopped }
    service = Rubernetes::Bootstrap::AgentService.new(config: agent_config("healthz_port" => 0), logger: @logger,
                                                      runtime: @runtime, sync_loop: @loop)
    service.start
    service.stop(reason: "TERM")

    observed = @events.map { |entry| entry.is_a?(Array) ? entry.first : entry }

    assert_equal %i[runtime_start runtime_reconcile log_rotation_started loop_start loop_stop log_rotation_stopped runtime_stop], observed
  ensure
    service&.stop(reason: "cleanup")
  end

  def test_agent_start_rolls_back_runtime_when_sync_loop_fails
    failing_loop = Class.new do
      def start(**)
        raise "loop failed"
      end

      def stop(reason:)
        @reason = reason
      end
    end.new

    service = Rubernetes::Bootstrap::AgentService.new(
      config: {},
      logger: @logger,
      runtime: @runtime,
      sync_loop: failing_loop
    )

    assert_raises(RuntimeError) { service.start }
    refute_predicate(service, :started?)
    assert_equal(:runtime_reconcile, @events.fetch(1))
    assert_equal([:runtime_stop, "startup_failed"], @events.fetch(2))
  end

  def test_agent_start_and_stop_are_idempotence_guarded
    service = Rubernetes::Bootstrap::AgentService.new(config: agent_config, logger: @logger,
                                                      runtime: @runtime, sync_loop: @loop)

    service.start
    assert_raises(RuntimeError) { service.start }
    service.stop(reason: "TERM")

    assert_same(service, service.stop(reason: "TERM"))
  end

  def test_agent_stop_closes_the_api_transport_after_stopping_the_sync_loop
    api_adapter = CloseableAPIAdapter.new
    service = Rubernetes::Bootstrap::AgentService.new(
      config: agent_config, logger: @logger, runtime: @runtime, sync_loop: @loop,
      api_adapter: api_adapter
    )

    service.start
    service.stop(reason: "TERM")

    assert_equal [:close], api_adapter.events
    assert_equal([[:loop_stop, "TERM"]], @events.grep(Array).select { |event| event.first == :loop_stop })
  end

  def test_the_local_kubelet_health_check_tracks_readiness_and_closes_on_stop
    socket = TCPServer.new("127.0.0.1", 0)
    port = socket.local_address.ip_port
    socket.close
    agent = Object.new
    ready = false
    agent.define_singleton_method(:ready?) { ready }
    service = Rubernetes::Bootstrap::AgentService.new(config: agent_config("healthz_port" => port), logger: @logger,
                                                      runtime: @runtime, sync_loop: @loop, node_agent: agent)
    http = Net::HTTP.new("127.0.0.1", port, nil)
    service.start

    assert_equal "500", http.get("/healthz").code
    ready = true

    assert_equal "ok", http.get("/healthz").body
    assert_equal "404", http.get("/metrics").code
    assert_equal "405", http.post("/healthz", "").code

    service.stop(reason: "TERM")

    assert_raises(Errno::ECONNREFUSED) { http.get("/healthz") }
  ensure
    service&.stop(reason: "cleanup")
  end

  def test_local_health_remains_available_while_the_pod_sync_loop_drains
    socket = TCPServer.new("127.0.0.1", 0)
    port = socket.local_address.ip_port
    socket.close
    entering_stop = Queue.new
    release_stop = Queue.new
    @loop.define_singleton_method(:stop) do |reason:|
      entering_stop << reason
      release_stop.pop
    end
    agent = Object.new
    agent.define_singleton_method(:ready?) { true }
    service = Rubernetes::Bootstrap::AgentService.new(config: agent_config("healthz_port" => port), logger: @logger,
                                                      runtime: @runtime, sync_loop: @loop, node_agent: agent)
    http = Net::HTTP.new("127.0.0.1", port, nil)
    service.start
    shutdown = Thread.new { service.stop(reason: "TERM") }

    assert_equal "TERM", entering_stop.pop(timeout: 5)
    assert_equal "ok", http.get("/healthz").body

    release_stop << true
    shutdown.value

    assert_raises(Errno::ECONNREFUSED) { http.get("/healthz") }
  ensure
    release_stop&.close
    shutdown&.join
    service&.stop(reason: "cleanup")
  end

  def test_read_only_kubelet_listener_exposes_diagnostics_without_streaming_routes
    socket = TCPServer.new("127.0.0.1", 0)
    port = socket.local_address.ip_port
    socket.close
    agent = Object.new
    stats = Object.new
    stats.define_singleton_method(:summary) { {"node" => {"nodeName" => "worker-a"}, "pods" => []} }
    agent.define_singleton_method(:stats_provider) { stats }
    config = agent_config("healthz_port" => 0, "read_only_port" => port)
    service = Rubernetes::Bootstrap::AgentService.new(config: config, logger: @logger, runtime: @runtime,
                                                      sync_loop: @loop, node_agent: agent)
    http = Net::HTTP.new("127.0.0.1", port, nil)
    service.start

    assert_equal "worker-a", JSON.parse(http.get("/stats/summary").body).dig("node", "nodeName")
    assert_equal "200", http.get("/metrics/resource").code
    assert_equal "404", http.get("/pods").code
    assert_equal "404", http.get("/containerLogs/default/test/main").code
    assert_equal "404", http.post("/exec/default/test/main", "").code
  ensure
    service&.stop(reason: "cleanup")
  end

  def test_bootstrap_assembler_uses_the_native_agent_service
    assembly = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new).build

    assert_instance_of(Rubernetes::Bootstrap::AgentService, assembly.service)
    assert_instance_of(Rubernetes::Runtime::Native, assembly.service.runtime)
    assert_instance_of(Rubernetes::Node::APIClientAdapter, assembly.service.api_adapter)
    assert_instance_of(Rubernetes::Node::Agent, assembly.service.node_agent)
    assert_equal(:pure, assembly.service.runtime.config.profile)
  end

  def test_typed_kubelet_configuration_controls_the_real_streaming_listener
    address = "::1"
    port = TCPServer.open(address, 0) { |socket| socket.local_address.ip_port }
    component = File.join(@staging_root, "kubelet.yml")
    document = {"apiVersion" => "kubelet.config.k8s.io/v1beta1", "kind" => "KubeletConfiguration",
                "address" => address, "port" => port, "healthzPort" => 0, "enableServer" => false}
    http = Net::HTTP.new(address, port, nil)

    service = start_typed_agent(component, document)
    assert_raises(Errno::ECONNREFUSED) { http.get("/configz") }
    service.stop(reason: "reload configuration")

    service = start_typed_agent(component, document.merge("enableServer" => true))
    response = http.get("/configz")

    assert_equal "200", response.code
    assert_equal [true, address, port], JSON.parse(response.body).fetch("kubeletconfig").values_at("enableServer", "address", "port")
  ensure
    service&.stop(reason: "cleanup")
  end

  private

  def start_typed_agent(path, document)
    File.write(path, YAML.dump(document))
    config = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: path).process
    service = Rubernetes::Bootstrap::AgentService.new(config: config.merge("image" => {"staging_root" => @staging_root}),
                                                      logger: @logger, runtime: @runtime, sync_loop: @loop)
    service.start
  end
end
