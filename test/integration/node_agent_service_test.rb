# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
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

    assert_same(service, service.stop(reason: "TERM"))
    refute_predicate(service, :started?)
    assert_equal([:loop_stop, "TERM"], @events.fetch(3))
    assert_equal([:runtime_stop, "TERM"], @events.fetch(4))
    lifecycle = @logger.events.map { |event| event.fetch(1) }.select do |name|
      %w[process.ready process.stopped].include?(name)
    end

    assert_equal(%w[process.ready process.stopped], lifecycle)
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

  def test_bootstrap_assembler_uses_the_native_agent_service
    assembly = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new).build

    assert_instance_of(Rubernetes::Bootstrap::AgentService, assembly.service)
    assert_instance_of(Rubernetes::Runtime::Native, assembly.service.runtime)
    assert_instance_of(Rubernetes::Node::APIClientAdapter, assembly.service.api_adapter)
    assert_instance_of(Rubernetes::Node::Agent, assembly.service.node_agent)
    assert_equal(:pure, assembly.service.runtime.config.profile)
  end
end
