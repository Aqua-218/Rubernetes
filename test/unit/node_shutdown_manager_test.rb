# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/shutdown_manager"
require "tmpdir"

# Graceful node shutdown: the D-Bus wire protocol (marshalling, SASL
# EXTERNAL, unix fd passing) against an in-process bus, logind's inhibitor
# lock and PrepareForShutdown, and the manager's priority groups, admission
# refusal, Ready status and state file.
class NodeShutdownManagerTest < Minitest::Test
  DBus = Rubernetes::Platform::Linux::DBus
  SM = Rubernetes::Node::ShutdownManager

  def test_messages_round_trip
    body = ["s", 7, [1, 2, 3], {"a" => DBus::Typed.new("t", 2**40), "b" => DBus::Typed.new("as", %w[x y])}, [5, "p"], true]
    bytes = DBus.encode(type: DBus::METHOD_CALL, serial: 9, fields: {DBus::FIELD_PATH => "/o", DBus::FIELD_MEMBER => "M"},
                        body_signature: "suaya{sv}(ys)b", body: body)
    message, used = DBus.decode(bytes)
    assert_equal bytes.bytesize, used
    assert_equal 9, message.serial
    assert_equal "/o", message.path
    assert_equal "suaya{sv}(ys)b", message.signature
    assert_equal ["s", 7, [1, 2, 3], {"a" => DBus::Typed.new("t", 2**40), "b" => DBus::Typed.new("as", %w[x y])}, [5, "p"], true],
                 message.body
    assert_nil DBus.decode(bytes.byteslice(0, bytes.bytesize - 1)), "an incomplete message waits for more"
  end

  # The bus side of one connection: auth, Hello, and scripted replies.
  class FakeBus
    attr_reader :calls, :lock_reader

    def initialize(socket, inhibit_delay_usec: 30_000_000)
      @socket = socket
      @calls = []
      @delay = inhibit_delay_usec
      @serial = 100
      @thread = Thread.new { serve }
    end

    def emit_prepare_for_shutdown(value)
      @serial += 1
      @socket.write(DBus.encode(type: DBus::SIGNAL, serial: @serial,
                                fields: {DBus::FIELD_PATH => "/org/freedesktop/login1", DBus::FIELD_INTERFACE => "org.freedesktop.login1.Manager",
                                         DBus::FIELD_MEMBER => "PrepareForShutdown"},
                                body_signature: "b", body: [value]))
    end

    def close = @socket.close

    private

    def serve
      buffer = +""
      buffer << @socket.readpartial(1) until buffer.end_with?("BEGIN\r\n") || respond_to_auth(buffer)
      data = String.new(encoding: Encoding::BINARY)
      loop do
        data << @socket.readpartial(65_536).b
        while (decoded = DBus.decode(data))
          message, used = decoded
          data = data.byteslice(used..)
          handle(message)
        end
      end
    rescue IOError, Errno::ECONNRESET, Errno::EPIPE
      nil
    end

    def respond_to_auth(buffer)
      if buffer.end_with?("\r\n")
        line = buffer.lines.last.chomp.delete("\0")
        @socket.write("OK 1234\r\n") if line.start_with?("AUTH EXTERNAL")
        @socket.write("AGREE_UNIX_FD\r\n") if line == "NEGOTIATE_UNIX_FD"
        return true if line == "BEGIN"
      end
      false
    end

    def reply(message, signature = "", body = [], fds: [])
      @serial += 1
      fields = {DBus::FIELD_REPLY_SERIAL => message.serial}
      fields[DBus::FIELD_UNIX_FDS] = fds.length unless fds.empty?
      bytes = DBus.encode(type: DBus::METHOD_RETURN, serial: @serial, fields: fields, body_signature: signature, body: body)
      if fds.empty?
        @socket.write(bytes)
      else
        @socket.sendmsg(bytes, 0, nil, Socket::AncillaryData.unix_rights(*fds))
      end
    end

    def handle(message)
      @calls << [message.interface, message.member, message.body]
      case message.member
      when "Hello" then reply(message, "s", [":1.42"])
      when "Get" then reply(message, "v", [DBus::Typed.new("t", @delay)])
      when "AddMatch", "KillUnit" then reply(message)
      when "Inhibit"
        reader, writer = IO.pipe
        @lock_reader = reader
        reply(message, "h", [0], fds: [writer])
        writer.close
      end
    end
  end

  def with_bus(**options)
    client, server = UNIXSocket.pair
    bus = FakeBus.new(server, **options)
    connection = DBus::Connection.new(client)
    yield SM::Logind.new(connection: connection, config_directory: Dir.mktmpdir("logind")), bus
  ensure
    bus&.close
    client&.close unless client&.closed?
  end

  def test_logind_inhibits_and_reports_prepare_for_shutdown
    with_bus do |logind, bus|
      assert_equal 30.0, logind.current_inhibit_delay
      lock = logind.inhibit_shutdown
      assert_equal ["org.freedesktop.login1.Manager", "Inhibit", ["shutdown", "kubelet", "Kubelet needs time to handle node shutdown", "delay"]],
                   bus.calls.last
      refute lock.closed?
      events = []
      thread = Thread.new { logind.monitor_shutdown { |value| events << value } }
      sleep 0.05 until bus.calls.any? { |call| call[1] == "AddMatch" }
      assert_equal "type='signal',interface='org.freedesktop.login1.Manager',member='PrepareForShutdown',path='/org/freedesktop/login1'",
                   bus.calls.find { |call| call[1] == "AddMatch" }[2].first
      bus.emit_prepare_for_shutdown(true)
      sleep 0.05 until events.any?
      assert_equal [true], events

      logind.release_inhibit_lock(lock)
      assert_nil bus.lock_reader.read_nonblock(1, exception: false), "closing the lock is what releases the inhibitor"
      bus.close
      thread.join(2)
    end
  end

  def test_the_drop_in_raises_the_delay_and_logind_is_reloaded
    with_bus(inhibit_delay_usec: 5_000_000) do |logind, bus|
      logind.override_inhibit_delay(90)
      path = File.join(logind.instance_variable_get(:@config_directory), "99-kubelet.conf")
      assert_equal "# Kubelet logind override\n[Login]\nInhibitDelayMaxSec=90\n", File.read(path)
      logind.reload_logind_conf
      assert_equal ["org.freedesktop.systemd1.Manager", "KillUnit", ["systemd-logind.service", "all", 1]], bus.calls.last
    end
  end

  # migrateConfig works in time.Duration (nanoseconds); float seconds made
  # 67.6s - 26.6s = 40.999...s one second short
  # (tools/differential/node_shutdown_differential.rb: 5000/5000 vs upstream).
  def test_migrated_periods_use_exact_durations
    assert_equal [SM::Period.new(0, 41), SM::Period.new(2_000_000_000, 26)], SM.periods(grace_period: 67.6, critical_grace_period: 26.6)
    assert_equal [SM::Period.new(0, 2), SM::Period.new(2_000_000_000, 1)], SM.periods(grace_period: 3.3, critical_grace_period: 1.3)
  end

  def test_periods_migrate_the_two_group_configuration
    assert_empty SM.periods(grace_period: 0)
    assert_equal [SM::Period.new(0, 20), SM::Period.new(2_000_000_000, 10)], SM.periods(grace_period: 30, critical_grace_period: 10)
    assert_equal [SM::Period.new(-5, 3), SM::Period.new(100, 7)],
                 SM.periods(grace_period: 30, by_priority: [{"priority" => 100, "shutdown_grace_period_seconds" => 7},
                                                            {"priority" => -5, "shutdown_grace_period_seconds" => 3}])
    assert_nil SM.build(grace_period: 0, active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil), "no period, no manager"
    assert_nil SM.build(gate: false, grace_period: 30, active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil)
  end

  class FakeInhibiter
    attr_reader :calls, :events

    def initialize(delays)
      @delays = delays
      @calls = []
      @events = Queue.new
    end

    def current_inhibit_delay = @delays.length > 1 ? @delays.shift : @delays.first
    def override_inhibit_delay(seconds) = @calls << [:override, seconds]
    def reload_logind_conf = @calls << [:reload]
    def inhibit_shutdown = (@calls << [:inhibit]) && "lock-#{@calls.count { |c| c == [:inhibit] }}"
    def release_inhibit_lock(lock) = @calls << [:release, lock]
    def close = nil

    def monitor_shutdown
      while (event = @events.pop) != :end
        yield event
      end
    end
  end

  def pod(name, priority: nil, grace: nil)
    spec = {}
    spec["priority"] = priority if priority
    spec["terminationGracePeriodSeconds"] = grace if grace
    {"metadata" => {"name" => name, "uid" => name}, "spec" => spec}
  end

  def test_a_shutdown_kills_pods_by_priority_group_and_releases_the_lock
    Dir.mktmpdir do |dir|
      inhibiter = FakeInhibiter.new([60.0])
      killed = []
      terminated = {}
      status_synced = Queue.new
      pods = [pod("critical", priority: 2_000_000_000), pod("app"), pod("quick", grace: 3), pod("low", priority: -10)]
      manager = SM.new(periods: SM.periods(grace_period: 30, critical_grace_period: 10), active_pods: -> { pods },
                       kill_pod: lambda { |target, grace, **options|
                         killed << [target["metadata"]["name"], grace, options[:reason], options[:message], options[:condition]["reason"]]
                         terminated[target["metadata"]["name"]] = true
                       },
                       pod_terminated: ->(target) { terminated[target["metadata"]["name"]] },
                       sync_node_status: -> { status_synced << true }, state_directory: dir, inhibiter: -> { inhibiter },
                       sleeper: ->(_) { Thread.pass })
      assert_nil manager.admit(pods.first)
      thread = Thread.new { manager.watch }
      Thread.pass until inhibiter.calls.include?([:inhibit])
      refute(inhibiter.calls.any? { |call| call[0] == :override }, "30s fits in logind's 60s")

      inhibiter.events << true
      status_synced.pop
      Thread.pass until inhibiter.calls.include?([:release, "lock-1"])
      assert_equal "node is shutting down", manager.shutdown_status
      assert_equal ["NodeShutdown", "Pod was rejected as the node is shutting down."], manager.admit(pod("new"))
      groups = killed.map { |name, grace, *| [name, grace] }
      assert_equal [["app", 20], ["low", 20], ["quick", 3]].sort, groups.first(3).sort, "the default group first, lowest priority pods in it"
      assert_equal ["critical", 10], groups.last
      assert(killed.all? { |_, _, reason, message, condition| reason == "Terminated" && condition == "TerminationByKubelet" &&
                                                        message == "Pod was terminated in response to imminent node shutdown." })
      state = JSON.parse(File.read(File.join(dir, "graceful_node_shutdown_state")))
      refute_equal "0001-01-01T00:00:00Z", state["endTime"]

      inhibiter.events << false
      Thread.pass until inhibiter.calls.count { |call| call == [:inhibit] } == 2
      assert_nil manager.shutdown_status, "a cancelled shutdown takes the lock again"
      inhibiter.events << :end
      thread.join(2)
    end
  end

  def test_a_short_logind_delay_is_raised_or_the_watch_fails
    inhibiter = FakeInhibiter.new([5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0])
    manager = SM.new(periods: SM.periods(grace_period: 30), active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil,
                     inhibiter: -> { inhibiter }, sleeper: ->(_) {})
    error = assert_raises(SM::Error) { manager.watch }
    assert_equal "node shutdown manager was timed out after 5 attempts waiting for logind InhibitDelayMaxSec to update to 30s " \
                 "(ShutdownGracePeriod), current value is 5s", error.message
    assert_equal [[:override, 30], [:reload]], inhibiter.calls
  end
  def test_the_system_bus_address_comes_from_the_environment_as_for_godbus
    Dir.mktmpdir do |dir|
      path = File.join(dir, "bus socket")
      server = UNIXServer.new(path)
      bus = nil
      acceptor = Thread.new { bus = FakeBus.new(server.accept) }
      saved = ENV.fetch(DBus::SYSTEM_BUS_ADDRESS_ENV, nil)
      ENV[DBus::SYSTEM_BUS_ADDRESS_ENV] = "tcp:host=localhost,port=1;unix:path=#{path.gsub(" ", "%20")}"
      connection = DBus::Connection.system
      acceptor.join
      assert_equal ":1.42", connection.unique_name
      connection.close
    ensure
      saved.nil? ? ENV.delete(DBus::SYSTEM_BUS_ADDRESS_ENV) : ENV[DBus::SYSTEM_BUS_ADDRESS_ENV] = saved
      bus&.close
      server&.close
    end
    error = assert_raises(DBus::Error) { DBus.connect_address("tcp:host=localhost,port=1") }
    assert_match(/no usable unix transport/, error.message)
  end

  class CleaningInhibiter < FakeInhibiter
    def initialize(delays, directory)
      super(delays)
      @logind = SM::Logind.allocate
      @logind.instance_variable_set(:@config_directory, directory)
    end

    def override_inhibit_delay(seconds)
      super
      @logind.override_inhibit_delay(seconds)
    end

    def remove_inhibit_delay_override(seconds)
      @calls << [:remove, seconds]
      @logind.remove_inhibit_delay_override(seconds)
    end
  end

  def test_stop_releases_the_lock_and_takes_back_the_drop_in
    Dir.mktmpdir do |dir|
      conf = File.join(dir, "logind.conf.d")
      inhibiter = CleaningInhibiter.new([5.0, 30.0], conf)
      manager = SM.new(periods: SM.periods(grace_period: 30), active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil,
                       inhibiter: -> { inhibiter }, sleeper: ->(_) {})
      thread = Thread.new { manager.watch }
      Thread.pass until inhibiter.calls.include?([:inhibit])
      assert File.file?(File.join(conf, "99-kubelet.conf"))

      stopper = Thread.new { manager.stop }
      Thread.pass until inhibiter.calls.include?([:release, "lock-1"])
      inhibiter.events << :end
      stopper.join(2)
      thread.join(2)
      assert_equal [[:override, 30], [:reload], [:inhibit], [:release, "lock-1"], [:remove, 30], [:reload]], inhibiter.calls
      refute File.exist?(conf), "the drop-in and the directory it needed are gone"
    end
  end

  def test_an_operators_own_drop_in_is_left_alone
    Dir.mktmpdir do |dir|
      logind = SM::Logind.allocate
      logind.instance_variable_set(:@config_directory, dir)
      path = File.join(dir, "99-kubelet.conf")
      File.write(path, "[Login]\nInhibitDelayMaxSec=600\n")
      refute logind.remove_inhibit_delay_override(30)
      assert File.file?(path)
      logind.override_inhibit_delay(30)
      File.write(File.join(dir, "10-site.conf"), "[Login]\n")
      assert logind.remove_inhibit_delay_override(30)
      refute File.exist?(path)
      assert File.directory?(dir), "a directory with other drop-ins stays"
    end
  end

  def test_a_manager_that_wrote_nothing_removes_nothing
    inhibiter = CleaningInhibiter.new([60.0], Dir.mktmpdir)
    manager = SM.new(periods: SM.periods(grace_period: 30), active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil,
                     inhibiter: -> { inhibiter }, sleeper: ->(_) {})
    thread = Thread.new { manager.watch }
    Thread.pass until inhibiter.calls.include?([:inhibit])
    manager.stop
    inhibiter.events << :end
    thread.join(2)
    assert_equal [[:inhibit], [:release, "lock-1"]], inhibiter.calls
  end
  # Start as managerImpl.Start: the first connection's failure is reported
  # once and nothing is retried (no lock, logind not reloaded again).
  def test_a_failed_first_start_is_reported_and_not_retried
    inhibiter = FakeInhibiter.new([30.0])
    errors = []
    manager = SM.new(periods: SM.periods(grace_period: 45), active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil,
                     inhibiter: -> { inhibiter }, sleeper: ->(_) {}, error_handler: ->(error, during) { errors << [error.message, during] })
    assert_equal false, manager.start
    assert_equal [["Failed to start node shutdown manager: node shutdown manager was timed out after 5 attempts waiting for " \
                   "logind InhibitDelayMaxSec to update to 45s (ShutdownGracePeriod), current value is 30s", :shutdown_manager]], errors
    sleep 0.05
    assert_equal [[:override, 45], [:reload]], inhibiter.calls, "one reload, no lock, no retry"
    assert_nil manager.instance_variable_get(:@thread)
  end

  def test_a_started_watch_reconnects_after_the_bus_goes_away
    first = FakeInhibiter.new([60.0])
    second = FakeInhibiter.new([60.0])
    buses = [first, second]
    manager = SM.new(periods: SM.periods(grace_period: 30), active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil,
                     inhibiter: -> { buses.shift || flunk("a third connection") }, sleeper: ->(_) { Thread.pass })
    assert_same manager, manager.start
    assert_equal [[:inhibit]], first.calls
    first.events << :end
    Thread.pass until second.calls.include?([:inhibit])
    assert_equal [[:inhibit], [:release, "lock-1"]], first.calls, "the old connection's lock is let go"
    stopper = Thread.new { manager.stop }
    Thread.pass until second.calls.include?([:release, "lock-1"])
    second.events << :end
    stopper.join(2)
    refute manager.instance_variable_get(:@thread).alive?
  end
  # A PrepareForShutdown sent the moment the lock is taken must not be lost:
  # the bus routes a signal only to connections whose match rule is already
  # installed, so AddMatch has to precede Inhibit.
  def test_the_shutdown_signal_is_subscribed_before_the_lock_is_taken
    with_bus do |logind, bus|
      manager = SM.new(periods: SM.periods(grace_period: 30), active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil,
                       inhibiter: -> { logind }, sleeper: ->(_) {})
      manager.connect
      members = bus.calls.map { |call| call[1] }
      assert_operator members.index("AddMatch"), :<, members.index("Inhibit")
      assert_equal 1, members.count("AddMatch")
      thread = Thread.new { logind.monitor_shutdown { |_| } }
      sleep 0.05
      assert_equal 1, bus.calls.count { |call| call[1] == "AddMatch" }, "monitoring does not subscribe twice"
      bus.close
      thread.join(2)
    end
  end
end
