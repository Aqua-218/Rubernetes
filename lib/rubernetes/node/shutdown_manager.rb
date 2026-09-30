# frozen_string_literal: true

require "fileutils"
require "json"
require "time"
require_relative "../platform/linux/dbus"

module Rubernetes
  module Node
    # pkg/kubelet/nodeshutdown (GracefulNodeShutdown, v1.36.2): with a
    # shutdown grace period the node holds a systemd-logind "delay"
    # inhibitor lock for shutdown; on PrepareForShutdown(true) it goes
    # NotReady ("node is shutting down"), refuses new Pods (NodeShutdown) and
    # kills the running ones in priority groups -- each within its group's
    # grace period (or its own shorter terminationGracePeriodSeconds) -- as
    # Failed/Terminated with a DisruptionTarget condition, then releases the
    # lock so the shutdown proceeds.  Without a grace period there is no
    # manager at all (managerStub), as upstream.
    class ShutdownManager
      NOT_ADMITTED_REASON = "NodeShutdown"
      NOT_ADMITTED_MESSAGE = "Pod was rejected as the node is shutting down."
      SHUTDOWN_REASON = "Terminated"
      SHUTDOWN_MESSAGE = "Pod was terminated in response to imminent node shutdown."
      STATUS_MESSAGE = "node is shutting down"
      STATE_FILE = "graceful_node_shutdown_state"
      RECONNECT_PERIOD = 1.0
      # scheduling.DefaultPriorityWhenNoDefaultClassExists / SystemCriticalPriority.
      DEFAULT_PRIORITY = 0
      SYSTEM_CRITICAL_PRIORITY = 2_000_000_000

      class Error < StandardError; end

      Period = Struct.new(:priority, :seconds)

      # migrateConfig: the two-group form of shutdownGracePeriod /
      # shutdownGracePeriodCriticalPods.
      def self.periods(grace_period:, critical_grace_period: 0, by_priority: [], based_on_priority: true)
        periods = if based_on_priority && !Array(by_priority).empty?
                    Array(by_priority).map do |entry|
                      entry = entry.to_h { |key, value| [key.to_s, value] }
                      Period.new(Integer(entry.fetch("priority")), Integer(entry.fetch("shutdown_grace_period_seconds")))
                    end
                  else
                    # time.Duration arithmetic: whole nanoseconds, truncated
                    # to seconds (3.3s - 1.3s is 2s, not 1.999...).
                    requested = nanoseconds(grace_period)
                    default = requested - nanoseconds(critical_grace_period)
                    critical = requested - default
                    if requested.zero? || default.negative? || critical.negative?
                      []
                    else
                      [Period.new(DEFAULT_PRIORITY, default / 1_000_000_000),
                       Period.new(SYSTEM_CRITICAL_PRIORITY, critical / 1_000_000_000)]
                    end
                  end
        periods.sort_by(&:priority)
      end

      def self.nanoseconds(seconds) = (seconds.to_r * 1_000_000_000).round

      # NewManager: nil (managerStub) when there is nothing to wait for.
      def self.build(gate: true, **options)
        return nil unless gate

        periods = periods(**options.slice(:grace_period, :critical_grace_period, :by_priority, :based_on_priority))
        return nil if periods.empty?

        new(periods: periods, **options.except(:grace_period, :critical_grace_period, :by_priority, :based_on_priority))
      end

      attr_reader :periods

      # +active_pods+: -> Pods; +kill_pod+: (pod, grace_seconds, message:,
      # reason:, condition:); +pod_terminated+: (pod) -> true once its
      # containers are gone; +sync_node_status+: publish Ready now.
      def initialize(periods:, active_pods:, kill_pod:, pod_terminated:, sync_node_status: nil, state_directory: nil,
                     recorder: nil, node_ref: nil, inhibiter: -> { Logind.new }, clock: -> { Time.now.utc },
                     sleeper: ->(seconds) { sleep(seconds) }, monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     error_handler: nil, based_on_priority: true)
        @periods = periods
        @active_pods = active_pods
        @kill_pod = kill_pod
        @pod_terminated = pod_terminated
        @sync_node_status = sync_node_status
        @state_path = state_directory && File.join(state_directory, STATE_FILE)
        @recorder = recorder
        @node_ref = node_ref
        @inhibiter_factory = inhibiter
        @clock = clock
        @sleeper = sleeper
        @monotonic = monotonic
        @error_handler = error_handler
        @metrics = based_on_priority
        @mutex = Mutex.new
        @shutting_down = false
        @lock = nil
        @stopped = false
        @override_written = false
      end

      # ->(name, value) for kubelet_graceful_shutdown_{start,end}_time_seconds.
      attr_writer :gauge_sink

      # setMetrics: the times of the last shutdown, from the state file.
      def load_metrics
        return unless @metrics && @state_path && File.file?(@state_path)

        state = JSON.parse(File.read(@state_path))
        started = self.class.unix_time(state["startTime"])
        ended = self.class.unix_time(state["endTime"])
        set_gauge("kubelet_graceful_shutdown_start_time_seconds", started) if started.positive?
        set_gauge("kubelet_graceful_shutdown_end_time_seconds", ended) if ended.positive?
      rescue JSON::ParserError, SystemCallError => error
        @error_handler&.call(error, :shutdown_manager)
      end

      # storage.go timestamp: whole Unix seconds, 0 for Go's zero time.
      def self.unix_time(text)
        return 0 if text.to_s.empty? || text.to_s.start_with?("0001-01-01")

        Time.parse(text.to_s).to_i
      rescue ArgumentError
        0
      end

      # The pod admit handler: [reason, message] to refuse, nil to admit.
      def admit(_pod) = shutting_down? ? [NOT_ADMITTED_REASON, NOT_ADMITTED_MESSAGE] : nil

      def shutting_down? = @mutex.synchronize { @shutting_down }

      # ShutdownStatus: the Ready condition's error, nil when not shutting down.
      def shutdown_status = shutting_down? ? STATUS_MESSAGE : nil

      # sum(ShutdownGracePeriodSeconds).
      def period_requested = @periods.sum(&:seconds)

      # Start: the first connection is made here, and a failure is returned
      # to the caller (the kubelet logs "Failed to start node shutdown
      # manager" and runs on without a lock -- no retry, so a logind that
      # never takes the drop-in is not reloaded again and again).  Once
      # watching, the watch is restarted a second after the bus goes away,
      # failures included.  False (after reporting the error) when the first
      # connection fails.
      def start
        begin
          connect
        rescue StandardError => error
          close_bus
          @error_handler&.call(Error.new("Failed to start node shutdown manager: #{error.message}"), :shutdown_manager)
          return false
        end
        @thread = Thread.new do
          connected = true
          until @mutex.synchronize { @stopped }
            begin
              monitor if connected
            rescue StandardError => error
              @error_handler&.call(error, :shutdown_manager)
            ensure
              disconnect
            end
            @sleeper.call(RECONNECT_PERIOD) unless @mutex.synchronize { @stopped }
            break if @mutex.synchronize { @stopped }

            begin
              connect
              connected = true
            rescue StandardError => error
              connected = false
              close_bus
              @error_handler&.call(error, :shutdown_manager)
            end
          end
        end
        load_metrics
        self
      end

      # Stop: release the inhibitor lock (the fd), end the watch, and take
      # back the logind drop-in this manager's grace period put there.
      # Upstream leaves both to the kubelet's exit (the fd closes with the
      # process; the drop-in stays until the next kubelet rewrites it); a
      # stopped agent here leaves the host's logind as it found it.
      def stop
        @mutex.synchronize { @stopped = true }
        release_inhibit_lock
        @bus&.close
        @thread&.join(2)
        restore_inhibit_delay
      end

      # Removes the drop-in if it is the one this grace period writes and
      # reloads logind, over a connection of its own (the watch's is gone).
      def restore_inhibit_delay
        return unless @override_written

        bus = @inhibiter_factory.call
        begin
          bus.reload_logind_conf if bus.respond_to?(:remove_inhibit_delay_override) && bus.remove_inhibit_delay_override(period_requested)
        ensure
          bus.close
        end
        @override_written = false
      rescue StandardError => error
        @error_handler&.call(error, :shutdown_manager)
      end

      # One connection's life: raise the inhibit delay if needed, take the
      # lock, and act on PrepareForShutdown until the bus goes away.
      def watch
        connect
        monitor
      ensure
        disconnect
      end

      # managerImpl.start up to MonitorShutdown.
      def connect
        @bus = @inhibiter_factory.call
        current = @bus.current_inhibit_delay
        requested = period_requested
        if requested > current
          @bus.override_inhibit_delay(requested)
          @override_written = true
          @bus.reload_logind_conf
          updated = current
          delay = 0.1
          5.times do
            updated = @bus.current_inhibit_delay
            break if requested <= updated

            @sleeper.call(delay)
            delay *= 2
          end
          if requested > updated
            raise Error, "node shutdown manager was timed out after 5 attempts waiting for logind InhibitDelayMaxSec to update " \
                         "to #{duration(requested)} (ShutdownGracePeriod), current value is #{duration(updated)}"
          end
        end
        # The match rule goes in before the lock: a PrepareForShutdown sent
        # while the lock is held but nothing is subscribed is dropped by the
        # bus, and logind then waits out the delay with no Pod stopped.
        # (Upstream subscribes after InhibitShutdown and has that window.)
        @bus.subscribe_shutdown if @bus.respond_to?(:subscribe_shutdown)
        acquire_inhibit_lock
        self
      end

      def monitor
        @bus.monitor_shutdown do |shutting_down|
          handle_event(shutting_down)
          break if @mutex.synchronize { @stopped }
        end
      end

      def handle_event(shutting_down)
        record_event(shutting_down ? "Shutdown manager detected shutdown event" : "Shutdown manager detected shutdown cancellation")
        @mutex.synchronize { @shutting_down = shutting_down }
        if shutting_down
          Thread.new { @sync_node_status&.call }
          process_shutdown_event
        else
          acquire_inhibit_lock
        end
      end

      # processShutdownEvent.
      def process_shutdown_event
        started = @clock.call
        store_state(started, nil)
        if @metrics
          set_gauge("kubelet_graceful_shutdown_start_time_seconds", started.to_i)
          set_gauge("kubelet_graceful_shutdown_end_time_seconds", 0)
        end
        kill_pods(Array(@active_pods.call))
        ended = @clock.call
        store_state(started, ended)
        set_gauge("kubelet_graceful_shutdown_end_time_seconds", ended.to_i) if @metrics
      ensure
        release_inhibit_lock
      end

      # killPods: group by group, lowest priority first.
      def kill_pods(pods)
        group_by_priority(pods).each do |period, members|
          next if members.empty?

          threads = members.map do |pod|
            Thread.new do
              @kill_pod.call(pod, kill_grace(period, pod), message: SHUTDOWN_MESSAGE, reason: SHUTDOWN_REASON,
                                                           condition: {"type" => "DisruptionTarget", "status" => "True",
                                                                       "reason" => "TerminationByKubelet", "message" => SHUTDOWN_MESSAGE})
            rescue StandardError => error
              @error_handler&.call(error, :shutdown_manager)
            end
          end
          deadline = @monotonic.call + period.seconds
          loop do
            break if threads.none?(&:alive?) && members.all? { |pod| @pod_terminated.call(pod) }
            break if @monotonic.call >= deadline

            @sleeper.call(0.1)
          end
        end
      end

      # killPods' gracePeriodOverride: the group's period, or the Pod's own
      # terminationGracePeriodSeconds when that is not longer.
      def kill_grace(period, pod)
        own = pod.dig("spec", "terminationGracePeriodSeconds")
        !own.nil? && own <= period.seconds ? own : period.seconds
      end

      # groupByPriority: a Pod goes to the group with the highest priority
      # not above its own (the lowest group when it is below all).
      def group_by_priority(pods)
        groups = @periods.map { |period| [period, []] }
        pods.each do |pod|
          priority = pod.dig("spec", "priority").to_i
          index = groups.index { |period, _| period.priority >= priority }
          if index.nil?
            index = groups.length - 1
          elsif index.positive? && groups[index][0].priority > priority
            index -= 1
          end
          groups[index][1] << pod
        end
        groups
      end

      private

      # The lock belongs to the connection's logind; a new connection takes
      # a new one.
      def disconnect
        release_inhibit_lock
        close_bus
      end

      def close_bus
        @bus&.close
      rescue StandardError
        nil
      end

      def acquire_inhibit_lock
        lock = @bus.inhibit_shutdown
        previous = @mutex.synchronize do
          old = @lock
          @lock = lock
          old
        end
        @bus.release_inhibit_lock(previous) if previous
      end

      def release_inhibit_lock
        lock = @mutex.synchronize do
          old = @lock
          @lock = nil
          old
        end
        @bus&.release_inhibit_lock(lock) if lock
      rescue Error => error
        @error_handler&.call(error, :shutdown_manager)
      end

      def set_gauge(name, value)
        @gauge_sink&.call(name, value)
      rescue StandardError
        nil
      end

      def store_state(started, ended)
        return unless @metrics && @state_path

        FileUtils.mkdir_p(File.dirname(@state_path))
        temporary = "#{@state_path}.tmp.#{Process.pid}"
        zero = "0001-01-01T00:00:00Z"
        File.write(temporary, JSON.generate("startTime" => started ? started.utc.iso8601(9) : zero,
                                            "endTime" => ended ? ended.utc.iso8601(9) : zero))
        File.chmod(0o644, temporary)
        File.rename(temporary, @state_path)
      rescue SystemCallError => error
        @error_handler&.call(error, :shutdown_manager)
      end

      def record_event(message)
        return unless @recorder && @node_ref

        @recorder.record(object: @node_ref, type: "Normal", reason: "NodeShutdown", message: message)
      rescue StandardError
        nil
      end

      def duration(seconds) = "#{seconds.to_i}s"

      # systemd.DBusCon: logind over the system bus.
      class Logind
        SERVICE = "org.freedesktop.login1"
        OBJECT = "/org/freedesktop/login1"
        INTERFACE = "org.freedesktop.login1.Manager"
        CONFIG_DIRECTORY = "/etc/systemd/logind.conf.d"
        CONFIG_FILE = "99-kubelet.conf"

        class << self
          # Where the drop-in goes (upstream: fixed); tests point it at a
          # temporary directory together with DBUS_SYSTEM_BUS_ADDRESS.
          attr_writer :config_directory

          def config_directory = @config_directory || CONFIG_DIRECTORY
        end

        def initialize(connection: nil, config_directory: self.class.config_directory)
          @connection = connection || Platform::Linux::DBus::Connection.system
          @config_directory = config_directory
        end

        def close = @connection.close

        # CurrentInhibitDelay: InhibitDelayMaxUSec, in seconds.
        def current_inhibit_delay
          value = @connection.get_property(destination: SERVICE, path: OBJECT, interface: INTERFACE, name: "InhibitDelayMaxUSec")
          raise Error, "InhibitDelayMaxUSec from logind is not a uint64 as expected" unless value.is_a?(Integer)

          value / 1_000_000.0
        rescue Platform::Linux::DBus::RemoteError => error
          raise Error, "failed reading InhibitDelayMaxUSec property from logind: #{error.message}"
        end

        # InhibitShutdown: the lock is the returned file descriptor.
        def inhibit_shutdown
          reply = @connection.call(destination: SERVICE, path: OBJECT, interface: INTERFACE, member: "Inhibit", signature: "ssss",
                                   args: ["shutdown", "kubelet", "Kubelet needs time to handle node shutdown", "delay"])
          fd = reply.first
          raise Error, "failed storing inhibit lock file descriptor" unless fd.respond_to?(:io) && fd.io

          fd.io
        rescue Platform::Linux::DBus::RemoteError => error
          raise Error, "failed creating systemd inhibitor: #{error.message}"
        end

        def release_inhibit_lock(lock)
          lock.close unless lock.closed?
        rescue IOError, SystemCallError => error
          raise Error, "unable to close systemd inhibitor lock: #{error.message}"
        end

        # ReloadLogindConf: SIGHUP to systemd-logind.
        def reload_logind_conf
          @connection.call(destination: "org.freedesktop.systemd1", path: "/org/freedesktop/systemd1",
                           interface: "org.freedesktop.systemd1.Manager", member: "KillUnit", signature: "ssi",
                           args: ["systemd-logind.service", "all", 1])
        rescue Platform::Linux::DBus::RemoteError => error
          raise Error, "unable to reload logind conf: #{error.message}"
        end

        MATCH_RULE = "type='signal',interface='#{INTERFACE}',member='PrepareForShutdown',path='#{OBJECT}'".freeze

        # MonitorShutdown's AddMatch, once per connection.
        def subscribe_shutdown
          return if @subscribed

          @connection.add_match(MATCH_RULE)
          @subscribed = true
        rescue Platform::Linux::DBus::RemoteError => error
          raise Error, "failed to monitor shutdown: #{error.message}"
        end

        # MonitorShutdown: yields PrepareForShutdown's boolean until the bus
        # connection ends.
        def monitor_shutdown
          subscribe_shutdown
          loop do
            signal = @connection.next_signal
            break if signal.nil?
            next unless signal.interface == INTERFACE && signal.member == "PrepareForShutdown"
            next unless [true, false].include?(signal.body.first)

            yield signal.body.first
          end
        rescue Platform::Linux::DBus::Error, IOError, SystemCallError
          nil
        end

        def self.override_content(seconds) = "# Kubelet logind override\n[Login]\nInhibitDelayMaxSec=#{format("%.0f", seconds)}\n"

        def override_path = File.join(@config_directory, CONFIG_FILE)

        # OverrideInhibitDelay: the logind drop-in the kubelet writes.
        def override_inhibit_delay(seconds)
          @created_directory = !File.directory?(@config_directory)
          FileUtils.mkdir_p(@config_directory, mode: 0o755)
          File.write(override_path, self.class.override_content(seconds))
        rescue SystemCallError => error
          raise Error, "failed writing logind shutdown inhibit override file #{override_path}: #{error.message}"
        end

        # The drop-in goes only when it still says what +seconds+ wrote (an
        # operator's own 99-kubelet.conf stays); the directory goes with it
        # when it is left empty.  True when logind needs a reload.
        def remove_inhibit_delay_override(seconds)
          return false unless File.file?(override_path) && File.read(override_path) == self.class.override_content(seconds)

          File.delete(override_path)
          begin
            Dir.rmdir(@config_directory) if Dir.empty?(@config_directory)
          rescue SystemCallError
            nil
          end
          true
        rescue SystemCallError => error
          raise Error, "failed removing logind shutdown inhibit override file #{override_path}: #{error.message}"
        end
      end
    end
  end
end
