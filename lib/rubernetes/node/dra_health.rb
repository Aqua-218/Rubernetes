# frozen_string_literal: true

require "fileutils"
require "json"
require "rbconfig"
require "tempfile"
require "time"
require "thread"

module Rubernetes
  module Node
    # ResourceHealthStatus for DRA (pkg/kubelet/cm/dra healthinfo.go and the
    # DRAResourceHealth stream of dra_plugin_manager.go, v1.36.2).
    module DRAHealth
      HEALTHY = "Healthy"
      UNHEALTHY = "Unhealthy"
      UNKNOWN = "Unknown"
      DEFAULT_TIMEOUT = 30.0
      # v1.ResourceHealthMessageMaxLength.
      MESSAGE_MAX_LENGTH = 1024
      CHECKPOINT = "dra_health_state"
      NANOSECONDS = 1_000_000_000

      module_function

      # toDeviceHealthStatus.
      def status_from_wire(value)
        case value.to_s
        when "HEALTHY", "1" then HEALTHY
        when "UNHEALTHY", "2" then UNHEALTHY
        else UNKNOWN
        end
      end

      # truncateHealthMessage.
      def truncate(message)
        message = message.to_s
        message.length <= MESSAGE_MAX_LENGTH ? message : "#{message[0, MESSAGE_MAX_LENGTH - 3]}..."
      end

      # buildDeviceHealth: a negative or missing timeout is the default.
      def device_from_wire(device)
        identifier = device["device"] || {}
        timeout = Integer(device["health_check_timeout_seconds"] || 0, exception: false) || 0
        {"pool" => identifier["pool_name"].to_s, "device" => identifier["device_name"].to_s,
         "health" => status_from_wire(device["health"]), "timeout" => timeout.positive? ? Float(timeout) : DEFAULT_TIMEOUT,
         "message" => truncate(device["message"])}
      end

      # healthInfoCache: driver => "pool/device" => health, with its last
      # update and timeout, checkpointed (the kubelet's JSON layout of
      # state.DevicesHealthMap) so a restart keeps what drivers reported.
      class Cache
        def initialize(path: nil, clock: -> { Time.now.utc })
          @path = path
          @clock = clock
          @drivers = {}
          @mutex = Mutex.new
          load
        end

        # getHealthInfo: Unknown for a device never reported or not
        # refreshed within its timeout.
        def get(driver, pool, device)
          @mutex.synchronize do
            entry = @drivers.dig(driver.to_s, "#{pool}/#{device}")
            return {"health" => UNKNOWN, "message" => ""} unless entry
            return {"health" => UNKNOWN, "message" => ""} if @clock.call - entry["updated"] > entry["timeout"]

            {"health" => entry["health"], "message" => entry["message"]}
          end
        end

        # updateHealthInfo: the changed devices (health, message or timeout
        # differ, or a stale unreported device fell back to Unknown).
        def update(driver, devices)
          @mutex.synchronize do
            now = @clock.call
            current = (@drivers[driver.to_s] ||= {})
            changed = []
            reported = {}
            devices.each do |device|
              key = "#{device["pool"]}/#{device["device"]}"
              reported[key] = true
              existing = current[key]
              if existing.nil? || %w[health message timeout].any? { |field| existing[field] != device[field] }
                changed << device
              end
              current[key] = device.merge("updated" => now)
            end
            current.each do |key, existing|
              next if reported[key] || existing["health"] == UNKNOWN || now - existing["updated"] <= existing["timeout"]

              current[key] = existing.merge("health" => UNKNOWN, "message" => "", "updated" => now)
              changed << current[key]
            end
            save unless changed.empty?
            changed
          end
        end

        # clearDriver: a driver's stream ended.
        def clear(driver)
          @mutex.synchronize do
            @drivers.delete(driver.to_s)
            save
          end
        end

        private

        def load
          return unless @path && File.file?(@path)

          document = JSON.parse(File.read(@path))
          document.each do |driver, state|
            devices = (state.is_a?(Hash) ? state["Devices"] : nil) || {}
            @drivers[driver] = devices.to_h do |key, device|
              timeout = Integer(device["HealthCheckTimeout"] || 0, exception: false).to_i
              [key, {"pool" => device["PoolName"].to_s, "device" => device["DeviceName"].to_s,
                     "health" => [HEALTHY, UNHEALTHY].include?(device["Health"]) ? device["Health"] : UNKNOWN,
                     "timeout" => timeout.positive? ? timeout.to_f / NANOSECONDS : DEFAULT_TIMEOUT,
                     "message" => device["Message"].to_s, "updated" => Time.parse(device["LastUpdated"].to_s).utc}]
            end
          end
        rescue StandardError
          # loadFromCheckpoint failing leaves an empty cache.
          @drivers = {}
        end

        # saveToCheckpointInternal: temp file then rename.
        def save
          return unless @path

          document = @drivers.to_h do |driver, devices|
            [driver, {"Devices" => devices.to_h do |key, device|
              [key, {"PoolName" => device["pool"], "DeviceName" => device["device"], "Health" => device["health"],
                     "LastUpdated" => device["updated"].utc.strftime("%Y-%m-%dT%H:%M:%S.%NZ"),
                     "HealthCheckTimeout" => (device["timeout"] * NANOSECONDS).to_i, "Message" => device["message"]}]
            end}]
          end
          FileUtils.mkdir_p(File.dirname(@path))
          Tempfile.create([File.basename(@path), ".tmp"], File.dirname(@path)) do |file|
            file.write(JSON.generate(document))
            file.close
            File.rename(file.path, @path)
          end
        rescue Errno::ENOENT
          nil
        rescue SystemCallError, IOError
          nil
        end
      end

      # The NodeWatchResources stream of one plugin endpoint.  It runs in a
      # fresh interpreter (grpc never loads into the agent) that keeps the
      # stream open, retries every 5 s when it ends or fails (a driver without
      # the service answers Unimplemented), and prints one JSON line per
      # message.  The helper exits when its stdin closes, so it cannot outlive
      # the agent.
      class Stream
        RETRY_PERIOD = 5.0

        HELPER = <<~'RUBY'
          require "json"
          $stdout.sync = true
          socket, lib, period = ARGV[0], ARGV[1], Float(ARGV[2])
          $LOAD_PATH.unshift(lib)
          Thread.new { $stdin.read; exit!(0) }
          begin
            require "grpc"
            require "rubernetes/node/plugins/generated/dra_health_v1alpha1_services_pb"
          rescue LoadError => error
            puts JSON.generate("event" => "error", "error" => error.message)
            exit!(1)
          end
          health = Rubernetes::Node::Plugins::Generated::DRAHealthV1alpha1
          loop do
            begin
              stub = health::DRAResourceHealth::Stub.new("unix:#{socket}", :this_channel_is_insecure)
              puts JSON.generate("event" => "started")
              stub.node_watch_resources(health::NodeWatchResourcesRequest.new).each do |response|
                devices = JSON.parse(response.to_json(preserve_proto_fieldnames: true, emit_defaults: true))["devices"] || []
                puts JSON.generate("event" => "devices", "devices" => devices)
              end
              puts JSON.generate("event" => "ended")
            rescue GRPC::BadStatus => error
              puts JSON.generate("event" => "ended", "code" => error.code, "error" => error.details)
            rescue StandardError => error
              puts JSON.generate("event" => "ended", "error" => "#{error.class}: #{error.message}")
            end
            sleep(period)
          end
        RUBY

        def initialize(endpoint:, on_event:, ruby: RbConfig.ruby, lib: File.expand_path("../..", __dir__), retry_period: RETRY_PERIOD)
          @endpoint = endpoint.to_s
          @on_event = on_event
          @ruby = ruby
          @lib = lib
          @retry_period = Float(retry_period)
          @mutex = Mutex.new
          @pid = nil
        end

        attr_reader :endpoint

        def start
          @mutex.synchronize do
            return self if @pid

            reader, writer = IO.pipe
            child_in, @stdin = IO.pipe
            @pid = Process.spawn(@ruby, "-e", HELPER, @endpoint, @lib, @retry_period.to_s,
                                 in: child_in, out: writer, err: File::NULL, pgroup: true)
            child_in.close
            writer.close
            @thread = Thread.new { read_loop(reader) }
          end
          self
        end

        def stop
          pid, thread = @mutex.synchronize do
            value = [@pid, @thread]
            @pid = nil
            value
          end
          return self unless pid

          @stdin&.close rescue nil
          Process.kill(:TERM, pid) rescue nil
          Process.wait(pid) rescue nil
          thread&.join(5)
          self
        end

        def running? = !@mutex.synchronize { @pid }.nil?

        private

        def read_loop(reader)
          while (line = reader.gets)
            message = begin
              JSON.parse(line)
            rescue JSON::ParserError
              next
            end
            @on_event.call(message)
          end
        rescue IOError
          nil
        ensure
          reader.close unless reader.closed?
          @on_event.call({"event" => "ended"})
        end
      end
    end
  end
end
