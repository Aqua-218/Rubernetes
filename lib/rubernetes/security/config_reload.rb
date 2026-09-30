# frozen_string_literal: true

require "digest"
require "socket"

module Rubernetes
  module Security
    # --authorization-config / --authentication-config automatic reload: the
    # file is polled (upstream: filesystem.WatchUntil, once a minute), a
    # changed file is parsed and validated, an unchanged parsed configuration
    # is a no-op, and a new one is applied.  Counted in
    # apiserver_<kind>_config_controller_automatic_reloads_total{status},
    # _automatic_reload_last_timestamp_seconds{status} and the active
    # file's hash in _last_config_info{hash}.
    class ConfigReloadController
      POLL_INTERVAL = 60.0
      METRICS = {
        "authorization" => {
          reloads: "apiserver_authorization_config_controller_automatic_reloads_total",
          timestamp: "apiserver_authorization_config_controller_automatic_reload_last_timestamp_seconds",
          info: "apiserver_authorization_config_controller_last_config_info"
        }.freeze,
        "authentication" => {
          reloads: "apiserver_authentication_config_controller_automatic_reloads_total",
          timestamp: "apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds",
          info: "apiserver_authentication_config_controller_last_config_info"
        }.freeze
      }.freeze

      def self.data_hash(bytes) = "sha256:#{Digest::SHA256.hexdigest(bytes.to_s)}"
      def self.apiserver_id_hash(id) = "sha256:#{Digest::SHA256.hexdigest(id.to_s)}"

      attr_accessor :metrics
      attr_reader :kind, :path, :last_error

      # +load+: bytes -> configuration (raises on an invalid file);
      # +apply+: configuration -> nil (raises when it cannot be installed);
      # +initial_bytes+ / +initial_config+: what the process started with.
      def initialize(kind:, path:, load:, apply:, initial_bytes:, initial_config:, apiserver_id: Socket.gethostname,
                     interval: POLL_INTERVAL, logger: nil, clock: -> { Time.now.to_f }, metrics: nil)
        @kind = kind.to_s
        @names = METRICS.fetch(@kind)
        @path = path
        @load = load
        @apply = apply
        @tracked_bytes = initial_bytes.to_s.b
        @loaded_config = initial_config
        @apiserver_id_hash = self.class.apiserver_id_hash(apiserver_id)
        @interval = Float(interval)
        @logger = logger
        @clock = clock
        @metrics = metrics
        @mutex = Mutex.new
        @thread = nil
        @stop = false
        @last_error = nil
        @info_hash = nil
      end

      # RecordAuthorizationConfigLastConfigInfo at start.
      def note_loaded
        set_info(self.class.data_hash(@tracked_bytes))
        self
      end

      # One poll.  Returns true when a new configuration was applied.
      def check!
        @mutex.synchronize do
          begin
            bytes = File.binread(@path)
          rescue SystemCallError => error
            return failure("read", error)
          end
          return false if bytes == @tracked_bytes

          configuration = begin
            @load.call(bytes)
          rescue StandardError => error
            # Structurally or semantically invalid and will stay so: stop retrying it.
            @tracked_bytes = bytes
            return failure("load", error)
          end
          if configuration == @loaded_config
            @tracked_bytes = bytes
            return false
          end
          begin
            @apply.call(configuration)
          rescue StandardError => error
            @tracked_bytes = bytes if @kind == "authorization"
            return failure("apply", error)
          end
          @tracked_bytes = bytes
          @loaded_config = configuration
          @last_error = nil
          record("success")
          set_info(self.class.data_hash(bytes))
          @logger&.info("#{@kind}.config.reloaded", hash: self.class.data_hash(bytes)) if @logger.respond_to?(:info)
          true
        end
      end

      def start
        return self if @thread&.alive?

        @stop = false
        @thread = Thread.new do
          Thread.current.name = "#{@kind}-config-reload"
          until @stop
            sleep_interruptibly(@interval)
            break if @stop

            begin
              check!
            rescue StandardError => error
              @logger&.warn("#{@kind}.config.reload_crashed", error: error.message) if @logger.respond_to?(:warn)
            end
          end
        end
        self
      end

      def stop
        @stop = true
        thread = @thread
        @thread = nil
        thread&.wakeup
        thread&.join(2)
        self
      end

      private

      def sleep_interruptibly(seconds)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
        while !@stop && (remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)).positive?
          sleep([remaining, 1.0].min)
        end
      end

      def failure(stage, error)
        @last_error = error
        record("failure")
        if @logger.respond_to?(:warn)
          @logger&.warn("#{@kind}.config.reload_failed", stage: stage, error: error.class.name,
                                                         message: error.message.to_s[0, 300])
        end
        false
      end

      def record(status)
        registry = @metrics
        return unless registry

        labels = {"apiserver_id_hash" => @apiserver_id_hash, "status" => status}
        registry.increment(@names[:reloads], labels)
        registry.set(@names[:timestamp], @clock.call, labels)
      rescue StandardError
        nil
      end

      # A "Custom" collector upstream: the current hash only.
      def set_info(hash)
        registry = @metrics
        return unless registry

        name = @names[:info]
        unless registry.registered?(name)
          registry.register(name, type: :gauge,
                                  help: "Information about the last applied #{@kind} configuration with hash as label, split by apiserver identity.")
        end
        registry.delete(name, {"apiserver_id_hash" => @apiserver_id_hash, "hash" => @info_hash}) if @info_hash && @info_hash != hash
        registry.set(name, 1, {"apiserver_id_hash" => @apiserver_id_hash, "hash" => hash})
        @info_hash = hash
      rescue StandardError
        nil
      end
    end
  end
end
