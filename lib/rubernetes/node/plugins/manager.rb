# frozen_string_literal: true

require "thread"

require_relative "rpc"

module Rubernetes
  module Node
    module Plugins
      # pkg/kubelet/pluginmanager (v1.36.2): kubelet plugin registration.
      #
      # A plugin announces itself with a Unix socket in the registry
      # directory (upstream /var/lib/kubelet/plugins_registry, walked with
      # its subdirectories; names starting with "." ignored).  Every second
      # the reconciler registers new or re-created sockets -- GetInfo, the
      # handler for the plugin's type (DRAPlugin, CSIPlugin, DevicePlugin),
      # ValidatePlugin, RegisterPlugin, NotifyRegistrationStatus -- and
      # deregisters plugins whose socket is gone.  A failed registration is
      # retried with exponential backoff (500 ms doubling to 2 min 2 s, as
      # nestedpendingoperations).  The directory is polled rather than
      # watched with inotify: the reconciler's own period bounds the delay
      # either way.
      class Manager
        RECONCILE_PERIOD = 1.0
        INITIAL_BACKOFF = 0.5
        MAX_BACKOFF = 122.0
        REGISTRATION = "pluginregistration.Registration"

        Registered = Struct.new(:socket, :identity, :handler, :name, :endpoint, keyword_init: true)

        # +handlers+: plugin type => handler responding to
        # validate_plugin(name, endpoint, versions), register_plugin(...),
        # deregister_plugin(name, endpoint).
        def initialize(directory:, handlers: {}, rpc: RPC, monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                       sleeper: ->(seconds) { sleep(seconds) }, error_handler: nil, timeout: 10.0)
          @directory = directory.to_s
          @handlers = handlers.transform_keys(&:to_s)
          @rpc = rpc
          @monotonic = monotonic
          @sleeper = sleeper
          @error_handler = error_handler
          @timeout = Float(timeout)
          @registered = {}
          @failures = {}
          @mutex = Mutex.new
          @thread = nil
          @stop = false
        end

        attr_reader :directory

        def add_handler(type, handler)
          @mutex.synchronize { @handlers[type.to_s] = handler }
        end

        def registered
          @mutex.synchronize { @registered.values.map(&:dup) }
        end

        # One reconcile pass.
        def reconcile
          desired = discover
          current = @mutex.synchronize { @registered.dup }
          current.each do |socket, plugin|
            next if desired[socket] == plugin.identity

            unregister(plugin)
          end
          now = @monotonic.call
          desired.each do |socket, identity|
            next if @mutex.synchronize { @registered[socket]&.identity == identity }

            failure = @mutex.synchronize { @failures[socket] }
            next if failure && failure[:identity] == identity && now < failure[:retry_at]

            register(socket, identity, failure)
          end
          @mutex.synchronize { @failures.delete_if { |socket, _| !desired.key?(socket) } }
        end

        def start(interval: RECONCILE_PERIOD)
          @mutex.synchronize do
            return self if @thread&.alive?

            @stop = false
            @thread = Thread.new do
              until @mutex.synchronize { @stop }
                begin
                  reconcile
                rescue StandardError => error
                  @error_handler&.call(error, :plugin_manager)
                end
                @sleeper.call(interval)
              end
            end
          end
          self
        end

        def stop
          thread = @mutex.synchronize do
            @stop = true
            @thread
          end
          thread&.join(5) unless thread == Thread.current
          self
        end

        private

        # Sockets under the registry directory => identity (device, inode,
        # change time): a re-created socket is a new registration, as the
        # watcher's fresh timestamp makes it upstream.
        def discover
          return {} unless File.directory?(@directory)

          found = {}
          walk(@directory) do |path|
            stat = File.lstat(path)
            found[path] = [stat.dev, stat.ino, stat.ctime.to_f] if stat.socket?
          rescue SystemCallError
            nil
          end
          found
        end

        def walk(directory, &block)
          Dir.each_child(directory) do |name|
            next if name.start_with?(".")

            path = File.join(directory, name)
            if File.directory?(path) && !File.symlink?(path)
              walk(path, &block)
            else
              block.call(path)
            end
          end
        rescue SystemCallError
          nil
        end

        def register(socket, identity, failure)
          info = @rpc.call(socket: socket, service: REGISTRATION, method: "GetInfo", timeout: 1.0)
          type = info["type"].to_s
          handler = @mutex.synchronize { @handlers[type] }
          unless handler
            message = "RegisterPlugin error -- no handler registered for plugin type: #{type} at socket #{socket}"
            notify(socket, false, message)
            raise RPC::Error, message
          end

          name = info["name"].to_s
          endpoint = info["endpoint"].to_s.empty? ? socket : info["endpoint"].to_s
          versions = Array(info["supported_versions"]).map(&:to_s)
          begin
            handler.validate_plugin(name, endpoint, versions)
          rescue StandardError => error
            notify(socket, false, "RegisterPlugin error -- plugin validation failed with err: #{error.message}")
            raise RPC::Error, "RegisterPlugin error -- pluginHandler.ValidatePluginFunc failed"
          end
          plugin = Registered.new(socket: socket, identity: identity, handler: handler, name: name, endpoint: endpoint)
          begin
            handler.register_plugin(name, endpoint, versions)
          rescue StandardError => error
            notify(socket, false, "RegisterPlugin error -- plugin registration failed with err: #{error.message}")
            raise RPC::Error, "RegisterPlugin error -- plugin registration failed with err: #{error.message}"
          end
          begin
            notify(socket, true, "")
          rescue StandardError
            handler.deregister_plugin(name, endpoint)
            raise
          end
          @mutex.synchronize do
            @registered[socket] = plugin
            @failures.delete(socket)
          end
        rescue StandardError => error
          backoff = failure && failure[:identity] == identity ? [failure[:backoff] * 2, MAX_BACKOFF].min : INITIAL_BACKOFF
          @mutex.synchronize { @failures[socket] = {identity: identity, backoff: backoff, retry_at: @monotonic.call + backoff} }
          @error_handler&.call(error, :plugin_registration)
        end

        def unregister(plugin)
          @mutex.synchronize { @registered.delete(plugin.socket) }
          plugin.handler.deregister_plugin(plugin.name, plugin.endpoint)
        rescue StandardError => error
          @error_handler&.call(error, :plugin_registration)
        end

        def notify(socket, registered, message)
          @rpc.call(socket: socket, service: REGISTRATION, method: "NotifyRegistrationStatus",
                    request: {"plugin_registered" => registered, "error" => message}, timeout: 1.0)
        end
      end
    end
  end
end
