# frozen_string_literal: true

require "json"
require "rbconfig"
require "timeout"

module Rubernetes
  module Node
    module DevicePlugins
      # The kubelet side of the device plugin gRPC API (v1beta1), run in one
      # long-lived helper interpreter so that grpc never loads into the agent
      # (as for CRI and the other kubelet plugins).  The helper serves
      # v1beta1.Registration on <directory>/kubelet.sock, checks a plugin's
      # API version and resource name the way kubelet does, asks the plugin
      # for its options, follows its ListAndWatch stream and runs the unary
      # DevicePlugin calls it is asked for.  Helper and agent exchange one JSON
      # line per message (protobuf JSON, proto field names):
      #
      #   helper -> agent  {"event":"registered","resource","endpoint","options"}
      #                    {"event":"devices","resource","devices":[...]}
      #                    {"event":"disconnected","resource","error"}
      #                    {"id":N,"ok":{...}} | {"id":N,"error":"...","code":C}
      #   agent -> helper  {"id":N,"endpoint","method","request"}
      class Broker
        class Error < StandardError
          attr_reader :code

          def initialize(message, code: nil)
            super(message)
            @code = code
          end
        end

        HELPER = <<~'RUBY'
          require "json"
          require "grpc"
          $LOAD_PATH.unshift(ARGV.fetch(1))
          require "rubernetes/node/plugins/generated/deviceplugin_v1beta1_services_pb"
          api = Rubernetes::Node::Plugins::Generated::DevicePluginV1beta1
          directory = ARGV.fetch(0)
          output = Mutex.new
          $stdout.sync = true
          emit = ->(payload) { output.synchronize { $stdout.write(JSON.generate(payload) + "\n") } }
          encode = ->(message) { JSON.parse(message.to_json(preserve_proto_fieldnames: true, emit_defaults: true)) }
          stubs = {}
          stub_lock = Mutex.new
          stub_for = lambda do |endpoint|
            stub_lock.synchronize { stubs[endpoint] ||= api::DevicePlugin::Stub.new("unix:#{File.join(directory, endpoint)}", :this_channel_is_insecure) }
          end
          qualified = /\A([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?\z/

          registration = Class.new(api::Registration::Service) do
            define_method(:register) do |request, _call|
              # DevicePluginRegistrationCount: every request, valid or not.
              emit.call("event" => "register_request", "resource" => request.resource_name)
              unless request.version == "v1beta1"
                raise GRPC::Unknown.new(%(requested API version "#{request.version}" is not supported by kubelet. Supported version is ["v1beta1"]))
              end
              name = request.resource_name
              extended = name.include?("/") && !name.start_with?("kubernetes.io/") && !name.start_with?("requests.") &&
                         "requests.#{name}".match?(qualified) && name.length <= 253
              raise GRPC::Unknown.new(%(the ResourceName "#{name}" is invalid)) unless extended

              stub = stub_for.call(request.endpoint)
              begin
                options = stub.get_device_plugin_options(api::Empty.new, deadline: Time.now + 10)
              rescue GRPC::BadStatus => error
                raise GRPC::Unknown.new("failed to get device plugin options: #{error.details}")
              end
              emit.call("event" => "registered", "resource" => name, "endpoint" => request.endpoint, "options" => encode.call(options))
              Thread.new do
                error = nil
                begin
                  stub.list_and_watch(api::Empty.new).each do |response|
                    emit.call("event" => "devices", "resource" => name, "endpoint" => request.endpoint,
                              "devices" => encode.call(response)["devices"] || [])
                  end
                rescue StandardError => failure
                  error = failure.respond_to?(:details) ? failure.details : failure.message
                end
                stub_lock.synchronize { stubs.delete(request.endpoint) }
                emit.call("event" => "disconnected", "resource" => name, "endpoint" => request.endpoint, "error" => error)
              end
              api::Empty.new
            end
          end

          socket = File.join(directory, "kubelet.sock")
          File.delete(socket) if File.exist?(socket) || File.symlink?(socket)
          server = GRPC::RpcServer.new
          server.add_http2_port("unix:#{socket}", :this_port_is_insecure)
          server.handle(registration.new)
          Thread.new { server.run }
          server.wait_till_running(10)
          emit.call("event" => "serving", "socket" => socket)

          while (line = $stdin.gets)
            call = JSON.parse(line)
            Thread.new(call) do |request|
              begin
                name = request.fetch("method")
                description = api::DevicePlugin::Service.rpc_descs.fetch(name.to_sym)
                message = description.input.decode_json(JSON.generate(request.fetch("request", {})), ignore_unknown_fields: true)
                method = name.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase
                reply = stub_for.call(request.fetch("endpoint")).public_send(method, message, deadline: Time.now + Float(request.fetch("timeout", 30)))
                emit.call("id" => request["id"], "ok" => encode.call(reply))
              rescue GRPC::BadStatus => error
                emit.call("id" => request["id"], "error" => error.details.to_s, "code" => error.code)
              rescue StandardError, ScriptError => error
                emit.call("id" => request["id"], "error" => "#{error.class}: #{error.message}")
              end
            end
          end
          server.stop
          File.delete(socket) if File.exist?(socket)
        RUBY

        def initialize(directory:, on_event:, ruby: RbConfig.ruby, lib: File.expand_path("../../..", __dir__), timeout: 30.0)
          @directory = directory
          @on_event = on_event
          @ruby = ruby
          @lib = lib
          @timeout = Float(timeout)
          @mutex = Mutex.new
          @pending = {}
          @next_id = 0
          @pid = nil
          @stdin = nil
        end

        attr_reader :directory

        # Starts the helper and waits until kubelet.sock is served.
        def start(wait: 15)
          ready = Queue.new
          @mutex.synchronize do
            return self if @pid

            reader, @child_out = IO.pipe
            child_in, @stdin = IO.pipe
            @pid = Process.spawn(@ruby, "-e", HELPER, @directory, @lib, in: child_in, out: @child_out, err: File::NULL, pgroup: true)
            child_in.close
            @child_out.close
            @reader = Thread.new { read_loop(reader, ready) }
          end
          Timeout.timeout(wait) { ready.pop }
          self
        rescue Timeout::Error
          stop
          raise Error, "device plugin registration server did not start in #{wait} s"
        end

        def stop
          pid = @mutex.synchronize do
            value = @pid
            @pid = nil
            value
          end
          return self unless pid

          @stdin&.close rescue nil
          Process.kill(:TERM, pid) rescue nil
          Process.wait(pid) rescue nil
          self
        end

        def running? = !@mutex.synchronize { @pid }.nil?

        # A unary DevicePlugin call on a registered plugin's endpoint.
        def call(endpoint, method, request = {}, timeout: @timeout)
          queue = Queue.new
          id = @mutex.synchronize do
            raise Error, "device plugin broker is not running" unless @pid

            @next_id += 1
            @pending[@next_id] = queue
            @stdin.write(JSON.generate("id" => @next_id, "endpoint" => endpoint, "method" => method, "request" => request,
                                       "timeout" => timeout) + "\n")
            @next_id
          end
          reply = Timeout.timeout(timeout + 5) { queue.pop }
          raise Error.new(reply["error"], code: reply["code"]) if reply.key?("error")

          reply["ok"]
        rescue Timeout::Error
          raise Error, "device plugin #{endpoint} #{method} timed out"
        ensure
          @mutex.synchronize { @pending.delete(id) } if id
        end

        private

        def read_loop(reader, ready)
          while (line = reader.gets)
            message = JSON.parse(line)
            if message.key?("id")
              queue = @mutex.synchronize { @pending[message["id"]] }
              queue&.push(message)
            elsif message["event"] == "serving"
              ready.push(true)
            else
              begin
                @on_event.call(message)
              rescue StandardError
                nil
              end
            end
          end
        rescue IOError, JSON::ParserError
          nil
        ensure
          @mutex.synchronize { @pending.each_value { |queue| queue.push("error" => "device plugin broker exited") } }
        end
      end
    end
  end
end
