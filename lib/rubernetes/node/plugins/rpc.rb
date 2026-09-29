# frozen_string_literal: true

require "json"
require "timeout"
require "rbconfig"

module Rubernetes
  module Node
    module Plugins
      # gRPC calls to kubelet plugins -- plugin registration and DRA drivers
      # -- over their Unix sockets.  Each call runs in a short-lived forked
      # helper that loads the grpc gem and the generated stubs: grpc is never
      # loaded into the agent itself, whose threads and constant forking it
      # is not safe with (the gRPC health probe does the same).  Requests and
      # responses cross the pipe as protobuf JSON with the proto field names.
      module RPC
        # service name => [generated file, stub constant path]
        SERVICES = {
          "pluginregistration.Registration" => %w[pluginregistration_v1_services_pb PluginRegistrationV1::Registration],
          "k8s.io.kubelet.pkg.apis.dra.v1.DRAPlugin" => %w[dra_v1_services_pb DRAV1::DRAPlugin],
          "k8s.io.kubelet.pkg.apis.dra.v1beta1.DRAPlugin" => %w[dra_v1beta1_services_pb DRAV1beta1::DRAPlugin]
        }.freeze
        GENERATED = File.expand_path("generated", __dir__)

        class Error < StandardError
          attr_reader :code

          def initialize(message, code: nil)
            super(message)
            @code = code
          end
        end

        module_function

        # The response as a Hash (proto field names, defaults included), or
        # raises Error (with the gRPC status code when the plugin answered).
        def call(socket:, service:, method:, request: {}, timeout: 10.0)
          file, stub_path = SERVICES.fetch(service) { raise Error, "unknown plugin service #{service}" }
          reader, writer = IO.pipe
          pid = if defined?(::GRPC::Core)
                  # grpc already lives in this process (not the agent: a
                  # tool or test that loaded it) and refuses to run in a fork
                  # of it -- run the helper in a fresh interpreter instead.
                  spawn_helper(writer, file, stub_path, socket, method, request, timeout)
                else
                  Process.fork do
                    GC.disable
                    reader.close
                    writer.write(JSON.generate(outcome_of(file, stub_path, socket, method, request, timeout)))
                    writer.close
                    exit!(0)
                  end
                end
          writer.close
          payload = read_with_deadline(reader, pid, Float(timeout) + 5.0)
          outcome = JSON.parse(payload.to_s.empty? ? "{}" : payload)
          raise Error.new(outcome["error"].to_s, code: outcome["code"]) if outcome.key?("error")
          raise Error, "plugin call #{service}/#{method} returned nothing" unless outcome.key?("ok")

          outcome["ok"]
        ensure
          reader&.close unless reader.nil? || reader.closed?
        end

        def outcome_of(file, stub_path, socket, method, request, timeout)
          {"ok" => perform(file, stub_path, socket, method, request, Float(timeout))}
        rescue StandardError, LoadError => error
          code = error.respond_to?(:code) ? error.code : nil
          details = error.respond_to?(:details) ? error.details : error.message
          {"error" => "#{error.class.name.split("::").last}: #{details}", "code" => code}
        end

        HELPER = <<~'RUBY'
          require "json"
          require "rubernetes/node/plugins/rpc"
          args = JSON.parse($stdin.read)
          outcome = Rubernetes::Node::Plugins::RPC.outcome_of(*args.values_at("file", "stub", "socket", "method", "request", "timeout"))
          $stdout.write(JSON.generate(outcome))
        RUBY

        def spawn_helper(writer, file, stub_path, socket, method, request, timeout)
          lib = File.expand_path("../../..", __dir__)
          input, feed = IO.pipe
          pid = Process.spawn(RbConfig.ruby, "-I", lib, "-e", HELPER, in: input, out: writer, err: File::NULL)
          input.close
          feed.write(JSON.generate("file" => file, "stub" => stub_path, "socket" => socket, "method" => method,
                                   "request" => request, "timeout" => Float(timeout)))
          feed.close
          pid
        end

        # In the helper: dial, call, and render the response as JSON.
        def perform(file, stub_path, socket, method, request, timeout)
          require "grpc"
          require File.join(GENERATED, file)
          service = stub_path.split("::").reduce(Generated) { |scope, name| scope.const_get(name) }
          description = service::Service.rpc_descs.fetch(method.to_sym) { raise Error, "unknown method #{method}" }
          message = description.input.decode_json(JSON.generate(request), ignore_unknown_fields: true)
          stub = service::Stub.new("unix:#{socket}", :this_channel_is_insecure, timeout: timeout)
          name = method.to_s.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
          response = stub.public_send(name, message, deadline: Time.now + timeout)
          JSON.parse(response.to_json(preserve_proto_fieldnames: true, emit_defaults: true))
        end

        def read_with_deadline(reader, pid, seconds)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
          buffer = +""
          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            if remaining <= 0
              Process.kill("KILL", pid)
              Process.wait(pid)
              raise Error, "plugin call timed out after #{seconds.round(1)}s"
            end
            ready = IO.select([reader], nil, nil, remaining)
            next unless ready

            chunk = reader.read_nonblock(65_536, exception: false)
            break if chunk.nil?
            next if chunk == :wait_readable

            buffer << chunk
          end
          Process.wait(pid)
          buffer
        end
      end
    end
  end
end
