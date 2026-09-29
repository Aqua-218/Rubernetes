# frozen_string_literal: true

require "json"
require "rbconfig"

module Rubernetes
  module Runtime
    module CRI
      # A client of a CRI runtime (containerd, CRI-O) over its Unix socket:
      # runtime.v1 RuntimeService and ImageService.  gRPC never loads into
      # the agent (its threads and forks are not safe with it), so the calls
      # go to one long-lived helper interpreter that holds the channel; the
      # two exchange one JSON line per request and response (protobuf JSON,
      # proto field names, defaults included), requests in flight at once.
      # A helper that died is started again by the next call.
      class Client
        class Error < StandardError
          attr_reader :code

          def initialize(message, code: nil)
            super(message)
            @code = code
          end
        end

        # gRPC status codes a caller tests for.
        NOT_FOUND = 5
        UNIMPLEMENTED = 12

        SERVICES = %w[RuntimeService ImageService].freeze

        HELPER = <<~'RUBY'
          require "json"
          require "grpc"
          $LOAD_PATH.unshift(ARGV.fetch(1))
          require "rubernetes/runtime/cri/generated/cri_runtime_v1_services_pb"
          generated = Rubernetes::Runtime::CRI::Generated::RuntimeV1
          endpoint = ARGV.fetch(0)
          services = {"RuntimeService" => generated::RuntimeService, "ImageService" => generated::ImageService}
          stubs = services.transform_values { |service| service::Stub.new("unix:#{endpoint}", :this_channel_is_insecure) }
          output = Mutex.new
          $stdout.sync = true
          respond = lambda do |payload|
            line = JSON.generate(payload)
            output.synchronize { $stdout.write(line + "\n") }
          end
          while (line = $stdin.gets)
            request = JSON.parse(line)
            Thread.new(request) do |call|
              begin
                stub = stubs.fetch(call.fetch("service"))
                name = call.fetch("method")
                description = services.fetch(call.fetch("service"))::Service.rpc_descs.fetch(name.to_sym)
                message = description.input.decode_json(JSON.generate(call.fetch("request", {})), ignore_unknown_fields: true)
                method = name.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase
                reply = stub.public_send(method, message, deadline: Time.now + Float(call.fetch("timeout", 30)))
                respond.call("id" => call["id"],
                             "ok" => JSON.parse(reply.to_json(preserve_proto_fieldnames: true, emit_defaults: true)))
              rescue GRPC::BadStatus => error
                respond.call("id" => call["id"], "error" => error.details.to_s, "code" => error.code)
              rescue StandardError, ScriptError => error
                respond.call("id" => call["id"], "error" => "#{error.class}: #{error.message}")
              end
            end
          end
        RUBY

        def initialize(endpoint:, timeout: 30.0, ruby: RbConfig.ruby, lib: File.expand_path("../../..", __dir__))
          @endpoint = endpoint.to_s.delete_prefix("unix://")
          @timeout = Float(timeout)
          @ruby = ruby
          @lib = lib
          @mutex = Mutex.new
          @pending = {}
          @next_id = 0
          @helper = nil
        end

        attr_reader :endpoint

        # The response Hash, or raises Error (with the gRPC status code when
        # the runtime answered).
        def call(service, method, request = {}, timeout: @timeout)
          raise ArgumentError, "unknown CRI service #{service}" unless SERVICES.include?(service.to_s)

          queue = Queue.new
          id = @mutex.synchronize do
            start_helper_locked
            @next_id += 1
            @pending[@next_id] = queue
            begin
              @helper[:input].write(JSON.generate("id" => @next_id, "service" => service.to_s, "method" => method.to_s,
                                                  "request" => request, "timeout" => timeout) + "\n")
            rescue IOError, SystemCallError => error
              @pending.delete(@next_id)
              stop_helper_locked
              raise Error, "CRI helper is gone: #{error.message}"
            end
            @next_id
          end
          outcome = wait(queue, Float(timeout) + 5.0)
          raise Error, "CRI #{service}/#{method} did not answer in #{timeout}s" if outcome.nil?
          raise Error.new(outcome["error"].to_s, code: outcome["code"]) if outcome.key?("error")

          outcome["ok"]
        ensure
          @mutex.synchronize { @pending.delete(id) } if id
        end

        def runtime(method, request = {}, **options) = call("RuntimeService", method, request, **options)
        def image(method, request = {}, **options) = call("ImageService", method, request, **options)

        def close
          @mutex.synchronize { stop_helper_locked }
        end

        private

        def wait(queue, seconds)
          queue.pop(timeout: seconds)
        end

        def start_helper_locked
          return if @helper && @helper[:thread].alive?

          stop_helper_locked
          input_reader, input_writer = IO.pipe
          output_reader, output_writer = IO.pipe
          pid = Process.spawn(@ruby, "-e", HELPER, @endpoint, @lib, in: input_reader, out: output_writer,
                                                                    err: File::NULL, close_others: true, pgroup: true)
          input_reader.close
          output_writer.close
          input_writer.sync = true
          thread = Thread.new { read_responses(output_reader) }
          thread.name = "cri-client"
          @helper = {pid: pid, input: input_writer, output: output_reader, thread: thread}
        end

        def read_responses(reader)
          while (line = reader.gets)
            outcome = JSON.parse(line)
            queue = @mutex.synchronize { @pending[outcome["id"]] }
            queue&.push(outcome)
          end
        rescue IOError, JSON::ParserError
          nil
        ensure
          # Every call still waiting learns that its helper is gone.
          @mutex.synchronize { @pending.each_value { |queue| queue.push("error" => "CRI helper exited") } }
        end

        def stop_helper_locked
          helper = @helper
          @helper = nil
          return if helper.nil?

          helper[:input].close unless helper[:input].closed?
          begin
            Process.kill(:TERM, -helper[:pid])
          rescue Errno::ESRCH, Errno::EPERM
            nil
          end
          Thread.new(helper[:pid]) do |pid|
            Process.wait(pid)
          rescue Errno::ECHILD
            nil
          end
        end
      end
    end
  end
end
