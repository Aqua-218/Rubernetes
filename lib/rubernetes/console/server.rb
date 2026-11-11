# frozen_string_literal: true

require "fileutils"
require "json"
require "socket"
require "stringio"
require "timeout"

require_relative "context"
require_relative "tracer"

module Rubernetes
  module Console
    # A Ruby prompt inside a running component, behind a Unix socket.
    #
    # Whoever can connect can read and change everything the process holds,
    # so the socket is created for its owner alone and a peer is let in only
    # when it is root or the user the component runs as -- the users who
    # could attach a debugger to it anyway.  A component listens only when
    # its configuration names a socket.
    class Server
      # sun_path is 108 bytes; a path the kernel would cut is refused.
      MAX_PATH = 100
      EVALUATION_SECONDS = 30
      TRACE_SECONDS = 600
      TRACE_CALLS = 10_000

      def initialize(path:, process_name:, service:, logger: nil)
        @path = path
        @process_name = process_name
        @service = service
        @logger = logger
      end

      def start
        raise ArgumentError, "console socket path is longer than #{MAX_PATH} bytes: #{@path}" if @path.bytesize > MAX_PATH

        FileUtils.mkdir_p(File.dirname(@path), mode: 0o700)
        FileUtils.rm_f(@path)
        @socket = UNIXServer.new(@path)
        File.chmod(0o600, @path)
        @thread = Thread.new { accept_connections }
        @thread.name = "console"
        self
      end

      def stop
        @thread&.kill
        @socket&.close
        FileUtils.rm_f(@path)
        self
      end

      private

      def accept_connections
        loop do
          connection = @socket.accept
          Thread.new { serve(connection) }.name = "console-session"
        end
      rescue IOError
        nil
      end

      def serve(connection)
        user, = connection.getpeereid
        unless [0, Process.euid].include?(user)
          @logger&.warn("console.refused", uid: user)
          return
        end

        @logger&.info("console.opened", uid: user)
        session(connection)
      rescue SystemCallError, IOError
        nil
      ensure
        connection.close
      end

      # One line of JSON per request; one or, for a trace, several per answer.
      def session(connection)
        out = StringIO.new
        context = CONTEXTS.fetch(@process_name, Context).new(@service, out)
        scope = context.session_binding
        line = 0
        while (request = connection.gets)
          request = JSON.parse(request)
          case request["op"]
          when "hello" then reply(connection, "process" => @process_name, "pid" => Process.pid, "ruby" => RUBY_VERSION)
          when "eval" then reply(connection, evaluate(scope, out, request.fetch("code"), line += 1))
          when "trace" then trace(connection, request)
          else reply(connection, "error" => "unknown request #{request["op"].inspect}")
          end
        end
      end

      def reply(connection, document)
        connection.puts(JSON.generate(document))
      end

      def evaluate(scope, out, code, line)
        value = Timeout.timeout(EVALUATION_SECONDS) { scope.eval(code, "(console)", line) }
        {"result" => Inspector.render(value), "output" => take(out)}
      rescue Exception => error # rubocop:disable Lint/RescueException -- a SyntaxError or SystemExit typed at the prompt is the prompt's to report
        {"error" => "#{error.class}: #{error.message}", "output" => take(out)}
      end

      def take(out)
        text = out.string.dup
        out.truncate(0)
        out.rewind
        text
      end

      def trace(connection, request)
        seconds = request.fetch("seconds", 10).to_f.clamp(0.1, TRACE_SECONDS)
        limit = request.fetch("limit", 200).to_i.clamp(1, TRACE_CALLS)
        calls = Tracer.watch(request.fetch("target"), seconds: seconds, limit: limit) { |call| reply(connection, "call" => call) }
        reply(connection, "done" => true, "calls" => calls)
      rescue Tracer::Error => error
        reply(connection, "error" => error.message)
      end
    end
  end
end
