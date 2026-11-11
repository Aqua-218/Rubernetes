# frozen_string_literal: true

require "json"
require "optparse"
require "prism"
require "socket"

require_relative "../cluster"

module Rubernetes
  module Console
    # `rubectl console`, `rubectl why` and `rubectl trace`: the client side
    # of the sockets the components of a cluster on this host listen on.
    class CLI
      class Error < StandardError; end

      USAGE = <<~TEXT
        Usage: rubectl console PROCESS [-e CODE]     a Ruby prompt inside a running component
               rubectl why [NAMESPACE/]POD            how the scheduler decided about a Pod, plugin by plugin
               rubectl trace PROCESS Some::Class#method [--seconds N] [--limit N]
                                                      the calls of one method as they happen

        PROCESS is scheduler, controller-manager, apiserver-control-0, agent-worker-0, ...; a unique beginning is enough.
      TEXT

      def initialize(stdout:, stderr:, stdin:)
        @stdout = stdout
        @stderr = stderr
        @stdin = stdin
      end

      def run(command, argv)
        options = {name: "default", root: nil, code: nil, seconds: 10, limit: 200}
        arguments = parser(options).parse(argv)
        case command
        when "console" then console(options, *arguments)
        when "why" then why(options, *arguments)
        when "trace" then trace(options, *arguments)
        end
      rescue ArgumentError, OptionParser::ParseError
        @stderr.puts(USAGE)
        64
      rescue Error, SystemCallError => error
        @stderr.puts("rubectl #{command}: #{error.message}")
        1
      end

      private

      def parser(options)
        OptionParser.new do |parser|
          parser.on("--name NAME") { |value| options[:name] = value }
          parser.on("--root DIR") { |value| options[:root] = value }
          parser.on("-e CODE") { |value| options[:code] = value }
          parser.on("--seconds N", Float) { |value| options[:seconds] = value }
          parser.on("--limit N", Integer) { |value| options[:limit] = value }
        end
      end

      def console(options, process)
        connect(options, process) do |socket, name|
          hello = request(socket, "op" => "hello")
          next evaluate(socket, options[:code]) ? 0 : 1 if options[:code]

          @stdout.puts("#{hello["process"]} (pid #{hello["pid"]}, Ruby #{hello["ruby"]}) -- `help` lists what is in reach, `exit` leaves")
          interact(socket, name)
          0
        end
      end

      def why(options, pod)
        connect(options, "scheduler") { |socket, _name| evaluate(socket, "why(#{pod.inspect})", result: false) ? 0 : 1 }
      end

      def trace(options, process, target)
        connect(options, process) do |socket, _name|
          socket.puts(JSON.generate("op" => "trace", "target" => target, "seconds" => options[:seconds], "limit" => options[:limit]))
          while (answer = JSON.parse(socket.gets || raise(Error, "the component closed the connection")))
            break answer["error"] ? fail_with(answer["error"]) : finished(answer) unless answer.key?("call")

            call = answer["call"]
            arguments = call["arguments"].map { |name, value| "#{name}=#{value}" }.join(" ")
            @stdout.puts(format("%<at>s  %8.3<ms>f ms  %<arguments>s  => %<result>s",
                                at: call["at"], ms: call["milliseconds"], arguments: arguments, result: call["result"]))
          end
        end
      end

      def finished(answer)
        @stdout.puts("#{answer["calls"]} calls")
        0
      end

      def fail_with(message)
        @stderr.puts("rubectl: #{message}")
        1
      end

      # Yields the socket of the one process `wanted` names.
      def connect(options, wanted)
        root = options[:root] || File.join(Cluster::DEFAULT_STATE_DIR, options[:name])
        sockets = Dir[File.join(root, "run", "*.sock")].to_h { |path| [File.basename(path, ".sock"), path] }
        raise Error, "no component of a cluster at #{root} has a console socket" if sockets.empty?

        names = sockets.key?(wanted) ? [wanted] : sockets.keys.select { |name| name.start_with?(wanted) }
        unless names.length == 1
          matched = names.empty? ? "no process" : names.sort.join(", ")
          raise Error, "#{wanted.inspect} names #{matched}; there are #{sockets.keys.sort.join(", ")}"
        end

        UNIXSocket.open(sockets.fetch(names.first)) { |socket| yield(socket, names.first) }
      end

      def request(socket, document)
        socket.puts(JSON.generate(document))
        JSON.parse(socket.gets || raise(Error, "the component closed the connection"))
      end

      # Prints what the code printed and what it evaluated to; false when it raised.
      def evaluate(socket, code, result: true)
        answer = request(socket, "op" => "eval", "code" => code)
        @stdout.print(answer["output"])
        if answer["error"]
          @stdout.puts(answer["error"])
          false
        else
          @stdout.puts("=> #{answer["result"]}") if result
          true
        end
      end

      def interact(socket, name)
        buffer = +""
        while (line = read_line(buffer.empty? ? "#{name}> " : "#{name}* "))
          break if buffer.empty? && %w[exit quit].include?(line.strip)

          buffer << line << "\n"
          next if unfinished?(buffer)

          evaluate(socket, buffer) unless buffer.strip.empty?
          buffer = +""
        end
      end

      # A `do` without its `end` yet, an open bracket, an open string: the
      # parser says it ran out of input ("close context"), or names the
      # terminator it is still waiting for.  Any other complaint is a mistake
      # to report at once.
      def unfinished?(code)
        Prism.parse(code).errors.any? do |error|
          error.type == :unexpected_token_close_context || error.type.to_s.match?(/_term(?:_|\z)|_eof\z/)
        end
      end

      def read_line(prompt)
        return @stdin.gets&.chomp unless @stdin.tty?

        require "reline"
        Reline.readline(prompt, true)
      rescue LoadError
        @stdout.print(prompt)
        @stdin.gets&.chomp
      end
    end
  end
end
