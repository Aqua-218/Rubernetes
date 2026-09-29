# frozen_string_literal: true

require "json"
require "rbconfig"
require "tempfile"

# A fake gRPC server for tests, in a FRESH ruby process rather than a fork.
#
# grpc refuses to work in a child forked after the parent initialised it
# ("grpc cannot be used before and after forking unless
# GRPC_ENABLE_FORK_SUPPORT ..."), so a fake server forked from the test
# process fails whenever an earlier test in the same run loaded grpc
# in-process -- the suite's seed decided whether the server ever created
# its socket.  A spawned interpreter has no such history.
#
#   pid = GRPCFakeServer.spawn(socket, <<~RUBY, params: {"info" => {...}})
#     # PARAMS is the parsed params hash; SOCKET the socket path.
#     server.handle(...)
#   RUBY
#
# The body runs after `require "grpc"` with `server` (a GRPC::RpcServer
# already bound to SOCKET) and `PARAMS` defined; the server is started
# after the body and stops on SIGTERM.  The load path is the test's.
module GRPCFakeServer
  WAIT_SECONDS = 60

  def self.spawn(socket, body, params: {}, requires: [])
    script = Tempfile.new(["grpc-fake-server", ".rb"])
    script.write(<<~RUBY)
      require "json"
      require "grpc"
      #{requires.map { |path| "require #{path.to_s.dump}" }.join("\n")}
      SOCKET = #{socket.to_s.dump}
      PARAMS = JSON.parse(#{JSON.generate(params).dump})
      server = GRPC::RpcServer.new
      server.add_http2_port("unix:\#{SOCKET}", :this_port_is_insecure)
      #{body}
      server.run_till_terminated_or_interrupted(%w[TERM])
      exit!(0)
    RUBY
    script.flush
    arguments = $LOAD_PATH.select { |path| path.start_with?("/") }.uniq.flat_map { |path| ["-I", path] }
    pid = Process.spawn(RbConfig.ruby, *arguments, script.path, in: File::NULL, out: File::NULL, err: $stderr)
    # A cold `require "grpc"` alone takes seconds on a loaded host.
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + WAIT_SECONDS
    until File.socket?(socket)
      if Process.waitpid(pid, Process::WNOHANG)
        raise "test gRPC server exited before creating #{socket}"
      end
      raise "test gRPC server never created #{socket}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.05
    end
    pid
  ensure
    # The interpreter has read the script by the time the socket exists.
    script&.close
    script&.unlink if pid && File.socket?(socket.to_s)
  end

  def self.stop(pid)
    return unless pid

    Process.kill("TERM", pid) rescue nil
    Process.wait(pid) rescue nil
  end
end
