# frozen_string_literal: true

require "socket"
require_relative "interface"

module Rubernetes
  module Network
    # Runs a node's Network::Interface in a process of its own.
    #
    # The node agent is one Ruby process, so everything it does -- volume
    # mounts, container starts, status updates and Pod network attach --
    # shares one interpreter lock and therefore one core.  Attaching a Pod's
    # network (IPAM, veth and bridge effects with their readbacks, the durable
    # operation record) was a quarter of that core while thirty Pods started
    # together.  Forked right after the interface is built, the worker owns
    # the interface and its state files from then on; the agent keeps a
    # RemoteInterface with the same public methods.  Calls are independent
    # requests, so each runs in its own worker thread and concurrent Pod
    # attaches still proceed in parallel.
    #
    # Requests and replies are length-prefixed Marshal frames over a UNIX
    # socket pair.  An exception raised in the worker is re-raised in the
    # agent; one that cannot be marshalled arrives as a RuntimeError with the
    # original class name and message.
    module Worker
      class Error < StandardError; end

      FRAME = "N"

      module_function

      def fork_for(interface, logger: nil)
        agent_side, worker_side = UNIXSocket.pair(:STREAM)
        pid = Process.fork do
          agent_side.close
          reset_signals
          $0 = "rubernetes-network-worker"
          serve(interface, worker_side)
          Process.exit!(0)
        end
        worker_side.close
        logger&.info("network.worker_started", pid: pid)
        RemoteInterface.new(agent_side, pid: pid, policy_engine: interface.policy_engine)
      end

      # The worker is a fork of the agent and inherited its signal handlers;
      # it must never run the agent's shutdown path.  It ends when the agent's
      # end of the socket closes.
      def reset_signals
        %w[TERM INT HUP QUIT USR1 USR2].each do |name|
          Signal.trap(name, "DEFAULT")
        rescue ArgumentError
          nil
        end
      end

      def serve(interface, socket)
        write_mutex = Mutex.new
        while (request = read_frame(socket))
          id, name, args, kwargs = request
          Thread.new do
            opened = []
            reply = begin
              args = args.map { |argument| localize_namespace(argument, opened) }
              [id, :ok, interface.public_send(name, *args, **kwargs)]
            rescue Exception => error # rubocop:disable Lint/RescueException -- every failure goes back to the caller
              [id, :error, error]
            ensure
              opened.each { |fd| IO.for_fd(fd).close rescue nil } # rubocop:disable Style/RescueModifier
            end
            write_mutex.synchronize { write_frame(socket, reply) }
          end
        end
      end

      # A sandbox's network namespace descriptor names its holder by a pidfd
      # -- a descriptor number of the agent's, meaningless here.  The worker
      # opens its own pidfd for the same holder PID; NamespaceLease still
      # proves it is the same process (start time, then the namespace inode).
      def localize_namespace(argument, opened)
        return argument unless argument.is_a?(Hash)

        key = %w[netns network_namespace].find { |name| argument[name].is_a?(Hash) }
        return argument unless key

        context = argument[key]
        return argument unless context["pid"] && context.key?("pidfd")

        fd = pidfd.open(pid: Integer(context["pid"]), resource_id: "network-worker:#{context["pid"]}")
        opened << fd
        argument.merge(key => context.merge("pidfd" => fd))
      end

      def pidfd
        @pidfd ||= begin
          require_relative "../platform/linux/pidfd"
          Platform::Linux::Pidfd.new
        end
      end

      def write_frame(socket, value)
        body = begin
          Marshal.dump(value)
        rescue TypeError => error
          id, status, payload = value
          substitute = if status == :error
                         RuntimeError.new("#{payload.class}: #{payload.message}")
                       else
                         RuntimeError.new("network worker result is not transferable: #{error.message}")
                       end
          Marshal.dump([id, :error, substitute])
        end
        socket.write([body.bytesize].pack(FRAME) + body)
      end

      def read_frame(socket)
        header = socket.read(4)
        return nil if header.nil? || header.bytesize < 4

        body = socket.read(header.unpack1(FRAME))
        return nil if body.nil?

        Marshal.load(body) # rubocop:disable Security/MarshalLoad -- both ends are this process tree
      end
    end

    # The agent's side of a Worker: Interface's public methods, answered by
    # the worker process.  Only the policy engine stays in the agent -- the
    # lifecycle adapter programs policy itself.
    class RemoteInterface < Interface
      FORWARDED = %i[node_gateways ensure_node_bridge ensure_host_forwarding! add add_transaction delete
                     delete_transaction check recover shutdown operation operations state].freeze

      attr_reader :policy_engine, :pid

      # rubocop:disable-next Lint/MissingSuper -- the interface lives in the worker
      def initialize(socket, pid:, policy_engine: nil)
        @socket = socket
        @pid = pid
        @policy_engine = policy_engine
        @write_mutex = Mutex.new
        @pending = {}
        @pending_mutex = Mutex.new
        @sequence = 0
        @reader = Thread.new { read_replies }
        @reader.name = "network-worker-client"
      end

      FORWARDED.each do |name|
        define_method(name) do |*args, **kwargs|
          call(name, args, kwargs)
        end
      end

      %i[ipam topology ledger sysctl_manager].each do |name|
        define_method(name) { raise Worker::Error, "#{name} lives in the network worker process" }
      end

      def alive?
        @reader.alive?
      end

      private

      def call(name, args, kwargs)
        raise Worker::Error, "network worker exited" unless @reader.alive?

        reply = Queue.new
        id = @pending_mutex.synchronize do
          @sequence += 1
          @pending[@sequence] = reply
          @sequence
        end
        begin
          @write_mutex.synchronize { Worker.write_frame(@socket, [id, name, args, kwargs]) }
        rescue IOError, SystemCallError => error
          @pending_mutex.synchronize { @pending.delete(id) }
          raise Worker::Error, "network worker is gone: #{error.message}"
        end
        status, value = reply.pop
        raise value if status == :error

        value
      end

      def read_replies
        while (frame = Worker.read_frame(@socket))
          id, status, value = frame
          waiter = @pending_mutex.synchronize { @pending.delete(id) }
          waiter&.push([status, value])
        end
      rescue IOError, SystemCallError
        nil
      ensure
        failure = Worker::Error.new("network worker exited")
        waiters = @pending_mutex.synchronize do
          taken = @pending.values
          @pending.clear
          taken
        end
        waiters.each { |waiter| waiter.push([:error, failure]) }
      end
    end
  end
end
