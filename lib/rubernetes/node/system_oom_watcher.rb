# frozen_string_literal: true

module Rubernetes
  module Node
    # Linux sends the OOM constraint and victim as records on /dev/kmsg.
    # A memory-cgroup kill belongs to that cgroup; only system OOMs become
    # Warning events on the Node (pkg/kubelet/oom).
    class SystemOOMWatcher
      GATE = "KubeletInUserNamespace"

      def self.user_namespace?(map = "/proc/self/uid_map")
        line = File.open(map, &:gets).to_s.strip
        return true if line.empty?

        fields = line.split
        fields.size == 3 && fields.all? { |value| /\A\d+\z/.match?(value) } && fields.map(&:to_i) != [0, 0, 4_294_967_295]
      rescue Errno::ENOENT
        false
      end

      def initialize(node:, recorder:, allow_user_namespace:, error_handler: nil)
        @node = node
        @recorder = recorder
        @allow_user_namespace = allow_user_namespace
        @error_handler = error_handler
      end

      def start
        return if @thread

        begin
          stream = File.open("/dev/kmsg", File::RDONLY | File::NONBLOCK)
          stream.seek(0, IO::SEEK_END)
        rescue SystemCallError => error
          stream&.close
          raise unless @allow_user_namespace && self.class.user_namespace?

          @error_handler&.call(error, :oom_watcher_unavailable_in_user_namespace)
          return
        end
        @shutdown, @signal = IO.pipe
        @thread = Thread.new { watch(stream) }
      end

      def stop
        return unless @thread

        @signal.close
        @thread.join
        @shutdown.close
        @thread = nil
      end

      # One kernel record per read. Modern kernels identify memcg kills
      # before the victim line; a global OOM can finish on the victim line.
      def observe(message)
        if message.include?("invoked oom-killer:")
          @awaiting_victim = true
          @system_oom = true
        end
        return unless @awaiting_victim

        if (memcg = message[/\boom_memcg=([^,]+),/, 1])
          @system_oom = memcg == "/"
          if (victim = message.match(/,task=(.+?),pid=(\d+),uid=/))
            finish(victim[1], victim[2])
          end
        elsif (legacy = message.match(/Task in .* killed as a result of limit of (\S+)/))
          @system_oom = legacy[1] == "/"
        elsif (victim = message.match(/Killed process (\d+) \((.+?)\)/))
          finish(victim[2], victim[1])
        end
      end

      private

      def finish(name, pid)
        @awaiting_victim = false
        return unless @system_oom

        @recorder.record(involved_object: @node, type: "Warning", reason: "SystemOOM", namespace: "default",
                         message: "System OOM encountered, victim process: #{name}, pid: #{pid}")
      end

      def watch(stream)
        loop do
          ready, = IO.select([stream, @shutdown])
          break if ready.include?(@shutdown)

          begin
            record = stream.read_nonblock(8192, exception: false)
            break if record.nil?

            observe(record) if record.is_a?(String)
          rescue Errno::EPIPE
            # The kernel overwrote unread records. Start with the next OOM.
            @awaiting_victim = false
          end
        end
      rescue IOError, SystemCallError => error
        @error_handler&.call(error, :oom_watcher)
      ensure
        stream.close
      end
    end
  end
end
