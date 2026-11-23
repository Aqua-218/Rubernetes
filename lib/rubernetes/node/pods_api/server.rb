# frozen_string_literal: true

require "base64"
require "json"
require_relative "../plugins/generated/pods_v1alpha1_services_pb"

module Rubernetes
  module Node
    module PodsAPIServer
      Proto = Plugins::Generated::PodsV1alpha1

      class Service < Proto::Pods::Service
        def initialize
          super
          @pods = {}
          @watchers = []
          @mutex = Mutex.new
          @tokens = 10.0
          @refill_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        def list_pods(_request, _call)
          pods = @mutex.synchronize do
            throttle!
            ordered_pods
          end
          Proto::ListPodsResponse.new(pods: pods)
        end

        def get_pod(request, _call)
          uid = request.podUID
          pod = @mutex.synchronize do
            throttle!
            @pods[uid]
          end
          raise GRPC::NotFound, "pod with UID #{uid} not found" unless pod

          Proto::GetPodResponse.new(pod: pod)
        end

        def watch_pods(_request, call)
          Enumerator.new do |response|
            queue = SizedQueue.new(100)
            initial = @mutex.synchronize do
              @watchers << queue
              ordered_pods
            end
            begin
              initial.each { |pod| response << Proto::WatchPodsEvent.new(type: :ADDED, pod: pod) }
              response << Proto::WatchPodsEvent.new(type: :INITIAL_SYNC_COMPLETE)
              until call.cancelled?
                event = queue.pop(timeout: 0.2)
                response << event if event
                raise GRPC::ResourceExhausted, "watch client channel closed" if queue.closed? && queue.empty?
              end
            ensure
              @mutex.synchronize { @watchers.delete(queue) }
            end
          end
        end

        def apply(changes)
          @mutex.synchronize do
            changes.each do |type, uid, data|
              pod = Base64.strict_decode64(data)
              type == "DELETED" ? @pods.delete(uid) : @pods[uid] = pod
              event = Proto::WatchPodsEvent.new(type: type.to_sym, pod: pod)
              @watchers.delete_if do |queue|
                queue.push(event, true)
                false
              rescue ThreadError
                queue.close
                true
              end
            end
          end
        end

        def close
          @mutex.synchronize { @watchers.each(&:close) }
        end

        private

        def ordered_pods = @pods.sort_by(&:first).map(&:last)

        # The upstream local endpoint limits unary requests to 100 per
        # second, with a burst of ten. Watch streams are independent.
        def throttle!
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          @tokens = [10.0, @tokens + (100 * (now - @refill_at))].min
          @refill_at = now
          raise GRPC::ResourceExhausted, "rejected by rate limit" if @tokens < 1

          @tokens -= 1
        end
      end

      def self.run(socket)
        service = Service.new
        service.apply(JSON.parse($stdin.readline))
        File.umask(0o077)
        File.open("#{socket}.lock", File::WRONLY | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
          raise IOError, "Pods API is already serving at #{socket}" unless lock.flock(File::LOCK_EX | File::LOCK_NB)

          File.unlink(socket) if File.socket?(socket)
          server = GRPC::RpcServer.new
          server.add_http2_port("unix:#{socket}", :this_port_is_insecure)
          File.chmod(0o600, socket)
          server.handle(service)
          listener = Thread.new { server.run }
          raise IOError, "Pods API could not listen on #{socket}" unless server.wait_till_running(5)

          $stdout.puts("ready")
          $stdout.flush
          $stdin.each_line { |line| service.apply(JSON.parse(line)) }
        ensure
          if server
            service.close
            server.stop
            listener&.join
            File.unlink(socket) if File.socket?(socket)
          end
        end
      end
    end
  end
end

Rubernetes::Node::PodsAPIServer.run(ARGV.fetch(0)) if $PROGRAM_NAME == __FILE__
