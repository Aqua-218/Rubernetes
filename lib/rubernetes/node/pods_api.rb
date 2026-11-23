# frozen_string_literal: true

require "base64"
require "fileutils"
require "json"
require "rbconfig"
require "timeout"

require_relative "../schema/codec/kubernetes_protobuf"

module Rubernetes
  module Node
    # The kubelet's opt-in local Pods API (KEP-4188). gRPC lives in a
    # separate interpreter so the node can still fork runtime processes.
    class PodsAPI
      SOCKET = "pods-api.sock"
      LIBRARY = File.expand_path("../..", __dir__)
      SERVER = File.join(__dir__, "pods_api", "server.rb")
      TYPE = "k8s.io.api.core.v1.Pod"

      def initialize(directory:, pods:)
        @directory = directory
        @pods = pods
        @codec = Schema::Codec::KubernetesProtobuf.new
        @mutex = Mutex.new
        @current = {}
      end

      def start
        @mutex.synchronize do
          return self if @process&.alive?

          FileUtils.mkdir_p(@directory, mode: 0o700)
          @writer&.close
          input, @writer = IO.pipe
          ready, output = IO.pipe
          begin
            @process = Process.detach(Process.spawn(RbConfig.ruby, "-I", LIBRARY, SERVER, File.join(@directory, SOCKET), in: input, out: output))
            input.close
            output.close
            @current = {}
            publish_snapshot
            message = Timeout.timeout(10) { ready.gets }
            raise IOError, "Pods API failed to start" unless message == "ready\n"
          ensure
            input.close unless input.closed?
            output.close unless output.closed?
            ready.close
          end
        end
        self
      rescue StandardError
        stop
        raise
      end

      def stop
        process = @mutex.synchronize do
          @writer&.close
          @writer = nil
          @process.tap { @process = nil }
        end
        if process && !process.join(5)
          Process.kill(:TERM, process.pid)
          unless process.join(2)
            Process.kill(:KILL, process.pid)
            process.join
          end
        end
        self
      rescue Errno::ESRCH
        self
      end

      def changed
        @mutex.synchronize { publish_snapshot if @process&.alive? }
      rescue Errno::EPIPE
        # The socket's owner is already shutting down.
        nil
      end

      private

      def publish_snapshot
        current = @pods.call.to_h { |pod| [pod.dig("metadata", "uid"), pod] }
        events = current.filter_map do |uid, pod|
          previous = @current[uid]
          next if previous == pod

          [previous ? "MODIFIED" : "ADDED", uid, marshal(pod)]
        end
        (@current.keys - current.keys).each do |uid|
          metadata = @current.fetch(uid).fetch("metadata").slice("name", "namespace", "uid")
          events << ["DELETED", uid, marshal({"metadata" => metadata})]
        end
        @writer.puts(JSON.generate(events)) if !events.empty? || @current.empty?
        @current = current
      end

      def marshal(pod)
        Base64.strict_encode64(@codec.encode_message(TYPE, pod))
      end
    end
  end
end
