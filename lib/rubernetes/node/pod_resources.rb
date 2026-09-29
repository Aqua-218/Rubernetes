# frozen_string_literal: true

require "fileutils"
require "json"
require "rbconfig"
require "timeout"

module Rubernetes
  module Node
    # kubelet's pod resources API (pkg/kubelet/apis/podresources, v1
    # PodResourcesLister on <directory>/kubelet.sock): monitoring and device
    # agents ask which devices, exclusive CPUs, NUMA-pinned memory and DRA
    # claims each running container holds (List / Get) and what the node can
    # hand out (GetAllocatableResources).  gRPC runs in a helper interpreter;
    # each call it receives comes back to the agent as one JSON line and is
    # answered from the agent's own state.
    class PodResources
      HELPER = <<~'RUBY'
        require "json"
        require "grpc"
        $LOAD_PATH.unshift(ARGV.fetch(1))
        require "rubernetes/node/plugins/generated/podresources_v1_services_pb"
        api = Rubernetes::Node::Plugins::Generated::PodResourcesV1
        socket = File.join(ARGV.fetch(0), "kubelet.sock")
        output = Mutex.new
        pending = {}
        lock = Mutex.new
        next_id = 0
        $stdout.sync = true
        ask = lambda do |method, request|
          queue = Queue.new
          id = lock.synchronize { next_id += 1; pending[next_id] = queue; next_id }
          output.synchronize { $stdout.write(JSON.generate("id" => id, "method" => method, "request" => request) + "\n") }
          reply = queue.pop
          raise GRPC::Unknown.new(reply["error"]) if reply["error"]

          reply["ok"]
        end
        decode = ->(klass, value) { klass.decode_json(JSON.generate(value), ignore_unknown_fields: true) }
        encode = ->(message) { JSON.parse(message.to_json(preserve_proto_fieldnames: true)) }
        service = Class.new(api::PodResourcesLister::Service) do
          define_method(:list) { |request, _call| decode.call(api::ListPodResourcesResponse, ask.call("List", encode.call(request))) }
          define_method(:get) { |request, _call| decode.call(api::GetPodResourcesResponse, ask.call("Get", encode.call(request))) }
          define_method(:get_allocatable_resources) do |request, _call|
            decode.call(api::AllocatableResourcesResponse, ask.call("GetAllocatableResources", encode.call(request)))
          end
        end
        File.delete(socket) if File.exist?(socket) || File.symlink?(socket)
        server = GRPC::RpcServer.new
        server.add_http2_port("unix:#{socket}", :this_port_is_insecure)
        server.handle(service.new)
        Thread.new { server.run }
        server.wait_till_running(10)
        output.synchronize { $stdout.write(JSON.generate("event" => "serving") + "\n") }
        while (line = $stdin.gets)
          reply = JSON.parse(line)
          queue = lock.synchronize { pending.delete(reply["id"]) }
          queue&.push(reply)
        end
        server.stop
        File.delete(socket) if File.exist?(socket)
      RUBY

      # +pods+: -> [Pod]; +device_plugins+, +container_manager+ and
      # +dra_manager+ answer for their resources (any may be nil).
      def initialize(directory:, pods:, device_plugins: nil, container_manager: nil, dra_manager: nil,
                     ruby: RbConfig.ruby, lib: File.expand_path("../..", __dir__))
        @directory = directory
        @pods = pods
        @device_plugins = device_plugins
        @container_manager = container_manager
        @dra_manager = dra_manager
        @ruby = ruby
        @lib = lib
        @mutex = Mutex.new
        @pid = nil
      end

      def start(wait: 15)
        ready = Queue.new
        @mutex.synchronize do
          return self if @pid

          FileUtils.mkdir_p(@directory)
          reader, child_out = IO.pipe
          child_in, @stdin = IO.pipe
          @pid = Process.spawn(@ruby, "-e", HELPER, @directory, @lib, in: child_in, out: child_out, err: File::NULL, pgroup: true)
          child_in.close
          child_out.close
          @reader = Thread.new { serve(reader, ready) }
        end
        Timeout.timeout(wait) { ready.pop }
        self
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

      # The kubelet registry for kubelet_pod_resources_endpoint_*.
      attr_writer :metrics

      # podresources v1 List.
      def list
        count("kubelet_pod_resources_endpoint_requests_total", "kubelet_pod_resources_endpoint_requests_list")
        {"pod_resources" => Array(@pods.call).filter_map { |pod| pod_resources(pod) }}
      end

      # v1 Get: one Pod, or upstream's error.
      def get(name, namespace)
        count("kubelet_pod_resources_endpoint_requests_total", "kubelet_pod_resources_endpoint_requests_get")
        pod = Array(@pods.call).find { |entry| entry.dig("metadata", "name") == name && entry.dig("metadata", "namespace") == namespace }
        if pod.nil?
          count("kubelet_pod_resources_endpoint_errors_get")
          raise ArgumentError, "pod #{name} in namespace #{namespace} not found"
        end

        {"pod_resources" => pod_resources(pod)}
      end

      # v1 GetAllocatableResources: every device plugin device, the CPUs and
      # memory the managers can assign exclusively.
      def allocatable
        count("kubelet_pod_resources_endpoint_requests_total", "kubelet_pod_resources_endpoint_requests_get_allocatable")
        result = {"devices" => [], "cpu_ids" => [], "memory" => []}
        if @device_plugins.respond_to?(:allocatable_devices)
          result["devices"] = @device_plugins.allocatable_devices.map do |resource, ids|
            {"resource_name" => resource, "device_ids" => ids}
          end
        end
        cpu = @container_manager.respond_to?(:cpu_manager) ? @container_manager.cpu_manager : nil
        result["cpu_ids"] = cpu.allocatable_cpus.each.to_a if cpu.respond_to?(:allocatable_cpus)
        memory = @container_manager.respond_to?(:memory_manager) ? @container_manager.memory_manager : nil
        if memory.respond_to?(:allocatable_memory)
          result["memory"] = Array(memory.allocatable_memory).map do |block|
            block = block.respond_to?(:to_h) ? block.to_h : block
            {"memory_type" => block["type"], "size" => block["size"],
             "topology" => {"nodes" => Array(block["numaAffinity"]).map { |id| {"ID" => id} }}}
          end
        end
        result
      end

      private

      def count(*names)
        names.each { |name| @metrics&.increment(name, {"server_api_version" => "v1"}) }
      rescue StandardError
        nil
      end

      def serve(reader, ready)
        while (line = reader.gets)
          message = JSON.parse(line)
          if message["event"] == "serving"
            ready.push(true)
            next
          end
          reply = begin
            ok = case message["method"]
                 when "List" then list
                 when "Get" then get(message.dig("request", "pod_name").to_s, message.dig("request", "pod_namespace").to_s)
                 when "GetAllocatableResources" then allocatable
                 else raise ArgumentError, "unknown method #{message["method"]}"
                 end
            {"id" => message["id"], "ok" => ok}
          rescue StandardError => error
            {"id" => message["id"], "error" => error.message}
          end
          @mutex.synchronize { @stdin.write(JSON.generate(reply) + "\n") if @pid }
        end
      rescue IOError, JSON::ParserError
        nil
      end

      def pod_resources(pod)
        uid = pod.dig("metadata", "uid").to_s
        containers = (Array(pod.dig("spec", "initContainers")).select { |c| c["restartPolicy"] == "Always" } +
                      Array(pod.dig("spec", "containers"))).map do |container|
          container_resources(pod, uid, container)
        end
        {"name" => pod.dig("metadata", "name"), "namespace" => pod.dig("metadata", "namespace"), "containers" => containers}
      end

      def container_resources(pod, uid, container)
        name = container["name"].to_s
        result = {"name" => name, "devices" => [], "cpu_ids" => [], "memory" => [], "dynamic_resources" => []}
        if @device_plugins.respond_to?(:container_devices)
          result["devices"] = @device_plugins.container_devices(uid, name).map do |resource, ids|
            {"resource_name" => resource, "device_ids" => ids}
          end
        end
        cpu = @container_manager.respond_to?(:cpu_manager) ? @container_manager.cpu_manager : nil
        if cpu.respond_to?(:state) && cpu.state.respond_to?(:cpu_set)
          set = cpu.state.cpu_set(uid, name)
          result["cpu_ids"] = set.each.to_a if set && !set.empty?
        end
        memory = @container_manager.respond_to?(:memory_manager) ? @container_manager.memory_manager : nil
        if memory.respond_to?(:memory)
          result["memory"] = Array(memory.memory(uid, name)).map do |block|
            {"memory_type" => block.type, "size" => block.size, "topology" => {"nodes" => Array(block.numa_affinity).map { |id| {"ID" => id} }}}
          end
        end
        if @dra_manager.respond_to?(:container_claims)
          result["dynamic_resources"] = Array(@dra_manager.container_claims(pod, container))
        end
        result
      end
    end
  end
end
