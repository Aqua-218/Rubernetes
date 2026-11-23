# frozen_string_literal: true

require_relative "plugins/helper_process"

require "fileutils"
require "json"
require "rbconfig"
require "timeout"

module Rubernetes
  module Node
    # kubelet's pod resources API (v1 and v1alpha1 PodResourcesLister on
    # <directory>/kubelet.sock): monitoring and device
    # agents ask which devices, exclusive CPUs, NUMA-pinned memory and DRA
    # claims each running container holds (List / Get) and what the node can
    # hand out (GetAllocatableResources).  gRPC runs in a helper interpreter;
    # each call it receives comes back to the agent as one JSON line and is
    # answered from the agent's own state.
    class PodResources
      include Plugins::HelperProcess

      HELPER = <<~'RUBY'
        require "json"
        require "grpc"
        $LOAD_PATH.unshift(ARGV.fetch(1))
        require "rubernetes/node/plugins/generated/podresources_v1_services_pb"
        require "rubernetes/node/plugins/generated/podresources_v1alpha1_services_pb"
        api = Rubernetes::Node::Plugins::Generated::PodResourcesV1
        alpha = Rubernetes::Node::Plugins::Generated::PodResourcesV1alpha1
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
        alpha_service = Class.new(alpha::PodResourcesLister::Service) do
          define_method(:list) do |_request, _call|
            decode.call(alpha::ListPodResourcesResponse, ask.call("ListAlpha", {}))
          end
        end
        File.delete(socket) if File.exist?(socket) || File.symlink?(socket)
        server = GRPC::RpcServer.new
        server.add_http2_port("unix:#{socket}", :this_port_is_insecure)
        server.handle(service.new)
        server.handle(alpha_service.new)
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
          spawn_helper(HELPER, @directory, @lib) { |reader, writer| serve(reader, ready, writer) }
        end
        Timeout.timeout(wait) { ready.pop }
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
            block = block.to_h if block.respond_to?(:to_h)
            {"memory_type" => block["type"], "size" => block["size"],
             "topology" => {"nodes" => Array(block["numaAffinity"]).map { |id| {"ID" => id} }}}
          end
        end
        result
      end

      private

      def list_alpha
        count("kubelet_pod_resources_endpoint_requests_total", version: "v1alpha1")
        {"pod_resources" => Array(@pods.call).filter_map { |pod| pod_resources(pod, devices_only: true) }}
      end

      def count(*names, version: "v1")
        names.each { |name| @metrics&.increment(name, {"server_api_version" => version}) }
      rescue StandardError
        nil
      end

      def serve(reader, ready, writer)
        while (line = reader.gets)
          message = JSON.parse(line)
          if message["event"] == "serving"
            ready.push(true)
            next
          end
          reply = begin
            ok = case message["method"]
                 when "List" then list
                 when "ListAlpha" then list_alpha
                 when "Get" then get(message.dig("request", "pod_name").to_s, message.dig("request", "pod_namespace").to_s)
                 when "GetAllocatableResources" then allocatable
                 else raise ArgumentError, "unknown method #{message["method"]}"
                 end
            {"id" => message["id"], "ok" => ok}
          rescue StandardError => error
            # kubelet_pod_resources_endpoint_errors_{list,get_allocatable}: a
            # call that failed (Get counts its own not-found).
            count("kubelet_pod_resources_endpoint_errors_list") if message["method"] == "List"
            count("kubelet_pod_resources_endpoint_errors_get_allocatable") if message["method"] == "GetAllocatableResources"
            {"id" => message["id"], "error" => error.message}
          end
          @mutex.synchronize { writer.write(JSON.generate(reply) + "\n") if @stdin.equal?(writer) }
        end
      rescue IOError, JSON::ParserError
        nil
      end

      def pod_resources(pod, devices_only: false)
        uid = pod.dig("metadata", "uid").to_s
        containers = Array(pod.dig("spec", "containers"))
        unless devices_only
          sidecars = Array(pod.dig("spec", "initContainers")).select { |container| container["restartPolicy"] == "Always" }
          containers = sidecars + containers
        end
        resources = containers.map { |container| container_resources(pod, uid, container, devices_only: devices_only) }
        {"name" => pod.dig("metadata", "name"), "namespace" => pod.dig("metadata", "namespace"), "containers" => resources}
      end

      def container_resources(pod, uid, container, devices_only:)
        name = container["name"].to_s
        result = {"name" => name, "devices" => []}
        if @device_plugins.respond_to?(:container_devices)
          result["devices"] = @device_plugins.container_devices(uid, name).map do |resource, ids|
            {"resource_name" => resource, "device_ids" => ids}
          end
        end
        return result if devices_only

        result.merge!("cpu_ids" => [], "memory" => [], "dynamic_resources" => [])
        cpu = @container_manager.respond_to?(:cpu_manager) ? @container_manager.cpu_manager : nil
        if cpu.respond_to?(:state) && cpu.state.respond_to?(:cpu_set)
          set = cpu.state.cpu_set(uid, name)
          result["cpu_ids"] = set.each.to_a if set && !set.empty?
        end
        memory = @container_manager.respond_to?(:memory_manager) ? @container_manager.memory_manager : nil
        if memory.respond_to?(:memory)
          result["memory"] = Array(memory.memory(uid, name)).map do |block|
            {"memory_type" => block.type, "size" => block.size, "topology" => {"nodes" => Array(block.numa_affinity).map do |id|
              {"ID" => id}
            end}}
          end
        end
        result["dynamic_resources"] = Array(@dra_manager.container_claims(pod, container)) if @dra_manager.respond_to?(:container_claims)
        result
      end
    end
  end
end
