# frozen_string_literal: true

require_relative "inspector"

module Rubernetes
  module Console
    # What a console session's code is evaluated against: `self` at the
    # prompt.  Its methods are the things in reach; local variables assigned
    # at the prompt stay for the session.
    class Context
      # name => one line of help, in the order `help` prints them.
      def self.helpers
        @helpers ||= (superclass.respond_to?(:helpers) ? superclass.helpers.dup : {})
      end

      def self.helper(name, description, &)
        helpers[name.to_s] = description
        define_method(name, &)
      end

      attr_reader :service

      def initialize(service, out)
        @service = service
        @out = out
      end

      # Printing at the prompt goes to the session, not into the component's
      # log.
      def puts(*lines) = @out.puts(*lines)
      def print(*parts) = @out.print(*parts)

      def p(*values)
        values.each { |value| @out.puts(Inspector.render(value)) }
        values.length <= 1 ? values.first : values
      end

      def session_binding = binding

      # Typed at the prompt, these would end the component, not the session.
      %i[exit exit! abort].each do |name|
        define_method(name) { |*| raise "#{name} would stop the component; Ctrl-D ends the session" }
      end

      helper(:help, "this list") do
        self.class.helpers.each { |name, description| puts(format("  %-12<name>s %<description>s", name: name, description: description)) }
        nil
      end

      helper(:service, "the component's service object; everything else hangs off it") { @service }

      helper(:ivars, "ivars(object): the names of what an object holds") { |object| object.instance_variables.sort }

      helper(:ivar, "ivar(object, :name): one of them") { |object, name| object.instance_variable_get("@#{name.to_s.delete_prefix("@")}") }

      helper(:threads, "the process's threads and where each one is") do
        Thread.list.each do |thread|
          frame = thread.backtrace&.find { |line| line.include?("/lib/rubernetes/") }.to_s.sub(%r{\A.*/lib/rubernetes/}, "")
          puts(format("  %-28<name>s %-8<status>s %<frame>s",
                      name: thread.name || "thread-#{thread.object_id}", status: thread.status.to_s, frame: frame))
        end
        Thread.list.length
      end

      helper(:memory, "resident memory and the Ruby heap") do
        resident = File.read("/proc/self/status")[/^VmRSS:\s+(\d+)/, 1].to_i / 1024
        {"resident_mb" => resident, "heap_live_objects" => GC.stat(:heap_live_slots), "major_gc" => GC.stat(:major_gc_count),
         "threads" => Thread.list.length}
      end
    end

    class SchedulerContext < Context
      helper(:framework, "the scheduling framework") { service.framework }
      helper(:queue, "the scheduling queue") { service.framework.queue }
      helper(:plugins, "the plugins a Pod passes through, in order") { service.framework.plugins.map(&:name) }
      # The scheduler keeps nodes and Pods apart and joins them for each
      # scheduling cycle; a node here carries its Pods as a plugin sees it.
      helper(:nodes, "the nodes as a plugin sees them, each with its Pods") do
        placed = pods.group_by(&:node_name)
        ivar(service, :nodes).values.map { |node| node.with_pods(placed.fetch(node.name, [])) }
      end
      helper(:pods, "the Pods as the scheduler sees them") { ivar(service, :pods).values }
      helper(:decisions, "the Pods whose last scheduling decision is remembered") { service.decisions.keys }

      helper(:why, 'why("namespace/pod"): which plugin ruled each node out, and how the rest were scored') do |pod|
        key = pod.to_s.include?("/") ? pod.to_s : "default/#{pod}"
        puts(service.decisions.explain(key))
        nil
      end
    end

    class APIServerContext < Context
      helper(:server, "the API server: routing, admission, storage strategy") { ivar(service, :api_server) }
      helper(:store, "the object store behind it") { ivar(service, :store) }
      helper(:raft, "this replica's raft node, when the datastore is raft") { ivar(service, :raft_server) }
      helper(:admission, "the admission chain, in order") do
        security = ivar(service, :security)
        security && security.pipeline.admission.names
      end

      helper(:keys, 'keys("registry/v1/pods"): the stored keys under a prefix') do |prefix = "registry"|
        store.list(prefix).items.map { |object| [object["kind"], object.dig("metadata", "namespace"), object.dig("metadata", "name")].compact.join("/") }
      end
    end

    class ControllerManagerContext < Context
      helper(:manager, "the controller manager: registry, queue, leadership") { service.manager }
      helper(:leader?, "whether this process holds the lease") { service.manager.leader? }
      helper(:controllers, "the controllers that are running") { ivar(service.manager, :controllers).keys }
    end

    class AgentContext < Context
      helper(:agent, "the node agent") { service.node_agent }
      helper(:lifecycle, "the Pod lifecycle: one record per Pod on this node") { ivar(agent, :lifecycle) }

      helper(:pods, "the Pods on this node and the state each is in") do
        ivar(lifecycle, :records).values.to_h do |record|
          metadata = record[:pod].fetch("metadata", {})
          ["#{metadata["namespace"]}/#{metadata["name"]}", record[:state]]
        end
      end
    end

    class ProxyContext < Context
      helper(:proxy, "the service proxy and its datapath backend") { service.proxy }
    end

    CONTEXTS = {
      "rubernetes-scheduler" => SchedulerContext, "rubernetes-apiserver" => APIServerContext,
      "rubernetes-controller-manager" => ControllerManagerContext, "rubernetes-agent" => AgentContext,
      "rubernetes-proxy" => ProxyContext
    }.freeze
  end
end
