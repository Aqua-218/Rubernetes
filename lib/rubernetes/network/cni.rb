# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"

require_relative "errors"

module Rubernetes
  module Network
    # Pod networking by CNI plugins instead of the built-in bridge: the node
    # agent as a CNI runtime (containernetworking.io, spec 1.0).
    #
    # The network is the first configuration file in the configuration
    # directory, by name, as kubelet's runtimes pick it.  Its plugins are run
    # in order for ADD -- each given the result of the one before -- and in
    # reverse for DEL, with the result ADD ended on.  That result is kept on
    # disk per sandbox, because DEL must be given it and may come after an
    # agent restart.
    #
    # With CNI the plugins own everything the built-in network otherwise does
    # for a Pod: addresses, routes, the node's bridge, and NetworkPolicy.
    class CNI
      class PluginError < EffectError; end

      CONFIG_PATTERN = "*.{conflist,conf,json}"
      INTERFACE = "eth0"
      DEFAULT_CONF_DIR = "/etc/cni/net.d"
      DEFAULT_BIN_DIRS = ["/opt/cni/bin"].freeze
      # What a plugin may be handed as runtimeConfig, when it declares the
      # capability.
      CAPABILITIES = %w[portMappings].freeze

      def initialize(state_dir:, conf_dir: DEFAULT_CONF_DIR, bin_dirs: DEFAULT_BIN_DIRS, runner: nil, logger: nil)
        @conf_dir = conf_dir
        @bin_dirs = Array(bin_dirs)
        @state_dir = state_dir
        @runner = runner || method(:execute)
        @logger = logger
        FileUtils.mkdir_p(@state_dir)
      end

      # Attaches the sandbox to the network and answers with its addresses.
      # A Pod on the host network has nothing to attach.
      def add(sandbox, pod = nil, **)
        context = context_for(sandbox)
        return {"sandbox_id" => context.fetch(:id), "ips" => [], "backend" => "cni", "state" => "committed"} if host_network?(pod)

        network = load_network
        # A plugin that is not installed is found out before the first one runs.
        network.fetch("plugins").each { |plugin| binary!(plugin.fetch("type")) }
        run_loopback(context, network)
        result = nil
        begin
          network.fetch("plugins").each do |plugin|
            result = invoke("ADD", plugin, network, context, pod, previous: result)
          end
        rescue StandardError => error
          # A chain that stopped half way is undone as far as it got; what
          # went wrong is still the ADD.
          begin
            detach(network, context, pod, result)
          rescue PluginError => undo
            @logger&.warn("cni.rollback_failed", sandbox: context.fetch(:id), message: undo.message)
          end
          raise error
        end
        store(context.fetch(:id), {"network" => network, "result" => result, "netns" => context.fetch(:netns)})
        summary(context.fetch(:id), result)
      end

      # Detaches the sandbox.  DEL is given the network ADD used, not the one
      # configured now, and a sandbox that was never attached (or already
      # detached) is done.
      def delete(sandbox, pod = nil, **)
        context = context_for(sandbox, require_netns: false)
        stored = load(context.fetch(:id))
        return {"sandbox_id" => context.fetch(:id), "state" => "removed"} if stored.nil?

        context[:netns] ||= stored["netns"]
        detach(stored.fetch("network"), context, pod, stored["result"])
        FileUtils.rm_f(state_path(context.fetch(:id)))
        {"sandbox_id" => context.fetch(:id), "state" => "removed"}
      end

      # CHECK, for plugins of a network that speaks 0.4.0 or later.
      def check(sandbox, pod = nil, **)
        context = context_for(sandbox)
        stored = load(context.fetch(:id)) || raise(ValidationError, "sandbox #{context.fetch(:id)} is not attached")
        network = stored.fetch("network")
        return true if Gem::Version.new(network.fetch("cniVersion")) < Gem::Version.new("0.4.0")

        network.fetch("plugins").each { |plugin| invoke("CHECK", plugin, network, context, pod, previous: stored["result"]) }
        true
      end

      # Nothing of a CNI network lives in this process: what was attached is
      # on disk, and the plugins keep their own state.
      def recover(**)
        {"operations" => Dir[File.join(@state_dir, "*.json")].length, "errors" => []}
      end

      def shutdown = nil

      private

      def context_for(sandbox, require_netns: true)
        hash = sandbox.is_a?(Hash) ? sandbox : {"sandbox_id" => sandbox}
        id = (hash["sandbox_id"] || hash[:sandbox_id] || hash["id"] || hash[:id]).to_s
        raise ValidationError, "sandbox ID is required" if id.empty?

        holder = hash["netns"] || hash[:netns] || hash["network_namespace"]
        netns = holder.is_a?(Hash) ? (holder["path"] || holder[:path]) : holder
        raise OwnershipError, "sandbox #{id} has no network namespace to attach" if require_netns && netns.to_s.empty?

        {id: id, netns: netns&.to_s}
      end

      def host_network?(pod)
        pod.is_a?(Hash) && (pod.dig("spec", "hostNetwork") == true)
      end

      # The first file by name; a single-plugin *.conf is a list of one.
      def load_network
        path = Dir[File.join(@conf_dir, CONFIG_PATTERN)].min
        raise ValidationError, "no CNI network configuration in #{@conf_dir}" if path.nil?

        document = JSON.parse(File.read(path))
        document = {"cniVersion" => document["cniVersion"], "name" => document["name"], "plugins" => [document]} unless document.key?("plugins")
        %w[cniVersion name].each do |key|
          raise ValidationError, "#{path}: #{key} is required" if document[key].to_s.empty?
        end
        raise ValidationError, "#{path}: a network needs at least one plugin" if Array(document["plugins"]).empty?

        document
      rescue JSON::ParserError => error
        raise ValidationError, "#{path}: #{error.message}"
      end

      # Every runtime brings the sandbox's loopback up before the network's
      # own plugins run; the plugins assume it.
      def run_loopback(context, network)
        return if binary("loopback").nil?

        loopback = {"cniVersion" => network.fetch("cniVersion"), "name" => "cni-loopback", "plugins" => [{"type" => "loopback"}]}
        invoke("ADD", loopback.fetch("plugins").first, loopback, context.merge(ifname: "lo"), nil, previous: nil)
      end

      def detach(network, context, pod, result)
        errors = network.fetch("plugins").reverse.filter_map do |plugin|
          invoke("DEL", plugin, network, context, pod, previous: result)
          nil
        rescue StandardError => error
          error.message
        end
        raise PluginError, "CNI DEL failed for sandbox #{context.fetch(:id)}: #{errors.join("; ")}" unless errors.empty?
      end

      def invoke(command, plugin, network, context, pod, previous:)
        type = plugin.fetch("type")
        path = binary!(type)
        configuration = plugin.merge("cniVersion" => network.fetch("cniVersion"), "name" => network.fetch("name"))
        configuration["prevResult"] = previous if previous
        runtime = runtime_config(plugin, pod)
        configuration["runtimeConfig"] = runtime unless runtime.empty?
        environment = {"CNI_COMMAND" => command, "CNI_CONTAINERID" => context.fetch(:id), "CNI_NETNS" => context[:netns].to_s,
                       "CNI_IFNAME" => context.fetch(:ifname, INTERFACE), "CNI_PATH" => @bin_dirs.join(":"), "CNI_ARGS" => arguments(context, pod),
                       "PATH" => ENV.fetch("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")}
        output, error, success = @runner.call(environment, path, JSON.generate(configuration))
        raise PluginError, "CNI #{command} #{type}: #{failure(output, error)}" unless success

        output.to_s.strip.empty? ? previous : JSON.parse(output)
      rescue JSON::ParserError => parse_error
        raise PluginError, "CNI #{command} #{plugin["type"]}: unreadable result: #{parse_error.message}"
      end

      # A plugin reports an error as a JSON object on stdout.
      def failure(output, error)
        document = JSON.parse(output.to_s)
        [document["msg"], document["details"]].compact.reject(&:empty?).join(": ")
      rescue JSON::ParserError, NoMethodError
        (error.to_s.strip.empty? ? output.to_s : error.to_s).strip[0, 500]
      end

      # What kubelet's runtimes pass: the Pod's identity, for plugins that
      # look the Pod up.
      def arguments(context, pod)
        metadata = pod.is_a?(Hash) ? pod.fetch("metadata", {}) : {}
        {"IgnoreUnknown" => "1", "K8S_POD_NAMESPACE" => metadata["namespace"], "K8S_POD_NAME" => metadata["name"],
         "K8S_POD_INFRA_CONTAINER_ID" => context.fetch(:id), "K8S_POD_UID" => metadata["uid"]}
          .compact.map { |key, value| "#{key}=#{value}" }.join(";")
      end

      def runtime_config(plugin, pod)
        wanted = (plugin["capabilities"] || {}).select { |name, enabled| enabled == true && CAPABILITIES.include?(name) }.keys
        return {} unless wanted.include?("portMappings") && pod.is_a?(Hash)

        mappings = Array(pod.dig("spec", "containers")).flat_map { |container| Array(container["ports"]) }.filter_map do |port|
          next unless port["hostPort"].to_i.positive?

          {"hostPort" => port["hostPort"], "containerPort" => port["containerPort"], "protocol" => (port["protocol"] || "TCP").downcase,
           "hostIP" => port["hostIP"]}.compact
        end
        mappings.empty? ? {} : {"portMappings" => mappings}
      end

      def binary(type)
        raise ValidationError, "invalid CNI plugin type #{type.inspect}" unless type.to_s.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]*\z/)

        @bin_dirs.map { |directory| File.join(directory, type) }.find { |path| File.executable?(path) }
      end

      def binary!(type)
        binary(type) || raise(ValidationError, "CNI plugin #{type.inspect} is not in #{@bin_dirs.join(":")}")
      end

      def execute(environment, path, input)
        output, error, status = Open3.capture3(environment, path, stdin_data: input, unsetenv_others: true)
        [output, error, status.success?]
      end

      def summary(id, result)
        addresses = Array(result && result["ips"]).map { |entry| entry["address"].to_s.split("/").first }.reject(&:empty?)
        # The plugins list the node's bridge before the Pod's own host-side
        # link.
        host = Array(result && result["interfaces"]).reverse.find { |interface| interface["sandbox"].to_s.empty? }
        {"sandbox_id" => id, "ip" => (addresses.length == 1 ? addresses.first : addresses), "ips" => addresses, "backend" => "cni",
         "interface" => host && host["name"], "pod_interface" => INTERFACE, "state" => "committed"}.compact
      end

      def state_path(id) = File.join(@state_dir, "#{id.gsub(/[^A-Za-z0-9_.-]/, "_")}.json")

      def store(id, document)
        temporary = "#{state_path(id)}.tmp"
        File.write(temporary, JSON.generate(document))
        File.rename(temporary, state_path(id))
      end

      def load(id)
        JSON.parse(File.read(state_path(id)))
      rescue Errno::ENOENT
        nil
      end
    end
  end
end
