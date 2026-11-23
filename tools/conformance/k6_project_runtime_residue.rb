# frozen_string_literal: true

require "json"
require "time"
require "yaml"
require_relative "../../lib/rubernetes/volume/record_files"
require_relative "k6_cilium_runtime"

module Conformance
  # Reads the same atomic state files as the native agents. A snapshot keeps
  # only identity and ownership references, never Pod or volume payloads.
  class K6ProjectRuntimeResidue
    def self.local(kubeconfig:, root: nil)
      root ||= File.dirname(File.realpath(kubeconfig))
      descriptor = JSON.parse(File.binread(File.join(root, "cluster.json")))
      unless descriptor["kind"] == "conformance_cluster" && File.identical?(descriptor.fetch("kubeconfig"), kubeconfig) &&
             kubeconfig_endpoint(kubeconfig) == descriptor.fetch("endpoint")
        raise ArgumentError, "cluster state does not belong to the selected kubeconfig"
      end

      agents = descriptor.fetch("processes").select { |process| process["executable"] == "rubernetes-agent" }
      configs = agents.to_h { |process| [process.fetch("name").delete_prefix("agent-"), process.fetch("config")] }
      new(root: root, workers: configs.keys, configs: configs, cilium: K6CiliumRuntime.local(descriptor, kubeconfig))
    rescue SystemCallError, TypeError, ArgumentError, KeyError => error
      new(reason: error.message)
    rescue JSON::ParserError, Psych::Exception, NoMethodError
      new(reason: "cluster descriptor or kubeconfig is malformed")
    end

    def self.kubeconfig_endpoint(path)
      config = YAML.safe_load_file(path)
      context = config.fetch("contexts").find { |entry| entry["name"] == config.fetch("current-context") }
      name = context.fetch("context").fetch("cluster")
      config.fetch("clusters").find { |entry| entry["name"] == name }.fetch("cluster").fetch("server")
    end
    private_class_method :kubeconfig_endpoint

    # An exported worker tree has the same path layout. Both sides of a
    # comparison need the expected workers and the state for each worker.
    def initialize(root: nil, workers: [], configs: nil, cilium: nil, reason: nil)
      unless workers.uniq == workers && workers.all? { |worker| worker.match?(/\Aworker-\d+\z/) }
        raise ArgumentError, "invalid worker identities in runtime observation"
      end

      @root = root
      @workers = workers
      @configs = configs
      @cilium = cilium
      @reason = reason || ("cluster descriptor contains no workers" if workers.empty?)
    end

    def available? = @reason.nil?

    def snapshot(stage: nil)
      state = {workers: {}, pods: {}, volumes: {}, entries: [], errors: [], captured_at: Time.now.utc.iso8601(6)}
      return state.merge(errors: [@reason]) unless available?

      @workers.each do |worker|
        worker_state(worker, state, stage: stage)
        state[:workers][worker] = "measured"
      rescue SystemCallError, TypeError, ArgumentError, KeyError => error
        state[:workers][worker] = "unmeasured"
        state[:errors] << "#{worker}: #{error.message}"
      rescue JSON::ParserError, Psych::Exception, NoMethodError
        state[:workers][worker] = "unmeasured"
        state[:errors] << "#{worker}: malformed runtime state or agent configuration"
      end
      directory = File.join(@root, "persistent-volumes")
      Dir.children(directory).sort.each { |name| add(state, nil, "ProvisionedPath", name) } if File.exist?(directory)
      state
    rescue SystemCallError => error
      state[:errors] << "persistent-volumes: #{error.message}"
      state
    end

    def compare(namespace:, baseline:, observations:, post:)
      snapshots = [baseline, *observations, post]
      owners = %i[pods volumes paths].to_h do |kind|
        [kind, snapshots.reduce({}) { |result, state| result.merge(state.fetch(kind, {})) }]
      end
      old_entries = baseline.fetch(:entries).group_by { |entry| identity(entry) }.transform_values do |entries|
        entries.map { |entry| ownership(entry, baseline) }
      end
      cilium_owners = snapshots.flat_map { |state| state.fetch(:entries) }.each_with_object({}) do |entry, seen|
        next unless %w[CiliumVeth CiliumKernelIP].include?(entry["kind"]) && entry["pod_uid"]

        (seen[identity(entry)] ||= []) << entry["pod_uid"]
      end
      residue = []
      unknown = []
      post.fetch(:entries).each do |entry|
        uid, owner = ownership(entry, owners)
        earlier = cilium_owners.fetch(identity(entry), []).uniq
        if uid.nil? && earlier.one?
          uid = earlier.first
          owner = owners.fetch(:pods)[uid]
        end
        previous = old_entries.fetch(identity(entry), [])
        next if previous.any? { |old_uid, old_owner| uid || old_uid ? uid == old_uid : owner == old_owner }
        next if uid && baseline.fetch(:pods).key?(uid)

        if owner == namespace
          residue << entry.merge("pod_uid" => uid).compact
        elsif owner.nil?
          unknown << entry
        end
      end
      errors = snapshots.flat_map { |state| state.fetch(:errors) }.uniq
      worker_names = snapshots.flat_map { |state| state.fetch(:workers).keys }.uniq
      workers = worker_names.to_h do |worker|
        measured_at_each_stage = snapshots.all? { |state| state.dig(:workers, worker) == "measured" }
        [worker, measured_at_each_stage ? "measured" : "unmeasured"]
      end
      measured = errors.empty? && unknown.empty? && !workers.empty? && workers.values.all?("measured")
      status = if !residue.empty?
                 "residue"
               elsif measured
                 "clean"
               else
                 "unmeasured"
               end
      observed_uids = owners.fetch(:pods).filter_map do |uid, owner|
        uid if owner == namespace && !baseline.fetch(:pods).key?(uid)
      end
      result = {"status" => status, "passed" => status == "clean", "workers" => workers,
                "baseline_at" => baseline.fetch(:captured_at), "post_uninstall_at" => post.fetch(:captured_at),
                "observed_pod_uids" => observed_uids.sort,
                "residue" => residue, "unattributed" => unknown, "errors" => errors}
      witnesses = snapshots.filter_map { |state| state[:cilium]&.merge("captured_at" => state.fetch(:captured_at)) }
      result["cilium"] = witnesses unless witnesses.empty?
      result
    end

    private

    def ownership(entry, state)
      volume = state.fetch(:volumes)[[entry["worker"], entry["volume_id"]]] || {}
      uid = entry["pod_uid"] || volume["pod_uid"]
      namespace = (state.fetch(:pods)[uid] if uid) || entry["namespace"] || volume["namespace"] || state.dig(:paths, entry["id"])
      [uid, namespace]
    end

    def worker_state(worker, state, stage:)
      runtime = File.join(@root, "runtime", worker)
      volumes = File.join(runtime, "volumes")
      raise ArgumentError, "volume state directory is missing" unless File.directory?(volumes)

      operations = File.join(@root, "network", worker, "state.json")
      native_network = @configs.nil? || native_agent?(worker, operations, volumes)
      if native_network
        read_network(worker, state, operations)
      else
        read_external_network(worker, state, operations, stage)
      end
      object_file(File.join(runtime, "ledger.jsonl.node-state.json")).fetch("records", []).each do |record|
        remember_pod(state, record.dig("pod", "metadata"), record["uid"])
      end
      volume_records(File.join(volumes, "volumes.json")).each do |record|
        read_volume(worker, state, record)
      end
      volume_records(File.join(volumes, "mounts.json")).each do |record|
        target = record.fetch("target")
        add(state, worker, "Mount", target, "volume_id" => record.fetch("volumeId"),
                                            "mount_id" => record["mountId"], "device_id" => record["deviceId"], "pod_uid" => path_pod(target))
      end
      raise ArgumentError, "external CNI identities require a separate observation" unless native_network || @cilium
    end

    def read_external_network(worker, state, operations, stage)
      directory = "#{operations}.cni"
      journal = Dir.glob(File.join(directory, "*.json")).to_h do |file|
        sandbox = File.basename(file, ".json")
        add(state, worker, "CNIAttachment", sandbox, "pod_uid" => sandbox_pod(sandbox))
        next [sandbox, []] unless @cilium

        record = object_file(file)
        plugins = record.fetch("network").fetch("plugins").map { |plugin| plugin.fetch("type") }
        raise ArgumentError, "unsupported CNI attachment on the Cilium worker" unless plugins == ["cilium-cni"]

        ips = record.fetch("result").fetch("ips").map { |item| item.fetch("address").split("/", 2).first }
        [sandbox, ips]
      end
      return unless @cilium

      raise ArgumentError, "Cilium runtime journal is missing" unless File.directory?(directory)

      witness, errors = @cilium.observe(worker, stage, journal)
      state[:cilium] = witness
      state.fetch(:errors).concat(errors)
      links = witness.fetch("endpoints").to_h { |entry| [entry.fetch("ifname"), entry] }
      ips = witness.fetch("endpoints").to_h { |entry| [entry.fetch("ipv4"), entry] }
      witness.fetch("endpoints").each do |endpoint|
        metadata = {"pod_uid" => endpoint.fetch("pod_uid"), "namespace" => endpoint["namespace"]}
        add(state, worker, "CiliumEndpoint", endpoint.fetch("endpoint_id").to_s, metadata)
        add(state, worker, "CiliumPodIP", endpoint.fetch("ipv4"), metadata)
      end
      witness.fetch("kernel_links").each do |link|
        endpoint = links.fetch(link.fetch("ifname"), {})
        device = "#{link.fetch("ifindex")}:#{link.fetch("mac")}"
        add(state, worker, "CiliumVeth", link.fetch("ifname"), "pod_uid" => endpoint["pod_uid"], "device_id" => device)
      end
      witness.fetch("kernel_pod_addresses").each do |ip|
        add(state, worker, "CiliumKernelIP", ip, "pod_uid" => ips.fetch(ip, {})["pod_uid"])
      end
    end

    def native_agent?(worker, network, volumes)
      agent = YAML.safe_load_file(@configs.fetch(worker)).fetch("processes").fetch("rubernetes-agent")
      unless agent.dig("network", "state_path") == network && agent.dig("volume", "data_dir") == volumes
        raise ArgumentError, "agent state paths do not match the fixture layout"
      end

      agent.dig("network", "plugin") != "cni"
    end

    def volume_records(path)
      attempts = 0
      begin
        Rubernetes::Volume::RecordFiles.read(path)
      rescue Errno::ENOENT
        attempts += 1
        retry if attempts < 3

        raise
      end
    end

    def read_network(worker, state, path)
      ipam = object_file("#{path}.ipam.json")
      ipam.fetch("operations", {}).each_value { |record| remember_network_pod(state, record) }
      ipam.fetch("leases", {}).each_value do |record|
        uid = remember_network_pod(state, record)
        next if record.fetch("state") == "released"

        add(state, worker, "IPAMLease", "#{record.fetch("operation_id")}:#{record.fetch("ip")}",
            "pod_uid" => uid, "state" => record.fetch("state"))
      end
      object_file(path).fetch("operations", {}).each_value do |record|
        next if record.fetch("state") == "removed"

        add(state, worker, "NetworkOperation", record.fetch("id"),
            "pod_uid" => sandbox_pod(record.fetch("sandbox_id")), "state" => record.fetch("state"))
      end
      object_file("#{path}.sysctl.json").fetch("owners", []).each do |sandbox|
        add(state, worker, "NetworkSysctlOwner", sandbox, "pod_uid" => sandbox_pod(sandbox))
      end
    end

    def read_volume(worker, state, record)
      id = record.fetch("id")
      spec = record.fetch("spec")
      metadata = spec.dig("pod", "metadata")
      uid = spec["podUid"] || metadata&.fetch("uid", nil)
      namespace = remember_pod(state, metadata, uid)
      claim = spec["claim"]
      namespace ||= claim.split("/", 2).first if claim.is_a?(String) && claim.include?("/")
      owner = {"pod_uid" => uid, "namespace" => namespace}.compact
      state[:volumes][[worker, id]] = owner unless owner.empty?
      associations = {"volume_id" => id}
      kind = record.fetch("state")
      add(state, worker, "Volume", id, associations.merge("state" => kind)) unless %w[Declared Deleted].include?(kind)
      record.fetch("stages", {}).each do |target, stage|
        shared = stage["sharedCSIStage"]
        state[:volumes][[worker, shared]] = owner if shared && !owner.empty?
        add(state, worker, "Stage", target, associations.merge("pod_uid" => path_pod(target)))
      end
      record.fetch("publishes", {}).each do |key, publish|
        add(state, worker, "Publish", publish.fetch("target"), associations.merge("pod_uid" => publish["pod"] || key.split("\0", 2).first))
      end
      record.fetch("attachments", {}).each do |node, attachment|
        pods = Array(attachment["pods"])
        pods = [nil] if pods.empty?
        pods.each do |pod|
          add(state, worker, "Attachment", "#{id}:#{node}:#{pod}", associations.merge("pod_uid" => pod))
        end
      end
    end

    def object_file(path)
      value = File.exist?(path) ? JSON.parse(File.binread(path)) : {}
      raise ArgumentError, "#{File.basename(path)} is not a state object" unless value.is_a?(Hash)

      value
    end

    def remember_network_pod(state, record)
      data = record["metadata"] || {}
      metadata = data["metadata"] || data
      uid = metadata["uid"] || sandbox_pod(record.fetch("sandbox_id"))
      remember_pod(state, metadata, uid)
      uid
    end

    def remember_pod(state, metadata, uid)
      namespace = metadata&.fetch("namespace", nil)
      state[:pods][uid] = namespace if uid && namespace
      namespace
    end

    def sandbox_pod(sandbox)
      sandbox[/\Apod(.+)-[0-9a-f]{12}\z/, 1] || sandbox
    end

    def path_pod(path)
      path[%r{/pods/(?:volumes/)?([0-9a-f]{8}-[0-9a-f-]{27})(?:/|\z)}, 1]
    end

    def identity(entry)
      entry.values_at("worker", "kind", "id", "volume_id", "mount_id", "device_id")
    end

    def add(state, worker, kind, id, details = {})
      state[:entries] << {"worker" => worker, "kind" => kind, "id" => id, **details}.compact
    end
  end
end
