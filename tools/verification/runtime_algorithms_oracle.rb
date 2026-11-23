#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require_relative "lean_oracle"
require "tmpdir"
require_relative "../../lib/rubernetes/network/ipam"
require_relative "../../lib/rubernetes/runtime"
require_relative "../../lib/rubernetes/runtime/common/rollback"
require_relative "../../lib/rubernetes/runtime/microvm/identity"
require_relative "../../lib/rubernetes/scheduler"
require_relative "../../lib/rubernetes/platform/linux/native_adapters"

module RuntimeAlgorithmsOracle
  SOURCE = File.expand_path("../../verification/lean/RuntimeAlgorithms.lean", __dir__)
  SEED = 20_260_918
  LINUX = Rubernetes::Platform::Linux

  # Kernel stand-in for observing exactly which cgroup files receive writes.
  class CgroupFiles
    attr_reader :limits

    def initialize(root)
      @directories = [root, File.join(root, "rubernetes")]
      @limits = {}
    end

    def directory?(path) = @directories.include?(path)
    def mkdir_p(path) = @directories << path
    def exists?(_path) = true
    def read(_path) = "cpu memory pids"
    def write(path, value) = @limits[path] = value
  end

  module_function

  def run(lean: LeanOracle.executable, seed: SEED)
    random = Random.new(seed)
    cases = ipam_cases(random) + rollback_cases(random) + identity_cases(random) +
            scheduler_cases(random) + overlay_cases(random) + cgroup_cases(random)
    expected = LeanOracle.run(SOURCE, cases.map(&:first), lean: lean)

    mismatches = cases.each_with_index.filter_map do |(input, ruby), index|
      model = expected.fetch(index)
      {"input" => input, "ruby" => ruby, "lean" => model} unless ruby == model
    end
    {"passed" => mismatches.empty?, "seed" => seed, "cases" => cases.map { |input, _| input.fetch("kind") }.tally,
     "source_sha256" => Digest::SHA256.file(SOURCE).hexdigest, "mismatches" => mismatches}
  end

  def ipam_cases(random)
    ipv4 = (2..6).to_a # /29, excluding the network, bridge and broadcast
    ipv6 = (2..7).to_a # /125, with no broadcast
    %w[ipv4 ipv6].zip([ipv4, ipv6], ["10.0.0.0", "fd00::"]).flat_map do |family, candidates, address|
      base = IPAddr.new(address)
      prefix = family == "ipv4" ? 29 : 125
      [[], candidates, *Array.new(64) { candidates.sample(random.rand(0..candidates.length), random: random) }].map do |used|
        ipam = Rubernetes::Network::IPAM.new(
          cluster_cidr: "#{address}/#{prefix}", ipv4_node_prefix: 29, ipv6_node_prefix: 125
        )
        leases = ipam.instance_variable_get(:@state).fetch("leases")
        used.each do |offset|
          ip = IPAddr.new(base.to_i + offset, base.family).to_s
          leases[ip] = {"ip" => ip, "node" => "node-1", "family" => family,
                        "state" => %w[reserved committed unknown].sample(random: random)}
        end
        (candidates - used).each do |offset|
          ip = IPAddr.new(base.to_i + offset, base.family).to_s
          leases[ip] = {"ip" => ip, "node" => "node-1", "family" => family, "state" => "released"}
        end
        input = {"kind" => "ipam", "candidates" => candidates, "used" => used}
        begin
          lease = ipam.reserve(node: "node-1", pod_uid: "new-pod", sandbox_id: "new-sandbox")
          [input, IPAddr.new(lease.ip).to_i - base.to_i]
        rescue Rubernetes::Network::LeaseUnavailable
          [input, nil]
        end
      end
    end
  end

  def rollback_cases(random)
    resource = Struct.new(:kind, :id, :identity, :sequence)
    ledger = Struct.new(:remaining, :released) do
      def operation(_id) = Struct.new(:state, :error, :cleanup_errors).new("RollingBack", nil, [])
      def resources(operation_id:, include_released:) = remaining
      def release(operation_id:, kind:, id:, identity:, force:) = released << id
      def transition(**) = nil
      def record_cleanup_error(*) = nil
    end
    adapter = Struct.new(:first_failure) do
      def cleanup_resource(resource)
        resource.id != first_failure
      end
    end
    Array.new(80) do
      acquisition = Array.new(random.rand(0..12)) { random.rand(1..100) }.uniq.sort
      released = acquisition.sample(random.rand(0..acquisition.length), random: random)
      active = acquisition - released
      first_failure = random.rand(3).zero? ? active.sample(random: random) : nil
      remaining = active.shuffle(random: random).map { |id| resource.new("workspace", id, id.to_s, id) }
      store = ledger.new(remaining, [])
      Rubernetes::Runtime::RollbackExecutor.new(ledger: store, adapter: adapter.new(first_failure)).execute(
        operation_id: "rollback", operation_error: nil, mark_failed: false
      )
      [{"kind" => "rollback", "acquisition" => acquisition, "released" => released, "first_failure" => first_failure}, store.released]
    end
  end

  def identity_cases(random)
    klass = Rubernetes::Runtime::MicroVM::IdentityLedger
    Dir.mktmpdir("rubernetes-identity-oracle-") do |directory|
      path = File.join(directory, "identity.jsonl")
      ledger = klass.new(path, fsync: false)
      seen = []
      Array.new(80) do |index|
        fields = {"request_id" => "request-#{random.rand(45)}", "workspace_id" => "workspace-#{random.rand(45)}"}
        input = {"kind" => "identity", "seen" => seen.dup, "values" => fields.to_a}
        begin
          record = ledger.allocate(sandbox_id: "sandbox-#{index}", runtime_class: "microvm", artifact_digest: "artifact",
                                   policy_digest: "policy", request_id: fields.fetch("request_id"),
                                   workspace_id: fields.fetch("workspace_id"))
          ledger.release(record.vm_id)
          seen.concat(fields.to_a)
          [input, true]
        rescue Rubernetes::Runtime::MicroVM::IdentityError => error
          raise unless error.message.match?(/identity value for (request_id|workspace_id) was issued before/)

          [input, false]
        ensure
          ledger = klass.new(path, fsync: false) if (index % 7).zero?
        end
      end
    end
  end

  def scheduler_cases(random)
    scheduler = Rubernetes::Scheduler
    pod = scheduler::Pod.new("metadata" => {"name" => "pending"})
    node = scheduler::Node.new({"metadata" => {"name" => "candidate"}})
    context = scheduler::CycleContext.new(nodes: [node], pods: [])
    skip = Struct.new(:result) { def score_nodes(*) = result }.new(scheduler::Scores::SKIP)
    Array.new(100) do
      filter_outputs = Array.new(random.rand(0..8)) { [true, true, true, false, nil].sample(random: random) }
      filters = filter_outputs.map.with_index do |output, index|
        scheduler::Plugin.new(name: "Filter#{index}", phase: :filter, block: ->(_pod, _node) { output })
      end
      score_outputs = Array.new(random.rand(0..8)) do
        [[nil, -1, 0, 1, 99, 100, 101].sample(random: random), random.rand(1..8)]
      end
      scores = score_outputs.map.with_index do |(value, weight), index|
        scheduler::Plugin.new(name: "Score#{index}", phase: :score, weight: weight,
                              block: ->(_pod, _node) { value }, score_extension: value.nil? ? skip : nil)
      end
      framework = scheduler::Framework.new(standard_plugins: false, filters: filters, scores: scores)
      filtered = begin
        result = framework.send(:run_filters, pod, node, context, trace: nil)
        result == true ? "accepted" : "rejected:#{result.fetch("plugin").delete_prefix("Filter")}"
      rescue scheduler::PluginError => error
        "error:#{error.plugin.delete_prefix("Filter")}"
      end
      total = begin
        framework.send(:score_nodes, pod, [node], context, nil).first.total
      rescue scheduler::PluginError
        nil
      end
      [[{"kind" => "scheduler_filter", "outputs" => filter_outputs}, filtered],
       [{"kind" => "scheduler_score", "outputs" => score_outputs}, total]]
    end.flatten(1)
  end

  def overlay_cases(random)
    workspace_type = Struct.new(:id, :identity, :root, :upper, :work)
    namespace = Struct.new(:adapter_handle).new(:fake)
    namespace_operations = Object.new
    namespace_operations.define_singleton_method(:with_mount_namespace) { |_handle, &block| block.call }
    mount_type = Struct.new(:options) do
      def make_slave(**); end
      def mount(data:, **) = self.options = data
    end
    Dir.mktmpdir("rubernetes-overlay-oracle-") do |directory|
      Array.new(60) do |index|
        base = File.join(directory, index.to_s)
        layers = Array.new(random.rand(1..8)) { |i| File.join(directory, "layer-#{i}") }
        layers.each { |path| FileUtils.mkdir_p(path) }
        workspace = workspace_type.new(index.to_s, "workspace-#{index}", File.join(base, "root"),
                                       File.join(base, "upper"), File.join(base, "work"))
        mount = mount_type.new
        adapter = LINUX::NativeAdapters::OverlayFilesystemAdapter.new(root: directory, namespace_adapter: namespace_operations,
                                                                      mount: mount)
        adapter.define_singleton_method(:validate_native_capabilities!) { true }
        adapter.define_singleton_method(:mount_readback) { |_namespace, _target| {} }
        adapter.prepare(workspace: workspace, lowerdirs: layers)
        adapter.activate(workspace, namespace: namespace)
        options = mount.options.split(",").to_h { |entry| entry.split("=", 2) }
        actual_order = [options.fetch("upperdir"), *options.fetch("lowerdir").split(":")]
        intended = [workspace.upper, *layers, File.join(base, "runtime-lower")]
        edits = intended.to_h { |path| [path, [0, 0, 1, random.rand(2..99)].sample(random: random)] }
        actual = actual_order.map { |path| edits.fetch(path) }.find(&:positive?) || 0
        [{"kind" => "overlay", "edits" => edits.values}, actual]
      end
    end
  end

  def cgroup_cases(random)
    root = "/formal-cgroup"
    Array.new(60) do
      limits = Array.new(4) { [nil, random.rand(1..1024)].sample(random: random) }
      base = File.join(root, "rubernetes")
      qos = File.join(base, "burstable")
      files = CgroupFiles.new(root)
      files.write(File.join(base, "memory.max"), limits.fetch(0) || "max")
      files.write(File.join(qos, "memory.max"), limits.fetch(1) || "max")
      cgroup = LINUX::CgroupV2.new(root: root, adapter: files)
      handle = cgroup.create(qos: "burstable", pod_id: "pod", container_id: "container",
                             pod_limits: {"memory.max" => limits.fetch(2) || "max"},
                             limits: {"memory.max" => limits.fetch(3) || "max"})
      ancestry = [base, qos, File.join(qos, "pod"), File.join(qos, "pod", "container")]
      raise "cgroup leaf escaped its pod hierarchy" unless handle.path == ancestry.last

      written_caps = ancestry.filter_map do |path|
        token = files.limits.fetch(File.join(path, "memory.max"), "max")
        Integer(token) unless token == "max"
      end
      [{"kind" => "cgroup", "limits" => limits}, written_caps.min]
    end
  end
end

if $PROGRAM_NAME == __FILE__
  report = RuntimeAlgorithmsOracle.run
  puts JSON.pretty_generate(report)
  exit(report.fetch("passed") ? 0 : 1)
end
