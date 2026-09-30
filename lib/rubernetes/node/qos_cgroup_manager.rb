# frozen_string_literal: true

require "fileutils"
require "json"
require_relative "status"
require_relative "../resource_helpers"

module Rubernetes
  module Node
    # The kubelet's cgroup side of node allocatable and QoS (pkg/kubelet/cm,
    # v1.36.2):
    #
    # * enforceNodeAllocatableCgroups -- the Pods' root cgroup ("kubepods";
    #   here <cgroup_root>/<hierarchy>) is limited to capacity less
    #   system-reserved and kube-reserved when enforceNodeAllocatable has
    #   "pods" (to capacity otherwise, so its CPU weight is never the low
    #   default): cpu weight from the CPU, memory.max, pids.max and
    #   hugetlb.<size>.max.  "system-reserved" / "kube-reserved" limit those
    #   existing cgroups to the reservations.  Retried every minute until it
    #   succeeds, with a NodeAllocatableEnforced / FailedNodeAllocatableEnforcement
    #   event on the Node.
    # * qosContainerManager.UpdateCgroups -- BestEffort always 2 shares,
    #   Burstable the shares of its Pods' CPU requests; on every Pod change and
    #   once a minute.  Guaranteed Pods are kubepods children upstream; here
    #   they share a "guaranteed" directory, which therefore gets the shares
    #   of its Pods' requests, so it weighs what those Pods would.
    #
    # Several agents of one host may share the hierarchy (a multi-node
    # cluster on one machine).  Each then publishes its node allocatable and
    # its Pods' QoS requests in a host-local state directory (/run, the scope
    # the cgroup tree has), and every agent writes the composition of the
    # live ones: the Pods' root is limited to the sum of the nodes'
    # allocatable (never above the host's capacity), a QoS class weighs the
    # requests of all its Pods.  With one agent this is exactly the kubelet.
    class QOSCgroupManager
      MIN_SHARES = 2
      MAX_SHARES = 262_144
      SHARES_PER_CPU = 1024
      MILLI_CPU_TO_CPU = 1000
      PERIOD_SECONDS = 60
      # kubetypes.NodeAllocatableEnforcementKey and friends; the
      # "-compressible" keys limit the reserved cgroups' CPU only.
      ENFORCEMENT_KEYS = %w[pods system-reserved kube-reserved system-reserved-compressible kube-reserved-compressible none].freeze

      class Error < StandardError; end

      attr_reader :last_node_limits

      # +capacity+ / +system_reserved+ / +kube_reserved+: resource => quantity
      # (the "pid" resource included).  +active_pods+ returns the admitted Pods.
      def initialize(root:, capacity:, hierarchy: "rubernetes", system_reserved: {}, kube_reserved: {},
                     enforce_node_allocatable: ["pods"], system_reserved_cgroup: nil, kube_reserved_cgroup: nil,
                     active_pods: -> { [] }, event: nil, error_handler: nil, period: PERIOD_SECONDS,
                     pid_max_paths: %w[/proc/sys/kernel/pid_max /proc/sys/kernel/threads-max],
                     node_name: nil, state_dir: nil)
        @base = File.join(File.expand_path(root.to_s), hierarchy.to_s)
        @node_name = (node_name || Process.pid).to_s
        @state_dir = state_dir || File.join("/run/rubernetes/qos-cgroups", hierarchy.to_s)
        @start_time = process_start_time(Process.pid)
        @root = File.expand_path(root.to_s)
        @capacity = quantities(capacity)
        pid_max = read_pid_max(pid_max_paths)
        @capacity["pid"] ||= Rational(pid_max) if pid_max
        @system_reserved = quantities(system_reserved)
        @kube_reserved = quantities(kube_reserved)
        @enforce = Array(enforce_node_allocatable).map(&:to_s)
        unknown = @enforce - ENFORCEMENT_KEYS
        raise Error, "invalid enforce_node_allocatable #{unknown.join(", ")}" unless unknown.empty?
        if @enforce.include?("none") && @enforce.length > 1
          raise Error,
                "enforce_node_allocatable \"none\" cannot be combined with other values"
        end

        @system_reserved_cgroup = system_reserved_cgroup
        @kube_reserved_cgroup = kube_reserved_cgroup
        if @enforce.intersect?(%w[system-reserved system-reserved-compressible]) && blank?(system_reserved_cgroup)
          raise Error, "system_reserved_cgroup must be set when enforce_node_allocatable has system-reserved"
        end
        if @enforce.intersect?(%w[kube-reserved kube-reserved-compressible]) && blank?(kube_reserved_cgroup)
          raise Error, "kube_reserved_cgroup must be set when enforce_node_allocatable has kube-reserved"
        end

        @active_pods = active_pods
        @event = event
        @error_handler = error_handler
        @period = period
        @mutex = Mutex.new
        @wake = ConditionVariable.new
        @pending = false
        @last_qos = nil
        @last_written = nil
        @thread = nil
        @stop = false
      end

      def start
        @thread ||= Thread.new do
          until @mutex.synchronize { @stop }
            tick
            wait_for_change
          end
        end
        self
      end

      def stop
        @mutex.synchronize do
          @stop = true
          @wake.broadcast
        end
        @thread&.join(2)
        @thread = nil
        begin
          File.delete(state_path)
        rescue SystemCallError
          nil
        end
        self
      end

      # A Pod was admitted, resized or finished: the QoS weights are
      # recomputed on the manager's thread (the kubelet does so in syncPod).
      def pods_changed
        @mutex.synchronize do
          @pending = true
          @wake.broadcast
        end
      end

      # One pass: publish this node's share, then write the composition.
      def tick(pods = nil)
        requests = qos_requests(pods || Array(@active_pods.call))
        publish(requests)
        peers = live_states
        enforce_node_allocatable(peers)
        update(peers)
      rescue StandardError => error
        @error_handler&.call(error, :qos_cgroups)
      end

      # getNodeAllocatableInternalAbsolute (pods enforced) or
      # internalCapacity: this node's values.
      def node_values
        @enforce.include?("pods") ? subtract(@capacity, sum(@system_reserved, @kube_reserved)) : @capacity
      end

      # The cgroup settings getCgroupConfig derives from the sum of the live
      # nodes' values, each capped at this host's capacity.
      def node_limits(peers = [])
        combined = node_values.dup
        peers.each do |peer|
          next if peer["node"] == @node_name

          Helpers.string_keys(peer["allocatable"] || {}).each do |name, value|
            combined[name] = combined.fetch(name, 0) + Rational(value) if combined.key?(name)
          end
        end
        cgroup_settings(combined.to_h { |name, value| [name, @capacity.key?(name) ? [value, @capacity[name]].min : value] })
      end

      def enforce_node_allocatable(peers = [])
        limits = node_limits(peers)
        return limits if limits == @last_written

        write_settings(@base, limits)
        write_settings(resolve(@system_reserved_cgroup), cgroup_settings(@system_reserved)) if @enforce.include?("system-reserved")
        write_settings(resolve(@kube_reserved_cgroup), cgroup_settings(@kube_reserved)) if @enforce.include?("kube-reserved")
        # enforceExistingCgroup(..., compressibleResources: true): CPU only.
        if @enforce.include?("system-reserved-compressible")
          write_settings(resolve(@system_reserved_cgroup), cgroup_settings(@system_reserved, compressible_only: true))
        end
        if @enforce.include?("kube-reserved-compressible")
          write_settings(resolve(@kube_reserved_cgroup), cgroup_settings(@kube_reserved, compressible_only: true))
        end
        first = @last_written.nil?
        @last_written = limits
        @last_node_limits = limits
        @event&.call("Normal", "NodeAllocatableEnforced", "Updated Node Allocatable limit across pods") if first
        limits
      rescue SystemCallError, Error => error
        @event&.call("Warning", "FailedNodeAllocatableEnforcement",
                     "Failed to update Node Allocatable Limits #{@base.inspect}: #{error.message}")
        raise
      end

      # The CPU requests (millicores) of this node's active Pods per QoS class.
      def qos_requests(pods)
        requests = Hash.new(0)
        pods.each do |pod|
          pod = Helpers.string_keys(pod)
          next if terminal?(pod)

          qos = ResourceHelpers.qos_class(pod)
          cpu = ResourceHelpers.pod_requests(pod)["cpu"]
          next unless cpu

          cores = cpu.respond_to?(:value) ? cpu.value : Rational(cpu)
          requests[qos] += (cores * 1000).ceil
        end
        requests
      end

      # ->(operation, seconds) per cgroup the manager writes
      # (kubelet_cgroup_manager_duration_seconds).
      attr_writer :cgroup_observer

      # setCPUCgroupConfig over every live node's requests.  Returns
      # {qos => cpu.weight} as written.
      def update(peers = nil)
        peers ||= [{"node" => @node_name, "requests" => qos_requests(Array(@active_pods.call))}]
        requests = Hash.new(0)
        peers.each do |peer|
          Helpers.string_keys(peer["requests"] || {}).each { |qos, milli| requests[qos] += Integer(milli) }
        end
        weights = {
          "guaranteed" => shares_to_weight(milli_cpu_to_shares(requests["Guaranteed"])),
          "burstable" => shares_to_weight(milli_cpu_to_shares(requests["Burstable"])),
          "besteffort" => shares_to_weight(MIN_SHARES)
        }
        return weights if weights == @last_qos && weights.keys.all? { |qos| current_weight(qos) == weights[qos] }

        weights.each do |qos, weight|
          directory = File.join(@base, qos)
          next unless File.directory?(directory)

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          write(File.join(directory, "cpu.weight"), weight.to_s)
          begin
            @cgroup_observer&.call("update", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          rescue StandardError
            nil
          end
        end
        @last_qos = weights
        weights
      end

      # MilliCPUToShares (pkg/kubelet/cm/helpers_linux.go).
      def self.milli_cpu_to_shares(milli)
        return MIN_SHARES if milli.zero?

        shares = (milli * SHARES_PER_CPU) / MILLI_CPU_TO_CPU
        shares.clamp(MIN_SHARES, MAX_SHARES)
      end

      # libcontainer cgroups.ConvertCPUSharesToCgroupV2Value.
      def self.shares_to_weight(shares)
        return 0 if shares.zero?

        1 + (((shares - 2) * 9999) / 262_142)
      end

      def milli_cpu_to_shares(milli) = self.class.milli_cpu_to_shares(milli)
      def shares_to_weight(shares) = self.class.shares_to_weight(shares)

      # This node's share, replaced atomically.
      def publish(requests)
        FileUtils.mkdir_p(@state_dir, mode: 0o700)
        state = {"node" => @node_name, "pid" => Process.pid, "start_time" => @start_time,
                 "allocatable" => node_values.transform_values(&:to_s),
                 "requests" => requests.to_h}
        temporary = "#{state_path}.#{Process.pid}.tmp"
        File.write(temporary, JSON.generate(state), perm: 0o600)
        File.rename(temporary, state_path)
      end

      # The published shares whose agent is still the process that wrote
      # them (pid and start time), this node's included; a dead agent's
      # share is removed.
      def live_states
        Dir.glob(File.join(@state_dir, "*.json")).filter_map do |path|
          state = JSON.parse(File.read(path))
          unless state.is_a?(Hash) && live?(state["pid"], state["start_time"])
            File.delete(path)
            next
          end

          state
        rescue JSON::ParserError, SystemCallError
          nil
        end
      end

      private

      def state_path = File.join(@state_dir, "#{@node_name.gsub(/[^A-Za-z0-9_.-]/, "_")}.json")

      def live?(pid, start_time)
        return false unless pid.is_a?(Integer)
        return true if pid == Process.pid

        process_start_time(pid) == start_time
      end

      def process_start_time(pid)
        stat = File.read("/proc/#{Integer(pid)}/stat")
        Integer(stat[(stat.rindex(")") + 1)..].split.fetch(19))
      rescue SystemCallError, ArgumentError, IndexError
        nil
      end

      def wait_for_change
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @period
        @mutex.synchronize do
          until @stop || @pending
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break if remaining <= 0

            @wake.wait(@mutex, remaining)
          end
          @pending = false
        end
      end

      # getCgroupConfigInternal: cpu (as weight), memory, pids and hugepage
      # limits; with +compressible_only+ the CPU alone.
      def cgroup_settings(values, compressible_only: false)
        settings = {}
        settings["cpu.weight"] = shares_to_weight(milli_cpu_to_shares((values["cpu"] * 1000).ceil)).to_s if values.key?("cpu")
        return settings if compressible_only

        settings["memory.max"] = values["memory"].floor.to_s if values.key?("memory")
        settings["pids.max"] = values["pid"].floor.to_s if values.key?("pid")
        values.each do |name, value|
          next unless name.start_with?("hugepages-")

          size = hugetlb_size(name.delete_prefix("hugepages-"))
          settings["hugetlb.#{size}.max"] = value.floor.to_s if size
        end
        settings
      end

      # The cgroup file's page size spelling: 2Mi -> 2MB, 1Gi -> 1GB.
      def hugetlb_size(size)
        bytes = Schema::Quantity.parse(size).value
        return "#{(bytes / (1024**3)).to_i}GB" if bytes >= 1024**3 && (bytes % (1024**3)).zero?
        return "#{(bytes / (1024**2)).to_i}MB" if bytes >= 1024**2 && (bytes % (1024**2)).zero?

        "#{(bytes / 1024).to_i}KB"
      rescue StandardError
        nil
      end

      def write_settings(directory, settings)
        raise Error, "cgroup #{directory} does not exist" unless File.directory?(directory)

        settings.each do |file, value|
          path = File.join(directory, file)
          # A controller the kernel does not offer here (hugetlb on a host
          # without huge pages) has no file to write.
          next unless File.exist?(path) || !file.start_with?("hugetlb.")

          write(path, value)
        end
      end

      def write(path, value)
        File.open(path, File::WRONLY | File::TRUNC) { |file| file.syswrite(value) }
      end

      def current_weight(qos)
        Integer(File.read(File.join(@base, qos, "cpu.weight")).strip)
      rescue SystemCallError, ArgumentError
        nil
      end

      def resolve(cgroup)
        path = cgroup.to_s
        path.start_with?(@root) ? path : File.join(@root, path.delete_prefix("/"))
      end

      def terminal?(pod)
        %w[Succeeded Failed].include?(Helpers.key(Helpers.key(pod, "status", {}), "phase", "").to_s)
      end

      def quantities(map)
        Helpers.string_keys(map || {}).each_with_object({}) do |(name, value), result|
          result[name] = Schema::Quantity.from_json(value.to_s).value
        end
      end

      def sum(*maps)
        maps.each_with_object(Hash.new(0r)) { |map, total| map.each { |name, value| total[name] += value } }
      end

      def subtract(capacity, reserved)
        capacity.to_h { |name, value| [name, [value - reserved.fetch(name, 0), 0].max] }
      end

      def read_pid_max(paths)
        values = paths.filter_map do |path|
          Integer(File.read(path).strip)
        rescue SystemCallError, ArgumentError
          nil
        end
        values.min
      end

      def blank?(value) = value.nil? || value.to_s.empty?
    end
  end
end
