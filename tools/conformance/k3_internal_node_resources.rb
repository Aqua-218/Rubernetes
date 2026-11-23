# frozen_string_literal: true

module Conformance
  # Use aggregate CPU and anonymous resident memory of the node agent and its
  # network worker against the combined kubelet/runtime ceilings. cAdvisor
  # reports memory.stat anon as RSS on cgroup v2. Profile only our daemon PIDs
  # in their shared host cgroup, where summing Pss_Anon avoids counting each
  # fork-shared mapping twice. CPU also includes reaped runtime subprocesses.
  module K3InternalNodeResources
    MONITOR_SECONDS = 20 * 60
    SAMPLE_SECONDS = 10
    CLEANUP_SECONDS = 10 * 60
    LIMITS = {
      0 => {"cpu_p50" => 0.20, "cpu_p95" => 0.40, "resident_anon_bytes" => (200 + 125) * 1024 * 1024}.freeze,
      100 => {"cpu_p50" => 0.45, "cpu_p95" => 1.00, "resident_anon_bytes" => (300 + 350) * 1024 * 1024}.freeze
    }.freeze

    private

    def verify_node_resources(key)
      count = key.end_with?("-idle") ? 0 : 100
      @resource_observations ||= {}
      observation = @resource_observations[count] ||= profile_native_agents(count)
      return observation if key.include?("experimental")

      limits = LIMITS.fetch(count)
      observation.fetch("nodes").each do |name, values|
        limits.each do |metric, ceiling|
          actual = values.fetch(metric)
          raise "#{name} #{metric} uses #{actual}, above the combined limit #{ceiling}" if actual > ceiling
        end
      end
      observation.merge("combined_resource_limits" => limits)
    end

    def profile_native_agents(count)
      processes = native_agents
      with_namespace("resource-#{count}", deletion_timeout: CLEANUP_SECONDS) do |namespace|
        if count.positive?
          processes.each_key do |node|
            create_replication_controller(namespace, node, replicas: count, image: K3InternalContracts::PAUSE, node: node)
          end
          processes.each_key { |node| wait_for_pods(namespace, node, count) }
        end
        before = check_node_summaries(processes.keys, namespace, count)
        started_at = Time.now.utc.iso8601
        observed = monitor_agents(processes)
        finished_at = Time.now.utc.iso8601
        after = check_node_summaries(processes.keys, namespace, count)
        {"pods_per_node" => count, "duration_seconds" => MONITOR_SECONDS, "sample_interval_seconds" => SAMPLE_SECONDS,
         "monitor_started_at" => started_at, "monitor_finished_at" => finished_at,
         "public_summary_before" => before, "public_summary_after" => after, "nodes" => observed}
      end
    end

    def native_agents
      driver = K7ClusterDriver
      nodes = driver.kubectl_object("get", "nodes").fetch("items").select do |node|
        node.dig("spec", "unschedulable") != true && driver.ready_node?(node)
      end
      raise "resource test requires at least one Ready schedulable worker" if nodes.empty?

      processes = driver.processes.to_h { |process| [process.fetch("name"), process] }
      nodes.to_h do |node|
        name = node.dig("metadata", "name")
        process = processes.fetch("agent-#{name}")
        profile = process_configuration(process)["runtime_profile"]
        raise "#{name} is not running the integrated native runtime" unless %w[kernel_isolation host_integration l3].include?(profile)

        [name, process]
      end
    end

    def check_node_summaries(nodes, namespace, count)
      nodes.to_h do |node|
        summary = nil
        K7ClusterDriver.wait_until("#{node} publishes #{count} workload Pod summaries", 180) do
          body = kubectl!("get", "--raw", "/api/v1/nodes/#{node}/proxy/stats/summary")
          summary = JSON.parse(body)
          summary.fetch("pods").count { |pod| pod.dig("podRef", "namespace") == namespace } == count
        end
        cpu = summary.dig("node", "cpu", "usageCoreNanoSeconds")
        memory = summary.dig("node", "memory", "workingSetBytes")
        raise "#{node} returns invalid resource counters" unless cpu.is_a?(Numeric) && memory.is_a?(Numeric)

        [node, {"pod_count" => count, "cpu_core_nanoseconds" => cpu, "memory_working_set_bytes" => memory}]
      end
    end

    def monitor_agents(processes)
      pids = processes.transform_values { |process| K7ClusterDriver.pid_of(process) || raise("agent is not running") }
      profiled_pids = pids.transform_values { |pid| [pid, *network_worker_pids(pid)] }
      histories = processes.transform_values { [] }
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      previous = profiled_pids.transform_values { |members| process_group_usage(members) }
      tick_rate = Etc.sysconf(Etc::SC_CLK_TCK)
      raise "sysconf did not provide the Linux clock tick rate" unless tick_rate.positive?

      1.upto(MONITOR_SECONDS / SAMPLE_SECONDS) do |index|
        wake_at = started + (index * SAMPLE_SECONDS)
        remaining = wake_at - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        sleep remaining if remaining.positive?
        processes.each do |name, process|
          pid = pids.fetch(name)
          raise "#{name} agent restarted during resource monitoring" unless K7ClusterDriver.process_alive?(pid, process)

          sample = process_group_usage(profiled_pids.fetch(name))
          earlier = previous.fetch(name)
          cores = (sample.fetch("cpu_ticks") - earlier.fetch("cpu_ticks")).fdiv(tick_rate * (sample.fetch("time") - earlier.fetch("time")))
          raise "#{name} agent CPU usage decreased" if cores.negative?

          histories.fetch(name) << sample.merge("cpu_cores" => cores)
          previous[name] = sample
        end
      end
      histories.to_h { |name, values| [name, summarize_resource_samples(values).merge("pids" => profiled_pids.fetch(name))] }
    end

    def network_worker_pids(agent)
      File.read("/proc/#{agent}/task/#{agent}/children").split.map(&:to_i).select do |pid|
        File.binread("/proc/#{pid}/cmdline").split("\0").first == "rubernetes-network-worker"
      rescue Errno::ENOENT
        false # A transient sandbox helper may have already exited.
      end
    end

    def process_group_usage(pids)
      samples = pids.map { |pid| process_resource_usage(pid) }
      {"time" => Process.clock_gettime(Process::CLOCK_MONOTONIC),
       "cpu_ticks" => samples.sum { |sample| sample.fetch("cpu_ticks") },
       "resident_anon_bytes" => samples.sum { |sample| sample.fetch("resident_anon_bytes") },
       "rss_bytes" => samples.sum { |sample| sample.fetch("rss_bytes") }}
    end

    def process_resource_usage(pid)
      stat = File.read("/proc/#{pid}/stat").rpartition(") ").last.split
      rss = File.read("/proc/#{pid}/status")[/^VmRSS:\s+(\d+)\s+kB$/, 1]
      resident_anon = File.read("/proc/#{pid}/smaps_rollup")[/^Pss_Anon:\s+(\d+)\s+kB$/, 1]
      {"cpu_ticks" => stat.slice(11, 4).sum(&:to_i), "rss_bytes" => Integer(rss) * 1024,
       "resident_anon_bytes" => Integer(resident_anon) * 1024}
    end

    def summarize_resource_samples(samples)
      cpu = samples.map { |sample| sample.fetch("cpu_cores") }.sort
      {"cpu_p50" => cpu.fetch((cpu.size * 0.50).ceil - 1), "cpu_p95" => cpu.fetch((cpu.size * 0.95).ceil - 1),
       "resident_anon_bytes" => samples.last.fetch("resident_anon_bytes"),
       "rss_bytes" => samples.last.fetch("rss_bytes"), "samples" => samples}
    end
  end
end
