# frozen_string_literal: true

require_relative "../platform/linux/kubelet_cgroup_layout"

module Rubernetes
  module Cluster
    # Host-global leftovers of earlier runs, and the processes of this one.
    module Host
      def purge_stale_namespaces
        output = IO.popen(%w[ip netns list], err: File::NULL, &:read).to_s
        output.each_line do |line|
          name = line.split.first.to_s
          next unless name.start_with?("rbn-")

          system("ip", "netns", "delete", name, out: File::NULL, err: File::NULL)
        end
      rescue SystemCallError
        nil
      end

      # Container workloads do not die with the agent that started them -- they
      # are in their own PID namespaces under the runtime's cgroup -- so a run
      # that ended without an orderly teardown leaves them running, holding their
      # network namespaces and every address in them.  cgroup.kill (cgroup v2)
      # kills the whole subtree in one step; nothing else on the host runs
      # under the runtime's cgroup.
      def workload_cgroup
        File.join(cgroup_root, "rubernetes")
      end

      # A cgroup root below the host's needs the agents' controllers delegated
      # to it (cgroup v2 delegates nothing by default); the host root already
      # has them.
      def ensure_cgroup_root!
        return if cgroup_root == "/sys/fs/cgroup"

        FileUtils.mkdir_p(cgroup_root)
        parent = File.dirname(cgroup_root)
        available = File.read(File.join(parent, "cgroup.controllers")).split
        wanted = %w[cpu cpuset memory pids io hugetlb] & available
        [parent, cgroup_root].each do |directory|
          enabled = File.read(File.join(directory, "cgroup.subtree_control")).split
          missing = wanted - enabled
          File.write(File.join(directory, "cgroup.subtree_control"), missing.map { |name| "+#{name}" }.join(" ")) unless missing.empty?
        end
        # The QoS cgroup manager expects the agents' hierarchy to exist (on the
        # host root it is left over from earlier runs).
        FileUtils.mkdir_p(workload_cgroup)
      end

      # A volume mount whose release never finished (the agent was killed, or
      # the unmount was reported ambiguous) stays in the kernel after the state
      # directory is removed: removing the directory tree then reaches through a
      # bind mount into the volume it was bound from, and the leftover tmpfs
      # keeps Pod data of a run that no longer exists.  Every mount below the
      # cluster root belongs to a run that is over by the time `up` runs;
      # deepest first, because a bind sits on the stage it was bound from.
      def unmount_stale_mounts
        prefix = "#{File.expand_path(root)}/"
        targets = File.readlines("/proc/self/mountinfo").filter_map do |line|
          fields = line.split
          target = fields[4].to_s.gsub(/\\(\d{3})/) { ::Regexp.last_match(1).to_i(8).chr }
          target if target.start_with?(prefix)
        end
        targets.sort_by { |target| [-target.count("/"), target] }.each do |target|
          system("umount", target, out: File::NULL, err: File::NULL) ||
            system("umount", "-l", target, out: File::NULL, err: File::NULL)
        end
        targets.length
      rescue SystemCallError
        0
      end

      def kill_stale_workloads
        cleanup_kubelet_workload_cgroups
        control = File.join(workload_cgroup, "cgroup.kill")
        return unless File.exist?(control)

        File.write(control, "1")
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
        until Dir.glob(File.join(workload_cgroup, "**", "cgroup.procs")).all? { |path| File.read(path).strip.empty? }
          break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

          sleep 0.2
        end
        remove_stale_cgroup_directories
      rescue SystemCallError
        nil
      end

      # kubepods can contain work from another kubelet. Target only exact
      # claims from this stopped cluster's journals, including kernel identity.
      def cleanup_kubelet_workload_cgroups
        layout = Platform::Linux::KubeletCgroupLayout.new(cgroup_root)
        Dir.glob(File.join(root, "runtime", "worker-*")).each do |node|
          layout.clear_reservations(layout.class.reservation_owner(File.basename(node)))
        end
        paths = Dir.glob(File.join(root, "runtime", "worker-*", "ledger.jsonl"))
        return if paths.empty?

        require_relative "../runtime/native"
        adapter = Platform::Linux::CgroupV2.new(root: cgroup_root, kubelet_layout: layout)
        paths.each do |path|
          journal = Runtime::Native::Support::RollbackJournal.new(path)
          ledger = Runtime::Native::Support::OwnershipLedger.new(journal: journal)
          ledger.resources.each do |claim|
            next unless claim["kind"] == "cgroup"

            metadata = claim.fetch("metadata")
            handle = layout.handle(metadata["path"].to_s)
            next unless handle && handle.identity == claim["identity"] && File.directory?(handle.path)
            next unless File.stat(handle.path).ino == metadata["cgroup_inode"]

            adapter.kill(handle)
            adapter.remove(handle)
          end
        end
      end

      # Killing leaves the Pod and container cgroup directories behind (only an
      # agent that is alive removes them); a thousand of them accumulated over a
      # day of rebuilds.  Children go before parents, the QoS tiers stay.
      def remove_stale_cgroup_directories
        Dir.glob(File.join(workload_cgroup, "*", "*", "**", "")).sort_by { |path| -path.count("/") }.each do |path|
          Dir.rmdir(path)
        rescue SystemCallError
          nil
        end
      end

      # A Pod's host-side veth outlives its agent when the agent is killed: the
      # Pod's namespace keeps the pair alive and the link stays enslaved to the
      # node bridge, still answering ARP for its old address.  The next run's IPAM
      # hands that same address to a new Pod, and traffic for it reaches the dead
      # Pod's namespace instead -- "Connection refused" from a Pod that is Running
      # and listening.  Every link on a bridge this provisioner owns (rbn0..N) is
      # a leftover by the time `up` runs, so it is removed; deleting the host end
      # of a veth deletes the pair.
      # `up` owns the host-global objects of its profile (the rbn0..2 bridges
      # and their veths, the cgroup tree, the rbn-* namespaces): the purges
      # below would take them from any OTHER cluster of the same profile that is
      # alive on this host (2026-09-30: an `up` for /srv/rbn-m8 deleted every
      # Pod veth of the /srv/rbn-app GitLab cluster).  Refuse unless forced,
      # and say which cluster is in the way; a separate network namespace +
      # cgroup root is the supported way to run two instances.
      def refuse_to_disturb_other_clusters!
        return if @force

        live = other_live_clusters
        return if live.empty?

        names = live.map { |entry| "#{entry[:root]} (#{entry[:alive]} live processes)" }.join(", ")
        raise Error, "another cluster is alive on this host: #{names}; " \
                     "bring it down first, run this instance in its own network namespace, " \
                     "or force the bring-up to take over its bridges and workloads"
      end

      def other_live_clusters
        Dir.glob(KNOWN_CLUSTER_GLOBS).uniq.filter_map do |path|
          other_root = File.dirname(path)
          next if other_root == root || other_root.start_with?("#{root}/")

          descriptor = begin
            JSON.parse(File.binread(path))
          rescue JSON::ParserError, SystemCallError
            next
          end
          # Only a cluster whose bridges live in THIS network namespace can be
          # disturbed; one brought up inside its own netns has its own rbnN.
          next unless same_network_namespace?(descriptor)

          alive = descriptor.fetch("processes", []).count { |process| owned?(process.fetch("pid"), process.fetch("config")) }
          {root: other_root, alive: alive} if alive.positive?
        end
      end

      def same_network_namespace?(descriptor)
        pid = descriptor.fetch("processes", []).find { |process| owned?(process.fetch("pid"), process.fetch("config")) }&.fetch("pid")
        return false if pid.nil?

        File.readlink("/proc/#{pid}/ns/net") == File.readlink("/proc/self/ns/net")
      rescue SystemCallError
        false
      end

      def purge_stale_bridge_links
        worker_ids.each_index do |index|
          bridge = "rbn#{index}"
          output = IO.popen(["ip", "-o", "link", "show", "master", bridge], err: File::NULL, &:read).to_s
          output.each_line do |line|
            name = line.split(":", 3)[1].to_s.strip.split("@").first.to_s
            next if name.empty?

            system("ip", "link", "delete", name, out: File::NULL, err: File::NULL)
          end
          system("ip", "neigh", "flush", "dev", bridge, out: File::NULL, err: File::NULL)
        end
      rescue SystemCallError
        nil
      end

      # What a cluster of this shape leaves in the host's network once its
      # processes are gone: the forwarding and egress rules for its Pod
      # CIDRs, the service proxy and network policy tables and the node
      # bridges.
      def remove_host_network!
        cidrs = worker_ids.each_index.flat_map { |index| families.map { |family| pod_cidr(index, family) } }
        Network::HostForward.new.remove!(cidrs, chain: true)
        %w[rubernetes rubernetes_policy].each do |table|
          system("nft", "delete", "table", "inet", table, out: File::NULL, err: File::NULL)
        end
        worker_ids.each_index { |index| system("ip", "link", "delete", "rbn#{index}", out: File::NULL, err: File::NULL) }
      rescue SystemCallError
        nil
      end

      def gc_environment
        GC_ENVIRONMENT.to_h { |name, value| [name, ENV.fetch(name, value)] }
      end

      def spawn_process(name, executable, config)
        FileUtils.mkdir_p([File.join(root, "logs"), File.join(root, "pids")])
        log = File.join(root, "logs", "#{name}.log")
        # glibc gives every thread that allocates concurrently its own 64 MB
        # malloc arena (up to 8 x cores).  A node agent runs a thread per Pod,
        # and its arenas alone held gigabytes resident after a conformance
        # round; two arenas are plenty for a Ruby process, whose object heap
        # is not malloc'd.
        environment = {"MALLOC_ARENA_MAX" => ENV.fetch("MALLOC_ARENA_MAX", "2")}.merge(gc_environment)
        if isolated_worker_networks?
          api_addresses = families.map { |family| host_advertise_address(family) }
          environment.merge!(worker_networks.proxy_environment(api_addresses: api_addresses, service_cidrs: service_cidrs))
        end
        command = if @bin_dir
                    [File.join(@bin_dir, executable)]
                  else
                    [RbConfig.ruby, *Cluster.load_path_arguments, File.join(SOURCE_ROOT, "exe", executable)]
                  end
        if isolated_worker_networks? && (worker = name[/\A(?:agent|proxy)-worker-(\d+)\z/, 1])
          command = worker_networks.process_command(Integer(worker), command)
        end
        pid = Process.spawn(environment, *command, "--config", config,
                            # Its own process group: the cluster must outlive the
                            # shell that started it, and a signal aimed at that
                            # shell must not take half the control plane with it.
                            out: [log, "a"], err: [log, "a"], chdir: SOURCE_ROOT, pgroup: true)
        File.write(File.join(root, "pids", "#{name}.pid"), pid.to_s)
        {"name" => name, "executable" => executable, "config" => config, "pid" => pid, "log" => log}
      end
    end
  end
end
