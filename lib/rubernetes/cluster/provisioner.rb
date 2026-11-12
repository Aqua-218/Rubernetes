# frozen_string_literal: true

module Rubernetes
  module Cluster
    # Brings one cluster directory up, back and down.
    #
    # `up` provisions from nothing: PKI, raft identities, one configuration per
    # process, then the processes in dependency order.  `start` only respawns
    # what `up` left under the root -- same configuration, PKI, raft log and
    # node state -- which is what a host reboot needs.  A component that does
    # not become ready is a failure, never waited out.
    class Provisioner
      include Processes
      include Pki
      include Host
      include Configs
      include Readiness
      include Shrink

      # Everything `up` writes directly under the root.  A directory holding
      # anything else is not a cluster directory and is never wiped.
      OWN_ENTRIES = /\A(?:cluster\.json|config|data|image_manager|(?:bootstrap-)?kubeconfig(?:-.+)?|logs|network|pids|pki|raft-pki|run|runtime)\z/
      IDENTITY_MODES = %i[admin components bootstrap].freeze

      attr_reader :root, :cluster_name, :cluster_id, :control_ids, :worker_ids, :families, :cgroup_root, :ready_timeout

      # identities: :admin runs every component as the cluster admin;
      # :components gives each its own identity as kubeadm provisions them
      # (kubelets as system:node:<name> under the Node authorizer, the kubelet
      # API behind TLS and webhook authorization); :bootstrap additionally
      # joins the workers through a bootstrap token and the CSR API.
      def initialize(root:, name: File.basename(root), cluster_id: name, controls: 3, workers: 3, ip_families: %w[ipv4],
                     cgroup_root: "/sys/fs/cgroup", identities: :admin, ready_timeout: 180, log_levels: {}, force: false,
                     extensions: false, storage: false, descriptor: {})
        raise ArgumentError, "identities must be one of #{IDENTITY_MODES.join(", ")}" unless IDENTITY_MODES.include?(identities)
        raise ArgumentError, "a cluster needs at least one control node and one worker" unless controls.positive? && workers.positive?

        @root = File.expand_path(root)
        @cluster_name = name
        @cluster_id = cluster_id
        @control_ids = Array.new(controls) { |index| "control-#{index}" }.freeze
        @worker_ids = Array.new(workers) { |index| "worker-#{index}" }.freeze
        @families = ip_families.map(&:to_s).freeze
        @cgroup_root = cgroup_root
        @identities = identities
        @ready_timeout = ready_timeout
        @log_levels = log_levels
        @force = force
        @extensions = extensions
        @storage = storage
        @descriptor = descriptor
      end

      def component_identities? = @identities != :admin
      def tls_bootstrap? = @identities == :bootstrap
      def log_level(component) = @log_levels.fetch(component, "info")

      # The configuration section that lets a component load Extension
      # objects -- Ruby source it will evaluate -- or nothing.
      def extensions_section = @extensions ? {"extensions" => {"enabled" => true}} : {}

      # Every "node" of the cluster is this host, which is the one case the
      # in-tree hostPath provisioner is meant for: with it and a default
      # StorageClass, a PersistentVolumeClaim just works.
      def storage_section = @storage ? {"enable_hostpath_provisioner" => true} : {}
      def descriptor_path = File.join(root, "cluster.json")

      # Returns the cluster descriptor (also written to cluster.json); raises
      # after tearing down whatever it had started.
      def up
        exclusively do
          prepare_root!
          provision
        rescue StandardError
          down
          raise
        end
      end

      def start
        exclusively do
          raise Error, "no provisioned cluster at #{root}; run `up` first" unless File.file?(descriptor_path)

          descriptor = adopt_stored_shape
          ensure_cgroup_root!
          restart(descriptor)
        end
      end

      # Stops every process the descriptor and the pid files name; returns the
      # ones that were running.  A pid file names a process by its cluster
      # directory only.
      def down
        remembered = stored_processes.reverse.map { |process| terminate(process.fetch("pid"), process.fetch("name"), process.fetch("config")) }
        strays = Dir[File.join(root, "pids", "*.pid")].map do |path|
          terminate(Integer(File.read(path).strip), File.basename(path, ".pid"), root)
        rescue ArgumentError, SystemCallError
          nil
        end
        (remembered + strays).compact
      end

      # `down`, then everything `up` put on the host: the mounts and the
      # state directory always, and the host-global objects (workload
      # cgroups, namespaces, bridges, firewall rules) unless another cluster
      # in this network namespace is still using them.
      def delete
        exclusively do
          foreign = Dir.children(root).grep_v(OWN_ENTRIES) if File.directory?(root)
          raise Error, "#{root} is not a cluster directory (found #{foreign.first(3).join(", ")}); refusing to remove it" if foreign&.any?

          adopt_stored_shape
          stopped = down
          if other_live_clusters.empty?
            kill_stale_workloads
            purge_stale_namespaces
            purge_stale_bridge_links
            remove_host_network!
          end
          unmount_stale_mounts
          FileUtils.rm_rf(root)
          stopped
        end
      end

      # Grows the control plane of the running cluster to `controls` nodes:
      # each new node is an API server and a voter of the raft datastore.
      # The cluster stays available throughout -- the datastore changes its
      # membership through joint consensus -- and one control node becoming
      # three is what makes it survive the loss of one.
      def scale(controls:)
        exclusively do
          raise Error, "no provisioned cluster at #{root}; run `up` first" unless File.file?(descriptor_path)

          descriptor = JSON.parse(File.binread(descriptor_path))
          current = descriptor.fetch("processes").filter_map { |process| process.fetch("name")[/\Aapiserver-(.+)\z/, 1] }
          return shrink(descriptor, current, controls) if controls < current.length

          added = Array.new(controls - current.length) { |index| "control-#{current.length + index}" }
          added.empty? ? descriptor : grow(descriptor, current, added)
        end
      end

      def status
        stored_processes.map do |process|
          process.slice("name", "pid").merge("alive" => owned?(process.fetch("pid"), process.fetch("config")))
        end
      end

      def kubeconfig = File.join(root, "kubeconfig")

      private

      # start and delete work on a cluster some earlier `up` shaped; what it
      # left on disk, not this object's defaults, says what that shape was.
      # The agent configurations outlive a bring-up that failed before it
      # wrote the descriptor.
      def adopt_stored_shape
        agents = Dir[File.join(root, "config", "agent-worker-*.yml")].length
        @worker_ids = Array.new(agents) { |index| "worker-#{index}" }.freeze if agents.positive?
        descriptor = JSON.parse(File.binread(descriptor_path))
        @families = descriptor.dig("profile", "ip_families")&.map(&:to_s)&.freeze || families
        @cgroup_root = descriptor.fetch("cgroup_root", cgroup_root)
        descriptor
      rescue JSON::ParserError, SystemCallError
        {}
      end

      def grow(descriptor, current, added)
        authority = Rubernetes::Consensus::Identity.read_ca(File.join(root, "raft-pki", "ca"))
        template = YAML.safe_load_file(config_path("apiserver-#{current.first}"))
        datastore = template.dig("processes", "rubernetes-apiserver", "datastore")
        raise Error, "#{root} does not run the raft datastore" unless datastore["type"] == "raft"

        addresses = current.to_h { |id| [id, raft_address(YAML.safe_load_file(config_path("apiserver-#{id}")))] }
        added.each { |id| addresses[id] = "127.0.0.1:#{free_port}" }
        started = added.map do |id|
          bundle = Rubernetes::Consensus::Identity.issue_node(*authority, cluster_id: datastore.fetch("cluster_id"), node_id: id)
          Rubernetes::Consensus::Identity.write_bundle(File.join(root, "raft-pki", id), bundle)
          # An empty newcomer names the running cluster's voters, never itself.
          config = write_config("apiserver-#{id}", control_node_config(template, id, addresses, voters: current, port: free_port))
          spawn_process("apiserver-#{id}", "rubernetes-apiserver", config)
        end
        # The membership change needs the newcomers' votes to finish: one that
        # is not there to be reached would leave the datastore half way.
        added.each { |id| await!("control node #{id}") { listening?(addresses.fetch(id)) || raise_on_dead!(started, "scale") } }
        reconfigure!(current, addresses, current + added)
        # From here every node's own configuration describes the cluster as
        # it is, for the next time the node starts.
        (current + added).each do |id|
          document = YAML.safe_load_file(config_path("apiserver-#{id}"))
          port = document.dig("processes", "rubernetes-apiserver", "port")
          write_config("apiserver-#{id}", control_node_config(document, id, addresses, voters: current + added, port: port))
        end
        pki = {ca: File.join(root, "pki", "ca.crt"), admin: File.join(root, "pki", "admin.crt"), admin_key: File.join(root, "pki", "admin.key")}
        added.zip(started) do |id, process|
          port = YAML.safe_load_file(process.fetch("config")).dig("processes", "rubernetes-apiserver", "port")
          replica = write_kubeconfig("https://127.0.0.1:#{port}", pki, name: "kubeconfig-#{id}")
          await!("apiserver #{id} /readyz") { api_ready?(replica) }
        end
        raise_on_dead!(started, "scale")

        servers, others = descriptor.fetch("processes").partition { |process| process.fetch("executable") == "rubernetes-apiserver" }
        descriptor["processes"] = servers + started + others
        descriptor["scaled_at"] = Time.now.utc.iso8601
        File.write(descriptor_path, JSON.pretty_generate(descriptor))
        descriptor
      end

      def config_path(name) = File.join(root, "config", "#{name}.yml")

      def listening?(address)
        host, port = address.split(":")
        TCPSocket.new(host, Integer(port)).close
        true
      rescue SystemCallError
        false
      end

      def raft_address(document)
        datastore = document.dig("processes", "rubernetes-apiserver", "datastore")
        "#{datastore.fetch("listen_address")}:#{datastore.fetch("listen_port")}"
      end

      # The configuration of control node `id`: another node's, with what is
      # the node's own replaced.
      def control_node_config(template, id, addresses, voters:, port:)
        document = Marshal.load(Marshal.dump(template)).except("console")
        server = document.fetch("processes").fetch("rubernetes-apiserver")
        server["port"] = port
        server["datastore"] = server.fetch("datastore").except("join").merge(
          "node_id" => id, "data_dir" => File.join(root, "data", id), "pki_dir" => File.join(root, "raft-pki", id),
          "listen_port" => Integer(addresses.fetch(id).split(":").last), "voters" => voters,
          "peers" => addresses.except(id)
        )
        server["datastore"]["join"] = true unless voters.include?(id)
        document
      end

      # Asks the datastore's leader, through its console socket, to take the
      # new nodes in.  Which node leads is found by asking each.
      def reconfigure!(current, addresses, voters)
        code = "service.reconfigure_datastore(voters: #{voters.inspect}, peers: #{addresses.except(*current).inspect}); :done"
        refusals = current.map do |id|
          answer = console_eval("apiserver-#{id}", code)
          return true if answer["result"] == ":done"

          "#{id}: #{answer["error"]}"
        end
        raise Error, "no control node could change the datastore's membership (#{refusals.join("; ")})"
      end

      def console_eval(process, code)
        UNIXSocket.open(File.join(root, "run", "#{process}.sock")) do |socket|
          socket.puts(JSON.generate("op" => "eval", "code" => code))
          JSON.parse(socket.gets.to_s)
        end
      rescue SystemCallError, JSON::ParserError => error
        {"error" => "#{error.class}: #{error.message}"}
      end

      def stored_processes
        JSON.parse(File.binread(descriptor_path)).fetch("processes", [])
      rescue JSON::ParserError, SystemCallError
        []
      end

      # `up` rebuilds the cluster directory and `down` empties it of
      # processes, so a second run entering while the first is still working
      # destroys the cluster the other one is building.  One writer at a time;
      # the lock lives beside the root because `up` removes the root itself.
      def exclusively
        FileUtils.mkdir_p(File.dirname(root))
        lock = File.open(File.join(File.dirname(root), ".#{File.basename(root)}.lock"), File::CREAT | File::RDWR, 0o600)
        raise Error, "another run is working on #{root}" unless lock.flock(File::LOCK_EX | File::LOCK_NB)

        yield
      ensure
        lock&.close
      end

      def prepare_root!
        foreign = Dir.children(root).grep_v(OWN_ENTRIES) if File.directory?(root)
        raise Error, "#{root} is not a cluster directory (found #{foreign.first(3).join(", ")}); refusing to replace it" if foreign&.any?

        # A cluster still running under this root keeps its ports (the agents'
        # streaming ports are fixed) and its nodes: the new agents then die on
        # "Address already in use" while the old ones keep the old nodes Ready.
        down
        refuse_to_disturb_other_clusters!
        unmount_stale_mounts
        FileUtils.rm_rf(root)
        FileUtils.mkdir_p(root)

        # Kernel objects outlive the state directory: a namespace or link left
        # by a crashed run makes the next run's identical name look like
        # someone else's resource, and the agent correctly refuses to adopt
        # it.  Only the "rbn" names this provisioner owns are removed.
        kill_stale_workloads
        purge_stale_namespaces
        purge_stale_bridge_links
        ensure_cgroup_root!
      end

      def provision
        pki = issue_pki
        issue_raft_identities(cluster_id)
        ports = allocate_ports
        descriptor = {"schema_version" => 1, "kind" => "rubernetes_cluster",
                      "profile" => {"name" => cluster_name, "ip_families" => families}}.merge(@descriptor)
        descriptor.merge!("root" => root, "cgroup_root" => cgroup_root, "started_at" => Time.now.utc.iso8601, "processes" => [])
        processes = descriptor.fetch("processes")

        control_ids.each do |id|
          processes << spawn_process("apiserver-#{id}", "rubernetes-apiserver", write_apiserver_config(id, ports, pki))
        end
        endpoints = control_ids.map { |id| "https://127.0.0.1:#{ports.fetch(:http).fetch(id)}" }
        descriptor["endpoint"] = endpoints.first
        descriptor["kubeconfig"] = write_kubeconfig(endpoints.first, pki)
        # One Ruby API server is one core.  With every component on control-0
        # that replica carried the whole control plane while the others idled;
        # the components are spread over the replicas, as a real cluster
        # spreads them behind its load balancer.  The admin keeps control-0.
        replicas = control_ids.zip(endpoints).map do |id, endpoint|
          {endpoint: endpoint, kubeconfig: write_kubeconfig(endpoint, pki, name: "kubeconfig-#{id}")}
        end
        replicas.zip(control_ids) { |replica, id| await!("apiserver #{id} /readyz") { api_ready?(replica.fetch(:kubeconfig)) } }
        apply_coredns_rbac!(kubeconfig) if pki[:identities]
        apply!(kubeconfig, {"items" => [DEFAULT_STORAGE_CLASS]}, "the default StorageClass") if @storage
        bootstrap_token = tls_bootstrap? ? create_bootstrap_token!(kubeconfig) : nil

        scheduler = replicas[1 % replicas.length]
        processes << spawn_process("scheduler", "rubernetes-scheduler",
                                   write_scheduler_config(component_kubeconfig(scheduler.fetch(:endpoint), pki, "kube-scheduler",
                                                                               scheduler.fetch(:kubeconfig))))
        controllers = replicas[2 % replicas.length]
        processes << spawn_process("controller-manager", "rubernetes-controller-manager",
                                   write_controller_config(component_kubeconfig(controllers.fetch(:endpoint), pki,
                                                                                "kube-controller-manager", controllers.fetch(:kubeconfig)),
                                                           service_account_credentials: !pki[:identities].nil?,
                                                           discovery_kubeconfig: controllers.fetch(:kubeconfig)))
        worker_ids.each_with_index do |id, index|
          processes.concat(spawn_node(id, index, replicas[(index + 1) % replicas.length], pki, bootstrap_token))
        end

        await!("#{worker_ids.length} Ready nodes") { ready_nodes(kubeconfig) >= worker_ids.length }
        # A Pod cannot be created before its namespace has a ServiceAccount;
        # "ready" must mean the first `kubectl run` works.
        await!("the default ServiceAccount") { stored?(kubeconfig, "/api/v1/namespaces/default/serviceaccounts/default") }
        # A component that died after spawning (a proxy whose attach failed, a
        # controller whose loop crashed) must not hide behind Ready nodes.
        raise_on_dead!(processes, "bring-up")

        descriptor["ready_at"] = Time.now.utc.iso8601
        descriptor["passed"] = true
        File.write(descriptor_path, JSON.pretty_generate(descriptor))
        descriptor
      end

      def spawn_node(id, index, replica, pki, bootstrap_token)
        endpoint = replica.fetch(:endpoint)
        bootstrap = if bootstrap_token
                      {"kubeconfig" => File.join(root, "runtime", id, "kubelet.conf"),
                       "bootstrap_kubeconfig" => write_bootstrap_kubeconfig(endpoint, pki, id, bootstrap_token),
                       "rotate_certificates" => true, "cert_dir" => File.join(root, "runtime", id, "pki")}
                    end
        agent = write_agent_config(id, index, component_kubeconfig(endpoint, pki, "node-#{id}", replica.fetch(:kubeconfig)),
                                   dns_kubeconfig: pki[:identities] ? component_kubeconfig(endpoint, pki, "coredns", nil) : nil,
                                   pki: pki, bootstrap: bootstrap)
        proxy = write_proxy_config(id, index, component_kubeconfig(endpoint, pki, "kube-proxy", replica.fetch(:kubeconfig)))
        [spawn_process("agent-#{id}", "rubernetes-agent", agent), spawn_process("proxy-#{id}", "rubernetes-proxy", proxy)]
      end

      # The datastore, the node ledgers and every configuration file live
      # under the root, so a provisioned cluster only needs its processes
      # again.  They come back in the order `up` starts them: the datastore
      # quorum before its clients, the control loops before the nodes.
      def restart(descriptor)
        stored = descriptor.fetch("processes")
        live = stored.select { |process| owned?(process.fetch("pid"), process.fetch("config")) }
        raise Error, "#{root} is running (#{live.map { |process| process.fetch("name") }.join(", ")}); bring it down first" unless live.empty?

        respawn = ->(process) { spawn_process(process.fetch("name"), process.fetch("executable"), process.fetch("config")) }
        servers, clients = stored.partition { |process| process.fetch("executable") == "rubernetes-apiserver" }
        respawned = servers.map(&respawn)
        # Every replica, not just the one the admin kubeconfig names: the
        # scheduler and the proxies talk to the others, and started against a
        # replica still opening its port they exited on the first refused
        # connection, failing the whole start.
        servers.each do |server|
          replica = File.join(root, server.fetch("name").sub("apiserver-", "kubeconfig-"))
          await!("#{server.fetch("name")} /readyz") { api_ready?(File.file?(replica) ? replica : kubeconfig) }
        end
        since = Time.now.utc
        respawned.concat(clients.map(&respawn))
        agents = clients.count { |process| process.fetch("executable") == "rubernetes-agent" }
        await!("#{agents} Ready nodes") { ready_nodes(kubeconfig, since: since) >= agents }
        raise_on_dead!(respawned, "start")

        descriptor["processes"] = respawned
        descriptor["restarted_at"] = Time.now.utc.iso8601
        File.write(descriptor_path, JSON.pretty_generate(descriptor))
        descriptor
      end

      def raise_on_dead!(processes, phase)
        dead = processes.reject { |process| alive?(process.fetch("pid")) }
        return if dead.empty?

        details = dead.map do |process|
          log = process.fetch("log")
          "#{process.fetch("name")}: #{File.file?(log) ? File.readlines(log).last(2).join.strip[0, 300] : "no log"}"
        end
        raise Error, "cluster processes exited during #{phase}: #{details.join(" | ")}"
      end
    end
  end
end
