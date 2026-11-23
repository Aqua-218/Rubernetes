# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/cluster/cli"
require "rubernetes/rubectl"
require "rubernetes/bootstrap/config"
require_relative "../../tools/conformance/cluster"
require "stringio"
require "tmpdir"

# `rubectl cluster up` and the conformance lanes provision through the same
# class; what differs is only the topology they ask for.
class ClusterProvisionerTest < Minitest::Test
  C = Rubernetes::Cluster

  def provisioner(root, **)
    C::Provisioner.new(root: root, name: "unit", **)
  end

  def config(path, process)
    YAML.safe_load_file(path).fetch("processes").fetch(process)
  end

  def test_dead_component_reports_the_last_lines_from_a_large_log
    Dir.mktmpdir do |root|
      path = File.join(root, "scheduler.log")
      File.open(path, "wb") do |io|
        io.seek(16 * 1024 * 1024)
        io.write("older event\nflush failed\nprocess exited\n")
      end
      process = {"pid" => 999_999_999, "name" => "scheduler", "log" => path}
      cluster = provisioner(root)
      error = assert_raises(C::Error) { cluster.send(:raise_on_dead!, [process], "start") }

      assert_equal "cluster processes exited during start: scheduler: flush failed\nprocess exited", error.message
      File.unlink(path)
      missing = assert_raises(C::Error) { cluster.send(:raise_on_dead!, [process], "start") }

      assert_match(/scheduler: no log/, missing.message)
    end
  end

  def test_default_routed_load_balancer_requires_the_pool_and_is_saved_only_on_opt_in
    Dir.mktmpdir do |root|
      pool = ["198.51.100.0/28"]
      process = "rubernetes-controller-manager"
      error = assert_raises(C::Error) { provisioner(root, default_routed_load_balancer: true) }

      assert_match(/requires --load-balancer-pool/, error.message)
      [false, true].each do |enabled|
        cluster = provisioner(root, load_balancer_pool: pool, default_routed_load_balancer: enabled)
        cluster.stub(:selected_controllers, ["service-lb-controller"]) do
          path = cluster.send(:write_controller_config, "kubeconfig", serving_port: 10_257)
          saved = Rubernetes::Bootstrap::Config.load(process_name: process, path: path).process

          assert_equal pool, saved.fetch("load_balancer_pool")
          assert_equal enabled, saved.fetch("default_routed_load_balancer", false)
          refute saved.key?("default_routed_load_balancer") unless enabled
        end
      end
    end
  end

  def test_default_routed_load_balancer_cli_checks_before_provisioning
    cli = lambda do |*argv|
      error = StringIO.new
      status = C::CLI.run(argv, stdout: StringIO.new, stderr: error)
      [status, error.string]
    end
    missing = cli.call("up", "--default-routed-load-balancer")
    wrong_command = cli.call("start", "--default-routed-load-balancer")

    assert_equal 64, missing.first
    assert_match(/requires --load-balancer-pool/, missing.last)
    assert_equal 64, wrong_command.first
    assert_match(/only available for up/, wrong_command.last)
  end

  def test_default_routed_load_balancer_cli_passes_the_pool_and_opt_in_together
    Dir.mktmpdir do |root|
      cli = C::CLI.new(stdout: StringIO.new, stderr: StringIO.new)
      observe_up = lambda do |cluster, _options|
        assert_equal({"load_balancer_pool" => ["198.51.100.0/28"], "default_routed_load_balancer" => true},
                     cluster.send(:routed_load_balancer_section))
        0
      end

      cli.stub(:up, observe_up) do
        assert_equal 0, cli.run(["up", "--root", root, "--default-routed-load-balancer", "--load-balancer-pool", "198.51.100.0/28"])
      end
    end
  end

  def test_manual_config_reserves_classless_services_for_an_external_cloud_controller
    process = "rubernetes-controller-manager"
    section = {"cloud_controller_manager" => "external", "load_balancer_pool" => ["198.51.100.0/28"]}
    config = lambda do |settings|
      Rubernetes::Bootstrap::Config.new(process_name: process,
                                        data: {"version" => 1, "logging" => {"level" => "warn"}, "processes" => {process => settings}}).process
    end

    assert_equal "external", config.call(section).fetch("cloud_controller_manager")
    conflict = assert_raises(Rubernetes::Bootstrap::Config::Error) { config.call(section.merge("default_routed_load_balancer" => true)) }
    invalid = assert_raises(Rubernetes::Bootstrap::Config::Error) { config.call(section.merge("default_routed_load_balancer" => "true")) }

    assert_match(/conflicts with cloud_controller_manager/, conflict.message)
    assert_match(/must be true or false/, invalid.message)
  end

  def test_a_single_control_node_is_a_raft_cluster_of_one
    Dir.mktmpdir do |root|
      cluster = provisioner(root, controls: 1, workers: 1)
      pki = cluster.send(:issue_pki)
      path = cluster.send(:write_apiserver_config, "control-0", {http: {"control-0" => 26_001}, raft: {"control-0" => 26_002}}, pki)
      datastore = config(path, "rubernetes-apiserver").fetch("datastore")

      assert_equal %w[control-0], datastore.fetch("voters")
      assert_empty datastore.fetch("peers")
      assert_equal "unit", datastore.fetch("cluster_id")
    end
  end

  def test_bootstrap_certificates_pass_strict_x509_validation
    Dir.mktmpdir do |root|
      cluster = provisioner(root, controls: 1, workers: 1, identities: :components)
      pki = cluster.send(:issue_pki)
      kubelet = pki.fetch(:identities).fetch("kubelet-serving-worker-0").fetch(:cert)
      verify = lambda do |ca, *leaves|
        trust = OpenSSL::X509::Store.new
        trust.flags = OpenSSL::X509::V_FLAG_X509_STRICT
        trust.add_file(ca)
        leaves.each do |path|
          leaf = OpenSSL::X509::Certificate.new(File.binread(path))

          assert trust.verify(leaf), "#{File.basename(path)}: #{trust.error_string}"
        end
      end

      verify.call(pki.fetch(:ca), pki.fetch(:server), pki.fetch(:admin), kubelet)
      verify.call(pki.fetch(:front_proxy_ca), pki.fetch(:front_proxy))
    end
  end

  def test_only_the_first_worker_attaches_the_host_datapath
    Dir.mktmpdir do |root|
      cluster = provisioner(root, controls: 3, workers: 3)
      attached = cluster.worker_ids.each_with_index.map do |id, index|
        config(cluster.send(:write_proxy_config, id, index, File::NULL), "rubernetes-proxy").fetch("attach")
      end

      assert_equal [true, false, false], attached
    end
  end

  def test_a_dual_stack_cluster_gives_each_node_an_address_per_family
    Dir.mktmpdir do |root|
      cluster = provisioner(root, ip_families: %w[ipv4 ipv6])

      assert_equal %w[10.241.0.1 fd00:d8:1::1], cluster.send(:node_advertise_addresses, 1)
      assert_equal %w[10.96.0.1 fd00:d8:5::1], cluster.send(:service_cluster_ips)
    end
  end

  def test_cluster_dns_publishes_a_local_listener_for_each_node_and_family
    Dir.mktmpdir do |root|
      cluster = provisioner(root, workers: 2, ip_families: %w[ipv4 ipv6])
      service = cluster.send(:cluster_dns_service)

      assert_equal "kube-dns", service.dig("metadata", "name")
      assert_equal "Local", service.dig("spec", "internalTrafficPolicy")
      assert_equal %w[IPv4 IPv6], service.dig("spec", "ipFamilies")
      assert_equal(%w[UDP TCP], service.dig("spec", "ports").map { |p| p.fetch("protocol") })
      slice = cluster.send(:cluster_dns_endpoints, "ipv6", "uid")

      assert_equal "uid", slice.dig("metadata", "ownerReferences", 0, "uid")
      assert_equal "worker-1", slice.dig("endpoints", 1, "nodeName")
      assert_equal ["fd00:d8:1::1"], slice.dig("endpoints", 1, "addresses")
    end
  end

  def test_nat64_prefix_is_passed_to_ipv6_only_workers
    Dir.mktmpdir do |root|
      prefix = "64:ff9b:1::/96"
      assert_raises(C::Error) { provisioner(root, nat64_prefix: prefix) }
      cluster = provisioner(root, ip_families: %w[ipv6], nat64_prefix: prefix)
      path = cluster.send(:write_agent_config, "worker-0", 0, File::NULL, dns_kubeconfig: "/dns/kubeconfig")
      agent = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: path).process

      assert_equal prefix, agent.dig("dns", "nat64_prefix")
      assert_equal "/dns/kubeconfig", agent.dig("dns", "kubeconfig")
    end
  end

  def test_conformance_resolver_is_recorded_and_passed_to_every_worker
    Dir.mktmpdir do |root|
      resolver = File.join(File.realpath(root), "worker-resolv.conf")
      link = File.join(root, "resolver")
      File.write(resolver, "nameserver 192.0.2.53\n")
      File.symlink(resolver, link)
      worker_resolver = Conformance::Cluster.resolver_identity(link)
      profile = Conformance::Lock.profiles.fetch("profiles").first
      cluster = Conformance::Cluster.provisioner(File.join(root, "cluster"), profile, worker_resolver: worker_resolver)

      assert_equal({"path" => resolver, "sha256" => Digest::SHA256.file(resolver).hexdigest}, worker_resolver)
      assert_raises(ArgumentError) { Conformance::Cluster.resolver_identity(root) }
      cluster.worker_ids.each_with_index do |id, index|
        path = cluster.send(:write_agent_config, id, index, File::NULL, dns_kubeconfig: "/dns/kubeconfig")
        agent = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: path).process

        assert_equal resolver, agent.dig("dns", "resolv_conf")
      end
    end
  end

  def test_isolated_workers_get_individual_proxy_and_api_endpoint_configuration
    Dir.mktmpdir do |root|
      cluster = provisioner(root, identities: :components, isolated_worker_networks: true, ip_families: %w[ipv4 ipv6])
      path = cluster.send(:write_proxy_config, "worker-2", 2, File::NULL)
      proxy = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-proxy", path: path).process
      networks = cluster.send(:worker_networks)

      assert proxy.fetch("attach")
      assert_equal({"enabled" => true, "bind_address" => "127.0.0.1", "port" => 10_249,
                    "healthz_bind_address" => "0.0.0.0", "healthz_port" => 10_256}, proxy.fetch("serving"))
      assert_equal %w[10.242.0.1 fd00:d8:2::1], proxy.fetch("node_addresses")
      agent_path = cluster.send(:write_agent_config, "worker-2", 2, File::NULL)
      agent = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: agent_path).process

      assert_equal 10_248, agent.fetch("healthz_port")
      assert_equal 10_250, agent.dig("streaming", "port")
      assert_equal "https://[fd00:d8:ffff:2::1]:6443", networks.endpoint(2, "ipv6", "https://127.0.0.1:6443")
      refute_equal networks.command(0), networks.command(2)
    end
  end

  def test_ipv6_proxy_binds_status_to_loopback_and_health_to_the_node
    Dir.mktmpdir do |root|
      cluster = provisioner(root, identities: :components, isolated_worker_networks: true, ip_families: ["ipv6"])
      path = cluster.send(:write_proxy_config, "worker-0", 0, File::NULL)
      proxy = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-proxy", path: path).process

      assert_equal({"enabled" => true, "bind_address" => "::1", "port" => 10_249,
                    "healthz_bind_address" => "::", "healthz_port" => 10_256}, proxy.fetch("serving"))
    end
  end

  def test_isolated_workers_keep_kubeconfigs_for_their_own_control_address
    Dir.mktmpdir do |root|
      cluster = provisioner(root, identities: :components, isolated_worker_networks: true)
      pki = cluster.send(:issue_pki)
      addresses = %w[https://169.254.128.1:6443 https://169.254.128.5:6443]
      paths = addresses.each_with_index.map do |address, index|
        cluster.send(:component_kubeconfig, address, pki, "kube-proxy", nil, instance: "worker-#{index}")
      end
      configured = paths.map { |path| YAML.safe_load_file(path).dig("clusters", 0, "cluster", "server") }

      assert_equal addresses, configured
    end
  end

  def test_native_release_profiles_isolate_worker_networks_by_default
    profiles = Conformance::Lock.profiles.fetch("profiles")
    cluster = Conformance::Cluster

    profiles.each do |profile|
      assert cluster.isolated_worker_networks?({}, profile)
      refute cluster.isolated_worker_networks?({isolated_worker_networks: false}, profile)
      refute cluster.isolated_worker_networks?({k7_bootstrap: true}, profile)
      refute cluster.isolated_worker_networks?({external_cni_bin_dir: "/opt/cni/bin"}, profile)
    end
  end

  def test_isolated_processes_bypass_inherited_proxy_for_cluster_networks
    networks = C::WorkerNetworks.new("/test/one", [["10.240.0.0/16", "fd00:d8::/48"]])
    inherited = {"NO_PROXY" => "localhost,.example.org", "no_proxy" => "localhost,.example.net"}
    variables = networks.proxy_environment(api_addresses: ["10.250.3.2"], service_cidrs: ["10.96.0.0/12"], environment: inherited)

    assert_equal variables.fetch("NO_PROXY"), variables.fetch("no_proxy")
    assert_equal %w[localhost .example.org .example.net 169.254.128.1 fd00:d8:ffff::1 10.250.3.2 10.240.0.0/16 fd00:d8::/48 10.96.0.0/12],
                 variables.fetch("NO_PROXY").split(",")
  end

  # `up` replaces the cluster directory.  Pointed at a directory that holds
  # anything it did not write, it must stop before touching it.
  def test_up_refuses_a_directory_that_is_not_a_cluster_directory
    Dir.mktmpdir do |parent|
      root = File.join(parent, "home")
      FileUtils.mkdir_p(root)
      File.write(File.join(root, "thesis.tex"), "years of work")

      error = assert_raises(C::Error) { provisioner(root).up }

      assert_match(/not a cluster directory \(found thesis\.tex\)/, error.message)
      assert_equal "years of work", File.read(File.join(root, "thesis.tex"))
    end
  end

  def test_a_cluster_that_was_never_provisioned_has_no_processes
    Dir.mktmpdir do |root|
      cluster = provisioner(root)

      assert_empty cluster.status
      assert_empty cluster.down
      assert_raises(C::Error) { cluster.start }
    end
  end

  def test_terminate_pins_a_cluster_process_until_it_is_reaped
    marker = "cluster-process-#{SecureRandom.hex(8)}"
    pid = Process.spawn(RbConfig.ruby, "-e", "sleep 30", "--", marker)

    assert_nil C::Processes.terminate(pid, "example", "#{marker}-another")
    assert_equal({"name" => "example", "pid" => pid}, C::Processes.terminate(pid, "example", marker))
    refute C::Processes.alive?(pid)
  ensure
    Process.waitpid(pid) if pid && C::Processes.alive?(pid)
  end

  def test_terminate_treats_exit_after_identification_as_complete
    marker = "cluster-process-#{SecureRandom.hex(8)}"
    pid = Process.spawn(RbConfig.ruby, "-e", "sleep 30", "--", marker)
    pidfd_class = Rubernetes::Platform::Linux::Pidfd
    probe = pidfd_class.new
    probe.define_singleton_method(:send_signal) do |**arguments|
      # The remembered process exits while the stopper has it identified.
      Process.kill("TERM", pid)
      Process.waitpid(pid)
      super(**arguments)
    end

    pidfd_class.stub(:new, probe) do
      assert_equal({"name" => "example", "pid" => pid}, C::Processes.terminate(pid, "example", marker))
    end
    refute C::Processes.alive?(pid)
  ensure
    Process.waitpid(pid) if pid && C::Processes.alive?(pid)
  end

  def test_delete_refuses_a_directory_that_is_not_a_cluster_directory
    Dir.mktmpdir do |parent|
      root = File.join(parent, "home")
      FileUtils.mkdir_p(root)
      File.write(File.join(root, "thesis.tex"), "years of work")

      assert_raises(C::Error) { provisioner(root).delete }
      assert_path_exists File.join(root, "thesis.tex")
    end
  end

  # `delete` is usually run by a fresh command line that knows nothing of the
  # topology `up` was given; the bridges it must remove are one per worker.
  def test_a_stored_cluster_keeps_its_shape
    Dir.mktmpdir do |root|
      FileUtils.mkdir_p(File.join(root, "config"))
      3.times { |index| File.write(File.join(root, "config", "agent-worker-#{index}.yml"), "") }
      File.write(File.join(root, "cluster.json"), JSON.generate({"profile" => {"ip_families" => %w[ipv4 ipv6]}, "cgroup_root" => "/sys/fs/cgroup/x"}))
      cluster = provisioner(root, controls: 1, workers: 1)
      cluster.send(:adopt_stored_shape)

      assert_equal %w[worker-0 worker-1 worker-2], cluster.worker_ids
      assert_equal %w[ipv4 ipv6], cluster.families
      assert_equal "/sys/fs/cgroup/x", cluster.cgroup_root
    end
  end

  # A node that joins a running datastore must not be able to vote itself
  # into a quorum with another empty newcomer.
  def test_a_joining_control_node_names_the_clusters_voters_not_itself
    Dir.mktmpdir do |root|
      cluster = provisioner(root, controls: 1, workers: 1)
      pki = cluster.send(:issue_pki)
      template = YAML.safe_load_file(cluster.send(:write_apiserver_config, "control-0", {http: {"control-0" => 26_001}, raft: {"control-0" => 26_002}}, pki))
      addresses = {"control-0" => "127.0.0.1:26002", "control-1" => "127.0.0.1:26004"}
      joining = cluster.send(:control_node_config, template, "control-1", addresses, voters: %w[control-0], port: 26_003)
      settled = cluster.send(:control_node_config, joining, "control-1", addresses, voters: %w[control-0 control-1], port: 26_003)
      datastore = joining.dig("processes", "rubernetes-apiserver", "datastore")

      assert_equal %w[control-0], datastore.fetch("voters")
      assert datastore.fetch("join")
      assert_equal({"control-0" => "127.0.0.1:26002"}, datastore.fetch("peers"))
      assert_equal ["control-1", 26_004, File.join(root, "data", "control-1")], datastore.values_at("node_id", "listen_port", "data_dir")
      assert_equal 26_003, joining.dig("processes", "rubernetes-apiserver", "port")
      refute settled.dig("processes", "rubernetes-apiserver", "datastore").key?("join"), "once a voter, it starts like any other"

      path = cluster.send(:write_config, "apiserver-control-1", joining)
      loaded = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-apiserver", path: path)

      assert loaded.process.dig("datastore", "join"), "the component accepts the configuration it is given"
    end
  end

  def test_scale_needs_a_cluster_and_keeps_one_control_node
    Dir.mktmpdir do |root|
      assert_raises(C::Error) { provisioner(root).scale(controls: 3) }

      File.write(File.join(root, "cluster.json"), JSON.generate({"processes" => %w[control-0 control-1 control-2].map do |id|
        {"name" => "apiserver-#{id}", "executable" => "rubernetes-apiserver", "config" => "/x", "pid" => 1}
      end}))

      assert_match(/at least one control node/, assert_raises(C::Error) { provisioner(root).scale(controls: 0) }.message)
      assert_equal 3, provisioner(root).scale(controls: 3).fetch("processes").length, "already that size: nothing to do"
    end
  end

  def test_component_processes_load_this_library
    arguments = C.load_path_arguments

    assert_equal ["-I", File.join(C::SOURCE_ROOT, "lib")], arguments.first(2)
    assert_predicate arguments.length, :even?
  end

  def run_cli(*argv)
    stdout = StringIO.new
    stderr = StringIO.new
    [C::CLI.run(argv, stdout: stdout, stderr: stderr), stdout.string, stderr.string]
  end

  def test_the_cli_reports_a_missing_cluster
    Dir.mktmpdir do |root|
      status, stdout, = run_cli("status", "--root", root)

      assert_equal 1, status
      assert_includes stdout, "no provisioned cluster at #{root}"
    end
  end

  def test_the_cli_rejects_unknown_commands_and_options
    status, _stdout, stderr = run_cli("explode")

    assert_equal 64, status
    assert_includes stderr, "Usage: rubectl cluster COMMAND"
    assert_equal 64, run_cli("up", "--ip-family", "ipx").first
  end

  def test_rubectl_hands_the_cluster_command_over
    stdout = StringIO.new
    status = Rubernetes::Rubectl::CLI.run(%w[cluster --help], stdout: stdout, stderr: StringIO.new)

    assert_equal 0, status
    assert_includes stdout.string, "provision a new cluster"
  end
end
