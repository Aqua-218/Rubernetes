# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/cluster/cli"
require "rubernetes/rubectl"
require "rubernetes/bootstrap/config"
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

  def test_scale_needs_a_cluster_and_does_not_remove_control_nodes
    Dir.mktmpdir do |root|
      assert_raises(C::Error) { provisioner(root).scale(controls: 3) }

      File.write(File.join(root, "cluster.json"), JSON.generate({"processes" => %w[control-0 control-1 control-2].map do |id|
        {"name" => "apiserver-#{id}", "executable" => "rubernetes-apiserver", "config" => "/x", "pid" => 1}
      end}))

      assert_match(/removing control nodes is not supported/, assert_raises(C::Error) { provisioner(root).scale(controls: 1) }.message)
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
