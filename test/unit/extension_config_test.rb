# frozen_string_literal: true

require "tempfile"
require_relative "../test_helper"
require "rubernetes/bootstrap/config"
require "rubernetes/cluster"

# Extension objects are Ruby source run inside the control plane, so a
# component loads them only when its own configuration says so -- and a
# cluster brought up with `--extensions` says so in all three.
class ExtensionConfigTest < Minitest::Test
  Config = Rubernetes::Bootstrap::Config
  PROCESSES = %w[rubernetes-apiserver rubernetes-scheduler rubernetes-controller-manager].freeze

  def load_config(process, extensions)
    file = Tempfile.new(["component", ".yml"])
    file.write(YAML.dump({"version" => 1, "logging" => {"level" => "info"}, "processes" => {process => {"extensions" => extensions}}}))
    file.flush
    Config.load(process_name: process, path: file.path)
  ensure
    file&.close
  end

  def test_every_control_plane_component_accepts_the_switch
    PROCESSES.each do |process|
      assert_equal true, load_config(process, {"enabled" => true}).process.dig("extensions", "enabled")
      assert_equal false, load_config(process, {"enabled" => false}).process.dig("extensions", "enabled")
    end
  end

  def test_anything_but_a_boolean_switch_is_rejected
    PROCESSES.each do |process|
      assert_raises(Config::Error) { load_config(process, {"enabled" => "yes"}) }
      assert_raises(Config::Error) { load_config(process, {"enabled" => true, "sandbox" => false}) }
      assert_raises(Config::Error) { load_config(process, true) }
    end
  end

  def test_the_node_components_have_no_such_switch
    assert_raises(Config::Error) { load_config("rubernetes-proxy", {"enabled" => true}) }
  end

  def configs(extensions:)
    Dir.mktmpdir do |root|
      cluster = Rubernetes::Cluster::Provisioner.new(root: root, name: "unit", controls: 1, workers: 1, extensions: extensions)
      pki = cluster.send(:issue_pki)
      cluster.define_singleton_method(:selected_controllers) { |_kubeconfig| [] }
      paths = [cluster.send(:write_apiserver_config, "control-0", {http: {"control-0" => 26_001}, raft: {"control-0" => 26_002}}, pki),
               cluster.send(:write_scheduler_config, "/x/kubeconfig"), cluster.send(:write_controller_config, "/x/kubeconfig"),
               cluster.send(:write_agent_config, "worker-0", 0, "/x/kubeconfig"), cluster.send(:write_proxy_config, "worker-0", 0, "/x/kubeconfig")]
      paths.to_h { |path| [File.basename(path, ".yml"), YAML.safe_load_file(path).fetch("processes").values.first] }
    end
  end

  def test_a_cluster_brought_up_with_extensions_turns_them_on_in_the_control_plane_only
    written = configs(extensions: true)

    %w[apiserver-control-0 scheduler controller-manager].each { |name| assert_equal({"enabled" => true}, written.fetch(name)["extensions"], name) }
    %w[agent-worker-0 proxy-worker-0].each { |name| refute written.fetch(name).key?("extensions"), name }
  end

  def test_a_cluster_brought_up_without_the_flag_loads_no_extensions
    configs(extensions: false).each { |name, config| refute config.key?("extensions"), name }
  end
end
