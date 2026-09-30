# frozen_string_literal: true

require_relative "../test_helper"
require "tempfile"
require "rubernetes/bootstrap/config"

# rubernetes-agent configuration keys the kubelet's node features need:
# `dra` (plugin registry, DRA state, CDI spec dirs) and
# `enforce_node_allocatable` with its reserved-cgroup requirements
# (ValidateKubeletConfiguration).
class AgentNodeConfigValidationTest < Minitest::Test
  Config = Rubernetes::Bootstrap::Config

  def load(agent_yaml)
    Tempfile.create(["rubernetes", ".yml"]) do |file|
      file.write("processes:\n  rubernetes-agent:\n#{agent_yaml.gsub(/^/, "    ")}\n")
      file.flush
      Config.load(process_name: "rubernetes-agent", path: file.path)
    end
  end

  def error_for(agent_yaml)
    assert_raises(Config::Error) { load(agent_yaml) }.message
  end

  def test_dra_is_a_known_agent_key_and_is_validated
    assert_includes Config::AGENT_KEYS, "dra"
    config = load(<<~YAML)
      node_name: n1
      dra:
        enabled: true
        plugins_registry: /var/lib/rubernetes/plugins_registry
        state_dir: /var/lib/rubernetes/dra
        cdi_spec_dirs: [/etc/cdi, /var/run/cdi]
    YAML
    assert_equal ["/etc/cdi", "/var/run/cdi"], config.to_h.dig("processes", "rubernetes-agent", "dra", "cdi_spec_dirs")

    assert_match(/rubernetes-agent.dra has unknown fields: bogus/, error_for("node_name: n1\ndra:\n  bogus: 1"))
    assert_match(/rubernetes-agent.dra.enabled must be a boolean/, error_for("node_name: n1\ndra:\n  enabled: yes please"))
    assert_match(/rubernetes-agent.dra.state_dir must be an absolute path/, error_for("node_name: n1\ndra:\n  state_dir: relative/dir"))
    assert_match(/rubernetes-agent.dra.plugins_registry must be an absolute path/, error_for("node_name: n1\ndra:\n  plugins_registry: 7"))
    assert_match(/rubernetes-agent.dra.cdi_spec_dirs must be a list of absolute paths/,
                 error_for("node_name: n1\ndra:\n  cdi_spec_dirs: /etc/cdi"))
    assert_match(/rubernetes-agent.dra.cdi_spec_dirs must be a list of absolute paths/,
                 error_for("node_name: n1\ndra:\n  cdi_spec_dirs: [etc/cdi]"))
    assert_match(/rubernetes-agent.dra must be a mapping/, error_for("node_name: n1\ndra: true"))
  end

  def test_enforce_node_allocatable_keys_and_their_reserved_cgroups
    load("node_name: n1\nenforce_node_allocatable: [pods]")
    load("node_name: n1\nenforce_node_allocatable: [pods, system-reserved-compressible]\nsystem_reserved_cgroup: /system.slice")
    load("node_name: n1\nenforce_node_allocatable: [kube-reserved-compressible]\nkube_reserved_cgroup: /kube.slice")

    assert_match(/must be a list of pods, system-reserved, kube-reserved, system-reserved-compressible, kube-reserved-compressible or none/,
                 error_for("node_name: n1\nenforce_node_allocatable: [everything]"))
    assert_match(/system_reserved_cgroup is required when enforce_node_allocatable has system-reserved-compressible/,
                 error_for("node_name: n1\nenforce_node_allocatable: [system-reserved-compressible]"))
    assert_match(/kube_reserved_cgroup is required when enforce_node_allocatable has kube-reserved/,
                 error_for("node_name: n1\nenforce_node_allocatable: [kube-reserved]"))
    assert_match(/system-reserved and system-reserved-compressible cannot both be set/,
                 error_for("node_name: n1\nenforce_node_allocatable: [system-reserved, system-reserved-compressible]\nsystem_reserved_cgroup: /s"))
    assert_match(/none cannot be combined/, error_for("node_name: n1\nenforce_node_allocatable: [none, pods]"))
    assert_match(/pods requires cgroups_per_qos/, error_for("node_name: n1\nenforce_node_allocatable: [pods]\ncgroups_per_qos: false"))
  end
end
