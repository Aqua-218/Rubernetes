# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/network/dns"

class NetworkDNSProjectionTest < Minitest::Test
  DNS = Rubernetes::Network::DNS
  DNSProjectionError = Rubernetes::Network::DNSProjectionError

  def setup
    @dir = Dir.mktmpdir("network-dns-projection")
    @target = File.join(@dir, "pod", "resolv.conf")
    @host = File.join(@dir, "host.conf")
    @resolver = DNS::Resolver.new
    File.write(@host, <<~CONF)
      nameserver 192.0.2.53
      search old.example
      search corp.example. .
      options ndots:1 timeout:2
      options timeout:3
    CONF
  end

  def teardown = FileUtils.remove_entry(@dir)

  def test_empty_explicit_resolver_uses_node_ip_families
    content = @resolver.project_resolv_conf(path: @target, dns_policy: "Default", host_resolv_conf: "", node_ips: %w[2001:db8::1 192.0.2.2])

    assert_equal "nameserver ::1\nnameserver 127.0.0.1\nsearch .\n", content
    assert_equal content, File.read(@target)
  end

  def test_default_merges_host_dns_with_overrides
    config = {nameservers: ["198.51.100.53"], search: ["extra.example"], options: [{name: "ndots", value: "2"}, {name: "rotate"}]}
    content = project("Default", dns_config: config)

    assert_equal <<~CONF, content
      nameserver 192.0.2.53
      nameserver 198.51.100.53
      search corp.example extra.example
      options ndots:2 timeout:3 rotate
    CONF
    assert_equal content, File.read(@target)
  end

  def test_cluster_dns_uses_searches_and_default_ndots
    content = project("ClusterFirst", namespace: "apps", dns_config: {searches: ["corp.example", "more.example"]})

    assert_equal <<~CONF, content
      nameserver 10.96.0.10
      search apps.svc.cluster.local svc.cluster.local cluster.local corp.example more.example
      options ndots:5
    CONF
  end

  def test_host_network_uses_host_dns_unless_cluster_policy_explicitly_opts_in
    assert_equal project("Default"), project("ClusterFirst", host_network: true)
    assert_equal project("ClusterFirst"), project("ClusterFirstWithHostNet", host_network: true)
  end

  def test_nameservers_only_none_does_not_require_a_host_file
    config = {"nameservers" => ["2001:db8::53"]}

    assert_equal "nameserver 2001:db8::53\n", project("None", dns_config: config, host_resolv_conf: File.join(@dir, "absent"))
    error = assert_raises(DNSProjectionError) { project("None") }

    assert_match(/dnsConfig.nameservers is required/, error.message)
  end

  def test_projection_uses_kubelet_limits
    search = (1..33).map { |index| "search#{index}.example" }
    config = {"nameservers" => %w[192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4], "searches" => search}
    content = project("None", dns_config: config)
    servers = content.lines.grep(/^nameserver /).map { |line| line.split.last }

    assert_equal %w[192.0.2.1 192.0.2.2 192.0.2.3], servers
    assert_equal ["search", *search.first(32)], content.lines.grep(/^search /).first.split
  end

  def test_invalid_addresses_cannot_reach_the_projection
    content = project("Default")
    error = assert_raises(DNSProjectionError) do
      project("None", dns_config: {"nameservers" => %w[192.0.2.1 192.0.2.2 192.0.2.3 0.0.0.0]})
    end

    assert_match(/unspecified/, error.message)
    assert_equal content, File.read(@target)

    File.write(@host, "nameserver 127.0.0.1\n")

    assert_raises(DNSProjectionError) { project("Default") }
    assert_equal content, File.read(@target)
  end

  def test_explicit_host_and_target_symlinks_are_rejected
    linked = File.join(@dir, "linked.conf")
    File.symlink(@host, linked)
    error = assert_raises(DNSProjectionError) { project("Default", host_resolv_conf: linked) }

    assert_match(/host resolv.conf must not be a symlink/, error.message)
    refute_path_exists @target

    source_dir_link = File.join(@dir, "source-link")
    File.symlink(@dir, source_dir_link)
    error = assert_raises(DNSProjectionError) { project("Default", host_resolv_conf: File.join(source_dir_link, File.basename(@host))) }

    assert_match(/parent path must not contain symlinks/, error.message)
    refute_path_exists @target

    physical = File.join(@dir, "metadata")
    Dir.mkdir(physical)
    File.symlink(physical, File.join(@dir, "linked-parent"))
    other = File.join(@dir, "linked-parent", "resolv.conf")
    error = assert_raises(DNSProjectionError) { @resolver.project_resolv_conf(path: other) }

    assert_match(/parent path must not contain symlinks/, error.message)
    refute_path_exists File.join(physical, "resolv.conf")
  end

  private

  def project(policy, **)
    @resolver.project_resolv_conf(path: @target, dns_policy: policy, host_resolv_conf: @host, fsync: false, **)
  end
end
