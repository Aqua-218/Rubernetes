# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/node/pod_files"

class PodDNSTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir("pod-dns")
    @resolver = File.join(@dir, "resolv.conf")
    File.write(@resolver, "nameserver 192.0.2.53\nsearch old\nsearch example.org. .\noptions ndots:2 timeout:1\noptions timeout:3\n")
    @metadata = {"name" => "catalog", "namespace" => "shop", "uid" => "u1"}
  end

  def teardown = FileUtils.remove_entry(@dir)

  def config(policy, dns: {}, host: false, ips: [], **args, &)
    writer = Rubernetes::Node::PodFiles.new(resolv_conf: @resolver, **args)
    pod = {"metadata" => @metadata, "spec" => {"dnsPolicy" => policy, "dnsConfig" => dns}}
    writer.dns_config(pod, host_network: host, node_ips: ips, &)
  end

  def test_cluster_and_host_policy_and_resolver_options
    servers = ["10.96.0.10"]

    assert_equal({"servers" => servers, "searches" => %w[shop.svc.cluster.local svc.cluster.local cluster.local example.org],
                  "options" => ["ndots:5"]}, config("ClusterFirstWithHostNet", cluster_dns: servers, host: true))
    assert_equal({"servers" => ["192.0.2.53"], "searches" => ["example.org"], "options" => %w[ndots:2 timeout:3]},
                 config("ClusterFirst", cluster_dns: servers, host: true))
    assert_equal ["example.org"], config("ClusterFirst", cluster_dns: servers, cluster_domain: "").fetch("searches")
    assert_equal ["ndots"], config("None", dns: {"options" => [{"name" => "ndots", "value" => ""}]}).fetch("options")
  end

  def test_empty_resolver_uses_node_families_and_warning_names_the_pod
    warnings = []
    applied = config("ClusterFirst", resolv_conf: "", ips: ["2001:db8::2", "192.0.2.7"]) { |*warning| warnings << warning }

    assert_equal({"servers" => ["::1", "127.0.0.1"], "searches" => ["."], "options" => []}, applied)
    assert_equal([%w[Node MissingClusterDNS], %w[Pod MissingClusterDNS]], warnings.map { |row| row.first(2) })
    assert_includes warnings.last.last, 'pod: "catalog_shop(u1)"'
    assert_equal ["127.0.0.1"], config("Default", resolv_conf: "").fetch("servers")
  end

  def test_search_limits_use_bytes_and_keep_a_full_2048_byte_search
    # Eight 253-byte names, a 16-byte name, and eight separating spaces.
    names = (1..8).map { |i| "#{i}#{"a" * 252}" } + ["z" * 16]

    assert_equal 2048, names.join(" ").bytesize
    warnings = []
    applied = config("None", dns: {"nameservers" => %w[192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4],
                                   "searches" => ["x" * 254, *names, "extra"]}) { |*warning| warnings << warning }

    assert_equal names, applied.fetch("searches")
    assert_equal %w[192.0.2.1 192.0.2.2 192.0.2.3], applied.fetch("servers")
    assert_equal([%w[Pod DNSConfigForming], %w[Pod DNSConfigForming]], warnings.map { |row| row.first(2) })
    assert_includes warnings.last.last, names.join(" ")
  end

  def test_empty_file_is_a_valid_host_configuration
    File.write(@resolver, "")

    assert_equal({"servers" => [], "searches" => [], "options" => []}, config("Default"))
  end

  def test_unreadable_and_invalid_resolver_fail_before_any_policy_is_applied
    assert_raises(Rubernetes::Node::PodFiles::Error) { config("None", resolv_conf: File.join(@dir, "absent")) }
    File.write(@resolver, "nameserver\n")
    assert_raises(Rubernetes::Node::PodFiles::Error) { config("ClusterFirst", cluster_dns: ["10.96.0.10"]) }
  end
end
