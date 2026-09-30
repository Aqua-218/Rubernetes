# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"

# Two Beta (default-on) kubelet features the node ignored:
# EnvFiles -- env[].valueFrom.fileKeyRef reads a variable from a file in a Pod
# volume (kubelet util/env ParseEnv; tools/differential/env_file_differential.rb
# compares the parser with upstream's) -- and HostnameOverride, with the
# setHostnameAsFQDN UTS name and upstream's hostname truncation.
class EnvFilesAndHostnameOverrideTest < Minitest::Test
  Node = Rubernetes::Node

  def setup
    @dir = Dir.mktmpdir("rbn-envfile-")
    @volume = File.join(@dir, "config")
    FileUtils.mkdir_p(@volume)
    @spec = Node::ContainerSpec.new(node_name: "n")
  end

  def teardown = FileUtils.rm_rf(@dir)

  def pod(spec = {})
    {"metadata" => {"name" => "web-0", "namespace" => "ns", "uid" => "u1"},
     "spec" => {"containers" => [{"name" => "app", "image" => "x"}]}.merge(spec)}
  end

  def environment(env)
    container = {"name" => "app", "image" => "x", "env" => env}
    built = @spec.build(pod: pod, container: container, category: :application,
                        volumes: {"mounts" => {"config" => {"path" => @volume}}})
    Array(built["env"] || built["environment"]).to_h { |entry| [entry["name"], entry["value"]] }
  end

  def file_ref(key, path: "vars.env", volume: "config", optional: nil)
    reference = {"volumeName" => volume, "path" => path, "key" => key}
    reference["optional"] = optional unless optional.nil?
    {"name" => key, "valueFrom" => {"fileKeyRef" => reference}}
  end

  def test_a_file_key_ref_reads_the_variable_from_the_volume
    File.write(File.join(@volume, "vars.env"), "# written by the init container\nDB_HOST='db.internal'\nMOTD='two\nlines' # note\n")
    env = environment([file_ref("DB_HOST"), file_ref("MOTD")])

    assert_equal "db.internal", env["DB_HOST"]
    assert_equal "two\nlines", env["MOTD"]
  end

  def test_a_missing_key_fails_unless_optional
    File.write(File.join(@volume, "vars.env"), "OTHER='1'\n")
    error = assert_raises(Node::ContainerSpec::ConfigError) { environment([file_ref("ABSENT")]) }
    assert_match(/environment variable key "ABSENT" not found in file/, error.message)
    refute environment([file_ref("ABSENT", optional: true)]).key?("ABSENT")
  end

  def test_a_malformed_or_missing_file_and_an_unknown_volume_fail
    File.write(File.join(@volume, "vars.env"), "KEY = 'spaced'\n")

    assert_equal "couldn't parse env file", assert_raises(Node::ContainerSpec::ConfigError) { environment([file_ref("KEY")]) }.message
    assert_equal "couldn't parse env file",
                 assert_raises(Node::ContainerSpec::ConfigError) {
                   environment([file_ref("KEY", path: "nope.env", optional: true)])
                 }.message
    error = assert_raises(Node::ContainerSpec::ConfigError) { environment([file_ref("KEY", volume: "other")]) }
    assert_equal %(cannot find the volume "other" referenced by FileKeyRef), error.message
  end

  def test_the_path_cannot_leave_the_volume
    File.write(File.join(@dir, "secret.env"), "KEY='outside'\n")
    File.symlink("/../secret.env", File.join(@volume, "link.env"))
    File.write(File.join(@volume, "secret.env"), "KEY='inside'\n")

    assert_equal "inside", environment([file_ref("KEY", path: "../secret.env")])["KEY"]
    assert_equal "inside", environment([file_ref("KEY", path: "link.env")])["KEY"], "an absolute link resolves inside the volume"
  end

  # containerd CRI appends HOSTNAME=<sandbox hostname> to every container's
  # environment; Gitaly's config template reads .Env.HOSTNAME.
  def test_hostname_is_in_every_container_environment
    assert_equal "web-0", environment([])["HOSTNAME"]
    container = {"name" => "app", "image" => "x", "env" => [{"name" => "HOSTNAME", "value" => "user-set"}]}
    built = @spec.build(pod: pod("hostname" => "h", "subdomain" => "svc"), container: container, category: :application,
                        volumes: {"mounts" => {"config" => {"path" => @volume}}})
    env = Array(built["env"]).to_h { |entry| [entry["name"], entry["value"]] }

    assert_equal "h", env["HOSTNAME"], "the sandbox hostname wins, as containerd appends it last"
  end

  # runc setupUser: HOME defaults to the user's /etc/passwd home, "/" without
  # an entry; a HOME the Pod or image sets wins.
  def test_home_defaults_to_the_passwd_home_of_the_container_user
    Dir.mktmpdir do |rootfs|
      FileUtils.mkdir_p(File.join(rootfs, "etc"))
      File.write(File.join(rootfs, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh\ngit:x:1000:1000::/var/opt/gitlab:/bin/sh\n")
      image = {"rootfs" => rootfs, "env" => {}}
      container = {"name" => "app", "image" => "x", "command" => ["/bin/sh"], "securityContext" => {"runAsUser" => 1000}}
      env = @spec.build(pod: pod, container: container, category: :application, resolved_image: image,
                        volumes: {"mounts" => {"config" => {"path" => @volume}}})["env"].to_h { |e| [e["name"], e["value"]] }

      assert_equal "/var/opt/gitlab", env["HOME"]

      container["securityContext"] = {"runAsUser" => 4242}
      env = @spec.build(pod: pod, container: container, category: :application, resolved_image: image,
                        volumes: {"mounts" => {"config" => {"path" => @volume}}})["env"].to_h { |e| [e["name"], e["value"]] }

      assert_equal "/", env["HOME"], "no passwd entry"

      container["env"] = [{"name" => "HOME", "value" => "/custom"}]
      env = @spec.build(pod: pod, container: container, category: :application, resolved_image: image,
                        volumes: {"mounts" => {"config" => {"path" => @volume}}})["env"].to_h { |e| [e["name"], e["value"]] }

      assert_equal "/custom", env["HOME"]

      image["env"] = {"HOME" => "/from-image"}
      container.delete("env")
      env = @spec.build(pod: pod, container: container, category: :application, resolved_image: image,
                        volumes: {"mounts" => {"config" => {"path" => @volume}}})["env"].to_h { |e| [e["name"], e["value"]] }

      assert_equal "/from-image", env["HOME"]
    end
  end

  def test_hostname_override_replaces_the_name_and_domain
    files = Node::PodFiles.new(cluster_domain: "cluster.local")
    subdomained = pod("hostname" => "h", "subdomain" => "svc")

    assert_equal ["h", "svc.ns.svc.cluster.local"], Node::PodHostname.generate(subdomained, cluster_domain: "cluster.local")
    overridden = pod("hostname" => "h", "subdomain" => "svc", "hostnameOverride" => "custom.example")

    assert_equal ["custom.example", ""], Node::PodHostname.generate(overridden, cluster_domain: "cluster.local")
    assert_equal "custom.example", @spec.pod_hostname(overridden)
    hosts = files.hosts_content(overridden, pod_ips: ["10.0.0.5"], host_network: false)

    assert_includes hosts, "10.0.0.5\tcustom.example\n"
  end

  def test_set_hostname_as_fqdn_sets_the_uts_name_and_limits_it
    fqdn = pod("hostname" => "h", "subdomain" => "svc", "setHostnameAsFQDN" => true)

    assert_equal "h.svc.ns.svc.cluster.local", @spec.pod_hostname(fqdn)
    hosts = Node::PodFiles.new(cluster_domain: "cluster.local").hosts_content(fqdn, pod_ips: ["10.0.0.5"], host_network: false,
                                                                                    hostname: @spec.pod_hostname(fqdn))

    assert_includes hosts, "10.0.0.5\th.svc.ns.svc.cluster.local\th\n", "/etc/hosts keeps the short name"
    long = pod("hostname" => "h" * 40, "subdomain" => "svc", "setHostnameAsFQDN" => true)
    error = assert_raises(Node::PodHostname::Error) { @spec.pod_hostname(long) }
    assert_match(/FQDN .* is too long \(64 characters is the max, 65 characters requested\)/, error.message)
  end

  def test_a_long_name_is_truncated_without_a_trailing_dash
    name = "#{"a" * 62}-b"

    assert_equal "a" * 62, Node::PodHostname.truncate("p", name)
  end
end
