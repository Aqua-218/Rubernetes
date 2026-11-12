#!/usr/bin/env ruby
# frozen_string_literal: true

# Brings up the release-topology Rubernetes cluster the M8 lanes run against
# (test/conformance/kubernetes/profiles.yml: 3 control nodes, 3 workers, raft
# datastore, native runtime) and tears it down again.
#
#   ruby tools/conformance/cluster.rb up   --profile <name> [--root DIR]
#   ruby tools/conformance/cluster.rb start [--root DIR]
#   ruby tools/conformance/cluster.rb down [--root DIR]
#   ruby tools/conformance/cluster.rb status [--root DIR]
#
# The provisioning itself is Rubernetes::Cluster::Provisioner, the same code
# `rubectl cluster up` runs; this tool pins the topology to the conformance
# profile, keeps one cluster directory per profile under the root and reports
# in JSON.  `up` prints the cluster descriptor, including the kubeconfig path
# the conformance runner needs.

require "json"
require "optparse"

require_relative "lock"

$LOAD_PATH.unshift(File.join(Conformance::Lock::ROOT, "lib")) unless $LOAD_PATH.include?(File.join(Conformance::Lock::ROOT, "lib"))
require "rubernetes/cluster"

module Conformance
  module Cluster
    L = Conformance::Lock
    Error = Rubernetes::Cluster::Error
    DEFAULT_ROOT = ENV.fetch("RUBERNETES_M8_CLUSTER_ROOT", "/srv/rbn-m8")
    # RUBERNETES_M8_COMPONENT_IDENTITIES: "1" gives each component its own
    # identity, "bootstrap" additionally joins the workers as kubeadm join
    # does; everything otherwise runs as the cluster admin.
    IDENTITIES = {"1" => :components, "bootstrap" => :bootstrap}.fetch(ENV.fetch("RUBERNETES_M8_COMPONENT_IDENTITIES", "0"), :admin)
    LOG_LEVELS = {"controller-manager" => "RUBERNETES_M8_CONTROLLER_LOG_LEVEL", "agent" => "RUBERNETES_M8_AGENT_LOG_LEVEL",
                  "proxy" => "RUBERNETES_M8_PROXY_LOG_LEVEL"}.filter_map { |name, variable| [name, ENV[variable]] if ENV[variable] }.to_h

    module_function

    def run(argv = ARGV)
      command = argv.shift
      options = {root: DEFAULT_ROOT, profile: nil}
      OptionParser.new do |parser|
        parser.on("--profile NAME") { |v| options[:profile] = v }
        parser.on("--root DIR") { |v| options[:root] = v }
      end.parse!(argv)

      case command
      when "up" then exclusively(options) { up(options) }
      when "start" then exclusively(options) { start(options) }
      when "down" then exclusively(options) { down(options) }
      when "status" then status(options)
      else
        warn "usage: cluster.rb {up|start|down|status} [--profile NAME] [--root DIR]"
        2
      end
    end

    # `down` tears down every cluster under the root, so a second run entering
    # while the first is still working -- or still unwinding after a failure --
    # destroys the cluster the other one is building.  One writer at a time.
    def exclusively(options)
      FileUtils.mkdir_p(options.fetch(:root))
      lock = File.open(File.join(options.fetch(:root), ".lock"), File::CREAT | File::RDWR, 0o600)
      unless lock.flock(File::LOCK_EX | File::LOCK_NB)
        warn JSON.generate({"kind" => "conformance_cluster", "passed" => false,
                            "detail" => "another cluster.rb run holds #{options.fetch(:root)}"})
        return 3
      end

      begin
        yield
      ensure
        lock.flock(File::LOCK_UN)
        lock.close
      end
    end

    def up(options)
      profile = resolve_profile(options.fetch(:profile))
      # Another profile's cluster under this root holds the same bridges.
      down(options)
      puts JSON.pretty_generate(provisioner(File.join(options.fetch(:root), profile.fetch("name")), profile).up)
      0
    rescue StandardError => error
      puts JSON.pretty_generate(failure("conformance_cluster", error, options))
      1
    end

    def start(options)
      roots = cluster_roots(options)
      raise Error, "no provisioned cluster under #{options.fetch(:root)}; run `up` first" if roots.empty?

      started = roots.map do |root|
        descriptor = provisioner(root).start
        {"profile" => descriptor.dig("profile", "name"), "root" => root, "kubeconfig" => descriptor.fetch("kubeconfig"),
         "processes" => descriptor.fetch("processes").map { |process| process.slice("name", "pid") }}
      end
      puts JSON.pretty_generate({"kind" => "conformance_cluster_start", "passed" => true, "clusters" => started})
      0
    rescue StandardError => error
      puts JSON.pretty_generate(failure("conformance_cluster_start", error, options))
      1
    end

    def down(options)
      stopped = Dir[File.join(options.fetch(:root), "*", "{cluster.json,pids}")].map { |path| File.dirname(path) }.uniq
        .flat_map { |root| provisioner(root).down }
      puts JSON.pretty_generate({"kind" => "conformance_cluster_down", "stopped" => stopped})
      0
    end

    def status(options)
      clusters = cluster_roots(options).map do |root|
        descriptor = JSON.parse(File.binread(File.join(root, "cluster.json")))
        {"profile" => descriptor.dig("profile", "name"), "kubeconfig" => descriptor["kubeconfig"], "processes" => provisioner(root).status}
      end
      puts JSON.pretty_generate({"kind" => "conformance_cluster_status", "clusters" => clusters})
      0
    end

    def cluster_roots(options)
      Dir[File.join(options.fetch(:root), "*", "cluster.json")].map { |path| File.dirname(path) }
    end

    def provisioner(root, profile = {"name" => File.basename(root), "ip_families" => ["ipv4"]})
      topology = L.profiles.fetch("topology")
      Rubernetes::Cluster::Provisioner.new(
        root: root, name: profile.fetch("name"), cluster_id: "m8-#{profile.fetch("name")}",
        controls: topology.fetch("control_nodes"), workers: topology.fetch("worker_nodes"),
        ip_families: profile.fetch("ip_families"),
        # One host can run several instances, each in its own network
        # namespace; a cgroup root of its own per instance keeps `up`'s
        # stale-workload kill from reaching another instance's Pods.
        cgroup_root: ENV.fetch("RUBERNETES_M8_CGROUP_ROOT", "/sys/fs/cgroup"),
        identities: IDENTITIES, ready_timeout: Float(ENV.fetch("RUBERNETES_M8_READY_TIMEOUT", "180")),
        log_levels: LOG_LEVELS, force: ENV["RUBERNETES_M8_FORCE_UP"] == "1",
        # The compatibility corpus (K6) installs charts that claim volumes;
        # the conformance profile itself has no StorageClass.
        storage: ENV["RUBERNETES_M8_DEFAULT_STORAGE"] == "1",
        descriptor: {"kind" => "conformance_cluster", "profile" => profile}
      )
    end

    def failure(kind, error, options)
      {"schema_version" => 1, "kind" => kind, "passed" => false, "detail" => "#{error.class}: #{error.message}",
       "logs" => Dir[File.join(options.fetch(:root), "**", "*.log")].last(12)}
    end

    def resolve_profile(name)
      profiles = L.profiles.fetch("profiles")
      return profiles.fetch(0) if name.nil?

      profiles.find { |profile| profile.fetch("name") == name } ||
        raise(ArgumentError, "unknown profile #{name.inspect}; known: #{profiles.map { |p| p.fetch("name") }.join(", ")}")
    end

    def alive?(pid) = Rubernetes::Cluster::Processes.alive?(pid)
    def owned?(pid, marker) = Rubernetes::Cluster::Processes.owned?(pid, marker)
    def terminate(pid, name, marker) = Rubernetes::Cluster::Processes.terminate(pid, name, marker)
  end
end

exit(Conformance::Cluster.run) if $PROGRAM_NAME == __FILE__
