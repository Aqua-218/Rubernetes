#!/usr/bin/env ruby
# frozen_string_literal: true

# Brings up the release-topology Rubernetes cluster the M8 lanes run against
# (test/conformance/kubernetes/profiles.yml: 3 control nodes, 3 workers, raft
# datastore, native runtime) and tears it down again.
#
#   ruby tools/conformance/cluster.rb up   --profile <name> [--root DIR]
#   ruby tools/conformance/cluster.rb start [--root DIR]
#   ruby tools/conformance/cluster.rb down [--root DIR]
#   ruby tools/conformance/cluster.rb delete [--root DIR]
#   ruby tools/conformance/cluster.rb status [--root DIR]
#
# The provisioning itself is Rubernetes::Cluster::Provisioner, the same code
# `rubectl cluster up` runs; this tool pins the topology to the conformance
# profile, keeps one cluster directory per profile under the root and reports
# in JSON.  `up` prints the cluster descriptor, including the kubeconfig path
# the conformance runner needs.

require "digest"
require "json"
require "optparse"

require_relative "lock"

$LOAD_PATH.unshift(File.join(Conformance::Lock::ROOT, "lib")) unless $LOAD_PATH.include?(File.join(Conformance::Lock::ROOT, "lib"))
require "rubernetes/cluster"
require_relative "external_cni_profile"

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
        parser.on("--k7-bootstrap", "Start with one MemoryStore control node for the K7 lifecycle lane") { options[:k7_bootstrap] = true }
        parser.on("--isolated-worker-networks", "Give each native worker a separate host network namespace") do
          options[:isolated_worker_networks] = true
        end
        parser.on("--shared-worker-network", "Run native workers in the control network namespace") do
          options[:isolated_worker_networks] = false
        end
        parser.on("--bin-dir DIR", "Start daemons from an installed release") { |v| options[:bin_dir] = File.expand_path(v) }
        parser.on("--external-cni-bin-dir DIR", "Use external reference CNI plugins for the IPv4 profile") do |value|
          options[:external_cni_bin_dir] = File.expand_path(value)
        end
        parser.on("--resolv-conf FILE", "Use a fixture-owned resolver configuration for every worker") do |value|
          options[:resolv_conf] = File.expand_path(value)
        end
        parser.on("--with-hpa-metrics", "Install the pinned metrics-server on a fresh K3 fixture") { options[:hpa_metrics] = true }
        parser.on("--retirable-image-cache", "Permit later retirement of this fresh native fixture's image cache") do
          options[:retirable_image_cache] = true
        end
        parser.on("--retire-images-after MANIFEST", "Retire opted-in image caches after a successful full K1 run") do |value|
          options[:retire_images_after] = File.expand_path(value)
        end
      end.parse!(argv)
      if command != "up" && options.keys.intersect?(%i[k7_bootstrap bin_dir external_cni_bin_dir isolated_worker_networks resolv_conf hpa_metrics])
        raise OptionParser::InvalidOption, "cluster topology, binary, resolver and metrics options are available only for up"
      end
      if (options[:retirable_image_cache] && command != "up") || (options[:retire_images_after] && command != "down")
        raise OptionParser::InvalidOption, "use --retirable-image-cache with up and --retire-images-after with down"
      end

      case command
      when "up" then exclusively(options) { up(options) }
      when "start" then exclusively(options) { start(options) }
      when "down" then exclusively(options) { down(options) }
      when "delete" then exclusively(options) { delete(options) }
      when "status" then status(options)
      else
        warn "usage: cluster.rb {up|start|down|delete|status} [--profile NAME] [--root DIR]"
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
      bootstrap = options.fetch(:k7_bootstrap, false)
      isolated = isolated_worker_networks?(options, profile)
      worker_resolver = resolver_identity(options[:resolv_conf])
      if options[:hpa_metrics] && !isolated && IDENTITIES == :admin
        raise ArgumentError, "--with-hpa-metrics requires kubelet TLS (use RUBERNETES_M8_COMPONENT_IDENTITIES=1)"
      end
      if options[:retirable_image_cache] && (!isolated || !ENV.fetch("RUBERNETES_M8_CGROUP_ROOT", "").start_with?("/sys/fs/cgroup/"))
        raise ArgumentError, "--retirable-image-cache requires isolated workers and a private RUBERNETES_M8_CGROUP_ROOT"
      end

      require_relative "retirable_image_cache" if options[:retirable_image_cache]

      # Another profile's cluster under this root holds the same bridges.
      down(options)
      cluster = provisioner(File.join(options.fetch(:root), profile.fetch("name")), profile,
                            k7_bootstrap: bootstrap, bin_dir: options[:bin_dir],
                            external_cni_bin_dir: options[:external_cni_bin_dir], isolated_worker_networks: isolated,
                            worker_resolver: worker_resolver)
      descriptor = cluster.up
      descriptor["hpa_metrics"] = install_hpa_metrics(cluster, descriptor) if options[:hpa_metrics]
      register_retirable_cache(cluster, descriptor) if options[:retirable_image_cache]
      puts JSON.pretty_generate(descriptor)
      0
    rescue StandardError => error
      puts JSON.pretty_generate(failure("conformance_cluster", error, options))
      1
    end

    def register_retirable_cache(cluster, descriptor)
      RetirableImageCache.new(descriptor.fetch("root"), descriptor).register!
    rescue StandardError
      cluster.down
      raise
    end

    def install_hpa_metrics(cluster, descriptor)
      require_relative "k3_hpa_metrics"
      K3HPAMetrics.install(descriptor, cluster.worker_ids)
    rescue StandardError
      cluster.down
      raise
    end

    def isolated_worker_networks?(options, profile)
      if options[:k7_bootstrap] || options[:external_cni_bin_dir]
        raise ArgumentError, "--isolated-worker-networks is for native release profiles" if options[:isolated_worker_networks]

        return false
      end

      options.fetch(:isolated_worker_networks) { profile.fetch("isolated_worker_networks", false) }
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
      return down_with_image_retirement(options) if options[:retire_images_after]

      stopped = Dir[File.join(options.fetch(:root), "*", "{cluster.json,pids}")].map { |path| File.dirname(path) }.uniq
        .flat_map { |root| provisioner(root).down }
      puts JSON.pretty_generate({"kind" => "conformance_cluster_down", "stopped" => stopped})
      0
    end

    def down_with_image_retirement(options)
      require_relative "retirable_image_cache"
      roots = cluster_roots(options)
      raise Error, "image cache retirement requires exactly one fixture under --root" unless roots.one?

      root = File.expand_path(roots.first)
      descriptor = JSON.parse(File.binread(File.join(root, "cluster.json")))
      retirement = RetirableImageCache.new(root, descriptor)
      cluster = provisioner(root)
      stopped = []
      reclaimed = retirement.retire!(options.fetch(:retire_images_after)) do
        stopped = cluster.down
        raise Error, "fixture processes are still running" if cluster.status.any? { |process| process.fetch("alive") }
      end

      puts JSON.pretty_generate({"kind" => "conformance_cluster_down", "stopped" => stopped,
                                 "retired_image_cache" => reclaimed})
      0
    rescue StandardError => error
      puts JSON.pretty_generate(failure("conformance_cluster_down", error, options).merge("stopped" => stopped || []))
      1
    end

    def status(options)
      clusters = cluster_roots(options).map do |root|
        descriptor = JSON.parse(File.binread(File.join(root, "cluster.json")))
        {"profile" => descriptor.dig("profile", "name"), "kubeconfig" => descriptor["kubeconfig"], "processes" => provisioner(root).status}
      end
      puts JSON.pretty_generate({"kind" => "conformance_cluster_status", "clusters" => clusters})
      0
    end

    def delete(options)
      partial = Dir[File.join(options.fetch(:root), "*", "network", "worker-topology.json")].map { |path| File.dirname(path, 2) }
      roots = (cluster_roots(options) + partial).uniq
      roots.each { |root| provisioner(root).delete }
      puts JSON.pretty_generate({"kind" => "conformance_cluster_delete", "deleted" => roots})
      0
    rescue StandardError => error
      puts JSON.pretty_generate(failure("conformance_cluster_delete", error, options))
      1
    end

    def cluster_roots(options)
      Dir[File.join(options.fetch(:root), "*", "cluster.json")].map { |path| File.dirname(path) }
    end

    def resolver_identity(path)
      return unless path

      resolved = File.realpath(path)
      raise ArgumentError, "--resolv-conf must name a regular file" unless File.file?(resolved)

      {"path" => resolved, "sha256" => Digest::SHA256.file(resolved).hexdigest}
    end

    def provisioner(root, profile = {"name" => File.basename(root), "ip_families" => ["ipv4"]}, k7_bootstrap: false, bin_dir: nil,
                    external_cni_bin_dir: nil, isolated_worker_networks: false, worker_resolver: nil)
      topology = L.profiles.fetch("topology")
      descriptor = {"kind" => "conformance_cluster", "profile" => profile, "isolated_worker_networks" => isolated_worker_networks}
      descriptor["k7_bootstrap"] = true if k7_bootstrap
      descriptor["worker_resolver"] = worker_resolver if worker_resolver
      implementation = external_cni_bin_dir ? ExternalCNIProfile : Rubernetes::Cluster::Provisioner
      cni = external_cni_bin_dir ? {cni_bin_dir: external_cni_bin_dir} : {}
      implementation.new(
        root: root, name: profile.fetch("name"), cluster_id: "m8-#{profile.fetch("name")}",
        controls: k7_bootstrap ? 1 : topology.fetch("control_nodes"), workers: topology.fetch("worker_nodes"),
        datastore: k7_bootstrap ? "memory" : "raft", bin_dir: bin_dir,
        ip_families: profile.fetch("ip_families"),
        # One host can run several instances, each in its own network
        # namespace; a cgroup root of its own per instance keeps `up`'s
        # stale-workload kill from reaching another instance's Pods.
        cgroup_root: ENV.fetch("RUBERNETES_M8_CGROUP_ROOT", "/sys/fs/cgroup"),
        identities: isolated_worker_networks && IDENTITIES == :admin ? :components : IDENTITIES,
        isolated_worker_networks: isolated_worker_networks, ready_timeout: Float(ENV.fetch("RUBERNETES_M8_READY_TIMEOUT", "180")),
        dns_resolv_conf: worker_resolver && worker_resolver.fetch("path"),
        log_levels: LOG_LEVELS, force: ENV["RUBERNETES_M8_FORCE_UP"] == "1",
        # The compatibility corpus (K6) installs charts that claim volumes;
        # the conformance profile itself has no StorageClass.
        storage: ENV["RUBERNETES_M8_DEFAULT_STORAGE"] == "1",
        descriptor: descriptor, **cni
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
