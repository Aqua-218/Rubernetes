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
# `start` brings the clusters already provisioned under the root back after a
# host reboot or a `down`: the same configuration, PKI, raft log and node
# state, nothing reissued and nothing removed.
#
# `up` prints the cluster descriptor, including the kubeconfig path the
# conformance runner needs.  Every process is a real `exe/rubernetes-*` under
# its own configuration: nothing here runs the control plane in-process, and a
# component that does not become ready is reported as a failure rather than
# waited out.

require "fileutils"
require "English"
require "json"
require "net/http"
require "securerandom"
require "ipaddr"
require "openssl"
require "optparse"
require "rbconfig"
require "socket"
require "time"
require "uri"
require "yaml"

require_relative "lock"

$LOAD_PATH.unshift(File.join(Conformance::Lock::ROOT, "lib")) unless $LOAD_PATH.include?(File.join(Conformance::Lock::ROOT, "lib"))
require "rubernetes/consensus/identity"
require "rubernetes/controller/registry"

module Conformance
  module Cluster
    L = Conformance::Lock
    ROOT = L::ROOT
    DEFAULT_ROOT = ENV.fetch("RUBERNETES_M8_CLUSTER_ROOT", "/srv/rbn-m8")
    class Error < StandardError; end

    CONTROL_IDS = %w[control-0 control-1 control-2].freeze
    WORKER_IDS = %w[worker-0 worker-1 worker-2].freeze
    READY_TIMEOUT = Float(ENV.fetch("RUBERNETES_M8_READY_TIMEOUT", "180"))
    KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")
    # Each component under its own identity, as kubeadm provisions them: the
    # kubelets as system:node:<name> (the Node authorizer and NodeRestriction
    # apply), kube-proxy as system:kube-proxy, the scheduler as
    # system:kube-scheduler (leader lease "kube-scheduler"), the controller
    # manager as system:kube-controller-manager with
    # --use-service-account-credentials (lease "kube-controller-manager"), and
    # the node's cluster DNS as system:coredns with the CoreDNS add-on's
    # ClusterRole.  The kubelets then serve their API over TLS with webhook
    # authentication and authorization, and the API server dials them with
    # its kubelet client certificate (kube-apiserver-kubelet-client, bound to
    # system:kubelet-api-admin as kubeadm binds it).
    # Off by default: everything otherwise runs as the conformance admin.
    # "bootstrap" additionally joins the workers the way kubeadm join does:
    # a bootstrap token, TLS bootstrapping of each kubelet's client
    # certificate through the CSR API (auto-approved by the kubeadm bindings)
    # and certificate rotation.
    COMPONENT_IDENTITIES = %w[1 bootstrap].include?(ENV.fetch("RUBERNETES_M8_COMPONENT_IDENTITIES", "0"))
    TLS_BOOTSTRAP = ENV.fetch("RUBERNETES_M8_COMPONENT_IDENTITIES", "0") == "bootstrap"
    BOOTSTRAP_GROUP = "system:bootstrappers:kubeadm:default-node-token"
    COREDNS_USER = "system:coredns"
    KUBELET_CLIENT_USER = "kube-apiserver-kubelet-client"
    # The cgroup the node agents put their workloads under.  One host can
    # run several cluster instances (each in its own network namespace); a
    # cgroup root of its own per instance keeps `up`'s stale-workload kill
    # from reaching another instance's Pods.  A sub-cgroup of the host root
    # is created with the controllers the agents require delegated to it.
    CGROUP_ROOT = ENV.fetch("RUBERNETES_M8_CGROUP_ROOT", "/sys/fs/cgroup")
    # Service CIDRs per family (kube-apiserver --service-cluster-ip-range);
    # the primary family is the profile's first.
    SERVICE_CIDRS = {"ipv4" => "10.96.0.0/12", "ipv6" => "fd00:d8:5::/112"}.freeze

    module_function

    # ---------------------------------------------------------------- command

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
      root = File.join(options.fetch(:root), profile.fetch("name"))
      # A cluster still running under this root keeps its ports (the agents'
      # streaming ports are fixed) and its nodes: the new agents then die on
      # "Address already in use" while the old ones keep the old nodes Ready,
      # and `up` reports a cluster that is half the previous one.
      down(options)
      refuse_to_disturb_other_clusters!(root, profile)
      unmount_stale_mounts(root)
      FileUtils.rm_rf(root)
      FileUtils.mkdir_p(root)

      # Kernel objects outlive the state directory: a namespace or link left by
      # a crashed run makes the next run's identical name look like someone
      # else's resource, and the agent correctly refuses to adopt it.  Only the
      # "rbn-" prefix this provisioner owns is removed -- never the host's.
      kill_stale_workloads
      purge_stale_namespaces
      purge_stale_bridge_links
      ensure_cgroup_root!

      pki = issue_pki(root, profile)
      issue_raft_identities(root, "m8-#{profile.fetch("name")}")
      ports = allocate_ports
      descriptor = {
        "schema_version" => 1, "kind" => "conformance_cluster", "profile" => profile,
        "root" => root, "started_at" => Time.now.utc.iso8601, "processes" => []
      }

      CONTROL_IDS.each_with_index do |id, index|
        config = write_apiserver_config(root, id, index, ports, pki, profile)
        descriptor["processes"] << spawn_process(root, "apiserver-#{id}", "rubernetes-apiserver", config)
      end

      endpoint = "https://127.0.0.1:#{ports.fetch(:http).fetch(CONTROL_IDS.first)}"
      kubeconfig = write_kubeconfig(root, endpoint, pki)
      descriptor["kubeconfig"] = kubeconfig
      descriptor["endpoint"] = endpoint
      # One Ruby API server is one core.  With every component on control-0
      # that replica carried the whole control plane (80% CPU, 70 client
      # connections) while the other two idled; the components are spread
      # over the replicas, as a real cluster spreads them behind its load
      # balancer.  The conformance client keeps control-0.
      replica_kubeconfigs = CONTROL_IDS.map do |id|
        write_kubeconfig(root, "https://127.0.0.1:#{ports.fetch(:http).fetch(id)}", pki, name: "kubeconfig-#{id}")
      end

      await_apiservers!(ports, pki)
      replica_endpoints = CONTROL_IDS.map { |id| "https://127.0.0.1:#{ports.fetch(:http).fetch(id)}" }
      apply_coredns_rbac!(kubeconfig) if pki[:identities]
      bootstrap_token = TLS_BOOTSTRAP ? create_bootstrap_token!(kubeconfig) : nil

      scheduler_kubeconfig = component_kubeconfig(root, replica_endpoints[1 % replica_endpoints.length], pki, "kube-scheduler",
                                                  replica_kubeconfigs[1 % replica_kubeconfigs.length])
      descriptor["processes"] << spawn_process(root, "scheduler",
                                               "rubernetes-scheduler",
                                               write_scheduler_config(root, scheduler_kubeconfig,
                                                                      lease_name: pki[:identities] ? "kube-scheduler" : "m8-scheduler"))
      controller_kubeconfig = component_kubeconfig(root, replica_endpoints[2 % replica_endpoints.length], pki, "kube-controller-manager",
                                                   replica_kubeconfigs[2 % replica_kubeconfigs.length])
      descriptor["processes"] << spawn_process(root, "controller-manager",
                                               "rubernetes-controller-manager",
                                               write_controller_config(root, controller_kubeconfig,
                                                                       service_account_credentials: !pki[:identities].nil?,
                                                                       discovery_kubeconfig: replica_kubeconfigs[2 % replica_kubeconfigs.length]))

      WORKER_IDS.each_with_index do |id, index|
        node_kubeconfig = replica_kubeconfigs[(index + 1) % replica_kubeconfigs.length]
        node_endpoint = replica_endpoints[(index + 1) % replica_endpoints.length]
        agent_kubeconfig = component_kubeconfig(root, node_endpoint, pki, "node-#{id}", node_kubeconfig)
        bootstrap = if bootstrap_token
                      {"kubeconfig" => File.join(root, "runtime", id, "kubelet.conf"),
                       "bootstrap_kubeconfig" => write_bootstrap_kubeconfig(root, node_endpoint, pki, id, bootstrap_token),
                       "rotate_certificates" => true, "cert_dir" => File.join(root, "runtime", id, "pki")}
                    end
        dns_kubeconfig = pki[:identities] ? component_kubeconfig(root, node_endpoint, pki, "coredns", nil) : nil
        proxy_kubeconfig = component_kubeconfig(root, node_endpoint, pki, "kube-proxy", node_kubeconfig)
        descriptor["processes"] << spawn_process(root, "agent-#{id}", "rubernetes-agent",
                                                 write_agent_config(root, id, index, agent_kubeconfig, profile,
                                                                    dns_kubeconfig: dns_kubeconfig, pki: pki, bootstrap: bootstrap))
        descriptor["processes"] << spawn_process(root, "proxy-#{id}", "rubernetes-proxy",
                                                 write_proxy_config(root, id, index, proxy_kubeconfig))
      end

      await_nodes!(kubeconfig, WORKER_IDS.length)
      # A component that died after spawning (a proxy whose attach failed, a
      # controller whose loop crashed) must not hide behind Ready nodes.
      dead = descriptor["processes"].reject { |process| alive?(process.fetch("pid")) }
      unless dead.empty?
        details = dead.map do |process|
          "#{process["name"]}: #{File.file?(process["log"]) ? File.readlines(process["log"]).last(2).join.strip[0, 300] : "no log"}"
        end
        raise "cluster processes exited during bring-up: #{details.join(" | ")}"
      end

      descriptor["ready_at"] = Time.now.utc.iso8601
      descriptor["passed"] = true
      File.write(File.join(root, "cluster.json"), JSON.pretty_generate(descriptor))
      puts JSON.pretty_generate(descriptor)
      0
    rescue StandardError => error
      report = {"schema_version" => 1, "kind" => "conformance_cluster", "passed" => false,
                "detail" => "#{error.class}: #{error.message}",
                "logs" => Dir[File.join(options.fetch(:root), "**", "*.log")].last(12)}
      puts JSON.pretty_generate(report)
      down(options)
      1
    end

    # The datastore, the node ledgers and every configuration file live under
    # the root, so a provisioned cluster only needs its processes again.  They
    # come back in the order `up` starts them: the datastore quorum before its
    # clients, the control loops before the nodes.
    def start(options)
      paths = Dir[File.join(options.fetch(:root), "*", "cluster.json")]
      raise Error, "no provisioned cluster under #{options.fetch(:root)}; run `up` first" if paths.empty?

      ensure_cgroup_root!
      started = paths.map { |path| restart_cluster(path) }
      puts JSON.pretty_generate({"kind" => "conformance_cluster_start", "passed" => true, "clusters" => started})
      0
    rescue StandardError => error
      puts JSON.pretty_generate({"kind" => "conformance_cluster_start", "passed" => false,
                                 "detail" => "#{error.class}: #{error.message}",
                                 "logs" => Dir[File.join(options.fetch(:root), "**", "*.log")].last(12)})
      1
    end

    def restart_cluster(path)
      descriptor = JSON.parse(File.binread(path))
      root = descriptor.fetch("root")
      kubeconfig = descriptor.fetch("kubeconfig")
      live = descriptor.fetch("processes").select { |process| owned?(process.fetch("pid"), process.fetch("config")) }
      raise Error, "#{root} is running (#{live.map { |process| process.fetch("name") }.join(", ")}); bring it down first" unless live.empty?

      servers, clients = descriptor.fetch("processes").partition { |process| process.fetch("executable") == "rubernetes-apiserver" }
      respawned = servers.map { |process| spawn_process(root, process.fetch("name"), process.fetch("executable"), process.fetch("config")) }
      await!("#{root} /readyz") { system(KUBECTL, "--kubeconfig", kubeconfig, "get", "--raw", "/readyz", out: File::NULL, err: File::NULL) }
      # The Node objects still say Ready from before the stop; only a
      # heartbeat written by the restarted agents counts.
      since = Time.now.utc
      respawned.concat(clients.map { |process| spawn_process(root, process.fetch("name"), process.fetch("executable"), process.fetch("config")) })
      await_nodes!(kubeconfig, WORKER_IDS.length, since: since)

      dead = respawned.reject { |process| alive?(process.fetch("pid")) }
      raise Error, "#{root}: #{dead.map { |process| process.fetch("name") }.join(", ")} exited during start" unless dead.empty?

      descriptor["processes"] = respawned
      descriptor["restarted_at"] = Time.now.utc.iso8601
      File.write(path, JSON.pretty_generate(descriptor))
      {"profile" => descriptor.dig("profile", "name"), "root" => root, "kubeconfig" => kubeconfig,
       "processes" => respawned.map { |process| process.slice("name", "pid") }}
    end

    def down(options)
      stopped = []
      Dir[File.join(options.fetch(:root), "*", "cluster.json")].each do |path|
        descriptor =
          begin
            JSON.parse(File.binread(path))
          rescue JSON::ParserError, SystemCallError
            next
          end
        descriptor.fetch("processes", []).reverse_each do |process|
          stopped << terminate(process.fetch("pid"), process.fetch("name"), process.fetch("config"))
        end
      end
      Dir[File.join(options.fetch(:root), "*", "pids", "*.pid")].each do |path|
        # A pid file names a process by its cluster directory only.
        stopped << terminate(Integer(File.read(path).strip), File.basename(path, ".pid"), File.dirname(File.dirname(path)))
      rescue ArgumentError, SystemCallError
        nil
      end
      puts JSON.pretty_generate({"kind" => "conformance_cluster_down", "stopped" => stopped.compact})
      0
    end

    def status(options)
      descriptors = Dir[File.join(options.fetch(:root), "*", "cluster.json")].map do |path|
        descriptor = JSON.parse(File.binread(path))
        {"profile" => descriptor.dig("profile", "name"), "kubeconfig" => descriptor["kubeconfig"],
         "processes" => descriptor.fetch("processes", []).map do |process|
           {"name" => process.fetch("name"), "pid" => process.fetch("pid"), "alive" => alive?(process.fetch("pid"))}
         end}
      end
      puts JSON.pretty_generate({"kind" => "conformance_cluster_status", "clusters" => descriptors})
      0
    end

    # ------------------------------------------------------------------- pki

    def issue_pki(root, profile = {"ip_families" => ["ipv4"]})
      directory = File.join(root, "pki")
      FileUtils.mkdir_p(directory)

      ca_key = OpenSSL::PKey::RSA.new(2048)
      ca = certificate(subject: "/CN=rubernetes-conformance-ca", key: ca_key, issuer_key: ca_key,
                       issuer: nil, ca: true)

      # kube-apiserver's serving certificate covers every address a client
      # legitimately dials: loopback, the node's advertise address, and the
      # `kubernetes` Service ClusterIP (the first address of the service
      # CIDR), which is what in-cluster clients use.  Without the ClusterIP
      # SAN every Pod's API access fails certificate verification.
      server_key = OpenSSL::PKey::RSA.new(2048)
      server = certificate(subject: "/CN=rubernetes-apiserver", key: server_key, issuer_key: ca_key,
                           issuer: ca, ca: false,
                           alt_names: ["DNS:localhost", "DNS:kubernetes", "DNS:kubernetes.default",
                                       "DNS:kubernetes.default.svc", "DNS:kubernetes.default.svc.cluster.local",
                                       "IP:127.0.0.1", "IP:::1",
                                       *families(profile).map { |family| "IP:#{host_advertise_address(family)}" },
                                       *service_cluster_ips(profile).map { |ip| "IP:#{ip}" }].uniq)

      admin_key = OpenSSL::PKey::RSA.new(2048)
      admin = certificate(subject: "/O=system:masters/CN=conformance-admin", key: admin_key,
                          issuer_key: ca_key, issuer: ca, ca: false, client: true)

      service_account_key = OpenSSL::PKey::RSA.new(2048)

      # kube-apiserver's front proxy: a CA of its own (--requestheader-
      # client-ca-file) and the client certificate the aggregator presents
      # to extension API servers (--proxy-client-cert-file), whose CN is the
      # one requestheader-allowed-name.
      front_proxy_ca_key = OpenSSL::PKey::RSA.new(2048)
      front_proxy_ca = certificate(subject: "/CN=rubernetes-front-proxy-ca", key: front_proxy_ca_key, issuer_key: front_proxy_ca_key,
                                   issuer: nil, ca: true)
      front_proxy_key = OpenSSL::PKey::RSA.new(2048)
      front_proxy = certificate(subject: "/CN=front-proxy-client", key: front_proxy_key, issuer_key: front_proxy_ca_key,
                                issuer: front_proxy_ca, ca: false, client: true)

      paths = {
        ca: File.join(directory, "ca.crt"), ca_key: File.join(directory, "ca.key"),
        server: File.join(directory, "apiserver.crt"), server_key: File.join(directory, "apiserver.key"),
        admin: File.join(directory, "admin.crt"), admin_key: File.join(directory, "admin.key"),
        sa_key: File.join(directory, "service-account.key"), sa_pub: File.join(directory, "service-account.pub"),
        front_proxy_ca: File.join(directory, "front-proxy-ca.crt"),
        front_proxy: File.join(directory, "front-proxy-client.crt"), front_proxy_key: File.join(directory, "front-proxy-client.key")
      }
      File.write(paths[:ca], ca.to_pem)
      File.write(paths[:ca_key], ca_key.to_pem)
      File.write(paths[:server], server.to_pem)
      File.write(paths[:server_key], server_key.to_pem)
      File.write(paths[:admin], admin.to_pem)
      File.write(paths[:admin_key], admin_key.to_pem)
      File.write(paths[:sa_key], service_account_key.to_pem)
      File.write(paths[:sa_pub], service_account_key.public_key.to_pem)
      File.write(paths[:front_proxy_ca], front_proxy_ca.to_pem)
      File.write(paths[:front_proxy], front_proxy.to_pem)
      File.write(paths[:front_proxy_key], front_proxy_key.to_pem)
      paths.each_value { |path| File.chmod(0o600, path) }
      paths[:identities] = issue_component_identities(directory, ca, ca_key, profile) if COMPONENT_IDENTITIES
      paths
    end

    # Client certificates for the components' own identities.
    def component_subjects
      subjects = {"kube-scheduler" => "/CN=system:kube-scheduler", "kube-proxy" => "/CN=system:kube-proxy",
                  "kube-controller-manager" => "/CN=system:kube-controller-manager", "coredns" => "/CN=#{COREDNS_USER}",
                  "kube-apiserver-kubelet-client" => "/CN=#{KUBELET_CLIENT_USER}"}
      WORKER_IDS.each { |id| subjects["node-#{id}"] = "/O=system:nodes/CN=system:node:#{id}" }
      subjects
    end

    def issue_component_identities(directory, ca, ca_key, profile)
      component_subjects.to_h do |name, subject|
        key = OpenSSL::PKey::RSA.new(2048)
        cert = certificate(subject: subject, key: key, issuer_key: ca_key, issuer: ca, ca: false, client: true)
        cert_path = File.join(directory, "#{name}.crt")
        key_path = File.join(directory, "#{name}.key")
        File.write(cert_path, cert.to_pem)
        File.write(key_path, key.to_pem)
        [cert_path, key_path].each { |path| File.chmod(0o600, path) }
        [name, {cert: cert_path, key: key_path}]
      end.merge(issue_kubelet_serving(directory, ca, ca_key, profile))
    end

    # kubelet --tls-cert-file: each worker's serving certificate, valid for
    # the addresses the API server dials it on.
    def issue_kubelet_serving(directory, ca, ca_key, profile)
      WORKER_IDS.each_with_index.to_h do |id, index|
        key = OpenSSL::PKey::RSA.new(2048)
        names = ["DNS:#{id}", "IP:127.0.0.1", "IP:::1",
                 *node_advertise_addresses(index, profile).map { |address| "IP:#{address}" }].uniq
        cert = certificate(subject: "/CN=#{id}", key: key, issuer_key: ca_key, issuer: ca, ca: false, alt_names: names)
        cert_path = File.join(directory, "kubelet-#{id}.crt")
        key_path = File.join(directory, "kubelet-#{id}.key")
        File.write(cert_path, cert.to_pem)
        File.write(key_path, key.to_pem)
        [cert_path, key_path].each { |path| File.chmod(0o600, path) }
        ["kubelet-serving-#{id}", {cert: cert_path, key: key_path}]
      end
    end

    # The kubeconfig a component uses: its own identity when component
    # identities are on, the conformance admin otherwise.
    def component_kubeconfig(root, endpoint, pki, component, fallback)
      identity = pki[:identities]&.fetch(component, nil)
      return fallback unless identity

      write_kubeconfig(root, endpoint, pki, name: "kubeconfig-#{component}", user: [component, identity])
    end

    # kubeadm init's bootstrap token (bootstrap.kubernetes.io/token in
    # kube-system, for authentication and signing) and the bindings that let
    # its bearers ask for and get node client certificates: kubeadm:
    # kubelet-bootstrap, kubeadm:node-autoapprove-bootstrap and
    # kubeadm:node-autoapprove-certificate-rotation.
    def create_bootstrap_token!(kubeconfig)
      id = SecureRandom.alphanumeric(6).downcase
      secret = SecureRandom.alphanumeric(16).downcase
      binding = lambda do |name, role, group|
        {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => "ClusterRoleBinding", "metadata" => {"name" => name},
         "roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => "ClusterRole", "name" => role},
         "subjects" => [{"apiGroup" => "rbac.authorization.k8s.io", "kind" => "Group", "name" => group}]}
      end
      manifest = {"apiVersion" => "v1", "kind" => "List", "items" => [
        {"apiVersion" => "v1", "kind" => "Secret", "type" => "bootstrap.kubernetes.io/token",
         "metadata" => {"name" => "bootstrap-token-#{id}", "namespace" => "kube-system"},
         "stringData" => {"token-id" => id, "token-secret" => secret, "usage-bootstrap-authentication" => "true",
                          "usage-bootstrap-signing" => "true", "auth-extra-groups" => BOOTSTRAP_GROUP,
                          "expiration" => (Time.now.utc + 86_400).iso8601}},
        binding.call("kubeadm:kubelet-bootstrap", "system:node-bootstrapper", BOOTSTRAP_GROUP),
        binding.call("kubeadm:node-autoapprove-bootstrap", "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
                     BOOTSTRAP_GROUP),
        binding.call("kubeadm:node-autoapprove-certificate-rotation",
                     "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient", "system:nodes")
      ]}
      kubectl_apply!(kubeconfig, manifest, "the bootstrap token")
      "#{id}.#{secret}"
    end

    def write_bootstrap_kubeconfig(root, endpoint, pki, id, token)
      document = {
        "apiVersion" => "v1", "kind" => "Config", "current-context" => "tls-bootstrap",
        "clusters" => [{"name" => "rubernetes", "cluster" => {"server" => endpoint, "certificate-authority" => pki.fetch(:ca)}}],
        "users" => [{"name" => "tls-bootstrap-token-user", "user" => {"token" => token}}],
        "contexts" => [{"name" => "tls-bootstrap", "context" => {"cluster" => "rubernetes", "user" => "tls-bootstrap-token-user"}}]
      }
      path = File.join(root, "bootstrap-kubeconfig-#{id}")
      File.write(path, YAML.dump(document))
      File.chmod(0o600, path)
      path
    end

    def kubectl_apply!(kubeconfig, manifest, what)
      IO.popen([KUBECTL, "--kubeconfig", kubeconfig, "apply", "-f", "-"], "r+", err: %i[child out]) do |io|
        io.write(JSON.generate(manifest))
        io.close_write
        output = io.read
        io.close
        raise "applying #{what} failed: #{output.strip[0, 300]}" unless $CHILD_STATUS.success?
      end
    end

    # kubeadm's CoreDNS add-on RBAC (ClusterRole system:coredns), bound to
    # the resolver's user.
    def apply_coredns_rbac!(kubeconfig)
      manifest = {"apiVersion" => "v1", "kind" => "List", "items" => [
        {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => "ClusterRole", "metadata" => {"name" => "system:coredns"},
         "rules" => [{"apiGroups" => [""], "resources" => %w[endpoints services pods namespaces], "verbs" => %w[list watch]},
                     {"apiGroups" => ["discovery.k8s.io"], "resources" => %w[endpointslices], "verbs" => %w[list watch]}]},
        {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => "ClusterRoleBinding", "metadata" => {"name" => "system:coredns"},
         "roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => "ClusterRole", "name" => "system:coredns"},
         "subjects" => [{"apiGroup" => "rbac.authorization.k8s.io", "kind" => "User", "name" => COREDNS_USER}]},
        # kubeadm's kubeadm:kubelet-api-admin binding for the API server's
        # kubelet client.
        {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => "ClusterRoleBinding", "metadata" => {"name" => "kubeadm:kubelet-api-admin"},
         "roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => "ClusterRole", "name" => "system:kubelet-api-admin"},
         "subjects" => [{"apiGroup" => "rbac.authorization.k8s.io", "kind" => "User", "name" => KUBELET_CLIENT_USER}]}
      ]}
      IO.popen([KUBECTL, "--kubeconfig", kubeconfig, "apply", "-f", "-"], "r+", err: %i[child out]) do |io|
        io.write(JSON.generate(manifest))
        io.close_write
        output = io.read
        io.close
        raise "applying the CoreDNS RBAC failed: #{output.strip[0, 300]}" unless $CHILD_STATUS.success?
      end
    end

    # The raft transport authenticates peers with its own per-node bundles; the
    # datastore reads them from `pki_dir` and refuses to start without one.
    def purge_stale_namespaces
      output = IO.popen(%w[ip netns list], err: File::NULL, &:read).to_s
      output.each_line do |line|
        name = line.split.first.to_s
        next unless name.start_with?("rbn-")

        system("ip", "netns", "delete", name, out: File::NULL, err: File::NULL)
      end
    rescue SystemCallError
      nil
    end

    # Container workloads do not die with the agent that started them -- they
    # are in their own PID namespaces under the runtime's cgroup -- so a run
    # that ended without an orderly teardown leaves them running, holding their
    # network namespaces and every address in them.  cgroup.kill (cgroup v2)
    # kills the whole subtree in one step; nothing else on a conformance host
    # runs under the runtime's cgroup.
    WORKLOAD_CGROUP = File.join(CGROUP_ROOT, "rubernetes")

    # A cgroup root below the host's needs the agents' controllers delegated
    # to it (cgroup v2 delegates nothing by default); the host root already
    # has them.
    def ensure_cgroup_root!
      return if CGROUP_ROOT == "/sys/fs/cgroup"

      FileUtils.mkdir_p(CGROUP_ROOT)
      parent = File.dirname(CGROUP_ROOT)
      available = File.read(File.join(parent, "cgroup.controllers")).split
      wanted = %w[cpu cpuset memory pids io hugetlb] & available
      [parent, CGROUP_ROOT].each do |directory|
        enabled = File.read(File.join(directory, "cgroup.subtree_control")).split
        missing = wanted - enabled
        File.write(File.join(directory, "cgroup.subtree_control"), missing.map { |name| "+#{name}" }.join(" ")) unless missing.empty?
      end
      # The QoS cgroup manager expects the agents' hierarchy to exist (on the
      # host root it is left over from earlier runs).
      FileUtils.mkdir_p(WORKLOAD_CGROUP)
    end

    # A volume mount whose release never finished (the agent was killed, or
    # the unmount was reported ambiguous) stays in the kernel after the state
    # directory is removed: removing the directory tree then reaches through a
    # bind mount into the volume it was bound from, and the leftover tmpfs
    # keeps Pod data of a run that no longer exists.  Every mount below the
    # cluster root belongs to a run that is over by the time `up` runs;
    # deepest first, because a bind sits on the stage it was bound from.
    def unmount_stale_mounts(root)
      prefix = "#{File.expand_path(root)}/"
      targets = File.readlines("/proc/self/mountinfo").filter_map do |line|
        fields = line.split
        target = fields[4].to_s.gsub(/\\(\d{3})/) { ::Regexp.last_match(1).to_i(8).chr }
        target if target.start_with?(prefix)
      end
      targets.sort_by { |target| [-target.count("/"), target] }.each do |target|
        system("umount", target, out: File::NULL, err: File::NULL) ||
          system("umount", "-l", target, out: File::NULL, err: File::NULL)
      end
      targets.length
    rescue SystemCallError
      0
    end

    def kill_stale_workloads
      control = File.join(WORKLOAD_CGROUP, "cgroup.kill")
      return unless File.exist?(control)

      File.write(control, "1")
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      until Dir.glob(File.join(WORKLOAD_CGROUP, "**", "cgroup.procs")).all? { |path| File.read(path).strip.empty? }
        break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        sleep 0.2
      end
      remove_stale_cgroup_directories
    rescue SystemCallError
      nil
    end

    # Killing leaves the Pod and container cgroup directories behind (only an
    # agent that is alive removes them); a thousand of them accumulated over a
    # day of rebuilds.  Children go before parents, the QoS tiers stay.
    def remove_stale_cgroup_directories
      Dir.glob(File.join(WORKLOAD_CGROUP, "*", "*", "**", "")).sort_by { |path| -path.count("/") }.each do |path|
        Dir.rmdir(path)
      rescue SystemCallError
        nil
      end
    end

    # A Pod's host-side veth outlives its agent when the agent is killed: the
    # Pod's namespace keeps the pair alive and the link stays enslaved to the
    # node bridge, still answering ARP for its old address.  The next run's IPAM
    # hands that same address to a new Pod, and traffic for it reaches the dead
    # Pod's namespace instead -- "Connection refused" from a Pod that is Running
    # and listening.  Every link on a bridge this provisioner owns (rbn0..N) is
    # a leftover by the time `up` runs, so it is removed; deleting the host end
    # of a veth deletes the pair.
    # `up` owns the host-global objects of its profile (the rbn0..2 bridges
    # and their veths, the cgroup tree, the rbn-* namespaces): the purges
    # below would take them from any OTHER cluster of the same profile that is
    # alive on this host (2026-09-30: an `up` for /srv/rbn-m8 deleted every
    # Pod veth of the /srv/rbn-app GitLab cluster).  Refuse unless
    # RUBERNETES_M8_FORCE_UP=1, and say which cluster is in the way; a
    # separate network namespace + cgroup root (tools/conformance/netns_env.sh)
    # is the supported way to run two instances.
    def refuse_to_disturb_other_clusters!(root, profile)
      return if ENV["RUBERNETES_M8_FORCE_UP"] == "1"

      live = other_live_clusters(root)
      return if live.empty?

      names = live.map { |entry| "#{entry[:root]} (#{entry[:alive]} live processes)" }.join(", ")
      raise Error, "another #{profile.fetch("name")} cluster is alive on this host: #{names}; " \
                   "bring it down first, run this instance in its own netns (netns_env.sh), " \
                   "or set RUBERNETES_M8_FORCE_UP=1 to take over its bridges and workloads"
    end

    def other_live_clusters(root)
      Dir.glob("/srv/*/**/cluster.json").filter_map do |path|
        other_root = File.dirname(path)
        next if other_root == root || other_root.start_with?("#{root}/")

        descriptor = begin
          JSON.parse(File.binread(path))
        rescue JSON::ParserError, SystemCallError
          next
        end
        # Only a cluster whose bridges live in THIS network namespace can be
        # disturbed; one brought up inside its own netns has its own rbnN.
        next unless same_network_namespace?(descriptor)

        alive = descriptor.fetch("processes", []).count { |process| alive?(process.fetch("pid")) }
        {root: other_root, alive: alive} if alive.positive?
      end
    end

    def same_network_namespace?(descriptor)
      pid = descriptor.fetch("processes", []).map { |process| process.fetch("pid") }.find { |candidate| alive?(candidate) }
      return false if pid.nil?

      File.readlink("/proc/#{pid}/ns/net") == File.readlink("/proc/self/ns/net")
    rescue SystemCallError
      false
    end

    def purge_stale_bridge_links
      WORKER_IDS.each_index do |index|
        bridge = "rbn#{index}"
        output = IO.popen(["ip", "-o", "link", "show", "master", bridge], err: File::NULL, &:read).to_s
        output.each_line do |line|
          name = line.split(":", 3)[1].to_s.strip.split("@").first.to_s
          next if name.empty?

          system("ip", "link", "delete", name, out: File::NULL, err: File::NULL)
        end
        system("ip", "neigh", "flush", "dev", bridge, out: File::NULL, err: File::NULL)
      end
    rescue SystemCallError
      nil
    end

    def issue_raft_identities(root, cluster_id)
      ca, ca_key = Rubernetes::Consensus::Identity.generate_ca(cluster_id)
      CONTROL_IDS.each do |id|
        bundle = Rubernetes::Consensus::Identity.issue_node(ca, ca_key, cluster_id: cluster_id, node_id: id)
        Rubernetes::Consensus::Identity.write_bundle(File.join(root, "raft-pki", id), bundle)
      end
    end

    def certificate(subject:, key:, issuer_key:, issuer:, ca:, client: false, alt_names: nil)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = OpenSSL::BN.rand(64)
      certificate.subject = OpenSSL::X509::Name.parse(subject)
      certificate.issuer = issuer ? issuer.subject : certificate.subject
      certificate.public_key = key.public_key
      certificate.not_before = Time.now - 3600
      certificate.not_after = Time.now + (365 * 24 * 3600)

      extensions = OpenSSL::X509::ExtensionFactory.new
      extensions.subject_certificate = certificate
      extensions.issuer_certificate = issuer || certificate
      if ca
        certificate.add_extension(extensions.create_extension("basicConstraints", "CA:TRUE", true))
        certificate.add_extension(extensions.create_extension("keyUsage", "keyCertSign,cRLSign", true))
      else
        certificate.add_extension(extensions.create_extension("basicConstraints", "CA:FALSE", true))
        certificate.add_extension(extensions.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
        usage = client ? "clientAuth" : "serverAuth,clientAuth"
        certificate.add_extension(extensions.create_extension("extendedKeyUsage", usage, false))
        certificate.add_extension(extensions.create_extension("subjectAltName", alt_names.join(","), false)) if alt_names
      end
      certificate.sign(issuer_key, OpenSSL::Digest.new("SHA256"))
      certificate
    end

    def write_kubeconfig(root, endpoint, pki, name: "kubeconfig", user: nil)
      user_name, credentials = user || ["conformance-admin", {cert: pki.fetch(:admin), key: pki.fetch(:admin_key)}]
      document = {
        "apiVersion" => "v1", "kind" => "Config", "current-context" => "conformance",
        "clusters" => [{"name" => "rubernetes",
                        "cluster" => {"server" => endpoint,
                                      "certificate-authority" => pki.fetch(:ca)}}],
        "users" => [{"name" => user_name,
                     "user" => {"client-certificate" => credentials.fetch(:cert),
                                "client-key" => credentials.fetch(:key)}}],
        "contexts" => [{"name" => "conformance",
                        "context" => {"cluster" => "rubernetes", "user" => user_name}}]
      }
      path = File.join(root, name)
      File.write(path, YAML.dump(document))
      File.chmod(0o600, path)
      path
    end

    # --------------------------------------------------------------- configs

    # Every socket stays open until all ports are drawn: closing each one at
    # once let the kernel hand the same ephemeral port out twice, and an
    # apiserver's HTTP listener then collided with its own raft address
    # ("Address already in use", round 99 never started).
    def allocate_ports
      sockets = []
      draw = lambda do
        socket = TCPServer.new("127.0.0.1", 0)
        sockets << socket
        socket.addr[1]
      end
      {http: CONTROL_IDS.to_h { |id| [id, draw.call] },
       raft: CONTROL_IDS.to_h { |id| [id, draw.call] }}
    ensure
      sockets&.each { |socket| socket.close unless socket.closed? }
    end

    def free_port
      socket = TCPServer.new("127.0.0.1", 0)
      port = socket.addr[1]
      socket.close
      port
    end

    # kube-apiserver --kubelet-client-certificate / -key and
    # --kubelet-certificate-authority, with component identities on.
    def kubelet_client_config(pki)
      identity = pki[:identities]&.fetch("kube-apiserver-kubelet-client", nil)
      return {} unless identity

      {"kubelet_client" => {"cert_file" => identity.fetch(:cert), "key_file" => identity.fetch(:key), "ca_file" => pki.fetch(:ca)}}
    end

    # The kubelet API behind TLS, webhook authentication and Webhook
    # authorization (KubeletConfiguration authentication / authorization).
    def kubelet_streaming_security(pki, id)
      serving = pki[:identities]&.fetch("kubelet-serving-#{id}", nil)
      return {} unless serving

      {"tls" => {"cert_file" => serving.fetch(:cert), "key_file" => serving.fetch(:key), "client_ca_file" => pki.fetch(:ca)},
       "authentication" => {"anonymous" => false, "webhook" => true},
       "authorization" => {"mode" => "Webhook"}}
    end

    def write_apiserver_config(root, id, _index, ports, pki, profile)
      peers = CONTROL_IDS.reject { |peer| peer == id }
        .to_h { |peer| [peer, "127.0.0.1:#{ports.fetch(:raft).fetch(peer)}"] }
      document = {
        "version" => 1, "logging" => {"level" => "info"},
        "processes" => {
          "rubernetes-apiserver" => {
            # Pods reach the API server through the kubernetes Service, whose
            # endpoint is the advertise address: bind everywhere, advertise the
            # host's primary address.
            # "::" is a dual-stack listener (loopback and the host address of
            # either family); an IPv4-only profile keeps the IPv4 wildcard.
            "bind_address" => families(profile).include?("ipv6") ? "::" : "0.0.0.0", "port" => ports.fetch(:http).fetch(id),
            # The `kubernetes` Service endpoint: an address of the profile's
            # primary family, or an IPv6-only Pod has no route to it.
            "advertise_address" => host_advertise_address(families(profile).first),
            "service_cluster_ip_range" => service_cidrs(profile).length == 1 ? service_cidrs(profile).first : service_cidrs(profile),
            "max_body_bytes" => 3_145_728, "watch_history_limit" => 100_000,
            "tls" => {"cert_file" => pki.fetch(:server), "key_file" => pki.fetch(:server_key)},
            "proxy_client" => {"cert_file" => pki.fetch(:front_proxy), "key_file" => pki.fetch(:front_proxy_key)},
            **kubelet_client_config(pki),
            "security" => {
              "authentication" => {
                "client_ca_file" => pki.fetch(:ca),
                **(TLS_BOOTSTRAP ? {"bootstrap_tokens" => true} : {}),
                # --requestheader-*: published in kube-system/extension-
                # apiserver-authentication for aggregated API servers.
                "request_header" => {"ca_file" => pki.fetch(:front_proxy_ca), "allowed_names" => ["front-proxy-client"],
                                     "username_headers" => ["X-Remote-User"], "uid_headers" => ["X-Remote-Uid"],
                                     "group_headers" => ["X-Remote-Group"], "extra_header_prefixes" => ["X-Remote-Extra-"]},
                # kube-apiserver's conventional issuer: a URL Pods resolve
                # through cluster DNS, so the OIDC discovery document and its
                # JWKS are reachable from inside the cluster, which
                # "ServiceAccountIssuerDiscovery should support OIDC discovery"
                # verifies from a Pod.
                "service_account" => {"issuer" => "https://kubernetes.default.svc.cluster.local",
                                      "signing_key_file" => pki.fetch(:sa_key),
                                      "key_files" => [pki.fetch(:sa_pub)],
                                      "api_audiences" => ["https://kubernetes.default.svc.cluster.local"]},
                "anonymous" => {"enabled" => false}
              },
              "authorization" => {"modes" => %w[Node RBAC]}
            },
            "datastore" => {
              "type" => "raft", "node_id" => id, "cluster_id" => "m8-#{profile.fetch("name")}",
              "data_dir" => File.join(root, "data", id), "pki_dir" => File.join(root, "raft-pki", id),
              "listen_address" => "127.0.0.1", "listen_port" => ports.fetch(:raft).fetch(id),
              "voters" => CONTROL_IDS, "peers" => peers
            }
          }
        }
      }
      write_config(root, "apiserver-#{id}", document)
    end

    # kube-scheduler's --secure-port equivalent (upstream 10259): /healthz,
    # /metrics and /metrics/resources on a loopback port of its own, which
    # the dashboard's discovery reads back from this file.
    def write_scheduler_config(root, kubeconfig, lease_name: "m8-scheduler", serving_port: free_port)
      write_config(root, "scheduler", {
                     "version" => 1, "logging" => {"level" => "info"},
                     "processes" => {"rubernetes-scheduler" => {
                       "kubeconfig" => kubeconfig, "identity" => "m8-scheduler",
                       "sync" => {"interval_seconds" => 0.5},
                       "lease" => {"namespace" => "kube-system", "name" => lease_name,
                                   "lease_duration_seconds" => 15, "renew_deadline_seconds" => 10,
                                   "retry_period_seconds" => 2},
                       "serving" => {"enabled" => true, "bind_address" => "127.0.0.1", "port" => serving_port}
                     }}
                   })
    end

    # Which controllers this cluster runs.  Two exclusions, both of which the
    # controller manager treats as fatal rather than skippable, so they have to
    # be settled before it starts:
    #
    #  * the cloud controllers, which refuse to start without an injected
    #    provider, exactly as kube-controller-manager does with no
    #    --cloud-provider;
    #  * controllers whose kind this apiserver does not serve -- a feature gate
    #    that is off by default (ClusterTrustBundle, PodCertificateRequest, ...)
    #    means the informer's first list 404s and takes the process down.
    #
    # Both sets are derived, not listed, so a controller added upstream or a
    # gate flipped in the corpus is picked up instead of silently dropped.
    # A controller-only marker kind.  The garbage collector is identified by a
    # kind no apiserver ever serves ("GarbageCollector") because its subject is
    # every object's ownerReferences rather than one resource, so the
    # served-kind filter below dropped it and the cluster ran with no garbage
    # collection at all: an EndpointSlice whose Service was deleted, a
    # ReplicaSet whose Deployment was deleted and a CustomResourceDefinition's
    # instances all stayed in the API for ever.
    CONTROLLER_ONLY_KINDS = %w[GarbageCollector].freeze

    def selected_controllers(kubeconfig)
      served = served_kinds(kubeconfig)
      Rubernetes::Controller::BuiltinControllerCorpus::ENTRIES.reject do |entry|
        entry.cloud_provider || (!served.include?(entry.kind) && !CONTROLLER_ONLY_KINDS.include?(entry.kind))
      end.map(&:name)
    end

    def served_kinds(kubeconfig)
      kinds = Set.new
      groups = kubectl_json(kubeconfig, "get", "--raw", "/apis")
      paths = Array(groups && groups["groups"]).filter_map do |group|
        version = group.dig("preferredVersion", "groupVersion") || group["versions"]&.first&.dig("groupVersion")
        "/apis/#{version}" if version
      end
      paths << "/api/v1"
      paths.each do |path|
        document = kubectl_json(kubeconfig, "get", "--raw", path)
        Array(document && document["resources"]).each do |resource|
          kinds << resource["kind"].to_s unless resource["name"].to_s.include?("/")
        end
      end
      raise "discovery returned no served kinds" if kinds.empty?

      kinds
    end

    def kubectl_json(kubeconfig, *arguments)
      output = IO.popen([KUBECTL, "--kubeconfig", kubeconfig, *arguments], err: File::NULL, &:read)
      return nil unless $CHILD_STATUS&.success?

      JSON.parse(output)
    rescue JSON::ParserError
      nil
    end

    def write_controller_config(root, kubeconfig, service_account_credentials: false, discovery_kubeconfig: kubeconfig,
                                serving_port: free_port)
      write_config(root, "controller-manager", {
                     "version" => 1, "logging" => {"level" => ENV.fetch("RUBERNETES_M8_CONTROLLER_LOG_LEVEL", "info")},
                     "processes" => {"rubernetes-controller-manager" => {
                       "kubeconfig" => kubeconfig, "identity" => "m8-controller-manager",
                       "controllers" => selected_controllers(discovery_kubeconfig),
                       "sync" => {"interval_seconds" => 0.5},
                       # kube-controller-manager's --secure-port (upstream 10257): /metrics and
                       # the health endpoints on loopback.
                       "serving" => {"enabled" => true, "bind_address" => "127.0.0.1", "port" => serving_port},
                       # kubeadm's --cluster-signing-{cert,key}-file: the cluster CA the
                       # apiserver trusts for client certificates.
                       "cluster_signing" => {"cert_file" => File.join(root, "pki", "ca.crt"),
                                             "key_file" => File.join(root, "pki", "ca.key")},
                       # kubeadm's --service-account-private-key-file: the tokens
                       # controller signs legacy service-account-token Secrets.
                       "service_account_private_key_file" => File.join(root, "pki", "service-account.key"),
                       "lease" => {"namespace" => "kube-system",
                                   "name" => service_account_credentials ? "kube-controller-manager" : "m8-controller-manager",
                                   "lease_duration_seconds" => 15, "renew_deadline_seconds" => 10,
                                   "retry_period_seconds" => 2}
                     }.merge(service_account_credentials ? {"use_service_account_credentials" => true} : {})}
                   })
    end

    def write_agent_config(root, id, index, kubeconfig, profile, dns_kubeconfig: nil, pki: {}, bootstrap: nil)
      families = profile.fetch("ip_families")
      network = {"state_path" => File.join(root, "network", id, "state.json"),
                 "bridge_name" => "rbn#{index}", "policy_backend" => "nftables",
                 "node_subnet_prefix" => 24}
      network["ipv4_cidr"] = pod_cidr(index, "ipv4") if families.include?("ipv4")
      if families.include?("ipv6")
        network["ipv6_cidr"] = pod_cidr(index, "ipv6")
        network["ipv6_node_prefix"] = 64
      end

      write_config(root, "agent-#{id}", {
                     "version" => 1, "logging" => {"level" => ENV.fetch("RUBERNETES_M8_AGENT_LOG_LEVEL", "info")},
                     "processes" => {"rubernetes-agent" => {
                       "node_name" => id, "kubeconfig" => kubeconfig,
                       "runtime_profile" => "kernel_isolation",
                       "sandbox_root" => File.join(root, "runtime", id, "sandbox"),
                       "cgroup_root" => CGROUP_ROOT,
                       "log_root" => File.join(root, "runtime", id, "log"),
                       "journal_path" => File.join(root, "runtime", id, "ledger.jsonl"),
                       "sync" => {"period_seconds" => 5, "watch_timeout_seconds" => 30},
                       "lease" => {"namespace" => "kube-node-lease", "duration_seconds" => 40,
                                   "renew_fraction" => 0.25},
                       "privileged" => true,
                       # Each agent needs its own streaming port on this host;
                       # the API server proxies logs/exec to whatever the node
                       # advertises.
                       # Above 20000: the host runs its own k3s kubelet on 10250.
                       # The node's InternalIP comes from this advertise
                       # address, and a loopback node IP is not a node IP:
                       # kubelet refuses one outright ("--node-ip cannot be a
                       # loopback address", pkg/kubelet/kubelet.go).  Every
                       # spec that dials a node by its InternalIP -- HostPort
                       # above all -- reached its own loopback instead.  Each
                       # worker's own bridge gateway is the address its Pods
                       # and this host both reach it on.
                       # The streaming endpoint trusts the API server's own
                       # authorization and has no authorizer of its own, so it
                       # stays on loopback; the API server learns where to dial
                       # it from the node's streaming-address annotation, not
                       # from its InternalIP.
                       "streaming" => {"host" => "127.0.0.1", "port" => free_port,
                                       "advertise_address" => "127.0.0.1"}.merge(kubelet_streaming_security(pki, id)),
                       "addresses" => [*node_advertise_addresses(index, profile).map do |address|
                         {"type" => "InternalIP", "address" => address}
                       end,
                                       {"type" => "Hostname", "address" => id}],
                       "network" => network,
                       "volume" => {"data_dir" => File.join(root, "runtime", id, "volumes"),
                                    "profile" => "native"}
                     }.merge(dns_kubeconfig ? {"dns" => {"kubeconfig" => dns_kubeconfig}} : {}).merge(bootstrap || {})}
                   })
    end

    # All "nodes" of this profile share one kernel, so exactly one proxy owns
    # the host datapath (nftables table); the others run the same control
    # loops without attaching, which is also what keeps them from fighting
    # over the table.
    # The first address of this node's own Pod bridge (10.24N.0.1), which the
    # agent creates before its first Pod and which is reachable from the host
    # and from every Pod on the cluster.
    # One per family of the profile, primary family first: the first address
    # of the node's Pod bridge subnet (10.24N.0.1 / fd00:d8:N::1), which the
    # agent's IPAM hands the first node of each CIDR and assigns to the
    # bridge before the first Pod.  kubelet publishes one InternalIP per
    # family on a dual-stack node (--node-ip "ipv4,ipv6").
    def node_advertise_addresses(index, profile)
      families(profile).map do |family|
        if family == "ipv4"
          IPAddr.new(IPAddr.new(pod_cidr(index, "ipv4")).to_i + 1, Socket::AF_INET).to_s
        else
          IPAddr.new(IPAddr.new(pod_cidr(index, "ipv6")).to_i + 1, Socket::AF_INET6).to_s
        end
      end
    end

    def node_advertise_address(index, profile)
      node_advertise_addresses(index, profile).first
    end

    def families(profile)
      profile.fetch("ip_families").map(&:to_s)
    end

    # The cluster Pod CIDR of one worker: a /16 or /48 per node from which
    # its agent carves its own /24 or /64.
    def pod_cidr(index, family)
      family == "ipv4" ? "10.#{240 + index}.0.0/16" : "fd00:d8:#{index}::/48"
    end

    def service_cidrs(profile)
      families(profile).map { |family| SERVICE_CIDRS.fetch(family) }
    end

    # kube-proxy's --metrics-bind-address / --healthz-bind-address (upstream
    # 10249 / 10256), one loopback port here: /metrics, /healthz, /livez.
    def write_proxy_config(root, id, index, kubeconfig, serving_port: free_port)
      write_config(root, "proxy-#{id}", {
                     "version" => 1, "logging" => {"level" => ENV.fetch("RUBERNETES_M8_PROXY_LOG_LEVEL", "info")},
                     "processes" => {"rubernetes-proxy" => {
                       "kubeconfig" => kubeconfig, "node_name" => id,
                       "backend" => "nftables", "attach" => index.zero?,
                       "sync" => {"interval_seconds" => 0.5},
                       "serving" => {"enabled" => true, "bind_address" => "127.0.0.1", "port" => serving_port}
                     }}
                   })
    end

    # The first non-loopback IPv4 address of the host (the route toward the
    # default gateway), which every Pod bridge can reach.
    # The `kubernetes` Service address: the first usable address of the
    # primary service CIDR, matching the API server's own bootstrap.
    SERVICE_CIDR_IPV4 = SERVICE_CIDRS.fetch("ipv4")

    # One per family, the primary first; the API server bootstraps the
    # Service with the primary and the profile's families as ipFamilies.
    def service_cluster_ips(profile)
      service_cidrs(profile).map do |cidr|
        network = IPAddr.new(cidr)
        IPAddr.new(network.to_i + 1, network.family).to_s
      end
    end

    def service_cluster_ip(profile = nil)
      profile ? service_cluster_ips(profile).first : service_cluster_ips({"ip_families" => ["ipv4"]}).first
    end

    def host_advertise_address(family = "ipv4")
      if family.to_s == "ipv6"
        output = `ip -6 route get 2606:4700:4700::1111 2>/dev/null`
        address = output[/\bsrc\s+(\S+)/, 1]
        return address if address && !address.empty?

        return Socket.ip_address_list.find do |entry|
          entry.ipv6? && !entry.ipv6_loopback? && !entry.ipv6_linklocal? && !entry.ipv6_multicast?
        end&.ip_address || "::1"
      end

      output = `ip -4 route get 1.1.1.1 2>/dev/null`
      address = output[/\bsrc\s+(\S+)/, 1]
      return address if address && !address.empty?

      Socket.ip_address_list.find { |entry| entry.ipv4? && !entry.ipv4_loopback? && !entry.ipv4_multicast? }&.ip_address || "127.0.0.1"
    end

    def write_config(root, name, document)
      FileUtils.mkdir_p(File.join(root, "config"))
      path = File.join(root, "config", "#{name}.yml")
      File.write(path, YAML.dump(document))
      path
    end

    # ------------------------------------------------------------- processes

    # Ruby's default GC thresholds are sized for short scripts.  A node agent
    # starting thirty Pods at once allocated past the 16 MB malloc limit
    # every few hundred milliseconds and ran 18 major collections (marking
    # 340k old objects each) in a 20 s burst -- a fifth of its CPU.  Larger
    # limits trade some resident memory for far fewer collections.  An
    # explicit value in the environment still wins.
    GC_ENVIRONMENT = {
      "RUBY_GC_MALLOC_LIMIT" => (64 << 20).to_s,
      "RUBY_GC_MALLOC_LIMIT_MAX" => (256 << 20).to_s,
      "RUBY_GC_OLDMALLOC_LIMIT" => (128 << 20).to_s,
      "RUBY_GC_OLDMALLOC_LIMIT_MAX" => (512 << 20).to_s,
      "RUBY_GC_HEAP_OLDOBJECT_LIMIT_FACTOR" => "3.0",
      # Ruby's own defaults, listed so an experiment can override them from
      # the environment like the values above.
      "RUBY_GC_HEAP_FREE_SLOTS_MIN_RATIO" => "0.20",
      "RUBY_GC_HEAP_GROWTH_FACTOR" => "1.8"
    }.freeze

    def gc_environment
      GC_ENVIRONMENT.to_h { |name, value| [name, ENV.fetch(name, value)] }
    end

    def spawn_process(root, name, executable, config)
      FileUtils.mkdir_p([File.join(root, "logs"), File.join(root, "pids")])
      log = File.join(root, "logs", "#{name}.log")
      # glibc gives every thread that allocates concurrently its own 64 MB
      # malloc arena (up to 8 x cores).  A node agent runs a thread per Pod,
      # and its arenas alone held gigabytes resident after a conformance
      # round; two arenas are plenty for a Ruby process, whose object heap
      # is not malloc'd.
      environment = {"MALLOC_ARENA_MAX" => ENV.fetch("MALLOC_ARENA_MAX", "2")}.merge(gc_environment)
      pid = Process.spawn(environment, RbConfig.ruby, "-I", File.join(ROOT, "lib"),
                          "-I", File.join(ROOT, "build/ext/rubernetes_linux"),
                          File.join(ROOT, "exe/#{executable}"), "--config", config,
                          # Its own process group: the cluster must outlive the
                          # shell that started it, and a signal aimed at that
                          # shell must not take half the control plane with it.
                          out: [log, "a"], err: [log, "a"], chdir: ROOT, pgroup: true)
      File.write(File.join(root, "pids", "#{name}.pid"), pid.to_s)
      {"name" => name, "executable" => executable, "config" => config, "pid" => pid, "log" => log}
    end

    def terminate(pid, name)
      return nil unless alive?(pid)

      Process.kill("TERM", pid)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
      sleep(0.05) while alive?(pid) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      Process.kill("KILL", pid) if alive?(pid)
      begin
        Process.waitpid(pid, Process::WNOHANG)
      rescue Errno::ECHILD, Errno::ESRCH
        nil
      end
      {"name" => name, "pid" => pid}
    end

    def alive?(pid)
      Process.kill(0, pid)
      true
    rescue Errno::ESRCH, Errno::EPERM
      false
    end

    # ------------------------------------------------------------- readiness

    def await_apiservers!(ports, pki)
      CONTROL_IDS.each do |id|
        endpoint = "https://127.0.0.1:#{ports.fetch(:http).fetch(id)}/readyz"
        await!("apiserver #{id} /readyz") { readyz?(endpoint, pki) }
      end
    end

    def readyz?(url, pki)
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.ca_file = pki.fetch(:ca)
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      # Anonymous auth is off, so /readyz answers 401 without a client
      # certificate.  The probe presents the same admin identity the kubeconfig
      # carries rather than reading "unauthorized" as "not ready".
      http.cert = OpenSSL::X509::Certificate.new(File.read(pki.fetch(:admin)))
      http.key = OpenSSL::PKey::RSA.new(File.read(pki.fetch(:admin_key)))
      http.open_timeout = 2
      http.read_timeout = 5
      http.start { |connection| connection.get(uri.path).code == "200" }
    rescue StandardError
      false
    end

    def await_nodes!(kubeconfig, expected, since: nil)
      await!("#{expected} Ready nodes") do
        output = `#{KUBECTL} --kubeconfig #{kubeconfig} get nodes -o json 2>/dev/null`
        document =
          begin
            output.strip.empty? ? nil : JSON.parse(output)
          rescue JSON::ParserError
            nil
          end
        if document.nil?
          false
        else
          ready = document.fetch("items", []).count do |node|
            node.dig("status", "conditions")&.any? do |c|
              c["type"] == "Ready" && c["status"] == "True" && (since.nil? || Time.iso8601(c.fetch("lastHeartbeatTime")) >= since)
            end
          end
          ready >= expected
        end
      end
    end

    def await!(what)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + READY_TIMEOUT
      until yield
        raise "#{what} did not become ready within #{READY_TIMEOUT}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep(0.25)
      end
      true
    end

    def resolve_profile(name)
      profiles = L.profiles.fetch("profiles")
      return profiles.fetch(0) if name.nil?

      profiles.find { |profile| profile.fetch("name") == name } ||
        raise(ArgumentError, "unknown profile #{name.inspect}; known: #{profiles.map { |p| p.fetch("name") }.join(", ")}")
    end
  end
end

exit(Conformance::Cluster.run) if $PROGRAM_NAME == __FILE__
