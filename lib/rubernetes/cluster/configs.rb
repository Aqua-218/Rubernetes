# frozen_string_literal: true

module Rubernetes
  module Cluster
    # One configuration file per process.
    module Configs
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
        {http: control_ids.to_h { |id| [id, draw.call] },
         raft: control_ids.to_h { |id| [id, draw.call] }}
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

      def write_apiserver_config(id, ports, pki)
        peers = control_ids.reject { |peer| peer == id }
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
              "bind_address" => families.include?("ipv6") ? "::" : "0.0.0.0", "port" => ports.fetch(:http).fetch(id),
              # The `kubernetes` Service endpoint: an address of the profile's
              # primary family, or an IPv6-only Pod has no route to it.
              "advertise_address" => host_advertise_address(families.first),
              "service_cluster_ip_range" => service_cidrs.length == 1 ? service_cidrs.first : service_cidrs,
              "max_body_bytes" => 3_145_728, "watch_history_limit" => 100_000,
              "tls" => {"cert_file" => pki.fetch(:server), "key_file" => pki.fetch(:server_key)},
              "proxy_client" => {"cert_file" => pki.fetch(:front_proxy), "key_file" => pki.fetch(:front_proxy_key)},
              **kubelet_client_config(pki), **extensions_section,
              "security" => {
                "authentication" => {
                  "client_ca_file" => pki.fetch(:ca),
                  **(tls_bootstrap? ? {"bootstrap_tokens" => true} : {}),
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
                "type" => "raft", "node_id" => id, "cluster_id" => cluster_id,
                "data_dir" => File.join(root, "data", id), "pki_dir" => File.join(root, "raft-pki", id),
                "listen_address" => "127.0.0.1", "listen_port" => ports.fetch(:raft).fetch(id),
                "voters" => control_ids, "peers" => peers
              }
            }
          }
        }
        write_config("apiserver-#{id}", document)
      end

      # kube-scheduler's --secure-port equivalent (upstream 10259): /healthz,
      # /metrics and /metrics/resources on a loopback port of its own, which
      # the dashboard's discovery reads back from this file.
      def write_scheduler_config(kubeconfig, serving_port: free_port)
        write_config("scheduler", {
                       "version" => 1, "logging" => {"level" => "info"},
                       "processes" => {"rubernetes-scheduler" => {
                         "kubeconfig" => kubeconfig, "identity" => "rubernetes-scheduler",
                         "sync" => {"interval_seconds" => 0.5},
                         "lease" => {"namespace" => "kube-system", "name" => "kube-scheduler",
                                     "lease_duration_seconds" => 15, "renew_deadline_seconds" => 10,
                                     "retry_period_seconds" => 2},
                         "serving" => {"enabled" => true, "bind_address" => "127.0.0.1", "port" => serving_port}
                       }.merge(extensions_section)}
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
      def selected_controllers(kubeconfig)
        served = served_kinds(kubeconfig)
        Rubernetes::Controller::BuiltinControllerCorpus::ENTRIES.reject do |entry|
          entry.cloud_provider || (!served.include?(entry.kind) && !CONTROLLER_ONLY_KINDS.include?(entry.kind))
        end.map(&:name)
      end

      def served_kinds(kubeconfig)
        client = api_client(kubeconfig)
        groups = JSON.parse(client.raw("GET", "/apis").body).fetch("groups", [])
        paths = groups.filter_map do |group|
          version = group.dig("preferredVersion", "groupVersion") || group["versions"]&.first&.dig("groupVersion")
          "/apis/#{version}" if version
        end
        kinds = (paths << "/api/v1").flat_map do |path|
          JSON.parse(client.raw("GET", path).body).fetch("resources", [])
            .reject { |resource| resource["name"].to_s.include?("/") }.map { |resource| resource["kind"].to_s }
        end.to_set
        raise Error, "discovery returned no served kinds" if kinds.empty?

        kinds
      ensure
        client&.close
      end

      def write_controller_config(kubeconfig, service_account_credentials: false, discovery_kubeconfig: kubeconfig,
                                  serving_port: free_port)
        write_config("controller-manager", {
                       "version" => 1, "logging" => {"level" => log_level("controller-manager")},
                       "processes" => {"rubernetes-controller-manager" => {
                         "kubeconfig" => kubeconfig, "identity" => "rubernetes-controller-manager",
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
                         "lease" => {"namespace" => "kube-system", "name" => "kube-controller-manager",
                                     "lease_duration_seconds" => 15, "renew_deadline_seconds" => 10,
                                     "retry_period_seconds" => 2}
                       }.merge(service_account_credentials ? {"use_service_account_credentials" => true} : {}).merge(extensions_section)}
                     })
      end

      def write_agent_config(id, index, kubeconfig, dns_kubeconfig: nil, pki: {}, bootstrap: nil)
        network = {"state_path" => File.join(root, "network", id, "state.json"),
                   "bridge_name" => "rbn#{index}", "policy_backend" => "nftables",
                   "node_subnet_prefix" => 24}
        network["ipv4_cidr"] = pod_cidr(index, "ipv4") if families.include?("ipv4")
        if families.include?("ipv6")
          network["ipv6_cidr"] = pod_cidr(index, "ipv6")
          network["ipv6_node_prefix"] = 64
        end

        write_config("agent-#{id}", {
                       "version" => 1, "logging" => {"level" => log_level("agent")},
                       "processes" => {"rubernetes-agent" => {
                         "node_name" => id, "kubeconfig" => kubeconfig,
                         "runtime_profile" => "kernel_isolation",
                         "sandbox_root" => File.join(root, "runtime", id, "sandbox"),
                         "cgroup_root" => cgroup_root,
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
                         "addresses" => [*node_advertise_addresses(index).map do |address|
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
      def node_advertise_addresses(index)
        families.map do |family|
          if family == "ipv4"
            IPAddr.new(IPAddr.new(pod_cidr(index, "ipv4")).to_i + 1, Socket::AF_INET).to_s
          else
            IPAddr.new(IPAddr.new(pod_cidr(index, "ipv6")).to_i + 1, Socket::AF_INET6).to_s
          end
        end
      end

      # The cluster Pod CIDR of one worker: a /16 or /48 per node from which
      # its agent carves its own /24 or /64.
      def pod_cidr(index, family)
        family == "ipv4" ? "10.#{240 + index}.0.0/16" : "fd00:d8:#{index}::/48"
      end

      def service_cidrs
        families.map { |family| SERVICE_CIDRS.fetch(family) }
      end

      # kube-proxy's --metrics-bind-address / --healthz-bind-address (upstream
      # 10249 / 10256), one loopback port here: /metrics, /healthz, /livez.
      def write_proxy_config(id, index, kubeconfig, serving_port: free_port)
        write_config("proxy-#{id}", {
                       "version" => 1, "logging" => {"level" => log_level("proxy")},
                       "processes" => {"rubernetes-proxy" => {
                         "kubeconfig" => kubeconfig, "node_name" => id,
                         "backend" => "nftables", "attach" => index.zero?,
                         "sync" => {"interval_seconds" => 0.5},
                         "serving" => {"enabled" => true, "bind_address" => "127.0.0.1", "port" => serving_port}
                       }}
                     })
      end

      # One per family, the primary first; the API server bootstraps the
      # Service with the primary and the profile's families as ipFamilies.
      def service_cluster_ips
        service_cidrs.map do |cidr|
          network = IPAddr.new(cidr)
          IPAddr.new(network.to_i + 1, network.family).to_s
        end
      end

      # The first non-loopback address of the host (the route toward the
      # default gateway), which every Pod bridge can reach.
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

      def write_config(name, document)
        FileUtils.mkdir_p(File.join(root, "config"))
        path = File.join(root, "config", "#{name}.yml")
        # Every process of a cluster on this host can be looked into
        # (`rubectl console`); the socket is its owner's alone.
        File.write(path, YAML.dump(document.merge("console" => {"socket" => File.join(root, "run", "#{name}.sock")})))
        path
      end
    end
  end
end
