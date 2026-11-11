# frozen_string_literal: true

module Rubernetes
  module Cluster
    # Certificates, kubeconfigs and the bootstrap objects a new cluster needs.
    module Pki
      def issue_pki
        directory = File.join(root, "pki")
        FileUtils.mkdir_p(directory)

        ca_key = OpenSSL::PKey::RSA.new(2048)
        ca = certificate(subject: "/CN=rubernetes-ca", key: ca_key, issuer_key: ca_key,
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
                                         *families.map { |family| "IP:#{host_advertise_address(family)}" },
                                         *service_cluster_ips.map { |ip| "IP:#{ip}" }].uniq)

        admin_key = OpenSSL::PKey::RSA.new(2048)
        admin = certificate(subject: "/O=system:masters/CN=#{ADMIN_USER}", key: admin_key,
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
        paths[:identities] = issue_component_identities(directory, ca, ca_key) if component_identities?
        paths
      end

      # Client certificates for the components' own identities.
      def component_subjects
        subjects = {"kube-scheduler" => "/CN=system:kube-scheduler", "kube-proxy" => "/CN=system:kube-proxy",
                    "kube-controller-manager" => "/CN=system:kube-controller-manager", "coredns" => "/CN=#{COREDNS_USER}",
                    "kube-apiserver-kubelet-client" => "/CN=#{KUBELET_CLIENT_USER}"}
        worker_ids.each { |id| subjects["node-#{id}"] = "/O=system:nodes/CN=system:node:#{id}" }
        subjects
      end

      def issue_component_identities(directory, ca, ca_key)
        component_subjects.to_h do |name, subject|
          key = OpenSSL::PKey::RSA.new(2048)
          cert = certificate(subject: subject, key: key, issuer_key: ca_key, issuer: ca, ca: false, client: true)
          cert_path = File.join(directory, "#{name}.crt")
          key_path = File.join(directory, "#{name}.key")
          File.write(cert_path, cert.to_pem)
          File.write(key_path, key.to_pem)
          [cert_path, key_path].each { |path| File.chmod(0o600, path) }
          [name, {cert: cert_path, key: key_path}]
        end.merge(issue_kubelet_serving(directory, ca, ca_key))
      end

      # kubelet --tls-cert-file: each worker's serving certificate, valid for
      # the addresses the API server dials it on.
      def issue_kubelet_serving(directory, ca, ca_key)
        worker_ids.each_with_index.to_h do |id, index|
          key = OpenSSL::PKey::RSA.new(2048)
          names = ["DNS:#{id}", "IP:127.0.0.1", "IP:::1",
                   *node_advertise_addresses(index).map { |address| "IP:#{address}" }].uniq
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
      def component_kubeconfig(endpoint, pki, component, fallback)
        identity = pki[:identities]&.fetch(component, nil)
        return fallback unless identity

        write_kubeconfig(endpoint, pki, name: "kubeconfig-#{component}", user: [component, identity])
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
        apply!(kubeconfig, manifest, "the bootstrap token")
        "#{id}.#{secret}"
      end

      def write_bootstrap_kubeconfig(endpoint, pki, id, token)
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

      def apply!(kubeconfig, manifest, what)
        client = api_client(kubeconfig)
        manifest.fetch("items").each { |item| client.apply(item, field_manager: "rubernetes-cluster", force: true) }
      rescue Client::Error => error
        raise Error, "applying #{what} failed: #{error.message[0, 300]}"
      ensure
        client&.close
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
        apply!(kubeconfig, manifest, "the CoreDNS RBAC")
      end

      # The raft transport authenticates peers with its own per-node bundles; the
      # datastore reads them from `pki_dir` and refuses to start without one.
      def issue_raft_identities(cluster_id)
        ca, ca_key = Rubernetes::Consensus::Identity.generate_ca(cluster_id)
        control_ids.each do |id|
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

      def write_kubeconfig(endpoint, pki, name: "kubeconfig", user: nil)
        user_name, credentials = user || [ADMIN_USER, {cert: pki.fetch(:admin), key: pki.fetch(:admin_key)}]
        document = {
          "apiVersion" => "v1", "kind" => "Config", "current-context" => "rubernetes",
          "clusters" => [{"name" => "rubernetes",
                          "cluster" => {"server" => endpoint,
                                        "certificate-authority" => pki.fetch(:ca)}}],
          "users" => [{"name" => user_name,
                       "user" => {"client-certificate" => credentials.fetch(:cert),
                                  "client-key" => credentials.fetch(:key)}}],
          "contexts" => [{"name" => "rubernetes",
                          "context" => {"cluster" => "rubernetes", "user" => user_name}}]
        }
        path = File.join(root, name)
        File.write(path, YAML.dump(document))
        File.chmod(0o600, path)
        path
      end
    end
  end
end
