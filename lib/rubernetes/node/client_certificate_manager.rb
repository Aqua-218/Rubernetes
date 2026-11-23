# frozen_string_literal: true

require "fileutils"
require "openssl"
require "tempfile"
require "yaml"

require_relative "../client/kubeconfig"

module Rubernetes
  module Node
    # The kubelet's client certificate (pkg/kubelet/certificate/kubelet.go,
    # bootstrap/bootstrap.go and client-go util/certificate, v1.36.2).
    #
    #   * TLS bootstrapping (--bootstrap-kubeconfig): with no valid client
    #     certificate yet, a CSR for CN=system:node:<name>, O=system:nodes to
    #     the kubernetes.io/kube-apiserver-client-kubelet signer is made with
    #     the bootstrap credentials, and the kubeconfig is written to use the
    #     issued pair (<cert_dir>/kubelet-client-current.pem).
    #   * rotation (RotateKubeletClientCertificate): at a jittered 70-90% of
    #     the certificate's lifetime a new ECDSA P-256 key and CSR are
    #     submitted with the current credentials; the issued certificate is
    #     stored as kubelet-client-<timestamp>.pem and the -current link
    #     moved to it, and the client's connections are reset so the next
    #     handshake presents it.
    class ClientCertificateManager
      SIGNER = "kubernetes.io/kube-apiserver-client-kubelet"
      PAIR_PREFIX = "kubelet-client"
      MAX_PAIR_BYTES = 1_048_576
      WAIT_TIMEOUT = 15 * 60.0
      POLL_INTERVAL = 2.0
      RETRY_INTERVAL = 30.0

      class Error < StandardError; end

      attr_reader :cert_dir

      def initialize(node_name:, cert_dir:, clock: -> { Time.now.utc }, random: Random.new,
                     sleeper: ->(seconds) { sleep(seconds) }, logger: nil, requested_lifetime: nil)
        @node_name = node_name.to_s
        @cert_dir = File.expand_path(cert_dir.to_s)
        @clock = clock
        @random = random
        @sleeper = sleeper
        @logger = logger
        @requested_lifetime = requested_lifetime && Integer(requested_lifetime)
        @mutex = Mutex.new
        @thread = nil
        @stop = false
      end

      def current_path
        File.join(@cert_dir, "#{self.class::PAIR_PREFIX}-current.pem")
      end

      # Read both credentials from the same generation even if rotation moves
      # the current link while a new TLS connection is being configured.
      def current_pair
        validate_store_directory!
        path = current_path
        if File.lstat(path).symlink?
          generation = File.readlink(path)
          timestamp = generation.delete_prefix("#{self.class::PAIR_PREFIX}-")
          raise Error, "invalid kubelet certificate generation" if timestamp == generation || !/\A[0-9]{4}(?:-[0-9]{2}){5}\.pem\z/.match?(timestamp)

          path = File.join(@cert_dir, generation)
        end

        flags = File::RDONLY | File::NONBLOCK
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        File.open(path, flags) do |file|
          stat = file.stat
          unless stat.file? && stat.uid == Process.euid && stat.mode.nobits?(0o077) && stat.mode.anybits?(0o400)
            raise Error, "kubelet client certificate and key must be a private regular file owned by the kubelet"
          end

          bytes = file.binmode.read(MAX_PAIR_BYTES + 1)
          raise Error, "kubelet client certificate and key file exceeds #{MAX_PAIR_BYTES} bytes" if bytes.bytesize > MAX_PAIR_BYTES

          bytes
        end
      rescue SystemCallError => error
        raise Error, "cannot read kubelet client certificate and key: #{error.message}"
      end

      # The current certificate, or nil when none is stored or it is not
      # the node's own (a template mismatch forces a new request).
      def current_certificate
        pair = current_pair
        certificate = OpenSSL::X509::Certificate.new(pair)
        return nil unless satisfies_template?(certificate)

        certificate if certificate.check_private_key(OpenSSL::PKey.read(pair))
      rescue OpenSSL::OpenSSLError, Error
        nil
      end

      def valid?(certificate = current_certificate)
        certificate && certificate.not_after > @clock.call && certificate.not_before <= @clock.call
      end

      # bootstrap.LoadClientCert: a kubeconfig whose client certificate is
      # still valid is used as it is; otherwise a certificate is requested
      # with +bootstrap_client+ and +kubeconfig_path+ written to use it.
      # ->() called after a failed renewal (the kubelet's renew-error counters).
      attr_writer :on_renew_failure

      def bootstrap!(kubeconfig_path:, bootstrap_client:, server:, ca_file: nil)
        return kubeconfig_path if File.exist?(kubeconfig_path) && kubeconfig_valid?(kubeconfig_path)

        rotate!(bootstrap_client) unless valid?
        write_kubeconfig(kubeconfig_path, server: server, ca_file: ca_file)
        kubeconfig_path
      end

      # nextRotationDeadline: now when the certificate is missing or does not
      # satisfy the template, else notBefore + a jittered 70-90% of its life.
      def rotation_deadline(certificate = current_certificate)
        return @clock.call if certificate.nil?

        total = certificate.not_after - certificate.not_before
        certificate.not_before + (total * (0.7 + (0.2 * @random.rand)))
      end

      # rotateCerts: one CSR, waited for until issued.  Returns the stored
      # certificate.
      def rotate!(client)
        key = OpenSSL::PKey::EC.generate("prime256v1")
        request = certificate_request(key)
        name = submit(client, request)
        pem = wait_for_certificate(client, name)
        store!(pem, key)
      end

      # Rotates in the background until #stop; +on_rotate+ runs after each
      # stored certificate (the client's connections are reset there).
      def start(client:, on_rotate: nil)
        @mutex.synchronize do
          return self if @thread&.alive?

          @stop = false
          @thread = Thread.new { rotation_loop(client, on_rotate) }
          @thread.name = "kubelet-client-certificate" if @thread.respond_to?(:name=)
        end
        self
      end

      def stop
        thread = @mutex.synchronize do
          @stop = true
          @thread
        end
        thread&.wakeup if thread&.alive?
        thread&.join(5)
        self
      rescue ThreadError
        self
      end

      private

      # ->() after a failed renewal (CertificateRenewFailure).

      def stopped? = @mutex.synchronize { @stop }

      def validate_store_directory!
        stat = File.lstat(@cert_dir)
        return if stat.directory? && stat.uid == Process.euid && stat.mode.nobits?(0o022) && File.realpath(@cert_dir) == @cert_dir

        raise Error, "kubelet client certificate directory must be owned by the kubelet, without writable group or other permissions or symlinks"
      end

      def rotation_loop(client, on_rotate)
        until stopped?
          wait = rotation_deadline - @clock.call
          if wait.positive?
            @sleeper.call([wait, 3600.0].min)
            next
          end
          begin
            certificate = rotate!(client)
            @logger&.call(:info, "certificate.rotated", subject: certificate.subject.to_s, not_after: certificate.not_after.utc.iso8601)
            on_rotate&.call(certificate)
          rescue StandardError => error
            @logger&.call(:warn, "certificate.rotation_failed", error: error.class.name, message: error.message.to_s[0, 300])
            begin
              @on_renew_failure&.call
            rescue StandardError
              nil
            end
            @sleeper.call(RETRY_INTERVAL)
          end
        end
      end

      def satisfies_template?(certificate)
        subject = certificate.subject.to_a
        common_name = subject.find { |entry| entry[0] == "CN" }&.fetch(1, nil)
        common_name == "system:node:#{@node_name}"
      end

      def certificate_request(key)
        request = OpenSSL::X509::Request.new
        request.version = 0
        request.subject = OpenSSL::X509::Name.new([["O", "system:nodes"], ["CN", "system:node:#{@node_name}"]])
        request.public_key = key
        request.sign(key, OpenSSL::Digest.new("SHA256"))
        request
      end

      # csr.RequestCertificate: generateName csr-, the kubelet client signer,
      # DefaultKubeletClientGetUsages for an ECDSA key.
      def submit(client, request)
        spec = {"request" => [request.to_pem].pack("m0"), "signerName" => SIGNER,
                "usages" => ["digital signature", "client auth"]}
        spec["expirationSeconds"] = @requested_lifetime if @requested_lifetime
        object = {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest",
                  "metadata" => {"generateName" => "csr-"}, "spec" => spec}
        created = client.create(object, api_version: "certificates.k8s.io/v1",
                                        path: "/apis/certificates.k8s.io/v1/certificatesigningrequests")
        name = created.to_h.dig("metadata", "name").to_s
        raise Error, "the CertificateSigningRequest was created without a name" if name.empty?

        name
      end

      # csr.WaitForCertificate: Approved with a certificate, or an error once
      # Denied / Failed or after the wait timeout.
      def wait_for_certificate(client, name)
        deadline = monotonic + WAIT_TIMEOUT
        loop do
          raise Error, "certificate rotation was stopped" if stopped?

          object = client.get("certificatesigningrequests", name, api_version: "certificates.k8s.io/v1").to_h
          conditions = Array(object.dig("status", "conditions"))
          if (denied = conditions.find { |condition| %w[Denied Failed].include?(condition["type"]) && condition["status"] != "False" })
            raise Error, "certificate signing request #{name} is #{denied["type"].downcase}: #{denied["reason"]} #{denied["message"]}".strip
          end

          certificate = object.dig("status", "certificate").to_s
          approved = conditions.any? { |condition| condition["type"] == "Approved" && condition["status"] != "False" }
          return certificate.unpack1("m") if approved && !certificate.empty?
          raise Error, "timed out waiting for the certificate signing request #{name}" if monotonic >= deadline

          @sleeper.call(POLL_INTERVAL)
        end
      end

      # certificate.FileStore Update: the pair in one timestamped file and the
      # -current symlink moved to it atomically.
      def store!(pem, key)
        certificate = OpenSSL::X509::Certificate.new(pem)
        raise Error, "issued certificate does not match the requested key" unless certificate.check_private_key(key)

        FileUtils.mkdir_p(@cert_dir, mode: 0o700)
        validate_store_directory!
        stamp = @clock.call.utc.strftime("%Y-%m-%d-%H-%M-%S")
        prefix = self.class::PAIR_PREFIX
        path = File.join(@cert_dir, "#{prefix}-#{stamp}.pem")
        atomic_write(path, pem.to_s.strip + "\n" + key.private_to_pem)
        link = File.join(@cert_dir, ".#{prefix}-current.#{Process.pid}")
        File.unlink(link) if File.symlink?(link) || File.exist?(link)
        File.symlink(File.basename(path), link)
        File.rename(link, current_path)
        certificate
      end

      def kubeconfig_valid?(path)
        context = Client::Kubeconfig.load(path).resolve(preload_exec: false, client_certificate_store: self)
        return valid? if context.client_certificate_store

        pem = context.client_certificate_data
        pem ||= File.binread(context.client_certificate_file, MAX_PAIR_BYTES + 1) if context.client_certificate_file
        return false if pem.nil? || pem.bytesize > MAX_PAIR_BYTES

        certificate = OpenSSL::X509::Certificate.new(pem)
        valid?(certificate)
      rescue Client::ConfigurationError, OpenSSL::X509::CertificateError, SystemCallError
        false
      end

      # The kubeconfig bootstrap writes: the rotated pair, both as the
      # certificate and the key (they share the file).
      def write_kubeconfig(path, server:, ca_file:)
        cluster = {"server" => server}
        cluster["certificate-authority"] = ca_file if ca_file
        document = {"apiVersion" => "v1", "kind" => "Config", "current-context" => "default-context",
                    "clusters" => [{"name" => "default-cluster", "cluster" => cluster}],
                    "users" => [{"name" => "default-auth",
                                 "user" => {"client-certificate" => current_path, "client-key" => current_path}}],
                    "contexts" => [{"name" => "default-context",
                                    "context" => {"cluster" => "default-cluster", "user" => "default-auth"}}]}
        FileUtils.mkdir_p(File.dirname(path))
        atomic_write(path, YAML.dump(document))
      end

      def atomic_write(path, content)
        Tempfile.create(".#{File.basename(path)}", File.dirname(path), binmode: true) do |file|
          file.write(content)
          file.fsync
          File.rename(file.path, path)
        end
      end

      def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
