# frozen_string_literal: true

require "socket"
require_relative "client_certificate_manager"

module Rubernetes
  module Node
    # RotateKubeletServerCertificate / serverTLSBootstrap: the kubelet's
    # serving certificate is requested from the cluster through a
    # CertificateSigningRequest for the kubernetes.io/kubelet-serving
    # signer (subject system:node:<name> in system:nodes, server auth, SANs
    # for the node's name and addresses) and rotated at 70-90% of its life,
    # like the client certificate.  The apiserver does not approve these
    # automatically; an approver (or the cluster admin) does.
    class ServingCertificateManager < ClientCertificateManager
      SIGNER = "kubernetes.io/kubelet-serving"
      PAIR_PREFIX = "kubelet-server"

      # +addresses+: the node's IP addresses and DNS names for the SANs, or
      # a callable returning them (they may not be known at construction).
      def initialize(node_name:, cert_dir:, addresses: nil, **)
        super(node_name: node_name, cert_dir: cert_dir, **)
        @addresses = addresses
      end

      def current_path
        File.join(@cert_dir, "#{PAIR_PREFIX}-current.pem")
      end

      # The key stored beside the current certificate (the pair file).
      def current_private_key
        return nil unless File.exist?(current_path)

        OpenSSL::PKey.read(File.read(current_path))
      rescue OpenSSL::PKey::PKeyError, SystemCallError
        nil
      end

      private

      def satisfies_template?(certificate)
        super && certificate.extensions.any? do |extension|
          extension.oid == "extendedKeyUsage" && extension.value.include?("Server Authentication")
        end
      end

      def certificate_request(key)
        request = OpenSSL::X509::Request.new
        request.version = 0
        request.subject = OpenSSL::X509::Name.new([["O", "system:nodes"], ["CN", "system:node:#{@node_name}"]])
        request.public_key = key
        factory = OpenSSL::X509::ExtensionFactory.new
        sans = subject_alternative_names
        extension = factory.create_extension("subjectAltName", sans.join(","))
        request.add_attribute(OpenSSL::X509::Attribute.new("extReq", OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Sequence.new([extension])])))
        request.sign(key, OpenSSL::Digest.new("SHA256"))
        request
      end

      def subject_alternative_names
        names = ["DNS:#{@node_name}"]
        Array(@addresses.respond_to?(:call) ? @addresses.call : @addresses).each do |address|
          value = address.to_s
          next if value.empty?

          names << (if value.match?(/\A[0-9a-fA-F:.]+\z/) && begin
            IPAddr.new(value)
          rescue StandardError
            nil
          end
                      "IP:#{value}"
                    else
                      "DNS:#{value}"
                    end)
        end
        names.uniq
      end

      def submit(client, request)
        spec = {"request" => [request.to_pem].pack("m0"), "signerName" => SIGNER,
                "usages" => ["digital signature", "key encipherment", "server auth"]}
        spec["expirationSeconds"] = @requested_lifetime if @requested_lifetime
        object = {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest",
                  "metadata" => {"generateName" => "csr-"}, "spec" => spec}
        created = client.create(object, api_version: "certificates.k8s.io/v1",
                                        path: "/apis/certificates.k8s.io/v1/certificatesigningrequests")
        name = created.to_h.dig("metadata", "name").to_s
        raise Error, "the CertificateSigningRequest was created without a name" if name.empty?

        name
      end

      def store!(pem, key)
        certificate = OpenSSL::X509::Certificate.new(pem)
        raise Error, "issued certificate does not match the requested key" unless certificate.check_private_key(key)

        FileUtils.mkdir_p(@cert_dir, mode: 0o700)
        stamp = @clock.call.utc.strftime("%Y-%m-%d-%H-%M-%S")
        path = File.join(@cert_dir, "#{PAIR_PREFIX}-#{stamp}.pem")
        File.write(path, pem.to_s.strip + "\n" + key.private_to_pem, perm: 0o600)
        link = File.join(@cert_dir, ".#{PAIR_PREFIX}-current.#{Process.pid}")
        File.unlink(link) if File.symlink?(link) || File.exist?(link)
        File.symlink(File.basename(path), link)
        File.rename(link, current_path)
        certificate
      end
    end
  end
end
