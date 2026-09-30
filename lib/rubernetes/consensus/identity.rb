# frozen_string_literal: true

require "openssl"
require "fileutils"

require_relative "errors"

module Rubernetes
  module Consensus
    # Cluster PKI for the Raft transport.  Every node presents a certificate
    # issued by the cluster CA whose subjectAltName carries the cluster ID and
    # node ID as a URI (rubernetes-raft://<cluster_id>/<node_id>).  Peer
    # identity is taken from the verified certificate, never from the
    # payload (spec 5.3.6).
    module Identity
      URI_PREFIX = "rubernetes-raft://"
      ID_PATTERN = /\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/

      Bundle = Data.define(:certificate, :key, :ca_certificate)

      module_function

      def validate_id!(value, label)
        raise ArgumentError, "#{label} must match #{ID_PATTERN.inspect}" unless value.is_a?(String) && value.match?(ID_PATTERN)

        value
      end

      def peer_uri(cluster_id, node_id)
        "#{URI_PREFIX}#{validate_id!(cluster_id, "cluster_id")}/#{validate_id!(node_id, "node_id")}"
      end

      def generate_ca(cluster_id, days: 3650)
        validate_id!(cluster_id, "cluster_id")
        key = OpenSSL::PKey::EC.generate("prime256v1")
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = OpenSSL::BN.rand(96)
        certificate.subject = OpenSSL::X509::Name.new([["CN", "rubernetes-raft-ca-#{cluster_id}"]])
        certificate.issuer = certificate.subject
        certificate.public_key = key
        certificate.not_before = Time.now - 300
        certificate.not_after = Time.now + (days * 86_400)
        factory = OpenSSL::X509::ExtensionFactory.new(certificate, certificate)
        certificate.add_extension(factory.create_extension("basicConstraints", "CA:TRUE,pathlen:0", true))
        certificate.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
        certificate.add_extension(factory.create_extension("subjectKeyIdentifier", "hash"))
        certificate.add_extension(factory.create_extension("subjectAltName", "URI:#{URI_PREFIX}#{cluster_id}"))
        certificate.sign(key, OpenSSL::Digest.new("SHA256"))
        [certificate, key]
      end

      def issue_node(ca_certificate, ca_key, cluster_id:, node_id:, days: 3650)
        uri = peer_uri(cluster_id, node_id)
        key = OpenSSL::PKey::EC.generate("prime256v1")
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = OpenSSL::BN.rand(96)
        certificate.subject = OpenSSL::X509::Name.new([["CN", "#{cluster_id}.#{node_id}"]])
        certificate.issuer = ca_certificate.subject
        certificate.public_key = key
        certificate.not_before = Time.now - 300
        certificate.not_after = Time.now + (days * 86_400)
        factory = OpenSSL::X509::ExtensionFactory.new(ca_certificate, certificate)
        certificate.add_extension(factory.create_extension("basicConstraints", "CA:FALSE", true))
        certificate.add_extension(factory.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
        certificate.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth,clientAuth"))
        certificate.add_extension(factory.create_extension("subjectAltName", "URI:#{uri}"))
        certificate.add_extension(factory.create_extension("authorityKeyIdentifier", "keyid:always"))
        certificate.sign(ca_key, OpenSSL::Digest.new("SHA256"))
        Bundle.new(certificate: certificate, key: key, ca_certificate: ca_certificate)
      end

      # Extract {cluster_id, node_id} from a verified peer certificate.
      def peer_identity(certificate)
        raise PeerIdentityMismatch, "peer presented no certificate" if certificate.nil?

        extension = certificate.extensions.find { |ext| ext.oid == "subjectAltName" }
        raise PeerIdentityMismatch, "peer certificate has no subjectAltName" if extension.nil?

        uris = extension.value.split(",").map(&:strip).filter_map { |entry| entry.delete_prefix("URI:") if entry.start_with?("URI:") }
        matches = uris.filter_map do |uri|
          next unless uri.start_with?(URI_PREFIX)

          parts = uri.delete_prefix(URI_PREFIX).split("/")
          next unless parts.length == 2 && parts.all? { |part| part.match?(ID_PATTERN) }

          {cluster_id: parts[0], node_id: parts[1]}
        end
        raise PeerIdentityMismatch, "peer certificate must carry exactly one rubernetes-raft identity" unless matches.length == 1

        matches.first
      end

      # Persist and load bundles.
      def write_bundle(directory, bundle)
        FileUtils.mkdir_p(directory)
        File.write(File.join(directory, "ca.pem"), bundle.ca_certificate.to_pem, perm: 0o600)
        File.write(File.join(directory, "node.pem"), bundle.certificate.to_pem, perm: 0o600)
        File.write(File.join(directory, "node-key.pem"), bundle.key.to_pem, perm: 0o600)
        directory
      end

      def read_bundle(directory)
        Bundle.new(
          certificate: OpenSSL::X509::Certificate.new(File.binread(File.join(directory, "node.pem"))),
          key: OpenSSL::PKey.read(File.binread(File.join(directory, "node-key.pem"))),
          ca_certificate: OpenSSL::X509::Certificate.new(File.binread(File.join(directory, "ca.pem")))
        )
      end

      def write_ca(directory, certificate, key)
        FileUtils.mkdir_p(directory)
        File.write(File.join(directory, "ca.pem"), certificate.to_pem, perm: 0o600)
        File.write(File.join(directory, "ca-key.pem"), key.to_pem, perm: 0o600)
        directory
      end

      def read_ca(directory)
        [OpenSSL::X509::Certificate.new(File.binread(File.join(directory, "ca.pem"))),
         OpenSSL::PKey.read(File.binread(File.join(directory, "ca-key.pem")))]
      end
    end
  end
end
