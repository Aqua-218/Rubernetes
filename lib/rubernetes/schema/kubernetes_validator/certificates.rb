# frozen_string_literal: true

require_relative "../../pem"

module Rubernetes
  module Schema
    # certificates.k8s.io: CertificateSigningRequest, ClusterTrustBundle and
    # PodCertificateRequest, including the PKCS#10 and PKIX key checks.
    module KubernetesValidator
      module_function

      POD_CERTIFICATE_REQUEST_DEFAULT_MAX_EXPIRATION = 86_400
      MAX_TRUST_BUNDLE_SIZE = 1024 * 1024

      def certificate_signing_request_errors(root, operation)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        request = fetch(spec, "request")
        # pkg/apis/certificates ParseCSR: the wire value is the base64 of a PEM
        # document whose first block must be a CERTIFICATE REQUEST holding a
        # parseable PKCS#10 request.
        issues.concat(certificate_request_errors(request)) unless blank?(request)

        usages = fetch(spec, "usages")
        issues << issue(%w[spec usages], :required, "") unless usages.is_a?(Array) && !usages.empty?

        signer = fetch(spec, "signerName")
        if blank?(signer)
          issues << issue(%w[spec signerName], :required, "")
        elsif !signer.to_s.match?(%r{\A[a-z0-9][a-z0-9.-]*/[a-z0-9][a-z0-9.-]*\z})
          issues << issue(
            %w[spec signerName], :invalid,
            "must be a fully qualified domain and path of the form 'example.com/signer-name'"
          )
        end
        if operation == :update
          status = fetch(root, "status")
          conditions = status.is_a?(Hash) ? fetch(status, "conditions") : nil
          if conditions.is_a?(Array)
            conditions.each_with_index do |condition, index|
              next unless condition.is_a?(Hash)

              value = fetch(condition, "status")
              next if %w[False True Unknown].include?(value.to_s)

              issues << issue(["status", "conditions", index.to_s, "status"], :unsupported,
                              "supported values: \"False\", \"True\", \"Unknown\"")
            end
          end
        end
        issues
      end

      # pkg/apis/certificates/helpers.go ParseCSR
      def certificate_request_errors(value)
        require "openssl"
        path = %w[spec request]
        bytes = decode_wire_bytes(value)
        bytes = value.to_s if bytes.nil?
        match = bytes.match(/-----BEGIN ([^-]+)-----/)
        return [issue(path, :invalid, "PEM block type must be CERTIFICATE REQUEST")] if match.nil? || match[1] != "CERTIFICATE REQUEST"

        OpenSSL::X509::Request.new(bytes)
        []
      rescue OpenSSL::X509::RequestError, OpenSSL::ASN1::ASN1Error, ArgumentError
        [issue(path, :invalid, "must be a valid PKCS#10 certificate request")]
      end

      def cluster_trust_bundle_errors(root, operation, old)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        signer = fetch(spec, "signerName").to_s
        signer_path = %w[spec signerName]
        issues = signer.empty? ? [] : signer_name_errors(signer, signer_path)
        trust_bundle = fetch(spec, "trustBundle").to_s
        previous = fetch(old, "spec")
        if operation == :update && previous.is_a?(Hash)
          issues.concat(trust_bundle_pem_errors(trust_bundle)) if trust_bundle != fetch(previous, "trustBundle").to_s
          if signer != fetch(previous, "signerName").to_s
            issues << ValidationIssue.new(path: signer_path, code: :invalid, value: signer, message: "field is immutable")
          end
        else
          issues.concat(trust_bundle_pem_errors(trust_bundle))
        end

        issues
      end

      def trust_bundle_pem_errors(bundle)
        require "openssl"
        path = %w[spec trustBundle]
        return [issue(path, :too_long, "may not be more than #{MAX_TRUST_BUNDLE_SIZE} bytes")] if bundle.bytesize > MAX_TRUST_BUNDLE_SIZE

        anchors = Hash.new { |indices, bytes| indices[bytes] = [] }
        errors = PEM.blocks(bundle).each_with_index.filter_map do |block, index|
          detail = trust_bundle_block_error(block)
          if detail
            trust_bundle_issue(path, "entry #{index} #{detail}")
          else
            anchors[block.bytes] << index
            nil
          end
        end
        return errors unless errors.empty?
        return [trust_bundle_issue(path, "at least one trust anchor must be provided")] if anchors.empty?

        anchors.values.filter_map do |indices|
          trust_bundle_issue(path, "duplicate trust anchor (indices [#{indices.join(" ")}])") if indices.length > 1
        end
      end

      def trust_bundle_block_error(block)
        return "has bad block type: #{block.type}" unless block.type == "CERTIFICATE"
        return "has PEM block headers" if block.headers

        certificate = OpenSSL::X509::Certificate.new(block.bytes)
        return "does not parse as X.509" unless certificate.to_der == block.bytes

        constraints = certificate.extensions.find { |extension| extension.oid == "basicConstraints" }
        return "does not have the CA bit set" unless constraints&.value&.match?(/\ACA:TRUE(?:,|\z)/)

        nil
      rescue OpenSSL::OpenSSLError, ArgumentError
        "does not parse as X.509"
      end

      def trust_bundle_issue(path, message)
        ValidationIssue.new(path: path, code: :invalid, value: "<value omitted>", message: message, kubernetes_type: "Invalid value")
      end

      def signer_name_errors(value, path)
        value = value.to_s
        return [issue(path, :required, "")] if value.empty?

        segments = value.split("/", -1)
        unless segments.length == 2
          return [issue(path, :invalid,
                        "must be a fully qualified domain and path of the form 'example.com/signer-name'")]
        end

        issues = []
        domain, signer_path = segments
        issues << issue(path, :too_long, "may not be more than 253 bytes") if domain.length > 253
        domain_labels = domain.split(".", -1)
        domain_labels.each do |label|
          messages = dns1123_label_messages(label)
          next if messages.empty?

          issues.concat(messages.map { |message| issue(path, :invalid, "validating label #{label.inspect}: #{message}") })
          break
        end
        issues << issue(path, :invalid, "should be a domain with at least two segments separated by dots") if domain_labels.length < 2
        signer_path.split(".", -1).each do |label|
          messages = dns1123_subdomain_messages(label)
          next if messages.empty?

          issues.concat(messages.map { |message| issue(path, :invalid, "validating label #{label.inspect}: #{message}") })
          break
        end
        issues << issue(path, :too_long, "may not be more than 571 bytes") if value.length > 571
        issues
      end

      def pod_certificate_request_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = signer_name_errors(fetch(spec, "signerName"), %w[spec signerName])
        annotations = fetch(spec, "unverifiedUserAnnotations")
        if annotations.is_a?(Hash)
          annotations.each_key do |key|
            issues.concat(invalid_messages(%w[spec unverifiedUserAnnotations], qualified_name_messages(key.to_s.downcase)))
          end
        end
        {"podName" => "podUID", "serviceAccountName" => "serviceAccountUID", "nodeName" => "nodeUID"}.each do |name_field, uid_field|
          issues.concat(invalid_messages(["spec", name_field], dns1123_subdomain_messages(fetch(spec, name_field).to_s)))
          uid = fetch(spec, uid_field).to_s
          issues << issue(["spec", uid_field], :invalid, "must not be empty") if uid.empty?
          issues << issue(["spec", uid_field], :too_long, "may not be more than 128 bytes") if uid.length > 128
        end
        # pkg/apis/certificates/v1beta1/defaults.go SetDefaults_PodCertificateRequestSpec
        # supplies MaxExpirationSeconds before validation runs.
        max_expiration = fetch(spec, "maxExpirationSeconds")
        max_expiration = POD_CERTIFICATE_REQUEST_DEFAULT_MAX_EXPIRATION if max_expiration.nil?
        signer = fetch(spec, "signerName").to_s
        kubernetes_signer = signer.start_with?("kubernetes.io/")
        upper = kubernetes_signer ? 86_400 : 7_862_400
        unless max_expiration.is_a?(Integer) && max_expiration >= 3600 && max_expiration <= upper
          issues << issue(%w[spec maxExpirationSeconds], :invalid, "must be in the range [3600, #{upper}]")
        end
        stub = fetch(spec, "stubPKCS10Request").to_s
        pkix = fetch(spec, "pkixPublicKey").to_s
        proof = fetch(spec, "proofOfPossession").to_s
        if !stub.empty? && pkix.empty? && proof.empty?
          issues.concat(stub_pkcs10_request_errors(stub))
        elsif stub.empty? && !pkix.empty? && !proof.empty?
          issues.concat(pkix_public_key_errors(pkix, proof, fetch(spec, "podUID").to_s))
        else
          issues << issue(%w[spec], :invalid, "exactly one of (stubPKCS10Request) or (pkixPublicKey, proofOfPossession) must be set")
        end
        issues
      end

      def decode_wire_bytes(value)
        require "base64"
        Base64.strict_decode64(value.to_s)
      rescue ArgumentError
        nil
      end

      def stub_pkcs10_request_errors(encoded)
        require "openssl"
        path = %w[spec stubPKCS10Request]
        der = decode_wire_bytes(encoded)
        return [issue(path, :invalid, "must be a valid PKCS#10 CSR")] if der.nil?
        return [issue(path, :too_long, "may not be more than 10240 bytes")] if der.bytesize > 10_240

        request = begin
          OpenSSL::X509::Request.new(der)
        rescue OpenSSL::X509::RequestError, OpenSSL::ASN1::ASN1Error
          nil
        end
        return [issue(path, :invalid, "must be a valid PKCS#10 CSR")] if request.nil?

        public_key = request.public_key
        case public_key
        when OpenSSL::PKey::EC
          curve = public_key.group.curve_name
          return [issue(path, :invalid, "elliptic public keys must use curve P256, P384, or P521")] unless %w[prime256v1 secp384r1
                                                                                                              secp521r1].include?(curve)
        when OpenSSL::PKey::RSA
          bits = public_key.n.num_bits
          return [issue(path, :invalid, "RSA keys must have modulus size 3072 or 4096")] unless [3072, 4096].include?(bits)
        else
          unless public_key.oid == "ED25519"
            return [issue(path, :invalid,
                          "unknown public key type; supported types are Ed25519, ECDSA, and RSA")]
          end
        end
        request.verify(public_key) ? [] : [issue(path, :invalid, "invalid signature")]
      rescue OpenSSL::PKey::PKeyError
        [issue(path, :invalid, "must be a valid PKCS#10 CSR")]
      end

      def pkix_public_key_errors(pkix, proof, pod_uid)
        require "openssl"
        pkix_path = %w[spec pkixPublicKey]
        proof_path = %w[spec proofOfPossession]
        key_der = decode_wire_bytes(pkix)
        proof_der = decode_wire_bytes(proof)
        return [issue(pkix_path, :invalid, "must be a valid PKIX-serialized public key")] if key_der.nil?
        return [issue(pkix_path, :too_long, "may not be more than 10240 bytes")] if key_der.bytesize > 10_240
        return [issue(proof_path, :too_long, "may not be more than 10240 bytes")] if proof_der && proof_der.bytesize > 10_240

        public_key = begin
          OpenSSL::PKey.read(key_der)
        rescue OpenSSL::PKey::PKeyError
          nil
        end
        return [issue(pkix_path, :invalid, "must be a valid PKIX-serialized public key")] if public_key.nil?

        digest = OpenSSL::Digest::SHA256.digest(pod_uid)
        verified = case public_key
                   when OpenSSL::PKey::EC
                     unless %w[prime256v1 secp384r1 secp521r1].include?(public_key.group.curve_name)
                       return [issue(pkix_path, :invalid, "elliptic public keys must use curve P256 or P384")]
                     end

                     public_key.dsa_verify_asn1(digest, proof_der.to_s)
                   when OpenSSL::PKey::RSA
                     return [issue(pkix_path, :invalid, "RSA keys must have modulus size 3072 or 4096")] unless [3072,
                                                                                                                 4096].include?(public_key.n.num_bits)

                     public_key.verify_pss("SHA256", proof_der.to_s, digest, salt_length: :auto, mgf1_hash: "SHA256")
                   else
                     unless public_key.oid == "ED25519"
                       return [issue(pkix_path, :invalid,
                                     "unknown public key type; supported types are Ed25519, ECDSA, and RSA")]
                     end

                     public_key.verify(nil, proof_der.to_s, pod_uid)
                   end
        verified ? [] : [issue(proof_path, :invalid, "could not verify proof-of-possession signature")]
      rescue OpenSSL::PKey::PKeyError
        [issue(proof_path, :invalid, "could not verify proof-of-possession signature")]
      end
    end
  end
end
