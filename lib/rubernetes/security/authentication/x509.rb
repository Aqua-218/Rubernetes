# frozen_string_literal: true

require "openssl"

require_relative "../identity"

module Rubernetes
  module Security
    module Authentication
      # Client-certificate authenticator (k8s.io/apiserver/pkg/authentication/request/x509).
      # The certificate must chain to one of the configured client CAs and be
      # valid for clientAuth; the user is the Subject CN and the groups are
      # the Subject O values.  An expired or unverifiable chain is a hard
      # failure, not an anonymous request.
      class X509
        # asn1util.X509UID: 1.3.6.1.4.1.57683.2, the CNCF enterprise number's UID element.
        UID_OID = "1.3.6.1.4.1.57683.2"
        NAME = "x509"

        # A verified certificate is remembered for a short while, keyed by its
        # exact bytes and the chain presented with it.  Every request on a
        # kept-alive connection re-walked the chain through OpenSSL, which was
        # the apiserver's largest non-I/O frame under load, and clients
        # (informers, the conformance suite) present the same handful of
        # certificates for hours.  The entry is dropped when the certificate's
        # validity window ends, so an expired certificate is never accepted
        # from the cache.
        CACHE_SECONDS = 30.0
        MAX_CACHED = 256

        def initialize(ca_certificates:, clock: -> { Time.now.utc })
          @store = OpenSSL::X509::Store.new
          Array(ca_certificates).each { |certificate| @store.add_cert(certificate) }
          @clock = clock
          @count = Array(ca_certificates).length
          @cache = {}
          @cache_mutex = Mutex.new
        end

        def name
          NAME
        end

        def configured?
          @count.positive?
        end

        EXPIRATION_BUCKETS = [0, 1800, 3600, 7200, 21_600, 43_200, 86_400, 172_800, 345_600, 604_800, 2_592_000, 7_776_000,
                              15_552_000, 31_104_000].freeze

        attr_reader :metrics

        # apiserver_client_certificate_expiration_seconds.
        def metrics=(registry)
          @metrics = registry
          registry&.register("apiserver_client_certificate_expiration_seconds", type: :histogram, buckets: EXPIRATION_BUCKETS,
                                                                                help: "Distribution of the remaining lifetime on the certificate used to authenticate a request.")
        end

        def authenticate(context)
          certificate = context.client_certificate
          return nil if certificate.nil?

          now = @clock.call
          begin
            @metrics&.observe("apiserver_client_certificate_expiration_seconds", certificate.not_after - now)
          rescue StandardError
            nil
          end
          key = cache_key(certificate, context.client_chain)
          cached = cached_result(key, now)
          return cached unless cached.nil?

          @store.time = now
          verified = @store.verify(certificate, context.client_chain)
          raise AuthenticationError, "x509: certificate verification failed: #{@store.error_string}" unless verified
          raise AuthenticationError, "x509: certificate is not valid for client authentication" unless client_auth?(certificate)

          common_name = subject_value(certificate, "CN")
          raise AuthenticationError, "x509: certificate has no subject common name" if common_name.to_s.empty?

          organizations = certificate.subject.to_a.select { |entry| entry[0] == "O" }.map { |entry| entry[1].to_s }
          # CommonNameUserConversion: the UID from the Kubernetes UID element
          # of the subject (AllowParsingUserUIDFromCertAuth, Beta, on) and the
          # certificate's fingerprint as the credential ID.
          uids = certificate.subject.to_a.select { |entry| entry[0] == UID_OID }.map { |entry| entry[1].to_s }
          raise AuthenticationError, "expected 1 UID, but found multiple: [#{uids.join(" ")}]" if uids.length > 1
          raise AuthenticationError, "UID cannot be an empty string" if uids == [""]

          extra = {"authentication.kubernetes.io/credential-id" => ["X509SHA256=#{OpenSSL::Digest::SHA256.hexdigest(certificate.to_der)}"]}
          user = UserInfo.new(name: common_name, uid: uids.first, groups: organizations + [UserInfo::ALL_AUTHENTICATED], extra: extra)
          result = AuthenticationResult.new(user: user, authenticator: NAME)
          remember(key, result, expires_at: [now + CACHE_SECONDS, certificate.not_after].min)
          result
        end

        private

        def cache_key(certificate, chain)
          chain_digest = Array(chain).map { |entry| entry.respond_to?(:to_der) ? entry.to_der : entry.to_s }.join
          OpenSSL::Digest::SHA256.digest(certificate.to_der + "\0" + chain_digest)
        end

        def cached_result(key, now)
          @cache_mutex.synchronize do
            entry = @cache[key]
            next nil if entry.nil?
            next @cache.delete(key) && nil if entry[:expires_at] <= now

            entry[:result]
          end
        end

        def remember(key, result, expires_at:)
          return if expires_at <= @clock.call

          @cache_mutex.synchronize do
            @cache.shift while @cache.length >= MAX_CACHED
            @cache[key] = {result: result, expires_at: expires_at}
          end
        end

        def client_auth?(certificate)
          extension = certificate.extensions.find { |ext| ext.oid == "extendedKeyUsage" }
          return true if extension.nil?

          extension.value.split(",").map(&:strip).any? { |usage| usage == "TLS Web Client Authentication" || usage == "clientAuth" }
        end

        def subject_value(certificate, key)
          entry = certificate.subject.to_a.find { |candidate| candidate[0] == key }
          entry && entry[1].to_s
        end
      end
    end
  end
end
