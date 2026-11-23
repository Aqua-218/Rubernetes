# frozen_string_literal: true

require "openssl"
require "uri"

require_relative "../identity"

module Rubernetes
  module Security
    module Authentication
      # Front-proxy / request-header authenticator
      # (k8s.io/apiserver/pkg/authentication/request/headerrequest).  Identity
      # headers are trusted only when the connection presents a client
      # certificate issued by the request-header CA whose CN is one of the
      # allowed names.  Extra headers are `X-Remote-Extra-<key>` with
      # percent-encoded keys.
      class RequestHeader
        NAME = "request-header"
        PEER_HEADER = "x-kubernetes-peer-proxied"
        PEER_USERNAME = ["X-Remote-User"].freeze
        PEER_UID = ["X-Remote-Uid"].freeze
        PEER_GROUPS = ["X-Remote-Group"].freeze
        PEER_EXTRA = ["x-remote-extra-"].freeze

        def initialize(ca_certificates:, allowed_names: [], username_headers: ["X-Remote-User"], uid_headers: ["X-Remote-Uid"],
                       group_headers: ["X-Remote-Group"], extra_header_prefixes: ["X-Remote-Extra-"], peer_proxy: false,
                       clock: -> { Time.now.utc })
          @store = OpenSSL::X509::Store.new
          @store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
          Array(ca_certificates).each { |certificate| @store.add_cert(certificate) }
          @allowed_names = Array(allowed_names).map(&:to_s)
          @username_headers = Array(username_headers)
          @uid_headers = Array(uid_headers)
          @group_headers = Array(group_headers)
          @extra_prefixes = Array(extra_header_prefixes).map(&:downcase)
          @peer_proxy = peer_proxy
          @clock = clock
          @verified = {}
          @verified_mutex = Mutex.new
        end

        def name
          NAME
        end

        def authenticate(context)
          certificate = context.client_certificate
          return nil if certificate.nil?

          # This authenticator is asked first for every request, and nearly
          # none of them come from the front proxy.  Without a user name
          # header the answer is nil whoever sent it, so the certificate --
          # a signature check per request, a quarter of a GET -- is looked at
          # only when there is one.
          # API-server peers speak client-go's fixed auth-proxy header
          # protocol. The same CA and allowed CN gate both header sets.
          peer = @peer_proxy && context.header(PEER_HEADER) == "true"
          username = first_header(context, peer ? PEER_USERNAME : @username_headers)
          return nil if username.nil? || username.empty?
          return nil unless verified?(certificate, context.client_chain)

          common_name = certificate.subject.to_a.find { |entry| entry[0] == "CN" }&.fetch(1).to_s
          return nil unless @allowed_names.empty? || @allowed_names.include?(common_name)

          uid = first_header(context, peer ? PEER_UID : @uid_headers)
          groups = (peer ? PEER_GROUPS : @group_headers).flat_map { |header| context.header_values(header) }.map(&:to_s).reject(&:empty?)
          prefixes = peer ? PEER_EXTRA : @extra_prefixes
          extra = {}
          context.headers.to_h.each_key do |header_name|
            prefix = prefixes.find { |candidate| header_name.downcase.start_with?(candidate) }
            next unless prefix

            key = unescape(header_name[prefix.length..])
            extra[key] = (extra[key] || []) + context.header_values(header_name).map(&:to_s)
          end
          groups << UserInfo::ALL_AUTHENTICATED if username != UserInfo::ANONYMOUS_NAME && !groups.include?(UserInfo::ALL_UNAUTHENTICATED)
          user = UserInfo.new(name: username, uid: uid.to_s.empty? ? nil : uid, groups: groups, extra: extra)
          AuthenticationResult.new(user: user, authenticator: NAME)
        end

        private

        VERIFIED_SECONDS = 10
        MAX_VERIFIED = 256

        # The front proxy presents the same certificate on every request; its
        # verification is remembered briefly, and never past its expiry.
        def verified?(certificate, chain)
          now = @clock.call
          key = OpenSSL::Digest::SHA256.digest(certificate.to_der + Array(chain).map(&:to_der).join)
          known = @verified_mutex.synchronize { @verified[key] }
          return known.fetch(:valid) if known && known.fetch(:until) > now

          @store.time = now
          valid = @store.verify(certificate, chain)
          @verified_mutex.synchronize do
            @verified.shift while @verified.length >= MAX_VERIFIED
            @verified[key] = {valid: valid, until: [now + VERIFIED_SECONDS, certificate.not_after].min}
          end
          valid
        end

        def first_header(context, names)
          names.each do |header|
            value = context.header_values(header).first
            return value unless value.nil?
          end
          nil
        end

        def unescape(value)
          URI::RFC2396_PARSER.unescape(value).force_encoding(Encoding::UTF_8).scrub.downcase
        end
      end
    end
  end
end
