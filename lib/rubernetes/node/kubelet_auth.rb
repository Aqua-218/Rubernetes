# frozen_string_literal: true

require "digest"
require "json"
require "openssl"

module Rubernetes
  module Node
    # The kubelet API's authentication and authorization
    # (pkg/kubelet/server/auth.go and server.go InstallAuthFilter, v1.36.2).
    #
    #   * authentication: a client certificate the TLS layer verified against
    #     the client CA (user = CN, groups = O), else a bearer token through
    #     a TokenReview (cached --authentication-token-webhook-cache-ttl, 2m),
    #     else anonymous when allowed (system:anonymous).  Failure is 401.
    #   * authorization (Webhook): a SubjectAccessReview for nodes/<sub> on
    #     this node, <sub> from the path -- stats, metrics, log, checkpoint,
    #     statusz, configz (/flagz), and with KubeletFineGrainedAuthz pods
    #     or healthz or configz first -- falling back to proxy.  Allowed
    #     answers are cached 5m, denials 30s.  Failure is 403 with upstream's
    #     message.
    class KubeletAuth
      AUTHN_TTL = 120.0
      AUTHORIZED_TTL = 300.0
      UNAUTHORIZED_TTL = 30.0
      ANONYMOUS = {"username" => "system:anonymous", "groups" => ["system:unauthenticated"]}.freeze
      VERBS = {"POST" => "create", "GET" => "get", "PUT" => "update", "PATCH" => "patch", "DELETE" => "delete"}.freeze

      User = Struct.new(:name, :uid, :groups, :extra, keyword_init: true)

      # +client_ca+: the certificates (or a PEM file) client certificates must
      # chain to (--client-ca-file); without it no certificate authenticates.
      def initialize(client:, node_name:, client_ca: nil, anonymous: false, webhook: true, authorization_mode: "Webhook",
                     fine_grained: true, authn_ttl: AUTHN_TTL, authorized_ttl: AUTHORIZED_TTL,
                     unauthorized_ttl: UNAUTHORIZED_TTL, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @client = client
        @node_name = node_name.to_s
        @client_ca = certificate_store(client_ca)
        @anonymous = anonymous == true
        @webhook = webhook != false
        @authorization_mode = authorization_mode.to_s
        @fine_grained = fine_grained != false
        @authn_ttl = Float(authn_ttl)
        @authorized_ttl = Float(authorized_ttl)
        @unauthorized_ttl = Float(unauthorized_ttl)
        @clock = clock
        @token_cache = {}
        @decision_cache = {}
        @mutex = Mutex.new
      end

      # nil when the request may proceed, otherwise the [status, headers, body]
      # to answer with.
      def filter(request)
        user = authenticate(request)
        return [401, {"content-type" => "text/plain"}, ["Unauthorized"]] if user.nil?

        attributes = request_attributes(user, request)
        attributes.each do |attribute|
          return nil if authorized?(attribute)
        rescue StandardError
          message = "Authorization error (user=#{user.name}, verb=#{attribute[:verb]}, resource=nodes, subresource=#{attribute[:subresource]})"
          return [500, {"content-type" => "text/plain"}, [message]]
        end
        subresources = attributes.map { |attribute| attribute[:subresource] }
        verb = attributes.first[:verb]
        [403, {"content-type" => "text/plain"},
         ["Forbidden (user=#{user.name}, verb=#{verb}, resource=nodes, subresource(s)=[#{subresources.join(" ")}])\n"]]
      end

      def authenticate(request)
        certificate = request.respond_to?(:client_certificate) ? request.client_certificate : nil
        if certificate
          chain = request.respond_to?(:client_chain) ? Array(request.client_chain) : []
          user = certificate_user(certificate, chain)
          return user if user
        end

        token = bearer_token(request)
        if token && @webhook
          user = token_user(token)
          return user if user
        end
        return User.new(name: ANONYMOUS["username"], uid: "", groups: ANONYMOUS["groups"], extra: {}) if @anonymous

        nil
      end

      # GetRequestAttributes.
      def request_attributes(user, request)
        path = request.path.to_s
        verb = VERBS.fetch(request.method.to_s.upcase, "")
        subresources = []
        if @fine_grained
          if subpath?(path, "/pods") || subpath?(path, "/runningpods/")
            subresources << "pods"
          elsif subpath?(path, "/healthz")
            subresources << "healthz"
          elsif subpath?(path, "/configz")
            subresources << "configz"
          end
        end
        subresources << if subpath?(path, "/stats/") then "stats"
                        elsif subpath?(path, "/metrics") then "metrics"
                        elsif subpath?(path, "/logs/") then "log"
                        elsif subpath?(path, "/checkpoint/") then "checkpoint"
                        elsif subpath?(path, "/statusz") then "statusz"
                        elsif subpath?(path, "/flagz") then "configz"
                        else "proxy"
                        end
        subresources.map { |subresource| {user: user, verb: verb, subresource: subresource, path: path} }
      end

      private

      def subpath?(path, prefix)
        base = prefix.chomp("/")
        path == base || (path.start_with?(base) && path[base.length] == "/")
      end

      def certificate_store(source)
        certificates = case source
                       when nil then []
                       when String
                         File.read(source).scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m)
                           .map { |pem| OpenSSL::X509::Certificate.new(pem) }
                       else Array(source)
                       end
        return nil if certificates.empty?

        store = OpenSSL::X509::Store.new
        certificates.each { |certificate| store.add_cert(certificate) }
        store
      end

      # x509 request authenticator: the chain must verify against the client
      # CA and the certificate must allow client authentication.
      def certificate_user(certificate, chain)
        return nil if @client_ca.nil?

        intermediates = chain.reject { |entry| entry.to_der == certificate.to_der }
        return nil unless @client_ca.verify(certificate, intermediates)

        usage = certificate.extensions.find { |extension| extension.oid == "extendedKeyUsage" }
        return nil if usage && !usage.value.split(/,\s*/).any? do |value|
          ["TLS Web Client Authentication", "Any Extended Key Usage"].include?(value)
        end

        subject = certificate.subject.to_a
        name = subject.find { |entry| entry[0] == "CN" }&.fetch(1, nil).to_s
        return nil if name.empty?

        groups = subject.select { |entry| entry[0] == "O" }.map { |entry| entry[1].to_s }
        User.new(name: name, uid: "", groups: groups, extra: {})
      end

      def bearer_token(request)
        header = request.respond_to?(:header) ? request.header("authorization") : nil
        headers = request.respond_to?(:headers) ? request.headers : nil
        header = headers["authorization"] || headers["Authorization"] if header.nil? && headers.respond_to?(:[])
        value = header.to_s
        return nil unless value.match?(/\ABearer\s+\S+/i)

        value.sub(/\ABearer\s+/i, "").strip
      end

      # TokenReview through the API server, cached by the token's digest.
      def token_user(token)
        key = Digest::SHA256.hexdigest(token)
        now = @clock.call
        cached = @mutex.synchronize { @token_cache[key] }
        return cached[:user] if cached && now < cached[:expires]

        review = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview", "spec" => {"token" => token}}
        status = (@client.create(review, api_version: "authentication.k8s.io/v1",
                                         path: "/apis/authentication.k8s.io/v1/tokenreviews") || {})["status"] || {}
        user = if status["authenticated"] == true
                 info = status["user"] || {}
                 User.new(name: info["username"].to_s, uid: info["uid"].to_s, groups: Array(info["groups"]),
                          extra: (info["extra"] || {}).to_h)
               end
        @mutex.synchronize do
          @token_cache[key] = {user: user, expires: now + @authn_ttl}
          @token_cache.delete_if { |_key, entry| entry[:expires] <= now } if @token_cache.length > 1024
        end
        user
      end

      def authorized?(attribute)
        return true if @authorization_mode == "AlwaysAllow"

        user = attribute[:user]
        key = JSON.generate([user.name, user.uid, user.groups.sort, user.extra, attribute[:verb], attribute[:subresource]])
        now = @clock.call
        cached = @mutex.synchronize { @decision_cache[key] }
        return cached[:allowed] if cached && now < cached[:expires]

        review = {"apiVersion" => "authorization.k8s.io/v1", "kind" => "SubjectAccessReview",
                  "spec" => {"user" => user.name, "uid" => user.uid, "groups" => user.groups,
                             "extra" => user.extra.transform_values { |value| Array(value) },
                             "resourceAttributes" => {"verb" => attribute[:verb], "group" => "", "version" => "v1",
                                                      "resource" => "nodes", "subresource" => attribute[:subresource],
                                                      "name" => @node_name}}}
        status = (@client.create(review, api_version: "authorization.k8s.io/v1",
                                         path: "/apis/authorization.k8s.io/v1/subjectaccessreviews") || {})["status"] || {}
        allowed = status["allowed"] == true
        @mutex.synchronize do
          @decision_cache[key] = {allowed: allowed, expires: now + (allowed ? @authorized_ttl : @unauthorized_ttl)}
          @decision_cache.delete_if { |_key, entry| entry[:expires] <= now } if @decision_cache.length > 4096
        end
        allowed
      end
    end
  end
end
