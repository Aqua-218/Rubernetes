# frozen_string_literal: true

require "digest"
require "json"
require "base64"
require "openssl"
require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # Reconciles legacy service-account-token Secrets.  Bound tokens issued by
    # the TokenRequest API are intentionally outside this controller; callers
    # that need signed JWTs can provide a token_provider or signing_key.
    class ServiceAccountTokenController < BaseController
      SERVICE_ACCOUNT = ResourceDescriptor.parse("ServiceAccount")
      SECRET = ResourceDescriptor.parse("Secret")
      TOKEN_TYPE = "kubernetes.io/service-account-token"
      NAME_ANNOTATION = "kubernetes.io/service-account.name"
      UID_ANNOTATION = "kubernetes.io/service-account.uid"
      TOKEN_KEY = "token"
      ROOT_CA_KEY = "ca.crt"
      NAMESPACE_KEY = "namespace"

      include SecondarySupport

      # kube-controller-manager stopped minting a token Secret per
      # ServiceAccount in 1.24 (LegacyServiceAccountTokenNoAutoGeneration); the
      # tokens controller only fills in Secrets a user created with the
      # kubernetes.io/service-account.name annotation.  `secret_name` keeps an
      # explicit creation path for callers that ask for one by name.
      def plan(service_account, store: nil, secrets: nil, token_provider: nil, token: nil,
               signing_key: nil, root_ca: nil, secret_name: nil, **_options)
        adapter = adapter_for(store)
        secrets ||= list_for(adapter, SECRET, namespace: Support.namespace(service_account))
        managed = Array(secrets).select { |secret| token_secret_for?(secret, service_account) }
          .sort_by { |candidate| [Support.name(candidate), Support.uid(candidate).to_s] }
        operations = []
        if managed.empty? && !secret_name.to_s.empty?
          desired = token_secret(service_account, secret_name.to_s,
                                 token: token || token_for(service_account, token_provider: token_provider, signing_key: signing_key,
                                                                            secret_name: secret_name.to_s),
                                 root_ca: root_ca)
          operations << operation_create(desired, owner: service_account, descriptor: SECRET,
                                                  reason: "service account token created")
          managed = [desired]
        end
        managed.each do |secret|
          next if operations.any? { |operation| operation.create? && Support.name(operation.object) == Support.name(secret) }

          # An existing token is kept: rewriting it would invalidate every
          # copy a client already holds (tokens_controller only fills a
          # Secret missing its token).
          existing = Support.value(Support.value(secret, "data", {}) || {}, TOKEN_KEY, nil)
          desired = token_secret(service_account, Support.name(secret),
                                 token: token || existing_token(existing) ||
                                        token_for(service_account, token_provider: token_provider, signing_key: signing_key,
                                                                   secret_name: Support.name(secret)),
                                 root_ca: root_ca)
          candidate = merge_token_secret(secret, desired)
          update = operation_update(secret, candidate, descriptor: SECRET,
                                                       reason: "service account token populated")
          operations << update if update
        end
        status = Support.deep_copy(Support.status(service_account))
        status["secrets"] = managed.map { |secret| {"name" => Support.name(secret), "namespace" => Support.namespace(service_account)} }
        events = if operations.any? { |operation| operation.resource == SECRET }
                   [{"type" => "Normal", "reason" => "TokenCreated",
                     "message" => "service account #{Support.name(service_account)} token Secret reconciled"}]
                 else
                   []
                 end
        ReconcileResult.new(operations: operations, status: status, events: events,
                            controller: name, key: object_key_for(service_account))
      end

      private

      def token_secret_for?(secret, service_account)
        return false unless Support.kind(secret) == "Secret"

        annotations = Support.annotations(secret)
        Support.value(secret, "type", "").to_s == TOKEN_TYPE &&
          annotations[NAME_ANNOTATION].to_s == Support.name(service_account) &&
          (annotations[UID_ANNOTATION].to_s.empty? || annotations[UID_ANNOTATION].to_s == Support.uid(service_account).to_s)
      end

      def token_secret_name(service_account)
        base = Support.name(service_account).downcase.gsub(/[^a-z0-9-]/, "-").squeeze("-").sub(/\A-|-\z/, "")
        digest = Digest::SHA256.hexdigest("#{Support.namespace(service_account)}/#{Support.uid(service_account)}")[0, 10]
        "#{base.empty? ? "serviceaccount" : base}-token-#{digest}"[0, 253]
      end

      def token_secret(service_account, name, token:, root_ca:)
        namespace = Support.namespace(service_account)
        annotations = {
          NAME_ANNOTATION => Support.name(service_account),
          UID_ANNOTATION => Support.uid(service_account)
        }
        # Secret.data is base64 on the wire (the protobuf codec refuses raw bytes).
        data = {TOKEN_KEY => Base64.strict_encode64(token.to_s), NAMESPACE_KEY => Base64.strict_encode64(namespace.to_s)}
        data[ROOT_CA_KEY] = Base64.strict_encode64(root_ca.to_s) unless root_ca.nil?
        {
          "apiVersion" => "v1", "kind" => "Secret",
          "metadata" => {"name" => name, "namespace" => namespace,
                         "annotations" => annotations,
                         "ownerReferences" => [owner_ref(service_account)]},
          "type" => TOKEN_TYPE, "data" => data
        }
      end

      def merge_token_secret(existing, desired)
        candidate = Support.deep_copy(existing)
        candidate["metadata"] ||= {}
        candidate["metadata"]["annotations"] = Support.deep_copy(desired.dig("metadata", "annotations"))
        candidate["type"] = TOKEN_TYPE
        candidate["data"] = Support.deep_copy(Support.value(existing, "data", {}))
        desired.fetch("data").each { |key, value| candidate["data"][key] ||= value }
        candidate
      end

      def service_account_secret_refs(service_account, token_secret)
        existing = Array(Support.value(service_account, "secrets", []))
        refs = existing.map { |reference| Support.deep_copy(reference) }
        return refs if refs.any? { |reference| Support.value(reference, "name", "").to_s == Support.name(token_secret) }

        refs << {"name" => Support.name(token_secret), "namespace" => Support.namespace(service_account)}
        refs
      end

      def existing_token(encoded)
        return nil if encoded.to_s.empty?

        decoded = encoded.to_s.unpack1("m")
        decoded.empty? ? nil : decoded
      rescue ArgumentError
        nil
      end

      def token_for(service_account, token_provider:, signing_key:, secret_name: nil)
        if token_provider
          value = token_provider.arity == 1 ? token_provider.call(service_account) : token_provider.call(service_account, secret_name)
          raise ArgumentError, "token_provider must return a non-empty token" if value.to_s.empty?

          return value.to_s
        end
        return deterministic_jwt(service_account, signing_key) if signing_key

        # A stable opaque token keeps the in-memory control plane idempotent.
        # Production API authentication should pass a signing key/provider.
        Digest::SHA256.hexdigest("rubernetes/service-account/#{Support.namespace(service_account)}/#{Support.uid(service_account)}")
      end

      def deterministic_jwt(service_account, signing_key)
        header = base64url(JSON.generate("alg" => "HS256", "typ" => "JWT"))
        payload = base64url(JSON.generate("sub" => "system:serviceaccount:#{Support.namespace(service_account)}:#{Support.name(service_account)}",
                                          "kubernetes.io/serviceaccount/service-account.uid" => Support.uid(service_account)))
        signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new("SHA256"), signing_key.to_s, "#{header}.#{payload}")
        "#{header}.#{payload}.#{base64url(signature)}"
      end

      def base64url(value)
        Base64.strict_encode64(value).tr("+/", "-_").delete("=")
      end
    end
  end
end
