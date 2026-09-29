# frozen_string_literal: true

module Rubernetes
  module Security
    # Authenticated caller identity (k8s.io/apiserver/pkg/authentication/user).
    class UserInfo
      ANONYMOUS_NAME = "system:anonymous"
      ALL_UNAUTHENTICATED = "system:unauthenticated"
      ALL_AUTHENTICATED = "system:authenticated"
      NODES_GROUP = "system:nodes"
      MASTERS_GROUP = "system:masters"
      SERVICE_ACCOUNT_GROUP_PREFIX = "system:serviceaccounts"
      SERVICE_ACCOUNT_USERNAME_PREFIX = "system:serviceaccount:"

      attr_reader :name, :uid, :groups, :extra

      def initialize(name:, uid: nil, groups: [], extra: {})
        @name = String(name)
        @uid = uid.nil? ? nil : String(uid)
        @groups = Array(groups).map(&:to_s).uniq.freeze
        @extra = (extra || {}).each_with_object({}) { |(key, values), hash| hash[key.to_s] = Array(values).map(&:to_s).freeze }.freeze
        freeze
      end

      def self.anonymous
        new(name: ANONYMOUS_NAME, groups: [ALL_UNAUTHENTICATED])
      end

      def self.service_account(namespace:, name:, uid: nil, extra: {})
        new(name: "#{SERVICE_ACCOUNT_USERNAME_PREFIX}#{namespace}:#{name}", uid: uid,
            groups: [SERVICE_ACCOUNT_GROUP_PREFIX, "#{SERVICE_ACCOUNT_GROUP_PREFIX}:#{namespace}", ALL_AUTHENTICATED], extra: extra)
      end

      def self.from_h(value)
        return value if value.is_a?(UserInfo)
        raise ArgumentError, "identity must be a Hash" unless value.is_a?(Hash)

        name = value["username"] || value[:username] || value["name"] || value[:name]
        new(name: name, uid: value["uid"] || value[:uid], groups: value["groups"] || value[:groups] || [], extra: value["extra"] || value[:extra] || {})
      end

      def anonymous?
        @name == ANONYMOUS_NAME
      end

      def service_account?
        @name.start_with?(SERVICE_ACCOUNT_USERNAME_PREFIX)
      end

      def service_account_namespace
        return nil unless service_account?

        @name.delete_prefix(SERVICE_ACCOUNT_USERNAME_PREFIX).split(":", 2).first
      end

      def node?
        @groups.include?(NODES_GROUP) && @name.start_with?("system:node:")
      end

      def node_name
        node? ? @name.delete_prefix("system:node:") : nil
      end

      def with_groups(*additional)
        UserInfo.new(name: @name, uid: @uid, groups: @groups + additional.flatten, extra: @extra)
      end

      # Kubernetes UserInfo wire shape (authentication.k8s.io/v1).
      def to_h
        hash = {"username" => @name}
        hash["uid"] = @uid if @uid
        hash["groups"] = @groups unless @groups.empty?
        hash["extra"] = @extra.transform_values(&:dup) unless @extra.empty?
        hash
      end

      def ==(other)
        other.is_a?(UserInfo) && to_h == other.to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end
    end

    # Result of authenticating a request.
    class AuthenticationResult
      attr_reader :user, :audiences, :authenticator

      def initialize(user:, authenticator:, audiences: [])
        @user = user
        @authenticator = authenticator.to_s
        @audiences = Array(audiences).map(&:to_s).freeze
      end
    end

    class Error < StandardError; end
    class AuthenticationError < Error; end
    class ConfigurationError < Error; end
  end
end
