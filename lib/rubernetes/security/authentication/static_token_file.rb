# frozen_string_literal: true

require "csv"

require_relative "../identity"

module Rubernetes
  module Security
    module Authentication
      # Static token file (--token-auth-file): CSV lines of
      # token,user,uid[,"group1,group2"].
      class StaticTokenFile
        NAME = "token-file"

        def self.load(path)
          new(parse(File.read(path)))
        end

        def self.parse(text)
          entries = {}
          CSV.parse(text).each_with_index do |row, index|
            next if row.nil? || row.compact.empty?
            raise ConfigurationError, "token file line #{index + 1} needs token,user,uid" if row.length < 3

            token, user, uid, groups = row
            raise ConfigurationError, "token file line #{index + 1} has an empty token" if token.to_s.empty?
            raise ConfigurationError, "token file line #{index + 1} repeats token" if entries.key?(token)

            entries[token] = UserInfo.new(name: user, uid: uid, groups: groups.to_s.split(",").map(&:strip).reject(&:empty?) + [UserInfo::ALL_AUTHENTICATED])
          end
          entries
        end

        def initialize(entries)
          @entries = entries
        end

        def name
          NAME
        end

        def authenticate_token(token, _audiences = [])
          user = @entries[token]
          user && AuthenticationResult.new(user: user, authenticator: NAME)
        end

        def authenticate(context)
          token = context.bearer_token
          token && authenticate_token(token)
        end
      end
    end
  end
end
