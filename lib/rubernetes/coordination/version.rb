# frozen_string_literal: true

module Rubernetes
  module Coordination
    # SemVer precedence used by Kubernetes' LeaseCandidate election. Build
    # metadata does not participate and numeric prerelease identifiers sort
    # before alphanumeric ones.
    module Version
      SEMVER = /\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z/
      ZERO = [0, 0, 0, 1, [].freeze].freeze

      module_function

      def key(value)
        match = SEMVER.match(value.to_s)
        return unless match

        major, minor, patch, prerelease = match.captures
        tokens = prerelease.to_s.split(".")
        return if tokens.any? { |token| token.match?(/\A0\d+\z/) }

        identifiers = tokens.map do |token|
          token.match?(/\A\d+\z/) ? [0, token.to_i] : [1, token]
        end
        [major.to_i, minor.to_i, patch.to_i, prerelease ? 0 : 1, identifiers]
      end
    end
  end
end
