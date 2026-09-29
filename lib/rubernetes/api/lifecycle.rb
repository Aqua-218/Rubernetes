# frozen_string_literal: true

require "json"

module Rubernetes
  module API
    # endpoints/deprecation (k8s.io/apiserver, v1.36.2): whether a built-in
    # kind at a served version is deprecated in this release, the release it
    # is removed in and the warning kube-apiserver sends for it.  The table
    # is k8s.io/api's generated prerelease-lifecycle data.
    module Lifecycle
      CURRENT = [1, 36].freeze
      TABLE_PATH = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/api-lifecycle.json", __dir__)

      Deprecation = Struct.new(:message, :removed_release, keyword_init: true)

      module_function

      def table
        @table ||= begin
          kinds = JSON.parse(File.read(TABLE_PATH)).fetch("kinds")
          kinds.to_h { |entry| [[entry["group"].to_s, entry["version"].to_s, entry["kind"].to_s], entry] }.freeze
        rescue SystemCallError, JSON::ParserError, KeyError
          {}.freeze
        end
      end

      # nil unless deprecated.IsDeprecated at CURRENT.
      def deprecation(group, version, kind)
        entry = table[[group.to_s, version.to_s, kind.to_s]]
        return nil unless entry

        deprecated = Array(entry["deprecated"])
        return nil if deprecated.empty? || deprecated == [0, 0] || (deprecated <=> CURRENT) == 1

        Deprecation.new(message: warning_message(group, version, kind, entry), removed_release: removed_release(entry))
      end

      def removed_release(entry)
        removed = Array(entry["removed"])
        return "" if removed.empty? || removed == [0, 0]

        removed.join(".")
      end

      # WarningMessage.
      def warning_message(group, version, kind, entry)
        deprecated = entry["deprecated"]
        message = "#{group_version(group, version)} #{kind} is deprecated in v#{deprecated[0]}.#{deprecated[1]}+"
        removed = Array(entry["removed"])
        message += ", unavailable in v#{removed[0]}.#{removed[1]}+" unless removed.empty? || removed == [0, 0]
        replacement = entry["replacement"]
        if replacement.is_a?(Hash) && !replacement["kind"].to_s.empty?
          message += "; use #{group_version(replacement["group"], replacement["version"])} #{replacement["kind"]}"
        end
        message
      end

      def group_version(group, version)
        group.to_s.empty? ? version.to_s : "#{group}/#{version}"
      end
    end
  end
end
