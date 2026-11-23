# frozen_string_literal: true

require "json"
require "time"
require "uri"

module Conformance
  # A trusted, narrowly scoped API audit log can identify the first write
  # from a dedicated Helm client even when the release never became ready.
  class K6ProjectCRDCreationAudit
    GROUP = "apiextensions.k8s.io"
    MAX_LOG_BYTES = 32 * 1024 * 1024

    def initialize(path:, username:)
      @path = path
      @username = username
    end

    def identities(install)
      return [] if @username.to_s.empty? || !File.file?(@path) || File.size(@path) > MAX_LOG_BYTES

      window = Time.iso8601(install.fetch("started_at"))..Time.iso8601(install.fetch("finished_at"))
      File.foreach(@path, encoding: Encoding::UTF_8).filter_map { |line| created_identity(JSON.parse(line), window) }.uniq
    rescue JSON::ParserError, EncodingError, ArgumentError, KeyError, SystemCallError
      []
    end

    private

    def created_identity(event, window)
      return unless event.is_a?(Hash)
      return unless event["stage"] == "ResponseComplete" && event.dig("responseStatus", "code") == 201
      return unless event.dig("user", "username") == @username && !event.key?("impersonatedUser")
      return unless %w[create patch].include?(event["verb"]) && window.cover?(Time.iso8601(event.fetch("stageTimestamp")))

      reference = event.fetch("objectRef")
      return unless reference.values_at("apiGroup", "apiVersion", "resource") == [GROUP, "v1", "customresourcedefinitions"]
      return unless reference["subresource"].to_s.empty? && reference["namespace"].to_s.empty?

      query = event.fetch("requestURI").partition("?").last
      return if URI.decode_www_form(query).any? { |key, _value| key == "dryRun" }

      response = event.fetch("responseObject")
      return unless response.values_at("kind", "apiVersion") == ["CustomResourceDefinition", "#{GROUP}/v1"]

      name, uid = response.fetch("metadata").values_at("name", "uid")
      [name, uid] unless name.to_s.empty? || uid.to_s.empty? || (!reference["name"].to_s.empty? && reference["name"] != name)
    end
  end
end
