#!/usr/bin/env ruby
# frozen_string_literal: true

# Resolves every corpus image reference to an immutable digest by asking the
# registry, so test/compatibility/projects/corpus.yml pins content and not a
# mutable tag.  Anonymous pull tokens only; nothing is pushed and no image is
# downloaded.

require "json"
require "net/http"
require "uri"

module Conformance
  module ImageDigests
    DEFAULT_REGISTRY = "registry-1.docker.io"
    ACCEPT = [
      "application/vnd.oci.image.index.v1+json",
      "application/vnd.oci.image.manifest.v1+json",
      "application/vnd.docker.distribution.manifest.list.v2+json",
      "application/vnd.docker.distribution.manifest.v2+json"
    ].join(", ")

    module_function

    # "quay.io/prometheus/alertmanager:v0.34.0" -> [host, repository, tag]
    def split(reference)
      # A colon is a tag separator unless it is the port of a registry host,
      # which only happens when the reference also has a path separator
      # (`localhost:5000/app`).  A bare `busybox:1.28` is name plus tag.
      without_digest = reference.split("@").first
      last_segment = without_digest.rpartition("/").last
      body, tag = last_segment.include?(":") ?
                  [without_digest.rpartition(":").first, without_digest.rpartition(":").last] :
                  [without_digest, "latest"]
      parts = body.split("/")
      if parts.length > 1 && (parts.first.include?(".") || parts.first.include?(":") || parts.first == "localhost")
        host = parts.first
        repository = parts[1..].join("/")
        # Docker Hub official images live under the implicit `library/`
        # namespace, whether written bare (`busybox`) or host-qualified
        # (`docker.io/traefik`).
        repository = "library/#{repository}" if hub?(host) && !repository.include?("/")
        [host, repository, tag]
      else
        [DEFAULT_REGISTRY, body.include?("/") ? body : "library/#{body}", tag]
      end
    end

    def hub?(host)
      [DEFAULT_REGISTRY, "docker.io", "index.docker.io"].include?(host)
    end

    # Ask the registry unauthenticated first; when it answers 401 the
    # WWW-Authenticate challenge names the token service to use.  This keeps
    # the resolver registry-agnostic instead of hardcoding each host.
    def token_from_challenge(challenge, repository)
      return nil if challenge.nil?

      realm = challenge[/realm="([^"]+)"/, 1]
      return nil if realm.nil?

      service = challenge[/service="([^"]+)"/, 1]
      uri = URI(realm)
      params = URI.decode_www_form(uri.query.to_s)
      params << ["service", service] if service
      params << ["scope", "repository:#{repository}:pull"]
      uri.query = URI.encode_www_form(params)
      body = fetch_json(uri)
      body && (body["token"] || body["access_token"])
    end

    def fetch_json(uri)
      response = Net::HTTP.get_response(uri)
      response.is_a?(Net::HTTPSuccess) ? JSON.parse(response.body) : nil
    rescue StandardError
      nil
    end

    # registry.k8s.io answers 307 to the regional Artifact Registry that
    # actually serves the blob, so redirects are followed (bounded) and the
    # bearer token is dropped when the host changes.
    def manifest_head(uri, bearer, redirects = 5)
      request = Net::HTTP::Head.new(uri)
      request["Accept"] = ACCEPT
      request["Authorization"] = "Bearer #{bearer}" if bearer
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 20, read_timeout: 30) { |http| http.request(request) }
      return response unless response.is_a?(Net::HTTPRedirection) && redirects.positive?

      target = URI(response["location"])
      target = URI.join(uri.to_s, response["location"]) if target.host.nil?
      manifest_head(target, target.host == uri.host ? bearer : nil, redirects - 1)
    end

    def digest(reference)
      return reference[/@(sha256:[0-9a-f]{64})/, 1] if reference.include?("@sha256:")

      host, repository, tag = split(reference)
      host = DEFAULT_REGISTRY if %w[docker.io index.docker.io].include?(host)
      uri = URI("https://#{host}/v2/#{repository}/manifests/#{tag}")
      response = manifest_head(uri, nil)
      if response.is_a?(Net::HTTPUnauthorized)
        bearer = token_from_challenge(response["www-authenticate"], repository)
        response = manifest_head(uri, bearer) if bearer
      end
      return nil unless response

      response["docker-content-digest"] || response["etag"]&.delete('"')&.delete_prefix("W/")
    rescue StandardError
      nil
    end
  end
end

if $PROGRAM_NAME == __FILE__
  ARGF.each_line do |line|
    reference = line.strip
    next if reference.empty?

    resolved = Conformance::ImageDigests.digest(reference)
    puts "#{reference}\t#{resolved || "UNRESOLVED"}"
  end
end
