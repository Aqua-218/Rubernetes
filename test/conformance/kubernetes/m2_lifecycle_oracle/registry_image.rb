# frozen_string_literal: true

# Fetch a digest-pinned OCI/Docker image from a registry into an OCI image
# layout archive without rewriting the manifest.
#
# Docker's graph driver re-compresses layers on `docker save`/`docker push`, so
# an image that travels through the host Docker daemon loses its upstream
# manifest digest. The lifecycle fixture pins the busybox workload image by its
# amd64 manifest digest, and the kubelet inside the isolated node resolves
# `image@sha256:<digest>` against its containerd image store by exactly that
# digest. This module downloads the manifest and blobs directly (verifying every
# byte against its digest) and writes an OCI layout tar that `ctr images import
# --digests` stores under the upstream digest.

require "digest"
require "fileutils"
require "json"
require "net/http"
require "rubygems/package"
require "stringio"
require "uri"

module M2LifecycleOracleRegistryImage
  class FetchError < StandardError; end

  MANIFEST_ACCEPT = [
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json"
  ].join(", ").freeze
  MAX_REDIRECTS = 5
  MAX_ATTEMPTS = 3
  RETRY_SLEEP_SECONDS = 2
  DIGEST_PATTERN = /\Asha256:[0-9a-f]{64}\z/.freeze

  module_function

  # reference: "registry.k8s.io/e2e-test-images/busybox@sha256:<digest>"
  def parse_reference(reference)
    raise FetchError, "image reference must be digest-pinned: #{reference.inspect}" unless reference.is_a?(String) && reference.include?("@sha256:")
    name, digest = reference.split("@", 2)
    raise FetchError, "image digest is invalid: #{digest.inspect}" unless DIGEST_PATTERN.match?(digest)
    registry, repository = name.split("/", 2)
    raise FetchError, "image reference must include a registry host: #{reference.inspect}" if repository.nil? || !registry.include?(".") && !registry.include?(":") && registry != "localhost"
    {"registry" => registry, "repository" => repository, "digest" => digest, "name" => name}
  end

  # Returns the path of the OCI layout archive. The archive is cached under
  # cache_dir by digest so repeated oracle runs do not touch the network.
  def fetch_oci_archive(reference, cache_dir:)
    parsed = parse_reference(reference)
    digest_hex = parsed.fetch("digest").delete_prefix("sha256:")
    FileUtils.mkdir_p(cache_dir)
    archive = File.join(cache_dir, "#{digest_hex}.oci.tar")
    return archive if File.file?(archive) && verify_archive(archive, parsed)

    manifest_bytes = get_with_retries(parsed, "manifests/#{parsed.fetch("digest")}", accept: MANIFEST_ACCEPT)
    actual = "sha256:#{Digest::SHA256.hexdigest(manifest_bytes)}"
    raise FetchError, "manifest digest mismatch: expected #{parsed.fetch("digest")}, got #{actual}" unless actual == parsed.fetch("digest")
    manifest = JSON.parse(manifest_bytes)
    raise FetchError, "manifest must be a single-platform image manifest, got #{manifest["mediaType"].inspect}" unless manifest.is_a?(Hash) && manifest["config"].is_a?(Hash) && manifest["layers"].is_a?(Array)

    blobs = {}
    [manifest.fetch("config"), *manifest.fetch("layers")].each do |descriptor|
      digest = descriptor["digest"]
      raise FetchError, "descriptor digest is invalid: #{digest.inspect}" unless DIGEST_PATTERN.match?(digest.to_s)
      bytes = get_with_retries(parsed, "blobs/#{digest}", accept: "*/*")
      actual_blob = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
      raise FetchError, "blob digest mismatch for #{digest}: got #{actual_blob}" unless actual_blob == digest
      raise FetchError, "blob size mismatch for #{digest}" if descriptor["size"].is_a?(Integer) && descriptor["size"] != bytes.bytesize
      blobs[digest] = bytes
    end
    write_oci_layout(archive, parsed, manifest_bytes, manifest.fetch("mediaType", MANIFEST_ACCEPT.split(", ").first), blobs)
    raise FetchError, "written OCI archive failed verification: #{archive}" unless verify_archive(archive, parsed)
    archive
  end

  def write_oci_layout(archive, parsed, manifest_bytes, manifest_media_type, blobs)
    index = {
      "schemaVersion" => 2,
      "mediaType" => "application/vnd.oci.image.index.v1+json",
      "manifests" => [
        {
          "mediaType" => manifest_media_type,
          "digest" => parsed.fetch("digest"),
          "size" => manifest_bytes.bytesize,
          "annotations" => {
            "org.opencontainers.image.ref.name" => parsed.fetch("digest"),
            "io.containerd.image.name" => "#{parsed.fetch("name")}@#{parsed.fetch("digest")}"
          }
        }
      ]
    }
    tmp = "#{archive}.tmp.#{Process.pid}"
    File.open(tmp, "wb") do |io|
      Gem::Package::TarWriter.new(io) do |tar|
        add_file(tar, "oci-layout", JSON.generate({"imageLayoutVersion" => "1.0.0"}))
        add_file(tar, "index.json", JSON.generate(index))
        add_file(tar, "blobs/sha256/#{parsed.fetch("digest").delete_prefix("sha256:")}", manifest_bytes)
        blobs.each do |digest, bytes|
          add_file(tar, "blobs/sha256/#{digest.delete_prefix("sha256:")}", bytes)
        end
      end
    end
    File.rename(tmp, archive)
  end

  def add_file(tar, path, bytes)
    tar.add_file_simple(path, 0o644, bytes.bytesize) { |entry| entry.write(bytes) }
  end

  # Re-verify the cached archive: index points at the pinned manifest and every
  # blob hashes to its file name.
  def verify_archive(archive, parsed)
    manifest_hex = parsed.fetch("digest").delete_prefix("sha256:")
    found_manifest = false
    index_ok = false
    File.open(archive, "rb") do |io|
      Gem::Package::TarReader.new(io) do |tar|
        tar.each do |entry|
          next unless entry.file?
          bytes = entry.read.to_s
          case entry.full_name
          when "index.json"
            index = JSON.parse(bytes, create_additions: false)
            index_ok = index.is_a?(Hash) && Array(index["manifests"]).any? { |m| m.is_a?(Hash) && m["digest"] == parsed.fetch("digest") }
          when %r{\Ablobs/sha256/([0-9a-f]{64})\z}
            hex = Regexp.last_match(1)
            return false unless Digest::SHA256.hexdigest(bytes) == hex
            found_manifest = true if hex == manifest_hex
          end
        end
      end
    end
    index_ok && found_manifest
  rescue JSON::ParserError, Gem::Package::TarInvalidError, Errno::ENOENT
    false
  end

  def get_with_retries(parsed, path, accept:)
    attempts = 0
    loop do
      attempts += 1
      begin
        return get(parsed, path, accept: accept)
      rescue FetchError, SocketError, Timeout::Error, SystemCallError, OpenSSL::SSL::SSLError => error
        raise FetchError, "registry fetch failed after #{attempts} attempts: #{path}: #{error.message}" if attempts >= MAX_ATTEMPTS
        sleep(RETRY_SLEEP_SECONDS)
      end
    end
  end

  def get(parsed, path, accept:)
    uri = URI("https://#{parsed.fetch("registry")}/v2/#{parsed.fetch("repository")}/#{path}")
    token = nil
    redirects = 0
    loop do
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = accept
      request["Authorization"] = "Bearer #{token}" if token
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 20, read_timeout: 120) do |http|
        http.request(request)
      end
      case response
      when Net::HTTPSuccess
        return response.body.to_s.b
      when Net::HTTPRedirection
        redirects += 1
        raise FetchError, "too many redirects for #{uri}" if redirects > MAX_REDIRECTS
        location = response["location"]
        raise FetchError, "redirect without location for #{uri}" if location.to_s.empty?
        uri = URI.join(uri.to_s, location)
        token = nil
      when Net::HTTPUnauthorized
        raise FetchError, "registry rejected anonymous token for #{uri}" if token
        token = anonymous_token(response["www-authenticate"].to_s, parsed)
      else
        raise FetchError, "registry returned #{response.code} for #{uri}"
      end
    end
  end

  # Docker distribution token flow for anonymous pulls.
  def anonymous_token(challenge, parsed)
    params = challenge.sub(/\ABearer\s+/i, "").scan(/(\w+)="([^"]*)"/).to_h
    realm = params["realm"]
    raise FetchError, "registry auth challenge has no realm: #{challenge.inspect}" if realm.to_s.empty?
    uri = URI(realm)
    query = {"service" => params["service"], "scope" => params["scope"] || "repository:#{parsed.fetch("repository")}:pull"}.compact
    uri.query = URI.encode_www_form(query)
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 20, read_timeout: 60) do |http|
      http.request(Net::HTTP::Get.new(uri))
    end
    raise FetchError, "token endpoint returned #{response.code}" unless response.is_a?(Net::HTTPSuccess)
    document = JSON.parse(response.body, create_additions: false)
    token = document["token"] || document["access_token"]
    raise FetchError, "token endpoint returned no token" unless token.is_a?(String) && !token.empty?
    token
  end
end
