#!/usr/bin/env ruby
# frozen_string_literal: true

# Import the Kubernetes v1.36.2 schema and discovery corpus from immutable
# upstream paths. The importer deliberately owns only external corpus inputs;
# generated Ruby/API code is produced by later stages.

require "digest"
require "fileutils"
require "json"
require "net/http"
require "openssl"
require "optparse"
require "tempfile"
require "uri"

module KubernetesCorpusImporter
  ROOT = File.expand_path("../..", __dir__).freeze
  LOCK_RELATIVE_PATH = "third_party/locks/kubernetes-v1.36.2.json"
  CORPUS_RELATIVE_PATH = "schema/kubernetes/v1.36.2"
  EXPECTED_TAG = "v1.36.2"
  OFFICIAL_REPOSITORY = "https://github.com/kubernetes/kubernetes.git"
  RAW_HOST = "raw.githubusercontent.com"
  API_HOST = "api.github.com"
  RAW_BASE_URL = "https://#{RAW_HOST}/kubernetes/kubernetes".freeze
  API_BASE_URL = "https://#{API_HOST}/repos/kubernetes/kubernetes/contents".freeze
  MAX_JSON_BYTES = 64 * 1024 * 1024
  MAX_PROTO_BYTES = 8 * 1024 * 1024
  MAX_API_BYTES = 4 * 1024 * 1024
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  COMMIT_PATTERN = /\A[0-9a-f]{40}\z/
  PROTO_IMPORT_PATTERN = /\bimport\s+(?:(?:public|weak)\s+)?"([^"]+)"\s*;/
  STANDARD_DESCRIPTOR_PREFIXES = %w[google/protobuf/ google/type/].freeze
  KUBERNETES_PROTO_PREFIXES = %w[
    k8s.io/api/
    k8s.io/apiextensions-apiserver/
    k8s.io/apimachinery/
    k8s.io/kube-aggregator/
  ].freeze
  PROTOCOL_ONLY_GVKS = %w[
    core/v1/NodeProxyOptions
    core/v1/PodAttachOptions
    core/v1/PodExecOptions
    core/v1/PodPortForwardOptions
    core/v1/PodProxyOptions
    core/v1/ServiceProxyOptions
  ].freeze

  OPENAPI_SOURCE = {
    id: "openapi",
    upstream_path: "api/openapi-spec/swagger.json",
    relative_path: "openapi/swagger.json",
    kind: "json",
    max_bytes: MAX_JSON_BYTES
  }.freeze

  DISCOVERY_DIRECTORY = "api/discovery"
  PROTO_API_DIRECTORY = "staging/src/k8s.io/api"
  PROTO_SUPPORT_PATHS = [
    "staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1/generated.proto",
    "staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto",
    "staging/src/k8s.io/apimachinery/pkg/api/resource/generated.proto",
    "staging/src/k8s.io/apimachinery/pkg/runtime/generated.proto",
    "staging/src/k8s.io/apimachinery/pkg/runtime/schema/generated.proto",
    "staging/src/k8s.io/apimachinery/pkg/util/intstr/generated.proto",
    "staging/src/k8s.io/kube-aggregator/pkg/apis/apiregistration/v1/generated.proto"
  ].freeze
  PROTO_ROOTS = {
    kubernetes_api: PROTO_API_DIRECTORY,
    support: PROTO_SUPPORT_PATHS
  }.freeze

  class Error < StandardError; end
  class ValidationError < Error; end
  class DuplicateKeyError < ValidationError; end

  class DuplicateCheckingHash < Hash
    def []=(key, value)
      raise DuplicateKeyError, "duplicate JSON object key #{key.inspect}" if key?(key)

      super
    end
  end

  FetchedSource = Struct.new(
    :id,
    :upstream_path,
    :relative_path,
    :url,
    :kind,
    :raw_bytes,
    :canonical_bytes,
    :parsed,
    :raw_sha256,
    :canonical_sha256,
    keyword_init: true
  )

  # Small HTTPS client used for both raw files and GitHub contents listings.
  # Redirects are rejected so a pinned URL cannot silently change origin.
  class HttpSourceFetcher
    USER_AGENT = "rubernetes-kubernetes-corpus-importer/1"

    def initialize(open_timeout: 20, read_timeout: 120)
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    def fetch(url, max_bytes:, accept: "application/json")
      uri = URI.parse(url)
      unless uri.scheme == "https" && [RAW_HOST, API_HOST].include?(uri.host)
        raise ValidationError, "source URL must use HTTPS on an official GitHub host: #{url}"
      end

      request = Net::HTTP::Get.new(uri.request_uri)
      request["Accept"] = accept
      request["User-Agent"] = USER_AGENT
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout
      http.write_timeout = @read_timeout if http.respond_to?(:write_timeout=)

      response = nil
      http.start do |connection|
        response = connection.request(request)
      end
      unless response.is_a?(Net::HTTPSuccess)
        location = response["location"]
        suffix = location ? " (redirect: #{location})" : ""
        raise Error, "upstream request failed with HTTP #{response.code} for #{url}#{suffix}"
      end

      content_length = response["content-length"]
      raise Error, "upstream response for #{url} exceeds #{max_bytes} bytes" if content_length && content_length.to_i > max_bytes

      body = response.body.to_s.b
      raise Error, "upstream response for #{url} exceeds #{max_bytes} bytes" if body.bytesize > max_bytes
      raise Error, "upstream response for #{url} is empty" if body.empty?

      body
    rescue URI::InvalidURIError => error
      raise ValidationError, "invalid source URL #{url.inspect}: #{error.message}"
    rescue SocketError, SystemCallError, Timeout::Error, OpenSSL::SSL::SSLError => error
      raise Error, "failed to fetch #{url}: #{error.class}: #{error.message}"
    end
  end

  # Enumerates only immutable paths below the pinned Kubernetes commit.
  class GitHubContentsClient
    def initialize(fetcher: HttpSourceFetcher.new)
      @fetcher = fetcher
    end

    def list(path, commit)
      validate_repo_path!(path)
      validate_commit!(commit)
      encoded_path = path.split("/").map { |part| URI.encode_uri_component(part) }.join("/")
      url = "#{API_BASE_URL}/#{encoded_path}?ref=#{commit}&per_page=100"
      body = @fetcher.fetch(url, max_bytes: MAX_API_BYTES, accept: "application/vnd.github+json")
      entries = JSON.parse(body)
      raise ValidationError, "GitHub contents API returned a non-array for #{path}" unless entries.is_a?(Array)

      entries.each { |entry| validate_entry!(entry, commit, path) }
      entries
    rescue JSON::ParserError => error
      raise ValidationError, "GitHub contents API returned invalid JSON for #{path}: #{error.message}"
    end

    private

    def validate_commit!(commit)
      return if commit.is_a?(String) && commit.match?(COMMIT_PATTERN)

      raise ValidationError, "GitHub contents API requires a 40-character commit SHA"
    end

    def validate_repo_path!(path)
      return if path.is_a?(String) && path.match?(%r{\A[a-zA-Z0-9._/-]+\z}) && !path.include?("..")

      raise ValidationError, "invalid GitHub repository path: #{path.inspect}"
    end

    def validate_entry!(entry, commit, parent_path)
      unless entry.is_a?(Hash) && %w[file dir].include?(entry["type"])
        raise ValidationError, "unexpected GitHub contents entry under #{parent_path}"
      end

      path = entry["path"]
      unless path.is_a?(String) && path.start_with?("#{parent_path}/") && !path.include?("..")
        raise ValidationError, "GitHub contents entry escaped #{parent_path}: #{path.inspect}"
      end

      sha = entry["sha"]
      unless sha.is_a?(String) && sha.match?(COMMIT_PATTERN)
        raise ValidationError, "GitHub contents entry has invalid blob/tree SHA: #{path}"
      end
      return unless entry["type"] == "file"

      expected_url = raw_url(commit, path)
      return if entry["download_url"] == expected_url

      raise ValidationError, "GitHub contents entry download URL is not the pinned raw URL: #{path}"
    end

    def raw_url(commit, path)
      "#{RAW_BASE_URL}/#{commit}/#{path}"
    end
  end

  class Importer
    attr_reader :root, :lock_path, :corpus_root

    def initialize(root: ROOT, lock_path: nil, output_root: nil, fetcher: HttpSourceFetcher.new,
                   contents_client: nil)
      @root = File.expand_path(root)
      @lock_path = File.expand_path(lock_path || File.join(@root, LOCK_RELATIVE_PATH))
      @corpus_root = File.expand_path(output_root || File.join(@root, CORPUS_RELATIVE_PATH))
      @fetcher = fetcher
      @contents_client = contents_client || GitHubContentsClient.new(fetcher: fetcher)
    end

    # Imports the corpus or verifies it without any network access when check is true.
    # Returns the canonical sources manifest hash.
    def run(check: false)
      lock = load_lock
      context = source_context(lock)
      check ? check_existing!(context) : import!(context)
    end

    private

    def load_lock
      data = JSON.parse(File.binread(@lock_path))
      source = data.fetch("source")
      unless source.is_a?(Hash) && source["repository"] == OFFICIAL_REPOSITORY
        raise ValidationError, "Kubernetes lock must pin #{OFFICIAL_REPOSITORY}"
      end
      raise ValidationError, "Kubernetes lock tag must be #{EXPECTED_TAG.inspect}" unless source["tag"] == EXPECTED_TAG

      commit = source["commit"]
      unless commit.is_a?(String) && commit.match?(COMMIT_PATTERN) && commit == commit.downcase
        raise ValidationError, "Kubernetes lock source.commit must be a lowercase 40-character SHA"
      end

      data
    rescue Errno::ENOENT => error
      raise Error, "Kubernetes lock file is missing: #{@lock_path}: #{error.message}"
    rescue JSON::ParserError => error
      raise ValidationError, "Kubernetes lock file is invalid JSON: #{error.message}"
    rescue KeyError => error
      raise ValidationError, "Kubernetes lock file is missing #{error.message}"
    end

    def source_context(lock)
      source = lock.fetch("source")
      commit = source.fetch("commit")
      {
        "source" => {
          "repository" => source.fetch("repository"),
          "tag" => source.fetch("tag"),
          "tag_object" => source["tag_object"],
          "commit" => commit
        }.compact,
        "commit" => commit
      }
    end

    def import!(context)
      fetched_sources = []
      openapi = fetch_json_source(context.fetch("commit"), OPENAPI_SOURCE)
      fetched_sources << openapi

      discovery_entries = discovery_file_entries(context.fetch("commit"))
      discovery_entries.each do |entry|
        fetched_sources << fetch_json_source(
          context.fetch("commit"),
          discovery_spec(entry)
        )
      end

      proto_paths = protobuf_paths(context.fetch("commit"))
      proto_paths.each do |path|
        fetched_sources << fetch_proto_source(context.fetch("commit"), path)
      end

      discovery_documents = fetched_sources.select { |source| source.id.start_with?("discovery:") }
      coverage = validate_corpus!(openapi.parsed, discovery_documents, protobuf_sources: fetched_sources.select do |source|
        source.kind == "protobuf"
      end)
      manifest = build_manifest(context, fetched_sources, coverage)
      write_sources(fetched_sources, manifest)
      puts "Imported #{fetched_sources.length} pinned Kubernetes corpus files into #{@corpus_root}"
      manifest
    end

    def check_existing!(context)
      manifest_path = File.join(@corpus_root, "sources.json")
      manifest = parse_canonical_file!(manifest_path, "sources manifest")
      validate_manifest_header!(manifest, context)

      source_records = manifest.fetch("sources")
      unless source_records.is_a?(Array) && source_records.all?(Hash)
        raise ValidationError, "sources.json must contain a sources array"
      end

      expected_paths = source_records.map { |record| record.fetch("path") }
      raise ValidationError, "sources.json contains duplicate source paths" if expected_paths.uniq.length != expected_paths.length

      source_ids = source_records.map { |record| record.fetch("id") }
      raise ValidationError, "sources.json contains duplicate source IDs" if source_ids.uniq.length != source_ids.length

      sources_by_kind = {}
      source_records.each do |record|
        validate_source_record!(record, context.fetch("commit"))
        path = safe_corpus_path(record.fetch("path"))
        raise ValidationError, "corpus source must not be a symlink: #{record.fetch("path")}" if File.symlink?(path)

        bytes = File.binread(path)
        if Digest::SHA256.hexdigest(bytes) != record.fetch("sha256")
          raise ValidationError, "corpus digest mismatch for #{record.fetch("path")}; rerun importer"
        end
        raise ValidationError, "corpus size mismatch for #{record.fetch("path")}; rerun importer" if bytes.bytesize != record.fetch("bytes")

        if record.fetch("kind") == "json"
          parse_canonical_bytes!(bytes, record.fetch("path"))
        elsif record.fetch("kind") == "protobuf"
          canonical = canonical_proto(bytes)
          raise ValidationError, "#{record.fetch("path")} is not canonical protobuf text; rerun importer" unless canonical == bytes
        else
          raise ValidationError, "unsupported corpus source kind for #{record.fetch("path")}: #{record.fetch("kind").inspect}"
        end
        sources_by_kind[record.fetch("id")] = [record, bytes]
      rescue Errno::ENOENT => error
        raise ValidationError, "corpus source is missing: #{record["path"]}: #{error.message}"
      end

      openapi_record, openapi_bytes = source_records
        .filter_map { |record| [record, sources_by_kind[record["id"]]&.last] if record["id"] == "openapi" }
        .first
      raise ValidationError, "sources.json does not contain the OpenAPI source" unless openapi_record && openapi_bytes

      openapi = JSON.parse(openapi_bytes)
      discovery_documents = source_records.filter_map do |record|
        next unless record["id"].to_s.start_with?("discovery:")

        JSON.parse(sources_by_kind.fetch(record.fetch("id")).last)
        FetchedSource.new(id: record.fetch("id"), parsed: JSON.parse(sources_by_kind.fetch(record.fetch("id")).last))
      end
      protobuf_sources = source_records.filter_map do |record|
        next unless record["kind"] == "protobuf"

        FetchedSource.new(
          id: record.fetch("id"), upstream_path: record.fetch("upstream_path"),
          relative_path: record.fetch("path"), kind: record.fetch("kind"),
          canonical_bytes: sources_by_kind.fetch(record.fetch("id")).last
        )
      end
      coverage = validate_corpus!(openapi, discovery_documents, protobuf_sources: protobuf_sources)
      raise ValidationError, "sources.json coverage does not match the pinned corpus" unless manifest.fetch("coverage") == coverage
      raise ValidationError, "sources.json source_count is incorrect" unless manifest.fetch("source_count") == source_records.length

      expected_file_paths = source_records.map { |record| File.expand_path(record.fetch("path"), @corpus_root) }
      expected_file_paths << manifest_path
      actual_file_paths = Dir.glob(File.join(@corpus_root, "**", "*"), File::FNM_DOTMATCH).select { |path| File.file?(path) }.sort
      extras = actual_file_paths - expected_file_paths
      missing = expected_file_paths - actual_file_paths
      unless extras.empty? && missing.empty?
        relative_extras = extras.map { |path| path.delete_prefix("#{@corpus_root}/") }
        relative_missing = missing.map { |path| path.delete_prefix("#{@corpus_root}/") }
        raise ValidationError, "corpus inventory mismatch (extra=#{relative_extras.inspect}, missing=#{relative_missing.inspect})"
      end

      puts "Kubernetes corpus check passed (#{source_records.length} files, offline)"
      manifest
    rescue KeyError => error
      raise ValidationError, "sources.json is missing #{error.message}"
    rescue JSON::ParserError => error
      raise ValidationError, "corpus JSON is invalid: #{error.message}"
    end

    def discovery_file_entries(commit)
      entries = @contents_client.list(DISCOVERY_DIRECTORY, commit)
      files = entries.select { |entry| entry["type"] == "file" }
      unless files.length == entries.length && files.all? { |entry| entry["name"].match?(/\A[a-zA-Z0-9._-]+\.json\z/) }
        raise ValidationError, "api/discovery contents contains an unexpected entry"
      end

      files.sort_by { |entry| entry.fetch("path") }
    end

    def protobuf_paths(commit)
      paths = []
      api_entries = @contents_client.list(PROTO_ROOTS.fetch(:kubernetes_api), commit)
      # API groups are directories directly below k8s.io/api. Listing every
      # group directory makes generated.proto discovery independent of a
      # hardcoded Kubernetes API group list. Kubernetes keeps generated.proto
      # directly under each version directory; the raw fetch below is also an
      # existence check for each enumerated path. Avoid listing every version
      # directory separately because anonymous GitHub API requests are rate
      # limited and the contents API already enumerates the version names.
      api_entries.select do |entry|
        entry["type"] == "dir" && !%w[.github testdata].include?(entry["name"])
      end.each do |group_entry|
        group_entries = @contents_client.list(group_entry.fetch("path"), commit)
        group_entries.each do |version_entry|
          next unless version_entry["type"] == "dir" && version_entry["name"].match?(/\Av\d+(?:alpha\d+|beta\d+)?\z/)

          paths << "#{version_entry.fetch("path")}/generated.proto"
        end
      end
      # Keep support files explicit: they provide Kubernetes API extension,
      # aggregator, version, runtime, schema, and utility descriptors that are
      # not located below k8s.io/api.
      PROTO_ROOTS.fetch(:support).each do |path|
        parent = path.delete_suffix("/generated.proto")
        entries = @contents_client.list(parent, commit)
        generated = entries.find { |entry| entry["type"] == "file" && entry["name"] == "generated.proto" }
        raise ValidationError, "pinned support protobuf is missing: #{path}" unless generated && generated["path"] == path

        paths << path
      end
      paths = paths.uniq.sort
      raise ValidationError, "no pinned Kubernetes protobuf files were discovered" if paths.empty?

      paths
    end

    def discovery_spec(entry)
      name = entry.fetch("name")
      {
        id: "discovery:#{name}",
        upstream_path: entry.fetch("path"),
        relative_path: "discovery/#{name}",
        kind: "json",
        max_bytes: MAX_JSON_BYTES
      }
    end

    def proto_spec(path)
      relative = path.delete_prefix("staging/src/")
      {
        id: "protobuf:#{relative}",
        upstream_path: path,
        relative_path: "protobuf/#{relative}",
        kind: "protobuf",
        max_bytes: MAX_PROTO_BYTES
      }
    end

    def fetch_json_source(commit, spec)
      url = raw_url(commit, spec.fetch(:upstream_path))
      raw_bytes = @fetcher.fetch(url, max_bytes: spec.fetch(:max_bytes), accept: "application/json")
      parsed = parse_json_bytes!(raw_bytes, spec.fetch(:upstream_path))
      canonical_bytes = canonical_json(parsed)
      FetchedSource.new(
        id: spec.fetch(:id), upstream_path: spec.fetch(:upstream_path),
        relative_path: spec.fetch(:relative_path), url: url, kind: spec.fetch(:kind),
        raw_bytes: raw_bytes, canonical_bytes: canonical_bytes, parsed: parsed,
        raw_sha256: Digest::SHA256.hexdigest(raw_bytes),
        canonical_sha256: Digest::SHA256.hexdigest(canonical_bytes)
      )
    end

    def fetch_proto_source(commit, path)
      spec = proto_spec(path)
      url = raw_url(commit, path)
      raw_bytes = @fetcher.fetch(url, max_bytes: spec.fetch(:max_bytes), accept: "text/plain")
      canonical_bytes = canonical_proto(raw_bytes)
      FetchedSource.new(
        id: spec.fetch(:id), upstream_path: path, relative_path: spec.fetch(:relative_path),
        url: url, kind: spec.fetch(:kind), raw_bytes: raw_bytes, canonical_bytes: canonical_bytes,
        raw_sha256: Digest::SHA256.hexdigest(raw_bytes),
        canonical_sha256: Digest::SHA256.hexdigest(canonical_bytes)
      )
    end

    def validate_corpus!(openapi, discovery_documents, protobuf_sources: [])
      openapi_gvks = extract_openapi_gvks(openapi)
      discovery = extract_discovery_records(discovery_documents)
      consistency = validate_discovery_consistency!(discovery)
      openapi_keys_by_kind = openapi_gvks.fetch(:keys).group_by { |key| key.split("/").last }
      schema_omitted = []
      missing = discovery.fetch(:gvks).keys.reject do |key|
        next true if openapi_gvks.fetch(:keys).include?(key)

        kind = key.split("/").last
        # Core discovery names a few protocol-only subresources with option
        # kinds that intentionally have no OpenAPI definition (exec, attach,
        # proxy, and port-forward). They remain covered GVRs, but are not
        # schema GVKs. Other cross-group subresources (Scale, Eviction, and
        # TokenRequest) are represented by their canonical OpenAPI GVK.
        if PROTOCOL_ONLY_GVKS.include?(key)
          schema_omitted << key
          true
        else
          openapi_keys_by_kind.key?(kind)
        end
      end.sort
      raise ValidationError, "discovery GVKs missing from OpenAPI: #{missing.join(", ")}" unless missing.empty?
      unless openapi_gvks.fetch(:duplicates).empty?
        raise ValidationError, "duplicate OpenAPI GVKs: #{openapi_gvks.fetch(:duplicates).join(", ")}"
      end
      unless discovery.fetch(:duplicate_gvrs).empty?
        raise ValidationError, "duplicate discovery GVRs: #{discovery.fetch(:duplicate_gvrs).join(", ")}"
      end

      served_gvr_coverage = validate_served_gvr_openapi_coverage!(discovery, openapi_gvks)
      protobuf_closure = validate_protobuf_closure!(protobuf_sources)

      {
        "discovery_gvk_count" => discovery.fetch(:gvks).length,
        "discovery_gvr_count" => discovery.fetch(:gvrs).length,
        "served_gvr_count" => served_gvr_coverage.fetch("served_gvr_count"),
        "served_gvr_openapi_gvk_count" => served_gvr_coverage.fetch("served_gvr_openapi_gvk_count"),
        "served_gvr_missing_openapi_gvrs" => served_gvr_coverage.fetch("missing_openapi_gvrs"),
        "served_gvr_schema_omitted_gvrs" => served_gvr_coverage.fetch("schema_omitted_gvrs"),
        "served_gvr_ambiguous_openapi_gvrs" => served_gvr_coverage.fetch("ambiguous_openapi_gvrs"),
        "openapi_gvk_count" => openapi_gvks.fetch(:keys).length,
        "duplicate_gvks" => openapi_gvks.fetch(:duplicates).sort,
        "duplicate_gvrs" => discovery.fetch(:duplicate_gvrs).sort,
        "missing_openapi_gvks" => missing,
        "schema_omitted_gvks" => schema_omitted.sort,
        "discovery_consistency" => consistency,
        "protobuf_closure" => protobuf_closure,
        "covered_gvks" => discovery.fetch(:gvks).keys.sort,
        "covered_gvrs" => discovery.fetch(:gvrs).keys.sort
      }
    end

    def validate_served_gvr_openapi_coverage!(discovery, openapi_gvks)
      keys = openapi_gvks.fetch(:keys)
      keys_by_kind = keys.group_by { |key| key.split("/").last }
      missing = []
      omitted = []
      ambiguous = []
      matched = []

      discovery.fetch(:gvrs).each do |gvr, record|
        gvk = gvk_key(record.fetch("group"), record.fetch("version"), record.fetch("kind"))
        candidates = if keys.include?(gvk)
                       [gvk]
                     else
                       keys_by_kind.fetch(record.fetch("kind"), [])
                     end
        if candidates.empty? && PROTOCOL_ONLY_GVKS.include?(gvk)
          omitted << gvr
        elsif candidates.empty?
          missing << gvr
        elsif candidates.length > 1
          ambiguous << {"gvr" => gvr, "openapi_gvks" => candidates.sort}
        else
          matched << gvr
        end
      end

      raise ValidationError, "served discovery GVRs missing from OpenAPI: #{missing.sort.join(", ")}" unless missing.empty?

      unless ambiguous.empty?
        values = ambiguous.sort_by { |entry| entry.fetch("gvr") }.map { |entry| entry.fetch("gvr") }
        raise ValidationError, "served discovery GVRs have ambiguous OpenAPI GVKs: #{values.join(", ")}"
      end

      {
        "served_gvr_count" => discovery.fetch(:gvrs).length,
        "served_gvr_openapi_gvk_count" => matched.length,
        "missing_openapi_gvrs" => missing.sort,
        "schema_omitted_gvrs" => omitted.sort,
        "ambiguous_openapi_gvrs" => ambiguous.sort_by { |entry| entry.fetch("gvr") }
      }
    end

    def validate_discovery_consistency!(discovery)
      records_by_resource = discovery.fetch(:records).group_by { |record| discovery_resource_key(record) }
      duplicate_resources = []
      kind_conflicts = []
      scope_conflicts = []
      verbs_conflicts = []

      records_by_resource.each do |resource_key, records|
        by_representation = records.group_by { |record| record.fetch("document") }
        duplicate_resources << resource_key if by_representation.any? { |_representation, values| values.length > 1 }

        kinds = records.map { |record| record.fetch("kind") }.uniq.sort
        scopes = records.map { |record| record.fetch("scope") }.uniq.sort
        verbs = records.map { |record| record.fetch("verbs").sort }.uniq.sort_by(&:to_s)
        kind_conflicts << {"resource" => resource_key, "kinds" => kinds} if kinds.length > 1
        scope_conflicts << {"resource" => resource_key, "scopes" => scopes} if scopes.length > 1
        verbs_conflicts << {"resource" => resource_key, "verbs" => verbs} if verbs.length > 1
      end

      duplicate_resources.sort!
      kind_conflicts.sort_by! { |entry| entry.fetch("resource") }
      scope_conflicts.sort_by! { |entry| entry.fetch("resource") }
      verbs_conflicts.sort_by! { |entry| entry.fetch("resource") }
      unless duplicate_resources.empty? && kind_conflicts.empty? && scope_conflicts.empty? && verbs_conflicts.empty?
        failures = []
        failures << "duplicate resources #{duplicate_resources.join(", ")}" unless duplicate_resources.empty?
        failures << "kind conflicts #{kind_conflicts.map { |entry| entry.fetch("resource") }.join(", ")}" unless kind_conflicts.empty?
        failures << "scope conflicts #{scope_conflicts.map { |entry| entry.fetch("resource") }.join(", ")}" unless scope_conflicts.empty?
        failures << "verbs conflicts #{verbs_conflicts.map { |entry| entry.fetch("resource") }.join(", ")}" unless verbs_conflicts.empty?
        raise ValidationError, "legacy/aggregated discovery consistency failed: #{failures.join("; ")}"
      end

      overlap = records_by_resource.filter_map do |resource_key, records|
        representations = records.map { |record| record.fetch("document") }.uniq
        resource_key if representations.sort == %w[aggregated resource-list]
      end.sort
      {
        "legacy_record_count" => discovery.fetch(:records).count { |record| record.fetch("document") == "resource-list" },
        "aggregated_record_count" => discovery.fetch(:records).count { |record| record.fetch("document") == "aggregated" },
        "legacy_aggregated_overlap_count" => overlap.length,
        "legacy_aggregated_overlap_gvrs" => overlap,
        "duplicate_resources" => duplicate_resources,
        "kind_conflicts" => kind_conflicts,
        "scope_conflicts" => scope_conflicts,
        "verbs_conflicts" => verbs_conflicts
      }
    end

    def validate_protobuf_closure!(protobuf_sources)
      raise ValidationError, "corpus contains no protobuf sources for import closure validation" if protobuf_sources.empty?

      sources_by_import_path = {}
      protobuf_sources.each do |source|
        import_path = source.upstream_path.delete_prefix("staging/src/")
        unless source.upstream_path.start_with?("staging/src/") &&
               KUBERNETES_PROTO_PREFIXES.any? { |prefix| import_path.start_with?(prefix) } &&
               import_path.match?(%r{\A[a-zA-Z0-9._/-]+\.proto\z}) && !import_path.split("/").include?("..")
          raise ValidationError, "invalid protobuf source path for import closure: #{source.upstream_path}"
        end
        raise ValidationError, "duplicate protobuf source path in corpus: #{import_path}" if sources_by_import_path.key?(import_path)

        sources_by_import_path[import_path] = source
      end

      imports_by_source = {}
      import_occurrences = []
      standard_imports = []
      unresolved_imports = []
      protobuf_sources.sort_by(&:id).each do |source|
        text = source.canonical_bytes.dup.force_encoding(Encoding::UTF_8)
        imports = extract_proto_imports(text, source.id)
        imports_by_source[source.upstream_path.delete_prefix("staging/src/")] = imports
        imports.each do |import_path|
          import_occurrences << import_path
          if standard_descriptor_import?(import_path)
            standard_imports << import_path
          elsif KUBERNETES_PROTO_PREFIXES.none? { |prefix| import_path.start_with?(prefix) } ||
                !sources_by_import_path.key?(import_path)
            unresolved_imports << {
              "source" => source.id,
              "import" => import_path
            }
          end
        end
      end

      states = {}
      stack = []
      reachable = []
      cycles = []
      visit = lambda do |import_path|
        case states[import_path]
        when :visited
          next
        when :visiting
          cycle_start = stack.index(import_path) || 0
          cycles << (stack[cycle_start..] + [import_path])
          next
        end
        states[import_path] = :visiting
        stack << import_path
        reachable << import_path
        imports_by_source.fetch(import_path, []).each do |dependency|
          next if standard_descriptor_import?(dependency)
          next unless sources_by_import_path.key?(dependency)

          visit.call(dependency)
        end
        stack.pop
        states[import_path] = :visited
      end
      sources_by_import_path.keys.sort.each { |import_path| visit.call(import_path) }

      unresolved_imports.sort_by! { |entry| [entry.fetch("source"), entry.fetch("import")] }
      cycles = cycles.map(&:freeze).uniq.sort_by(&:to_s)
      unless unresolved_imports.empty?
        formatted = unresolved_imports.map { |entry| "#{entry.fetch("source")} -> #{entry.fetch("import")}" }
        raise ValidationError, "protobuf imports are not present in the corpus: #{formatted.join(", ")}"
      end
      raise ValidationError, "protobuf import cycle detected: #{cycles.first.join(" -> ")}" unless cycles.empty?

      {
        "source_count" => protobuf_sources.length,
        "reachable_source_count" => reachable.uniq.length,
        "import_count" => import_occurrences.length,
        "unique_import_count" => import_occurrences.uniq.length,
        "resolved_import_count" => (import_occurrences - standard_imports).length,
        "standard_descriptor_imports" => standard_imports.uniq.sort,
        "unresolved_imports" => unresolved_imports,
        "cycle_count" => cycles.length,
        "cycles" => cycles,
        "closed" => true
      }
    end

    def extract_proto_imports(text, source_id)
      raise ValidationError, "protobuf source is not valid UTF-8 for import closure: #{source_id}" unless text.valid_encoding?

      uncommented = text.gsub(%r{/\*.*?\*/}m, " ").gsub(%r{//[^\n]*}, "")
      imports = uncommented.scan(PROTO_IMPORT_PATTERN).flatten
      imports.each do |import_path|
        unless import_path.match?(%r{\A[a-zA-Z0-9._/-]+\.proto\z}) && !import_path.start_with?("/") &&
               !import_path.split("/").include?("..")
          raise ValidationError, "invalid protobuf import path #{import_path.inspect} in #{source_id}"
        end
      end
      imports
    end

    def standard_descriptor_import?(import_path)
      STANDARD_DESCRIPTOR_PREFIXES.any? { |prefix| import_path.start_with?(prefix) }
    end

    def extract_openapi_gvks(openapi)
      unless openapi.is_a?(Hash) && openapi["swagger"] == "2.0" && openapi["definitions"].is_a?(Hash)
        raise ValidationError, "OpenAPI source must be a Swagger v2 document with definitions"
      end

      keys = []
      duplicates = []
      openapi.fetch("definitions").each do |definition_name, definition|
        extension = definition.is_a?(Hash) ? definition["x-kubernetes-group-version-kind"] : nil
        next if extension.nil?
        unless extension.is_a?(Array) && !extension.empty?
          raise ValidationError, "OpenAPI #{definition_name} has an invalid x-kubernetes-group-version-kind"
        end

        extension.each do |record|
          unless record.is_a?(Hash) && %w[group version kind].all? { |field| record[field].is_a?(String) }
            raise ValidationError, "OpenAPI #{definition_name} has an invalid GVK extension"
          end

          key = gvk_key(record["group"], record["version"], record["kind"])
          duplicates << key if keys.include?(key)
          keys << key
        end
      end
      raise ValidationError, "OpenAPI contains no GVK extensions" if keys.empty?

      {keys: keys.uniq, duplicates: duplicates.uniq}
    end

    def extract_discovery_records(documents)
      gvks = {}
      gvrs = {}
      duplicate_gvrs = []
      records = []
      documents.sort_by(&:id).each do |document|
        parsed = document.parsed
        next if parsed.nil?

        if parsed["kind"] == "APIGroupDiscoveryList"
          extract_aggregated_records(parsed).each do |record|
            records << record.merge("document_id" => document.id)
            add_discovery_record(record, gvks, gvrs, duplicate_gvrs, document.id)
          end
        elsif parsed["kind"] == "APIResourceList"
          extract_api_resource_list_records(parsed).each do |record|
            records << record.merge("document_id" => document.id)
            add_discovery_record(record, gvks, gvrs, duplicate_gvrs, document.id)
          end
        elsif %w[APIGroupList APIGroup APIVersions].include?(parsed["kind"])
          validate_discovery_index!(parsed)
        else
          raise ValidationError, "unsupported discovery document kind in #{document.id}: #{parsed["kind"].inspect}"
        end
      end
      raise ValidationError, "discovery corpus contains no GVKs" if gvks.empty?

      {gvks: gvks, gvrs: gvrs, records: records, duplicate_gvrs: duplicate_gvrs.uniq}
    end

    def extract_aggregated_records(document)
      items = document["items"]
      raise ValidationError, "aggregated discovery document must contain items" unless items.is_a?(Array)

      records = []
      items.each do |item|
        group = item.dig("metadata", "name")
        raise ValidationError, "aggregated discovery item has no group name" unless group.is_a?(String)

        versions = item["versions"]
        raise ValidationError, "aggregated discovery group #{group} has no versions" unless versions.is_a?(Array)

        versions.each do |version_entry|
          version = version_entry["version"]
          resources = version_entry["resources"]
          unless version.is_a?(String) && resources.is_a?(Array)
            raise ValidationError, "aggregated discovery group #{group} has an invalid version"
          end

          resources.each do |resource|
            raise ValidationError, "aggregated discovery group #{group}/#{version} contains an invalid resource" unless resource.is_a?(Hash)

            records << aggregated_record(group, version, resource, nil)
            subresources = resource["subresources"]
            unless subresources.nil? || subresources.is_a?(Array)
              raise ValidationError, "aggregated discovery resource #{resource["resource"]} has invalid subresources"
            end

            subresources.to_a.each do |subresource|
              unless subresource.is_a?(Hash)
                raise ValidationError, "aggregated discovery resource #{resource["resource"]} has an invalid subresource"
              end

              records << aggregated_record(group, version, resource, subresource)
            end
          end
        end
      end
      records
    end

    def aggregated_record(group, version, resource, subresource)
      name = subresource ? "#{resource.fetch("resource")}/#{subresource.fetch("subresource")}" : resource.fetch("resource")
      response_kind = (subresource || resource).fetch("responseKind")
      unless response_kind.is_a?(Hash) && response_kind["kind"].is_a?(String)
        raise ValidationError, "aggregated discovery resource #{name} has an invalid responseKind"
      end

      scope = resource.fetch("scope")
      verbs = (subresource || resource).fetch("verbs")
      unless %w[Cluster Namespaced].include?(scope) && verbs.is_a?(Array) && verbs.all?(String)
        raise ValidationError, "aggregated discovery resource #{name} has invalid scope or verbs"
      end

      kind_group = response_kind["group"].to_s
      kind_version = response_kind["version"].to_s
      {
        "group" => kind_group.empty? ? group : kind_group,
        "version" => kind_version.empty? ? version : kind_version,
        "kind" => response_kind.fetch("kind"),
        "resource" => name,
        "endpoint_group" => group,
        "endpoint_version" => version,
        "scope" => scope,
        "verbs" => verbs.sort,
        "document" => "aggregated"
      }
    rescue KeyError => error
      raise ValidationError, "aggregated discovery resource is incomplete: #{error.message}"
    end

    def extract_api_resource_list_records(document)
      group_version = document["groupVersion"]
      resources = document["resources"]
      unless group_version.is_a?(String) && resources.is_a?(Array)
        raise ValidationError, "APIResourceList must contain groupVersion and resources"
      end

      parts = group_version.split("/", 2)
      group, version = parts.length == 2 ? parts : ["", parts.fetch(0)]
      resources.map do |resource|
        unless resource.is_a?(Hash) && resource["name"].is_a?(String) && resource["kind"].is_a?(String) &&
               [true, false].include?(resource["namespaced"]) && resource["verbs"].is_a?(Array) &&
               resource["verbs"].all?(String)
          raise ValidationError, "APIResourceList #{group_version} contains an invalid resource"
        end

        {
          "group" => group,
          "version" => version,
          "kind" => resource.fetch("kind"),
          "resource" => resource.fetch("name"),
          "endpoint_group" => group,
          "endpoint_version" => version,
          "scope" => resource["namespaced"] == true ? "Namespaced" : "Cluster",
          "verbs" => resource.fetch("verbs").sort,
          "document" => "resource-list"
        }
      end
    end

    def validate_discovery_index!(document)
      case document["kind"]
      when "APIGroupList"
        raise ValidationError, "APIGroupList must contain groups" unless document["groups"].is_a?(Array)
      when "APIGroup"
        raise ValidationError, "APIGroup must contain versions" unless document["versions"].is_a?(Array)
      when "APIVersions"
        raise ValidationError, "APIVersions must contain versions" unless document["versions"].is_a?(Array)
      end
    end

    def add_discovery_record(record, gvks, gvrs, duplicate_gvrs, document_id)
      gvk = gvk_key(record.fetch("group"), record.fetch("version"), record.fetch("kind"))
      gvr = gvr_key(record.fetch("group"), record.fetch("version"), record.fetch("resource"))
      if gvrs.key?(gvr) && gvrs.fetch(gvr).fetch("kind") != record.fetch("kind")
        raise ValidationError, "discovery GVR #{gvr} maps to conflicting kinds"
      end

      # Aggregated discovery and APIResourceList are two representations of
      # the same endpoint. Duplicate GVRs are errors only within one document;
      # cross-document copies must agree and are intentionally deduplicated.
      duplicate_gvrs << gvr if gvrs.key?(gvr) && gvrs.fetch(gvr).fetch("document") == record.fetch("document")
      gvrs[gvr] ||= record.merge("document_id" => document_id)
      gvks[gvk] ||= record.merge("document_id" => document_id)
    rescue KeyError => error
      raise ValidationError, "discovery record is incomplete: #{error.message}"
    end

    def gvk_key(group, version, kind)
      [group.to_s.empty? ? "core" : group, version, kind].join("/")
    end

    def gvr_key(group, version, resource)
      [group.to_s.empty? ? "core" : group, version, resource].join("/")
    end

    def discovery_resource_key(record)
      gvr_key(record.fetch("endpoint_group", record.fetch("group")),
              record.fetch("endpoint_version", record.fetch("version")), record.fetch("resource"))
    end

    def build_manifest(context, fetched_sources, coverage)
      records = fetched_sources.sort_by(&:relative_path).map do |source|
        {
          "id" => source.id,
          "kind" => source.kind,
          "path" => source.relative_path,
          "upstream_path" => source.upstream_path,
          "url" => source.url,
          "source_commit" => context.fetch("commit"),
          "source_sha256" => source.raw_sha256,
          "source_bytes" => source.raw_bytes.bytesize,
          "sha256" => source.canonical_sha256,
          "bytes" => source.canonical_bytes.bytesize
        }
      end
      {
        "schema_version" => 1,
        "source" => context.fetch("source"),
        "source_count" => records.length,
        "sources" => records,
        "coverage" => coverage
      }
    end

    def write_sources(fetched_sources, manifest)
      fetched_sources.each do |source|
        atomic_write(File.join(@corpus_root, source.relative_path), source.canonical_bytes)
      end
      atomic_write(File.join(@corpus_root, "sources.json"), canonical_json(manifest))
    end

    def validate_manifest_header!(manifest, context)
      return if manifest["schema_version"] == 1 && manifest["source"] == context.fetch("source")

      raise ValidationError, "sources.json source header does not match the Kubernetes lock"
    end

    def validate_source_record!(record, commit)
      required = %w[id kind path upstream_path url source_commit source_sha256 source_bytes sha256 bytes]
      missing = required.reject { |key| record.key?(key) }
      raise ValidationError, "sources.json source record is missing #{missing.join(", ")}" unless missing.empty?
      raise ValidationError, "source commit mismatch for #{record["path"]}" unless record["source_commit"] == commit
      unless record["url"] == raw_url(commit, record.fetch("upstream_path"))
        raise ValidationError, "source URL is not pinned to the lock commit for #{record["path"]}"
      end

      validate_raw_url!(record.fetch("url"), commit, record.fetch("upstream_path"))
      unless record["source_sha256"].is_a?(String) && record["source_sha256"].match?(SHA256_PATTERN)
        raise ValidationError, "source_sha256 is invalid for #{record["path"]}"
      end
      unless record["sha256"].is_a?(String) && record["sha256"].match?(SHA256_PATTERN)
        raise ValidationError, "sha256 is invalid for #{record["path"]}"
      end
      unless record["source_bytes"].is_a?(Integer) && record["source_bytes"] > 0 &&
             record["bytes"].is_a?(Integer) && record["bytes"] > 0
        raise ValidationError, "source byte sizes are invalid for #{record["path"]}"
      end
    end

    def parse_canonical_file!(path, label)
      bytes = File.binread(path)
      parse_canonical_bytes!(bytes, label)
    rescue Errno::ENOENT => error
      raise ValidationError, "#{label} is missing: #{path}: #{error.message}"
    end

    def parse_canonical_bytes!(bytes, label)
      value = parse_json_bytes!(bytes, label)
      canonical = canonical_json(value)
      raise ValidationError, "#{label} is not canonical JSON; rerun importer" unless canonical.b == bytes.b

      value
    end

    def parse_json_bytes!(bytes, label)
      JSON.parse(bytes, object_class: DuplicateCheckingHash, allow_nan: false)
    rescue DuplicateKeyError => error
      raise ValidationError, "#{label} contains #{error.message}"
    rescue JSON::ParserError => error
      raise ValidationError, "#{label} is invalid JSON: #{error.message}"
    end

    def canonical_json(value)
      JSON.generate(canonical_value(value), ascii_only: false)
    end

    def canonical_value(value)
      case value
      when Hash
        value.keys.sort.to_h { |key| [key, canonical_value(value.fetch(key))] }
      when Array
        value.map { |item| canonical_value(item) }
      else
        value
      end
    end

    def canonical_proto(bytes)
      text = bytes.dup.force_encoding(Encoding::UTF_8)
      raise ValidationError, "protobuf source is not valid UTF-8" unless text.valid_encoding?

      text.gsub("\r\n", "\n").tr("\r", "\n").sub(/\n*\z/, "\n").b
    end

    def safe_corpus_path(relative_path)
      unless relative_path.is_a?(String) && relative_path.match?(%r{\A[a-zA-Z0-9._/-]+\z}) &&
             !relative_path.start_with?("/") && !relative_path.split("/").include?("..")
        raise ValidationError, "invalid corpus path in sources.json: #{relative_path.inspect}"
      end

      path = File.expand_path(relative_path, @corpus_root)
      unless path == @corpus_root || path.start_with?("#{@corpus_root}/")
        raise ValidationError, "corpus path escaped output root: #{relative_path.inspect}"
      end

      path
    end

    def atomic_write(path, bytes)
      FileUtils.mkdir_p(File.dirname(path))
      raise Error, "refusing to overwrite symlink: #{path}" if File.symlink?(path)
      return if File.file?(path) && File.binread(path) == bytes

      temporary = Tempfile.new([".#{File.basename(path)}.", ".tmp"], File.dirname(path))
      temporary.binmode
      temporary.write(bytes)
      temporary.flush
      temporary.fsync
      temporary.close
      File.rename(temporary.path, path)
    ensure
      temporary&.close!
    end

    def raw_url(commit, upstream_path)
      unless upstream_path.is_a?(String) && upstream_path.match?(%r{\A[a-zA-Z0-9._/-]+\.json\z|\A[a-zA-Z0-9._/-]+\.proto\z}) &&
             !upstream_path.split("/").include?("..")
        raise ValidationError, "invalid pinned upstream path: #{upstream_path.inspect}"
      end

      url = "#{RAW_BASE_URL}/#{commit}/#{upstream_path}"
      validate_raw_url!(url, commit, upstream_path)
      url
    end

    def validate_raw_url!(url, commit, upstream_path)
      uri = URI.parse(url)
      expected_path = "/kubernetes/kubernetes/#{commit}/#{upstream_path}"
      unless uri.scheme == "https" && uri.host == RAW_HOST && uri.path == expected_path && uri.query.nil?
        raise ValidationError, "source URL must be the official HTTPS raw URL for #{upstream_path}"
      end

      url
    rescue URI::InvalidURIError => error
      raise ValidationError, "invalid source URL #{url.inspect}: #{error.message}"
    end
  end

  module_function

  def run!(argv = ARGV, root: ROOT)
    options = {root: root, check: false, output_root: nil, lock_path: nil}
    parser = OptionParser.new do |opts|
      opts.banner = "Usage: ruby tools/schema/import_kubernetes.rb [--check] [--root PATH]"
      opts.on("--check", "verify the pinned corpus without network access") { options[:check] = true }
      opts.on("--root PATH", "repository root (default: #{root})") { |value| options[:root] = value }
      opts.on("--output-root PATH", "corpus output directory") { |value| options[:output_root] = value }
      opts.on("--lock PATH", "Kubernetes lock file") { |value| options[:lock_path] = value }
    end
    parser.parse!(argv)
    Importer.new(root: options.fetch(:root), lock_path: options[:lock_path], output_root: options[:output_root]).run(
      check: options.fetch(:check)
    )
  rescue Error, OptionParser::ParseError => error
    warn "kubernetes corpus import failed: #{error.message}"
    1
  end
end

if $PROGRAM_NAME == __FILE__
  result = KubernetesCorpusImporter.run!
  exit(result.is_a?(Integer) ? result : 0)
end
