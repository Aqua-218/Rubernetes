#!/usr/bin/env ruby
# frozen_string_literal: true

# Shared, deterministic helpers for the M1 evidence probes.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "time"

ROOT = File.expand_path("../..", __dir__).freeze unless defined?(ROOT)
# Generator runs use a root-level mktemp directory. Keep the exclusion anchored
# to that exact name shape so an arbitrary similarly named source directory is
# still part of the content-addressed input.
unless defined?(SOURCE_EXCLUSIONS)
  SOURCE_EXCLUSIONS = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/}
end
SHA256_PATTERN = /\A[0-9a-f]{64}\z/ unless defined?(SHA256_PATTERN)

module M1ProbeSupport
  module_function

  class ProbeError < StandardError; end

  # A source identity is only usable after two complete inventories agree.
  # A disagreement is evidence of a moving input, not a transient condition
  # that can be retried into a falsely stable report.
  SOURCE_SNAPSHOT_PHASES = 2

  def source_paths(root)
    root = File.expand_path(root)
    raise ProbeError, "source root is not a directory: #{root}" unless File.directory?(root)

    Dir.glob(File.join(root, "**/*"), File::FNM_DOTMATCH).select do |path|
      next false unless File.file?(path)

      relative = path.delete_prefix("#{root}/")
      !relative.match?(SOURCE_EXCLUSIONS)
    end.sort
  rescue Errno::ENOENT, Errno::EACCES => error
    raise ProbeError, "cannot enumerate source input: #{error.message}"
  end

  def source_file_metadata(path)
    stat = File.stat(path)
    {
      "dev" => stat.dev,
      "ino" => stat.ino,
      "size" => stat.size,
      "mtime_ns" => (stat.mtime.to_i * 1_000_000_000) + stat.mtime.nsec,
      "ctime_ns" => (stat.ctime.to_i * 1_000_000_000) + stat.ctime.nsec
    }
  rescue Errno::ENOENT, Errno::EACCES => error
    raise ProbeError, "source file disappeared while capturing #{path}: #{error.message}"
  end

  def source_file_capture(root, path)
    before = source_file_metadata(path)
    digest = Digest::SHA256.file(path).hexdigest
    after = source_file_metadata(path)
    raise ProbeError, "source file changed while capturing #{path.delete_prefix("#{root}/")}" unless before == after

    relative = path.delete_prefix("#{root}/")
    {
      "entry" => {"path" => relative, "sha256" => digest, "bytes" => after.fetch("size")},
      "stability_metadata" => after.merge("path" => relative)
    }
  rescue Errno::ENOENT, Errno::EACCES => error
    raise ProbeError, "source file disappeared while hashing #{path}: #{error.message}"
  end

  def source_identity(root = ROOT)
    root = File.expand_path(root)
    paths = source_paths(root)
    captures = paths.map { |path| source_file_capture(root, path) }
    raise ProbeError, "source input paths changed while capturing the inventory" unless source_paths(root) == paths

    {
      "sha256" => canonical_inventory_digest(captures.map { |capture| capture.fetch("entry") }),
      "file_count" => captures.length,
      "entries" => captures.map { |capture| capture.fetch("entry") },
      "stability_metadata" => captures.map { |capture| capture.fetch("stability_metadata") }
    }
  end

  def stable_source_identity(root = ROOT, between_snapshots: nil)
    snapshots = []
    SOURCE_SNAPSHOT_PHASES.times do |phase|
      snapshots << source_identity(root)
      if between_snapshots && phase < SOURCE_SNAPSHOT_PHASES - 1
        if between_snapshots.arity.zero?
          between_snapshots.call
        else
          between_snapshots.call(phase, snapshots.last)
        end
      end
    end
    return snapshots.first if snapshots.uniq.length == 1

    raise ProbeError, "source input changed during the stable inventory snapshot"
  end

  def capture_source_input(root = ROOT)
    starting = stable_source_identity(root)
    yield(starting) if block_given?
    finishing = stable_source_identity(root)
    {
      "start" => starting,
      "finish" => finishing,
      "stable" => starting == finishing
    }
  end

  def canonical_inventory_digest(entries)
    material = entries.sort_by { |entry| entry.fetch("path") }.map do |entry|
      "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n"
    end.join
    Digest::SHA256.hexdigest(material)
  end

  def input_context(current)
    expected_sha = ENV.fetch("RUBERNETES_M1_INPUT_SHA256", nil)
    expected_count = ENV.fetch("RUBERNETES_M1_INPUT_FILE_COUNT", nil)
    errors = []

    errors << "RUBERNETES_M1_INPUT_SHA256 must be a lowercase SHA-256 digest" if expected_sha && !SHA256_PATTERN.match?(expected_sha)
    parsed_count = begin
      Integer(expected_count, 10) if expected_count
    rescue ArgumentError, TypeError
      nil
    end
    errors << "RUBERNETES_M1_INPUT_FILE_COUNT must be a positive integer" if expected_count && (!parsed_count || parsed_count <= 0)

    input_sha = expected_sha && SHA256_PATTERN.match?(expected_sha) ? expected_sha : current.fetch("sha256")
    input_file_count = parsed_count && parsed_count.positive? ? parsed_count : current.fetch("file_count")
    stable = current.fetch("sha256") == input_sha && current.fetch("file_count") == input_file_count
    errors << "source input changed before probe execution" unless stable
    {
      "sha256" => input_sha,
      "file_count" => input_file_count,
      "stable" => stable,
      "errors" => errors
    }
  end

  def report_base(kind, input, passed:, errors: [], **fields)
    {
      "schema_version" => 1,
      "kind" => kind,
      "input_sha256" => input.fetch("sha256"),
      "input_file_count" => input.fetch("file_count"),
      "input_stable" => input.fetch("stable"),
      "retry_count" => 0,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "flake_count" => 0,
      "passed" => passed,
      "errors" => Array(errors).map(&:to_s)
    }.merge(fields)
  end

  def probe_report(kind, root: ROOT)
    starting = nil
    finishing = nil
    input = nil
    errors = []

    begin
      starting = stable_source_identity(root)
      input = input_context(starting)
      errors.concat(input.fetch("errors"))
    rescue StandardError => error
      errors << "#{error.class}: #{error.message}"
      input = {"sha256" => "0" * 64, "file_count" => 0, "stable" => false, "errors" => []}
    end

    payload = {}
    begin
      # Some Linux filesystems assign ctime at clock-tick granularity.  Keep
      # the execution window on a later tick than the starting inventory so a
      # write-then-restore cannot reproduce identical stability metadata.
      sleep(0.001)
      payload = yield(starting, input) if errors.empty?
    rescue StandardError => error
      errors << "#{error.class}: #{error.message}"
    end

    begin
      finishing = stable_source_identity(root)
    rescue StandardError => error
      errors << "#{error.class}: #{error.message}"
    end

    source_capture_stable = starting.is_a?(Hash) && finishing.is_a?(Hash) && starting == finishing
    errors << "source input changed during probe execution" unless source_capture_stable
    input["stable"] = input.fetch("stable") && source_capture_stable

    payload = {} unless payload.is_a?(Hash)
    payload_errors = Array(payload.delete("errors")).map(&:to_s)
    errors.concat(payload_errors)
    declared_passed = payload.delete("passed")
    declared_failures = payload["failure_count"]
    declared_failures = 0 unless declared_failures.is_a?(Integer) && declared_failures >= 0
    failure_count = [declared_failures, errors.empty? ? 0 : 1].max
    payload["failure_count"] = failure_count
    passed = input.fetch("stable") && errors.empty? && (declared_passed.nil? || declared_passed == true) && failure_count.zero?
    report = report_base(kind, input, passed: passed, errors: errors, **payload)
    report["input_capture"] = {
      "stable" => input.fetch("stable"),
      "start" => starting,
      "finish" => finishing
    }
    report
  end

  def run_probe(kind, pretty: true, &)
    report = probe_report(kind, &)
    puts(pretty ? JSON.pretty_generate(report) : JSON.generate(report))
    exit(report.fetch("passed") ? 0 : 1)
  end

  def parse_json(path, label: path)
    JSON.parse(File.binread(path), max_nesting: 512)
  rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR => error
    raise ProbeError, "cannot read #{label}: #{error.message}"
  rescue JSON::ParserError => error
    raise ProbeError, "invalid JSON #{label}: #{error.message}"
  end

  def tree_snapshot(directory, ignore_prefixes: [])
    directory = File.expand_path(directory)
    return {} unless Dir.exist?(directory)

    Dir.glob(File.join(directory, "**/*")).select { |path| File.file?(path) }.each_with_object({}) do |path, snapshot|
      relative = path.delete_prefix("#{directory}/")
      next if ignore_prefixes.any? { |prefix| relative == prefix || relative.start_with?("#{prefix}/") }

      snapshot[relative] = {
        "sha256" => Digest::SHA256.file(path).hexdigest,
        "bytes" => File.size(path)
      }
    end
  end

  def tree_digest(snapshot)
    material = snapshot.keys.sort.map do |path|
      entry = snapshot.fetch(path)
      "#{path}\0#{entry.fetch("sha256")}\n"
    end.join
    Digest::SHA256.hexdigest(material)
  end

  def tree_differences(expected, actual)
    (expected.keys | actual.keys).sort.filter_map do |path|
      if !expected.key?(path)
        {"path" => path, "kind" => "unexpected"}
      elsif !actual.key?(path)
        {"path" => path, "kind" => "missing"}
      elsif expected.fetch(path) != actual.fetch(path)
        {"path" => path, "kind" => "changed"}
      end
    end
  end

  def run_command(*argv, env: {}, chdir: ROOT)
    stdout, stderr, status = Open3.capture3(env, *argv, chdir: chdir)
    {
      "command" => argv,
      "stdout" => stdout,
      "stderr" => stderr,
      "exit_status" => status.exitstatus || 1
    }
  rescue SystemCallError => error
    {
      "command" => argv,
      "stdout" => "",
      "stderr" => "",
      "exit_status" => 127,
      "error" => "command could not be executed: #{error.message}"
    }
  end

  def build_api_server
    $LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
    require "rubernetes/api"
    require "rubernetes/bootstrap/api_server_service"
    require "rubernetes/storage/memory_store"
    registry_payload = parse_json(
      File.join(ROOT, "generated/schema/registry.json"),
      label: "generated schema registry"
    )
    type_index = registry_payload.fetch("types").to_h { |entry| [entry.fetch("schema"), entry] }
    resources = registry_payload.fetch("resources").map do |entry|
      subresources = Array(entry.fetch("subresources", [])).map do |subresource|
        {
          resource: subresource.fetch("resource"),
          kind: subresource["kind"],
          verbs: subresource.fetch("verbs", [])
        }
      end
      Rubernetes::API::Resource.new(
        group: entry.fetch("group", ""),
        version: entry.fetch("version"),
        resource: entry.fetch("resource"),
        kind: entry.fetch("kind"),
        scope: entry.fetch("scope", "Cluster"),
        short_names: entry.fetch("short_names", []),
        categories: entry.fetch("categories", []),
        verbs: entry.fetch("verbs", []),
        list_kind: entry.fetch("list_kind", "#{entry.fetch("kind")}List"),
        singular_name: entry.fetch("singular", ""),
        merge_keys: entry.fetch("merge_keys", {}),
        patch_strategy: entry.fetch("patch_strategy", "merge") || :merge,
        schema: begin
          type = type_index.fetch(entry.fetch("schema"))
          generated = Rubernetes::Generated.const_get(type.fetch("ruby_constant"), false)
          definition = generated.const_get(:DEFINITION, false)
          Rubernetes::Bootstrap::APIServerService::SchemaContract.new(definition)
        rescue KeyError, NameError => error
          raise ProbeError, "generated schema contract is missing for #{entry.fetch("schema").inspect}: #{error.message}"
        end,
        subresources: subresources
      )
    end
    registry = Rubernetes::API::Registry.new(resources: resources, defaults: false)
    store = Rubernetes::Storage::MemoryStore.new(
      clock: -> { Time.utc(2026, 1, 1, 0, 0, 0) },
      token_secret: "m1-probe-token-secret",
      random: Random.new(1)
    )
    server = Rubernetes::API::Server.new(
      namespace_lifecycle: true,
      registry: registry,
      store: store,
      openapi_root: File.join(ROOT, "generated/openapi"),
      identity_resolver: DifferentialIdentityResolver.new
    )
    [server, store, registry_payload]
  end

  # The in-process differential requester carries the same identity as the
  # static token file entry of the isolated kube-apiserver, and the
  # TokenReview endpoint recognizes the deterministic review token.
  class DifferentialIdentityResolver
    REQUESTER = {"username" => "m1-oracle", "uid" => "1", "groups" => %w[system:masters system:authenticated]}.freeze
    REVIEW_TOKEN = "m1-review-token-6f1c0d2a"
    REVIEW = {"username" => "m1-review", "uid" => "2", "groups" => %w[system:reviewers system:authenticated]}.freeze

    def call(_request = nil)
      REQUESTER.transform_values(&:dup)
    end

    def authenticate_token(token)
      token.to_s == REVIEW_TOKEN ? REVIEW.transform_values(&:dup) : nil
    end
  end

  # The discovery files are part of the pinned v1.36.2 input, rather than a
  # hand-written list in a probe.  Keeping the endpoint/path derivation here
  # makes both the corpus probe and the live API differential use the same
  # immutable inventory.
  def canonical_discovery_documents(root = ROOT)
    discovery_root = File.join(root, "schema/kubernetes/v1.36.2/discovery")
    Dir.glob(File.join(discovery_root, "*.json")).filter_map do |path|
      basename = File.basename(path, ".json")
      endpoint = case basename
                 when "api"
                   "/api"
                 when "api__v1"
                   "/api/v1"
                 when "apis"
                   "/apis"
                 when /\Aapis__(.+)__(.+)\z/
                   "/apis/#{Regexp.last_match(1)}/#{Regexp.last_match(2)}"
                 when /\Aapis__(.+)\z/
                   "/apis/#{Regexp.last_match(1)}"
                 end
      next unless endpoint

      {
        "path" => endpoint,
        "source_path" => path.delete_prefix("#{root}/"),
        "body" => parse_json(path, label: "pinned discovery #{basename}")
      }
    end.sort_by { |entry| entry.fetch("path") }
  end

  def discovery_group_version(path)
    segments = path.to_s.split("/").reject(&:empty?)
    if segments.first == "api" && segments.length >= 2
      ["", segments.fetch(1)]
    elsif segments.first == "apis" && segments.length >= 3
      [segments.fetch(1), segments.fetch(2)]
    else
      [nil, nil]
    end
  end

  # Convert an APIResourceList entry to the stable surface vocabulary used by
  # the evidence gate.  Kubernetes also places discovery-only group/version
  # overrides on a few core subresources; the endpoint group/version is the
  # GVR identity for this matrix, matching the pinned corpus coverage ledger.
  def discovery_surface_fields(entry, group:, version:, subresources: [])
    name = entry.fetch("name").to_s
    parent = name.split("/", 2).first
    subresource = name.include?("/")
    kind = entry.fetch("kind", "").to_s
    {
      "group" => group.to_s,
      "version" => version.to_s,
      "resource" => name,
      "kind" => kind,
      "scope" => entry["namespaced"] == true ? "Namespaced" : "Cluster",
      "plural" => parent,
      "singular" => entry.fetch("singularName", "").to_s,
      "verbs" => Array(entry.fetch("verbs", [])).map(&:to_s).sort,
      "subresources" => subresource ? [] : Array(subresources).map(&:to_s).sort,
      "shortNames" => Array(entry.fetch("shortNames", [])).map(&:to_s).sort,
      "categories" => Array(entry.fetch("categories", [])).map(&:to_s).sort,
      "listKind" => subresource || !Array(entry.fetch("verbs", [])).map(&:to_s).include?("list") ? "" : "#{kind}List",
      "schema_contract_present" => false
    }
  end

  def canonical_discovery_surface(root = ROOT)
    documents = canonical_discovery_documents(root)
    registry_path = File.join(root, "generated/schema/registry.json")
    registry = parse_json(registry_path, label: "generated schema registry")
    expected_ids = Array(registry.fetch("gvrs", [])).map { |entry| entry.fetch("identifier") }.to_h { |id| [id, true] }
    rows = []
    documents.each do |document|
      group, version = discovery_group_version(document.fetch("path"))
      next unless group && version

      raw_resources = Array(document.fetch("body")["resources"])
      raw_resources.each do |entry|
        name = entry.fetch("name").to_s
        parent = name.split("/", 2).first
        subresources = raw_resources.filter_map do |candidate|
          candidate_name = candidate.fetch("name").to_s
          candidate_name.delete_prefix("#{parent}/") if candidate_name.start_with?("#{parent}/")
        end
        base_fields = discovery_surface_fields(
          entry,
          group: group,
          version: version,
          subresources: subresources
        ).merge("source_path" => document.fetch("source_path"))
        rows << base_fields

        # A few APIResourceList entries describe a cross-group subresource via
        # group/version overrides.  Only materialize an override when the
        # pinned registry explicitly serves that alternate identity (the
        # policy Eviction annotation is descriptive, not a second GVR).
        override_group = entry["group"]
        override_version = entry["version"] || version
        next unless override_group

        override_fields = discovery_surface_fields(
          entry,
          group: override_group,
          version: override_version,
          subresources: subresources
        ).merge("source_path" => document.fetch("source_path"))
        rows << override_fields if expected_ids.key?(surface_identifier(override_fields))
      end
    end

    # API discovery v2 carries cross-group subresources (notably the
    # autoscaling Scale endpoints) that are intentionally absent from the
    # legacy per-group APIResourceList fixtures.  Merge that pinned response
    # into the same 153-entry served-GVR inventory, retaining the legacy row
    # when both representations describe the same identity.
    aggregate_path = File.join(root, "schema/kubernetes/v1.36.2/discovery/aggregated_v2.json")
    if File.file?(aggregate_path)
      aggregate = parse_json(aggregate_path, label: "pinned aggregated discovery")
      Array(aggregate.fetch("items", [])).each do |group_entry|
        group = group_entry.dig("metadata", "name").to_s
        Array(group_entry.fetch("versions", [])).each do |version_entry|
          version = version_entry.fetch("version").to_s
          raw_resources = Array(version_entry.fetch("resources", []))
          raw_resources.each do |entry|
            parent_name = entry.fetch("resource").to_s
            parent_kind = entry.dig("responseKind", "kind").to_s
            parent = {
              "name" => parent_name,
              "kind" => parent_kind,
              "namespaced" => entry.fetch("scope").to_s == "Namespaced",
              "singularName" => entry.fetch("singularResource", ""),
              "verbs" => entry.fetch("verbs", []),
              "shortNames" => entry.fetch("shortNames", []),
              "categories" => entry.fetch("categories", [])
            }
            subresource_names = Array(entry.fetch("subresources", [])).map { |sub| sub.fetch("subresource").to_s }
            rows << discovery_surface_fields(
              parent,
              group: group,
              version: version,
              subresources: subresource_names
            ).merge("source_path" => "schema/kubernetes/v1.36.2/discovery/aggregated_v2.json")

            Array(entry.fetch("subresources", [])).each do |subresource|
              response_kind = subresource.fetch("responseKind", {})
              sub_group = response_kind.fetch("group", "").to_s
              sub_group = group if sub_group.empty?
              sub_version = response_kind.fetch("version", "").to_s
              sub_version = version if sub_version.empty?
              sub = {
                "name" => "#{parent_name}/#{subresource.fetch("subresource")}",
                "kind" => response_kind.fetch("kind", parent_kind),
                "namespaced" => parent["namespaced"],
                "singularName" => "",
                "verbs" => subresource.fetch("verbs", []),
                "shortNames" => [],
                "categories" => []
              }
              rows << discovery_surface_fields(
                sub,
                group: sub_group,
                version: sub_version,
                subresources: []
              ).merge("source_path" => "schema/kubernetes/v1.36.2/discovery/aggregated_v2.json")
            end
          end
        end
      end
    end

    # The same GVR can occur in legacy and aggregated representations.  Keep
    # the legacy row first because that is the endpoint-specific
    # APIResourceList contract, while the aggregate adds the three
    # cross-group Scale identities missing from those legacy fixtures.
    rows.each_with_object({}) do |row, unique|
      unique[surface_identifier(row)] ||= row
    end.values.sort_by { |row| surface_identifier(row) }
  end

  def schema_contract_present?(schema_name, type_index:)
    return false unless schema_name.is_a?(String) && !schema_name.empty?

    type = type_index[schema_name]
    return false unless type.is_a?(Hash)

    # Keep this helper truthful when called by a focused corpus test without
    # first constructing the API server.  The probe and the server both load
    # this exact generated Definitions file; no metadata-only registry flag is
    # sufficient evidence of a production SchemaContract.
    require File.join(ROOT, "generated/ruby/kubernetes_types") unless defined?(Rubernetes::Generated)

    constant_name = type["ruby_constant"]
    return false unless constant_name.is_a?(String) && !constant_name.empty?

    generated = Rubernetes::Generated.const_get(constant_name, false)
    definition = generated.const_get(:DEFINITION, false)
    definition.respond_to?(:validator) && definition.respond_to?(:defaulting)
  rescue NameError, TypeError
    false
  end

  # Build the production registry view, including subresources.  The API
  # server is already constructed from these same Definition objects by
  # #build_api_server; this explicit boolean is retained in evidence so a
  # registry entry cannot silently pass by carrying only a metadata schema
  # name.
  def runtime_surface_entries(registry_document)
    type_index = Array(registry_document.fetch("types")).to_h { |entry| [entry.fetch("schema"), entry] }
    rows = []
    Array(registry_document.fetch("resources")).each do |entry|
      parent_fields = {
        "group" => entry.fetch("group", "").to_s,
        "version" => entry.fetch("version").to_s,
        "resource" => entry.fetch("resource").to_s,
        "kind" => entry.fetch("kind").to_s,
        "scope" => entry.fetch("scope", "Cluster").to_s,
        "plural" => entry.fetch("resource").to_s,
        "singular" => entry.fetch("singular", "").to_s,
        "verbs" => Array(entry.fetch("verbs", [])).map(&:to_s).sort,
        "subresources" => Array(entry.fetch("subresources", [])).filter_map { |sub| sub["resource"] || sub[:resource] }.map(&:to_s).sort,
        "shortNames" => Array(entry.fetch("short_names", [])).map(&:to_s).sort,
        "categories" => Array(entry.fetch("categories", [])).map(&:to_s).sort,
        "listKind" => begin
          verbs = Array(entry.fetch("verbs", [])).map(&:to_s)
          configured = entry["list_kind"]
          if configured.nil?
            verbs.include?("list") ? "#{entry.fetch("kind")}List" : ""
          else
            configured.to_s
          end
        end,
        "schema_contract_present" => schema_contract_present?(entry["schema"], type_index: type_index),
        "schema" => entry["schema"]
      }
      rows << parent_fields

      Array(entry.fetch("subresources", [])).each do |subresource|
        name = (subresource["resource"] || subresource[:resource]).to_s
        verbs = subresource.key?("verbs") ? subresource["verbs"] : subresource[:verbs]
        rows << parent_fields.merge(
          "resource" => "#{entry.fetch("resource")}/#{name}",
          "kind" => (subresource["kind"] || subresource[:kind] || entry.fetch("kind")).to_s,
          "verbs" => Array(verbs || []).map(&:to_s).sort,
          "singular" => "",
          "subresources" => [],
          "shortNames" => [],
          "categories" => [],
          "listKind" => "",
          "schema" => entry["schema"]
        )
      end
    end

    # Registry GVRs retain the served group/version of cross-group
    # subresources (apps/v1/.../scale is also served as
    # autoscaling/v1/.../scale).  Resource metadata intentionally stores the
    # parent group, so materialize any alternate GVR identity from the
    # authoritative registry inventory before producing the matrix.
    by_id = rows.to_h { |row| [surface_identifier(row), row] }
    Array(registry_document.fetch("gvrs", [])).each do |gvr|
      group = gvr.fetch("group", "").to_s
      version = gvr.fetch("version").to_s
      resource = gvr.fetch("resource").to_s
      id = identifier(group, version, resource)
      next if by_id.key?(id)

      candidate = rows.find do |row|
        row.fetch("version") == version && row.fetch("resource") == resource
      end
      next unless candidate

      alternate = candidate.merge("group" => group, "version" => version)
      by_id[id] = alternate
      rows << alternate
    end
    by_id.values.sort_by { |row| surface_identifier(row) }
  end

  def surface_identifier(fields)
    identifier(fields.fetch("group", ""), fields.fetch("version"), fields.fetch("resource"))
  end

  def gvk_identifier(entry)
    identifier(entry.fetch("group", ""), entry.fetch("version"), entry.fetch("kind"))
  end

  def identifier(group, version, name)
    "#{group.to_s.empty? ? "core" : group}/#{version}/#{name}"
  end
end
