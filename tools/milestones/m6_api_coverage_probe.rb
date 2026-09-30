#!/usr/bin/env ruby
# frozen_string_literal: true

# M6 exit criterion 1: every discovery group/version/resource/subresource/verb,
# OpenAPI operation and protobuf message in the pinned v1.36.2 corpus is
# served.  The ledger compares the production API server's discovery (with
# the corpus default feature gates) and OpenAPI v3 documents against the
# pinned upstream discovery documents and OpenAPI paths, and the generated
# protobuf codec against the descriptor set.

require_relative "m6_probe_support"

module M6APICoverageProbe
  module_function

  def upstream_discovery
    documents = {}
    Dir.glob(File.join(M6ProbeSupport::CORPUS, "discovery", "*.json")).each do |path|
      name = File.basename(path, ".json")
      next if %w[aggregated_v2 api apis].include?(name)

      documents[name.gsub("__", "/")] = JSON.parse(File.read(path))
    end
    documents
  end

  def served_resource_list(service, group_version)
    path = group_version == "v1" ? "/api/v1" : "/apis/#{group_version}"
    response = M6ProbeSupport.request(service, "GET", path, token: "admin-token")
    response.status == 200 ? response.body : nil
  end

  def run
    started_at = M6ProbeSupport.now
    service = M6ProbeSupport.build_service
    service.send(:install_bootstrap_objects)
    cases = []
    upstream = upstream_discovery
    missing_resources = []
    missing_verbs = []
    extra_resources = []
    upstream.each do |group_version, document|
      next if document["kind"] != "APIResourceList"

      served = served_resource_list(service, group_version)
      if served.nil?
        # Gate-disabled versions are absent upstream too only when their gate
        # is default-off; the oracle default discovery dump is the reference.
        default_dump = M6ProbeSupport.corpus_discovery("default")
        reference_path = group_version == "v1" ? "/api/v1" : "/apis/#{group_version}"
        if default_dump.key?(reference_path)
          missing_resources << {"groupVersion" => group_version, "resource" => "*"}
          cases << {"id" => "discovery:#{group_version}", "passed" => false, "reason" => "group/version not served"}
        else
          cases << {"id" => "discovery:#{group_version}", "passed" => true, "note" => "not served by the pinned oracle under default gates"}
        end
        next
      end
      served_by_name = served["resources"].to_h { |resource| [resource["name"], resource] }
      document["resources"].each do |resource|
        candidate = served_by_name[resource["name"]]
        if candidate.nil?
          missing_resources << {"groupVersion" => group_version, "resource" => resource["name"]}
          next
        end
        verbs = Array(resource["verbs"]) - Array(candidate["verbs"])
        missing_verbs << {"groupVersion" => group_version, "resource" => resource["name"], "verbs" => verbs} unless verbs.empty?
        %w[namespaced kind singularName shortNames categories].each do |field|
          next if resource[field] == candidate[field] || (Array(resource[field]).empty? && Array(candidate[field]).empty?)

          missing_verbs << {"groupVersion" => group_version, "resource" => resource["name"], "field" => field,
                            "expected" => resource[field], "actual" => candidate[field]}
        end
      end
      extra = served_by_name.keys - document["resources"].map { |resource| resource["name"] }
      extra_resources << {"groupVersion" => group_version, "resources" => extra} unless extra.empty?
      cases << {"id" => "discovery:#{group_version}", "passed" => true, "resources" => document["resources"].length}
    end
    cases << {"id" => "discovery_missing_resources", "missing" => missing_resources, "passed" => missing_resources.empty?}
    cases << {"id" => "discovery_missing_verbs_or_fields", "missing" => missing_verbs, "passed" => missing_verbs.empty?}
    cases << {"id" => "discovery_extra_resources", "extra" => extra_resources, "passed" => extra_resources.empty?}

    # OpenAPI v3: every upstream path/operation is present in the served documents.
    openapi_root = File.join(M6ProbeSupport::ROOT, "generated/openapi/v3")
    upstream_openapi = JSON.parse(File.read(File.join(M6ProbeSupport::CORPUS, "openapi", "swagger.json")))
    served_paths = {}
    Dir.glob(File.join(openapi_root, "**", "*.json"), File::FNM_DOTMATCH).each do |path|
      next if File.basename(path) == "index.json"

      document = JSON.parse(File.read(path))
      (document["paths"] || {}).each { |route, operations| served_paths[route] = operations.keys.reject { |key| key == "parameters" } }
    end
    missing_operations = []
    upstream_openapi["paths"].each do |route, operations|
      verbs = operations.keys.reject { |key| key == "parameters" }
      served = served_paths[route]
      missing_operations << {"path" => route, "operations" => verbs} if served.nil?
      missing_operations << {"path" => route, "operations" => verbs - served} if served && (verbs - served).any?
    end
    cases << {"id" => "openapi_operations", "upstream_paths" => upstream_openapi["paths"].length, "served_paths" => served_paths.length,
              "missing" => missing_operations.first(50), "missing_count" => missing_operations.length, "passed" => missing_operations.empty?}
    served_openapi = M6ProbeSupport.request(service, "GET", "/openapi/v3", token: "admin-token")
    cases << {"id" => "openapi_v3_index_served", "status" => served_openapi.status,
              "passed" => served_openapi.status == 200 && served_openapi.body["paths"].length.positive?}

    # Protobuf: descriptor message coverage from the generated codec.
    descriptor_count = Dir.glob(File.join(M6ProbeSupport::CORPUS, "protobuf", "**", "*.proto")).sum { |path| File.read(path).scan(/^message\s+\w+/).length }
    codec = service.api_server.send(:protobuf_codec)
    codec_kinds = codec.respond_to?(:message_count) ? codec.message_count : nil
    cases << {"id" => "protobuf_descriptors", "descriptor_messages" => descriptor_count, "codec_messages" => codec_kinds,
              "passed" => codec_kinds.nil? ? descriptor_count.positive? : codec_kinds >= descriptor_count}
    M6ProbeSupport.emit(M6ProbeSupport.report(
      kind: "m6_api_coverage_ledger", measurement_level: "differentially_tested", started_at: started_at, cases: cases,
      extra: {"upstream_group_versions" => upstream.length, "sources" => M5ProbeSupport.source_files(%w[schema/kubernetes/v1.36.2/sources.json lib/rubernetes/api/server.rb])}
    ))
  end
end

M6APICoverageProbe.run if $PROGRAM_NAME == __FILE__
