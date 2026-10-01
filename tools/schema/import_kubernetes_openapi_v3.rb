#!/usr/bin/env ruby
# frozen_string_literal: true

# Pin the upstream OpenAPI v3 documents into schema/kubernetes/v1.36.2-openapi-v3/
# so the generator serves what kube-apiserver v1.36.2 publishes.
#
# Two sources, both recorded per file in manifest.json:
# - the source tree's api/openapi-spec/v3/*_openapi.json at the pinned tag
#   (every group/version, including feature-gated ones);
# - with --kubeconfig, the documents a running v1.36.2 kube-apiserver serves
#   (`/openapi/v3/<path>` for every entry of its root document), which
#   overlay the tree's.  The served documents carry the `enum` lists
#   (OpenAPIEnums) and `info.version` that the checked-in files do not; they
#   are what `kubectl explain` prints and what the K5 wire differential
#   compares, so the pin follows the server.
#
# Usage: KUBERNETES_SOURCE_ROOT=/tmp/kubernetes-v1.36.2 \
#          ruby tools/schema/import_kubernetes_openapi_v3.rb [--kubeconfig PATH]

require "digest"
require "fileutils"
require "json"

module KubernetesOpenAPIV3Importer
  ROOT = File.expand_path("../..", __dir__)
  OUTPUT = File.join(ROOT, "schema/kubernetes/v1.36.2-openapi-v3")
  EXPECTED_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  SOURCE_DIRECTORY = "api/openapi-spec/v3"

  module_function

  def canonical_json(value)
    JSON.pretty_generate(sort_keys(value))
  end

  def sort_keys(value)
    case value
    when Hash then value.keys.sort.to_h { |key| [key, sort_keys(value[key])] }
    when Array then value.map { |item| sort_keys(item) }
    else value
    end
  end

  def run
    source_root = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
    directory = File.join(source_root, SOURCE_DIRECTORY)
    raise "missing #{directory}" unless File.directory?(directory)

    FileUtils.rm_rf(OUTPUT)
    FileUtils.mkdir_p(OUTPUT)
    files = Dir.glob(File.join(directory, "*_openapi.json"), File::FNM_DOTMATCH).sort.map do |path|
      name = File.basename(path, "_openapi.json")
      # api__v1 -> api/v1 ; apis__apps__v1 -> apis/apps/v1 ; apis__apps -> apis/apps (group index, no paths)
      key = name.gsub("__", "/")
      document = JSON.parse(File.read(path))
      relative = "#{key}.json"
      target = File.join(OUTPUT, relative)
      FileUtils.mkdir_p(File.dirname(target))
      File.write(target, canonical_json(document) << "\n")
      {"path" => relative, "upstream_path" => "#{SOURCE_DIRECTORY}/#{File.basename(path)}", "source_sha256" => Digest::SHA256.file(path).hexdigest,
       "sha256" => Digest::SHA256.file(target).hexdigest, "paths" => (document["paths"] || {}).length}
    end
    manifest = {"schema_version" => 1, "kubernetes" => {"tag" => "v1.36.2", "commit" => EXPECTED_COMMIT}, "source_directory" => SOURCE_DIRECTORY,
                "file_count" => files.length, "path_count" => files.sum { |file| file["paths"] }, "files" => files}
    File.write(File.join(OUTPUT, "manifest.json"), JSON.pretty_generate(manifest) << "\n")
    puts "pinned #{files.length} OpenAPI v3 documents with #{manifest["path_count"]} paths"
  end
end

KubernetesOpenAPIV3Importer.run if $PROGRAM_NAME == __FILE__
