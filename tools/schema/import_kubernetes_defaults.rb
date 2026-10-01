#!/usr/bin/env ruby
# frozen_string_literal: true

# Import the v1.36.2 feature-gate table, admission plugin order/default sets,
# and authorization modes from the pinned Kubernetes source checkout into
# schema/kubernetes/v1.36.2-defaults/{features.json,admission-plugins.json,authorization-modes.json}.
# The directory is separate from the M1 schema corpus so the strict M1
# inventory check (tools/schema/import_kubernetes.rb) stays unchanged.  The Go
# tables are parsed structurally (regular expressions over the fixed
# upstream layout) and every source file is pinned by SHA-256 so a
# regeneration from a different commit is detectable.
#
# Usage: KUBERNETES_SOURCE_ROOT=/path/to/kubernetes-v1.36.2 ruby tools/schema/import_kubernetes_defaults.rb

require "digest"
require "json"

module KubernetesDefaultsImporter
  ROOT = File.expand_path("../..", __dir__)
  OUTPUT_ROOT = File.join(ROOT, "schema/kubernetes/v1.36.2-defaults")
  EXPECTED_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  TARGET_VERSION = [1, 36].freeze

  FEATURE_FILES = {
    "kubernetes" => "pkg/features/kube_features.go",
    "apiserver" => "staging/src/k8s.io/apiserver/pkg/features/kube_features.go",
    "client-go" => "staging/src/k8s.io/client-go/features/known_features.go",
    "component-base-zpages" => "staging/src/k8s.io/component-base/zpages/features/kube_features.go"
  }.freeze
  PLUGINS_FILE = "pkg/kubeapiserver/options/plugins.go"
  MODES_FILE = "pkg/kubeapiserver/authorizer/modes/modes.go"

  module_function

  def source_root
    ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  end

  def read(relative)
    path = File.join(source_root, relative)
    raise "missing #{path}" unless File.file?(path)

    File.read(path)
  end

  def digest(relative)
    Digest::SHA256.hexdigest(read(relative))
  end

  # Parse `Name: {\n {Version: version.MustParse("1.x"), Default: bool, PreRelease: featuregate.X[, LockToDefault: true]}, ...},`
  def parse_versioned_features(text, file_label)
    gates = {}
    body = text[/defaultVersioned\w*FeatureGates\s*=\s*map\[featuregate\.Feature\]featuregate\.VersionedSpecs\{(.*?)\n\}/m, 1]
    body ||= text[/var\s+\w*[Ff]eatureGates\s*=\s*map\[featuregate\.Feature\]featuregate\.VersionedSpecs\{(.*?)\n\}/m, 1]
    # client-go and component-base keep client-side gates in their own
    # registries; they are not part of the API server surface.
    return {} if body.nil?

    body.scan(/^\t([A-Za-z0-9_.]+):\s*\{\n(.*?)\n\t\},/m) do |name, specs|
      # rubocop:disable-next Layout/LineLength -- the pattern reads better whole
      versions = specs.scan(/\{Version:\s*version\.MustParse\("(\d+)\.(\d+)"\),\s*Default:\s*(true|false),\s*PreRelease:\s*featuregate\.(\w+)(?:,\s*LockToDefault:\s*(true|false))?\s*\}/).map do |major, minor, default, prerelease, lock|
        {"version" => "#{major}.#{minor}", "default" => default == "true", "prerelease" => prerelease, "lock_to_default" => lock == "true"}
      end
      raise "feature #{name} in #{file_label} has no versioned specs" if versions.empty?

      gates[name] = versions
    end
    gates
  end

  # Resolve constant names of the form `genericfeatures.Foo` or bare `Foo` to the gate key string.
  def constant_names(text)
    names = {}
    text.scan(/^\t([A-Za-z0-9_]+)\s+featuregate\.Feature\s*=\s*"([^"]+)"/) { |const, value| names[const] = value }
    names
  end

  def effective(versions)
    applicable = versions.select { |spec| (spec_version(spec) <=> TARGET_VERSION) <= 0 }
    applicable.max_by { |spec| spec_version(spec) } || versions.first
  end

  def spec_version(spec)
    spec["version"].split(".").map(&:to_i)
  end

  def import_features
    gates = {}
    sources = {}
    FEATURE_FILES.each do |label, relative|
      next unless File.file?(File.join(source_root, relative))

      text = read(relative)
      sources[label] = {"path" => relative, "sha256" => digest(relative)}
      names = constant_names(text)
      parse_versioned_features(text, label).each do |const, versions|
        key = names.fetch(const.sub(/\A\w+\./, ""), const.sub(/\A\w+\./, ""))
        current = effective(versions)
        gates[key] = {
          "source" => label,
          "default" => current["default"],
          "stage" => current["prerelease"],
          "lock_to_default" => current["lock_to_default"],
          "since" => current["version"],
          "history" => versions
        }
      end
    end
    {"schema_version" => 1, "kubernetes" => {"tag" => "v1.36.2", "commit" => EXPECTED_COMMIT}, "target_version" => "1.36",
     "sources" => sources, "gate_count" => gates.length, "gates" => gates.sort.to_h}
  end

  def import_admission_plugins
    text = read(PLUGINS_FILE)
    ordered = text[/var AllOrderedPlugins = \[\]string\{(.*?)\n\}/m, 1]
    raise "AllOrderedPlugins not found" if ordered.nil?

    order = ordered.scan(%r{^\s*\w+\.PluginName,\s*//\s*([A-Za-z0-9]+)}).flatten
    default_on = text[/defaultOnPlugins := sets\.New\((.*?)\n\t\)/m, 1]
    raise "defaultOnPlugins not found" if default_on.nil?

    # Comments in the default-on list occasionally differ in case from the
    # canonical plugin name; resolve them against the ordered list.
    canonical = order.to_h { |name| [name.downcase, name] }
    on = default_on.scan(%r{//\s*([A-Za-z0-9]+)}).flatten.map do |name|
      canonical.fetch(name.downcase) do
        raise "unknown default-on plugin #{name}"
      end
    end
    # rubocop:disable-next Layout/LineLength -- the pattern reads better whole
    conditional = text.scan(%r{if utilfeature\.DefaultFeatureGate\.Enabled\(\w+\.(\w+)\) \{\n\s*defaultOnPlugins\.Insert\(\w+\.PluginName\) // ([A-Za-z0-9]+)}).map do |gate, plugin|
      {"plugin" => plugin, "feature_gate" => gate}
    end
    {"schema_version" => 1, "kubernetes" => {"tag" => "v1.36.2", "commit" => EXPECTED_COMMIT},
     "source" => {"path" => PLUGINS_FILE, "sha256" => digest(PLUGINS_FILE)},
     "ordered_plugins" => order, "default_on" => on, "default_on_when_gate_enabled" => conditional,
     "default_off" => order - on - conditional.map { |entry| entry["plugin"] }}
  end

  def import_authorization_modes
    text = read(MODES_FILE)
    modes = text.scan(/Mode\w+\s+string\s*=\s*"([A-Za-z]+)"/).flatten
    {"schema_version" => 1, "source" => {"path" => MODES_FILE, "sha256" => digest(MODES_FILE)}, "modes" => modes,
     "default_modes" => %w[Node RBAC]}
  end

  def write(name, document)
    path = File.join(OUTPUT_ROOT, name)
    File.write(path, JSON.pretty_generate(document) << "\n")
    path
  end

  def run
    features = import_features
    plugins = import_admission_plugins
    modes = import_authorization_modes
    write("features.json", features)
    write("admission-plugins.json", plugins)
    write("authorization-modes.json", modes)
    puts "features: #{features["gate_count"]} gates; admission plugins: #{plugins["ordered_plugins"].length} ordered, #{plugins["default_on"].length} " \
         "default on; modes: " \
         "#{modes["modes"].join(",")}"
  end
end

KubernetesDefaultsImporter.run if $PROGRAM_NAME == __FILE__
