# frozen_string_literal: true

require "json"
require "fileutils"
require "open3"
require "rbconfig"
require "rubygems/package"
require "rubygems/request_set"
require "tmpdir"
require_relative "../test_helper"

class M1GemContentsTest < Minitest::Test
  class CachedGems < Gem::Resolver::CurrentSet
    def find_all(request)
      super.select { |candidate| File.file?(candidate.cache_file) }
    end
  end

  ROOT = File.expand_path("../..", __dir__)
  GEMSPEC = File.join(ROOT, "rubernetes.gemspec")
  GENERATED_PATTERNS = %w[
    generated/ruby/**/*
    generated/rbs/**/*
    generated/openapi/**/*
    generated/schema/**/*
  ].freeze
  GENERATED_ROOTS = %w[generated/ruby/ generated/rbs/ generated/openapi/ generated/schema/].freeze
  DEFAULTS_ROOT = "schema/kubernetes/v1.36.2-defaults"
  RUNTIME_CORPUS = [
    *%w[admission-plugins api-lifecycle cel_declarations cel_type_definitions features internal_pod_spec_layout metrics zero_objects]
      .map { |name| "#{DEFAULTS_ROOT}/#{name}.json" },
    *%w[clusterrolebindings clusterroles discovery-default flowschemas namespaces prioritylevelconfigurations rolebindings roles]
      .map { |name| "#{DEFAULTS_ROOT}/bootstrap/#{name}.json" }
  ].freeze
  PROTOBUF_PATTERN = "schema/kubernetes/v1.36.2/protobuf/**/*.proto"
  MICROVM_LOCK = "third_party/locks/m7-microvm-artifacts.json"
  REQUIRED_FILES = %w[
    LICENSE
    NOTICE
    README.md
    spec.md
    config/defaults/m0.yml
    config/defaults/m1.yml
    lib/rubernetes.rb
    sig/rubernetes.rbs
    exe/rubectl
    ext/rubernetes_linux/extconf.rb
    ext/rubernetes_linux/rubernetes_linux.c
    tools/milestones/m0_source_inventory.rb
    tools/milestones/m1_probe_support.rb
    tools/milestones/report_output.rb
  ].freeze

  def test_gem_archive_contains_only_the_production_file_inventory
    Dir.mktmpdir("rubernetes-m1-gem-") do |directory|
      gem_path = build_gem(directory)
      archive_files = package_contents(gem_path)

      expected_files = source_package_files

      assert_equal(expected_files, archive_files, "gem archive must match the explicit production allowlist")
      (REQUIRED_FILES + RUNTIME_CORPUS + [MICROVM_LOCK]).each { |path| assert_includes(archive_files, path) }

      archive_files.each do |path|
        refute_match(%r{\A(?:test|artifacts|build|oracle|protobuf|verification)/}, path)
        refute_match(%r{\Aschema/kubernetes/v1\.36\.2/(?:discovery|openapi)(?:/|\z)}, path)
        refute_match(%r{\Agenerated/(?:fixtures|protobuf)(?:/|\z)}, path)
      end
      refute_includes(archive_files, "generated/manifest.json")
      refute_includes(archive_files, "generated/README.md")
      refute_includes(archive_files, "tools/milestones/m0_kernel_probe.rb")
      refute_includes(archive_files, "tools/milestones/m1_kubernetes_oracle.rb")

      generated_files = source_generated_files

      assert_equal(generated_files, archive_files.select { |path| generated_path?(path) })
      assert_equal([MICROVM_LOCK], archive_files.grep(%r{\Athird_party/}))
      assert_equal((RUNTIME_CORPUS + source_files([PROTOBUF_PATTERN])).sort, archive_files.grep(%r{\Aschema/}))
    end
  end

  def test_built_gem_loads_from_a_clean_gem_home_and_uses_packaged_schema_paths
    Dir.mktmpdir("rubernetes-m1-gem-") do |directory|
      gem_path = build_gem(directory)
      gem_home = File.join(directory, "gem-home")
      FileUtils.mkdir_p(gem_home)
      install_runtime_dependencies(gem_home)
      install_gem(gem_path, gem_home)

      stdout, stderr, status = Open3.capture3(
        clean_gem_environment(gem_home),
        RbConfig.ruby,
        "-e",
        clean_load_script,
        chdir: directory
      )

      assert_predicate(status, :success?, stderr)
      assert_empty(stderr)
      result = JSON.parse(stdout)

      assert_equal("rubernetes", result.fetch("name"))
      assert_equal(false, result.fetch("source_tree_used"))
      assert_equal(%w[M0Gate M1Gate M2Gate M3Gate M4Gate], result.fetch("gates"))

      generated_files = source_generated_files
      if generated_files.empty?
        assert_equal([], result.fetch("generated_files"))
        assert_equal(false, result.fetch("generated_schema_present"))
      else
        GENERATED_ROOTS.each do |root|
          assert(generated_files.any? { |path| path.start_with?(root) }, "generated output is missing #{root}")
        end
        assert_equal(generated_files, result.fetch("generated_files"))
        assert_equal(true, result.fetch("generated_schema_present"))
        assert_equal(true, result.fetch("registry_valid"))
        assert_equal(true, result.fetch("openapi_valid"))
        assert_equal(true, result.fetch("generated_ruby_loaded"))
        assert_equal([422, 201, 200, 200], result.fetch("packaged_api").fetch("statuses"))
        assert_equal("spec.topologySpreadConstraints[0][0]", result.fetch("packaged_api").fetch("invalid_field"))
        assert_equal("blue", result.fetch("packaged_api").fetch("patched_label"))
        assert_equal("packaged-ok", result.fetch("packaged_api").fetch("protobuf_pod"))
        assert_equal(true, result.fetch("packaged_api").fetch("default_gate"))
        assert_equal(true, result.fetch("packaged_api").fetch("bootstrap_rbac"))
        assert_equal(true, result.fetch("packaged_api").fetch("protobuf_readable"))
      end

      assert_equal(true, result.fetch("native_extension_loaded"))
      assert_equal(true, result.fetch("microvm_lock_loaded"))
    end
  end

  private

  def build_gem(directory)
    gem_path = File.join(directory, "rubernetes.gem")
    stdout, stderr, status = Open3.capture3(
      "gem",
      "build",
      GEMSPEC,
      "--output",
      gem_path,
      chdir: ROOT
    )

    assert_predicate(status, :success?, "gem build failed: #{stdout}\n#{stderr}")
    assert_path_exists(gem_path)
    gem_path
  end

  def install_gem(gem_path, gem_home)
    stdout, stderr, status = Open3.capture3(
      clean_gem_environment(gem_home),
      "gem",
      "install",
      "--local",
      gem_path,
      "--install-dir",
      gem_home,
      "--ignore-dependencies",
      "--no-document",
      chdir: ROOT
    )

    assert_predicate(status, :success?, "gem install failed: #{stdout}\n#{stderr}")
  end

  def runtime_dependencies
    specification = Gem::Specification.load(GEMSPEC)

    refute_nil(specification, "rubernetes.gemspec must load")
    dependencies = specification.runtime_dependencies

    refute_empty(dependencies, "the gemspec must declare its runtime dependencies")
    dependencies
  end

  def install_runtime_dependencies(gem_home)
    # Resolve the entire dependency graph together and only use local archives.
    # A dependency of a runtime gem must also be present in the clean GEM_HOME.
    request_set = Gem::RequestSet.new(*runtime_dependencies)
    request_set.resolve(CachedGems.new)
    request_set.sorted_requests.each { |request| install_gem(request.full_spec.cache_file, gem_home) }
  end

  def clean_gem_environment(gem_home)
    {
      "GEM_HOME" => gem_home,
      "GEM_PATH" => gem_home,
      "RUBERNETES_SOURCE_ROOT" => ROOT,
      "RUBYLIB" => nil,
      "RUBYOPT" => nil,
      "BUNDLE_GEMFILE" => nil,
      "BUNDLE_BIN_PATH" => nil,
      "BUNDLE_APP_CONFIG" => nil,
      "BUNDLE_WITH" => nil,
      "BUNDLE_WITHOUT" => nil,
      "BUNDLER_SETUP" => nil,
      "BUNDLER_VERSION" => nil,
      "BUNDLER_ORIG_BUNDLE_BIN_PATH" => nil,
      "BUNDLER_ORIG_BUNDLE_GEMFILE" => nil,
      "BUNDLER_ORIG_GEM_HOME" => nil,
      "BUNDLER_ORIG_GEM_PATH" => nil,
      "BUNDLER_ORIG_PATH" => nil,
      "BUNDLER_ORIG_RUBYLIB" => nil,
      "BUNDLER_ORIG_RUBYOPT" => nil
    }
  end

  def package_contents(gem_path)
    Gem::Package.new(gem_path).contents.sort
  end

  def source_package_files
    patterns = [
      "config/**/*",
      "exe/*",
      "ext/rubernetes_linux/**/*.{c,h,rb}",
      "generated/platform/linux/abi/*.json",
      *GENERATED_PATTERNS,
      *RUNTIME_CORPUS,
      PROTOBUF_PATTERN,
      MICROVM_LOCK,
      "lib/**/*.rb",
      "tools/milestones/m0_gate.rb",
      "tools/milestones/m0_source_inventory.rb",
      "tools/milestones/m1_gate.rb",
      "tools/milestones/m1_probe_support.rb",
      "tools/milestones/m2_*.rb",
      "tools/milestones/m3_*.rb",
      "tools/milestones/m4_*.rb",
      "tools/milestones/report_output.rb",
      "sig/**/*.rbs",
      "README.md",
      "LICENSE",
      "NOTICE",
      "spec.md",
      "spec/**/*.md"
    ]
    source_files(patterns)
  end

  def source_generated_files
    source_files(GENERATED_PATTERNS)
  end

  def source_files(patterns)
    Dir.chdir(ROOT) do
      patterns.flat_map { |pattern| Dir[pattern] }
        .select { |path| File.file?(path) }
        .sort
    end
  end

  def generated_path?(path)
    GENERATED_ROOTS.any? { |root| path.start_with?(root) }
  end

  def clean_load_script
    packaged_api_script + <<~'RUBY'
      require "json"
      gem "rubernetes"
      require "rubernetes"
      require "rubernetes_linux"
      require "rubernetes/runtime/microvm/artifacts"
      specification = Gem.loaded_specs.fetch("rubernetes")
      root = specification.full_gem_path
      source = File.expand_path(ENV.fetch("RUBERNETES_SOURCE_ROOT"))
      missing_manifest = File.join(Dir.pwd, "missing-manifest.json")
      gates = (0..4).map do |index|
        require File.join(root, "tools/milestones/m#{index}_gate")
        gate = Object.const_get("M#{index}Gate")
        raise "#{gate} accepted a missing manifest" unless gate.evaluate(missing_manifest).fetch("passed") == false

        gate.name
      end
      generated = Dir[File.join(root, "generated/{ruby,rbs,openapi,schema}/**/*")].select { |path| File.file?(path) }.map { |path| path.delete_prefix("#{root}/") }.sort
      generated_ruby = generated.select { |path| path.start_with?("generated/ruby/") }
      generated_ruby_loaded = generated_ruby.empty?
      generated_ruby.each { |path| require File.join(root, path) }
      generated_ruby_loaded = defined?(Rubernetes::Generated) == "constant" if generated_ruby.any?
      registry_path = File.join(root, "generated/schema/registry.json")
      openapi_path = File.join(root, "generated/openapi/v2.json")
      registry_valid = File.file?(registry_path) && JSON.parse(File.binread(registry_path)).fetch("resources").is_a?(Array)
      openapi_valid = File.file?(openapi_path) && JSON.parse(File.binread(openapi_path)).fetch("definitions").is_a?(Hash)
      api = packaged_api_probe if generated_ruby.any?
      artifacts = Rubernetes::Runtime::MicroVM::Artifacts.load(
        lock_path: File.join(root, Rubernetes::MicroVMArtifactDefaults::LOCK_PATH), root: root
      )
      used_source = File.expand_path(root) == source || $LOADED_FEATURES.any? { |feature| feature.start_with?("#{source}/") }
      extension_loaded = $LOADED_FEATURES.any? do |feature|
        feature.end_with?("/rubernetes_linux.so") && feature.start_with?("#{ENV.fetch("GEM_HOME")}/")
      end
      puts JSON.generate(
        "name" => specification.name,
        "source_tree_used" => used_source,
        "gates" => gates,
        "generated_files" => generated,
        "generated_schema_present" => File.file?(registry_path) && File.file?(openapi_path),
        "registry_valid" => registry_valid,
        "openapi_valid" => openapi_valid,
        "generated_ruby_loaded" => generated_ruby_loaded,
        "packaged_api" => api,
        "native_extension_loaded" => extension_loaded,
        "microvm_lock_loaded" => artifacts.lock.fetch("schema_version") == 1
      )
    RUBY
  end

  def packaged_api_script
    <<~'RUBY'
      def packaged_api_probe
        require "rubernetes/api"
        require "rubernetes/bootstrap/security_assembly"

        api = Rubernetes::API
        schema = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod")
        resource = api::Resource.new(group: "", version: "v1", resource: "pods", kind: "Pod", scope: :namespaced, schema: schema)
        registry = api::Registry.new(resources: [resource], defaults: false)
        server = api::Server.new(registry: registry)
        pods = "/api/v1/namespaces/default/pods"
        constraint = {"maxSkew" => 1, "topologyKey" => "rack", "whenUnsatisfiable" => "DoNotSchedule",
                      "matchLabelKeys" => ["app"], "labelSelector" => {}}
        pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "packaged-ok", "labels" => {"app" => "test"}},
               "spec" => {"containers" => [{"name" => "main", "image" => "busybox"}], "topologySpreadConstraints" => [constraint]}}
        invalid_constraint = constraint.merge("labelSelector" => {"matchLabels" => {"app" => "test"}})
        invalid_pod = pod.merge("spec" => pod.fetch("spec").merge("topologySpreadConstraints" => [invalid_constraint]))
        invalid, created = [invalid_pod, pod].map do |object|
          server.call(method: "POST", path: "#{pods}?fieldValidation=Strict", headers: {"Content-Type" => "application/json"},
                      body: JSON.generate(object))
        end
        path = "#{pods}/packaged-ok"
        patched = server.call(method: "PATCH", path: "#{path}?fieldValidation=Strict",
                              headers: {"Content-Type" => "application/merge-patch+json"},
                              body: {"metadata" => {"labels" => {"release" => "blue"}}})
        codec = Rubernetes::Schema::Codec::KubernetesProtobuf
        protobuf = server.call(method: "GET", path: path, headers: {"Accept" => codec::CONTENT_TYPE})
        decoded = codec.new.decode(protobuf.body)
        assembly = Rubernetes::Bootstrap::SecurityAssembly
        {
          "statuses" => [invalid.status, created.status, patched.status, protobuf.status],
          "invalid_field" => invalid.body.dig("details", "causes", 0, "field"),
          "patched_label" => patched.body.dig("metadata", "labels", "release"),
          "protobuf_pod" => decoded.dig("metadata", "name"),
          "protobuf_readable" => File.stat(File.join(codec::DEFAULT_DESCRIPTOR_ROOT, "k8s.io/api/core/v1/generated.proto")).mode.anybits?(0o004),
          "default_gate" => assembly.default_feature_gates.fetch("MatchLabelKeysInPodTopologySpread"),
          "bootstrap_rbac" => assembly.bootstrap_documents.fetch("clusterroles").any? { |role| role.dig("metadata", "name") == "cluster-admin" }
        }
      end
    RUBY
  end
end
