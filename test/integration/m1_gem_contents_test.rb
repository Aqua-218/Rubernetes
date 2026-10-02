# frozen_string_literal: true

require "json"
require "fileutils"
require "open3"
require "rbconfig"
require "rubygems/package"
require "tmpdir"
require_relative "../test_helper"

class M1GemContentsTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  GEMSPEC = File.join(ROOT, "rubernetes.gemspec")
  GENERATED_PATTERNS = %w[
    generated/ruby/**/*
    generated/rbs/**/*
    generated/openapi/**/*
    generated/schema/**/*
  ].freeze
  GENERATED_ROOTS = %w[generated/ruby/ generated/rbs/ generated/openapi/ generated/schema/].freeze
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
  ].freeze

  def test_gem_archive_contains_only_the_production_file_inventory
    Dir.mktmpdir("rubernetes-m1-gem-") do |directory|
      gem_path = build_gem(directory)
      archive_files = package_contents(gem_path)

      expected_files = source_package_files

      assert_equal(expected_files, archive_files, "gem archive must match the explicit production allowlist")
      REQUIRED_FILES.each { |path| assert_includes(archive_files, path) }

      archive_files.each do |path|
        refute_match(%r{\A(?:schema|test|artifacts|build|oracle|protobuf|verification)/}, path)
        refute_match(%r{\Athird_party/}, path)
        refute_match(%r{\Aschema/kubernetes/v1\.36\.2/(?:protobuf|discovery|openapi)(?:/|\z)}, path)
        refute_match(%r{\Agenerated/(?:fixtures|protobuf)(?:/|\z)}, path)
      end
      refute_includes(archive_files, "generated/manifest.json")
      refute_includes(archive_files, "generated/README.md")

      generated_files = source_generated_files

      assert_equal(generated_files, archive_files.select { |path| generated_path?(path) })
    end
  end

  def test_built_gem_loads_from_a_clean_gem_home_and_uses_packaged_schema_paths
    Dir.mktmpdir("rubernetes-m1-gem-") do |directory|
      gem_path = build_gem(directory)
      gem_home = File.join(directory, "gem-home")
      FileUtils.mkdir_p(gem_home)
      install_gem(gem_path, gem_home)
      # Derived from the gemspec, never hardcoded: a runtime dependency added
      # to the gemspec but forgotten here would leave the clean-gem-home load
      # untested for that gem.
      runtime_dependencies.each do |dependency|
        install_runtime_dependency(dependency.name, dependency.requirement.as_list, gem_home)
      end

      stdout, stderr, status = Open3.capture3(
        clean_gem_environment(gem_home),
        RbConfig.ruby,
        "-e",
        clean_load_script,
        chdir: ROOT
      )

      assert_predicate(status, :success?, stderr)
      assert_empty(stderr)
      result = JSON.parse(stdout)

      assert_equal("rubernetes", result.fetch("name"))
      assert_equal(false, result.fetch("source_tree_used"))

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
      end
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

  def install_runtime_dependency(name, requirements, gem_home)
    requirement = Gem::Requirement.new(requirements)
    specification = Gem::Specification.find_all_by_name(name).find do |candidate|
      requirement.satisfied_by?(candidate.version) && File.file?(candidate.cache_file)
    end

    refute_nil(specification, "a cached #{name} gem satisfying #{requirements.join(", ")} is required")
    stdout, stderr, status = Open3.capture3(
      clean_gem_environment(gem_home),
      "gem",
      "install",
      "--local",
      specification.cache_file,
      "--install-dir",
      gem_home,
      "--ignore-dependencies",
      "--no-document",
      chdir: ROOT
    )

    assert_predicate(status, :success?, "#{name} install failed: #{stdout}\n#{stderr}")
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
      "lib/**/*.rb",
      "tools/milestones/m0_gate.rb",
      "tools/milestones/m1_gate.rb",
      "tools/milestones/m2_*.rb",
      "tools/milestones/m3_*.rb",
      "tools/milestones/m4_*.rb",
      "sig/**/*.rbs",
      "README.md",
      "LICENSE",
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
    <<~'RUBY'
      require "json"
      gem "rubernetes"
      require "rubernetes"
      specification = Gem.loaded_specs.fetch("rubernetes")
      root = specification.full_gem_path
      source_tree = File.expand_path(root) == File.expand_path(ENV.fetch("RUBERNETES_SOURCE_ROOT"))
      generated = Dir[File.join(root, "generated/{ruby,rbs,openapi,schema}/**/*")].select { |path| File.file?(path) }.map { |path| path.delete_prefix("#{root}/") }.sort
      generated_ruby = generated.select { |path| path.start_with?("generated/ruby/") }
      generated_ruby_loaded = generated_ruby.empty?
      generated_ruby.each { |path| load File.join(root, path) }
      generated_ruby_loaded = defined?(Rubernetes::Generated) == "constant" if generated_ruby.any?
      registry_path = File.join(root, "generated/schema/registry.json")
      openapi_path = File.join(root, "generated/openapi/v2.json")
      registry_valid = File.file?(registry_path) && JSON.parse(File.binread(registry_path)).fetch("resources").is_a?(Array)
      openapi_valid = File.file?(openapi_path) && JSON.parse(File.binread(openapi_path)).fetch("definitions").is_a?(Hash)
      puts JSON.generate(
        "name" => specification.name,
        "source_tree_used" => source_tree,
        "generated_files" => generated,
        "generated_schema_present" => File.file?(registry_path) && File.file?(openapi_path),
        "registry_valid" => registry_valid,
        "openapi_valid" => openapi_valid,
        "generated_ruby_loaded" => generated_ruby_loaded
      )
    RUBY
  end
end
