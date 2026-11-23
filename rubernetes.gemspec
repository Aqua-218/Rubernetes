# frozen_string_literal: true

require_relative "lib/rubernetes/version"

Gem::Specification.new do |spec|
  spec.name = "rubernetes"
  spec.version = Rubernetes::VERSION
  spec.authors = ["Aqua-218"]
  spec.summary = "A Ruby-first Kubernetes-compatible container orchestrator"
  spec.description = "Independent Ruby-first implementation of the Kubernetes v1.36.2 observable contract."
  spec.homepage = "https://github.com/Aqua-218"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.4.0"
  defaults = "schema/kubernetes/v1.36.2-defaults"
  package_paths = [
    "config/**/*",
    "exe/*",
    "ext/rubernetes_linux/**/*.{c,h,rb}",
    "generated/platform/linux/abi/*.json",
    "generated/ruby/**/*",
    "generated/rbs/**/*",
    "generated/openapi/**/*",
    "generated/schema/**/*",
    "schema/kubernetes/v1.36.2/protobuf/**/*.proto",
    "#{defaults}/{admission-plugins,api-lifecycle,cel_declarations,cel_type_definitions,features,internal_pod_spec_layout,metrics,zero_objects}.json",
    "#{defaults}/bootstrap/{clusterrolebindings,clusterroles,discovery-default,flowschemas,namespaces,prioritylevelconfigurations,rolebindings,roles}.json",
    "third_party/locks/m7-microvm-artifacts.json",
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
  source_root = File.realpath(__dir__)
  source_prefix = "#{source_root}/"
  package_files = package_paths.flat_map { |pattern| Dir[File.join(source_root, pattern)] }
  spec.files = package_files.select do |path|
    File.file?(path) && File.realpath(path).start_with?(source_prefix)
  end.map { |path| path.delete_prefix(source_prefix) }.sort
  spec.bindir = "exe"
  spec.extensions = ["ext/rubernetes_linux/extconf.rb"]
  spec.executables = %w[
    rubectl
    rubernetes-apiserver
    rubernetes-controller-manager
    rubernetes-scheduler
    rubernetes-agent
    rubernetes-proxy
  ]
  spec.require_paths = ["lib"]
  spec.add_dependency "base64", "~> 0.2"
  spec.add_dependency "csv", "~> 3.3"
  spec.add_dependency "fiddle", "~> 1.1", ">= 1.1.0"
  spec.add_dependency "rexml", "~> 3.4"
  spec.add_dependency "tzinfo", "~> 2.0"
  spec.metadata["rubygems_mfa_required"] = "true"
end
