# frozen_string_literal: true

# Regenerate the Ruby protobuf and gRPC stubs for the kubelet plugin APIs
# (plugin registration, device plugins, DRA and DRA resource health) and the
# CRI (runtime.v1, for the CRI runtime backend) from the pinned Kubernetes
# v1.36.2 source tree.  Each .proto is checked against the
# digest recorded here before protoc runs, so a different checkout cannot
# change the wire contract silently.
#
#   KUBERNETES_SOURCE_ROOT=/tmp/kubernetes-v1.36.2 bundle exec ruby tools/node/generate_kubelet_plugin_stubs.rb
#
# The only transformation applied to a proto is an added `ruby_package`
# option, so the generated Ruby constants live under Rubernetes::Node::Plugins
# instead of top-level modules such as ::V1beta1.  `package` (and therefore
# every gRPC service and message full name on the wire) is untouched.
require "digest"
require "fileutils"
require "open3"
require "rbconfig"
require "tmpdir"

module KubeletPluginStubGenerator
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  API_ROOT = "staging/src/k8s.io/kubelet/pkg/apis"
  OUTPUT_DIR = File.expand_path("../../lib/rubernetes/node/plugins/generated", __dir__)

  PROTOS = [
    {path: "pluginregistration/v1/api.proto", name: "pluginregistration_v1",
     sha256: "7a67a0000a1a167c155286834bc9ccb489f8bcdb394e006daba270189c272afa",
     ruby_package: "Rubernetes::Node::Plugins::Generated::PluginRegistrationV1"},
    {path: "deviceplugin/v1beta1/api.proto", name: "deviceplugin_v1beta1",
     sha256: "b780bfeac99c93c231dc165ce417f4da88481eececa0c65eeb90f5f2e9b5b65b",
     ruby_package: "Rubernetes::Node::Plugins::Generated::DevicePluginV1beta1"},
    {path: "dra/v1/api.proto", name: "dra_v1",
     sha256: "b3066ad7f6abcfd0003c47b06ceb801d76997d78d6be505597478d3905b9cc57",
     ruby_package: "Rubernetes::Node::Plugins::Generated::DRAV1"},
    # Drivers still built against the v1beta1 service (supported_versions
    # ["v1beta1.DRAPlugin"]); same messages, no share_id.
    {path: "dra/v1beta1/api.proto", name: "dra_v1beta1",
     sha256: "7900b11793ad897d0375d67b3bbae675869b574e21dfb1bf5334cc1556138c42",
     ruby_package: "Rubernetes::Node::Plugins::Generated::DRAV1beta1"},
    {path: "dra-health/v1alpha1/api.proto", name: "dra_health_v1alpha1",
     sha256: "75f8c523ec546ceb83bd63f3b7a38c23d979494e7015db12d146e2f39dd4528e",
     ruby_package: "Rubernetes::Node::Plugins::Generated::DRAHealthV1alpha1"},
    # The kubelet's own pod resources API (monitoring agents read it).
    {path: "podresources/v1/api.proto", name: "podresources_v1",
     sha256: "f65bc77eb41334effc87fdd8c234bdcdbf01a64122010dca50a6fecfaed9390c",
     ruby_package: "Rubernetes::Node::Plugins::Generated::PodResourcesV1"},
    {root: "staging/src/k8s.io/cri-api/pkg/apis", path: "runtime/v1/api.proto", name: "cri_runtime_v1",
     sha256: "6d130c2651d335bfc755d25efc63072a1cd1eba3591ead6422dc0a27f20167f3",
     ruby_package: "Rubernetes::Runtime::CRI::Generated::RuntimeV1",
     output_dir: File.expand_path("../../lib/rubernetes/runtime/cri/generated", __dir__)}
  ].freeze

  module_function

  def run(source_root: ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2"), output_dir: OUTPUT_DIR,
          only: ENV["ONLY"]&.split(","))
    Dir.mktmpdir("rubernetes-kubelet-plugin-stubs") do |temporary|
      PROTOS.each do |proto|
        next if only && !only.include?(proto.fetch(:name))

        target_dir = proto.fetch(:output_dir, output_dir)
        FileUtils.mkdir_p(target_dir)
        api_root = proto.fetch(:root, API_ROOT)
        source = File.join(source_root, api_root, proto.fetch(:path))
        digest = Digest::SHA256.file(source).hexdigest
        raise "#{proto.fetch(:path)} digest mismatch: expected #{proto.fetch(:sha256)}, got #{digest}" unless digest == proto.fetch(:sha256)

        input_dir = File.join(temporary, proto.fetch(:name))
        FileUtils.mkdir_p(input_dir)
        input = File.join(input_dir, "#{proto.fetch(:name)}.proto")
        File.binwrite(input, with_ruby_package(File.binread(source), proto.fetch(:ruby_package)))
        generated_dir = File.join(temporary, "out-#{proto.fetch(:name)}")
        FileUtils.mkdir_p(generated_dir)
        run_protoc(input, generated_dir)
        header = <<~HEADER
          # Kubernetes source version: #{KUBERNETES_VERSION}
          # Kubernetes source commit: #{KUBERNETES_SOURCE_COMMIT}
          # Proto: #{api_root}/#{proto.fetch(:path)}
          # Proto SHA-256: #{proto.fetch(:sha256)}
          # Transformation: added option ruby_package = "#{proto.fetch(:ruby_package)}"
        HEADER
        message_file = "#{proto.fetch(:name)}_pb.rb"
        service_file = "#{proto.fetch(:name)}_services_pb.rb"
        File.binwrite(File.join(target_dir, message_file), header + File.binread(File.join(generated_dir, message_file)))
        service = File.binread(File.join(generated_dir, service_file))
          .sub("require '#{proto.fetch(:name)}_pb'", "require_relative \"#{proto.fetch(:name)}_pb\"")
        File.binwrite(File.join(target_dir, service_file), header + service)
      end
    end
  end

  def with_ruby_package(source, ruby_package)
    lines = source.lines
    index = lines.index { |line| line.start_with?("package ") } or raise "proto has no package statement"
    lines.insert(index + 1, "option ruby_package = \"#{ruby_package}\";\n")
    lines.join
  end

  def run_protoc(proto_path, generated_dir)
    gem_path = Gem::Specification.find_by_name("grpc-tools").full_gem_path
    include_dir = File.join(gem_path, "bin", grpc_tools_platform)
    raise "grpc-tools protobuf include directory is unavailable: #{include_dir}" unless File.file?(File.join(include_dir, "google/protobuf/descriptor.proto"))

    command = [Gem.bin_path("grpc-tools", "grpc_tools_ruby_protoc"), "-I", File.dirname(proto_path),
               "-I", include_dir, "--ruby_out=#{generated_dir}", "--grpc_out=#{generated_dir}", proto_path]
    stdout, stderr, status = Open3.capture3(*command)
    return if status.success?

    raise "protoc failed for #{proto_path} (#{status.exitstatus}): #{[stdout, stderr].reject(&:empty?).join("\n")}"
  end

  def grpc_tools_platform
    cpu = RbConfig::CONFIG.fetch("host_cpu").downcase
    os = RbConfig::CONFIG.fetch("host_os").downcase
    architecture = case cpu
                   when /x86_64|amd64/ then "x86_64"
                   when /aarch64|arm64/ then "aarch64"
                   else raise "unsupported grpc-tools CPU: #{cpu}"
                   end
    system = os.include?("linux") ? "linux" : raise("unsupported grpc-tools OS: #{os}")
    "#{architecture}-#{system}"
  end
end

KubeletPluginStubGenerator.run if $PROGRAM_NAME == __FILE__
