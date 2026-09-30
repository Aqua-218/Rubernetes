# frozen_string_literal: true

# Regenerate the CSI Ruby protobuf and gRPC stubs from the exact CSI revision
# consumed by Kubernetes v1.36.2.  The source is fetched by immutable commit,
# and its digest is checked before protoc runs so a moving upstream cannot alter
# the generated wire contract silently.
require "digest"
require "fileutils"
require "open3"
require "open-uri"
require "rbconfig"
require "tmpdir"

module CSIStubGenerator
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  CSI_SPEC_VERSION = "1.9.0"
  CSI_SPEC_COMMIT = "80d53107c70981b9da8aaf9cd1c90249562b22f0"
  CSI_PROTO_SHA256 = "0b625eff0484fa61a1ddb06570a71c118e6af3b8f73e4d860f43d477412e4d55"
  CSI_PROTO_URL = "https://raw.githubusercontent.com/container-storage-interface/spec/#{CSI_SPEC_COMMIT}/csi.proto"
  OUTPUT_DIR = File.expand_path("../../lib/rubernetes/volume/generated", __dir__)

  module_function

  def run(output_dir: OUTPUT_DIR)
    FileUtils.mkdir_p(output_dir)
    Dir.mktmpdir("rubernetes-csi-stubs") do |temporary|
      proto_path = File.join(temporary, "csi.proto")
      File.binwrite(proto_path, URI.open(CSI_PROTO_URL, "rb", &:read))
      verify_source!(proto_path)

      generated_dir = File.join(temporary, "generated")
      FileUtils.mkdir_p(generated_dir)
      run_protoc(proto_path, generated_dir)
      write_generated(generated_dir, output_dir, "csi_pb.rb")
      write_generated(generated_dir, output_dir, "csi_services_pb.rb", service_stub: true)
    end
  end

  def verify_source!(path)
    digest = Digest::SHA256.file(path).hexdigest
    return if digest == CSI_PROTO_SHA256

    raise "CSI proto digest mismatch: expected #{CSI_PROTO_SHA256}, got #{digest}"
  end

  def run_protoc(proto_path, generated_dir)
    gem_path = Gem::Specification.find_by_name("grpc-tools").full_gem_path
    platform_dir = File.join(gem_path, "bin", grpc_tools_platform)
    include_dir = File.join(platform_dir)
    unless File.file?(File.join(include_dir, "google/protobuf/descriptor.proto"))
      raise "grpc-tools protobuf include directory is unavailable: #{include_dir}"
    end

    command = [Gem.bin_path("grpc-tools", "grpc_tools_ruby_protoc"), "-I", File.dirname(proto_path),
               "-I", include_dir, "--ruby_out=#{generated_dir}", "--grpc_out=#{generated_dir}", proto_path]
    stdout, stderr, status = Open3.capture3(*command)
    return if status.success?

    detail = [stdout, stderr].reject(&:empty?).join("\n")
    raise "CSI stub generation failed (#{status.exitstatus}): #{detail}"
  end

  def write_generated(generated_dir, output_dir, filename, service_stub: false)
    source = File.binread(File.join(generated_dir, filename))
    source = source.sub("require 'csi_pb'", "require_relative \"csi_pb\"") if service_stub
    header = <<~HEADER
      # Kubernetes source version: #{KUBERNETES_VERSION}
      # Kubernetes source commit: #{KUBERNETES_SOURCE_COMMIT}
      # CSI spec version: #{CSI_SPEC_VERSION}
      # CSI source revision: #{CSI_SPEC_COMMIT}
      # CSI proto SHA-256: #{CSI_PROTO_SHA256}
    HEADER
    File.binwrite(File.join(output_dir, filename), header + source)
  end

  def grpc_tools_platform
    cpu = RbConfig::CONFIG.fetch("host_cpu").downcase
    os = RbConfig::CONFIG.fetch("host_os").downcase
    architecture = case cpu
                   when "x86_64", "amd64" then "x86_64"
                   when "aarch64", "arm64" then "aarch64"
                   else cpu
                   end
    operating_system = if os.include?("linux")
                         "linux"
                       else
                         os.include?("darwin") ? "macos" : "windows"
                       end
    "#{architecture}-#{operating_system}"
  end
end

CSIStubGenerator.run if $PROGRAM_NAME == __FILE__
