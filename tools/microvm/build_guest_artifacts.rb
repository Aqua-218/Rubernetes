#!/usr/bin/env ruby
# frozen_string_literal: true

# Builds and pins the M7 guest artifacts (spec/node/runtime.md 5.8.11):
#
#   * the read-only guest rootfs (ext4) from the digest-pinned ruby:3.4-alpine
#     image plus this repository's lib/ tree, the Linux ABI extension compiled
#     for musl inside that image, and the guest init;
#   * its dm-verity hash tree and root hash;
#   * the pinned guest kernel (built by tools/microvm/build_guest_kernel.sh);
#   * the Firecracker v1.16.1 release binaries (firecracker, jailer, seccomp
#     filter) verified against the published SHA256SUMS.
#
# Outputs go to build/microvm/artifacts/ and the lock is written to
# third_party/locks/m7-microvm-artifacts.json with the SHA-256 of every file,
# the base image digest, the source lib digest and the tool versions.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

ROOT = File.expand_path("../..", __dir__)
BUILD = File.join(ROOT, "build/microvm")
ARTIFACTS = File.join(BUILD, "artifacts")
DOWNLOADS = File.join(BUILD, "downloads")
RELEASE = File.join(DOWNLOADS, "release-v1.16.1-x86_64")
LOCK = File.join(ROOT, "third_party/locks/m7-microvm-artifacts.json")
BASE_IMAGE = "ruby:3.4-alpine"
BASE_IMAGE_DIGEST = ENV.fetch("RUBERNETES_M7_BASE_IMAGE_DIGEST", "sha256:c5a5064d190055633011c03aa800170cc36945ff3afb5f6c915329f92d6f1e00")
FIRECRACKER_TGZ_SHA256 = "382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"
KERNEL = File.join(BUILD, "kernel", "vmlinux-rubernetes-6.1.128")
ROOTFS_SIZE_MIB = Integer(ENV.fetch("RUBERNETES_M7_ROOTFS_MIB", "768"))

def run!(*arguments, chdir: nil, env: {})
  output, status = Open3.capture2e(env, *arguments, chdir: chdir || ROOT)
  raise "#{arguments.first(3).join(" ")} failed:\n#{output}" unless status.success?

  output
end

def sha256(path)
  Digest::SHA256.file(path).hexdigest
end

def tree_digest(directory)
  files = Dir.glob(File.join(directory, "**", "*"), File::FNM_DOTMATCH).select { |path| File.file?(path) }.sort
  Digest::SHA256.hexdigest(files.map { |path| "#{path.delete_prefix("#{directory}/")}\0#{sha256(path)}\n" }.join)
end

def verify_release!
  tgz = File.join(DOWNLOADS, "firecracker-v1.16.1-x86_64.tgz")
  raise "missing #{tgz}" unless File.file?(tgz)
  raise "firecracker release digest mismatch" unless sha256(tgz) == FIRECRACKER_TGZ_SHA256

  sums = File.read(File.join(RELEASE, "SHA256SUMS")).lines.to_h do |line|
    digest, name = line.split
    [File.basename(name), digest]
  end
  %w[firecracker-v1.16.1-x86_64 jailer-v1.16.1-x86_64 seccomp-filter-v1.16.1-x86_64.json].each do |name|
    path = File.join(RELEASE, name)
    raise "#{name} digest does not match SHA256SUMS" unless sha256(path) == sums.fetch(name)
  end
end

def build_rootfs(staging)
  FileUtils.rm_rf(staging)
  FileUtils.mkdir_p(staging)
  reference = "#{BASE_IMAGE.split(":").first}@#{BASE_IMAGE_DIGEST}"
  run!("docker", "pull", reference)
  image_id = run!("docker", "inspect", "--format", "{{.Id}}", reference).strip
  # Compile the Linux ABI extension for musl inside the pinned image.
  ext_output = File.join(BUILD, "ext-musl")
  FileUtils.rm_rf(ext_output)
  FileUtils.mkdir_p(ext_output)
  proxy_env = ENV.select do |key, _|
    key =~ /\A(https?_proxy|HTTPS?_PROXY|no_proxy|NO_PROXY)\z/
  end.flat_map { |key, value| ["-e", "#{key}=#{value}"] }
  run!("docker", "run", "--rm", *proxy_env, "-v", "#{File.join(ROOT, "ext")}:/src/ext:ro", "-v", "#{ext_output}:/out", reference, "sh", "-c",
       "apk add --no-cache build-base linux-headers >/dev/null && mkdir -p /build && cp -r /src/ext/rubernetes_linux /build/ && cd /build/rubernetes_linux " \
       "&& ruby extconf.rb >/dev/null && make >/dev/null && cp rubernetes_linux.so /out/ && chmod 644 /out/rubernetes_linux.so")
  raise "extension build produced no rubernetes_linux.so" unless File.file?(File.join(ext_output, "rubernetes_linux.so"))

  container = run!("docker", "create", reference, "true").strip
  begin
    run!("sh", "-c", "docker export #{container} | tar -C #{staging} -xf -")
  ensure
    run!("docker", "rm", container)
  end
  # Project code and extension.
  FileUtils.mkdir_p(File.join(staging, "opt/rubernetes/ext"))
  FileUtils.cp_r(File.join(ROOT, "lib"), File.join(staging, "opt/rubernetes/lib"))
  # The Linux ABI manifest is resolved relative to lib/ by the platform layer.
  FileUtils.mkdir_p(File.join(staging, "opt/rubernetes/generated"))
  FileUtils.cp_r(File.join(ROOT, "generated/platform"), File.join(staging, "opt/rubernetes/generated/platform"))
  FileUtils.cp(File.join(ext_output, "rubernetes_linux.so"), File.join(staging, "opt/rubernetes/ext/rubernetes_linux.so"))
  init = File.join(staging, "sbin/rubernetes-init")
  FileUtils.cp(File.join(ROOT, "lib/rubernetes/runtime/microvm/guest/init.rb"), init)
  FileUtils.chmod(0o755, init)
  # Writable locations live on tmpfs (/run) or the injected workspace.
  FileUtils.rm_f(File.join(staging, "etc/machine-id"))
  File.symlink("/run/machine-id", File.join(staging, "etc/machine-id"))
  FileUtils.rm_f(File.join(staging, "etc/resolv.conf"))
  File.symlink("/run/resolv.conf", File.join(staging, "etc/resolv.conf"))
  FileUtils.rm_f(File.join(staging, "etc/hostname"))
  File.write(File.join(staging, "etc/hostname"), "rubernetes-base\n")
  %w[proc sys dev run tmp var/lib/rubernetes sys/fs/cgroup].each { |dir| FileUtils.mkdir_p(File.join(staging, dir)) }
  # No credentials, no package caches, no shell history in the guest image.
  FileUtils.rm_rf(File.join(staging, "root/.cache"))
  FileUtils.rm_rf(File.join(staging, "var/cache/apk"))
  Dir.glob(File.join(staging, "**", "*.gem")).each { |path| File.delete(path) if path.include?("/cache/") }
  {"image_id" => image_id, "reference" => reference, "lib_tree_sha256" => tree_digest(File.join(ROOT, "lib")),
   "generated_platform_sha256" => tree_digest(File.join(ROOT, "generated/platform")), "ext_sha256" => sha256(File.join(ext_output, "rubernetes_linux.so"))}
end

def main
  options = {write_lock: true}
  OptionParser.new do |parser|
    parser.on("--no-lock", "build the artifacts without rewriting the lock") { options[:write_lock] = false }
  end.parse!(ARGV)
  verify_release!
  raise "guest kernel #{KERNEL} is missing (run tools/microvm/build_guest_kernel.sh)" unless File.file?(KERNEL)

  FileUtils.mkdir_p(ARTIFACTS)
  staging = File.join(BUILD, "rootfs-staging")
  provenance = build_rootfs(staging)
  rootfs = File.join(ARTIFACTS, "rootfs.ext4")
  FileUtils.rm_f(rootfs)
  run!("mkfs.ext4", "-q", "-F", "-d", staging, "-L", "rubernetes-guest", "-O", "^has_journal", rootfs, "#{ROOTFS_SIZE_MIB}M")
  FileUtils.rm_rf(staging)
  hash_image = File.join(ARTIFACTS, "rootfs.verity")
  FileUtils.rm_f(hash_image)
  output = run!("veritysetup", "format", "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096", rootfs, hash_image)
  root_hash = output[/Root hash:\s*([0-9a-f]{64})/, 1] || raise("veritysetup reported no root hash")
  salt = output[/Salt:\s*([0-9a-f]+)/, 1]
  run!("veritysetup", "verify", rootfs, hash_image, root_hash)
  FileUtils.cp(KERNEL, File.join(ARTIFACTS, "vmlinux"))
  FileUtils.cp(File.join(RELEASE, "firecracker-v1.16.1-x86_64"), File.join(ARTIFACTS, "firecracker"))
  FileUtils.cp(File.join(RELEASE, "jailer-v1.16.1-x86_64"), File.join(ARTIFACTS, "jailer"))
  FileUtils.cp(File.join(RELEASE, "seccomp-filter-v1.16.1-x86_64.json"), File.join(ARTIFACTS, "seccomp-filter.json"))
  FileUtils.cp(File.join(BUILD, "kernel", "vmlinux-rubernetes-6.1.128.config"), File.join(ARTIFACTS, "vmlinux.config"))
  Dir.children(ARTIFACTS).each do |name|
    path = File.join(ARTIFACTS, name)
    File.chown(0, 0, path)
    File.chmod(name.start_with?("firecracker", "jailer") ? 0o755 : 0o644, path)
  end
  File.chmod(0o755, ARTIFACTS)
  files = %w[firecracker jailer seccomp-filter.json vmlinux rootfs.ext4 rootfs.verity vmlinux.config].to_h do |name|
    key = {"seccomp-filter.json" => "seccomp_filter", "vmlinux" => "kernel", "rootfs.ext4" => "rootfs", "rootfs.verity" => "verity_hash",
           "vmlinux.config" => "kernel_config"}.fetch(
             name, name
           )
    path = File.join(ARTIFACTS, name)
    [key, {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => sha256(path), "bytes" => File.size(path)}]
  end
  lock = {
    "schema_version" => 1,
    "verified_at" => Time.now.utc.iso8601,
    "purpose" => "M7 MicroVM guest artifacts: Firecracker v1.16.1 release binaries, pinned guest kernel, read-only rootfs with the Ruby guest supervisor, " \
                 "dm-verity hash tree",
    "firecracker" => {"version" => "1.16.1", "release_archive_sha256" => FIRECRACKER_TGZ_SHA256,
                      "release_url" => "https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.1/firecracker-v1.16.1-x86_64.tgz"},
    "kernel" => {"version" => "6.1.128", "source_sha256" => "874d67d3181570e69ac6b33853f0448f05fc90d4cf3e4baaadc4a9cede7c50f3",
                 "base_config" => "firecracker v1.16.1 resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config",
                 "base_config_sha256" => "adbc70ab5e89213ba00594b12d25e09bdf8bb1ed3c252d7449326bb14c22963b",
                 "build_script" => "tools/microvm/build_guest_kernel.sh", "added_options" => %w[CONFIG_SECURITY_LANDLOCK CONFIG_DM_VERITY CONFIG_IKCONFIG_PROC CONFIG_PSI CONFIG_CGROUP_FREEZER]},
    "guest_image" => {"base" => provenance["reference"], "base_image_id" => provenance["image_id"], "lib_tree_sha256" => provenance["lib_tree_sha256"],
                      "extension_sha256" => provenance["ext_sha256"], "generated_platform_sha256" => provenance["generated_platform_sha256"],
                      "init" => "lib/rubernetes/runtime/microvm/guest/init.rb", "size_mib" => ROOTFS_SIZE_MIB},
    "verity" => {"algorithm" => "sha256", "data_block_size" => 4096, "hash_block_size" => 4096, "root_hash" => root_hash, "salt" => salt},
    "guest_bundle" => {"sha256" => provenance["lib_tree_sha256"]},
    "files" => files
  }
  File.write(LOCK, JSON.pretty_generate(lock) + "\n") if options[:write_lock]
  puts JSON.pretty_generate({"artifacts" => ARTIFACTS, "root_hash" => root_hash, "files" => files.transform_values do |entry|
    entry["sha256"]
  end})
end

main if $PROGRAM_NAME == __FILE__
