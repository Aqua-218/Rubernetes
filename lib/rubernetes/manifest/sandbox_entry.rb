#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "optparse"
require "tmpdir"

options = {}
OptionParser.new do |parser|
  %i[manifest registry openapi worker library ruby_prefix ruby_executable max_output max_resources].each do |name|
    parser.on("--#{name.to_s.tr('_', '-')} VALUE") { |value| options[name] = value }
  end
end.parse!(ARGV)

missing = %i[manifest registry openapi worker library ruby_prefix ruby_executable max_output max_resources].reject { |name| options[name] }
abort "missing sandbox arguments: #{missing.join(', ')}" unless missing.empty?

Dir.mktmpdir("rubernetes-manifest-root-") do |root|
  %w[input usr/lib usr/lib64 work tmp].each { |relative| FileUtils.mkdir_p(File.join(root, relative)) }
  File.symlink("usr/lib", File.join(root, "lib"))
  File.symlink("usr/lib64", File.join(root, "lib64"))
  ruby_destination = File.join(root, options.fetch(:ruby_prefix).delete_prefix("/"))
  FileUtils.mkdir_p(ruby_destination)
  bindings = {
    options.fetch(:ruby_prefix) => ruby_destination,
    "/usr/lib" => File.join(root, "usr/lib"),
    "/usr/lib64" => File.join(root, "usr/lib64")
  }
  inputs = {
    options.fetch(:manifest) => File.join(root, "input/manifest.rb"),
    options.fetch(:registry) => File.join(root, "input/registry.json"),
    options.fetch(:openapi) => File.join(root, "input/openapi.json"),
    options.fetch(:worker) => File.join(root, "input/worker.rb")
  }
  FileUtils.mkdir_p(File.join(root, "input/lib"))
  bindings[options.fetch(:library)] = File.join(root, "input/lib")
  inputs.each_value { |destination| FileUtils.touch(destination) }
  bindings.merge!(inputs)
  mounted = []
  status = false
  begin
    bindings.each do |source, destination|
      abort "sandbox input does not exist: #{source}" unless File.exist?(source)
      abort "cannot bind sandbox input" unless system("/usr/bin/mount", "--bind", source, destination, exception: false)
      mounted << destination
      abort "cannot make sandbox input read-only" unless system("/usr/bin/mount", "-o", "remount,bind,ro,nosuid,nodev", destination, exception: false)
    end
    status = system(
      "/usr/sbin/chroot", root, options.fetch(:ruby_executable), "/input/worker.rb",
      "--manifest", "/input/manifest.rb",
      "--registry", "/input/registry.json",
      "--openapi", "/input/openapi.json",
      "--library", "/input/lib",
      "--max-output", options.fetch(:max_output),
      "--max-resources", options.fetch(:max_resources),
      exception: false
    )
  ensure
    mounted.reverse_each do |destination|
      system("/usr/bin/umount", "--lazy", destination, exception: false)
    end
  end
  abort "sandbox worker failed" unless status
end
