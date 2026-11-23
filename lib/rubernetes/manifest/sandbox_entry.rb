#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "optparse"

options = {}
OptionParser.new do |parser|
  %i[root manifest registry openapi worker library ruby_prefix ruby_executable max_output max_resources].each do |name|
    parser.on("--#{name.to_s.tr("_", "-")} VALUE") { |value| options[name] = value }
  end
end.parse!(ARGV)

missing = %i[root manifest registry openapi worker library ruby_prefix ruby_executable max_output max_resources].reject { |name| options[name] }
abort "missing sandbox arguments: #{missing.join(", ")}" unless missing.empty?

root = options.fetch(:root)
%w[input work tmp].each { |relative| FileUtils.mkdir_p(File.join(root, relative)) }
ruby_destination = File.join(root, options.fetch(:ruby_prefix).delete_prefix("/"))
FileUtils.mkdir_p(ruby_destination)
bindings = {options.fetch(:ruby_prefix) => ruby_destination}
# Keep the loader's absolute paths on both merged-/usr and split-/usr hosts.
%w[/lib /lib64 /usr/lib /usr/lib64].each do |directory|
  next unless File.directory?(directory)

  destination = File.join(root, directory.delete_prefix("/"))
  FileUtils.mkdir_p(destination)
  bindings[directory] = destination
end
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
    abort "cannot make sandbox input read-only" unless system("/usr/bin/mount", "-o", "remount,bind,ro,nosuid,nodev", destination,
                                                              exception: false)
  end
  worker = fork do
    Dir.chroot(root)
    Dir.chdir("/")
    exec(options.fetch(:ruby_executable), "/input/worker.rb",
         "--manifest", "/input/manifest.rb", "--source-name", File.basename(options.fetch(:manifest)),
         "--registry", "/input/registry.json", "--openapi", "/input/openapi.json", "--library", "/input/lib",
         "--max-output", options.fetch(:max_output), "--max-resources", options.fetch(:max_resources))
  rescue SystemCallError => error
    warn "cannot start sandbox worker: #{error.class}"
    exit! 1
  end
  status = Process.wait2(worker).last.success?
ensure
  mounted.reverse_each do |destination|
    system("/usr/bin/umount", "--lazy", destination, exception: false)
  end
end
abort "sandbox worker failed" unless status
