#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "optparse"

options = {}
OptionParser.new do |parser|
  %i[manifest registry openapi library max_output max_resources].each do |name|
    parser.on("--#{name.to_s.tr('_', '-')} VALUE") { |value| options[name] = value }
  end
end.parse!(ARGV)

Process.setrlimit(Process::RLIMIT_CPU, 4, 5)
Process.setrlimit(Process::RLIMIT_FSIZE, Integer(options.fetch(:max_output)), Integer(options.fetch(:max_output)))

$LOAD_PATH.unshift(options.fetch(:library))
require "rubernetes/manifest/builder"

builder = Rubernetes::Manifest::Builder.load(
  registry_path: options.fetch(:registry),
  openapi_path: options.fetch(:openapi)
)
source = File.binread(options.fetch(:manifest), 4 * 1024 * 1024)
builder.instance_eval(source, options.fetch(:manifest), 1)
resources = builder.result
abort "manifest resource limit exceeded" if resources.length > Integer(options.fetch(:max_resources))

payload = JSON.generate(resources)
abort "manifest output limit exceeded" if payload.bytesize > Integer(options.fetch(:max_output))
$stdout.binmode
$stdout.write([payload.bytesize].pack("Q>"))
$stdout.write(payload)
