#!/usr/bin/env ruby
# frozen_string_literal: true

# Runs the real ControllerManagerService through the project bootstrap seam.
# The built-in corpus marks cloud-provider controllers as requiring an injected
# provider at startup; this inert provider is only a wiring capability for the
# controller chaos fixture, which contains no cloud-managed Service or Node.

ROOT = File.expand_path("../../../..", __dir__).freeze
$LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
require "rubernetes/bootstrap/assembler"
require "rubernetes/bootstrap/runner"
require File.join(ROOT, "lib", "rubernetes", "controller", "effect_journal")

class M3ChaosCloudProvider
  def initialize
    @journal = Rubernetes::Controller::EffectJournal.from_env(component: "controller-manager")
  end

  def method_missing(name, *arguments, **keywords)
    @journal&.record_provider(
      reconcile_key: ENV.fetch("RUBERNETES_M3_PROCESS_IDENTITY", "unknown"),
      provider: self.class.name,
      operation: name,
      extra: {"argument_count" => arguments.length, "keyword_count" => keywords.length}
    )
    super
  end

  def respond_to_missing?(_name, _include_private = false)
    false
  end
end

assembly = Rubernetes::Bootstrap::Assembler.new(
  process_name: "rubernetes-controller-manager",
  config_path: ARGV.fetch(ARGV.index("--config") + 1),
  log_io: $stderr,
  runtime_adapters: {cloud_provider: M3ChaosCloudProvider.new}
).build

exit Rubernetes::Bootstrap::Runner.new(assembly: assembly).run
