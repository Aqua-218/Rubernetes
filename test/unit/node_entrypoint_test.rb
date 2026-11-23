# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"

class NodeEntrypointTest < Minitest::Test
  def test_first_access_and_preloaded_fragments_resolve_to_the_complete_implementation
    script = <<~'RUBY'
      ARGV.each { |file| require "rubernetes/node/#{file}" }
      require "rubernetes/node"
      node = Rubernetes::Node
      raise "missing cAdvisor renderer" unless node::CadvisorMetrics.respond_to?(:render)
      raise "missing plugin manager" unless node::Plugins::Manager.public_method_defined?(:reconcile)
      raise "missing agent implementation" unless node::Agent.public_method_defined?(:ready?)
      raise "incorrect agent alias" unless node::NodeAgent.equal?(node::Agent)
    RUBY
    [[], %w[cadvisor_filesystems plugins/rpc agent/extensions]].each do |fragments|
      output, status = Open3.capture2e(RbConfig.ruby, "-I#{File.expand_path("../../lib", __dir__)}", "-e", script, *fragments)

      assert_predicate status, :success?, output
    end
  end
end
