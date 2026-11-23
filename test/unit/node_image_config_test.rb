# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/image_credentials"
require "tmpdir"

class NodeImageConfigTest < Minitest::Test
  ImageCredentials = Rubernetes::Node::ImageCredentials

  def setup
    @directory = Dir.mktmpdir("node-image-config")
    @file = File.join(@directory, "config.json")
    @now = 0
    @config = ImageCredentials::NodeConfig.new(root: @directory, monotonic: -> { @now })
  end

  def teardown = FileUtils.remove_entry(@directory)

  def test_node_config_is_cached_for_five_minutes_and_updates_after_rotation
    write_credentials("first")
    reference = "test.registry/team/app:1"
    first = @config.lookup(reference)

    assert_equal({username: "fixture-user", password: "first"}, first.to_h)
    assert_nil first.pull_secret
    assert_nil @config.lookup("test.registry/other/app:1")
    assert_nil @config.lookup("different.registry/team/app:1")

    write_credentials("rotated")
    @now = 299

    assert_equal "first", @config.lookup(reference).password

    @now = 300

    assert_equal "rotated", @config.lookup(reference).password

    File.unlink(@file)
    @now = 600

    assert_nil @config.lookup(reference)
  end

  def test_pod_credentials_take_priority_and_node_credentials_remain_node_wide
    write_credentials("node")
    pod = {"spec" => {"imagePullSecrets" => [{"name" => "pull-secret"}]}}
    auths = {"test.registry" => {"username" => "pod-user", "password" => "fixture-secret"}}
    secret = {"type" => "kubernetes.io/dockerconfigjson", "metadata" => {"name" => "pull-secret", "uid" => "uid"},
              "data" => {".dockerconfigjson" => Base64.strict_encode64(JSON.generate({"auths" => auths}))}}
    reader = Object.new
    reader.define_singleton_method(:get) { |resource, *| secret if resource == "secrets" }
    image = "test.registry/team/app:1"
    keyring = ImageCredentials.for_pod(pod, reader: reader, node_config: @config)
    node_keyring = ImageCredentials.for_pod({}, reader: nil, node_config: @config)

    assert_equal "pod-user", keyring.lookup(image).username
    assert_equal "pull-secret", keyring.lookup(image).pull_secret[:name]
    assert_equal "fixture-user", node_keyring.lookup(image).username
    assert_empty node_keyring.lookup_all(image)
  end

  private

  def write_credentials(password)
    entry = {"auth" => Base64.strict_encode64("fixture-user:#{password}")}
    File.write(@file, JSON.generate({"auths" => {"test.registry/team" => entry}}))
  end
end
