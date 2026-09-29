# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# ?dryRun=All runs admission and validation and returns the object that WOULD
# have been stored, without storing it.  Not honouring it made
# "[sig-cli] Kubectl client Kubectl server-side dry-run" write the object for
# real, which is the opposite of what the verb means.
class APIDryRunTest < Minitest::Test
  Server = Rubernetes::API::Server

  def request(values)
    Struct.new(:values) do
      def query_values(name) = values.fetch(name, [])
    end.new(values)
  end

  def server
    server = Server.allocate
    server.instance_variable_set(:@clock, -> { Time.at(0).utc })
    server.instance_variable_set(:@uid_generator, -> { "uid-fixed" })
    server
  end

  def test_dry_run_all_is_recognised
    assert server.send(:dry_run?, request("dryRun" => ["All"]))
  end

  def test_no_dry_run_parameter_is_not_a_dry_run
    refute server.send(:dry_run?, request({}))
    refute server.send(:dry_run?, request("dryRun" => []))
  end

  def test_an_unknown_dry_run_value_is_not_all
    refute server.send(:dry_run?, request("dryRun" => ["true"]))
    refute server.send(:dry_run?, request("dryRun" => [""]))
  end

  def test_the_preview_fills_in_what_the_server_owns
    object = {"apiVersion" => "v1", "kind" => "ConfigMap",
              "metadata" => {"name" => "c"}, "data" => {"k" => "v"}}
    preview = server.send(:dry_run_view, object, "ns")

    assert_equal "ns", preview.dig("metadata", "namespace")
    assert_equal "uid-fixed", preview.dig("metadata", "uid")
    refute_nil preview.dig("metadata", "creationTimestamp")
    assert_equal({"k" => "v"}, preview["data"])
  end

  def test_the_preview_does_not_overwrite_what_the_client_set
    object = {"apiVersion" => "v1", "kind" => "ConfigMap",
              "metadata" => {"name" => "c", "namespace" => "other", "uid" => "client-uid"}}
    preview = server.send(:dry_run_view, object, "ns")

    assert_equal "other", preview.dig("metadata", "namespace")
    assert_equal "client-uid", preview.dig("metadata", "uid")
  end

  def test_a_cluster_scoped_preview_gets_no_namespace
    preview = server.send(:dry_run_view, {"metadata" => {"name" => "n"}}, :cluster)

    assert_nil preview.dig("metadata", "namespace")
  end
end
