# frozen_string_literal: true

require_relative "../test_helper"
require "net/http"
require "rubernetes/api"
require "rubernetes/bootstrap/api_server_service"
require "rubernetes/bootstrap/assembler"

# Three fixes found with a real aggregated API server behind the proxy.
class APIServiceSyncFixesTest < Minitest::Test
  # Net::HTTP joins a repeated header into one "a, b" line; client-go sends
  # one X-Remote-Group line per group, and the backend only reads the first
  # value of a joined line (system:masters was lost).
  def test_repeated_identity_headers_go_out_one_line_per_value
    request = Net::HTTP::Get.new("/apis/x/v1").extend(Rubernetes::API::Aggregator::RepeatedHeaderLines)
    request.delete("X-Remote-Group")
    request.add_field("X-Remote-Group", "system:masters")
    request.add_field("X-Remote-Group", "system:authenticated")
    request["X-Remote-User"] = "system:kube-aggregator"

    lines = request.each_capitalized.to_a
    assert_equal [["X-Remote-Group", "system:masters"], ["X-Remote-Group", "system:authenticated"]],
                 lines.select { |key, _| key == "X-Remote-Group" }
    assert_includes lines, ["X-Remote-User", "system:kube-aggregator"]
  end

  # An APIService that arrives in the initial list, or through the watch,
  # gets its availability probed like one created through the API.
  def test_listed_and_watched_apiservices_schedule_an_availability_check
    scheduled = []
    synced = []
    service = Rubernetes::Bootstrap::APIServerService.allocate
    service.instance_variable_set(:@aggregator, Struct.new(:synced, :names) {
      def sync(object) = synced << object.dig("metadata", "name")
      def backend_names = names
      def remove(name) = names.delete(name)
    }.new(synced, ["v1beta1.stale.example.com"]))
    service.instance_variable_set(:@api_server, Struct.new(:scheduled) {
      def schedule_apiservice_availability(name) = scheduled << name
    }.new(scheduled))

    service.send(:apply_dynamic_snapshot, :apiservice, [{"metadata" => {"name" => "v1.metrics.k8s.io"}}])
    event = Struct.new(:type, :object).new("MODIFIED", {"metadata" => {"name" => "v1beta1.custom.example.com"}})
    service.send(:apply_dynamic_event, :apiservice, event)

    assert_equal %w[v1.metrics.k8s.io v1beta1.custom.example.com], synced
    assert_equal %w[v1.metrics.k8s.io v1beta1.custom.example.com], scheduled
  end

  # The agent's dns.hosts (static names, CoreDNS hosts semantics) was parsed
  # from the configuration but dropped on the way to the DNS service.
  def test_dns_hosts_reach_the_dns_options
    assembler = Rubernetes::Bootstrap::Assembler.allocate
    process = {"dns" => {"hosts" => {"*.r8s.example.com" => ["10.240.0.1"]}}}

    assert_equal({"*.r8s.example.com" => ["10.240.0.1"]}, assembler.send(:dns_options, process)["hosts"])
    assert_nil assembler.send(:dns_options, {})["hosts"]
  end
end
