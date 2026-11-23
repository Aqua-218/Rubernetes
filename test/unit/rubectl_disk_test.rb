# frozen_string_literal: true

require "stringio"
require_relative "../test_helper"
require "rubernetes/rubectl"

class RubectlDiskTest < Minitest::Test
  CLI = Rubernetes::Rubectl::CLI
  SUMMARY = "/api/v1/nodes/worker.example/proxy/stats/summary"
  OTHER_SUMMARY = "/api/v1/nodes/other.example/proxy/stats/summary"

  class Rest
    def initialize(pod, summaries, statuses)
      @pod = pod
      @summaries = summaries
      @statuses = statuses
      @calls = []
      @queries = []
    end

    attr_reader :calls, :queries

    def request(method, path, query:, **)
      @calls << [method, path]
      @queries << query
      status = @statuses.fetch(path, 200)
      value = @summaries.fetch(path, @pod)
      value = value.call(query) if value.respond_to?(:call)
      Rubernetes::Client::HTTPClient::Response.new(status: status, headers: {"content-type" => "application/json"}, body: JSON.generate(value))
    end
  end

  def test_reports_only_the_current_uid_and_keeps_the_measured_aggregate
    stale = {"podRef" => pod.fetch("metadata").merge("uid" => "previous"), "ephemeral-storage" => {"usedBytes" => 100_000}}
    rest, status, output, errors = run_disk("-n", "test", "-o", "json", summary: {"pods" => [stale, current_sample]})

    assert_equal CLI::EX_OK, status, errors
    assert_empty errors
    assert_equal [["GET", "/api/v1/namespaces/test/pods/web"], ["GET", SUMMARY]], rest.calls
    report = JSON.parse(output)

    assert_equal pod.fetch("metadata"), report["pod"]
    assert_equal "worker.example", report["nodeName"]
    assert_equal "sampled", report["status"]
    assert_equal 170, report["ephemeralStorageUsedBytes"]
    assert_equal [{"name" => "app", "writableLayerUsedBytes" => 80, "logsUsedBytes" => 0},
                  {"name" => "setup", "writableLayerUsedBytes" => nil, "logsUsedBytes" => nil}], report["containers"]
    volumes = report["volumes"].to_h { |volume| [volume.fetch("name"), volume.values_at("storage", "usedBytes", "claimName")] }

    assert_equal({"scratch" => ["disk", 60, nil], "cache" => ["ram", 20, nil], "database" => ["pvc", 200, "data"],
                  "generated" => ["pvc", nil, "web-generated"], "host" => ["unknown", nil, nil]}, volumes)
  end

  def test_empty_dir_limits_are_available_even_without_a_usage_sample
    object = pod
    scratch, cache = object.fetch("spec").fetch("volumes")
    scratch.fetch("emptyDir")["sizeLimit"] = "1.5Mi"
    cache.fetch("emptyDir")["sizeLimit"] = "0"
    _, status, output, errors = run_disk("-o", "json", pod_object: object, summary: {"pods" => []})

    assert_equal CLI::EX_OK, status, errors
    volumes = JSON.parse(output).fetch("volumes").to_h { |volume| [volume.fetch("name"), volume] }

    assert_equal [nil, 1_572_864], volumes.fetch("scratch").values_at("usedBytes", "sizeLimitBytes")
    refute volumes.fetch("cache").key?("sizeLimitBytes")
    _, status, text, errors = run_disk(pod_object: object, summary: {"pods" => [current_sample]})

    assert_equal CLI::EX_OK, status, errors
    assert_includes text, "scratch  disk (emptyDir): 60 B  emptyDir limit: 1572864 B"
    assert_equal 1, text.scan("emptyDir limit:").size
  end

  def test_text_marks_an_unmeasured_pod_and_preserves_the_context_namespace
    rest, status, output, errors = run_disk(summary: {"pods" => [{"podRef" => pod.fetch("metadata").merge("uid" => "previous")}]})

    assert_equal CLI::EX_OK, status, errors
    assert_equal [["GET", "/api/v1/namespaces/context-space/pods/web"], ["GET", SUMMARY]], rest.calls
    assert_match(/Ephemeral storage: unknown \(no kubelet sample for this Pod UID\)/, output)
    assert_match(/app  writable layer: unknown  logs: unknown/, output)
    assert_match(/scratch  disk \(emptyDir\): unknown/, output)
    assert_match(/cache  RAM \(emptyDir\): unknown/, output)
    assert_match(/database  PVC \(data\): unknown/, output)
  end

  def test_does_not_query_a_node_for_an_unscheduled_pod_or_missing_uid
    [[pod(node: nil), "notScheduled"], [pod(uid: nil), "missingUID"]].each do |object, reason|
      rest, status, output, errors = run_disk("-o", "json", pod_object: object)

      assert_equal CLI::EX_OK, status, errors
      assert_equal [["GET", "/api/v1/namespaces/context-space/pods/web"]], rest.calls
      assert_equal [reason, nil], JSON.parse(output).values_at("status", "ephemeralStorageUsedBytes")
    end
  end

  def test_does_not_replace_missing_total_with_sum_of_details_or_hide_api_denial
    partial = current_sample.except("ephemeral-storage")
    _, status, output, errors = run_disk("-o", "json", summary: {"pods" => [partial]})

    assert_equal CLI::EX_OK, status, errors
    assert_nil JSON.parse(output).fetch("ephemeralStorageUsedBytes")
    assert_equal 80, JSON.parse(output).dig("containers", 0, "writableLayerUsedBytes")

    rest, status, output, errors = run_disk(summary: {"kind" => "Status", "code" => 403, "reason" => "Forbidden"}, summary_status: 403)

    assert_equal 1, status
    assert_empty output
    assert_equal "Forbidden", JSON.parse(errors).fetch("reason")
    assert_equal ["GET", SUMMARY], rest.calls.last
  end

  def test_validates_usage_and_rejects_unusable_node_names_without_proxying
    %w[yaml name].each do |format|
      rest, status, _, errors = run_disk("-o", format)

      assert_equal CLI::EX_USAGE, status
      assert_includes errors, "disk output must be text or json"
      assert_empty rest.calls
    end

    rest, status, output, errors = run_disk(pod_object: pod(node: "worker/other"))

    assert_equal CLI::EX_DATAERR, status
    assert_empty output
    assert_includes errors, "invalid Pod node name"
    assert_equal [["GET", "/api/v1/namespaces/context-space/pods/web"]], rest.calls
  end

  def test_ranks_namespace_pods_with_one_summary_get_per_node
    pods = [pod(name: "other", node: "other.example", uid: "other"), pod(name: "zero", uid: "zero"), pod,
            pod(name: "pending", node: nil, uid: "pending"), pod(name: "missing", uid: nil)]
    first_node = {"pods" => [current_sample, {"podRef" => {"uid" => "zero"}, "ephemeral-storage" => {"usedBytes" => 0}}]}
    stale_ref = {"uid" => "current", "name" => "other", "namespace" => "test"}
    second_node = {"pods" => [{"podRef" => stale_ref, "ephemeral-storage" => {"usedBytes" => 937_193}}]}
    rest, status, output, errors = run_disk("-n", "test", "-o", "json", name: nil, pod_object: {"items" => pods}, summary: first_node,
                                                                        other_summaries: {OTHER_SUMMARY => second_node})

    assert_equal CLI::EX_OK, status, errors
    assert_equal [["GET", "/api/v1/namespaces/test/pods"], ["GET", OTHER_SUMMARY], ["GET", SUMMARY]], rest.calls
    rows = JSON.parse(output).fetch("pods")

    assert_equal(%w[web zero missing other pending], rows.map { |row| row.dig("pod", "name") })
    assert_equal([170, 0, nil, nil, nil], rows.map { |row| row["ephemeralStorageUsedBytes"] })
    assert_equal(%w[sampled sampled missingUID noSample notScheduled], rows.map { |row| row["status"] })
    rows.each { |row| refute row.key?("containers") }
  end

  def test_filters_ranking_to_a_node_and_keeps_node_proxy_denials_visible
    list = {"items" => [pod, pod(name: "other", node: "other.example", uid: "other"), pod(name: "pending", node: nil)]}
    rest, status, output, errors = run_disk("--node", "worker.example", name: nil, pod_object: list, summary: {"pods" => [current_sample]})

    assert_equal CLI::EX_OK, status, errors
    assert_equal [["GET", "/api/v1/namespaces/context-space/pods"], ["GET", SUMMARY]], rest.calls
    assert_equal({"fieldSelector" => "spec.nodeName=worker.example", "limit" => 500}, rest.queries.first)
    assert_match(%r{test/web\s+worker\.example\s+170 B}, output)
    refute_match(/other|pending/, output)

    denied = {"kind" => "Status", "code" => 403, "reason" => "Forbidden"}
    _, status, output, errors = run_disk("--node", "worker.example", name: nil, pod_object: list, summary: denied, summary_status: 403)

    assert_equal 1, status
    assert_empty output
    assert_equal "Forbidden", JSON.parse(errors).fetch("reason")
  end

  def test_pages_across_namespaces_and_fetches_one_summary_per_node
    second = pod(name: "web", uid: "second")
    second["metadata"]["namespace"] = "alpha"
    pages = lambda do |query|
      if query["continue"]
        {"items" => [second]}
      else
        {"items" => [pod], "metadata" => {"continue" => "next-page"}}
      end
    end
    other = current_sample.merge("podRef" => second.fetch("metadata"))
    rest, status, output, errors = run_disk("-A", "-o", "json", name: nil, pod_object: pages, summary: {"pods" => [current_sample, other]})

    assert_equal CLI::EX_OK, status, errors
    assert_equal [["GET", "/api/v1/pods"], ["GET", "/api/v1/pods"], ["GET", SUMMARY]], rest.calls
    assert_equal [{"limit" => 500}, {"limit" => 500, "continue" => "next-page"}], rest.queries.first(2)
    assert_equal(%w[alpha test], JSON.parse(output).fetch("pods").map { |row| row.dig("pod", "namespace") })
    rest, status, _, errors = run_disk("-A")

    assert_equal CLI::EX_USAGE, status
    assert_match(/omitting the resource name/, errors)
    assert_empty rest.calls
  end

  def test_empty_ranking_does_not_fetch_a_node_summary
    rest, status, output, errors = run_disk(name: nil, pod_object: {"items" => []})

    assert_equal CLI::EX_OK, status, errors
    assert_equal "No Pods found.\n", output
    assert_equal [["GET", "/api/v1/namespaces/context-space/pods"]], rest.calls
  end

  def test_reports_node_filesystems_with_only_one_summary_request
    root = {"usedBytes" => 201, "availableBytes" => 700, "capacityBytes" => 1000}
    summary = {"node" => {"fs" => root, "runtime" => {"imageFs" => root.merge("inodes" => 72), "containerFs" => {"usedBytes" => 0}}},
               "pods" => [current_sample]}
    container = {"usedBytes" => 0, "availableBytes" => nil, "capacityBytes" => nil}
    filesystems = {"fs" => root, "imageFs" => root, "containerFs" => container}
    rest, status, output, errors = run_disk("-o", "json", name: "node/worker.example", summary: summary)

    assert_equal CLI::EX_OK, status, errors
    assert_empty errors
    assert_equal [["GET", SUMMARY]], rest.calls
    assert_equal({"nodeName" => "worker.example", "filesystems" => filesystems}, JSON.parse(output))
  end

  def test_node_text_distinguishes_missing_filesystem_measurements_from_zero
    _, status, output, errors = run_disk(name: "node/worker.example", summary: {"node" => {"fs" => {"usedBytes" => 0, "capacityBytes" => 120}}})

    assert_equal CLI::EX_OK, status, errors
    assert_equal ["Node worker.example", "Node root filesystem  used: 0 B  available: unknown  capacity: 120 B",
                  "Runtime image filesystem  used: unknown  available: unknown  capacity: unknown",
                  "Runtime container filesystem  used: unknown  available: unknown  capacity: unknown"], output.lines(chomp: true)
  end

  def test_node_operand_rejects_invalid_names_and_listing_options_before_requests
    %w[node/ node/Worker node/worker/other node/worker%2Fother].each do |name|
      rest, status, _, errors = run_disk(name: name)

      assert_equal CLI::EX_USAGE, status
      assert_includes errors, "valid Kubernetes node name"
      assert_empty rest.calls
    end

    [["-A"], ["--all-namespaces"], ["--node", "worker.example"]].each do |args|
      rest, status, _, errors = run_disk(*args, name: "node/worker.example")

      assert_equal CLI::EX_USAGE, status
      assert_includes errors, "omitting the resource name"
      assert_empty rest.calls
    end
  end

  def test_node_summary_errors_are_visible
    denied = {"kind" => "Status", "code" => 403, "reason" => "Forbidden"}
    rest, status, output, errors = run_disk(name: "node/worker.example", summary: denied, summary_status: 403)

    assert_equal 1, status
    assert_empty output
    assert_equal "Forbidden", JSON.parse(errors).fetch("reason")
    assert_equal [["GET", SUMMARY]], rest.calls

    _, status, output, errors = run_disk(name: "node/worker.example", summary: {"pods" => []})

    assert_equal CLI::EX_DATAERR, status
    assert_empty output
    assert_includes errors, "kubelet for node worker.example returned an invalid stats summary"
  end

  private

  def pod(name: "web", node: "worker.example", uid: "current")
    {"metadata" => {"name" => name, "namespace" => "test", "uid" => uid}.compact,
     "spec" => {"nodeName" => node, "containers" => [{"name" => "app"}], "initContainers" => [{"name" => "setup"}],
                "volumes" => [{"name" => "scratch", "emptyDir" => {}}, {"name" => "cache", "emptyDir" => {"medium" => "Memory"}},
                              {"name" => "database", "persistentVolumeClaim" => {"claimName" => "data"}},
                              {"name" => "generated", "ephemeral" => {}}, {"name" => "host", "hostPath" => {"path" => "/path"}}]}}
  end

  def current_sample
    {"podRef" => pod.fetch("metadata"), "ephemeral-storage" => {"usedBytes" => 170},
     "containers" => [{"name" => "app", "rootfs" => {"usedBytes" => 80}, "logs" => {"usedBytes" => 0}}],
     "volume" => [{"name" => "scratch", "usedBytes" => 60}, {"name" => "cache", "usedBytes" => 20},
                  {"name" => "database", "usedBytes" => 200, "pvcRef" => {"name" => "data", "namespace" => "test"}}]}
  end

  def run_disk(*args, name: "web", pod_object: pod, summary: {}, summary_status: 200, other_summaries: {})
    rest = Rest.new(pod_object, other_summaries.merge(SUMMARY => summary), SUMMARY => summary_status)
    client = Rubernetes::Client::KubernetesClient.new(rest_client: rest, context: {namespace: "context-space"})
    output = StringIO.new
    errors = StringIO.new
    status = CLI.run(["disk", *Array(name), *args], client: client, stdout: output, stderr: errors, env: {"KUBERC" => "off"})
    [rest, status, output.string, errors.string]
  end
end
