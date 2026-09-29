# frozen_string_literal: true

require "fileutils"
require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/api"
require "rubernetes/observability/zpages"

# kubelet /logs/ (the node's log directory through http.FileServer, and the
# NodeLogQuery API when enableSystemLogQuery is on) and the /statusz and
# /flagz pages (ComponentStatusz/ComponentFlagz, Beta, on) of the kubelet
# and the API server.
class NodeSystemLogsAndZPagesTest < Minitest::Test
  Node = Rubernetes::Node
  ZPages = Rubernetes::Observability::ZPages

  def setup
    @dir = Dir.mktmpdir("rbn-varlog-")
    File.write(File.join(@dir, "syslog"), "line one\nline two\n")
    FileUtils.mkdir_p(File.join(@dir, "pods", "ns_p"))
    File.write(File.join(@dir, "kube-proxy.log"), "proxy started\n")
    File.write(File.join(@dir, "odd name?.log"), "x")
    @journal = []
  end

  def teardown = FileUtils.rm_rf(@dir)

  def logs(query_enabled: false, units: "")
    runner = lambda do |argv|
      @journal << argv
      argv.include?("--field") ? [units, true, true] : ["journal lines\n", true, true]
    end
    Node::SystemLogs.new(log_dir: @dir, query_enabled: query_enabled, runner: runner)
  end

  def body(response) = response.is_a?(Array) ? response[2].join : response.body.to_a.join

  def test_the_directory_is_listed_and_files_served_as_http_file_server_does
    status, headers, listing = logs.call("")
    assert_equal 200, status
    assert_equal "text/html; charset=utf-8", headers["content-type"]
    assert_equal "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n" \
                 "<a href=\"kube-proxy.log\">kube-proxy.log</a>\n<a href=\"odd%20name%3F.log\">odd name?.log</a>\n" \
                 "<a href=\"pods/\">pods/</a>\n<a href=\"syslog\">syslog</a>\n</pre>\n", listing.join
    file = logs.call("syslog")
    assert_equal 200, file.status
    assert_equal "line one\nline two\n", body(file)
    assert_equal [301, "pods/"], logs.call("pods").values_at(0).push(logs.call("pods")[1]["location"])
    assert_equal 404, logs.call("../etc/passwd")[0], "nothing outside the log directory"
    assert_equal 404, logs.call("missing")[0]
  end

  def test_queries_are_ignored_unless_enabled
    assert_equal "line one\nline two\n", body(logs.call("syslog", params: {"query" => ["kubelet"]}))
  end

  def test_a_service_query_reads_the_journal_or_the_heuristic_file
    response = logs(query_enabled: true, units: "kubelet.service\nsshd.service\n")
                 .call("", params: {"query" => ["kubelet"], "tailLines" => ["5"], "sinceTime" => ["2026-09-24T01:02:03Z"]})
    assert_equal 200, response[0]
    assert_equal "journal lines\n", response[2].join
    assert_equal ["journalctl", "--utc", "--no-pager", "--output=short-precise", "--since=2026-9-24 1:2:3", "--pager-end", "--lines=5",
                  "--unit=kubelet"], @journal.last
    assert_equal "proxy started\n", logs(query_enabled: true).call("", params: {"query" => ["kube-proxy"]})[2].join
    assert_equal "\nlog not found for nothing\n", logs(query_enabled: true).call("", params: {"query" => ["nothing"]})[2].join
    assert_match(/options present and query resolved to log files for \[kube-proxy\]/,
                 logs(query_enabled: true).call("", params: {"query" => ["kube-proxy"], "tailLines" => ["2"]})[2].join)
  end

  def test_query_validation_matches_upstream
    enabled = logs(query_enabled: true)
    assert_equal [406, "path not allowed in query mode\n"], enabled.call("syslog", params: {"query" => ["kubelet"]}).values_at(0, 2).then { |s, b| [s, b.join] }
    assert_equal 400, enabled.call("", params: {"tailLines" => ["x"]})[0]
    status, _, message = enabled.call("", params: {"query" => ["a", "b/c"]})
    assert_equal 406, status
    assert_equal %(query: Invalid value: "[b/c], [a]": cannot specify a file and service\n), message.join
    assert_equal "line one\nline two\n", body(enabled.call("", params: {"query" => ["/syslog"]})), "a file query serves that file"
    assert_match(/must be less than 1/, enabled.call("", params: {"query" => ["kubelet"], "boot" => ["1"]})[2].join)
  end

  def test_the_statusz_and_flagz_pages
    status, headers, text = ZPages.statusz(component: "kubelet", start_time: Time.utc(2026, 9, 24, 1, 0, 0), now: Time.utc(2026, 9, 24, 2, 1, 5),
                                           binary_version: "1.36.2", emulation_version: "1.36", paths: %w[/pods /healthz /api/v1],
                                           random: Random.new(3))
    assert_equal [200, "text/plain; charset=utf-8"], [status, headers["content-type"]]
    assert_match(/\A\nkubelet statusz\nWarning: This endpoint is not meant to be machine parseable/, text)
    assert_match(/^Up.* 1 hr 01 min 05 sec$/, text)
    assert_match(%r{^Paths.* /healthz /pods$}, text)
    _, headers, json = ZPages.statusz(component: "kubelet", start_time: Time.utc(2026, 9, 24), binary_version: "1.36.2",
                                      accept: "application/json;g=config.k8s.io;v=v1beta1;as=Statusz")
    object = JSON.parse(json)
    assert_equal %w[Statusz config.k8s.io/v1beta1 kubelet 2026-09-24T00:00:00Z], [object["kind"], object["apiVersion"], object.dig("metadata", "name"), object["startTime"]]
    assert_nil headers["warning"]
    assert_equal 406, ZPages.statusz(component: "k", start_time: Time.now, binary_version: "1", accept: "application/json")[0]
    _, _, flags = ZPages.flagz(component: "k", flags: ZPages.flags_from(arguments: ["--config=/etc/x.yml", "-v"], config: {"port" => 1, "tls" => {"token" => "t"}}),
                               accept: "application/yaml;g=config.k8s.io;v=v1alpha1;as=Flagz")
    assert_includes flags, "config: \"/etc/x.yml\""
    assert_includes flags, "tls.token: \"<redacted>\""
  end

  def test_the_kubelet_and_the_api_server_serve_them
    server = Node::StreamingServer.new(log_service: Object.new, port: 0, system_logs: logs, flags: {"node_name" => "n1"})
    request = ->(path) { Rubernetes::Transport::Request.new(method: "GET", target: path, headers: Rubernetes::Transport::Headers.new) }
    assert_equal 200, server.call(request.call("/statusz"))[0]
    assert_match(/node_name(: |:|=| )n1/, server.call(request.call("/flagz"))[2].join)
    assert_equal 200, server.call(request.call("/logs/syslog")).status
    disabled = Node::StreamingServer.new(log_service: Object.new, port: 0)
    assert_equal [405, ["logs endpoint is disabled.\n"]], disabled.call(request.call("/logs/")).values_at(0, 2)
    api = Rubernetes::API::Server.new
    response = api.call(Rubernetes::API::Request.new(method: "GET", path: "/statusz"))
    assert_equal 200, response.status
    assert_match(/kube-apiserver statusz/, response.body)
  end
end
