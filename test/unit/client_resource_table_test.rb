# frozen_string_literal: true

require "test_helper"
require "rubernetes/client/output"

# `rubectl get pods -o wide` prints kubectl's columns, not a JSON document.
class ClientResourceTableTest < Minitest::Test
  NOW = Time.utc(2026, 11, 23, 12, 0, 0)

  def pod(name, created:, ready: true, node: "worker-1", ip: "10.240.0.9", **status)
    {"kind" => "Pod", "metadata" => {"name" => name, "creationTimestamp" => created},
     "spec" => {"nodeName" => node, "containers" => [{"name" => "app"}, {"name" => "sidecar"}]},
     "status" => {"phase" => "Running", "podIP" => ip,
                  "containerStatuses" => [{"ready" => ready, "restartCount" => 1, "state" => {"running" => {}}},
                                          {"ready" => true, "restartCount" => 2, "state" => {"running" => {}}}]}.merge(status)}
  end

  def render(value, format) = Rubernetes::Client::Output.new(format: format, now: NOW).render(value)

  def test_pods_print_kubectl_columns_and_wide_adds_ip_and_node
    list = {"kind" => "PodList", "items" => [pod("web-1", created: "2026-11-23T11:55:00Z"),
                                             pod("db-0", created: "2026-10-03T12:00:00Z", ready: false)]}

    assert_equal <<~TABLE.chomp, render(list, "table")
      NAME    READY   STATUS    RESTARTS   AGE
      web-1   2/2     Running   3          5m
      db-0    1/2     Running   3          51d
    TABLE
    assert_match(/\ANAME\s+READY\s+STATUS\s+RESTARTS\s+AGE\s+IP\s+NODE\n/, render(list, "wide"))
    assert_match(/web-1\s+2\/2\s+Running\s+3\s+5m\s+10\.240\.0\.9\s+worker-1/, render(list, "wide"))
  end

  def test_status_shows_waiting_init_and_terminating_like_kubectl
    crashing = pod("a", created: "2026-11-23T11:00:00Z")
    crashing["status"]["containerStatuses"][0]["state"] = {"waiting" => {"reason" => "CrashLoopBackOff"}}
    init = pod("b", created: "2026-11-23T11:00:00Z")
    init["spec"]["initContainers"] = [{"name" => "setup"}, {"name" => "configure"}]
    init["status"]["initContainerStatuses"] = [{"state" => {"terminated" => {"exitCode" => 0, "reason" => "Completed"}}},
                                               {"state" => {"waiting" => {"reason" => "CrashLoopBackOff"}}}]
    deleting = pod("c", created: "2026-11-23T11:00:00Z")
    deleting["metadata"]["deletionTimestamp"] = "2026-11-23T11:59:00Z"
    rows = render({"kind" => "PodList", "items" => [crashing, init, deleting]}, "table").lines.drop(1)

    assert_equal %w[CrashLoopBackOff Init:CrashLoopBackOff Terminating], rows.map { |row| row.split[2] }
  end

  def test_nodes_print_status_roles_and_version
    node = {"kind" => "Node", "metadata" => {"name" => "worker-0", "creationTimestamp" => "2026-10-03T12:00:00Z", "labels" => {}},
            "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}], "nodeInfo" => {"kubeletVersion" => "v1.36.2"}}}

    assert_equal "NAME       STATUS   ROLES    AGE   VERSION\nworker-0   Ready    <none>   51d   v1.36.2", render({"kind" => "NodeList", "items" => [node]}, "table")
  end

  def test_other_kinds_print_name_and_age_and_an_empty_list_says_so
    list = {"kind" => "ConfigMapList", "items" => [{"metadata" => {"name" => "settings", "creationTimestamp" => "2026-11-23T09:00:00Z"}}]}

    assert_equal "NAME       AGE\nsettings   3h", render(list, "table")
    assert_equal "No resources found.", render({"kind" => "PodList", "items" => []}, "table")
  end
end
