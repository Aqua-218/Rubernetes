# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/k7_lifecycle"

class K7LifecycleStateTest < Minitest::Test
  LIFECYCLE = Conformance::K7Lifecycle

  def state(fields, kind: "Node")
    {"available" => true, "objects" => [
      {"kind" => kind, "name" => "test-object", "uid" => "test-uid",
       "managed_fields" => LIFECYCLE.managed_fields(fields, kind: kind)}
    ]}
  end

  def owned_fields(fields, **entry)
    {"manager" => "kubelet", "operation" => "Update", "apiVersion" => "v1",
     "fieldsType" => "FieldsV1", "fieldsV1" => fields}.merge(entry.transform_keys(&:to_s))
  end

  def test_first_status_write_after_restart_does_not_signal_ownership_loss
    registration = owned_fields({"f:metadata" => {"f:labels" => {"f:kubernetes.io/hostname" => {}}}}, time: "2026-11-18T10:00:00Z")
    expanded = owned_fields({"f:metadata" => {"f:labels" => {"f:kubernetes.io/hostname" => {}, "f:kubernetes.io/os" => {}}}},
                            time: "2026-11-18T10:01:00Z")
    status = owned_fields({"f:status" => {"f:conditions" => {}}}, subresource: "status")

    assert_empty LIFECYCLE.compare_state(state([registration]), state([expanded, status]))
  end

  def test_an_unchanged_node_uid_does_not_hide_loss_of_field_ownership
    registration = owned_fields({"f:metadata" => {"f:labels" => {"f:kubernetes.io/hostname" => {}}}})
    moved = registration.merge("manager" => "other")

    assert_equal "managedFields ownership was lost", LIFECYCLE.compare_state(state([registration]), state([moved])).first.fetch("reason")
  end

  def test_a_parent_marker_keeps_ownership_of_a_field_with_new_children
    registration = owned_fields({"f:metadata" => {"f:annotations" => {}}})
    expanded = owned_fields({"f:metadata" => {"f:annotations" => {"." => {}, "f:status" => {}}}})

    assert_empty LIFECYCLE.compare_state(state([registration]), state([expanded]))
  end

  def test_reallocated_pod_ip_keeps_field_ownership
    addresses = lambda do |*ips|
      selectors = ips.to_h { |ip| ["k:#{JSON.generate("ip" => ip)}", {"." => {}, "f:ip" => {}}] }
      entry = owned_fields({"f:status" => {"f:podIPs" => selectors}}, subresource: "status")
      state([entry], kind: "Pod")
    end

    before = addresses.call("10.240.0.2", "fd00::2")

    assert_empty LIFECYCLE.compare_state(before, addresses.call("10.240.0.3", "fd00::3"))
    loss = LIFECYCLE.compare_state(before, addresses.call("10.240.0.3"))

    assert_equal "managedFields ownership was lost", loss.first.fetch("reason")
  end

  def test_baseline_requires_a_pod_and_an_attached_volume
    attachments = [{"kind" => "VolumeAttachment", "volumes" => {"attached" => false}}]
    summary = LIFECYCLE.baseline_summary({"objects" => attachments})

    assert_equal 1, summary.fetch("baseline_volume_attachments")
    assert_equal 0, summary.fetch("baseline_attached_volumes")
    assert_equal ["Pod identity", "attached VolumeAttachment"], summary.fetch("baseline_missing")

    objects = [{"kind" => "Pod", "ready" => true}, {"kind" => "VolumeAttachment", "volumes" => {"attached" => true}}]
    summary = LIFECYCLE.baseline_summary({"objects" => objects})

    assert_equal 1, summary.fetch("baseline_pods")
    assert_equal 1, summary.fetch("baseline_attached_volumes")
    assert_empty summary.fetch("baseline_missing")
  end

  def test_whole_run_tracks_a_ready_pod_that_remains_unknown_after_restart
    identity = {"kind" => "Pod", "name" => "stateful", "namespace" => "test", "uid" => "uid-1"}
    workload = {"kind" => "Pod", "metadata" => identity.except("kind"),
                "status" => {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => "True"}]}}

    assert_empty LIFECYCLE.unavailable_workloads([identity], [workload])
    workload.fetch("status")["phase"] = "Unknown"

    assert_equal [identity.merge("reason" => "baseline workload did not recover to Ready", "phase" => "Unknown")],
                 LIFECYCLE.unavailable_workloads([identity], [workload])
  end

  def test_deployment_status_and_hash_key_order_can_change_but_desired_spec_must_persist
    deployment = resource("apps/v1", "Deployment", "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "api"}}})
    after = deployment.merge("spec" => deployment.fetch("spec").to_a.reverse.to_h, "status" => {"readyReplicas" => 1},
                             "metadata" => deployment.fetch("metadata").merge("resourceVersion" => "2"))

    assert_empty compare_resources(deployment, after)

    after.fetch("spec")["replicas"] = 2

    assert_equal "declared content changed", compare_resources(deployment, after).first.fetch("reason")
  end

  def test_node_health_taints_can_change_but_operator_taints_must_persist
    node = resource("v1", "Node", "spec" => {"taints" => [
                      {"key" => "node.kubernetes.io/unreachable", "effect" => "NoExecute"},
                      {"key" => "test.example/maintenance", "effect" => "NoSchedule"}
                    ]})
    after = node.merge("spec" => {"taints" => node.dig("spec", "taints").last(1)})

    assert_empty compare_resources(node, after)

    assert_equal "declared content changed", compare_resources(node, after.merge("spec" => {})).first.fetch("reason")
  end

  def test_rbac_rules_subjects_and_role_ref_are_compared_without_revealing_values
    version = "rbac.authorization.k8s.io/v1"
    policy = lambda do |name|
      {"rules" => [{"apiGroups" => [""], "resources" => ["secrets"], "resourceNames" => [name], "verbs" => ["get"]}],
       "subjects" => [{"kind" => "User", "name" => name}], "roleRef" => {"kind" => "ClusterRole", "name" => name}}
    end
    original = policy.call("before")
    changed = policy.call("sensitive-new-value")
    original.each do |field, value|
      kind = field == "rules" ? "ClusterRole" : "ClusterRoleBinding"
      object = resource(version, kind, field => value)
      loss = compare_resources(object, object.merge(field => changed.fetch(field)))

      assert_equal "declared content changed", loss.first.fetch("reason")
      refute_includes JSON.generate(loss), "sensitive-new-value"
    end
  end

  def test_attachment_status_keeps_the_attached_flag_and_compares_metadata_without_revealing_it
    status = {"attached" => true, "attachmentMetadata" => {"token" => "private-attachment-token"}}
    attachment = resource("storage.k8s.io/v1", "VolumeAttachment", "spec" => {"nodeName" => "worker"}, "status" => status)
    before = resource_state(attachment)
    after = attachment.merge("status" => {"attached" => true, "attachmentMetadata" => {"token" => "different-token"}})

    assert_equal 1, LIFECYCLE.baseline_summary(before).fetch("baseline_attached_volumes")
    refute_includes JSON.generate(before), "private-attachment-token"
    assert_equal "volumes changed", compare_resources(attachment, after).first.fetch("reason")
  end

  def test_custom_resources_can_share_a_builtin_kind_name_and_use_non_spec_payload
    builtin = resource("apps/v1", "Deployment", "spec" => {"replicas" => 1})
    custom = resource("test.example/v1", "Deployment", "configuration" => {"host" => "first"})
    after = custom.merge("configuration" => {"host" => "second"})
    loss = LIFECYCLE.compare_state(resource_state(builtin, custom), resource_state(after, builtin))

    assert_equal [{"object" => ["test.example", "Deployment", "test", "test-object"], "reason" => "declared content changed"}], loss
  end

  def test_crd_schema_change_and_loss_of_established_condition_are_detected
    crd = established_crd
    changed = crd.merge("spec" => crd.fetch("spec").merge("conversion" => {"strategy" => "Webhook"}))

    assert_equal "declared content changed", compare_resources(crd, changed).first.fetch("reason")
    assert_equal "CRD stopped serving", compare_resources(crd, crd.except("status")).first.fetch("reason")
  end

  def test_inventory_reads_custom_collection_pages_and_checks_each_served_version
    calls = []
    collection = "/apis/test.example/v1/widgets"
    second = resource("test.example/v1", "Widget", "settings" => {"value" => "token-should-only-be-hashed"})
    first = second.merge("metadata" => {"name" => "first", "namespace" => "test", "uid" => "first-uid"})
    replies = {
      [collection, nil] => list(first, token: "a+/="),
      [collection, "a+/="] => list(second)
    }
    state = capture(replies, calls: calls)

    assert state.fetch("available"), state.fetch("read_error", nil)
    assert_equal(%w[first test-object], state.fetch("objects").select { |item| item["kind"] == "Widget" }.map { |item| item.fetch("name") })
    assert_includes calls, ["/apis/test.example/v2", nil]
    assert_includes calls, [collection, "a+/="]
    refute_includes JSON.generate(state), "token-should-only-be-hashed"
  end

  def test_failed_dynamic_discovery_and_list_fail_the_capture_without_response_bodies
    ["/apis/test.example/v2", "/apis/test.example/v1/widgets"].each do |path|
      state = capture({[path, nil] => :forbidden})

      refute state.fetch("available")
      assert_empty state.fetch("objects")
      assert_includes state.fetch("read_error"), path
      refute_includes JSON.generate(state), "private-response"
      assert_equal "post-stage state was not readable", LIFECYCLE.compare_state(resource_state, state).first.fetch("reason")
    end
  end

  def test_missing_listable_discovery_never_looks_like_an_empty_collection
    state = capture({["/apis/test.example/v2", nil] => {"groupVersion" => "test.example/v2", "resources" => []}})

    refute state.fetch("available")
    assert_includes state.fetch("read_error"), "not listable"
  end

  private

  def resource(version, kind, fields)
    {"apiVersion" => version, "kind" => kind, "metadata" => {"name" => "test-object", "namespace" => "test", "uid" => "test-uid"}}.merge(fields)
  end

  def resource_state(*items)
    {"available" => true, "objects" => items.map { |item| LIFECYCLE.object_snapshot(item) }}
  end

  def compare_resources(before, after)
    LIFECYCLE.compare_state(resource_state(before), resource_state(after))
  end

  def established_crd
    resource("apiextensions.k8s.io/v1", "CustomResourceDefinition",
             "spec" => {"group" => "test.example", "names" => {"kind" => "Widget", "plural" => "widgets"}, "scope" => "Namespaced",
                        "versions" => [{"name" => "v2", "storage" => false, "served" => true}, {"name" => "v1", "storage" => true, "served" => true}]},
             "status" => {"conditions" => [{"type" => "Established", "status" => "True"}]})
  end

  def list(*items, token: "")
    {"metadata" => {"continue" => token}, "items" => items}
  end

  def capture(replies, calls: [])
    response = lambda do |*args|
      path, query = args.include?("--raw") ? args.last.split("?", 2) : [:builtin, nil]
      key = [path, URI.decode_www_form(query.to_s).to_h["continue"]]
      calls << key
      body = replies.fetch(key) do
        case path
        when Conformance::K7StateInventory::CRD_PATH then list(established_crd)
        when "/apis/test.example/v1", "/apis/test.example/v2"
          {"groupVersion" => path.delete_prefix("/apis/"),
           "resources" => [{"name" => "widgets", "kind" => "Widget", "namespaced" => true, "verbs" => ["list"]}]}
        else list
        end
      end
      status = Struct.new(:exitstatus) { def success? = exitstatus.zero? }.new(body == :forbidden ? 1 : 0)
      [JSON.generate(body), "private-response", status]
    end
    Open3.stub(:capture3, response) { LIFECYCLE.capture_state(kubeconfig: "/unused") }
  end
end
