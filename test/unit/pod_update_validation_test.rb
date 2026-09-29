# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/schema/kubernetes_validator"

# ValidatePodUpdate's spec rules (kubernetes_validator/pod_update.rb).  The
# expected strings are what validation.ValidatePodUpdate of v1.36.2 returns
# for the same Pods (test/conformance/kubernetes/internal_pod_spec oracle);
# tools/differential/pod_update_diff_differential.rb compares the diff text
# on random Pods.
class PodUpdateValidationTest < Minitest::Test
  KV = Rubernetes::Schema::KubernetesValidator
  CONTAINER = {"name" => "c", "image" => "busybox", "imagePullPolicy" => "Always", "terminationMessagePolicy" => "File",
               "terminationMessagePath" => "/dev/termination-log"}.freeze
  TOLERATION = {"key" => "k", "operator" => "Equal", "value" => "v", "effect" => "NoExecute", "tolerationSeconds" => 5}.freeze
  A = {"key" => "a", "operator" => "In", "values" => ["x"]}.freeze
  B = {"key" => "b", "operator" => "Exists"}.freeze
  GATED = {"schedulingGates" => [{"name" => "g"}]}.freeze

  def pod(spec = {})
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "default", "resourceVersion" => "1"},
     "spec" => {"restartPolicy" => "Always", "dnsPolicy" => "ClusterFirst", "terminationGracePeriodSeconds" => 30,
                "schedulerName" => "default-scheduler", "containers" => [CONTAINER]}.merge(spec)}
  end

  def affinity(*terms)
    {"nodeAffinity" => {"requiredDuringSchedulingIgnoredDuringExecution" => {"nodeSelectorTerms" => terms.map { |exprs| {"matchExpressions" => exprs} }}}}
  end

  def errors(old, new)
    KV.pod_update_errors(new, "Pod", :update, old).map do |issue|
      cause = issue.to_cause(new)
      "#{cause["field"]}: #{cause["message"]}"
    end
  end

  def test_container_count_and_image_rules
    assert_equal ["spec.containers: Forbidden: pod updates may not add or remove containers"],
                 errors(pod, pod("containers" => [CONTAINER, CONTAINER.merge("name" => "d")]))
    assert_equal ["spec.containers[0].image: Invalid value: \" busybox\": must not have leading or trailing whitespace"],
                 errors(pod, pod("containers" => [CONTAINER.merge("image" => " busybox")]))
  end

  def test_active_deadline_seconds
    assert_equal ["spec.activeDeadlineSeconds: Invalid value: 20: must be less than or equal to previous value"],
                 errors(pod("activeDeadlineSeconds" => 10), pod("activeDeadlineSeconds" => 20))
    assert_equal ["spec.activeDeadlineSeconds: Invalid value: null: must not update from a positive integer to nil value"],
                 errors(pod("activeDeadlineSeconds" => 10), pod)
    assert_equal ["spec.activeDeadlineSeconds: Invalid value: 3000000000: must be between 0 and 2147483647, inclusive"],
                 errors(pod, pod("activeDeadlineSeconds" => 3_000_000_000))
  end

  def test_tolerations_and_scheduling_gates
    assert_empty errors(pod("tolerations" => [TOLERATION]), pod("tolerations" => [TOLERATION.merge("tolerationSeconds" => 9)]))
    assert_equal ["spec.tolerations: Forbidden: existing toleration can not be modified except its tolerationSeconds"],
                 errors(pod("tolerations" => [TOLERATION]), pod("tolerations" => [TOLERATION.merge("value" => "w")]))
    assert_equal ["spec.schedulingGates[1].name: Forbidden: only deletion is allowed, but found new scheduling gate 'g2'"],
                 errors(pod("schedulingGates" => [{"name" => "g1"}]), pod("schedulingGates" => [{"name" => "g1"}, {"name" => "g2"}]))
  end

  def test_gated_pods_may_extend_node_selector_and_affinity
    assert_empty errors(pod(GATED.merge("nodeSelector" => {"a" => "b"})), pod(GATED.merge("nodeSelector" => {"a" => "b", "c" => "d"})))
    assert_equal ["spec.nodeSelector: Invalid value: {\"a\":\"z\",\"c\":\"d\"}: only additions to spec.nodeSelector are allowed (no mutations or deletions)"],
                 errors(pod(GATED.merge("nodeSelector" => {"a" => "b"})), pod(GATED.merge("nodeSelector" => {"a" => "z", "c" => "d"})))
    assert_empty errors(pod(GATED.merge("affinity" => affinity([A]))), pod(GATED.merge("affinity" => affinity([A, B]))))
    assert_equal ["spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0]: Invalid value: " \
                  "{\"MatchExpressions\":[{\"Key\":\"b\",\"Operator\":\"Exists\",\"Values\":null}],\"MatchFields\":null}: " \
                  "only additions are allowed (no mutations or deletions)"],
                 errors(pod(GATED.merge("affinity" => affinity([A]))), pod(GATED.merge("affinity" => affinity([B]))))
    assert_equal ["spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms: Invalid value: " \
                  "[{\"MatchExpressions\":[{\"Key\":\"a\",\"Operator\":\"In\",\"Values\":[\"x\"]}],\"MatchFields\":null}," \
                  "{\"MatchExpressions\":[{\"Key\":\"b\",\"Operator\":\"Exists\",\"Values\":null}],\"MatchFields\":null}]: " \
                  "no additions/deletions to non-empty NodeSelectorTerms list are allowed"],
                 errors(pod(GATED.merge("affinity" => affinity([A]))), pod(GATED.merge("affinity" => affinity([A], [B]))))
  end

  def test_other_spec_changes_are_refused_with_the_internal_spec_diff
    expected = "spec: Forbidden: pod updates may not change fields other than `spec.containers[*].image`,`spec.initContainers[*].image`," \
               "`spec.activeDeadlineSeconds`,`spec.tolerations` (only additions to existing tolerations),`spec.terminationGracePeriodSeconds` " \
               "(allow it to be set to 1 if it was previously negative)\n@@ -40,7 +40,8 @@\n  \"ActiveDeadlineSeconds\": null,\n  \"DNSPolicy\": " \
               "\"ClusterFirst\",\n  \"NodeSelector\": {\n-  \"a\": \"b\"\n+  \"a\": \"b\",\n+  \"c\": \"d\"\n  },\n  \"ServiceAccountName\": \"\",\n" \
               "  \"AutomountServiceAccountToken\": null,\n"
    assert_equal [expected], errors(pod("nodeSelector" => {"a" => "b"}), pod("nodeSelector" => {"a" => "b", "c" => "d"}))
    # Semantic equality: an empty list or map equals an absent one; a grace
    # period set to 1 from a negative one is allowed.
    assert_empty errors(pod, pod("tolerations" => [], "nodeSelector" => {}))
    assert_empty errors(pod("terminationGracePeriodSeconds" => -1), pod("terminationGracePeriodSeconds" => 1))
  end

  # go-difflib: the autojunk heuristic (b of 200+ lines drops lines seen
  # more than 1% + 1 times from the index), hunk ranges and grouping.  The
  # expected texts were printed by vendor/github.com/pmezard/go-difflib.
  def test_go_difflib_unified_diff
    lib = KV::GoDiffLib
    a = lib.split_lines("a\nb\nc\nd\ne\nf\ng\nh\ni\nj")
    b = lib.split_lines("a\nb\nc\nD\ne\nf\ng\nh\ni\nJ\nk")
    assert_equal "@@ -1,10 +1,11 @@\n a\n b\n c\n-d\n+D\n e\n f\n g\n h\n i\n-j\n+J\n+k\n", lib.unified_diff(a, b)
    long_a = lib.split_lines((["}"] * 150 + ["x"] + ["}"] * 100).join("\n"))
    long_b = lib.split_lines((["}"] * 150 + ["y"] + ["}"] * 100).join("\n"))
    # Every "}" is popular: after the "x"/"y" line nothing re-anchors, so the
    # tail is replaced wholesale -- exactly what go-difflib prints.
    assert_equal "@@ -148,104 +148,104 @@\n }\n }\n }\n-x\n#{"-}\n" * 100}+y\n#{"+}\n" * 100}", lib.unified_diff(long_a, long_b)
    assert_equal "", lib.unified_diff(a, a)
    assert_equal "@@ -0,0 +1 @@\n+x\n", lib.unified_diff([], ["x\n"])
  end
end
