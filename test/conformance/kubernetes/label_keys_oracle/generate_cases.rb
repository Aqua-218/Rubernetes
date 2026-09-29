# frozen_string_literal: true

# Writes cases.json for the label-keys oracle (see oracle_test.go).
require "json"

def pod(labels: {"app" => "web", "tier" => "front"}, affinity: nil, spread: nil)
  spec = {"containers" => [{"name" => "c", "image" => "i", "imagePullPolicy" => "IfNotPresent",
                            "terminationMessagePolicy" => "File"}],
          "restartPolicy" => "Always", "dnsPolicy" => "ClusterFirst"}
  spec["affinity"] = affinity if affinity
  spec["topologySpreadConstraints"] = spread if spread
  {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "labels" => labels}, "spec" => spec}
end

def term(selector: {"matchLabels" => {"app" => "web"}}, match: nil, mismatch: nil)
  entry = {"topologyKey" => "kubernetes.io/hostname"}
  entry["labelSelector"] = selector if selector
  entry["matchLabelKeys"] = match if match
  entry["mismatchLabelKeys"] = mismatch if mismatch
  entry
end

def affinity(kind: "podAffinity", required: [], preferred: [])
  section = {}
  section["requiredDuringSchedulingIgnoredDuringExecution"] = required unless required.empty?
  unless preferred.empty?
    section["preferredDuringSchedulingIgnoredDuringExecution"] = preferred.map { |t| {"weight" => 10, "podAffinityTerm" => t} }
  end
  {kind => section}
end

def spread(selector: {"matchLabels" => {"app" => "web"}}, match: nil)
  entry = {"maxSkew" => 1, "topologyKey" => "zone", "whenUnsatisfiable" => "DoNotSchedule"}
  entry["labelSelector"] = selector if selector
  entry["matchLabelKeys"] = match if match
  entry
end

cases = []
add = ->(name, mode, new, old = nil) { cases << {"name" => name, "mode" => mode, "new" => new, "old" => old}.compact }

add.("affinity_merge", "create", pod(affinity: affinity(required: [term(match: ["tier"], mismatch: ["app2"])])))
add.("affinity_mismatch_merge", "create", pod(labels: {"app" => "web", "track" => "canary"},
                                               affinity: affinity(kind: "podAntiAffinity", required: [term(mismatch: ["track"])])))
add.("affinity_missing_label", "create", pod(affinity: affinity(required: [term(match: ["absent"])])))
add.("affinity_nil_selector", "create", pod(affinity: affinity(required: [term(selector: nil, match: ["tier"])])))
add.("affinity_dup_matchlabels", "create", pod(affinity: affinity(required: [term(match: ["app"])])))
add.("affinity_dup_expression", "create", pod(affinity: affinity(required: [term(selector: {"matchExpressions" => [{"key" => "tier", "operator" => "In", "values" => ["x"]}]}, match: ["tier"])])))
add.("affinity_match_mismatch_dup", "create", pod(affinity: affinity(required: [term(match: ["tier"], mismatch: ["tier"])])))
add.("affinity_bad_key", "create", pod(affinity: affinity(required: [term(match: ["-bad"])])))
add.("affinity_preferred", "create", pod(affinity: affinity(preferred: [term(match: ["tier"])])))
add.("affinity_preferred_dup", "create", pod(affinity: affinity(kind: "podAntiAffinity", preferred: [term(match: ["app"])])))
add.("spread_merge", "create", pod(spread: [spread(match: ["tier"])]))
add.("spread_dup_matchlabels", "create", pod(spread: [spread(match: ["app"])]))
add.("spread_dup_expression", "create", pod(spread: [spread(selector: {"matchExpressions" => [{"key" => "tier", "operator" => "Exists"}]}, match: ["tier"])]))
add.("spread_nil_selector", "create", pod(spread: [spread(selector: nil, match: ["tier"])]))
add.("spread_bad_key", "create", pod(spread: [spread(match: ["bad key"])]))
add.("spread_missing_label", "create", pod(spread: [spread(match: ["absent", "tier"])]))
# Updates: a stored (already merged) Pod, and one whose old spec only passes
# the legacy rule.
merged = pod(spread: [spread(selector: {"matchLabels" => {"app" => "web"},
                                        "matchExpressions" => [{"key" => "tier", "operator" => "In", "values" => ["front"]}]}, match: ["tier"])])
add.("update_merged", "update", merged, merged)
legacy_old = pod(spread: [spread(selector: {"matchExpressions" => [{"key" => "tier", "operator" => "In", "values" => ["front"]},
                                                                    {"key" => "tier", "operator" => "In", "values" => ["front"]}]}, match: ["tier"])])
add.("update_old_violates", "update", legacy_old, legacy_old)
# Templates: validated without the merge.
add.("template_dup_matchlabels", "template", pod(spread: [spread(match: ["app"])], affinity: affinity(required: [term(match: ["app"])])))
add.("template_dup_expression", "template", pod(spread: [spread(selector: {"matchExpressions" => [{"key" => "tier", "operator" => "In", "values" => ["a"]}]}, match: ["tier"])]))
add.("template_ok", "template", pod(spread: [spread(match: ["pod-template-hash"])], affinity: affinity(required: [term(match: ["pod-template-hash"])])))
add.("template_nil_selector", "template", pod(spread: [spread(selector: nil, match: ["x"])]))

File.write(File.join(__dir__, "cases.json"), JSON.pretty_generate(cases))
puts "#{cases.length} cases"
