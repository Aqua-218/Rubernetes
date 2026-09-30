#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m4_probe_support"

M4ProbeSupport.run_report(kind: "m4_policy_differential", adapter_name: "policy-differential-probe") do |_input, errors|
  engine_class = M4ProbeSupport.constant("Rubernetes::Network::PolicyEngine")
  unless engine_class.is_a?(Class)
    errors << "production NetworkPolicy engine is unavailable"
    next {"measurement_source" => "missing_production_module", "cases" => []}
  end

  source = {"namespace" => "default", "labels" => {"role" => "client"}, "ip" => "10.0.0.10", "ports" => {}}
  destination = {"namespace" => "default", "labels" => {"app" => "server"}, "ip" => "10.0.0.20",
                 "ports" => {"http" => 8080}}
  make_policy = lambda do |name, spec|
    {"metadata" => {"name" => name, "namespace" => "default"}, "spec" => spec}
  end
  oracle_fixtures = {}
  cases = []
  evaluate_case = lambda do |id, policy, expected, protocol: "TCP", port: nil, end_port: nil|
    engine = engine_class.new
    engine.apply([policy], revision: 1)
    actual = engine.allowed?(source: source, destination: destination, direction: "ingress",
                             protocol: protocol, port: port, end_port: end_port)
    passed = expected == actual
    errors << "NetworkPolicy #{id} oracle mismatch" unless passed
    cases << {"id" => id, "case" => id, "expected" => expected, "actual" => actual,
              "passed" => passed, "attempt_count" => 1, "measurement_source" => "production_module",
              "identity_set_sha256" => M4ProbeSupport.digest(engine.identity_set)}
    # Give the independent runner the policy/input fixture, never the local
    # expected boolean.  Echoing a probe-supplied answer is not independent
    # NetworkPolicy evidence.
    oracle_fixtures[id] = {"policy" => policy, "source" => source,
                           "destination" => destination, "direction" => "ingress",
                           "protocol" => protocol, "port" => port, "end_port" => end_port}
  end

  evaluate_case.call("default_deny", make_policy.call("default-deny", {
                                                        "podSelector" => {"matchLabels" => {"app" => "server"}}, "policyTypes" => ["Ingress"]
                                                      }), false)
  evaluate_case.call("selector", make_policy.call("selector", {
                                                    "podSelector" => {"matchLabels" => {"app" => "server"}}, "policyTypes" => ["Ingress"],
                                                    "ingress" => [{"from" => [{"podSelector" => {"matchLabels" => {"role" => "client"}}}]}]
                                                  }), true)
  evaluate_case.call("named_port", make_policy.call("named-port", {
                                                      "podSelector" => {"matchLabels" => {"app" => "server"}}, "policyTypes" => ["Ingress"],
                                                      "ingress" => [{"ports" => [{"protocol" => "TCP", "port" => "http"}]}]
                                                    }), true, port: "http")
  evaluate_case.call("end_port", make_policy.call("end-port", {
                                                    "podSelector" => {"matchLabels" => {"app" => "server"}}, "policyTypes" => ["Ingress"],
                                                    "ingress" => [{"ports" => [{"protocol" => "TCP", "port" => 8000, "endPort" => 8002}]}]
                                                  }), true, port: 8001, end_port: 8002)
  evaluate_case.call("sctp", make_policy.call("sctp", {
                                                "podSelector" => {"matchLabels" => {"app" => "server"}}, "policyTypes" => ["Ingress"],
                                                "ingress" => [{"ports" => [{"protocol" => "SCTP", "port" => 9999}]}]
                                              }), true, protocol: "SCTP", port: 9999)

  oracle_document = M4ProbeSupport.run_external_json(
    env_keys: %w[RUBERNETES_M4_NETWORK_POLICY_ORACLE_COMMAND RUBERNETES_M4_CNI_NETWORK_POLICY_ORACLE_COMMAND],
    input: {"kubernetes_version" => M3ProbeSupport::KUBERNETES_VERSION,
            "source_commit" => M3ProbeSupport::KUBERNETES_SOURCE_COMMIT,
            "case_ids" => cases.map { |entry| entry["id"] },
            "cases" => cases.map { |entry| {"id" => entry["id"], "fixture" => oracle_fixtures.fetch(entry["id"])} }},
    errors: errors,
    label: "external CNI/network-policy oracle"
  )
  runner = oracle_document.is_a?(Hash) ? oracle_document["runner"] : nil
  oracle_comparisons = oracle_document.is_a?(Hash) ? oracle_document["comparisons"] : nil
  comparison_by_id = Array(oracle_comparisons).filter_map do |comparison|
    next unless comparison.is_a?(Hash) && comparison["id"]

    [comparison["id"].to_s, comparison]
  end.to_h
  errors << "network-policy oracle did not return runner provenance" unless runner.is_a?(Hash)
  cases.each do |entry|
    # The observable is the reachability verdict alone.  The engine's
    # identity-set digest stays on the case record as provenance; an
    # independent CNI oracle cannot (and must not) reproduce it.
    actual_observable = {"allowed" => entry["actual"] == true}
    oracle_expected = comparison_by_id.dig(entry["id"], "expected_observable")
    expected_observable = oracle_expected.is_a?(Hash) && oracle_expected.key?("allowed") ? {"allowed" => oracle_expected["allowed"] == true} : nil
    entry["actual_observable"] = actual_observable
    entry["expected_observable"] = expected_observable
    entry["actual_sha256"] = M4ProbeSupport.digest(actual_observable)
    entry["expected_sha256"] = M4ProbeSupport.digest(expected_observable || {"missing" => entry["id"]})
    entry["passed"] = expected_observable.is_a?(Hash) && entry["actual_sha256"] == entry["expected_sha256"]
    errors << "NetworkPolicy #{entry.fetch("id")} did not match the external oracle" unless entry["passed"]
  end
  mismatch = cases.count { |entry| entry["passed"] != true }
  comparisons = cases.map do |entry|
    {"id" => entry["id"], "passed" => entry["passed"], "expected_observable" => entry["expected_observable"],
     "actual_observable" => entry["actual_observable"], "expected_sha256" => entry["expected_sha256"],
     "actual_sha256" => entry["actual_sha256"]}
  end
  {
    "measurement_source" => "production_module",
    "adapter_class" => "Rubernetes::Network::PolicyEngine",
    "cases" => cases,
    "oracle" => {"executed" => oracle_document.is_a?(Hash), "version" => runner.is_a?(Hash) ? runner["version"] : nil,
                 "source_commit" => runner.is_a?(Hash) ? runner["source_commit"] : nil,
                 "runner_sha256" => runner.is_a?(Hash) ? runner["runner_sha256"] : nil,
                 "runner" => runner,
                 "comparison_count" => cases.length,
                 "comparisons" => comparisons},
    "difference_count" => mismatch,
    "default_deny_bypass_count" => cases.find { |entry| entry["id"] == "default_deny" && entry["actual"] } ? 1 : 0,
    "selector_mismatch_count" => cases.find { |entry| entry["id"] == "selector" && entry["expected"] != entry["actual"] } ? 1 : 0,
    "named_port_mismatch_count" => cases.find { |entry| entry["id"] == "named_port" && entry["expected"] != entry["actual"] } ? 1 : 0,
    "end_port_mismatch_count" => cases.find { |entry| entry["id"] == "end_port" && entry["expected"] != entry["actual"] } ? 1 : 0,
    "sctp_mismatch_count" => cases.find { |entry| entry["id"] == "sctp" && entry["expected"] != entry["actual"] } ? 1 : 0
  }
end
