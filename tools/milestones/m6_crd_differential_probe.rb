#!/usr/bin/env ruby
# frozen_string_literal: true

# M6 exit criteria 3 and (aggregation half of) 4: the same
# CustomResourceDefinition, custom resources and APIService are submitted to
# the production API server and to the pinned kube-apiserver oracle (Docker,
# same cluster the M1 differential uses); the observable responses are
# normalized and compared: HTTP status, Status reason/causes, defaulting,
# pruning, CEL validation messages, status subresource behaviour, CRD
# conditions, discovery entries, OpenAPI v3 paths, and the aggregated
# APIService availability condition.

require_relative "m6_probe_support"
require_relative "m1_kubernetes_oracle"

module M6CRDDifferentialProbe
  VOLATILE = %w[uid resourceVersion creationTimestamp managedFields generation selfLink lastTransitionTime].freeze

  class OracleClient
    def initialize(client)
      @client = client
    end

    def call(method, path, body: nil, headers: {})
      response = @client.request(method: method.downcase.to_sym, path: path, body: body && JSON.generate(body), headers: headers)
      [response.status, response.body]
    end
  end

  class LocalClient
    def initialize(service)
      @service = service
    end

    def call(method, path, body: nil, headers: {})
      response = M6ProbeSupport.request(@service, method, path, body: body, token: "admin-token", headers: headers)
      [response.status, response.body]
    end
  end

  module_function

  def crd
    schema = {"type" => "object", "properties" => {
      "spec" => {"type" => "object", "required" => ["size"],
                 "properties" => {"size" => {"type" => "integer", "minimum" => 1, "maximum" => 10},
                                  "color" => {"type" => "string", "default" => "blue", "enum" => %w[blue red]},
                                  "tags" => {"type" => "array", "items" => {"type" => "string"}, "x-kubernetes-list-type" => "set"}},
                 "x-kubernetes-validations" => [{"rule" => "self.size <= 5 || self.color == 'red'", "message" => "large widgets must be red"}]},
      "status" => {"type" => "object", "properties" => {"ready" => {"type" => "boolean"}}}
    }}
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "widgets.probe.example.com"},
     "spec" => {"group" => "probe.example.com", "scope" => "Namespaced",
                "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget", "shortNames" => ["wd"]},
                "versions" => [{"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema},
                                "subresources" => {"status" => {}}},
                               {"name" => "v2", "served" => true, "storage" => false, "schema" => {"openAPIV3Schema" => schema}}]}}
  end

  def widget(name, spec)
    {"apiVersion" => "probe.example.com/v1", "kind" => "Widget", "metadata" => {"name" => name, "namespace" => "default"}, "spec" => spec}
  end

  def apiservice
    {"apiVersion" => "apiregistration.k8s.io/v1", "kind" => "APIService", "metadata" => {"name" => "v1beta1.metrics.probe.example.com"},
     "spec" => {"group" => "metrics.probe.example.com", "version" => "v1beta1",
                "service" => {"namespace" => "default", "name" => "no-such-service", "port" => 443},
                "groupPriorityMinimum" => 100, "versionPriority" => 100, "insecureSkipTLSVerify" => true}}
  end

  # Ordered request script; each step yields an observable that must match.
  def script
    [
      ["create_crd", "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", crd],
      ["wait_established", :wait_established, nil, nil],
      ["get_crd_conditions", "GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.probe.example.com", nil],
      ["discovery_group", "GET", "/apis/probe.example.com", nil],
      ["discovery_v1", "GET", "/apis/probe.example.com/v1", nil],
      ["openapi_v3", "GET", "/openapi/v3/apis/probe.example.com/v1", nil],
      ["create_invalid_min", "POST", "/apis/probe.example.com/v1/namespaces/default/widgets", widget("w1", {"size" => 0})],
      ["create_missing_required", "POST", "/apis/probe.example.com/v1/namespaces/default/widgets", widget("w1", {"color" => "blue"})],
      ["create_bad_enum", "POST", "/apis/probe.example.com/v1/namespaces/default/widgets", widget("w1", {"size" => 2, "color" => "green"})],
      ["create_cel_violation", "POST", "/apis/probe.example.com/v1/namespaces/default/widgets", widget("w1", {"size" => 8})],
      ["create_duplicate_set_item", "POST", "/apis/probe.example.com/v1/namespaces/default/widgets",
       widget("w1", {"size" => 2, "tags" => %w[a a]})],
      ["create_ok", "POST", "/apis/probe.example.com/v1/namespaces/default/widgets", widget("w1", {"size" => 3, "junk" => "x"})],
      ["get_ok", "GET", "/apis/probe.example.com/v1/namespaces/default/widgets/w1", nil],
      ["get_via_v2", "GET", "/apis/probe.example.com/v2/namespaces/default/widgets/w1", nil],
      ["list", "GET", "/apis/probe.example.com/v1/namespaces/default/widgets", nil],
      ["status_update", :status_update, nil, nil],
      ["get_after_status", "GET", "/apis/probe.example.com/v1/namespaces/default/widgets/w1", nil],
      ["patch_merge", "PATCH", "/apis/probe.example.com/v1/namespaces/default/widgets/w1", {"spec" => {"color" => "red", "size" => 7}},
       {"content-type" => "application/merge-patch+json"}],
      ["create_apiservice", "POST", "/apis/apiregistration.k8s.io/v1/apiservices", apiservice],
      ["wait_apiservice", :wait_apiservice, nil, nil],
      ["discovery_with_apiservice", "GET", "/apis", nil],
      ["aggregated_unavailable", "GET", "/apis/metrics.probe.example.com/v1beta1/nodes", nil],
      ["delete_apiservice", "DELETE", "/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.probe.example.com", nil],
      ["delete_crd", "DELETE", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.probe.example.com", nil],
      ["wait_gone", :wait_gone, nil, nil],
      ["get_after_delete", "GET", "/apis/probe.example.com/v1/namespaces/default/widgets/w1", nil]
    ]
  end

  def normalize(step, status, body)
    document = body.is_a?(Hash) ? deep_strip(body) : body
    case step
    when "get_crd_conditions"
      conditions = Array(document.dig("status", "conditions")).map do |condition|
        condition.slice("type", "status", "reason")
      end.sort_by { |condition| condition["type"] }
      {"status" => status, "conditions" => conditions.reject do |condition|
        condition["type"] == "NonStructuralSchema" && condition["status"] == "False"
      end,
       "acceptedNames" => document.dig("status", "acceptedNames"), "storedVersions" => document.dig("status", "storedVersions")}
    when "discovery_group"
      {"status" => status, "name" => document["name"], "versions" => document["versions"],
       "preferredVersion" => document["preferredVersion"]}
    when "discovery_v1"
      {"status" => status, "resources" => Array(document["resources"]).map do |resource|
        resource.slice("name", "singularName", "namespaced", "kind", "verbs", "shortNames", "storageVersionHash").reject do |key, _|
          key == "storageVersionHash"
        end
      end}
    when "openapi_v3"
      {"status" => status, "paths" => Array(document["paths"]&.keys).sort, "operations" => (document["paths"] || {}).transform_values do |operations|
        operations.keys.sort
      end}
    when "discovery_with_apiservice"
      {"status" => status, "group" => Array(document["groups"]).find { |group| group["name"] == "metrics.probe.example.com" }}
    when "list"
      {"status" => status, "kind" => document["kind"], "names" => Array(document["items"]).map { |item| item.dig("metadata", "name") }}
    when "aggregated_unavailable"
      {"status" => status, "reason" => document.is_a?(Hash) ? document["reason"] : nil}
    else
      if document.is_a?(Hash) && document["kind"] == "Status"
        {"status" => status, "reason" => document["reason"], "causes" => Array(document.dig("details", "causes")).map do |cause|
          cause.slice("reason", "field")
        end.sort_by(&:to_s),
         "message_fragments" => message_fragments(document["message"])}
      elsif document.is_a?(Hash)
        {"status" => status, "spec" => document["spec"], "status_field" => document["status"], "apiVersion" => document["apiVersion"],
         "kind" => document["kind"],
         "labels" => document.dig("metadata", "labels")}
      else
        {"status" => status}
      end
    end
  end

  def message_fragments(message)
    ["Required value", "should be greater than or equal to", "Unsupported value", "large widgets must be red", "Duplicate value",
     "not found", "already exists", "Invalid value"].select do |fragment|
      message.to_s.include?(fragment)
    end.sort
  end

  def deep_strip(value)
    case value
    when Hash
      value.each_with_object({}) do |(key, child), hash|
        next if VOLATILE.include?(key)

        hash[key] = deep_strip(child)
      end
    when Array then value.map { |child| deep_strip(child) }
    else value
    end
  end

  def run_script(client)
    observations = {}
    nil
    script.each do |step, method, path, body, headers|
      case method
      when :wait_established
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
        loop do
          status, document = client.call("GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.probe.example.com")
          break if status == 200 && Array(document.dig("status", "conditions")).any? do |condition|
            condition["type"] == "Established" && condition["status"] == "True"
          end
          break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

          sleep 0.2
        end
        # Discovery propagation on the oracle is asynchronous.
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
        loop do
          status, _document = client.call("GET", "/apis/probe.example.com/v1")
          break if status == 200 || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

          sleep 0.2
        end
        sleep 1
        observations[step] = {"waited" => true}
      when :status_update
        status, current = client.call("GET", "/apis/probe.example.com/v1/namespaces/default/widgets/w1")
        unless current.is_a?(Hash) && current["spec"].is_a?(Hash)
          observations[step] = {"status" => status, "error" => "widget w1 was not readable before the status update"}
          next
        end
        candidate = current.merge("status" => {"ready" => true}, "spec" => current["spec"].merge("size" => 9))
        status, document = client.call("PUT", "/apis/probe.example.com/v1/namespaces/default/widgets/w1/status", body: candidate)
        observations[step] = normalize(step, status, document)
      when :wait_apiservice
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
        loop do
          status, document = client.call("GET", "/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.probe.example.com")
          condition = Array(document.dig("status", "conditions")).find { |entry| entry["type"] == "Available" } if status == 200
          if condition && condition["status"] == "False"
            observations[step] = {"available" => condition["status"], "reason" => condition["reason"]}
            break
          end
          if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
            observations[step] = {"available" => condition && condition["status"], "timeout" => true}
            break
          end
          sleep 0.5
        end
      when :wait_gone
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
        loop do
          status, _document = client.call("GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.probe.example.com")
          break if status == 404 || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

          sleep 0.2
        end
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
        loop do
          status, _document = client.call("GET", "/apis/probe.example.com/v1")
          break if status == 404 || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

          sleep 0.2
        end
        observations[step] = {"waited" => true}
      else
        status, document = client.call(method, path, body: body, headers: headers || {})
        observations[step] = normalize(step, status, document)
      end
    end
    observations
  end

  def run
    started_at = M6ProbeSupport.now
    local_service = M6ProbeSupport.build_service
    local_service.send(:install_bootstrap_objects)
    local = run_script(LocalClient.new(local_service))
    if ENV["RUBERNETES_M6_LOCAL_ONLY"]
      puts JSON.pretty_generate(local)
      exit 0
    end
    oracle = nil
    evidence = nil
    cluster = M1KubernetesOracle::DockerCluster.new
    cluster.with_client do |client, oracle_evidence|
      evidence = oracle_evidence
      oracle = run_script(OracleClient.new(client))
    end
    cases = script.map(&:first).map do |step|
      expected = oracle[step]
      actual = local[step]
      {"id" => step, "oracle" => expected, "rubernetes" => actual, "passed" => expected == actual}
    end
    M6ProbeSupport.emit(M6ProbeSupport.report(
      kind: "m6_crd_aggregation_differential", measurement_level: "differentially_tested", started_at: started_at, cases: cases,
      extra: {"oracle" => evidence, "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/api/crd/manager.rb lib/rubernetes/api/crd/structural_schema.rb lib/rubernetes/api/aggregator.rb])}
    ))
  end
end

M6CRDDifferentialProbe.run if $PROGRAM_NAME == __FILE__
