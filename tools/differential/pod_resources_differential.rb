#!/usr/bin/env ruby
# frozen_string_literal: true

# Container and pod-level (PodLevelResources) resource validation, defaulting
# and qosClass: the same Pods are created with dryRun=All on the production
# API server and on the pinned kube-apiserver v1.36.2 oracle (Docker), and the
# HTTP status, Status causes, defaulted spec.resources and status.qosClass are
# compared.  RUBERNETES_DIFF_LOCAL_ONLY=1 prints the local side only.

require "json"
require_relative "../milestones/m6_probe_support"
require_relative "../milestones/m1_kubernetes_oracle"

module PodResourcesDifferential
  module_function

  def pod(name, containers:, resources: nil, init: nil, os: nil, overhead: nil)
    spec = {"containers" => containers.each_with_index.map do |value, index|
      {"name" => "c#{index}", "image" => "registry.k8s.io/pause:3.10"}.merge(value)
    end}
    if init
      spec["initContainers"] = init.each_with_index.map do |value, index|
        {"name" => "i#{index}", "image" => "registry.k8s.io/pause:3.10"}.merge(value)
      end
    end
    spec["resources"] = resources if resources
    spec["os"] = {"name" => os} if os
    spec["overhead"] = overhead if overhead
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name}, "spec" => spec}
  end

  def res(requests: nil, limits: nil)
    value = {}
    value["requests"] = requests if requests
    value["limits"] = limits if limits
    {"resources" => value}
  end

  CASES = [
    ["request-over-limit", pod("a", containers: [res(requests: {"cpu" => "2"}, limits: {"cpu" => "1"})])],
    ["bad-names", pod("b", containers: [res(requests: {"cpus" => "1", "example.com/foo" => "1500m", "memory" => "-1"})])],
    ["extended-needs-limit-equal", pod("c", containers: [res(requests: {"example.com/foo" => "1"}, limits: {"example.com/foo" => "2"})])],
    ["extended-request-only", pod("d", containers: [res(requests: {"example.com/foo" => "1"})])],
    ["hugepages-alone", pod("e", containers: [res(requests: {"hugepages-2Mi" => "2Mi"}, limits: {"hugepages-2Mi" => "2Mi"})])],
    ["hugepages-indivisible",
     pod("f", containers: [res(requests: {"cpu" => "1", "hugepages-2Mi" => "3Mi"}, limits: {"hugepages-2Mi" => "3Mi"})])],
    ["storage-resource", pod("g", containers: [res(requests: {"storage" => "1Gi"})])],
    ["pod-request-over-limit", pod("h", containers: [{}], resources: {"requests" => {"cpu" => "2"}, "limits" => {"cpu" => "1"}})],
    ["pod-unsupported", pod("i", containers: [{}], resources: {"requests" => {"ephemeral-storage" => "1Gi"}})],
    ["pod-below-aggregate", pod("j", containers: [res(requests: {"cpu" => "600m"}), res(requests: {"cpu" => "600m"})],
                                     resources: {"requests" => {"cpu" => "1"}, "limits" => {"cpu" => "2"}})],
    ["container-limit-over-pod", pod("k", containers: [res(limits: {"memory" => "2Gi"})], resources: {"limits" => {"memory" => "1Gi"}})],
    ["windows-pod-level", pod("l", containers: [{}], resources: {"limits" => {"cpu" => "1"}}, os: "windows")],
    ["default-requests-from-limits", pod("m", containers: [{}], resources: {"limits" => {"cpu" => "1", "memory" => "1Gi"}})],
    ["default-requests-from-containers", pod("n", containers: [res(requests: {"cpu" => "100m"}), res(requests: {"cpu" => "250m"})],
                                                  resources: {"limits" => {"cpu" => "1", "memory" => "1Gi"}})],
    ["default-with-init", pod("o", containers: [res(requests: {"cpu" => "100m"})], init: [res(requests: {"cpu" => "700m"})],
                                   resources: {"limits" => {"cpu" => "1"}})],
    ["pod-guaranteed",
     pod("p", containers: [{}],
              resources: {"requests" => {"cpu" => "1", "memory" => "1Gi"}, "limits" => {"cpu" => "1", "memory" => "1Gi"}})],
    ["pod-burstable-cpu-only", pod("q", containers: [res(requests: {"cpu" => "1"}, limits: {"cpu" => "1", "memory" => "1Gi"})],
                                        resources: {"limits" => {"cpu" => "1"}})],
    ["pod-requests-only", pod("r", containers: [{}], resources: {"requests" => {"memory" => "100Mi"}})],
    ["hugepage-pod-limit-default", pod("s", containers: [res(requests: {"cpu" => "1", "hugepages-2Mi" => "4Mi"}, limits: {"hugepages-2Mi" => "4Mi"})],
                                            resources: {"limits" => {"memory" => "1Gi"}})],
    ["pod-hugepage-below-containers", pod("t", containers: [res(requests: {"cpu" => "1", "hugepages-2Mi" => "4Mi"}, limits: {"hugepages-2Mi" => "4Mi"})],
                                               resources: {"limits" => {"memory" => "1Gi", "hugepages-2Mi" => "2Mi"}})],
    ["container-guaranteed",
     pod("u", containers: [res(requests: {"cpu" => "1", "memory" => "1Gi"}, limits: {"cpu" => "1000m", "memory" => "1Gi"})])],
    ["container-besteffort", pod("v", containers: [{}])],
    ["empty-pod-resources", pod("w", containers: [res(limits: {"cpu" => "1", "memory" => "1Gi"})], resources: {})],
    ["integer-pods-resource", pod("x", containers: [res(requests: {"pods" => "1"})])]
  ].freeze

  # Cases run in namespaces with a LimitRange / ResourceQuota.
  NAMESPACED_CASES = [
    ["limitrange-defaults", "diff-lr", pod("lr1", containers: [{}, res(requests: {"cpu" => "50m"})], init: [{}])],
    ["limitrange-pod-max", "diff-lr", pod("lr2", containers: [res(requests: {"memory" => "800Mi"}, limits: {"memory" => "800Mi"}),
                                                              res(requests: {"memory" => "400Mi"}, limits: {"memory" => "400Mi"})])],
    ["limitrange-pod-level", "diff-lr", pod("lr3", containers: [{}], resources: {"limits" => {"memory" => "2Gi"}})],
    ["quota-status-unknown", "diff-q", pod("q1", containers: [res(requests: {"cpu" => "100m"})])]
  ].freeze

  def normalize(status, body)
    document = JSON.parse(body)
    if status >= 400
      causes = Array(document.dig("details", "causes")).map { |cause| cause.slice("reason", "field", "message") }
      {"status" => status, "reason" => document["reason"], "causes" => causes.sort_by(&:to_s)}
    else
      {"status" => status, "resources" => document.dig("spec", "resources"),
       "annotations" => (document.dig("metadata", "annotations") || {}).slice("kubernetes.io/limit-ranger"),
       "containerResources" => Array(document.dig("spec", "containers")).map { |container| container["resources"] },
       "qosClass" => document.dig("status", "qosClass")}
    end
  rescue JSON::ParserError
    {"status" => status, "body" => body.to_s[0, 300]}
  end

  def run_cases(call)
    call.call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "diff-res"}})
    # No controller manager runs on either side, so the ServiceAccount
    # admission plugin needs the default account created by hand.
    call.call("POST", "/api/v1/namespaces/diff-res/serviceaccounts",
              {"apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => "default"}})
    %w[diff-lr diff-q].each do |namespace|
      call.call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace}})
      call.call("POST", "/api/v1/namespaces/#{namespace}/serviceaccounts",
                {"apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => "default"}})
    end
    call.call("POST", "/api/v1/namespaces/diff-lr/limitranges",
              {"apiVersion" => "v1", "kind" => "LimitRange", "metadata" => {"name" => "lr"},
               "spec" => {"limits" => [{"type" => "Container", "default" => {"cpu" => "500m", "memory" => "256Mi"}, "defaultRequest" => {"cpu" => "100m"}},
                                       {"type" => "Pod", "max" => {"memory" => "1Gi"}}]}})
    # No quota controller runs on either side: status.used stays unknown.
    call.call("POST", "/api/v1/namespaces/diff-q/resourcequotas",
              {"apiVersion" => "v1", "kind" => "ResourceQuota", "metadata" => {"name" => "compute"}, "spec" => {"hard" => {"requests.cpu" => "1"}}})
    results = CASES.to_h do |name, object|
      status, body = call.call("POST", "/api/v1/namespaces/diff-res/pods?dryRun=All", object)
      [name, normalize(status, body)]
    end
    NAMESPACED_CASES.each do |name, namespace, object|
      status, body = call.call("POST", "/api/v1/namespaces/#{namespace}/pods?dryRun=All", object)
      results[name] = normalize(status, body)
    end
    results
  end

  def case_names = CASES.map(&:first) + NAMESPACED_CASES.map(&:first)

  def run
    service = M6ProbeSupport.build_service
    service.send(:install_bootstrap_objects)
    local = run_cases(lambda do |method, path, body|
      response = M6ProbeSupport.request(service, method, path, body: body, token: "admin-token")
      body = response.body
      body = body.join if body.is_a?(Array)
      [response.status, body.is_a?(String) ? body : JSON.generate(body)]
    end)
    if ENV["RUBERNETES_DIFF_LOCAL_ONLY"]
      puts JSON.pretty_generate(local)
      return
    end
    oracle = nil
    M1KubernetesOracle::DockerCluster.new.with_client do |client, _evidence|
      oracle = run_cases(lambda do |method, path, body|
        response = client.request(method: method.downcase.to_sym, path: path, body: JSON.generate(body))
        [response.status, response.body.is_a?(String) ? response.body : JSON.generate(response.body)]
      end)
    end
    failures = 0
    case_names.each do |name|
      next if oracle[name] == local[name]

      failures += 1
      puts "MISMATCH #{name}\n  oracle: #{JSON.generate(oracle[name])}\n  local:  #{JSON.generate(local[name])}"
    end
    puts "#{case_names.length - failures}/#{case_names.length} cases match"
    File.write(ENV["RUBERNETES_DIFF_ORACLE_OUT"], JSON.pretty_generate(oracle)) if ENV["RUBERNETES_DIFF_ORACLE_OUT"]
    exit(failures.zero? ? 0 : 1)
  end
end

PodResourcesDifferential.run if $PROGRAM_NAME == __FILE__
