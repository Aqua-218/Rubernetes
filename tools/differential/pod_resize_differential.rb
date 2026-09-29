#!/usr/bin/env ruby
# frozen_string_literal: true

# pods/resize (ValidatePodResize, the resize strategy) and resource changes
# through the main pods resource (ValidatePodUpdate): the same requests go to
# the production API server and the pinned kube-apiserver v1.36.2 oracle and
# the HTTP status, Status causes and resulting spec.resources/generation are
# compared.  RUBERNETES_DIFF_LOCAL_ONLY=1 prints the local side only.

require "json"
require_relative "../milestones/m6_probe_support"
require_relative "../milestones/m1_kubernetes_oracle"

module PodResizeDifferential
  module_function

  def container(name, requests: nil, limits: nil, image: "registry.k8s.io/pause:3.10")
    resources = {}
    resources["requests"] = requests if requests
    resources["limits"] = limits if limits
    {"name" => name, "image" => image, "resources" => resources}
  end

  def pod(name, containers:, resources: nil)
    spec = {"containers" => containers}
    spec["resources"] = resources if resources
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name}, "spec" => spec}
  end

  BURSTABLE = [container("c", requests: {"cpu" => "100m", "memory" => "64Mi"}, limits: {"cpu" => "200m", "memory" => "128Mi"})].freeze
  GUARANTEED = [container("c", requests: {"cpu" => "100m", "memory" => "64Mi"}, limits: {"cpu" => "100m", "memory" => "64Mi"})].freeze

  # [id, pod, verb, subresource, body]
  CASES = [
    ["resize-cpu", pod("r1", containers: BURSTABLE), "PATCH", "resize",
     {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "150m"}}}]}}],
    ["resize-qos-change", pod("r2", containers: BURSTABLE), "PATCH", "resize",
     {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "200m", "memory" => "128Mi"}}}]}}],
    ["resize-remove-request", pod("r3", containers: BURSTABLE), "PUT", "resize",
     {"spec" => {"containers" => [container("c", requests: {"cpu" => "100m"}, limits: {"cpu" => "200m", "memory" => "128Mi"})]}}],
    ["resize-image", pod("r4", containers: BURSTABLE), "PATCH", "resize",
     {"spec" => {"containers" => [{"name" => "c", "image" => "registry.k8s.io/pause:3.10.2"}]}}],
    ["resize-ephemeral-storage", pod("r5", containers: BURSTABLE), "PATCH", "resize",
     {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"ephemeral-storage" => "1Gi"}}}]}}],
    ["resize-guaranteed", pod("r6", containers: GUARANTEED), "PATCH", "resize",
     {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "200m"}, "limits" => {"cpu" => "200m"}}}]}}],
    ["resize-pod-level", pod("r7", containers: [container("c")], resources: {"requests" => {"cpu" => "100m"}, "limits" => {"cpu" => "200m"}}), "PATCH", "resize",
     {"spec" => {"resources" => {"requests" => {"cpu" => "150m"}}}}],
    ["resize-pod-level-remove", pod("r8", containers: [container("c")], resources: {"requests" => {"cpu" => "100m", "memory" => "64Mi"}}), "PUT", "resize",
     {"spec" => {"resources" => {"requests" => {"cpu" => "100m"}}}}],
    ["resize-add-pod-level", pod("r9", containers: BURSTABLE), "PATCH", "resize",
     {"spec" => {"resources" => {"requests" => {"cpu" => "200m"}}}}],
    ["main-update-resources", pod("r10", containers: BURSTABLE), "PATCH", "",
     {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "150m"}}}]}}],
    ["main-update-pod-level", pod("r11", containers: [container("c")], resources: {"requests" => {"cpu" => "100m"}}), "PATCH", "",
     {"spec" => {"resources" => {"requests" => {"cpu" => "150m"}}}}],
    ["resize-labels-ignored", pod("r12", containers: BURSTABLE), "PATCH", "resize",
     {"metadata" => {"labels" => {"x" => "y"}}, "spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "150m"}}}]}}]
  ].freeze

  def normalize(status, body)
    document = body.is_a?(String) ? JSON.parse(body) : body
    if status >= 400
      causes = Array(document.dig("details", "causes")).map { |cause| cause.slice("reason", "field", "message") }
      {"status" => status, "reason" => document["reason"], "message" => document["message"], "causes" => causes.sort_by(&:to_s)}
    else
      {"status" => status, "generation" => document.dig("metadata", "generation"), "labels" => document.dig("metadata", "labels"),
       "resources" => document.dig("spec", "resources"), "containers" => Array(document.dig("spec", "containers")).map { |c| c.slice("image", "resources") }}
    end
  rescue JSON::ParserError
    {"status" => status, "body" => body.to_s[0, 300]}
  end

  def run_cases(call)
    call.call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "diff-resize"}}, nil)
    call.call("POST", "/api/v1/namespaces/diff-resize/serviceaccounts",
              {"apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => "default"}}, nil)
    CASES.to_h do |id, object, verb, subresource, body|
      status, created = call.call("POST", "/api/v1/namespaces/diff-resize/pods", object, nil)
      next [id, {"create" => normalize(status, created)}] if status >= 300

      name = object.dig("metadata", "name")
      path = "/api/v1/namespaces/diff-resize/pods/#{name}#{subresource.empty? ? "" : "/#{subresource}"}"
      if verb == "PUT"
        current = created.is_a?(String) ? JSON.parse(created) : created
        body = current.merge("spec" => current["spec"].merge(body["spec"].to_h { |key, value| [key, value] }).tap do |spec|
          if body["spec"]["containers"]
            spec["containers"] = current["spec"]["containers"].each_with_index.map { |c, i| c.merge("resources" => body["spec"]["containers"][i]["resources"]) }
          end
        end)
        [id, normalize(*call.call("PUT", path, body, nil))]
      else
        [id, normalize(*call.call("PATCH", path, body, "application/strategic-merge-patch+json"))]
      end
    end
  end

  def run
    service = M6ProbeSupport.build_service
    service.send(:install_bootstrap_objects)
    local = run_cases(lambda do |method, path, body, content_type|
      headers = content_type ? {"content-type" => content_type} : {}
      response = M6ProbeSupport.request(service, method, path, body: body, token: "admin-token", headers: headers)
      payload = response.body
      payload = payload.join if payload.is_a?(Array)
      [response.status, payload.is_a?(String) ? payload : JSON.generate(payload)]
    end)
    if ENV["RUBERNETES_DIFF_LOCAL_ONLY"]
      puts JSON.pretty_generate(local)
      return
    end
    oracle = nil
    M1KubernetesOracle::DockerCluster.new.with_client do |client, _evidence|
      oracle = run_cases(lambda do |method, path, body, content_type|
        headers = content_type ? {"Content-Type" => content_type} : {}
        response = client.request(method: method.downcase.to_sym, path: path, body: JSON.generate(body), headers: headers)
        [response.status, response.body.is_a?(String) ? response.body : JSON.generate(response.body)]
      end)
    end
    failures = CASES.count do |id, *|
      next false if oracle[id] == local[id]

      puts "MISMATCH #{id}\n  oracle: #{JSON.generate(oracle[id])}\n  local:  #{JSON.generate(local[id])}"
      true
    end
    puts "#{CASES.length - failures}/#{CASES.length} cases match"
    exit(failures.zero? ? 0 : 1)
  end
end

PodResizeDifferential.run if $PROGRAM_NAME == __FILE__
