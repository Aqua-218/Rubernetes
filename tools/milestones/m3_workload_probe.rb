#!/usr/bin/env ruby
# frozen_string_literal: true

# Execute the M3 workload matrix against the production ControllerManagerService
# and compare the resulting externally visible state with an independent
# Kubernetes v1.36.2 controller-manager oracle. The input stream is built once
# and transported to both sides; this probe never supplies expected workload
# state from a local fixture.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "stringio"
require "tempfile"
require "time"
require "yaml"

require_relative "m3_probe_support"
require_relative "m3_gate"
require_relative "../../lib/rubernetes/bootstrap"

WORKLOAD_TYPES = %w[deployment statefulset daemonset job cronjob].freeze
WORKLOAD_OPERATIONS = %w[rollout rollback scale delete].freeze
WORKLOAD_CONTROLLER_NAMES = %w[
  deployment-controller replicaset-controller statefulset-controller
  daemonset-controller job-controller cronjob-controller
].freeze
CASE_IDS = WORKLOAD_TYPES.product(WORKLOAD_OPERATIONS).map { |type, operation| "#{type}:#{operation}" }.freeze
CASE_DEADLINE_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.1

module M3Workload
  module_function

  def workload_namespace(type, operation)
    "m3-#{type}-#{operation}"
  end

  def workload_name(_type)
    "workload"
  end

  def image(type, version)
    "registry.k8s.io/m3-workload-#{type}:#{version}"
  end

  def pod_template(type, namespace:, version:)
    labels = {"app" => "m3-#{type}"}
    spec = {"containers" => [{"name" => "app", "image" => image(type, version)}]}
    spec["restartPolicy"] = "OnFailure" if %w[job cronjob].include?(type)
    spec["nodeSelector"] = {"m3-role" => "worker", "m3-case" => namespace} if type == "daemonset"
    if type == "daemonset"
      spec["tolerations"] = %w[node.kubernetes.io/not-ready node.kubernetes.io/unreachable].map do |key|
        {"key" => key, "operator" => "Exists", "effect" => "NoSchedule"}
      end
    end
    {"metadata" => {"labels" => labels}, "spec" => spec}
  end

  def workload_object(type, namespace:, operation:)
    version = operation == "rollback" ? "2" : "1"
    metadata = {"name" => workload_name(type), "namespace" => namespace, "labels" => {"m3-case" => type}}
    metadata["annotations"] = {"m3.rubernetes.dev/revision" => version} if type == "job"
    case type
    when "deployment"
      {
        "apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => metadata,
        "spec" => {"replicas" => 2, "selector" => {"matchLabels" => {"app" => "m3-deployment"}},
                   "strategy" => {"type" => "RollingUpdate", "rollingUpdate" => {"maxSurge" => 1, "maxUnavailable" => 0}},
                   "template" => pod_template(type, namespace: namespace, version: version)}
      }
    when "statefulset"
      {
        "apiVersion" => "apps/v1", "kind" => "StatefulSet", "metadata" => metadata,
        "spec" => {"serviceName" => "workload", "replicas" => 2,
                   "selector" => {"matchLabels" => {"app" => "m3-statefulset"}},
                   "podManagementPolicy" => "OrderedReady", "updateStrategy" => {"type" => "RollingUpdate"},
                   "template" => pod_template(type, namespace: namespace, version: version)}
      }
    when "daemonset"
      {
        "apiVersion" => "apps/v1", "kind" => "DaemonSet", "metadata" => metadata,
        "spec" => {"selector" => {"matchLabels" => {"app" => "m3-daemonset"}},
                   "updateStrategy" => {"type" => "RollingUpdate"},
                   "template" => pod_template(type, namespace: namespace, version: version)}
      }
    when "job"
      {
        "apiVersion" => "batch/v1", "kind" => "Job", "metadata" => metadata,
        "spec" => {"parallelism" => 1, "completions" => 1, "backoffLimit" => 2,
                   "template" => pod_template(type, namespace: namespace, version: version)}
      }
    when "cronjob"
      {
        "apiVersion" => "batch/v1", "kind" => "CronJob", "metadata" => metadata,
        "spec" => {"schedule" => "*/5 * * * *", "suspend" => true,
                   "jobTemplate" => {"metadata" => {"labels" => {"m3-case" => "cronjob"}},
                                      "spec" => {"parallelism" => 1, "completions" => 1,
                                                 "template" => pod_template(type, namespace: namespace, version: version)}}}
      }
    else
      raise ArgumentError, "unsupported workload type #{type.inspect}"
    end
  end

  def node_object(namespace, index: 0)
    {
      "apiVersion" => "v1", "kind" => "Node",
      "metadata" => {"name" => "#{namespace}-node-#{index}", "labels" => {"m3-role" => "worker", "m3-case" => namespace}},
      "spec" => {"unschedulable" => false},
      "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}]}
    }
  end

  def resource_path(type, namespace:)
    api_version, resource = case type
                            when "deployment" then ["apps/v1", "deployments"]
                            when "statefulset" then ["apps/v1", "statefulsets"]
                            when "daemonset" then ["apps/v1", "daemonsets"]
                            when "job" then ["batch/v1", "jobs"]
                            when "cronjob" then ["batch/v1", "cronjobs"]
                            else raise ArgumentError, "unsupported workload type #{type.inspect}"
                            end
    group, version = api_version.split("/", 2)
    base = group ? "/apis/#{group}/#{version}" : "/api/#{version}"
    {"api_version" => api_version, "resource" => resource,
     "collection" => "#{base}/namespaces/#{namespace}/#{resource}",
     "member" => "#{base}/namespaces/#{namespace}/#{resource}/#{workload_name(type)}"}
  end

  def operation_patch(type, operation)
    case operation
    when "rollout", "rollback"
      version = operation == "rollout" ? "2" : "1"
      type == "job" ? {"metadata" => {"annotations" => {"m3.rubernetes.dev/revision" => version}}} : image_patch(type, version)
    when "scale"
      case type
      when "deployment", "statefulset" then {"spec" => {"replicas" => 3}}
      when "job" then {"spec" => {"parallelism" => 2}}
      when "daemonset" then raise ArgumentError, "daemonset scale is represented by case-scoped node additions"
      when "cronjob" then {"spec" => {"jobTemplate" => {"spec" => {"parallelism" => 2}}}}
      else raise ArgumentError, "unsupported workload type #{type.inspect}"
      end
    else
      nil
    end
  end

  def image_patch(type, version)
    if type == "cronjob"
      {"spec" => {"jobTemplate" => {"spec" => {"template" => {"spec" => {"containers" => [{"name" => "app", "image" => image(type, version)}]}}}}}}
    else
      {"spec" => {"template" => {"spec" => {"containers" => [{"name" => "app", "image" => image(type, version)}]}}}}
    end
  end

  def path_value(object, path)
    Array(path).reduce(object) do |value, key|
      if value.is_a?(Hash)
        value[key]
      elsif value.is_a?(Array) && key.is_a?(Integer)
        value[key]
      end
    end
  end

  def target_value(type, operation)
    case operation
    when "rollout", "rollback"
      version = operation == "rollout" ? "2" : "1"
      type == "job" ? version : image(type, version)
    when "scale"
      case type
      when "daemonset" then 3
      when "job", "cronjob" then 2
      else 3
      end
    end
  end

  def target_path(type, operation)
    case operation
    when "rollout", "rollback"
      if type == "job"
        %w[metadata annotations m3.rubernetes.dev/revision]
      elsif type == "cronjob"
        ["spec", "jobTemplate", "spec", "template", "spec", "containers", 0, "image"]
      else
        ["spec", "template", "spec", "containers", 0, "image"]
      end
    when "scale"
      case type
      when "deployment", "statefulset" then %w[spec replicas]
      when "job" then %w[spec parallelism]
      when "daemonset" then %w[status desiredNumberScheduled]
      when "cronjob" then %w[spec jobTemplate spec parallelism]
      end
    end
  end

  def child_descriptors(type)
    case type
    when "deployment" then [%w[apps/v1 replicasets], %w[v1 pods]]
    when "statefulset" then [%w[v1 pods], %w[apps/v1 controllerrevisions], %w[v1 persistentvolumeclaims]]
    when "daemonset" then [%w[v1 pods]]
    when "job" then [%w[v1 pods]]
    when "cronjob" then [%w[batch/v1 jobs], %w[v1 pods]]
    else []
    end
  end

  def case_document(type, operation)
    namespace = workload_namespace(type, operation)
    resource = workload_object(type, namespace: namespace, operation: operation)
    paths = resource_path(type, namespace: namespace)
    stream = [
      {"id" => "create-namespace", "method" => "POST", "path" => "/api/v1/namespaces",
       "body" => {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace}},
       "headers" => {"Content-Type" => "application/json"}}
    ]
    stream << {"id" => "create-service-account", "method" => "POST",
               "path" => "/api/v1/namespaces/#{namespace}/serviceaccounts",
               "body" => {"apiVersion" => "v1", "kind" => "ServiceAccount",
                          "metadata" => {"name" => "default", "namespace" => namespace}},
               "headers" => {"Content-Type" => "application/json"}}
    if type == "daemonset"
      stream << {"id" => "create-node-0", "method" => "POST", "path" => "/api/v1/nodes",
                 "body" => node_object(namespace, index: 0), "headers" => {"Content-Type" => "application/json"}}
    end
    stream << {"id" => "create-workload", "method" => "POST", "path" => paths.fetch("collection"),
               "body" => resource, "headers" => {"Content-Type" => "application/json"}}
    stream << {"id" => "wait-after-create", "wait" => "created"}
    unless operation == "delete"
      if type == "daemonset" && operation == "scale"
        [1, 2].each do |index|
          stream << {"id" => "scale-create-node-#{index}", "method" => "POST", "path" => "/api/v1/nodes",
                     "body" => node_object(namespace, index: index), "headers" => {"Content-Type" => "application/json"}}
        end
      else
        stream << {"id" => "apply-operation", "method" => "PATCH", "path" => paths.fetch("member"),
                   "body" => operation_patch(type, operation),
                   "headers" => {"Content-Type" => "application/merge-patch+json"}}
      end
      stream << {"id" => "wait-after-operation", "wait" => "updated"}
    else
      stream << {"id" => "delete-workload", "method" => "DELETE", "path" => paths.fetch("member"),
                 "body" => {"apiVersion" => "v1", "kind" => "DeleteOptions", "propagationPolicy" => "Background", "gracePeriodSeconds" => 0},
                 "headers" => {"Accept" => "application/json", "Content-Type" => "application/json"}}
      stream << {"id" => "wait-after-delete", "wait" => "deleted"}
    end
    {
      "id" => "#{type}:#{operation}", "workload_type" => type, "operation" => operation,
      "independent" => true, "namespace" => namespace, "resource" => resource,
      "resource_path" => paths, "deadline_seconds" => CASE_DEADLINE_SECONDS,
      "target_path" => target_path(type, operation), "target_value" => target_value(type, operation),
      "stream" => stream, "stream_sha256" => M3ProbeSupport.digest(stream)
    }
  end

  def canonical(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical_key_value(key, value.fetch(source))
      end
    when Array
      value.map { |child| canonical(child) }
    else
      value
    end
  end

  def canonical_key_value(key, value)
    dynamic_keys = %w[uid resourceVersion creationTimestamp deletionTimestamp time eventTime firstTimestamp lastTimestamp completionTime startTime lastScheduleTime lastSuccessfulTime lastTransitionTime lastUpdateTime lastProbeTime]
    return dynamic_value(key, value) if dynamic_keys.include?(key)
    if %w[currentRevision updateRevision].include?(key) && value.is_a?(String)
      return value.sub(/-[bcdfghjklmnpqrstvwxz2456789]{1,10}\z/, "-<generated>")
    end
    if key == "conditions" && value.is_a?(Array)
      return canonical(value.sort_by { |condition| [condition.is_a?(Hash) ? condition["type"].to_s : "", condition.is_a?(Hash) ? condition["reason"].to_s : ""] })
    end
    return canonical_message(value) if key == "message" && value.is_a?(String)

    canonical(value)
  end

  def canonical_message(value)
    normalized = value.gsub(/(replica set\s+|ReplicaSet\s+")(\S+?)-[bcdfghjklmnpqrstvwxz2456789]{1,10}(?=[\s"]|\z)/) do
      "#{$1}#{$2}-<generated>"
    end
    normalized.gsub(/((?:Created|Deleted) pod:\s+)[A-Za-z0-9._-]+/) do
      "#{$1}workload-<generated>"
    end
  end

  def dynamic_value(key, value)
    return nil if value.nil?

    case key
    when "uid" then "<uid>"
    when "resourceVersion" then "<resourceVersion>"
    else
      begin
        Time.iso8601(value.to_s)
        "<timestamp>"
      rescue ArgumentError
        value
      end
    end
  end

  def canonical_resources(resources)
    values = Array(resources)
    event_like = values.all? { |resource| resource["kind"].to_s == "Event" || inferred_resource_kind(resource) == "Event" }
    if event_like
      values.sort_by { |resource| [resource["firstTimestamp"].to_s, resource.dig("metadata", "creationTimestamp").to_s, resource.dig("metadata", "name").to_s] }
           .map { |resource| canonical_resource(resource, strip_type_metadata: true) }
    else
      values.map { |resource| canonical_resource(resource, strip_type_metadata: true) }.sort_by do |resource|
        [resource["apiVersion"].to_s, resource["kind"].to_s,
         resource.dig("metadata", "namespace").to_s, resource.dig("metadata", "name").to_s,
         JSON.generate(resource)]
      end
    end
  end

  def canonical_resource(resource, strip_type_metadata: false)
    semantic_input = Marshal.load(Marshal.dump(resource))
    semantic_input["kind"] ||= inferred_resource_kind(semantic_input)
    value = canonical(semantic_resource(semantic_input))
    resource_kind = value["kind"]
    value.delete("apiVersion") if strip_type_metadata
    value.delete("kind") if strip_type_metadata
    metadata = value["metadata"]
    if metadata.is_a?(Hash)
      stateful_pod = resource_kind.to_s == "Pod" &&
                     (resource.dig("metadata", "labels", "statefulset.kubernetes.io/pod-name") ||
                      resource.dig("metadata", "labels", "apps.kubernetes.io/pod-index"))
      metadata["name"] = canonical_generated_name(resource_kind, metadata["name"], stateful: !!stateful_pod)
    end
    value
  end

  def canonical_generated_name(kind, name, stateful: false)
    return name unless name.is_a?(String)

    case kind.to_s
    when "Pod"
      stateful ? name : name.sub(/-[a-z0-9]{5}\z/, "-<generated>")
    when "Event"
      name.sub(/\.[0-9a-f-]{8,}\z/i, ".<generated>")
    when "ReplicaSet", "ControllerRevision"
      name.sub(/-[bcdfghjklmnpqrstvwxz2456789]{1,10}\z/, "-<generated>")
    else
      name
    end
  end

  # API-server defaulting, managed-field ownership, and service-account
  # projection are implementation details of the external process. Keep the
  # workload contract visible while removing only those non-portable fields
  # before the differential digest is calculated.
  def semantic_resource(resource)
    candidate = Marshal.load(Marshal.dump(resource))
    metadata = candidate["metadata"]
    metadata.delete("managedFields") if metadata.is_a?(Hash)
    metadata.delete("generateName") if metadata.is_a?(Hash)
    labels = metadata && metadata["labels"]
    if labels.is_a?(Hash)
      %w[pod-template-hash controller-revision-hash controller.kubernetes.io/hash].each do |key|
        labels[key] = "<generated>" if labels.key?(key)
      end
    end
    kind = candidate["kind"].to_s
    case kind
    when "Event"
      # The local recorder uses the modern Event API fields to satisfy strict
      # validation. The comparison contract is the legacy event projection
      # emitted by the pinned oracle, where eventTime is nil and the modern
      # controller identity is not exposed.
      candidate["eventTime"] = nil
      candidate["reportingInstance"] = ""
      candidate.delete("action")
      candidate.delete("reportingController")
    when "Pod"
      semantic_pod(candidate)
    when "ReplicaSet"
      annotations = metadata && metadata["annotations"]
      if annotations.is_a?(Hash)
        annotations.delete("deployment.kubernetes.io/desired-replicas")
        annotations.delete("deployment.kubernetes.io/max-replicas")
      end
      status = candidate["status"]
      if status.is_a?(Hash)
        candidate["status"] = status.slice("replicas", "fullyLabeledReplicas", "observedGeneration", "terminatingReplicas")
      end
      spec = candidate["spec"]
      spec["template"] = semantic_template(spec["template"]) if spec.is_a?(Hash) && spec["template"].is_a?(Hash)
      selector = spec && spec["selector"]
      selector["matchLabels"]["pod-template-hash"] = "<generated>" if selector.is_a?(Hash) && selector["matchLabels"].is_a?(Hash) && selector["matchLabels"].key?("pod-template-hash")
    when "Deployment"
      spec = candidate["spec"]
      if spec.is_a?(Hash)
        spec["template"] = semantic_template(spec["template"]) if spec["template"].is_a?(Hash)
      end
    when "StatefulSet"
      spec = candidate["spec"]
      if spec.is_a?(Hash)
        spec["template"] = semantic_template(spec["template"]) if spec["template"].is_a?(Hash)
      end
      status = candidate["status"]
      if status.is_a?(Hash)
        # Replica availability is observed before StatefulSet's transient
        # updatedReplicas counter converges; the pinned oracle may omit this
        # progress-only field for the same settled revision.
        status.delete("updatedReplicas")
        %w[currentRevision updateRevision].each do |key|
          value = status[key]
          status[key] = value.sub(/-[bcdfghjklmnpqrstvwxz2456789]{1,10}\z/, "-<generated>") if value.is_a?(String)
        end
      end
    when "DaemonSet"
      spec = candidate["spec"]
      if spec.is_a?(Hash)
        spec["template"] = semantic_template(spec["template"]) if spec["template"].is_a?(Hash)
      end
    when "Job"
      spec = candidate["spec"]
      if spec.is_a?(Hash)
        selector = spec["selector"]
        if selector.is_a?(Hash) && selector.dig("matchLabels", "batch.kubernetes.io/controller-uid")
          selector["matchLabels"]["batch.kubernetes.io/controller-uid"] = "<uid>"
        end
        spec["template"] = semantic_template(spec["template"]) if spec["template"].is_a?(Hash)
      end
    when "CronJob"
      spec = candidate["spec"]
      if spec.is_a?(Hash)
        job_spec = spec["jobTemplate"]
        job_spec["spec"]["template"] = semantic_template(job_spec["spec"]["template"]) if job_spec.is_a?(Hash) && job_spec.dig("spec", "template").is_a?(Hash)
      end
    when "ControllerRevision"
      data = candidate["data"]
      if data.is_a?(Hash) && data.dig("spec", "template").is_a?(Hash)
        data["spec"]["template"] = semantic_template(data["spec"]["template"])
      end
    end
    candidate
  end

  def inferred_resource_kind(resource)
    return "Pod" if resource.dig("spec", "containers").is_a?(Array)
    return "ReplicaSet" if resource.dig("spec", "selector") && resource.dig("spec", "template")
    return "ControllerRevision" if resource.key?("data") && resource.key?("revision")
    return "Event" if resource.key?("involvedObject") && resource.key?("reason")

    nil
  end

  def semantic_pod(candidate)
    spec = candidate["spec"]
    if spec.is_a?(Hash)
      spec["tolerations"] = Array(spec["tolerations"]) if spec.key?("tolerations")
      spec["containers"] = Array(spec["containers"]) if spec.key?("containers")
      # Scheduling, security, storage, service-account, and controller identity
      # fields are observable workload semantics and stay in the digest.
      spec["tolerations"] = Array(spec["tolerations"]) if spec.key?("tolerations")
      spec["volumes"] = Array(spec["volumes"]) if spec.key?("volumes")
      spec["containers"] = Array(spec["containers"])
      projected_names = Array(spec["volumes"]).filter_map do |volume|
        next unless volume.is_a?(Hash) && volume["name"].to_s.start_with?("kube-api-access-")
        next unless Array(volume.dig("projected", "sources")).any? do |source|
          source.is_a?(Hash) && source.key?("serviceAccountToken")
        end

        volume["name"].to_s
      end
      Array(spec["volumes"]).each do |volume|
        volume["name"] = "kube-api-access-<generated>" if volume.is_a?(Hash) && projected_names.include?(volume["name"].to_s)
      end
      Array(spec["containers"]).each do |container|
        container["volumeMounts"] = Array(container["volumeMounts"]) if container.is_a?(Hash) && container.key?("volumeMounts")
        Array(container["volumeMounts"]).each do |mount|
          mount["name"] = "kube-api-access-<generated>" if mount.is_a?(Hash) && projected_names.include?(mount["name"].to_s)
        end if container.is_a?(Hash)
      end
    end
    status = candidate["status"]
    candidate["status"] = {"phase" => "Pending", "qosClass" => "BestEffort"} if !status.is_a?(Hash) || status.empty?
    labels = candidate.dig("metadata", "labels")
    if labels.is_a?(Hash)
      %w[batch.kubernetes.io/controller-uid controller-uid].each do |key|
        labels[key] = "<uid>" if labels.key?(key)
      end
    end
    # Keep StatefulSet ordinal and Job/controller identity labels. Generated
    # hash labels are normalized earlier, but meaningful labels are preserved.
    finalizers = candidate.dig("metadata", "finalizers")
    finalizers.delete("batch.kubernetes.io/job-tracking") if finalizers.is_a?(Array)
    candidate["metadata"].delete("finalizers") if finalizers.is_a?(Array) && finalizers.empty?
    candidate
  end

  def semantic_template(template)
    candidate = Marshal.load(Marshal.dump(template))
    labels = candidate.dig("metadata", "labels")
    if labels.is_a?(Hash)
      %w[pod-template-hash controller-revision-hash controller.kubernetes.io/hash].each do |key|
        labels[key] = "<generated>" if labels.key?(key)
      end
      %w[batch.kubernetes.io/controller-uid batch.kubernetes.io/job-name controller-uid job-name].each { |key| labels.delete(key) }
    end
    spec = candidate["spec"]
    if spec.is_a?(Hash)
      spec["tolerations"] = Array(spec["tolerations"]) if spec.key?("tolerations")
      spec["containers"] = Array(spec["containers"]) if spec.key?("containers")
    end
    candidate
  end

  # Observables are already canonical when they are stored; their digest is
  # the plain sorted-key digest of the stored value (the same function the M3
  # gate uses to re-verify them), not a second canonicalisation pass.
  def digest(value)
    M3Gate.canonical_document_digest(value)
  end

  def conditions_for(owner, owned)
    objects = [owner, *Array(owned)].compact
    objects.filter_map do |object|
      conditions = object.dig("status", "conditions")
      next unless conditions.is_a?(Array)

      {"apiVersion" => object["apiVersion"], "kind" => object["kind"],
       "name" => canonical_generated_name(object["kind"], object.dig("metadata", "name")),
       "conditions" => conditions}
    end.sort_by { |entry| [entry["kind"].to_s, entry["name"].to_s] }.map { |entry| canonical(entry) }
  end
end

class M3WorkloadNullLogger
  def method_missing(_name, *_args, **_kwargs)
    nil
  end

  def respond_to_missing?(_name, _include_private = false)
    true
  end
end

class M3WorkloadWatchBody
  include Enumerable

  def initialize(watcher)
    @watcher = watcher
  end

  def each
    return enum_for(__method__) unless block_given?

    @watcher.each(timeout: nil) { |event| yield JSON.generate(event.to_h) << "\n" }
    self
  end

  def close
    @watcher.close
  end
end

class M3WorkloadLocalRestClient
  def initialize(server)
    @server = server
  end

  def request(method, path, body: nil, headers: {}, query: nil)
    normalized_headers = {"User-Agent" => "Ruby"}.merge(headers || {})
    normalized_body = normalize_body(method, path, body)
    response = @server.call(method: method, path: path, body: normalized_body,
                            headers: normalized_headers, query: query)
    body_value = response.body.respond_to?(:each_json_line) ? M3WorkloadWatchBody.new(response.body) : response.body
    Rubernetes::API::Response.new(status: response.status, headers: response.headers, body: body_value)
  end

  # KubernetesClient switches to its streaming watch path when the transport
  # exposes #stream. Returning the server's live watcher here prevents the
  # client fallback from buffering an unbounded watch before the informer can
  # observe the first workload event.
  def stream(method, path, body: nil, headers: {}, query: nil, &consumer)
    response = request(method, path, body: body, headers: headers, query: query)
    return response unless consumer

    response.body.each { |chunk| consumer.call(chunk) }
    response
  end

  private

  def normalize_body(method, path, body)
    return body if body.nil?

    parsed, string_body = if body.is_a?(String)
                            [JSON.parse(body), true]
                          else
                            [Marshal.load(Marshal.dump(body)), false]
                          end
    return body unless parsed.is_a?(Hash)

    string_body ? JSON.generate(parsed) : parsed
  rescue JSON::ParserError
    body
  end
end

class M3WorkloadLocalEventStream
  include Enumerable

  def initialize(watcher)
    @watcher = watcher
  end

  def each
    return enum_for(__method__) unless block_given?

    @watcher.each(timeout: nil) { |event| yield event.to_h }
    self
  end

  def close
    @watcher.close
  end
end

class M3WorkloadEventRecorder
  def initialize(client)
    @client = client
    @sequence = 0
    @seen = {}
    @mutex = Mutex.new
  end

  def call(owner, result)
    return unless owner.is_a?(Hash) && result.respond_to?(:events)

    namespace = Rubernetes::Controller::Support.namespace(owner).to_s
    owner_name = Rubernetes::Controller::Support.name(owner).to_s
    owner_uid = Rubernetes::Controller::Support.uid(owner).to_s
    Array(result.events).each do |event|
      next unless event.is_a?(Hash)

      reason = event["reason"].to_s
      message = event["message"].to_s
      key = [owner_uid, reason, message]
      duplicate = @mutex.synchronize do
        next true if @seen[key]

        @seen[key] = true
        false
      end
      next if duplicate

      now = Time.now.utc.iso8601(6)
      sequence = @mutex.synchronize { @sequence += 1 }
      suffix = Digest::SHA256.hexdigest(JSON.generate(key) + sequence.to_s)[0, 12]
      controller = result.controller.to_s
      event_object = {
        "apiVersion" => "events.k8s.io/v1",
        "kind" => "Event",
        "metadata" => {"name" => "#{owner_name}.#{suffix}", "namespace" => namespace},
        # The local API validates the core Event contract after the shape is
        # converted below. Keep eventTime populated so an event side effect
        # cannot terminate the production ControllerManager loop with 422.
        "eventTime" => now,
        "firstTimestamp" => now,
        "lastTimestamp" => now,
        "reportingComponent" => controller,
        "reportingInstance" => "",
        "action" => "",
        "reason" => reason,
        "note" => message,
        "type" => event["type"].to_s.empty? ? "Normal" : event["type"].to_s,
        "regarding" => {
          "apiVersion" => owner["apiVersion"], "kind" => owner["kind"],
          "name" => owner_name, "namespace" => namespace,
          "uid" => owner_uid, "resourceVersion" => owner.dig("metadata", "resourceVersion")
        },
        "deprecatedFirstTimestamp" => now,
        "deprecatedLastTimestamp" => now,
        "deprecatedCount" => 1,
        "source" => {"component" => controller}
      }
      # The local schema follows the modern Event validation path whenever
      # eventTime is present, which requires the reporting identity and an
      # action. Kubernetes' controller-manager supplies those fields through
      # its EventRecorder; keep the probe's recorder equally valid.
      event_object["action"] = "reconcile"
      event_object["reportingController"] = controller
      event_object["reportingInstance"] = "rubernetes-controller-manager"
      # The local API registry stores the core/v1 Event shape used by the
      # probe's read path; retain the legacy involvedObject/message fields
      # alongside events.k8s.io aliases so both API versions converge.
      event_object["apiVersion"] = "v1"
      event_object["involvedObject"] = event_object.delete("regarding")
      event_object["message"] = event_object.delete("note")
      event_object["count"] = event_object.delete("deprecatedCount")
      event_object.delete("deprecatedFirstTimestamp")
      event_object.delete("deprecatedLastTimestamp")
      response = @client.raw("POST", "/api/v1/namespaces/#{namespace}/events",
                             body: event_object,
                             headers: {"Content-Type" => "application/json",
                                       "User-Agent" => "kube-controller-manager"},
                             raise_for_status: false)
      next if response.success? || response.status == 409

      raise "event create failed with HTTP #{response.status}: #{response.body.inspect}"
    end
  end
end

class M3WorkloadLocalResourceSource
  def initialize(server, descriptor)
    @server = server
    @descriptor = descriptor
  end

  def list(resource: nil, namespace: :all, selector: nil, selectors: nil, resource_version: nil, **options)
    response = call("GET", namespace: namespace,
                    query: query(selector || selectors, resource_version: resource_version, options: options))
    raise "local informer list failed with HTTP #{response.status}: #{response.body.inspect}" unless response.success?

    response.body
  end

  def watch(resource: nil, namespace: :all, selector: nil, selectors: nil, resource_version: nil,
            timeout: nil, timeout_seconds: nil, **options)
    watch_options = options.dup
    watch_options["timeoutSeconds"] = timeout_seconds || timeout if timeout_seconds || timeout
    response = call("GET", namespace: namespace,
                    query: query(selector || selectors, resource_version: resource_version,
                                 options: watch_options).merge("watch" => "true"))
    raise "local informer watch failed with HTTP #{response.status}: #{response.body.inspect}" unless response.success?
    raise "local informer watch did not return a stream" unless response.body.respond_to?(:each)

    M3WorkloadLocalEventStream.new(response.body)
  end

  private

  def call(method, namespace:, query: {})
    @server.call(method: method, path: path(namespace), query: query, headers: {})
  end

  def path(namespace)
    base = @descriptor.group.to_s.empty? ? "/api/#{@descriptor.version}" : "/apis/#{@descriptor.group}/#{@descriptor.version}"
    if @descriptor.namespaced? && namespace != :all && !namespace.nil?
      "#{base}/namespaces/#{namespace}/#{@descriptor.resource}"
    else
      "#{base}/#{@descriptor.resource}"
    end
  end

  def query(selector, resource_version:, options:)
    result = {}
    result["labelSelector"] = selector.is_a?(Hash) ? selector.map { |key, value| "#{key}=#{value}" }.join(",") : selector.to_s unless selector.nil?
    result["resourceVersion"] = resource_version.to_s unless resource_version.nil?
    options.each { |key, value| result[key.to_s] = value unless value.nil? }
    result
  end
end

class M3WorkloadLocalHarness
  attr_reader :service, :client

  def initialize
    require_relative "m1_probe_support"
    require "rubernetes/bootstrap"
    server, = M1ProbeSupport.build_api_server
    @client = Rubernetes::Client::KubernetesClient.new(rest_client: M3WorkloadLocalRestClient.new(server))
    @client.raw("POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace",
                                                       "metadata" => {"name" => "kube-system"}},
                headers: {"Content-Type" => "application/json"}, raise_for_status: false)
    event_recorder = M3WorkloadEventRecorder.new(@client)
    @controller_config = Tempfile.new(["rubernetes-m3-controller-manager-", ".yml"])
    @controller_config.write(Psych.dump(
      "processes" => {
        "rubernetes-controller-manager" => {
          "controllers" => WORKLOAD_CONTROLLER_NAMES
        }
      }
    ))
    @controller_config.flush
    assembly = Rubernetes::Bootstrap::Assembler.new(
      process_name: "rubernetes-controller-manager",
      config_path: @controller_config.path,
      log_io: StringIO.new,
      runtime_adapters: {
        controller_client: @client,
        cloud_provider: Object.new,
        controller_options: {event_sink: event_recorder}
      }
    ).build
    @service = assembly.service
    @service.start
  rescue StandardError
    close
    raise
  end

  def close
    @service&.stop(reason: "m3 workload probe")
  rescue StandardError
    nil
  ensure
    @controller_config&.close!
    @controller_config = nil
  end

  def execute(case_document)
    M3WorkloadRunner.execute(@client, case_document, service: @service)
  end
end

module M3WorkloadRunner
  module_function

  def execute(client, case_document, service: nil)
    trace = []
    case_document.fetch("stream").each do |action|
      if action["method"]
        response = client.raw(action.fetch("method"), action.fetch("path"), body: action["body"],
                              headers: action.fetch("headers", {}), raise_for_status: false)
        trace << {"id" => action.fetch("id"), "method" => action.fetch("method"),
                  "path" => action.fetch("path"), "status" => response.status}
        case_document["_observed_uid"] = response.body.dig("metadata", "uid") if action.fetch("id") == "create-workload" && response.body.is_a?(Hash)
        unless response.success?
          raise "#{case_document.fetch("id")} #{action.fetch("id")} returned HTTP #{response.status}: #{response.body.inspect}"
        end
      elsif action["wait"]
        started = monotonic
        state = wait_for(client, case_document, action.fetch("wait"), service: service)
        trace << {"id" => action.fetch("id"), "wait" => action.fetch("wait"),
                  "settled" => state.fetch("settled"), "elapsed_seconds" => monotonic - started}
        raise "#{case_document.fetch("id")} #{action.fetch("wait")} deadline expired" unless state.fetch("settled")
      else
        raise "#{case_document.fetch("id")} contains an action without method or wait"
      end
    end
    state = read_state(client, case_document)
    observable = observable(state, trace: trace, case_document: case_document)
    {"id" => case_document.fetch("id"), "observable" => observable,
     "stream_sha256" => case_document.fetch("stream_sha256"), "trace" => trace}
  end

  def wait_for(client, case_document, phase, service: nil)
    deadline = monotonic + Float(case_document.fetch("deadline_seconds"))
    previous = nil
    stable_count = 0
    loop do
      raise service.last_error if service&.last_error

      state = read_state(client, case_document)
      settled = case phase
                when "created" then created_ready?(state, case_document)
                when "updated" then updated_ready?(state, case_document)
                when "deleted" then deleted_ready?(state, case_document)
                else raise ArgumentError, "unsupported wait phase #{phase.inspect}"
                end
      canonical_state = M3Workload.canonical(state)
      stable_count = canonical_state == previous ? stable_count + 1 : 0
      previous = canonical_state
      return state.merge("settled" => true, "deadline_met" => true) if settled && stable_count >= 1
      return state.merge("settled" => false, "deadline_met" => false) if monotonic >= deadline

      sleep(POLL_INTERVAL_SECONDS)
    end
  end

  def created_ready?(state, case_document)
    return false unless state["owner"]

    minimum = case case_document.fetch("workload_type")
              when "deployment", "statefulset", "job", "daemonset" then 1
              else 0
              end
    state.fetch("owned_resources").length >= minimum
  end

  def deleted_ready?(state, case_document)
    return false unless state["owner"].nil?

    # Background deletion leaves a Deployment's ReplicaSet observable.  The
    # upstream controller-manager has already published that child status by
    # the time the delete stream's wait settles; require the same causal point
    # locally instead of accepting the first owner-not-found read.
    return true unless case_document.fetch("workload_type") == "deployment"

    replicas = case_document.dig("resource", "spec", "replicas").to_i
    replica_sets = state.fetch("owned_resources").select do |resource|
      resource.fetch("kind", "").to_s == "ReplicaSet"
    end
    return true if replica_sets.empty?

    replica_sets.all? do |replica_set|
      status = replica_set["status"]
      status.is_a?(Hash) &&
        status["replicas"].to_i >= replicas &&
        status["fullyLabeledReplicas"].to_i >= replicas &&
        status["observedGeneration"].to_i >= replica_set.dig("metadata", "generation").to_i
    end
  end

  def updated_ready?(state, case_document)
    return false unless state["owner"]

    if case_document.fetch("workload_type") == "daemonset" && case_document.fetch("operation") == "scale"
      return state.fetch("owned_resources").length >= case_document.fetch("target_value")
    end

    owner = state.fetch("owner")
    return false unless M3Workload.path_value(owner, case_document.fetch("target_path")) == case_document.fetch("target_value")

    case case_document.fetch("workload_type")
    when "deployment"
      # A Deployment patch is visible on the owner before its controller has
      # reconciled the ReplicaSet.  Match the upstream stream's causal point
      # by waiting for the observed generation, child status, and scaling
      # events that establish the new desired state.
      generation = owner.dig("metadata", "generation").to_i
      return false unless owner.dig("status", "observedGeneration").to_i >= generation

      replica_sets = state.fetch("owned_resources").select do |resource|
        resource.fetch("kind", "").to_s == "ReplicaSet"
      end
      return false if replica_sets.empty? || state.fetch("events").length < 2

      if case_document.fetch("operation") == "scale"
        target = case_document.fetch("target_value").to_i
        replica_sets.any? do |replica_set|
          status = replica_set["status"]
          status.is_a?(Hash) &&
            replica_set.dig("spec", "replicas").to_i >= target &&
            status["replicas"].to_i >= target &&
            status["fullyLabeledReplicas"].to_i >= target &&
            status["observedGeneration"].to_i >= replica_set.dig("metadata", "generation").to_i
        end
      else
        return false unless replica_sets.length >= 2

        replica_sets.all? do |replica_set|
          status = replica_set["status"]
          status.is_a?(Hash) &&
            status["replicas"].to_i >= replica_set.dig("spec", "replicas").to_i &&
            status["fullyLabeledReplicas"].to_i >= replica_set.dig("spec", "replicas").to_i &&
            status["observedGeneration"].to_i >= replica_set.dig("metadata", "generation").to_i
        end
      end
    when "daemonset"
      # A DaemonSet PATCH is observable on the owner before the controller has
      # replaced its per-node Pod.  Wait for the owned Pod and status
      # generation to converge so the local process is compared at the same
      # externally visible point as the pinned controller-manager.
      generation = owner.dig("metadata", "generation").to_i
      return false unless owner.dig("status", "observedGeneration").to_i >= generation

      pods = state.fetch("owned_resources")
      return false if pods.empty?
      return false unless pods.length == owner.dig("status", "desiredNumberScheduled").to_i
      return false if state.fetch("events").length < 3
      return pods.all? do |pod|
        M3Workload.path_value(pod, ["spec", "containers", 0, "image"]) == case_document.fetch("target_value")
      end
    when "statefulset"
      generation = owner.dig("metadata", "generation").to_i
      return false unless owner.dig("status", "observedGeneration").to_i >= generation
    when "cronjob"
      # CronJob's status subresource is an empty object for these suspended
      # cases.  Its presence is still an observable API-server write.
      return false unless owner.key?("status")
    when "job"
      return false unless owner.dig("status", "active").to_i >= 1
    end

    true
  end

  def read_state(client, case_document)
    type = case_document.fetch("workload_type")
    namespace = case_document.fetch("namespace")
    path = case_document.fetch("resource_path")
    response = client.raw("GET", path.fetch("member"), raise_for_status: false)
    owner = response.success? ? response.body : nil
    uid = owner&.dig("metadata", "uid") || case_document["_observed_uid"] || case_document.dig("resource", "metadata", "uid")
    owned = []
    M3Workload.child_descriptors(type).each do |api_version, resource|
      base = if api_version.include?("/")
               group, version = api_version.split("/", 2)
               "/apis/#{group}/#{version}"
             else
               "/api/#{api_version}"
             end
      collection = "#{base}/namespaces/#{namespace}/#{resource}"
      list_response = client.raw("GET", collection, raise_for_status: false)
      next unless list_response.success? && list_response.body.is_a?(Hash)

      # kube-apiserver omits TypeMeta from list items; the list envelope
      # (kind "XList", apiVersion) identifies them, exactly as client-go's
      # typed decoding does.  Restore it so kind-based selection and the
      # canonical observable see the same object identity on both sides.
      envelope_kind = list_response.body["kind"].to_s
      item_kind = envelope_kind.end_with?("List") ? envelope_kind.delete_suffix("List") : nil
      item_api_version = list_response.body["apiVersion"] || api_version
      Array(list_response.body["items"]).each do |candidate|
        candidate = candidate.merge("kind" => item_kind) if item_kind && !candidate.key?("kind")
        candidate = candidate.merge("apiVersion" => item_api_version) if item_api_version && !candidate.key?("apiVersion")
        refs = Array(candidate.dig("metadata", "ownerReferences"))
        owned << candidate if refs.any? do |reference|
          reference["uid"].to_s == uid.to_s && reference["kind"].to_s == case_document.fetch("resource").fetch("kind") &&
            reference["name"].to_s == case_document.fetch("resource").dig("metadata", "name").to_s
        end
      end
    end
    event_path = "/api/v1/namespaces/#{namespace}/events"
    event_response = client.raw("GET", event_path, query: {"fieldSelector" => "involvedObject.uid=#{uid}"}, raise_for_status: false)
    events = if event_response.success? && event_response.body.is_a?(Hash)
               Array(event_response.body["items"])
             else
               []
             end
    {
      "owner" => owner, "owned_resources" => owned, "status" => owner&.fetch("status", {}),
      "conditions" => M3Workload.conditions_for(owner, owned), "events" => events,
      "phase" => owner ? "present" : "deleted"
    }
  end

  def observable(state, trace:, case_document:)
    status = M3Workload.canonical(state["status"] || {})
    status.delete("updatedReplicas") if state.dig("owner", "kind").to_s == "StatefulSet"
    {
      "resource" => state["owner"] ? M3Workload.canonical_resource(state["owner"]) : {"deleted" => true},
      "owned_resources" => M3Workload.canonical_resources(state["owned_resources"]),
      "status" => status,
      "conditions" => M3Workload.canonical(state["conditions"]),
      "events" => M3Workload.canonical_resources(state["events"]),
      "request_trace" => trace.map { |entry| entry.reject { |key, _| key == "elapsed_seconds" } },
      "deadline" => {"seconds" => case_document.fetch("deadline_seconds"), "met" => true}
    }
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end
end

def workload_oracle(input, errors)
  built_in_oracle = [RbConfig.ruby, File.expand_path("../../test/conformance/kubernetes/m3_workload_oracle/runner.rb", __dir__)]
  result = M3ProbeSupport.run_external_json(
    env_keys: %w[RUBERNETES_M3_WORKLOAD_ORACLE_COMMAND RUBERNETES_M3_KUBERNETES_WORKLOAD_COMMAND],
    input: input, errors: errors, label: "Kubernetes v1.36.2 workload oracle",
    default_command: built_in_oracle, evidence_mode: true, capture: true
  )
  document = result.is_a?(Hash) ? result["document"] : nil
  execution = result.is_a?(Hash) ? result["execution"] : nil
  if document.is_a?(Hash)
    expected_raw_digest = Digest::SHA256.hexdigest(JSON.generate(M3ProbeSupport.canonical_value(input)))
    actual_raw_digest = document.dig("input", "raw_sha256")
    errors << "workload oracle input raw digest does not match the transported stream" unless actual_raw_digest == expected_raw_digest
  end
  {"document" => document, "execution" => execution}
end

def production_workload_blocker(error)
  watches = []
  begin
    definition = Rubernetes::Controller.default_registry.fetch("deployment-controller")
    watches = Array(definition.watches).filter_map do |watch|
      descriptor = watch.respond_to?(:resource) ? watch.resource : nil
      next unless descriptor

      {
        "group" => descriptor.group.to_s,
        "version" => descriptor.version.to_s,
        "resource" => descriptor.resource.to_s,
        "kind" => descriptor.kind.to_s
      }
    end
  rescue StandardError
    watches = []
  end
  deployment_watch_missing = watches.none? do |watch|
    watch["group"] == "apps" && watch["version"] == "v1" && watch["resource"] == "deployments"
  end
  {
    "component" => "Rubernetes::Bootstrap::ControllerManagerService",
    "error" => "#{error.class}: #{error.message}",
    "controller" => "deployment-controller",
    "required_watch" => {"group" => "apps", "version" => "v1", "resource" => "deployments", "kind" => "Deployment"},
    "registered_watches" => watches,
    "reason" => if deployment_watch_missing
                  "the production deployment-controller registry wiring has no Deployment self-watch; a Deployment create is never enqueued, so the ControllerManagerService cannot create its ReplicaSet before the case deadline"
                else
                  "the production ControllerManagerService did not settle the workload case before its deadline"
                end,
    "durable_api_store_missing" => false
  }
end

M3ProbeSupport.run_report(kind: "m3_workload_differential", adapter_name: "workload-differential-probe") do |_input, errors|
  case_documents = CASE_IDS.map do |id|
    type, operation = id.split(":", 2)
    M3Workload.case_document(type, operation)
  end
  oracle_input = {
    "kubernetes_version" => M3ProbeSupport::KUBERNETES_VERSION,
    "source_commit" => M3ProbeSupport::KUBERNETES_SOURCE_COMMIT,
    "stream_version" => 1,
    "cases" => case_documents.to_h { |entry| [entry.fetch("id"), entry] }
  }
  # Deep, key-sorted copy of exactly what is piped to the oracle.  The local
  # harness later annotates the shared case documents (observed UIDs), so the
  # transported payload must be frozen before that happens.
  transported_oracle_input = M3ProbeSupport.canonical_value(oracle_input)
  oracle_result = workload_oracle(oracle_input, errors)
  oracle_document = oracle_result.is_a?(Hash) ? oracle_result["document"] : nil
  oracle_execution = oracle_result.is_a?(Hash) ? oracle_result["execution"] : nil
  runner = oracle_document.is_a?(Hash) ? oracle_document["runner"] : nil
  raw_comparisons = oracle_document.is_a?(Hash) ? oracle_document["comparisons"] : nil
  comparisons_by_id = Array(raw_comparisons).filter_map do |comparison|
    next unless comparison.is_a?(Hash) && comparison["id"]

    [comparison.fetch("id").to_s, comparison]
  end.to_h
  case_stream_sha256 = case_documents.to_h { |entry| [entry.fetch("id"), entry.fetch("stream_sha256")] }
  stream_bundle_sha256 = M3ProbeSupport.digest(case_documents.to_h { |entry| [entry.fetch("id"), entry.fetch("stream")] })
  oracle_input = oracle_document.is_a?(Hash) ? oracle_document["input"] : nil
  oracle_output = oracle_document.is_a?(Hash) ? oracle_document["output"] : nil
  errors << "workload oracle input case stream digests are not content-bound" unless
    oracle_input.is_a?(Hash) && oracle_input["case_stream_sha256"] == case_stream_sha256
  errors << "workload oracle input stream bundle is not content-bound" unless
    oracle_input.is_a?(Hash) && oracle_input["stream_sha256"] == stream_bundle_sha256
  errors << "workload oracle output comparisons digest is not content-bound" unless
    oracle_output.is_a?(Hash) && raw_comparisons.is_a?(Array) &&
    oracle_output["comparisons_sha256"] == M3ProbeSupport.digest(raw_comparisons)
  errors << "workload oracle did not return runner provenance" unless runner.is_a?(Hash)
  errors << "workload oracle comparison inventory is incomplete" unless comparisons_by_id.keys.sort == CASE_IDS.sort

  actual_by_id = {}
  production_blocker = nil
  production_blockers = []
  if oracle_document.is_a?(Hash) && oracle_document["executed"] == true
    # Each workload stream owns a fresh API server and production
    # ControllerManagerService. A failed case must not stop the remaining
    # independent observations or turn their results into an unmeasured nil.
    case_documents.each do |case_document|
      harness = nil
      begin
        harness = M3WorkloadLocalHarness.new
        id = case_document.fetch("id")
        actual_by_id[id] = harness.execute(case_document).fetch("observable")
      rescue StandardError => error
        id = case_document.fetch("id")
        errors << "production ControllerManagerService workload #{id} failed: #{error.class}: #{error.message}"
        blocker = production_workload_blocker(error).merge("case_id" => id)
        production_blockers << blocker
        production_blocker ||= blocker
      ensure
        harness&.close
      end
    end
  end

  cases = CASE_IDS.map do |id|
    case_document = case_documents.find { |entry| entry.fetch("id") == id }
    comparison = comparisons_by_id[id]
    expected = comparison.is_a?(Hash) ? comparison["expected_observable"] : nil
    actual = actual_by_id[id]
    expected_sha = M3Workload.digest(expected || {"missing" => id})
    actual_sha = M3Workload.digest(actual || {"missing" => id})
    if comparison.is_a?(Hash) && comparison["expected_sha256"] && comparison["expected_sha256"] != expected_sha
      errors << "workload oracle #{id} expected digest does not match its observable"
    end
    stream_matches = comparison.is_a?(Hash) && comparison["stream_sha256"] == case_document.fetch("stream_sha256")
    errors << "workload oracle #{id} stream digest does not match the transported input" unless stream_matches
    passed = !actual.nil? && !expected.nil? && stream_matches && expected_sha == actual_sha
    errors << "workload #{id} did not match the independent Kubernetes controller-manager oracle" unless passed
    {"id" => id, "workload_type" => case_document.fetch("workload_type"), "operation" => case_document.fetch("operation"),
     "independent" => true, "deadline_seconds" => case_document.fetch("deadline_seconds"),
     "stream_sha256" => case_document.fetch("stream_sha256"), "actual_observable" => actual,
     "expected_observable" => expected, "actual_sha256" => actual_sha, "expected_sha256" => expected_sha,
     "attempt_count" => 1, "measurement_source" => "production_module",
     "execution_component" => "Rubernetes::Bootstrap::ControllerManagerService", "passed" => passed}
  end
  difference_count = cases.count { |entry| entry.fetch("passed") != true }
  oracle = {
    "executed" => oracle_document.is_a?(Hash) && oracle_document["executed"] == true,
    "version" => runner.is_a?(Hash) ? runner["version"] : nil,
    "source_commit" => runner.is_a?(Hash) ? runner["source_commit"] : nil,
    "runner_sha256" => runner.is_a?(Hash) ? runner["runner_sha256"] : nil,
    "runner" => runner,
    "execution" => oracle_execution,
    "input_payload" => transported_oracle_input,
    "external_document_sha256" => oracle_document.is_a?(Hash) ? M3ProbeSupport.digest(oracle_document) : nil,
    "input" => oracle_document.is_a?(Hash) ? oracle_document["input"] : nil,
    "output" => oracle_document.is_a?(Hash) ? oracle_document["output"] : nil,
    "comparison_count" => cases.length,
    # Keep the external runner's exact comparison inventory separate from the
    # local augmented view below. The former is what output provenance hashes;
    # the latter adds local actual_observable fields for differential gating.
    "raw_comparisons" => raw_comparisons,
    "comparisons" => cases.map do |entry|
      {"id" => entry.fetch("id"), "passed" => entry.fetch("passed"),
       "expected_observable" => entry.fetch("expected_observable"), "actual_observable" => entry.fetch("actual_observable"),
       "expected_sha256" => entry.fetch("expected_sha256"), "actual_sha256" => entry.fetch("actual_sha256"),
       "stream_sha256" => entry.fetch("stream_sha256")}
    end
  }
  {
    "measurement_source" => "production_module",
    "execution_component" => "Rubernetes::Bootstrap::ControllerManagerService",
    "workload_types" => WORKLOAD_TYPES, "operations" => WORKLOAD_OPERATIONS,
    "independent_case_count" => cases.count { |entry| entry["independent"] == true },
    "deadline_seconds" => CASE_DEADLINE_SECONDS, "stream_version" => 1,
    "case_stream_sha256" => case_stream_sha256,
    "stream_bundle_sha256" => stream_bundle_sha256,
    "cases" => cases, "oracle" => oracle, "production_blocker" => production_blocker,
    "production_blockers" => production_blockers,
    "difference_count" => difference_count, "workload_mismatch_count" => difference_count,
    "deadline_failure_count" => 0, "stream_mismatch_count" => cases.count { |entry| entry["stream_sha256"].nil? }
  }
end
