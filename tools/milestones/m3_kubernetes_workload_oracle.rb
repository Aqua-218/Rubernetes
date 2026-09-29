#!/usr/bin/env ruby
# frozen_string_literal: true

# External M3 workload oracle. The Kubernetes controller-manager executable is
# built from a clean, pinned v1.36.2 source checkout and runs beside an
# isolated, digest-pinned kube-apiserver/etcd pair. This file is evidence-only;
# it is never loaded by the production package.

require "digest"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "tempfile"
require "tmpdir"
require "time"

require_relative "m1_kubernetes_oracle"

module M3KubernetesWorkloadOracle
  VERSION = "v1.36.2".freeze
  SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467".freeze
  KUBE_APISERVER_IMAGE = "registry.k8s.io/kube-apiserver@sha256:0535dde1a857029209d7effe681c919a1580d2eb24eda4bd122d24e9a372e1b8".freeze
  ETCD_IMAGE = "registry.k8s.io/etcd@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5".freeze
  START_TIMEOUT = 45.0
  POLL_INTERVAL = 0.1
  ORACLE_SOURCE = File.expand_path("../../test/conformance/kubernetes/m3_workload_oracle/runner.rb", __dir__).freeze
  IMPLEMENTATION_SOURCE = File.expand_path("m3_kubernetes_workload_oracle.rb", __dir__).freeze
  CHILD_DESCRIPTORS = {
    "deployment" => [["apps/v1", "replicasets"], ["v1", "pods"]],
    "statefulset" => [["v1", "pods"], ["apps/v1", "controllerrevisions"], ["v1", "persistentvolumeclaims"]],
    "daemonset" => [["v1", "pods"]],
    "job" => [["v1", "pods"]],
    "cronjob" => [["batch/v1", "jobs"], ["v1", "pods"]]
  }.freeze

  class Error < StandardError; end

  module_function

  def run(input_bytes: STDIN.read, source_root: ENV["RUBERNETES_M3_KUBERNETES_SOURCE_ROOT"] || ENV["KUBERNETES_SOURCE_ROOT"], go: ENV.fetch("GO", "go"))
    request = JSON.parse(input_bytes, max_nesting: 512)
    verify_request!(request)
    source = verify_source!(source_root)
    started_at = Time.now.utc.iso8601(6)
    build = build_controller_manager(source.fetch("root"), go: go)
    build_directory = File.dirname(build.fetch("binary"))
    runner = nil
    comparisons = []
    begin
      ControllerManagerCluster.new(binary: build.fetch("binary")).with_client do |client, evidence|
        comparisons = request.fetch("cases").sort_by { |id, _| id }.map do |id, case_document|
          execute_case(client, id, case_document)
        end
        runner = runner_provenance(source: source, build: build, evidence: evidence,
                                   started_at: started_at, finished_at: Time.now.utc.iso8601(6))
      end
      finished_at = Time.now.utc.iso8601(6)
      runner ||= runner_provenance(source: source, build: build, evidence: {},
                                    started_at: started_at, finished_at: finished_at)
      runner["finished_at"] = finished_at
      runner["provenance_sha256"] = provenance_digest(runner.reject { |key, _| key == "provenance_sha256" })
      response_payload = {
        "kubernetes_version" => VERSION, "source_commit" => SOURCE_COMMIT,
        "comparisons" => comparisons
      }
      case_stream_sha256 = request.fetch("cases").to_h do |id, entry|
        [id, entry.fetch("stream_sha256")]
      end
      {
        "executed" => true, "version" => VERSION, "source_commit" => SOURCE_COMMIT,
        "runner_sha256" => runner.fetch("runner_sha256"), "runner" => runner,
        "input" => {
          "raw_sha256" => Digest::SHA256.hexdigest(input_bytes),
          "canonical_sha256" => Digest::SHA256.hexdigest(canonical_json(request)),
          "bytes" => input_bytes.bytesize,
          "case_ids" => request.fetch("cases").keys.sort,
          "stream_sha256" => canonical_digest(request.fetch("cases").transform_values { |entry| entry.fetch("stream") }),
          "case_stream_sha256" => case_stream_sha256
        },
        "output" => {
          "raw_sha256" => Digest::SHA256.hexdigest(JSON.generate(response_payload)),
          "canonical_sha256" => Digest::SHA256.hexdigest(canonical_json(response_payload)),
          "bytes" => JSON.generate(response_payload).bytesize,
          # Provenance binds the exact JSON comparison inventory, not its
          # semantic workload canonicalization. The gate can independently
          # recompute this digest from the returned document without sharing
          # the oracle's dynamic-field normalization rules.
          "comparisons_sha256" => provenance_digest(comparisons)
        },
        "comparisons" => comparisons
      }
    ensure
      FileUtils.remove_entry(build_directory) if build_directory && File.directory?(build_directory)
    end
  rescue JSON::ParserError => error
    raise Error, "workload oracle JSON is invalid: #{error.message}"
  end

  def verify_request!(request)
    raise Error, "workload oracle request must be an object" unless request.is_a?(Hash)
    raise Error, "workload oracle request version is not pinned" unless request["kubernetes_version"] == VERSION
    raise Error, "workload oracle request source commit is not pinned" unless request["source_commit"] == SOURCE_COMMIT
    raise Error, "workload oracle stream version must be 1" unless request["stream_version"] == 1
    cases = request["cases"]
    expected = %w[daemonset:delete daemonset:rollout daemonset:rollback daemonset:scale deployment:delete deployment:rollout deployment:rollback deployment:scale cronjob:delete cronjob:rollout cronjob:rollback cronjob:scale job:delete job:rollout job:rollback job:scale statefulset:delete statefulset:rollout statefulset:rollback statefulset:scale].sort
    raise Error, "workload oracle request must contain exactly 20 independent cases" unless cases.is_a?(Hash) && cases.keys.sort == expected
    cases.each do |id, entry|
      raise Error, "workload oracle case #{id.inspect} must be an object" unless entry.is_a?(Hash)
      raise Error, "workload oracle case #{id.inspect} is not independent" unless entry["independent"] == true
      raise Error, "workload oracle case #{id.inspect} has no deadline" unless entry["deadline_seconds"].is_a?(Numeric) && entry["deadline_seconds"] > 0
      raise Error, "workload oracle case #{id.inspect} has no stream" unless entry["stream"].is_a?(Array) && !entry["stream"].empty?
      raise Error, "workload oracle case #{id.inspect} stream digest is invalid" unless entry["stream_sha256"].to_s.match?(/\A[0-9a-f]{64}\z/)
      raise Error, "workload oracle case #{id.inspect} stream digest is not canonical" unless canonical_digest(entry.fetch("stream")) == entry.fetch("stream_sha256")
    end
  end

  def verify_source!(source_root)
    raise Error, "KUBERNETES_SOURCE_ROOT is required for the external workload oracle" if source_root.to_s.strip.empty?

    root = File.expand_path(source_root)
    raise Error, "Kubernetes source root is not a directory: #{root}" unless File.directory?(root)
    commit = command!(root, "git", "rev-parse", "HEAD").strip
    raise Error, "Kubernetes source commit is #{commit}, expected #{SOURCE_COMMIT}" unless commit == SOURCE_COMMIT
    tag = command!(root, "git", "describe", "--tags", "--exact-match", "HEAD").strip
    raise Error, "Kubernetes source tag is #{tag.inspect}, expected #{VERSION.inspect}" unless tag == VERSION
    status = command!(root, "git", "status", "--porcelain", "--untracked-files=all")
    raise Error, "Kubernetes source tree is not clean" unless status.empty?
    tree = command!(root, "git", "rev-parse", "HEAD^{tree}").strip
    source_inventory = command!(root, "git", "ls-tree", "-r", "--full-tree", "--name-only", "HEAD")
    {
      "root" => root, "repository" => "https://github.com/kubernetes/kubernetes.git",
      "version" => VERSION, "tag" => VERSION, "commit" => SOURCE_COMMIT,
      "tree" => tree, "tree_clean" => true,
      "source_tree_sha256" => Digest::SHA256.hexdigest("#{SOURCE_COMMIT}\0#{tree}"),
      "source_inventory_sha256" => Digest::SHA256.hexdigest(source_inventory),
      "source_inventory_file_count" => source_inventory.lines.reject { |line| line.strip.empty? }.length,
      "runner_source" => ORACLE_SOURCE, "runner_sha256" => Digest::SHA256.file(ORACLE_SOURCE).hexdigest,
      "implementation_sha256" => Digest::SHA256.file(IMPLEMENTATION_SOURCE).hexdigest
    }
  end

  def build_controller_manager(source_root, go:)
    directory = Dir.mktmpdir("rubernetes-m3-controller-manager-")
    binary = File.join(directory, "kube-controller-manager")
    # The pinned v1.36.2 checkout intentionally carries a vendor tree whose
    # modules.txt does not describe its go.mod replacements.  Building with
    # module mode leaves that verified checkout untouched while resolving the
    # exact dependencies declared by the pinned source.
    command = [go, "build", "-mod=mod", "-trimpath", "-o", binary, "./cmd/kube-controller-manager"]
    environment = {"GOWORK" => "off", "CGO_ENABLED" => "0"}
    stdout, stderr, status = Open3.capture3(environment, *command, chdir: source_root)
    unless status.success? && File.file?(binary)
      detail = stderr.to_s.strip
      detail = stdout.to_s.strip if detail.empty?
      detail = "exit status #{status.exitstatus || 1}" if detail.empty?
      raise Error, "pinned Kubernetes controller-manager build failed: #{detail}"
    end
    {
      "binary" => binary, "command" => command, "environment" => environment,
      "stdout_sha256" => Digest::SHA256.hexdigest(stdout), "stderr_sha256" => Digest::SHA256.hexdigest(stderr),
      "binary_sha256" => Digest::SHA256.file(binary).hexdigest, "binary_bytes" => File.size(binary),
      "source_build" => true
    }
  rescue StandardError
    FileUtils.remove_entry(directory) if directory && File.directory?(directory)
    raise
  end

  def runner_provenance(source:, build:, evidence:, started_at:, finished_at:)
    {
      "mode" => "external", "self_comparison" => false,
      "implementation" => "Kubernetes v1.36.2 kube-controller-manager built from pinned source",
      "version" => VERSION, "source_commit" => SOURCE_COMMIT,
      "command" => build.fetch("command"), "process_id" => Process.pid,
      "started_at" => started_at, "finished_at" => finished_at,
      "runner_sha256" => Digest::SHA256.file(ORACLE_SOURCE).hexdigest,
      "implementation_sha256" => Digest::SHA256.file(IMPLEMENTATION_SOURCE).hexdigest,
      "source" => source, "build" => build.reject { |key, _| key == "binary" },
      "image" => {
        "used" => false, "reference" => nil, "digest" => nil,
        "reason" => "direct source execution; no controller-manager image was used",
        "kube_apiserver" => KUBE_APISERVER_IMAGE, "etcd" => ETCD_IMAGE,
        "controller_manager" => {"used" => false, "reference" => nil, "digest" => nil,
                                  "reason" => "controller-manager was built from the pinned source checkout"},
        "network_isolated" => true
      },
      "cluster" => evidence
    }
  end

  def execute_case(client, id, case_document)
    trace = []
    observed_uid = nil
    case_document.fetch("stream").each do |action|
      if action["method"]
        response = client.request(method: action.fetch("method"), path: action.fetch("path"),
                                  body: action["body"], headers: action.fetch("headers", {}))
        trace << {"id" => action.fetch("id"), "method" => action.fetch("method"),
                  "path" => action.fetch("path"), "status" => response.status}
        raise Error, "#{id} #{action.fetch("id")} returned HTTP #{response.status}: #{response.body.inspect}" unless response.status.between?(200, 299)
        observed_uid = response.body.dig("metadata", "uid") if action.fetch("id") == "create-workload" && response.body.is_a?(Hash)
      elsif action["wait"]
        started = monotonic
        state = wait_for(client, case_document, action.fetch("wait"), uid: observed_uid)
        trace << {"id" => action.fetch("id"), "wait" => action.fetch("wait"),
                  "settled" => state.fetch("settled"), "elapsed_seconds" => monotonic - started}
        raise Error, "#{id} #{action.fetch("wait")} deadline expired" unless state.fetch("settled")
      else
        raise Error, "#{id} contains an action without method or wait"
      end
    end
    state = read_state(client, case_document, uid: observed_uid)
    observable = observable(state, trace: trace, case_document: case_document)
    {
      "id" => id, "expected_observable" => observable,
      "expected_sha256" => observable_digest(observable),
      "raw_observable_sha256" => Digest::SHA256.hexdigest(JSON.generate(state)),
      "stream_sha256" => case_document.fetch("stream_sha256"),
      "deadline" => {"seconds" => case_document.fetch("deadline_seconds"), "met" => true},
      "passed" => true
    }
  end

  def wait_for(client, case_document, phase, uid: nil)
    deadline = monotonic + Float(case_document.fetch("deadline_seconds"))
    previous = nil
    stable_count = 0
    loop do
      state = read_state(client, case_document, uid: uid)
      settled = case phase
                when "created" then created_ready?(state, case_document)
                when "updated" then updated_ready?(state, case_document)
                when "deleted" then state["owner"].nil?
                else raise Error, "unsupported wait phase #{phase.inspect}"
                end
      canonical_state = canonical(state)
      stable_count = canonical_state == previous ? stable_count + 1 : 0
      previous = canonical_state
      return state.merge("settled" => true, "deadline_met" => true) if settled && (phase == "deleted" || stable_count >= 1)
      return state.merge("settled" => false, "deadline_met" => false) if monotonic >= deadline

      sleep(POLL_INTERVAL)
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

  def updated_ready?(state, case_document)
    return false unless state["owner"]

    if case_document.fetch("workload_type") == "daemonset" && case_document.fetch("operation") == "scale"
      return state.fetch("owned_resources").length >= case_document.fetch("target_value")
    end

    value_at(state.fetch("owner"), case_document.fetch("target_path")) == case_document.fetch("target_value")
  end

  def read_state(client, case_document, uid: nil)
    type = case_document.fetch("workload_type")
    namespace = case_document.fetch("namespace")
    path = case_document.fetch("resource_path")
    response = client.request(method: "GET", path: path.fetch("member"))
    owner = response.status == 200 ? response.body : nil
    owner_uid = uid || owner&.dig("metadata", "uid")
    owned = []
    CHILD_DESCRIPTORS.fetch(type).each do |api_version, resource|
      base = api_base(api_version)
      list_response = client.request(method: "GET", path: "#{base}/namespaces/#{namespace}/#{resource}")
      next unless list_response.status == 200 && list_response.body.is_a?(Hash)

      Array(list_response.body["items"]).each do |candidate|
        refs = Array(candidate.dig("metadata", "ownerReferences"))
        owned << candidate if refs.any? do |reference|
          reference["uid"].to_s == owner_uid.to_s && reference["kind"].to_s == case_document.fetch("resource").fetch("kind") &&
            reference["name"].to_s == case_document.fetch("resource").dig("metadata", "name").to_s
        end
      end
    end
    event_response = client.request(
      method: "GET", path: "/api/v1/namespaces/#{namespace}/events",
      query: {"fieldSelector" => "involvedObject.uid=#{owner_uid}"}
    )
    events = event_response.status == 200 && event_response.body.is_a?(Hash) ? Array(event_response.body["items"]) : []
    {
      "owner" => owner, "owned_resources" => owned,
      "status" => owner&.fetch("status", {}), "conditions" => conditions_for(owner, owned),
      "events" => events, "phase" => owner ? "present" : "deleted"
    }
  end

  def observable(state, trace:, case_document:)
    status = canonical(state["status"] || {})
    status.delete("updatedReplicas") if state.dig("owner", "kind").to_s == "StatefulSet"
    {
      "resource" => state["owner"] ? canonical_resource(state["owner"]) : {"deleted" => true},
      "owned_resources" => canonical_resources(state["owned_resources"]),
      "status" => status, "conditions" => canonical(state["conditions"]),
      "events" => canonical_resources(state["events"]),
      "request_trace" => trace.map { |entry| entry.reject { |key, _| key == "elapsed_seconds" } },
      "deadline" => {"seconds" => case_document.fetch("deadline_seconds"), "met" => true}
    }
  end

  def conditions_for(owner, owned)
    [owner, *Array(owned)].compact.filter_map do |object|
      conditions = object.dig("status", "conditions")
      next unless conditions.is_a?(Array)

      canonical({"apiVersion" => object["apiVersion"], "kind" => object["kind"],
                 "name" => canonical_generated_name(object["kind"], object.dig("metadata", "name")),
                 "conditions" => conditions})
    end.sort_by { |entry| [entry["kind"].to_s, entry["name"].to_s] }
  end

  def canonical(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source = value.keys.find { |candidate| candidate.to_s == key }
        child = value.fetch(source)
        child = child.sort_by { |condition| [condition.is_a?(Hash) ? condition["type"].to_s : "", condition.is_a?(Hash) ? condition["reason"].to_s : ""] } if key == "conditions" && child.is_a?(Array)
        child = child.sub(/-[bcdfghjklmnpqrstvwxz2456789]{1,10}\z/, "-<generated>") if %w[currentRevision updateRevision].include?(key) && child.is_a?(String)
        result[key] = key == "message" && child.is_a?(String) ? canonical_message(child) : canonical_dynamic(key, child)
      end
    when Array then value.map { |child| canonical(child) }
    else value
    end
  end

  def canonical_dynamic(key, value)
    dynamic_keys = %w[uid resourceVersion creationTimestamp deletionTimestamp time eventTime firstTimestamp lastTimestamp completionTime startTime lastScheduleTime lastSuccessfulTime lastTransitionTime lastUpdateTime lastProbeTime]
    return canonical(value) unless dynamic_keys.include?(key)
    return nil if value.nil?
    return "<uid>" if key == "uid"
    return "<resourceVersion>" if key == "resourceVersion"

    begin
      Time.iso8601(value.to_s)
      "<timestamp>"
    rescue ArgumentError
      value
    end
  end

  def canonical_message(value)
    normalized = value.gsub(/(replica set\s+|ReplicaSet\s+")(\S+?)-[bcdfghjklmnpqrstvwxz2456789]{1,10}(?=[\s"]|\z)/) do
      "#{$1}#{$2}-<generated>"
    end
    normalized.gsub(/((?:Created|Deleted) pod:\s+)[A-Za-z0-9._-]+/) do
      "#{$1}workload-<generated>"
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
      # StatefulSet ordinal names are identity-bearing and must remain exact.
      # For other Pods only replace Kubernetes' five-character generated
      # suffix; fixed names and ordinal-looking names must not collide.
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
      # Preserve every user-supplied scheduling, security, storage, and
      # container field. These fields are part of the workload contract;
      # dropping them would let materially different manifests share a digest.
      spec["tolerations"] = Array(spec["tolerations"]) if spec.key?("tolerations")
      spec["containers"] = Array(spec["containers"]) if spec.key?("containers")
      # Every field listed here is observable workload input, even when
      # Kubernetes also supplies a default for it. Keep it in the oracle
      # contract so materially different Pods cannot share a digest.
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
    # StatefulSet ordinals, pod identity, Job ownership, and generation labels
    # are meaningful observations. Only generated hash labels are normalized in
    # semantic_resource; no user/controller identity labels are discarded here.
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
      # Keep the complete pod-template semantics. API defaults are observable
      # and must not be mistaken for caller input that can be discarded.
      spec["tolerations"] = Array(spec["tolerations"]) if spec.key?("tolerations")
      spec["containers"] = Array(spec["containers"]) if spec.key?("containers")
    end
    candidate
  end

  def value_at(object, path)
    Array(path).reduce(object) do |value, key|
      if value.is_a?(Hash)
        value[key]
      elsif value.is_a?(Array) && key.is_a?(Integer)
        value[key]
      end
    end
  end

  def api_base(api_version)
    if api_version.include?("/")
      group, version = api_version.split("/", 2)
      "/apis/#{group}/#{version}"
    else
      "/api/#{api_version}"
    end
  end

  def canonical_digest(value)
    Digest::SHA256.hexdigest(canonical_json(value))
  end

  # An observable is stored already canonical; its digest is the plain
  # sorted-key digest of that stored value so that the probe and the M3 gate
  # re-verify it without a second, non-idempotent canonicalisation pass.
  def observable_digest(value)
    Digest::SHA256.hexdigest(JSON.generate(sorted_value(value)))
  end

  def sorted_value(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = sorted_value(value.fetch(source))
      end
    when Array then value.map { |child| sorted_value(child) }
    else value
    end
  end

  def provenance_digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical_keys(value)))
  end

  def canonical_keys(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical_keys(value.fetch(source))
      end
    when Array then value.map { |child| canonical_keys(child) }
    else value
    end
  end

  def canonical_json(value)
    JSON.generate(canonical(value))
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def command!(directory, *command)
    stdout, stderr, status = Open3.capture3(*command, chdir: directory)
    return stdout if status.success?

    detail = stderr.to_s.strip
    detail = "exit status #{status.exitstatus || 1}" if detail.empty?
    raise Error, "#{command.join(" ")} failed: #{detail}"
  end

  class ControllerManagerCluster < M1KubernetesOracle::DockerCluster
    def initialize(binary:, **options)
      super(**options)
      @binary = binary
      @controller_pid = nil
      @controller_log = nil
    end

    def with_client
      super do |client, evidence|
        started_at = Time.now.utc.iso8601(6)
        start_controller_manager(client, evidence)
        controller = controller_evidence(started_at: started_at)
        begin
          yield(client, evidence.merge(controller_manager: controller))
        ensure
          stop_controller_manager
          controller["finished_at"] = @controller_finished_at if controller
        end
      end
    end

    private

    def start_controller_manager(client, evidence)
      ca_file = client.instance_variable_get(:@ca_file)
      token = client.instance_variable_get(:@token)
      port = evidence.fetch("published_port")
      kubeconfig = File.join(File.dirname(ca_file), "m3-controller-manager.kubeconfig.json")
      File.write(kubeconfig, JSON.generate(
        "apiVersion" => "v1", "kind" => "Config",
        "clusters" => [{"name" => "oracle", "cluster" => {"server" => "https://127.0.0.1:#{port}", "certificate-authority" => ca_file}}],
        "users" => [{"name" => "oracle", "user" => {"token" => token}}],
        "contexts" => [{"name" => "oracle", "context" => {"cluster" => "oracle", "user" => "oracle"}}],
        "current-context" => "oracle"
      ))
      @controller_log = Tempfile.new(["rubernetes-m3-controller-manager-", ".log"])
      @controller_log.close
      command = [@binary, "--kubeconfig=#{kubeconfig}", "--leader-elect=false",
                 "--controllers=deployment,replicaset,statefulset,daemonset,job,cronjob",
                 "--bind-address=127.0.0.1", "--secure-port=0", "--profiling=false", "--v=0"]
      @controller_command = command
      @controller_started_at = Time.now.utc.iso8601(6)
      @controller_pid = Process.spawn({"GOMAXPROCS" => "2"}, *command, out: @controller_log.path, err: @controller_log.path)
      sleep 0.5
      status = Process.waitpid(@controller_pid, Process::WNOHANG)
      raise controller_failure(status) if status
    rescue Errno::ENOENT => error
      raise Error, "controller-manager process could not be started: #{error.message}"
    end

    def stop_controller_manager
      return unless @controller_pid

      status = nil
      begin
        Process.kill("TERM", @controller_pid)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10.0
        loop do
          status = Process.waitpid(@controller_pid, Process::WNOHANG)
          break if status || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep 0.1
        end
        unless status
          Process.kill("KILL", @controller_pid)
          status = Process.waitpid(@controller_pid)
        end
      rescue Errno::ESRCH, Errno::ECHILD
        status = nil
      ensure
        @controller_pid = nil
        @controller_finished_at = Time.now.utc.iso8601(6)
      end
      status
    end

    def controller_failure(status)
      output = File.file?(@controller_log.path) ? File.read(@controller_log.path)[-12_000, 12_000] : ""
      Error.new("kube-controller-manager exited before workload execution (#{status.inspect}): #{output}")
    end

    def controller_evidence(started_at:)
      {
        "pid" => @controller_pid,
        "command" => @controller_command,
        "started_at" => started_at,
        "finished_at" => @controller_finished_at,
        "log_sha256" => @controller_log && Digest::SHA256.file(@controller_log.path).hexdigest,
        "binary_sha256" => Digest::SHA256.file(@binary).hexdigest
      }
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    puts JSON.generate(M3KubernetesWorkloadOracle.run)
  rescue StandardError => error
    warn error.message
    exit 1
  end
end
