#!/usr/bin/env ruby
# frozen_string_literal: true

# K7 — upgrade and recovery (spec/verification/kubernetes-compatibility.md#k7).
#
# Migrates a single-node MemoryStore to Raft, scales to three control
# nodes, and exercises release transitions and recovery. Acknowledged
# objects, managedFields, UID ownership, volume attachments and Pod
# identity must survive every stage.

require "digest"
require "fileutils"
require "ipaddr"
require "json"
require "open3"
require "optparse"
require "time"

require_relative "k7_checks"
require_relative "k7_contract"
require_relative "k7_state_inventory"

module Conformance
  module K7Lifecycle
    ROOT = File.expand_path("../..", __dir__)
    KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")
    DEFAULT_DRIVER = File.join(__dir__, "k7_cluster_driver.rb")
    NODE_EVICTION_TAINTS = %w[node.kubernetes.io/not-ready node.kubernetes.io/unreachable].freeze
    NODE_CONDITION_TAINTS = (NODE_EVICTION_TAINTS + %w[
      node.kubernetes.io/memory-pressure node.kubernetes.io/disk-pressure node.kubernetes.io/network-unavailable
      node.kubernetes.io/pid-pressure node.kubernetes.io/unschedulable
    ]).freeze

    STAGES = K7Contract::STAGES

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/conformance/k7")}
      OptionParser.new do |parser|
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
        parser.on("--oracle-kubeconfig PATH") { |v| options[:oracle_kubeconfig] = v }
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--driver PATH", "Cluster driver script implementing the stages") { |v| options[:driver] = v }
      end.parse!(argv)
      raise ArgumentError, "--kubeconfig is required" if options[:kubeconfig].nil?

      options[:kubeconfig] = File.expand_path(options.fetch(:kubeconfig))
      options[:oracle_kubeconfig] = File.expand_path(options[:oracle_kubeconfig]) if options[:oracle_kubeconfig]
      options[:output] = File.expand_path(options.fetch(:output))
      FileUtils.mkdir_p(options[:output])
      driver = options[:driver] || ENV["RUBERNETES_K7_DRIVER"] || default_driver(options.fetch(:kubeconfig))
      driver = File.expand_path(driver) if driver
      inventory_sha256 = K7Contract.state_inventory_sha256
      baseline = nil
      results = STAGES.map do |stage|
        before = capture_state(options)
        baseline ||= before
        run_stage(stage, driver, before, ready_workloads(baseline), options)
      end
      upgrade = results.find { |stage| stage.fetch("id") == "release_upgrade" }
      rollback = results.find { |stage| stage.fetch("id") == "rollback" }
      if upgrade["operation_passed"]
        upgrade["reversible"] = rollback["operation_passed"] == true
        unless upgrade["reversible"]
          upgrade.merge!("passed" => false, "status" => rollback.fetch("status"), "reason" => "rollback did not verify the upgraded datastore")
        end
      end
      report = {
        "schema_version" => 1,
        "kind" => "k7_upgrade_and_recovery",
        "generated_at" => Time.now.utc.iso8601,
        "driver" => driver,
        "state_inventory_sha256" => inventory_sha256,
        "state_inventory_stable" => inventory_sha256 == K7Contract.state_inventory_sha256,
        **baseline_summary(baseline),
        "stages" => results,
        "data_loss" => results.flat_map { |stage| Array(stage["data_loss"]) },
        "stuck_operations" => results.flat_map { |stage| Array(stage["stuck_operations"]) },
        "irreversible_migrations" => results.select { |stage| stage["reversible"] == false }.map { |s| s.fetch("id") }
      }
      File.write(File.join(options[:output], "lifecycle.json"), "#{JSON.pretty_generate(report)}\n")
      if report.fetch("state_inventory_stable") && report.fetch("baseline_missing").empty? &&
         report.fetch("data_loss").empty? && report.fetch("stuck_operations").empty? &&
         report.fetch("irreversible_migrations").empty? && results.all? { |stage| stage["passed"] }
        0
      else
        1
      end
    end

    def default_driver(kubeconfig)
      root = ENV["RUBERNETES_K7_CLUSTER_ROOT"] || File.dirname(File.expand_path(kubeconfig))
      descriptor = JSON.parse(File.binread(File.join(root, "cluster.json")))
      DEFAULT_DRIVER if descriptor["k7_bootstrap"] == true && File.realpath(descriptor.fetch("kubeconfig")) == File.realpath(kubeconfig)
    rescue SystemCallError, JSON::ParserError, KeyError
      nil
    end

    def baseline_summary(baseline)
      objects = baseline.fetch("objects")
      pods = objects.count { |object| object.fetch("kind") == "Pod" && object.fetch("group", "").empty? }
      ready = ready_workloads(baseline).length
      attachments = objects.select { |object| object.fetch("kind") == "VolumeAttachment" && object.fetch("group", "storage.k8s.io") == "storage.k8s.io" }
      attached = attachments.count { |object| object.dig("volumes", "attached") == true }
      missing = []
      missing << baseline.fetch("read_error") if baseline["read_error"]
      missing << "Pod identity" if pods.zero?
      missing << "Ready Pod" if pods.positive? && ready.zero?
      missing << "attached VolumeAttachment" if attached.zero?
      {"baseline_objects" => objects.length, "baseline_pods" => pods, "baseline_ready_pods" => ready,
       "baseline_volume_attachments" => attachments.length, "baseline_attached_volumes" => attached,
       "baseline_missing" => missing}
    end

    def run_stage(stage, driver, baseline, workloads, options)
      id = stage.fetch("id")
      if driver.nil? || !File.executable?(driver)
        return stage.merge("passed" => false, "status" => "INCOMPLETE",
                           "reason" => "no cluster driver: set --driver or RUBERNETES_K7_DRIVER to a script implementing the stages")
      end
      unless baseline.fetch("available")
        return stage.merge("passed" => false, "status" => "INCOMPLETE", "reason" => "pre-stage API state was not readable",
                           "read_error" => baseline["read_error"])
      end

      started = Time.now.utc
      out, err, status = Open3.capture3({"KUBECONFIG" => File.expand_path(options.fetch(:kubeconfig))}, driver, id, chdir: ROOT)
      after = capture_state(options)
      loss = compare_state(baseline, after)
      evidence = parse_evidence(out)
      reversible =
        (evidence["memory_snapshot_round_trip"] == true if status.success? && id == "memory_to_raft")
      operation_passed = status.success? && loss.empty? && reversible != false
      checks = operation_passed ? K7Checks.run(id, options) : {}
      stuck = stuck_operations(options, workloads: status.success? ? workloads : [])
      operation_passed &&= stuck.empty?
      passed = operation_passed && checks.values.all? { |check| check.fetch("passed") }
      # Exit 2 is the driver saying "not performed on this topology" (with the
      # reason on stderr): recorded as INCOMPLETE, never as a pass or a failure
      # of the cluster.
      not_performed = status.exitstatus == 2
      stage_status = if passed
                       "COMPLETE"
                     elsif !loss.empty? || !stuck.empty?
                       "FAILED"
                     elsif not_performed || (operation_passed && checks.values.none? { |check| check.fetch("status") == "FAILED" })
                       "INCOMPLETE"
                     else
                       "FAILED"
                     end
      finished = Time.now.utc
      stage.merge(
        "passed" => passed,
        "operation_passed" => operation_passed,
        "status" => stage_status,
        "reason" => stage_reason(not_performed, err, loss, stuck, checks),
        "exit_status" => status.exitstatus,
        "started_at" => started.iso8601(6),
        "finished_at" => finished.iso8601(6),
        "elapsed_seconds" => (finished - started).round(3),
        "data_loss" => loss,
        "stuck_operations" => stuck,
        "reversible" => reversible,
        "evidence" => evidence,
        "api_inventory" => {"before" => inventory_receipt(baseline), "after" => inventory_receipt(after)},
        "checks" => checks,
        "stderr" => status.success? ? nil : err.lines.last(5).join.strip
      )
    end

    def inventory_receipt(state)
      return unless state.fetch("available")

      objects = state.fetch("objects").sort_by { |object| object_key(object).map(&:to_s) }
      {"objects" => objects.length, "sha256" => content_digest(objects)}
    end

    def stage_reason(not_performed, stderr, loss, stuck, checks)
      return stderr.lines.last.to_s.strip if not_performed
      return "acknowledged API state changed" unless loss.empty?
      return "operations remain stuck" unless stuck.empty?

      unsuccessful = checks.reject { |_check, result| result.fetch("passed") }.keys
      "verification did not pass for #{unsuccessful.join(", ")}" unless unsuccessful.empty?
    end

    def capture_state(options)
      inventory = K7StateInventory.new(KUBECTL, options.fetch(:kubeconfig))
      objects = []
      identities = Set.new
      inventory.each_item do |item|
        object = object_snapshot(item)
        raise K7StateInventory::Unreadable, "duplicate object identity in the API inventory" unless identities.add?(object_key(object))

        objects << object
      end
      {"available" => true, "objects" => objects}
    rescue K7StateInventory::Unreadable => error
      {"available" => false, "objects" => [], "read_error" => error.message}
    end

    def object_snapshot(item)
      kind = item.fetch("kind")
      group = item.fetch("apiVersion").rpartition("/").first
      metadata = item.fetch("metadata")
      name = metadata.fetch("name")
      uid = metadata.fetch("uid")
      unless [kind, name, uid].all? { |value| value.is_a?(String) && !value.empty? }
        raise K7StateInventory::Unreadable, "invalid object identity in the API inventory"
      end

      {
        "group" => group, "kind" => kind, "namespace" => metadata["namespace"], "name" => name, "uid" => uid,
        "ready" => ready_pod?(item),
        "owners" => Array(metadata["ownerReferences"]).map { |ref| canonical(ref) }.sort_by { |ref| ref.fetch("uid") },
        "managed_fields" => managed_fields(metadata["managedFields"], kind: (kind if group.empty?)),
        "volumes" => volume_identity(item, group),
        "declared_digest" => content_digest(declared_content(item)),
        "data" => (content_digest(item.slice("data", "binaryData")) if group.empty? && %w[ConfigMap Secret].include?(kind)),
        "established" => (K7StateInventory.established?(item) if group == "apiextensions.k8s.io" && kind == "CustomResourceDefinition")
      }
    end

    def declared_content(item)
      content = item.except("apiVersion", "kind", "metadata", "status")
      case item.values_at("apiVersion", "kind")
      when %w[v1 Node]
        spec = node_spec(content.fetch("spec", {}))
        spec.empty? ? content.except("spec") : content.merge("spec" => spec)
      when %w[v1 PersistentVolume]
        ref = content.dig("spec", "claimRef")
        ref ? content.merge("spec" => content.fetch("spec").merge("claimRef" => ref.except("resourceVersion"))) : content
      else content
      end
    end

    def node_spec(spec)
      # Node health and readiness are controller outputs. Their taints can
      # change after a reboot, while operator taints and the rest of spec persist.
      taints = Array(spec["taints"]).reject do |taint|
        (taint["effect"] == "NoSchedule" && NODE_CONDITION_TAINTS.include?(taint["key"])) ||
          (taint["effect"] == "NoExecute" && NODE_EVICTION_TAINTS.include?(taint["key"]))
      end
      taints.empty? ? spec.except("taints") : spec.merge("taints" => taints)
    end

    def content_digest(value)
      Digest::SHA256.hexdigest(JSON.generate(canonical(value), max_nesting: false))
    end

    def ready_pod?(item)
      item["kind"] == "Pod" && item.fetch("apiVersion", "v1") == "v1" && item.dig("status", "phase") == "Running" &&
        Array(item.dig("status", "conditions")).any? { |condition| condition.values_at("type", "status") == %w[Ready True] }
    end

    def ready_workloads(state)
      state.fetch("objects").select { |object| object["ready"] }
        .map { |object| object.slice("kind", "namespace", "name", "uid") }
    end

    def volume_identity(item, group)
      spec = item["spec"] || {}
      case [group, item["kind"]]
      when ["", "Pod"]
        content_digest(spec["volumes"])
      when ["", "PersistentVolume"]
        content_digest(spec.merge("claimRef" => spec["claimRef"]&.slice("name", "namespace", "uid")))
      when ["", "PersistentVolumeClaim"]
        spec["volumeName"]
      when ["storage.k8s.io", "VolumeAttachment"]
        {"attached" => item.dig("status", "attached"), "digest" => content_digest([spec, item.dig("status", "attachmentMetadata")])}
      end
    end

    def canonical(value)
      case value
      when Hash then value.keys.sort.to_h { |key| [key, canonical(value.fetch(key))] }
      when Array then value.map { |item| canonical(item) }
      else value
      end
    end

    def managed_fields(fields, kind: nil)
      # Recovering components can acknowledge new fields, such as the first
      # kubelet status update. Preserve the owners of fields already stored.
      Array(fields).flat_map do |entry|
        manager = canonical(entry.except("time", "fieldsV1"))
        owned_field_paths(entry.fetch("fieldsV1", {})).map do |path|
          path = pod_ip_field_path(path) if kind == "Pod" && entry["subresource"] == "status"
          Digest::SHA256.hexdigest(JSON.generate([manager, path]))
        end
      end.sort.uniq
    end

    def pod_ip_field_path(path)
      selector = path[2]
      return path unless path.first(2) == %w[f:status f:podIPs] && selector&.start_with?("k:")

      key = JSON.parse(selector.delete_prefix("k:"))
      return path unless key.is_a?(Hash) && key.keys == ["ip"] && key["ip"].is_a?(String)

      # Restarting a Pod sandbox may allocate another IP for the same Pod.
      family = IPAddr.new(key.fetch("ip")).ipv4? ? "IPv4" : "IPv6"
      [*path.first(2), "ip-family:#{family}", *path.drop(3)]
    rescue JSON::ParserError, IPAddr::InvalidAddressError
      path
    end

    def owned_field_paths(tree, parent = [])
      return [parent] unless tree.is_a?(Hash) && !tree.empty?

      tree.flat_map do |key, child|
        key == "." ? [parent] : owned_field_paths(child, parent + [key])
      end
    end

    def compare_state(before, after)
      return [{"reason" => "baseline state was not readable", "read_error" => before["read_error"]}.compact] unless before.fetch("available")
      return [{"reason" => "post-stage state was not readable", "read_error" => after["read_error"]}.compact] unless after.fetch("available")

      index = after.fetch("objects").to_h { |object| [object_key(object), object] }
      before.fetch("objects").filter_map do |object|
        key = object_key(object)
        current = index[key]
        next {"object" => key, "reason" => "object disappeared"} if current.nil?
        if current["uid"] != object["uid"]
          next {"object" => key, "reason" => "uid changed", "before" => object["uid"],
                "after" => current["uid"]}
        end
        next {"object" => key, "reason" => "ownerReferences changed"} if current["owners"] != object["owners"]
        next {"object" => key, "reason" => "managedFields ownership was lost"} unless (object.fetch("managed_fields") - current.fetch("managed_fields")).empty?
        next {"object" => key, "reason" => "volumes changed"} if current["volumes"] != object["volumes"]
        next {"object" => key, "reason" => "acknowledged data changed"} if current["data"] != object["data"]
        next {"object" => key, "reason" => "CRD stopped serving"} if object["established"] && !current["established"]
        next {"object" => key, "reason" => "declared content changed"} if current["declared_digest"] != object["declared_digest"]

        nil
      end
    end

    def object_key(object)
      [object["group"], object["kind"], object["namespace"], object["name"]]
    end

    def stuck_operations(options, workloads:)
      out, _err, status = Open3.capture3(KUBECTL, "--request-timeout=10s", "--kubeconfig", options.fetch(:kubeconfig),
                                         "get", "namespaces,pods", "--all-namespaces", "-o", "json")
      return [{"reason" => "pending operations were not readable"}] unless status.success?

      items = JSON.parse(out).fetch("items")
      pending = items.filter_map do |item|
        phase = item.dig("status", "phase")
        deleting = !item.dig("metadata", "deletionTimestamp").nil?
        next unless deleting || phase == "Terminating"

        {"kind" => item["kind"], "name" => item.dig("metadata", "name"),
         "namespace" => item.dig("metadata", "namespace"),
         "finalizers" => item.dig("metadata", "finalizers"), "phase" => phase}
      end
      pending + unavailable_workloads(workloads, items)
    rescue JSON::ParserError, KeyError
      [{"reason" => "pending operations were not readable"}]
    end

    def unavailable_workloads(workloads, items)
      pods = items.select { |item| item["kind"] == "Pod" }.to_h { |item| [item.dig("metadata", "uid"), item] }
      workloads.filter_map do |pod|
        item = pods[pod.fetch("uid")]
        next if item && ready_pod?(item)

        pod.merge("reason" => "baseline workload did not recover to Ready",
                  "phase" => item&.dig("status", "phase"))
      end
    end

    def parse_evidence(out)
      result = JSON.parse(out)
      result.is_a?(Hash) ? result : {}
    rescue JSON::ParserError
      {}
    end
  end
end

exit(Conformance::K7Lifecycle.run) if $PROGRAM_NAME == __FILE__
