#!/usr/bin/env ruby
# frozen_string_literal: true

# K7 — upgrade and recovery (spec/verification/kubernetes-compatibility.md#k7).
#
# Walks single-node -> 3-node, MemoryStore -> RaftStore and an older Rubernetes
# release -> 1.0.0, running a K1 smoke subset and a K5 state comparison at each
# stage.  Acknowledged objects, managedFields, UID ownership, volume
# attachments and Pod identity must survive every stage, and no storage
# migration may be irreversible.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

module Conformance
  module K7Lifecycle
    ROOT = File.expand_path("../..", __dir__)
    KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")

    STAGES = [
      {"id" => "single_to_three_node", "description" => "single-node cluster grown to 3 control nodes"},
      {"id" => "memory_to_raft", "description" => "MemoryStore datastore migrated to RaftStore"},
      {"id" => "release_upgrade", "description" => "previous Rubernetes release upgraded to 1.0.0"},
      {"id" => "rollback", "description" => "1.0.0 rolled back to the previous release"},
      {"id" => "apiserver_rolling_restart", "description" => "API server rolling restart"},
      {"id" => "controller_leader_loss", "description" => "controller-manager leader lost"},
      {"id" => "scheduler_leader_loss", "description" => "scheduler leader lost"},
      {"id" => "worker_reboot", "description" => "worker node rebooted"},
      {"id" => "backup_restore", "description" => "backup taken and restored"}
    ].freeze

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/conformance/k7")}
      OptionParser.new do |parser|
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--driver PATH", "Cluster driver script implementing the stages") { |v| options[:driver] = v }
      end.parse!(argv)
      raise ArgumentError, "--kubeconfig is required" if options[:kubeconfig].nil?

      FileUtils.mkdir_p(options[:output])
      driver = options[:driver] || ENV.fetch("RUBERNETES_K7_DRIVER", nil)
      baseline = capture_state(options)
      results = STAGES.map { |stage| run_stage(stage, driver, baseline, options) }
      report = {
        "schema_version" => 1,
        "kind" => "k7_upgrade_and_recovery",
        "generated_at" => Time.now.utc.iso8601,
        "driver" => driver,
        "baseline_objects" => baseline.fetch("objects").length,
        "stages" => results,
        "data_loss" => results.flat_map { |stage| Array(stage["data_loss"]) },
        "stuck_operations" => results.flat_map { |stage| Array(stage["stuck_operations"]) },
        "irreversible_migrations" => results.select { |stage| stage["reversible"] == false }.map { |s| s.fetch("id") }
      }
      File.write(File.join(options[:output], "lifecycle.json"), "#{JSON.pretty_generate(report)}\n")
      if report.fetch("data_loss").empty? && report.fetch("stuck_operations").empty? &&
         report.fetch("irreversible_migrations").empty? && results.all? { |stage| stage["passed"] }
        0
      else
        1
      end
    end

    def run_stage(stage, driver, baseline, options)
      id = stage.fetch("id")
      if driver.nil? || !File.executable?(driver)
        return stage.merge("passed" => false, "status" => "INCOMPLETE",
                           "reason" => "no cluster driver: set --driver or RUBERNETES_K7_DRIVER to a script implementing the stages")
      end

      started = Time.now.utc
      _out, err, status = Open3.capture3({"KUBECONFIG" => options.fetch(:kubeconfig)}, driver, id, chdir: ROOT)
      after = capture_state(options)
      loss = compare_state(baseline, after)
      stuck = stuck_operations(options)
      # Exit 2 is the driver saying "not performed on this topology" (with the
      # reason on stderr): recorded as INCOMPLETE, never as a pass or a failure
      # of the cluster.
      not_performed = status.exitstatus == 2
      stage_status = if status.success?
                       "COMPLETE"
                     elsif not_performed
                       "INCOMPLETE"
                     else
                       "FAILED"
                     end
      stage.merge(
        "passed" => status.success? && loss.empty? && stuck.empty?,
        "status" => stage_status,
        "reason" => not_performed ? err.lines.last.to_s.strip : nil,
        "exit_status" => status.exitstatus,
        "elapsed_seconds" => (Time.now.utc - started).round(3),
        "data_loss" => loss,
        "stuck_operations" => stuck,
        "reversible" => reversible?(id, options),
        "stderr" => status.success? ? nil : err.lines.last(5).join.strip
      )
    end

    # Acknowledged objects are identified by (kind, namespace, name) and must
    # keep their UID, ownerReferences and managedFields across every stage.
    def capture_state(options)
      out, _err, status = Open3.capture3(KUBECTL, "--kubeconfig", options.fetch(:kubeconfig),
                                         "get", "all,configmaps,secrets,pvc,pv", "--all-namespaces",
                                         "-o", "json", "--show-managed-fields")
      return {"available" => false, "objects" => []} unless status.success?

      items = begin
        JSON.parse(out)["items"]
      rescue StandardError
        []
      end || []
      {
        "available" => true,
        "objects" => items.map do |item|
          {
            "kind" => item["kind"],
            "namespace" => item.dig("metadata", "namespace"),
            "name" => item.dig("metadata", "name"),
            "uid" => item.dig("metadata", "uid"),
            "owners" => Array(item.dig("metadata", "ownerReferences")).map { |ref| ref["uid"] }.sort,
            "managed_fields" => Digest::SHA256.hexdigest(JSON.generate(item.dig("metadata", "managedFields") || [])),
            "volumes" => Array(item.dig("spec", "volumes")).map { |volume| volume["name"] }.sort
          }
        end
      }
    end

    def compare_state(before, after)
      return [{"reason" => "baseline state was not readable"}] unless before.fetch("available")
      return [{"reason" => "post-stage state was not readable"}] unless after.fetch("available")

      index = after.fetch("objects").to_h { |object| [[object["kind"], object["namespace"], object["name"]], object] }
      before.fetch("objects").filter_map do |object|
        key = [object["kind"], object["namespace"], object["name"]]
        current = index[key]
        next {"object" => key, "reason" => "object disappeared"} if current.nil?
        if current["uid"] != object["uid"]
          next {"object" => key, "reason" => "uid changed", "before" => object["uid"],
                "after" => current["uid"]}
        end
        next {"object" => key, "reason" => "ownerReferences changed"} if current["owners"] != object["owners"]
        next {"object" => key, "reason" => "managedFields changed"} if current["managed_fields"] != object["managed_fields"]
        next {"object" => key, "reason" => "volumes changed"} if current["volumes"] != object["volumes"]

        nil
      end
    end

    def stuck_operations(options)
      out, _err, status = Open3.capture3(KUBECTL, "--kubeconfig", options.fetch(:kubeconfig),
                                         "get", "namespaces,pods", "--all-namespaces", "-o", "json")
      return [] unless status.success?

      items = begin
        JSON.parse(out)["items"]
      rescue StandardError
        []
      end || []
      items.filter_map do |item|
        phase = item.dig("status", "phase")
        deleting = !item.dig("metadata", "deletionTimestamp").nil?
        next unless deleting || phase == "Terminating"

        {"kind" => item["kind"], "name" => item.dig("metadata", "name"),
         "namespace" => item.dig("metadata", "namespace"),
         "finalizers" => item.dig("metadata", "finalizers"), "phase" => phase}
      end
    end

    # A storage migration is reversible when the previous release can still read
    # the on-disk state; the driver reports this through a `<stage>-reversible`
    # probe so the check stays a real observation rather than an assumption.
    def reversible?(stage_id, options)
      driver = options[:driver] || ENV.fetch("RUBERNETES_K7_DRIVER", nil)
      return false if driver.nil? || !File.executable?(driver)

      _out, _err, status = Open3.capture3({"KUBECONFIG" => options.fetch(:kubeconfig)},
                                          driver, "#{stage_id}-reversible", chdir: ROOT)
      status.success?
    end
  end
end

exit(Conformance::K7Lifecycle.run) if $PROGRAM_NAME == __FILE__
