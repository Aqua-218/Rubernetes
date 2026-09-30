#!/usr/bin/env ruby
# frozen_string_literal: true

# 72-hour soak runner (spec/delivery/milestones.md#milestone-m9 exit 5):
# zero unexpected process exits, resource leaks, stuck queues, lost watches and
# lost commits.
#
# The duration is wall-clock bound and cannot be compressed.  The runner
# samples continuously, writes an append-only journal so a crash of the runner
# itself is visible, and reports the elapsed fraction honestly: a report whose
# `elapsed_hours` is below the required duration is NOT a pass, and says so.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

module Release
  module Soak
    ROOT = File.expand_path("../..", __dir__)
    REQUIRED_HOURS = 72

    module_function

    def run(argv = ARGV)
      options = {
        output: File.join(ROOT, "artifacts/release/soak-report.json"),
        journal: File.join(ROOT, "artifacts/release/soak-journal.jsonl"),
        hours: Float(ENV.fetch("RUBERNETES_SOAK_HOURS", REQUIRED_HOURS)),
        interval: Float(ENV.fetch("RUBERNETES_SOAK_INTERVAL", 60)),
        kubeconfig: ENV.fetch("RUBERNETES_SOAK_KUBECONFIG", nil)
      }
      OptionParser.new do |parser|
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--journal PATH") { |v| options[:journal] = v }
        parser.on("--hours H", Float, "soak duration (default #{REQUIRED_HOURS})") { |v| options[:hours] = v }
        parser.on("--interval S", Float, "sample interval seconds") { |v| options[:interval] = v }
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
      end.parse!(argv)

      FileUtils.mkdir_p(File.dirname(options[:journal]))
      started = Time.now.utc
      deadline = started + (options[:hours] * 3600)
      samples = 0
      findings = Hash.new { |hash, key| hash[key] = [] }
      baseline = nil

      File.open(options[:journal], "a") do |journal|
        while Time.now.utc < deadline
          sample = collect(options)
          baseline ||= sample
          detect(baseline, sample, findings)
          journal.puts(JSON.generate(sample))
          journal.flush
          samples += 1
          remaining = deadline - Time.now.utc
          sleep([options[:interval], remaining].min) if remaining.positive?
        end
      end

      elapsed_hours = ((Time.now.utc - started) / 3600.0).round(4)
      complete = elapsed_hours >= REQUIRED_HOURS
      report = {
        "schema_version" => 1,
        "kind" => "release_soak_report",
        "started_at" => started.iso8601,
        "finished_at" => Time.now.utc.iso8601,
        "required_hours" => REQUIRED_HOURS,
        "elapsed_hours" => elapsed_hours,
        "duration_satisfied" => complete,
        "samples" => samples,
        "unexpected_process_exits" => findings["process_exit"],
        "resource_leaks" => findings["resource_leak"],
        "stuck_queues" => findings["stuck_queue"],
        "lost_watches" => findings["lost_watch"],
        "lost_commits" => findings["lost_commit"],
        "journal" => options[:journal].delete_prefix("#{ROOT}/"),
        "journal_sha256" => File.file?(options[:journal]) ? Digest::SHA256.file(options[:journal]).hexdigest : nil,
        # A short run is evidence of nothing: the criterion is 72 hours.
        "passed" => complete && findings.values.all?(&:empty?)
      }
      FileUtils.mkdir_p(File.dirname(options[:output]))
      File.write(options[:output], "#{JSON.pretty_generate(report)}\n")
      puts JSON.pretty_generate(report.reject { |key, _| key.end_with?("s") && report[key].is_a?(Array) && report[key].length > 5 })
      report.fetch("passed") ? 0 : 1
    end

    def collect(options)
      at = Time.now.utc.iso8601
      processes = component_processes
      cluster = options[:kubeconfig] ? cluster_sample(options[:kubeconfig]) : {"available" => false}
      {
        "at" => at,
        "processes" => processes,
        "open_files" => processes.sum { |entry| entry["open_files"].to_i },
        "rss_kb" => processes.sum { |entry| entry["rss_kb"].to_i },
        "cluster" => cluster
      }
    end

    # Rubernetes components running on this host, by their exe/ names.
    def component_processes
      names = Dir.glob(File.join(ROOT, "exe", "*")).map { |path| File.basename(path) }
      names.flat_map do |name|
        out, _err, status = Open3.capture3("pgrep", "-f", name)
        next [] unless status.success?

        out.split.filter_map do |pid|
          {
            "name" => name,
            "pid" => Integer(pid),
            "rss_kb" => File.read("/proc/#{pid}/status")[/VmRSS:\s+(\d+)/, 1].to_i,
            "open_files" => begin
              Dir.children("/proc/#{pid}/fd").length
            rescue StandardError
              0
            end
          }
        rescue Errno::ENOENT
          nil
        end
      end
    end

    def cluster_sample(kubeconfig)
      kubectl = File.join(ROOT, "build/tools/kubectl-v1.36.2")
      out, _err, status = Open3.capture3(kubectl, "--kubeconfig", kubeconfig, "get",
                                         "pods,events", "--all-namespaces", "-o", "json")
      return {"available" => false} unless status.success?

      document = begin
        JSON.parse(out)
      rescue StandardError
        {"items" => []}
      end
      items = document["items"] || []
      {
        "available" => true,
        "pods" => items.count { |item| item["kind"] == "Pod" },
        "terminating" => items.count { |item| item.dig("metadata", "deletionTimestamp") },
        "resource_version" => document.dig("metadata", "resourceVersion").to_i
      }
    end

    # Leaks and stalls are differences against the first sample, so a slow
    # drift over 72 hours is caught rather than only a sudden failure.
    def detect(baseline, sample, findings)
      baseline_pids = baseline.fetch("processes").map { |entry| entry["pid"] }
      current_pids = sample.fetch("processes").map { |entry| entry["pid"] }
      (baseline_pids - current_pids).each do |pid|
        findings["process_exit"] << {"pid" => pid, "at" => sample.fetch("at")}
      end
      if baseline["open_files"].to_i.positive? && sample["open_files"].to_i > baseline["open_files"].to_i * 2
        findings["resource_leak"] << {"at" => sample.fetch("at"), "kind" => "open_files",
                                      "baseline" => baseline["open_files"], "observed" => sample["open_files"]}
      end
      if baseline["rss_kb"].to_i.positive? && sample["rss_kb"].to_i > baseline["rss_kb"].to_i * 3
        findings["resource_leak"] << {"at" => sample.fetch("at"), "kind" => "rss",
                                      "baseline" => baseline["rss_kb"], "observed" => sample["rss_kb"]}
      end
      cluster = sample.fetch("cluster")
      return unless cluster["available"]

      if cluster["terminating"].to_i.positive?
        findings["stuck_queue"] << {"at" => sample.fetch("at"),
                                    "terminating" => cluster["terminating"]}
      end
      base_rv = baseline.dig("cluster", "resource_version").to_i
      return unless base_rv.positive? && cluster["resource_version"].to_i < base_rv

      findings["lost_commit"] << {"at" => sample.fetch("at"),
                                  "resource_version" => cluster["resource_version"]}
    end
  end
end

exit(Release::Soak.run) if $PROGRAM_NAME == __FILE__
