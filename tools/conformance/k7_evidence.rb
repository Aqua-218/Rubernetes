# frozen_string_literal: true

require "digest"
require "json"
require "rexml/parsers/pullparser"
require "rubygems/version"
require "time"
require_relative "archived_artifact"
require_relative "k5_evidence"
require_relative "k7_contract"
require_relative "lock"

module Conformance
  module K7Evidence
    class Invalid < StandardError; end

    REPORT = "lifecycle.json"
    COMMAND = "k7-command.json"
    SHA256 = /\A[0-9a-f]{64}\z/

    module_function

    def verify(report, execution, directory:)
      stage_ids = K7Contract::STAGE_IDS
      stages = report.fetch("stages")
      unless stages.is_a?(Array) && stages.all?(Hash) && stages.map { |stage| stage["id"] } == stage_ids
        raise Invalid, "K7 stage inventory differs from the current contract"
      end

      incomplete = stages.reject { |stage| stage_complete?(stage) }.map { |stage| stage.fetch("id") }
      raise Invalid, "K7 stages did not complete: #{incomplete.join(", ")}" unless incomplete.empty?

      validate_baseline!(report)
      validate_operations!(stages)
      target, out, oracle = lifecycle_command!(execution)
      verify_window!(execution, stages.first.fetch("started_at"), stages.last.fetch("finished_at"))
      generated = Time.iso8601(report.fetch("generated_at"))
      unless Time.iso8601(stages.last.fetch("finished_at")).to_i <= generated.to_i && generated <= Time.iso8601(execution.fetch("finished_at"))
        raise Invalid, "K7 lifecycle report lies outside its recorded invocation"
      end

      artifacts = []
      k5_fixtures = Set.new
      previous_finish = Time.iso8601(execution.fetch("started_at"))
      directory = File.realpath(directory)
      stages.each do |stage|
        started, finished = stage.values_at("started_at", "finished_at").map { |value| Time.iso8601(value) }
        raise Invalid, "K7 stage timestamps overlap" unless started.between?(previous_finish, finished)

        previous_finish = finished
        validate_inventory!(stage)
        checks = stage.fetch("checks")
        raise Invalid, "#{stage.fetch("id")}: K7 check inventory differs" unless checks.keys.sort == %w[k1_smoke k5_differential]

        original_paths = check_originals!(stage, directory, artifacts)
        check_smoke!(stage, original_paths, target, out)
        fixture = check_differential!(stage, original_paths, target, oracle, out)
        raise Invalid, "K7 stages reuse a K5 fixture" unless k5_fixtures.add?(fixture)
      end
      {"passed" => true, "completed_stages" => stages.length, "artifacts" => artifacts}
    rescue Invalid, JSON::ParserError, REXML::ParseException, SystemCallError, ArgumentError, KeyError, TypeError, NoMethodError => error
      failure(error, report)
    end

    def archived(manifest, lane, root:)
      return failure(Invalid.new(lane["reason"] || "K7 lane did not complete"), lane) unless lane["status"] == "COMPLETE" && lane["passed"] == true
      unless manifest["sourceCommit"] == Lock.source_commit && manifest["rubernetesSourceStable"] == true &&
             nonempty_strings?(manifest.values_at("runId", "rubernetesCommit")) && manifest["rubernetesCommit"] == manifest["rubernetesCommitAfter"]
        raise Invalid, "K7 manifest does not establish stable pinned source"
      end

      directory = File.realpath(File.dirname(File.expand_path(manifest.fetch("_path"), root)))
      lane_dir = File.join(directory, "k7")
      report, execution = [REPORT, COMMAND].map do |name|
        path = ArchivedArtifact.verify!(manifest, lane, directory, "k7/#{name}")
        JSON.parse(File.binread(path))
      end
      unless lane.fetch("stages") == report.fetch("stages") && lane["baseline_missing"] == report["baseline_missing"]
        raise Invalid, "K7 manifest stages do not match the lifecycle original"
      end

      check_archive_window!(manifest, lane, execution)
      verdict = verify(report, execution, directory: lane_dir)
      return verdict unless verdict["passed"]

      verdict.fetch("artifacts").each do |artifact|
        path = artifact.fetch("path").delete_prefix("#{directory}/")
        ArchivedArtifact.verify!(manifest, lane, directory, path)
      end
      verdict.except("artifacts")
    rescue ArchivedArtifact::Invalid => error
      failure(Invalid.new(error.message), lane)
    rescue Invalid, JSON::ParserError, SystemCallError, ArgumentError, KeyError, TypeError, NoMethodError => error
      failure(error, lane)
    end

    def failure(error, report)
      stages = report.is_a?(Hash) ? Array(report["stages"]).grep(Hash) : []
      completed = K7Contract::STAGE_IDS.count { |id| stages.any? { |stage| stage["id"] == id && stage_complete?(stage) } }
      detail = error.is_a?(Invalid) ? error.message : "K7 evidence is missing or malformed"
      {"passed" => false, "detail" => detail, "completed_stages" => completed}
    end

    def stage_complete?(stage)
      stage.values_at("status", "passed", "operation_passed", "exit_status", "data_loss", "stuck_operations") == ["COMPLETE", true, true, 0, [], []]
    end

    def validate_baseline!(report)
      unless report["kind"] == "k7_upgrade_and_recovery" && report["state_inventory_stable"] == true &&
             report["state_inventory_sha256"] == K7Contract.state_inventory_sha256
        raise Invalid, "K7 report does not use the current API state inventory"
      end

      counters = %w[baseline_objects baseline_pods baseline_ready_pods baseline_attached_volumes]
      valid_counts = counters.all? { |name| positive_count?(report.fetch(name)) }
      unless valid_counts && %w[baseline_missing data_loss stuck_operations irreversible_migrations].all? { |name| report.fetch(name) == [] }
        raise Invalid, "K7 baseline coverage, recovery or reversibility did not pass"
      end
      return if report.fetch("stages").first.dig("api_inventory", "before", "objects") == report.fetch("baseline_objects")

      raise Invalid, "K7 baseline does not match the first staged API inventory"
    end

    def validate_operations!(stages)
      by_id = stages.to_h { |stage| [stage.fetch("id"), stage] }
      migration, upgrade, rollback = by_id.values_at("memory_to_raft", "release_upgrade", "rollback")
      unless migration["reversible"] == true && migration.dig("evidence", "memory_snapshot_round_trip") == true && upgrade["reversible"] == true
        raise Invalid, "K7 migration reversibility was not verified"
      end

      validate_release_pair!(upgrade, rollback)

      migration_evidence = migration.fetch("evidence")
      from, to, checked = by_id.fetch("single_to_three_node").fetch("evidence").values_at("from_voters", "to_voters", "checked_replicas")
      unless migration_evidence.values_at("from", "to", "raft_voters") == ["memory", "raft", from] && positive_count?(migration_evidence["seed_revision"]) &&
             from.is_a?(Array) && from.one? && to.is_a?(Array) && to.uniq.length == 3 && (from - to).empty? && checked == to
        raise Invalid, "K7 migration and control-plane growth evidence is incomplete"
      end
      unless by_id.fetch("apiserver_rolling_restart").dig("evidence", "restarted") == to.map { |voter| "apiserver-#{voter}" }
        raise Invalid, "K7 did not restart the three verified API servers"
      end

      %w[controller_leader_loss scheduler_leader_loss].each do |id|
        evidence = by_id.fetch(id).fetch("evidence")
        unless nonempty_strings?(evidence.values_at("lease", "holder_before", "holder_after")) && time_in_stage?(evidence["renewed_at"], by_id.fetch(id))
          raise Invalid, "#{id}: K7 lease did not recover"
        end
      end
      worker = by_id.fetch("worker_reboot").fetch("evidence")
      unless nonempty_strings?(worker.values_at("worker", "worker_uid", "boot_id_before",
                                                "boot_id_after")) && worker["boot_id_before"] != worker["boot_id_after"]
        raise Invalid, "K7 worker reboot evidence is incomplete"
      end

      backup = by_id.fetch("backup_restore").fetch("evidence")
      return if to.any? { |voter| "apiserver-#{voter}" == backup["restored_replica"] } && positive_count?(backup["restored_snapshot_revision"]) &&
                nonempty_strings?(backup.values_at("checkpoint_uid"))

      raise Invalid, "K7 restored replica or checkpoint evidence is incomplete"
    end

    def time_in_stage?(value, stage)
      Time.iso8601(value).between?(Time.iso8601(stage.fetch("started_at")), Time.iso8601(stage.fetch("finished_at")))
    end

    def nonempty_strings?(values) = values.all? { |value| value.is_a?(String) && !value.empty? }

    def validate_release_pair!(upgrade, rollback)
      original = upgrade.fetch("evidence")
      reverted = rollback.fetch("evidence")
      older, newer = original.values_at("from_version", "to_version")
      unless newer == "1.0.0" && Gem::Version.new(older) < Gem::Version.new(newer) && reverted.values_at("from_version", "to_version") == [newer, older]
        raise Invalid, "K7 release upgrade and rollback do not attest opposing installed release versions"
      end

      source, target = original.values_at("from_binaries", "to_binaries")
      unless [source, target].all? { |binaries| binaries.is_a?(Hash) && !binaries.empty? && binaries.values.all?(SHA256) } &&
             source.keys.sort == target.keys.sort && source != target && reverted.values_at("from_binaries", "to_binaries") == [target, source]
        raise Invalid, "K7 installed binary digests do not match across upgrade and rollback"
      end
      return if [original, reverted].all? { |entry| nonempty_strings?(entry.values_at("checkpoint_uid", "checkpoint_revision")) }

      raise Invalid, "K7 release transitions are missing acknowledged checkpoints"
    end

    def validate_inventory!(stage)
      before, after = stage.fetch("api_inventory").values_at("before", "after")
      valid = [before, after].all? do |inventory|
        inventory.is_a?(Hash) && positive_count?(inventory["objects"]) && SHA256.match?(inventory["sha256"].to_s)
      end
      return if valid && after.fetch("objects") >= before.fetch("objects")

      raise Invalid, "#{stage.fetch("id")}: staged API inventories are missing or inconsistent"
    end

    def positive_count?(count) = count.is_a?(Integer) && count.positive?

    def lifecycle_command!(execution)
      _ruby, runner, target_flag, target, output_flag, output, oracle_flag, oracle, *extra = successful_command!(execution, "K7 lifecycle")
      unless File.basename(runner.to_s) == "k7_lifecycle.rb" && [target_flag, output_flag, oracle_flag] == %w[--kubeconfig --output --oracle-kubeconfig] &&
             [target, output, oracle].all? { |path| path && !path.empty? && !path.start_with?("-") } && target != oracle && extra.empty?
        raise Invalid, "K7 lifecycle command is missing its target, output, or separate oracle"
      end

      [target, output, oracle]
    end

    def check_originals!(stage, directory, artifacts)
      id = stage.fetch("id")
      smoke, differential = stage.fetch("checks").values_at("k1_smoke", "k5_differential")
      unless [smoke, differential].all? { |check| check.is_a?(Hash) && check.values_at("status", "passed") == ["COMPLETE", true] }
        raise Invalid, "#{id}: the K1 or K5 check did not complete"
      end

      files = {"k1-smoke-command.json" => smoke["command_sha256"], "k1-smoke.xml" => smoke["junit_sha256"],
               "k5-differential-command.json" => differential["command_sha256"], "differential.json" => differential["report_sha256"]}
      files.to_h do |name, digest|
        path = File.join(directory, id, name)
        verify_file!(path, digest, "#{id}/#{name}")
        artifacts << {"path" => path, "sha256" => digest}
        [name, path]
      end
    end

    def check_smoke!(stage, paths, target, output)
      smoke = stage.fetch("checks").fetch("k1_smoke")
      expected = K7Contract::SMOKE_SPECS.map { |id| {"id" => id, "status" => "passed"} }
      unless smoke["cases"] == expected && smoke["namespaces_cleaned_up"] == true && SHA256.match?(smoke["binary_sha256"].to_s)
        raise Invalid, "#{stage.fetch("id")}: K1 smoke case or cleanup evidence is incomplete"
      end

      command = JSON.parse(File.binread(paths.fetch("k1-smoke-command.json")))
      executable, *arguments = successful_command!(command, "K1 smoke")
      kubectl = arguments[4]
      expected_arguments = ["--provider=skeleton", "--kubeconfig", target, "--kubectl-path", kubectl,
                            "--ginkgo.focus=#{K7Contract.smoke_focus}", "--ginkgo.junit-report=#{File.join(output, stage.fetch("id"), "k1-smoke.xml")}",
                            "--ginkgo.no-color"]
      unless File.basename(executable) == "e2e.test" && File.basename(kubectl.to_s) == "kubectl-v1.36.2" && arguments == expected_arguments
        raise Invalid, "#{stage.fetch("id")}: K1 smoke command does not match the contracted subset"
      end

      verify_window!(stage, *command.values_at("started_at", "finished_at"), truncated: true)

      executed = smoke_junit_cases(paths.fetch("k1-smoke.xml"))
      observed = expected.all? do |entry|
        executed.one? { |testcase| testcase["name"].start_with?("[It] #{entry.fetch("id")} [") && testcase["status"] == "passed" }
      end
      return if observed && executed.length == expected.length

      raise Invalid, "#{stage.fetch("id")}: K1 original JUnit does not show the contracted smoke cases passing"
    end

    def smoke_junit_cases(path)
      parser = REXML::Parsers::PullParser.new(File.binread(path))
      executed = []
      active = false
      root = nil
      depth = 0
      while parser.has_next?
        event = parser.pull
        case event.event_type
        when :start_element
          name = event[0]
          attributes = event[1]
          if depth.zero?
            raise Invalid, "K1 original JUnit has an invalid root" if root || !%w[testsuites testsuite].include?(name)

            root = name
          end
          depth += 1
          if name == "testcase"
            active = attributes["name"].to_s.start_with?("[It] ") && attributes["status"] != "skipped"
            executed << attributes if active
          elsif %w[failure error].include?(name) || (name == "skipped" && active)
            raise Invalid, "K1 original JUnit contains a failed or skipped execution"
          end
        when :end_element
          depth -= 1
          active = false if event[0] == "testcase"
        end
      end
      raise Invalid, "K1 original JUnit is incomplete" unless root && depth.zero?

      executed
    end

    def check_differential!(stage, paths, target, oracle, output)
      command = JSON.parse(File.binread(paths.fetch("k5-differential-command.json")))
      _ruby, runner, *arguments = successful_command!(command, "K5 differential")
      expected_args = ["--kubeconfig", target, "--oracle-kubeconfig", oracle, "--output", File.join(output, stage.fetch("id"))]
      unless File.basename(runner.to_s) == "k5_differential.rb" && arguments == expected_args
        raise Invalid, "#{stage.fetch("id")}: K5 command does not match the lifecycle target and oracle"
      end

      verify_window!(stage, *command.values_at("started_at", "finished_at"), truncated: true)

      report = JSON.parse(File.binread(paths.fetch("differential.json")))
      verdict = K5Evidence.verify(report, cbor_enabled: false)
      raise Invalid, "#{stage.fetch("id")}: #{verdict.fetch("detail")}" unless verdict.fetch("passed")

      generated_at = report.fetch("generated_at")
      verify_window!(command, generated_at, generated_at)
      verdict.fetch("fixture")
    end

    def successful_command!(execution, description)
      argv = execution.fetch("command")
      unless execution.values_at("exit_status", "timed_out") == [0, false] && argv.is_a?(Array) && !argv.empty? && argv.all?(String)
        raise Invalid, "#{description} original invocation did not finish successfully"
      end

      argv.take(3) == %w[ip netns exec] ? argv.drop(4) : argv
    end

    def verify_window!(parent, child_start, child_finish, truncated: false)
      start, finish = parent.values_at("started_at", "finished_at").map { |value| Time.iso8601(value) }
      first, last = [child_start, child_finish].map { |value| Time.iso8601(value) }
      return if (truncated ? start.to_i <= first.to_i : start <= first) && first <= last && last.to_i <= finish.to_i

      raise Invalid, "K7 original timestamps fall outside their invocation"
    end

    def check_archive_window!(manifest, lane, execution)
      run_start, run_finish = manifest.values_at("startedAt", "finishedAt").map { |value| Time.iso8601(value) }
      lane_start, lane_finish = lane.values_at("startedAt", "finishedAt").map { |value| Time.iso8601(value) }
      valid_window = lane_start.between?(run_start, lane_finish) && lane_finish <= run_finish
      raise Invalid, "K7 lane timestamps fall outside the recorded run" unless valid_window

      verify_window!({"started_at" => lane.fetch("startedAt"), "finished_at" => lane.fetch("finishedAt")}, *execution.values_at("started_at", "finished_at"))
    end

    def verify_file!(path, digest, relative)
      return if SHA256.match?(digest.to_s) && File.file?(path) && File.realpath(path) == path && Digest::SHA256.file(path).hexdigest == digest

      raise Invalid, "K7 original artifact does not match the recorded SHA-256: #{relative}"
    end
  end
end
