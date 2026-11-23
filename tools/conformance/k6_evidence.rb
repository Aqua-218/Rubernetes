# frozen_string_literal: true

require "digest"
require "json"
require "time"
require_relative "archived_artifact"
require_relative "k6_client_evidence"
require_relative "k6_project_images"
require_relative "k6_cilium_runtime"

module Conformance
  # Cross-check the runtime measurements against the pinned corpus and the
  # same invocation that produced the project results.
  module K6Evidence
    STAGES = %w[install ready smoke scale upgrade rollback restart uninstall].freeze
    REPORT = "corpus-results.json"
    COMMAND = "k6-command.json"

    module_function

    def verify(report, execution, projects:, corpus_sha256:)
      check_report!(report, execution, projects, corpus_sha256)
      {"passed" => true, "verified_projects" => projects.length, "verified_clients" => report.fetch("clients").length}
    rescue ArgumentError, KeyError, TypeError, NoMethodError => error
      {"passed" => false, "detail" => error.message}
    end

    def archived(manifest, lane, root:, projects:, corpus_sha256:)
      unless lane["status"] == "COMPLETE" && lane["passed"] == true && manifest["rubernetesSourceStable"] != false
        return {"passed" => false, "detail" => lane["reason"] || "K6 lane did not complete"}
      end

      directory = File.realpath(File.dirname(File.expand_path(manifest.fetch("_path"), root)))
      records = [REPORT, COMMAND].map do |name|
        relative = "k6/#{name}"
        path = ArchivedArtifact.verify!(manifest, lane, directory, relative)
        JSON.parse(File.binread(path))
      end
      execution = records.last
      lane_start, run_start, command_start = [lane["startedAt"], manifest["startedAt"], execution["started_at"]].map { |value| Time.iso8601(value) }
      lane_finish, run_finish, command_finish = [lane["finishedAt"], manifest["finishedAt"], execution["finished_at"]].map { |value| Time.iso8601(value) }
      unless lane_start.between?(run_start, command_start) && lane_finish.between?(command_finish, run_finish)
        raise ArgumentError, "K6 command was recorded outside the manifest's lane"
      end

      verify(*records, projects: projects, corpus_sha256: corpus_sha256)
    rescue ArchivedArtifact::Invalid, SystemCallError, JSON::ParserError, ArgumentError, KeyError, TypeError, NoMethodError => error
      {"passed" => false, "detail" => error.message}
    end

    def check_report!(report, execution, projects, corpus_sha256)
      unless report["schema_version"] == 1 && report["kind"] == "k6_client_and_project_corpus" && report["corpus_sha256"] == corpus_sha256 &&
             report["clients_only"] == false && report["projects_only"] == false
        raise ArgumentError, "K6 report does not identify a full run of the pinned corpus"
      end
      unless execution["exit_status"] == 0 && execution["timed_out"] == false && report.fetch("failures") == [] && report.fetch("residue") == []
        raise ArgumentError, "K6 invocation or corpus did not complete cleanly"
      end

      command = validate_execution!(execution.fetch("command"))
      check_clients!(report.fetch("clients"), kubeconfig: command.fetch(3))

      start, finish = report.values_at("started_at", "generated_at").map { |value| Time.iso8601(value) }
      command_start, command_finish = execution.values_at("started_at", "finished_at").map { |value| Time.iso8601(value) }
      # The common command recorder truncates its boundaries to UTC seconds.
      raise ArgumentError, "K6 report was generated outside its invocation" unless start.between?(command_start, finish) && finish < command_finish + 1

      expected = projects.to_h { |project| project.values_at("name", "source_commit") }
      actual = report.fetch("projects")
      unless !expected.empty? && expected.length == actual.length && actual.to_h { |project| project.values_at("name", "source_commit") } == expected
        raise ArgumentError, "K6 project identities differ from the pinned corpus"
      end

      pins = projects.to_h { |project| [project.fetch("name"), project] }
      repositories = YAML.safe_load_file(K6Corpus::CORPUS).fetch("repositories", {})
      actual.each do |project|
        check_project!(project, start, finish)
        check_project_inputs!(project, pins.fetch(project.fetch("name")), repositories: repositories)
      end
    end

    def check_clients!(clients, kubeconfig: nil)
      require_relative "k6_corpus"

      K6ClientEvidence.check!(clients, YAML.safe_load_file(K6Corpus::CLIENTS), kubeconfig: kubeconfig)
    end

    def validate_execution!(command)
      raise ArgumentError, "K6 command record is malformed" unless command.is_a?(Array) && command.all? { |arg| arg.is_a?(String) && !arg.empty? }

      command = command.drop(4) if command.take(3) == %w[ip netns exec]
      return command if command.length == 6 && File.basename(command[1]) == "k6_corpus.rb" && command.values_at(2, 4) == %w[--kubeconfig --output]

      raise ArgumentError, "K6 command does not invoke the full corpus"
    end

    def check_project_inputs!(project, pin, repositories:)
      check_chart_preparation!(project, pin, repositories)
      check_image_observations!(project, pin)
    end

    def check_chart_preparation!(project, pin, repositories)
      expected = chart_preparation_pins(pin, repositories)
      records = project["preparation"]
      unless records.is_a?(Array) && records.all?(Hash) && records.map { |record| record["id"].to_s }.sort == expected.keys.sort
        raise ArgumentError, "#{project.fetch("name")}: chart preparation evidence is missing or incomplete"
      end

      records.each do |record|
        id = record.fetch("id")
        receipt = expected.fetch(id)
        next if record["passed"] == true && record.slice(*receipt.keys) == receipt

        raise ArgumentError, "#{project.fetch("name")}: #{id} preparation does not match the pinned corpus"
      end
    end

    def chart_preparation_pins(project, repositories)
      require_relative "k6_corpus"

      charts = project.fetch("prerequisite_charts", []) + [project]
      charts.each_with_object({}) do |chart, expected|
        source = K6Corpus.chart_alias(chart)
        expected["repo-#{source}"] = {"url" => repositories.fetch(source)} if source

        sha256 = chart.fetch("chart_sha256")
        expected["chart-#{chart.fetch("name")}"] = {"expected_sha256" => sha256, "observed_sha256" => sha256}
      end
    end

    def check_image_observations!(project, pin)
      images = project["images"]
      observations = images["images"] if images.is_a?(Hash)
      unless observations.is_a?(Array) && !observations.empty? && observations.all?(Hash) && images.values_at("passed", "errors") == [true, []]
        raise ArgumentError, "#{project.fetch("name")}: running image observations are missing or incomplete"
      end

      if images.key?("watch") || observations.any? { |row| row.key?("observation") }
        watch = images["watch"]
        classified = observations.all? { |row| %w[list watch].include?(row["observation"]) }
        unless classified && watch.is_a?(Hash) && watch.values_at("status", "errors") == ["complete", []]
          raise ArgumentError, "#{project.fetch("name")}: running image watch evidence is incomplete"
        end
      end
      if project.fetch("name") == "cilium" && observations.none? { |row| row["observation"] == "watch" || row.key?("watch_observation") }
        raise ArgumentError, "cilium: the running image watch did not observe a container"
      end

      locks = K6ProjectImages.index_locks(pin.fetch("images"))
      seen = Set.new
      observations.each do |row|
        reference, status_id, lock = row.values_at("reference", "image_id", "lock")
        digest = K6ProjectImages.observed_digest(status_id)
        identity = present_strings?(row.values_at("pod", "container", "reference", "image_id"))
        watched = row["watch_observation"]
        watched_provenance = watched.nil? || (watched.is_a?(Hash) && watched["observation"] == "watch" &&
          present_strings?(watched.values_at("pod", "container")) && image_provenance?(watched))
        next if identity && row["passed"] == true && image_provenance?(row) && watched_provenance &&
                digest && digest == row["manifest_digest"] && lock && lock == locks[K6ProjectImages.reference_key(reference)] &&
                seen.add?([reference, status_id])

        raise ArgumentError, "#{project.fetch("name")}: running image observation does not match its pinned reference and manifest digest"
      end
    end

    def image_provenance?(row)
      stage = row.fetch("stage")
      case row["observation"]
      when nil
        K6ProjectImages::CAPTURE_STAGES.include?(stage)
      when "list"
        present_strings?(row.values_at("pod_uid")) && K6ProjectImages::CAPTURE_STAGES.include?(stage)
      when "watch"
        present_strings?(row.values_at("pod_uid", "resource_version")) && STAGES.include?(stage) &&
          %w[ADDED MODIFIED DELETED].include?(row["watch_event"])
      else false
      end
    end

    def present_strings?(values) = values.all? { |value| value.is_a?(String) && !value.empty? }

    def check_project!(project, start, finish)
      runtime = project.fetch("runtime_residue")
      stages = project.fetch("stages")
      workers = runtime.fetch("workers")
      unless project["api_passed"] == true && project["passed"] == true && stages.map { |stage| stage["stage"] } == STAGES &&
             stages.all? { |stage| stage["passed"] == true } && runtime["status"] == "clean" && runtime["passed"] == true &&
             !workers.empty? && workers.values.all?("measured") && !runtime.fetch("observed_pod_uids").empty? &&
             %w[residue unattributed errors].all? { |name| runtime.fetch(name) == [] }
        raise ArgumentError, "#{project["name"]}: runtime cleanup or project stages are incomplete"
      end

      K6CiliumRuntime.verify!(runtime, stages) if project["name"] == "cilium"

      timestamps = [runtime["baseline_at"], *stages.flat_map { |stage| stage.values_at("started_at", "finished_at") }, runtime["post_uninstall_at"]]
      measured = timestamps.map { |value| Time.iso8601(value) }
      if start <= measured.first && measured.first < measured[1] && measured[-2] < measured.last &&
         measured.each_cons(2).all? { |before, after| before <= after } && measured.last <= finish
        return
      end

      raise ArgumentError, "#{project["name"]}: runtime evidence does not bracket the recorded install and uninstall"
    end
  end
end
