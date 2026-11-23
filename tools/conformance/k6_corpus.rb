#!/usr/bin/env ruby
# frozen_string_literal: true

# K6 — client matrix and existing-project corpus
# (spec/verification/kubernetes-compatibility.md#k6).
#
# Every project is installed with its own upstream procedure, exercised, and
# uninstalled; no Rubernetes-specific patch is applied to any template,
# manifest, source, image or webhook configuration.  Residual namespaced or
# cluster-scoped resources, finalizers, volumes and network identities must be
# zero after uninstall.

require "digest"
require "fileutils"
require "json"
require "open3"
require "tmpdir"
require "optparse"
require "shellwords"
require "time"
require "yaml"
require_relative "k6_client_verbs"
require_relative "k6_tool_clients"
require_relative "k6_project_residue"
require_relative "k6_project_runtime_residue"
require_relative "k6_project_workloads"
require_relative "k6_project_images"
require_relative "k6_project_crd_cleanup"
require_relative "k6_stage_receipt"

module Conformance
  module K6Corpus
    ROOT = File.expand_path("../..", __dir__)
    CORPUS = File.join(ROOT, "test/compatibility/projects/corpus.yml")
    CLIENTS = File.join(ROOT, "test/compatibility/clients/matrix.yml")

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/conformance/k6")}
      OptionParser.new do |parser|
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--only LIST") { |v| options[:only] = v.split(",").map(&:strip) }
        parser.on("--clients-only", "Run the client matrix without installing projects") { options[:clients_only] = true }
        parser.on("--projects-only", "Install projects without rerunning the client matrix") { options[:projects_only] = true }
        parser.on("--cleanup-retained-crds", "Clean up empty CRDs installed during this run on a disposable cluster") { options[:cleanup_retained_crds] = true }
      end.parse!(argv)
      raise ArgumentError, "--kubeconfig is required" if options[:kubeconfig].nil?
      raise ArgumentError, "--projects-only and --clients-only are mutually exclusive" if options[:projects_only] && options[:clients_only]

      started_at = Time.now.utc.iso8601(6)
      corpus_sha256 = Digest::SHA256.file(CORPUS).hexdigest unless options[:clients_only]
      FileUtils.mkdir_p(options[:output])
      clients = options[:projects_only] ? [] : client_matrix(options)
      projects = options[:clients_only] ? [] : project_runs(options)
      report = {
        "schema_version" => 1,
        "kind" => "k6_client_and_project_corpus",
        "clients_only" => options.fetch(:clients_only, false),
        "projects_only" => options.fetch(:projects_only, false),
        "corpus_sha256" => corpus_sha256,
        "started_at" => started_at,
        "generated_at" => Time.now.utc.iso8601(6),
        "clients" => clients,
        "projects" => projects,
        "failures" => (clients + projects).select { |entry| entry["passed"] == false },
        "residue" => projects.flat_map { |entry| Array(entry["residue"]) }
      }
      File.write(File.join(options[:output], "corpus-results.json"), "#{JSON.pretty_generate(report)}\n")
      report.fetch("failures").empty? && report.fetch("residue").empty? ? 0 : 1
    end

    def client_matrix(options)
      return [] unless File.file?(CLIENTS)

      matrix = YAML.safe_load_file(CLIENTS)
      kubectl = Array(matrix["kubectl"]).map do |entry|
        binary = File.join(ROOT, entry.fetch("path"))
        unless File.executable?(binary)
          next {"id" => "kubectl-#{entry.fetch("version")}", "passed" => false,
                "reason" => "binary #{entry.fetch("path")} is not installed"}
        end

        digest = Digest::SHA256.file(binary).hexdigest
        unless digest == entry.fetch("sha256")
          next {"id" => "kubectl-#{entry.fetch("version")}", "passed" => false,
                "reason" => "checksum mismatch", "expected" => entry.fetch("sha256"), "observed" => digest}
        end

        fixture = K6ClientVerbs.new(binary: binary, kubeconfig: options.fetch(:kubeconfig),
                                    image: options.fetch(:client_image, K6ClientVerbs::IMAGE))
        {"id" => "kubectl-#{entry.fetch("version")}", "sha256" => digest, **fixture.run}
      end
      kubectl + K6ToolClients.new(matrix, options.fetch(:kubeconfig)).run
    end

    def project_runs(options)
      corpus = YAML.safe_load_file(CORPUS)
      projects = corpus.fetch("projects", [])
      if options[:only]
        missing = options[:only] - projects.map { |project| project.fetch("name") }
        raise ArgumentError, "unknown K6 projects #{missing.join(", ")}" unless missing.empty?

        projects = projects.select { |project| options[:only].include?(project.fetch("name")) }
      end
      Dir.mktmpdir("k6-helm") do |directory|
        env = %w[CONFIG CACHE DATA].to_h { |kind| ["HELM_#{kind}_HOME", File.join(directory, kind.downcase)] }
        packages = File.join(directory, "packages")
        FileUtils.mkdir_p(packages)
        options = options.merge(path: client_path, helm_env: env, chart_directory: packages)
        charts = projects.flat_map { |project| project.fetch("prerequisite_charts", []) + [project] }.uniq { |chart| chart.fetch("name") }
        preparation = prepare_repositories(corpus.fetch("repositories", {}), charts, options)
        projects.map do |project|
          ids = (project.fetch("prerequisite_charts", []) + [project]).flat_map do |chart|
            ["chart-#{chart.fetch("name")}", "repo-#{chart_alias(chart)}"]
          end
          evidence = preparation.select { |entry| ids.include?(entry.fetch("id")) }
          outcome = if evidence.all? { |entry| entry.fetch("passed") }
                      run_project(project, options)
                    else
                      unprepared_project(project, evidence)
                    end
          outcome["preparation"] = evidence
          outcome["source_commit"] = project.fetch("source_commit")
          record_project_result(outcome, options[:output])
          outcome
        end
      end
    end

    def record_project_result(outcome, directory)
      return unless directory

      destination = File.join(directory, "projects")
      FileUtils.mkdir_p(destination)
      File.write(File.join(destination, "#{outcome.fetch("name")}.json"), "#{JSON.pretty_generate(outcome)}\n")
    end

    def chart_alias(project)
      source = project.fetch("chart")
      source.split("/", 2).first unless source.start_with?("oci://")
    end

    # Each successfully downloaded package stays on disk through execution.
    # A failed source only prevents installation of charts that depend on it.
    def prepare_repositories(repositories, projects, options)
      helm = File.join(ROOT, "build/tools/clients/helm")
      aliases = projects.filter_map { |project| chart_alias(project) }.uniq
      env = options.fetch(:helm_env).merge("PATH" => options.fetch(:path))
      sources = aliases.to_h do |name|
        url = repositories[name]
        if url
          _out, err, status = Open3.capture3(env, helm, "repo", "add", name, url, "--force-update")
          evidence = {"id" => "repo-#{name}", "passed" => status.success?, "url" => url, "stderr" => status.success? ? nil : err.lines.last(5).join.strip}
        else
          evidence = {"id" => "repo-#{name}", "passed" => false, "stderr" => "repository alias is absent from the corpus"}
        end
        [name, evidence]
      end

      results = projects.filter_map do |project|
        source = chart_alias(project)
        next if source && !sources.fetch(source).fetch("passed")

        pull_chart(project, options.fetch(:chart_directory), env, helm)
      end
      sources.values + results
    end

    def pull_chart(project, directory, env, helm)
      chart = project.fetch("chart")
      _out, err, status = Open3.capture3(env, helm, "pull", chart, "--version", project.fetch("chart_version").to_s, "--destination", directory)
      package = File.join(directory, project.fetch("chart_package"))
      observed = File.file?(package) ? Digest::SHA256.file(package).hexdigest : nil
      {"id" => "chart-#{project.fetch("name")}", "passed" => status.success? && observed == project.fetch("chart_sha256"),
       "expected_sha256" => project.fetch("chart_sha256"), "observed_sha256" => observed, "stderr" => status.success? ? nil : err.lines.last(5).join.strip}
    end

    def unprepared_project(project, preparation)
      failed = preparation.reject { |entry| entry.fetch("passed") }.map { |entry| entry.fetch("id") }
      {"name" => project.fetch("name"), "categories" => project["categories"], "namespace" => project_namespace(project),
       "passed" => false, "stages" => [], "residue" => [],
       "reason" => "repository preparation failed: #{failed.join(", ")}"}
    end

    # The stage commands call `kubectl` and `helm` by name: the pinned
    # binaries, under those names, come first on PATH.
    def client_path
      bin = File.join(ROOT, "build/tools/clients/bin")
      FileUtils.mkdir_p(bin)
      {"kubectl" => File.join(ROOT, "build/tools/kubectl-v1.36.2"), "helm" => File.join(ROOT, "build/tools/clients/helm")}.each do |name, target|
        link = File.join(bin, name)
        File.symlink(target, link) unless File.symlink?(link) && File.readlink(link) == target
      end
      [bin, ENV.fetch("PATH", "")].join(File::PATH_SEPARATOR)
    end

    # install -> Ready -> smoke -> scale -> upgrade -> rollback -> restart ->
    # uninstall, then a residue sweep, exactly as the spec lists.
    def run_project(project, options)
      name = project.fetch("name")
      namespace = project_namespace(project)
      client = {kubectl: File.join(ROOT, "build/tools/kubectl-v1.36.2"), kubeconfig: options.fetch(:kubeconfig)}
      receipt_dir = options[:stage_receipt_directory] || (File.join(options[:output], "projects") if options[:output])
      receipt = K6StageReceipt.new(directory: receipt_dir, name: name, namespace: namespace, **client) if receipt_dir
      residue_checker = K6ProjectResidue.new(**client)
      runtime = K6ProjectRuntimeResidue.local(kubeconfig: client.fetch(:kubeconfig))
      images = K6ProjectImages.new(**client, namespace: namespace, locks: project.fetch("images"))
      crd_cleanup = project_crd_cleanup(client, namespace, options) if options[:cleanup_retained_crds]
      baseline = residue_checker.snapshot
      runtime_baseline = residue_checker.runtime_snapshot(runtime, namespace, pv_snapshot: baseline, check_workers: true, stage: "baseline")
      reservation = reserve_fixture_namespace(project, namespace, baseline, residue_checker)
      if reservation["error"]
        return {"name" => name, "categories" => project["categories"], "namespace" => namespace, "passed" => false,
                "stages" => [], "residue" => [], "reason" => reservation.fetch("error")}
      end

      stages = []
      prerequisite = nil
      retained_names = []
      installed_crds = nil
      charts = project.fetch("prerequisite_charts", []) + [project]
      observed_runtime = []
      begin
        images.start_watch
        %w[install ready smoke scale upgrade rollback restart].each do |id|
          unless prerequisite.nil?
            stages << {"stage" => id, "passed" => false, "skipped" => "#{prerequisite} failed"}
            receipt&.record(stages.last)
            next
          end

          images.during(id) do
            outcome = timed_stage { project_stage(project, id, namespace, options) }
            stages << outcome
            receipt&.record(outcome)
            observed_runtime << residue_checker.runtime_snapshot(runtime, namespace, stage: id) if runtime.available?
            images.capture(id) if K6ProjectImages::CAPTURE_STAGES.include?(id)
            if id == "smoke" && project["after_smoke"]
              cleanup = stage(name, "smoke-cleanup", project.fetch("after_smoke"), namespace, options)
              outcome["cleanup"] = cleanup
              outcome["passed"] &&= cleanup.fetch("passed")
            end
            prerequisite = id if %w[install ready].include?(id) && !outcome.fetch("passed")
          end
        end
      ensure
        begin
          if crd_cleanup && stages.first
            retained_names = crd_cleanup.names(charts, options.fetch(:chart_directory))
            installed_crds = residue_checker.snapshot(["customresourcedefinitions"]) unless retained_names.empty?
          end
          images.during("uninstall") do
            stages << timed_stage { project_uninstall(project, namespace, options, residue_checker, reservation["uid"]) }
            receipt&.record(stages.last)
          end
        ensure
          images.stop_watch
        end
      end
      post = residue_checker.snapshot
      initial_residue = residue_checker.residue(namespace, baseline, post: post)
      installed_crds = nil unless stages.last.fetch("passed")
      failed_releases = charts.map { |chart| chart.fetch("name") } unless stages.first&.fetch("passed")
      audit = options[:crd_creation_audit]
      created = failed_releases && audit && stages.first ? audit.identities(stages.first) : []
      cleanup = cleanup_retained_crds(crd_cleanup, retained_names, baseline, installed_crds, post, failed_releases: failed_releases, created: created)
      waited_for_reclaim = stages.last.fetch("passed") && residue_checker.await_volume_reclaim(namespace, baseline, post)
      final = cleanup.empty? && !waited_for_reclaim ? post : residue_checker.snapshot
      residue = final.equal?(post) ? initial_residue : residue_checker.residue(namespace, baseline, post: final)
      runtime_evidence = runtime_residue(runtime, residue_checker, namespace, runtime_baseline, observed_runtime, final,
                                         uninstall_passed: stages.last.fetch("passed"))
      image_evidence = images.result
      identity = if reservation["uid"]
                   {"fixture_namespace_uid" => reservation.fetch("uid"),
                    "missing_baseline_identities" => residue_checker.missing_baseline_identities(baseline, final)}
                 else
                   {}
                 end
      api_passed = stages.compact.all? { |s| s.fetch("passed") } && cleanup.all? { |item| item.fetch("passed") } &&
                   residue.empty? && identity.fetch("missing_baseline_identities", []).empty? && image_evidence.fetch("passed")
      {"name" => name, "categories" => project["categories"], "namespace" => namespace, **identity,
       "passed" => api_passed && runtime_evidence.fetch("passed"), "api_passed" => api_passed,
       "stages" => stages.compact, "images" => image_evidence, "residue" => residue + runtime_evidence.fetch("residue"),
       "runtime_residue" => runtime_evidence,
       "residue_after_uninstall" => initial_residue, "fixture_crd_cleanup" => cleanup}
    end

    def timed_stage
      started_at = Time.now.utc.iso8601(6)
      result = yield
      result&.merge("started_at" => started_at, "finished_at" => Time.now.utc.iso8601(6))
    end

    def runtime_residue(runtime, checker, namespace, baseline, observations, api_snapshot, uninstall_passed:)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
      loop do
        post = checker.runtime_snapshot(runtime, namespace, pv_snapshot: api_snapshot, check_workers: true, stage: "post-uninstall")
        result = runtime.compare(namespace: namespace, baseline: baseline, observations: observations, post: post)
        return result if result.fetch("residue").empty? || !uninstall_passed || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 1
      end
    end

    def project_namespace(project)
      namespace = project.fetch("fixture_namespace") { "k6-#{project.fetch("name")}".downcase.gsub(/[^a-z0-9-]/, "-")[0, 63] }
      raise ArgumentError, "invalid fixture namespace #{namespace.inspect}" unless namespace.match?(/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/)

      namespace
    end

    def reserve_fixture_namespace(project, namespace, baseline, residue_checker)
      return {} unless project.key?("fixture_namespace")

      {"uid" => residue_checker.reserve_namespace(namespace, baseline, webhook_labels: project.fetch("fixture_webhook_labels", {}))}
    rescue RuntimeError, JSON::ParserError, KeyError => error
      {"error" => error.message}
    end

    def project_uninstall(project, namespace, options, residue_checker, uid)
      name = project.fetch("name")
      return stage(name, "uninstall", cleanup_command(project), namespace, options) if uid.nil?

      unless residue_checker.namespace_owned?(namespace, uid)
        return {"project" => name, "stage" => "uninstall", "passed" => false,
                "reason" => "namespace #{namespace} no longer has the fixture UID #{uid}"}
      end

      request = Shellwords.escape(JSON.generate("apiVersion" => "v1", "kind" => "DeleteOptions", "preconditions" => {"uid" => uid}))
      delete = "kubectl delete --raw \"/api/v1/namespaces/$K6_NAMESPACE\" -f - <<< #{request} && " \
               "kubectl wait --for=delete \"namespace/$K6_NAMESPACE\" --timeout=10m"
      stage(name, "uninstall", cleanup_command(project, namespace_delete: delete), namespace, options)
    end

    def project_crd_cleanup(client, namespace, options)
      K6ProjectCRDCleanup.new(**client, namespace: namespace, helm: File.join(ROOT, "build/tools/clients/helm"),
                                        helm_env: options.fetch(:helm_env))
    end

    def cleanup_retained_crds(cleanup, names, baseline, installed, post, failed_releases: nil, created: [])
      return [] unless cleanup && installed && !names.empty?
      return [] unless [baseline, installed, post].all? { |snapshot| snapshot.fetch(:errors).empty? }

      kind = "customresourcedefinitions"
      cleanup.run(names, baseline.dig(:resources, kind), installed.dig(:resources, kind), post.dig(:resources, kind),
                  failed_releases: failed_releases, created: created)
    end

    def project_stage(project, id, namespace, options)
      return workload_stage(project, id, namespace, options) if %w[scale restart].include?(id)

      command = project_command(project, id, options.fetch(:chart_directory))
      evidence = stage(project.fetch("name"), id, command, namespace, options)
      return evidence unless id == "smoke"

      reference = project["smoke_reference"]
      return evidence.merge("scenario" => reference) if reference

      evidence.merge("passed" => false, "reason" => "no published application smoke scenario is configured")
    end

    def workload_stage(project, id, namespace, options)
      name = project.fetch("name")
      warn "K6 #{name} #{id}"
      workloads = K6ProjectWorkloads.new(kubectl: File.join(ROOT, "build/tools/kubectl-v1.36.2"), kubeconfig: options.fetch(:kubeconfig), namespace: namespace)
      checks = if id == "scale"
                 workloads.scale(replica_count(project), exclusions: project.fetch("scale_exclusions", {}), targets: project.fetch("scale_targets", []))
               else
                 workloads.restart
               end
      checks.merge("project" => name, "stage" => id)
    end

    def replica_count(project)
      desired = project.fetch("scale")[/--replicas=(\d+)/, 1]
      raise ArgumentError, "#{project.fetch("name")} must specify the test replica count" unless desired

      Integer(desired)
    end

    # Helm installs the exact archive the runner hashed. Its release, version,
    # values, namespace and all other options still come from the corpus.
    def project_command(project, id, packages)
      command = project.fetch(id)
      return command unless %w[install upgrade].include?(id)

      prerequisites = id == "install" ? project.fetch("prerequisite_charts", []) : []
      commands = (prerequisites + [project]).map { |chart| verified_chart_command(chart, id, packages) }
      commands.unshift(project["setup"]) if id == "install" && project["setup"]
      commands.join(" && ")
    end

    def verified_chart_command(project, id, packages)
      command = project.fetch(id)
      chart = Regexp.escape(project.fetch("chart"))
      prefix = /\A(helm upgrade(?: --install)? \S+ )#{chart}(?=\s|\z)/
      raise ArgumentError, "#{project.fetch("name")} #{id} must use the pinned chart" unless command.match?(prefix)

      package = File.join(packages, project.fetch("chart_package"))
      command.sub(prefix) { "#{Regexp.last_match(1)}#{Shellwords.escape(package)}" }
    end

    def cleanup_command(project, namespace_delete: nil)
      command = project.fetch("uninstall")
      helm, namespace = command.split("; ", 2)
      unless helm.start_with?("helm uninstall ") && namespace&.start_with?("kubectl delete namespace ")
        raise ArgumentError, "#{project.fetch("name")} must provide a separable Helm uninstall and fixture namespace deletion" if namespace_delete

        return command
      end

      before_namespace = project.fetch("prerequisite_charts", []).reverse.map { |chart| chart.fetch("uninstall") }
      steps = [project["before_uninstall"], helm, *before_namespace, namespace_delete || namespace].compact
      ["k6_cleanup_status=0", *steps.map { |step| "#{step} || k6_cleanup_status=1" },
       "(( k6_cleanup_status == 0 ))"].join("; ")
    end

    def stage(project, id, command, namespace, options)
      return nil if command.nil? || command.to_s.empty?

      env = {"KUBECONFIG" => options.fetch(:kubeconfig), "K6_NAMESPACE" => namespace, "PATH" => options.fetch(:path, ENV.fetch("PATH", ""))}
      env.merge!(options.fetch(:helm_env, {}))
      warn "K6 #{project} #{id}"
      started = Time.now.utc
      stdout, stderr, status = Open3.capture3(env, "bash", "-o", "pipefail", "-c", command, chdir: ROOT, binmode: true)
      {"project" => project, "stage" => id, "passed" => status.success?, "exit_status" => status.exitstatus,
       "elapsed_seconds" => (Time.now.utc - started).round(3),
       "stdout_sha256" => Digest::SHA256.hexdigest(stdout),
       "stderr" => status.success? ? nil : stderr.lines.last(5).join.strip.byteslice(0, 6000).force_encoding(Encoding::UTF_8).scrub}
    end
  end
end

exit(Conformance::K6Corpus.run) if $PROGRAM_NAME == __FILE__
