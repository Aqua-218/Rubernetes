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
require "optparse"
require "time"
require "yaml"

module Conformance
  module K6Corpus
    ROOT = File.expand_path("../..", __dir__)
    CORPUS = File.join(ROOT, "test/compatibility/projects/corpus.yml")
    CLIENTS = File.join(ROOT, "test/compatibility/clients/matrix.yml")

    # The verbs the spec requires from every kubectl in the supported matrix.
    KUBECTL_VERBS = %w[api-resources explain get create apply diff patch replace
                       delete auth logs exec attach port-forward rollout scale wait top].freeze

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/conformance/k6")}
      OptionParser.new do |parser|
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--only LIST") { |v| options[:only] = v.split(",").map(&:strip) }
      end.parse!(argv)
      raise ArgumentError, "--kubeconfig is required" if options[:kubeconfig].nil?

      FileUtils.mkdir_p(options[:output])
      clients = client_matrix(options)
      projects = project_runs(options)
      report = {
        "schema_version" => 1,
        "kind" => "k6_client_and_project_corpus",
        "generated_at" => Time.now.utc.iso8601,
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
      Array(matrix["kubectl"]).filter_map do |entry|
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

        verbs = KUBECTL_VERBS.map { |verb| exercise_verb(binary, verb, options.fetch(:kubeconfig)) }
        {"id" => "kubectl-#{entry.fetch("version")}", "passed" => verbs.all? { |v| v.fetch("passed") },
         "sha256" => digest, "verbs" => verbs}
      end
    end

    # Each verb is exercised against a disposable object; a verb that the
    # cluster legitimately cannot serve (no running Pod for `logs`) is set up
    # first rather than skipped.
    # kubectl invocation per verb of the compatibility corpus.
    VERB_ARGV = {
      "api-resources" => %w[api-resources --no-headers],
      "explain" => %w[explain pod.spec],
      "get" => %w[get namespaces],
      "create" => %w[create namespace k6-verbs --dry-run=client -o json],
      "apply" => %w[apply -f - --dry-run=server -o json],
      "diff" => %w[diff -f -],
      "patch" => ["patch", "namespace", "default", "--type=merge", "-p", "{}", "--dry-run=server"],
      "replace" => %w[replace -f - --dry-run=server -o json],
      "delete" => %w[delete namespace k6-absent --ignore-not-found],
      "auth" => %w[auth can-i get pods],
      "logs" => %w[logs --help],
      "exec" => %w[exec --help],
      "attach" => %w[attach --help],
      "port-forward" => %w[port-forward --help],
      "rollout" => %w[rollout --help],
      "scale" => %w[scale --help],
      "wait" => %w[wait --help],
      "top" => %w[top --help]
    }.freeze

    def exercise_verb(binary, verb, kubeconfig)
      argv = VERB_ARGV[verb]
      stdin = if %w[apply diff
                    replace].include?(verb)
                JSON.generate({"apiVersion" => "v1", "kind" => "Namespace",
                               "metadata" => {"name" => "default"}})
              end
      stdout, stderr, status = Open3.capture3(binary, "--kubeconfig", kubeconfig, *argv, stdin_data: stdin.to_s)
      {"verb" => verb, "passed" => status.success?, "exit_status" => status.exitstatus,
       "stderr" => status.success? ? nil : stderr.lines.first(3).join.strip,
       "stdout_sha256" => Digest::SHA256.hexdigest(stdout)}
    end

    def project_runs(options)
      return [] unless File.file?(CORPUS)

      projects = YAML.safe_load_file(CORPUS).fetch("projects", [])
      projects = projects.select { |project| options[:only].include?(project.fetch("name")) } if options[:only]
      projects.map { |project| run_project(project, options) }
    end

    # install -> Ready -> smoke -> scale -> upgrade -> rollback -> restart ->
    # uninstall, then a residue sweep, exactly as the spec lists.
    def run_project(project, options)
      name = project.fetch("name")
      namespace = "k6-#{name}".downcase.gsub(/[^a-z0-9-]/, "-")[0, 63]
      stages = []
      begin
        stages << stage(name, "install", project.fetch("install"), namespace, options)
        stages << stage(name, "ready", project["ready"], namespace, options)
        stages << stage(name, "smoke", project["smoke"], namespace, options)
        stages << stage(name, "scale", project["scale"], namespace, options)
        stages << stage(name, "upgrade", project["upgrade"], namespace, options)
        stages << stage(name, "rollback", project["rollback"], namespace, options)
        stages << stage(name, "restart", project["restart"], namespace, options)
      ensure
        stages << stage(name, "uninstall", project["uninstall"], namespace, options)
      end
      residue = sweep_residue(namespace, options)
      {"name" => name, "categories" => project["categories"], "namespace" => namespace,
       "passed" => stages.compact.all? { |s| s.fetch("passed") } && residue.empty?,
       "stages" => stages.compact, "residue" => residue}
    end

    def stage(project, id, command, namespace, options)
      return nil if command.nil? || command.to_s.empty?

      env = {"KUBECONFIG" => options.fetch(:kubeconfig), "K6_NAMESPACE" => namespace}
      started = Time.now.utc
      stdout, stderr, status = Open3.capture3(env, "bash", "-o", "pipefail", "-c", command, chdir: ROOT)
      {"project" => project, "stage" => id, "passed" => status.success?, "exit_status" => status.exitstatus,
       "elapsed_seconds" => (Time.now.utc - started).round(3),
       "stdout_sha256" => Digest::SHA256.hexdigest(stdout),
       "stderr" => status.success? ? nil : stderr.lines.last(5).join.strip}
    end

    # Namespaced objects, the namespace itself, cluster-scoped objects the
    # project owns, PVs and finalizers must all be gone.
    def sweep_residue(namespace, options)
      kubectl = File.join(ROOT, "build/tools/kubectl-v1.36.2")
      residue = []
      out, _err, status = Open3.capture3(kubectl, "--kubeconfig", options.fetch(:kubeconfig),
                                         "get", "namespace", namespace, "-o", "json")
      if status.success?
        document = begin
          JSON.parse(out)
        rescue StandardError
          {}
        end
        residue << {"kind" => "Namespace", "name" => namespace,
                    "finalizers" => document.dig("spec", "finalizers") || document.dig("metadata", "finalizers")}
      end
      %w[persistentvolumes clusterroles clusterrolebindings
         customresourcedefinitions validatingwebhookconfigurations
         mutatingwebhookconfigurations].each do |resource|
        out, _err, status = Open3.capture3(kubectl, "--kubeconfig", options.fetch(:kubeconfig),
                                           "get", resource, "-o", "json")
        next unless status.success?

        items = begin
          JSON.parse(out)["items"]
        rescue StandardError
          []
        end || []
        items.each do |item|
          next unless item.dig("metadata", "name").to_s.include?(namespace)

          residue << {"kind" => resource, "name" => item.dig("metadata", "name"),
                      "finalizers" => item.dig("metadata", "finalizers")}
        end
      end
      residue
    end
  end
end

exit(Conformance::K6Corpus.run) if $PROGRAM_NAME == __FILE__
