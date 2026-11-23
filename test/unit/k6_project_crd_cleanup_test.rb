# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/k6_project_crd_cleanup"
require_relative "../../tools/conformance/k6_project_crd_creation_audit"

class K6ProjectCRDCleanupTest < Minitest::Test
  def test_cleanup_selects_only_chart_owned_crds_with_the_original_uid
    cleanup = Conformance::K6ProjectCRDCleanup.allocate
    cleanup.define_singleton_method(:remove) { |record| record.fetch("metadata").fetch("name") }
    names = %w[kept.example new.example replaced.example]
    before = snapshot("kept.example" => "old")
    installed = snapshot("kept.example" => "different", "new.example" => "created", "replaced.example" => "first")
    after = snapshot("kept.example" => "different", "new.example" => "created", "replaced.example" => "second", "extra.example" => "other")

    assert_equal ["new.example"], cleanup.run(names, before, installed, after)
    assert_empty cleanup.run(names, nil, installed, after)
  end

  def test_existing_instances_prevent_crd_deletion
    Dir.mktmpdir do |dir|
      kubectl = File.join(dir, "kubectl")
      File.write(kubectl, <<~SH)
        #!/bin/sh
        case "$4" in
          get) echo '{"items":[{"metadata":{"name":"still-in-use"}}]}' ;;
          *) touch "#{dir}/unexpected"; exit 1 ;;
        esac
      SH
      File.chmod(0o700, kubectl)
      cleanup = Conformance::K6ProjectCRDCleanup.new(kubectl: kubectl, helm: "helm", kubeconfig: "fixture", namespace: "test", helm_env: {})
      installed = snapshot("widgets.example" => "uid")

      assert_equal [{"name" => "widgets.example", "passed" => false, "error" => "custom resources still exist"}],
                   cleanup.run(["widgets.example"], {}, installed, installed)
      refute_path_exists File.join(dir, "unexpected")
    end
  end

  def test_failed_release_uses_only_matching_ownership_or_observed_creation
    cleanup = Conformance::K6ProjectCRDCleanup.new(kubectl: "kubectl", helm: "helm", kubeconfig: "fixture", namespace: "test", helm_env: {})
    cleanup.define_singleton_method(:remove) { |record| record.fetch("metadata").fetch("name") }
    pairs = {"preexisting.example" => "before", "templated.example" => "release", "foreign.example" => "foreign",
             "static.example" => "observed", "anonymous.example" => "unknown", "replacement.example" => "original"}
    installed = snapshot(pairs)
    annotate_release(installed, ["templated.example", "release"], "project")
    annotate_release(installed, ["foreign.example", "foreign"], "another-project")
    annotate_release(installed, ["preexisting.example", "before"], "project")
    after = Marshal.load(Marshal.dump(installed))
    after.delete(["replacement.example", "original"])
    after.merge!(snapshot("replacement.example" => "replacement"))
    before = snapshot("preexisting.example" => "before")
    creation_receipts = [["static.example", "observed"], ["replacement.example", "original"]]

    assert_equal %w[templated.example static.example],
                 cleanup.run(pairs.keys, before, installed, after, failed_releases: ["project"], created: creation_receipts)
  end

  def test_creation_audit_excludes_existing_updates_other_callers_and_dry_runs
    Dir.mktmpdir do |dir|
      audit_log = File.join(dir, "audit.jsonl")
      created = audit_event
      created.fetch("responseObject")["spec"] = {"description" => "Kubernetes \u2013 audited creation"}
      ignored = [{"responseStatus" => {"code" => 200}}, {"user" => {"username" => "concurrent-helm"}},
                 {"impersonatedUser" => {"username" => "helm-fixture"}}, {"stageTimestamp" => "2026-11-20T09:00:00Z"},
                 {"requestURI" => "#{created.fetch("requestURI")}?dryRun=All"}].each_with_index.map do |other, index|
        event = audit_event
        event.dig("responseObject", "metadata")["uid"] = "ignored-#{index}"
        event.merge(other)
      end
      File.write(audit_log, [created, *ignored].map { |row| JSON.generate(row) }.join("\n"))
      audit = Conformance::K6ProjectCRDCreationAudit.new(path: audit_log, username: "helm-fixture")
      install = {"started_at" => "2026-11-20T08:00:00Z", "finished_at" => "2026-11-20T08:00:02Z"}

      assert_equal [["widgets.example", "created"]], audit.identities(install)
      File.write(audit_log, "\n{", mode: "a")

      assert_empty audit.identities(install)
    end
  end

  private

  def annotate_release(records, key, name)
    records.fetch(key).fetch("metadata").merge!("labels" => {"app.kubernetes.io/managed-by" => "Helm"},
                                                "annotations" => {"meta.helm.sh/release-name" => name, "meta.helm.sh/release-namespace" => "test"})
  end

  def audit_event
    group = "apiextensions.k8s.io"
    path = "/apis/#{group}/v1/customresourcedefinitions/widgets.example"
    {"stage" => "ResponseComplete", "verb" => "patch", "stageTimestamp" => "2026-11-20T08:00:01Z", "requestURI" => path,
     "responseStatus" => {"code" => 201}, "user" => {"username" => "helm-fixture"},
     "objectRef" => {"apiGroup" => group, "apiVersion" => "v1", "resource" => "customresourcedefinitions", "name" => "widgets.example"},
     "responseObject" => {"apiVersion" => "#{group}/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "widgets.example", "uid" => "created"}}}
  end

  def snapshot(entries)
    entries.to_h { |name, uid| [[name, uid], {"metadata" => {"name" => name, "uid" => uid, "resourceVersion" => "10"}}] }
  end
end
