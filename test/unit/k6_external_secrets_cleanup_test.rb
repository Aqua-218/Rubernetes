# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/k6_corpus"

class K6ExternalSecretsCleanupTest < Minitest::Test
  SAMPLE_DELETE = "kubectl -n dedicated delete externalsecret/k6-smoke --ignore-not-found --wait --timeout=2m"
  STORE_DELETE = "kubectl -n dedicated delete secretstore/k6-fake-store --ignore-not-found --wait --timeout=90s"
  HELM_UNINSTALL = "helm uninstall external-secrets --namespace dedicated --wait --timeout 10m"
  NAMESPACE_DELETE = "kubectl delete namespace dedicated --ignore-not-found --timeout=10m"

  def test_waits_for_the_application_sample_before_deleting_its_store_and_helm_release
    calls, stderr, status = run_cleanup("")

    assert_predicate status, :success?, stderr
    assert_equal [SAMPLE_DELETE, STORE_DELETE, HELM_UNINSTALL, NAMESPACE_DELETE], calls
  end

  def test_missing_sample_and_store_are_idempotent
    calls, stderr, status = run_cleanup(<<~SH)
      case "$4" in
        externalsecret/k6-smoke|secretstore/k6-fake-store)
          test "$5" = --ignore-not-found
          exit "$?"
          ;;
      esac
    SH

    assert_predicate status, :success?, stderr
    assert_equal [SAMPLE_DELETE, STORE_DELETE, HELM_UNINSTALL, NAMESPACE_DELETE], calls
  end

  def test_failed_sample_finalization_is_reported_and_skips_store_deletion
    calls, stderr, status = run_cleanup(<<~SH)
      if test "$4" = externalsecret/k6-smoke; then
        echo "timed out waiting for the application sample to be deleted" >&2
        exit 1
      fi
    SH

    refute_predicate status, :success?
    assert_includes stderr, "timed out waiting for the application sample"
    assert_equal [SAMPLE_DELETE, HELM_UNINSTALL, NAMESPACE_DELETE], calls
  end

  private

  def run_cleanup(kubectl_fixture)
    corpus = Conformance::K6Corpus
    project = YAML.safe_load_file(corpus::CORPUS).fetch("projects").find { |entry| entry.fetch("name") == "external-secrets" }
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      File.write(File.join(directory, "kubectl"), "#!/bin/sh\nprintf 'kubectl %s\\n' \"$*\" >> \"$K6_TEST_CALLS\"\n#{kubectl_fixture}", perm: 0o700)
      File.write(File.join(directory, "helm"), "#!/bin/sh\nprintf 'helm %s\\n' \"$*\" >> \"$K6_TEST_CALLS\"\n", perm: 0o700)
      environment = {"PATH" => directory, "K6_NAMESPACE" => "dedicated", "K6_TEST_CALLS" => calls}
      _, stderr, status = Open3.capture3(environment, "/bin/bash", "-o", "pipefail", "-c", corpus.cleanup_command(project))
      [File.readlines(calls, chomp: true), stderr, status]
    end
  end
end
