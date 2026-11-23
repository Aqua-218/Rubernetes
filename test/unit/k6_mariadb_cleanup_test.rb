# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/k6_corpus"

class K6MariaDBCleanupTest < Minitest::Test
  def test_helm_waits_for_the_foreground_deletion_of_the_fixture_database
    corpus = Conformance::K6Corpus
    project = YAML.safe_load_file(corpus::CORPUS).fetch("projects").find { |entry| entry.fetch("name") == "mariadb-operator" }
    command = corpus.cleanup_command(project)
    database = 'kubectl -n "$K6_NAMESPACE" delete mariadb k6-mariadb --cascade=foreground --ignore-not-found --wait --timeout=3m'
    operator = 'helm uninstall mariadb-operator --namespace "$K6_NAMESPACE" --wait --timeout 10m'
    crds = 'helm uninstall mariadb-operator-crds --namespace "$K6_NAMESPACE" --wait --timeout 10m'

    assert_match(/#{Regexp.escape(database)}.*#{Regexp.escape(operator)}.*#{Regexp.escape(crds)}/, command)
  end
end
