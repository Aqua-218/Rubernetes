# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# validateCompletions (pkg/apis/batch/validation/validation.go:902):
# completions is immutable for a non-indexed Job, and an indexed Job may only
# change it in tandem with parallelism.  Nothing enforced it.
class JobCompletionsUpdateTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def job(spec_extra = {})
    {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => {"name" => "j", "namespace" => "ns"},
     "spec" => {"completions" => 3, "parallelism" => 3,
                "template" => {"spec" => {"containers" => [{"name" => "c", "image" => "i"}],
                                          "restartPolicy" => "Never"}}}.merge(spec_extra)}
  end

  def errors(new_job, old_job, operation: :update)
    Validator.send(:job_completions_update_errors, new_job, old_job, operation)
  end

  def test_unchanged_completions_are_accepted
    assert_empty errors(job, job)
  end

  def test_a_non_indexed_job_may_not_change_completions
    refute_empty errors(job("completions" => 5), job)
  end

  def test_an_indexed_job_may_change_completions_with_parallelism
    old = job("completionMode" => "Indexed")
    changed = job("completionMode" => "Indexed", "completions" => 5, "parallelism" => 5)

    assert_empty errors(changed, old)
  end

  def test_an_indexed_job_may_not_change_completions_alone
    old = job("completionMode" => "Indexed")
    changed = job("completionMode" => "Indexed", "completions" => 5)

    refute_empty errors(changed, old)
  end

  def test_a_create_is_never_restricted
    assert_empty errors(job("completions" => 9), job, operation: :create)
  end
end
