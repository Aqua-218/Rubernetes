# frozen_string_literal: true

require "open3"
require "stringio"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/rubectl"
require "rubernetes/transport"

class RubectlCronTest < Minitest::Test
  CLI = Rubernetes::Rubectl::CLI
  ROOT = File.expand_path("../..", __dir__).freeze
  ANCHOR = "2026-11-01T04:45:00Z"
  TIMESTAMP = "batch.kubernetes.io/cronjob-scheduled-timestamp"

  def test_ruby_manifest_preview_matches_jobs_created_by_the_controller
    Dir.mktmpdir do |directory|
      path = File.join(directory, "nightly.rb")
      File.write(path, <<~RUBY)
        cron_job "nightly", namespace: "default" do
          schedule "30 1 * * *"
          time_zone "America/New_York"
          container("report", image: "busybox:1.36") { command ["echo", "ready"] }
        end
      RUBY

      args = ["--allow-code", "-f", path]
      preview = executable("cron", *args, "--from", ANCHOR, "--count", "2", "--kubeconfig", File.join(directory, "missing"))
      times = preview.dig("cronJobs", 0, "nextRuns")

      assert_equal %w[2026-11-01T01:30:00-04:00 2026-11-01T01:30:00-05:00], times

      with_api do |client, url, clock|
        resource = executable("apply", *args, "--server", url)

        assert_equal ["30 1 * * *", "America/New_York"], resource.fetch("spec").values_at("schedule", "timeZone")
        controller = cron_controller(client)
        observed = times.map do |time|
          clock[0] = Time.iso8601(time).utc
          result = controller.reconcile(resource, apply: true, now: clock.first)
          resource = client.get("CronJob", "nightly", namespace: "default", api_version: "batch/v1")
          created = client.get("Job", result.creates.first.object.dig("metadata", "name"), namespace: "default", api_version: "batch/v1")
          created.dig("metadata", "annotations", TIMESTAMP)
        end

        assert_equal times, observed
        assert_equal "2026-11-01T06:30:00Z", resource.dig("status", "lastScheduleTime")
      end
    end
  end

  def test_streams_only_previewed_cronjobs_from_a_mixed_manifest
    documents = {"apiVersion" => "v1", "kind" => "List", "items" => [
      {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "hidden"}, "stringData" => {"key" => "sensitive"}},
      {"apiVersion" => "batch/v1", "kind" => "CronJob", "metadata" => {"name" => "interval"},
       "spec" => {"schedule" => "@every 90s", "suspend" => true}}
    ]}
    code, output, error = run_cli(%w[cron -f - --from 2026-01-01T09:00:17+09:00 --count 2], input: JSON.generate(documents))

    assert_equal 0, code, error
    assert_empty error
    refute_includes output, "sensitive"
    job = JSON.parse(output).fetch("cronJobs").first

    assert_equal [true, %w[2026-01-01T00:01:47Z 2026-01-01T00:03:17Z]], job.values_at("suspended", "nextRuns")
  end

  def test_zero_history_deletes_the_job_and_preserves_its_last_successful_time
    with_api do |client, _url, clock|
      template = {"spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "run", "image" => "busybox:1.36"}]}}
      cron = client.create({"apiVersion" => "batch/v1", "kind" => "CronJob", "metadata" => {"name" => "ephemeral"},
                            "spec" => {"schedule" => "* * * * *", "successfulJobsHistoryLimit" => 0,
                                       "jobTemplate" => {"spec" => {"template" => template}}}}, namespace: "default")
      controller = cron_controller(client)
      clock[0] += 60
      name = controller.reconcile(cron, apply: true, now: clock.first).creates.first.object.dig("metadata", "name")
      job = client.get("Job", name, namespace: "default", api_version: "batch/v1")

      assert_equal clock.first.iso8601, job.dig("metadata", "annotations", TIMESTAMP)

      clock[0] += 5
      completed_at = clock.first.iso8601
      job["status"] = {"startTime" => job.dig("metadata", "creationTimestamp"), "completionTime" => completed_at, "succeeded" => 1,
                       "conditions" => %w[SuccessCriteriaMet Complete].map { |type| {"type" => type, "status" => "True"} }}
      client.update(job, subresource: "status")
      cron = client.get("CronJob", "ephemeral", namespace: "default", api_version: "batch/v1")
      result = controller.reconcile(cron, apply: true, now: clock.first)

      assert_empty client.get("Job", namespace: "default", api_version: "batch/v1").fetch("items")
      assert_equal(["SuccessfulDelete"], result.events.map { |event| event.fetch("reason") })
      status = client.get("CronJob", "ephemeral", namespace: "default", api_version: "batch/v1").fetch("status")

      assert_equal completed_at, status.fetch("lastSuccessfulTime")
      assert_empty Array(status["active"])
    end
  end

  def test_arguments_are_checked_before_reading_the_manifest
    {
      [] => "--from is required",
      ["--from", "2026-01-01T01:00:00"] => "--from must be an RFC3339 timestamp",
      ["--from", "2026-02-30T01:00:00Z"] => "--from must be an RFC3339 timestamp",
      ["--from", ANCHOR, "--count", "101"] => "--count must be between 1 and 100"
    }.each do |args, message|
      code, output, error = run_cli(["cron", "-f", "missing.rb", *args])

      assert_equal CLI::EX_USAGE, code
      assert_empty output
      assert_includes error, message
    end
  end

  def test_invalid_ruby_schedule_points_to_its_declaration
    Dir.mktmpdir do |directory|
      path = File.join(directory, "bad.rb")
      File.write(path, "# declarations\ncron_job(\"no-unit\") { schedule \"@every 9\"; container \"c\", image: \"busybox:1.36\" }\n")
      args = ["cron", "-f", path, "--from", ANCHOR]
      code, output, error = run_cli(args)

      assert_equal CLI::EX_DATAERR, code
      assert_empty output
      assert_includes error, "--allow-code"

      code, output, error = run_cli([*args, "--allow-code"])

      assert_equal CLI::EX_DATAERR, code
      assert_empty output
      assert_includes error, "bad.rb:2: failed to parse duration"
    end
  end

  private

  def run_cli(args, input: "")
    output = StringIO.new
    error = StringIO.new
    code = CLI.run(args, stdout: output, stderr: error, stdin: StringIO.new(input), client_factory: ->(_) { flunk("cron built an API client") })
    [code, output.string, error.string]
  end

  def executable(*)
    env = {"KUBERC" => "off", "NO_PROXY" => "127.0.0.1", "no_proxy" => "127.0.0.1"}
    output, error, status = Open3.capture3(env, RbConfig.ruby, "-Ilib", "exe/rubectl", *, chdir: ROOT)

    assert_predicate status, :success?, error
    JSON.parse(output)
  end

  def with_api
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    clock = [Time.iso8601(ANCHOR)]
    handler = Rubernetes::API::Server.new(registry: registry, clock: -> { clock.first })
    transport = Rubernetes::Transport::HTTPServer.new(handler, host: "127.0.0.1", port: 0, shutdown_timeout: 1).start
    url = "http://127.0.0.1:#{transport.port}"
    client = Rubernetes::Client::KubernetesClient.new(server: url, namespace: "default")
    yield client, url, clock
  ensure
    transport&.stop(timeout: 1)
  end

  def cron_controller(client)
    controller = Rubernetes::Controller::CronJobController
    store = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: [controller::DESCRIPTOR, controller::JOB])
    controller.new(store: store)
  end
end
