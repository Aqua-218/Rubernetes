# frozen_string_literal: true

require "stringio"
require_relative "../test_helper"
require "rubernetes/rubectl"

class RubectlLogsTest < Minitest::Test
  Client = Rubernetes::Client
  CLI = Rubernetes::Rubectl::CLI

  class Rest
    attr_reader :requests, :streams, :closed

    def initialize(pod)
      @pod = pod
      @requests = []
      @streams = []
    end

    def request(method, path, **)
      @requests << [method, path]
      Client::HTTPClient::Response.new(status: 200, headers: {"content-type" => "application/json"}, body: JSON.generate(@pod))
    end

    def stream(method, path, query:, **options)
      @streams << [method, path, query, options]
      yield "first\n"
      yield "\xFFlast".b
    ensure
      @closed = true
    end
  end

  def setup
    @pod = {"metadata" => {"name" => "app", "namespace" => "team"},
            "spec" => {"containers" => [{"name" => "first"}, {"name" => "second"}],
                       "initContainers" => [{"name" => "setup"}], "ephemeralContainers" => [{"name" => "debug"}]}}
    @rest = Rest.new(@pod)
    @client = Client::KubernetesClient.new(context: {namespace: "team"}, rest_client: @rest)
    @stdout = StringIO.new
    @stderr = StringIO.new
  end

  def run_logs(*args)
    CLI.run(args, stdout: @stdout, stderr: @stderr, client: @client, env: {})
  end

  def test_logs_select_first_and_write_binary_chunks_with_no_final_newline
    assert_equal 0, run_logs("logs", "app")
    assert_equal "first\n\xFFlast".b, @stdout.string.b
    assert_equal "Defaulted container \"first\" out of: first, second, debug (ephem), setup (init)\n", @stderr.string
    assert_equal [["GET", "/api/v1/namespaces/team/pods/app"]], @rest.requests
    assert_equal [["GET", "/api/v1/namespaces/team/pods/app/log", {"container" => "first"}, {}]], @rest.streams
  end

  def test_annotation_can_select_an_init_container
    @pod["metadata"]["annotations"] = {"kubectl.kubernetes.io/default-container" => "setup"}

    assert_equal 0, run_logs("logs", "pod/app", "--tail=-1", "--follow=false")
    assert_empty @stderr.string
    assert_equal({"container" => "setup"}, @rest.streams.first.fetch(2))
  end

  def test_executable_options_override_namespace_and_use_stream_timeout
    assert_equal 0, run_logs("--namespace", "other", "logs", "app", "-c", "debug", "-p", "-f", "--tail", "0", "--timestamps",
                             "--since", "1m1.5s")
    assert_empty @stderr.string
    assert_equal [["GET", "/api/v1/namespaces/other/pods/app"]], @rest.requests
    assert_equal [["GET", "/api/v1/namespaces/other/pods/app/log",
                   {"container" => "debug", "follow" => true, "previous" => true, "tailLines" => 0,
                    "timestamps" => true, "sinceSeconds" => 62}, {read_timeout: 0}]], @rest.streams
  end

  def test_since_time_is_normalized_and_a_zero_duration_is_unset
    assert_equal 0, run_logs("logs", "app", "-c", "first", "--since=0s", "--since-time=2026-11-20T09:10:11.2+09:00")
    assert_equal({"container" => "first", "sinceTime" => "2026-11-20T00:10:11Z"}, @rest.streams.first.fetch(2))
  end

  def test_bad_arguments_fail_before_accessing_the_api
    [%w[--since=30], %w[--since=-1s], %w[--since-time=2026-02-29T00:00:00Z], %w[--tail=-2],
     %w[--since=1s --since-time=2026-11-20T00:00:00Z], %w[--output=json]].each do |flags|
      assert_equal CLI::EX_USAGE, run_logs("logs", "app", *flags)
    end
    assert_empty @rest.requests
    assert_empty @rest.streams
  end

  def test_broken_pipe_stops_following_without_an_error
    @stdout.define_singleton_method(:write) { |_| raise Errno::EPIPE }

    assert_equal 0, run_logs("logs", "app", "-c", "first", "-f")
    assert @rest.closed
    assert_empty @stderr.string
  end
end
