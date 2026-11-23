# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require_relative "../../tools/conformance/k6_project_images"

class K6ProjectImagesTest < Minitest::Test
  NAMESPACE = "k6-fixture"
  MAIN = "docker.io/library/main:1"
  HOOK = "docker.io/library/hook:1"
  INIT = "docker.io/library/init:1"
  DEBUG = "docker.io/library/debug:1"

  def test_watch_replays_from_the_list_cursor_and_keeps_a_deleted_hook_and_init_and_ephemeral_images
    hook = pod("hook", "hook-uid", "21", {"containerStatuses" => [container(HOOK, "b", :terminated)],
                                          "initContainerStatuses" => [container(INIT, "c", :terminated)],
                                          "ephemeralContainerStatuses" => [container(DEBUG, "d", :running)]})
    active = pod("main", "main-uid", "22", {"containerStatuses" => [container(MAIN, "a", :running)]})
    responses = {"20" => [event("DELETED", hook), event("BOOKMARK", {"metadata" => {"resourceVersion" => "21"}})],
                 "21" => [event("ADDED", active)]}
    with_images(responses: responses, listed: [active]) do |images, queries|
      images.start_watch
      images.during("smoke") { wait_for_query(queries, "21") }
      images.capture("restart")
      images.stop_watch
      result = images.result

      assert result.fetch("passed")
      assert_equal({"status" => "complete", "errors" => []}, result.fetch("watch"))
      by_image = result.fetch("images").to_h { |image| [image.fetch("reference"), image] }

      assert_equal [DEBUG, HOOK, INIT, MAIN].sort, by_image.keys.sort
      assert_equal %w[watch DELETED 21 hook-uid], by_image.fetch(HOOK).values_at("observation", "watch_event", "resource_version", "pod_uid")
      assert_equal %w[list restart main-uid], by_image.fetch(MAIN).values_at("observation", "stage", "pod_uid")
      assert_equal %w[watch ADDED 22 main-uid], by_image.fetch(MAIN).fetch("watch_observation")
        .values_at("observation", "watch_event", "resource_version", "pod_uid")
      lines = File.readlines(queries, chomp: true)

      assert lines.first.start_with?("/api/v1/namespaces/#{NAMESPACE}/pods?limit=1")
      assert lines[1].include?("watch=true") && lines[1].include?("resourceVersion=20")
      assert_includes lines[2], "resourceVersion=21"
    end
  end

  def test_an_expired_watch_fails_visibility_even_when_the_stage_list_still_passes
    active = pod("main", "main-uid", "23", {"containerStatuses" => [container(MAIN, "a", :running)]})
    expired = event("ERROR", {"code" => 410, "message" => "adversarial-private-pod-data"})
    with_images(responses: {"20" => [expired]}, listed: [active]) do |images, queries|
      images.start_watch
      images.during("smoke") { images.capture("smoke") }
      images.stop_watch
      result = images.result

      refute result.fetch("passed")
      assert_equal "incomplete", result.dig("watch", "status")
      assert_match(/resourceVersion expired/, result.fetch("errors").join)
      assert_equal "list", result.fetch("images").first.fetch("observation")
      refute_includes JSON.generate(result), "adversarial-private-pod-data"
      assert_equal(1, File.readlines(queries).count { |query| query.include?("watch=true") })
    end
  end

  def test_final_watch_captures_a_hook_committed_after_the_original_server_closed
    hook = pod("last-hook", "last-hook-uid", "21", {"containerStatuses" => [container(HOOK, "b", :terminated)]})
    with_images(responses: {"20" => [event("DELETED", hook)]}, first_stream_closes_before_response: true) do |images, queries|
      images.start_watch
      images.during("smoke") { wait_for { File.exist?(queries + ".server_closed") } }
      images.stop_watch
      result = images.result

      assert result.fetch("passed")
      assert_equal "complete", result.dig("watch", "status")
      assert_equal %w[last-hook-uid DELETED 21], result.fetch("images").first.values_at("pod_uid", "watch_event", "resource_version")
      assert_equal(2, File.readlines(queries).count { |query| query.include?("resourceVersion=20") })
    end
  end

  def test_a_transient_stream_failure_retries_at_the_same_cursor
    hook = pod("hook", "hook-uid", "21", {"containerStatuses" => [container(HOOK, "b", :terminated)]})
    with_images(responses: {"20" => [event("DELETED", hook)]}, first_error_code: 503) do |images, queries|
      images.start_watch
      images.during("smoke") { wait_for_query(queries, "21") }
      images.stop_watch
      result = images.result

      assert result.fetch("passed")
      assert_equal "hook-uid", result.fetch("images").first.fetch("pod_uid")
      assert_equal(2, File.readlines(queries).count { |query| query.include?("resourceVersion=20") })
    end
  end

  def test_bad_stream_does_not_expose_a_raw_event_and_has_no_hidden_relist
    with_images(responses: {"20" => ["raw-data"]}) do |images, queries|
      images.start_watch
      images.stop_watch
      result = images.result

      assert_equal "incomplete", result.dig("watch", "status")
      assert_match(/invalid JSON/, result.fetch("errors").join)
      refute_includes JSON.generate(result), "raw-data"
      assert_equal(1, File.readlines(queries).count { |query| query.include?("limit=1") })
    end
  end

  def test_watch_decodes_api_utf8_under_a_c_locale
    external = Encoding.default_external
    Encoding.default_external = Encoding::US_ASCII
    hook = pod("hook", "hook-uid", "21", {"containerStatuses" => [container(HOOK, "b", :terminated)]})
    hook["metadata"]["annotations"] = {"example.com/display-name" => "日本語"}
    with_images(responses: {"20" => [event("DELETED", hook)]}) do |images, _queries|
      images.start_watch
      images.stop_watch
      result = images.result

      assert result.fetch("passed")
      assert_equal "complete", result.dig("watch", "status")
      assert_equal "hook-uid", result.fetch("images").first.fetch("pod_uid")
    end
  ensure
    Encoding.default_external = external
  end

  private

  def with_images(responses:, listed: [], first_stream_closes_before_response: false, first_error_code: nil)
    Dir.mktmpdir do |directory|
      queries = File.join(directory, "queries")
      client = File.join(directory, "kubectl")
      fixture = JSON.generate({"listed" => listed, "responses" => responses, "first_stream_closes_before_response" => first_stream_closes_before_response,
                               "first_error_code" => first_error_code})
      File.write(client, <<~RUBY, encoding: Encoding::UTF_8)
        #!#{RbConfig.ruby}
        require "json"
        require "uri"
        fixture = JSON.parse(#{fixture.inspect})
        target = ARGV.last
        if target == "json"
          puts JSON.generate({"items" => fixture.fetch("listed")})
          exit
        end
        File.open(#{queries.inspect}, "a") { |log| log.puts(target) }
        params = URI.decode_www_form(URI.parse(target).query).to_h
        if params.key?("watch")
          first = File.readlines(#{queries.inspect}).count { |query| query.include?("watch=true") } == 1
          if first && fixture.fetch("first_stream_closes_before_response")
            STDOUT.close
            File.write(#{queries.inspect} + ".server_closed", "")
            sleep 0.2
            exit
          end
          if first && (code = fixture.fetch("first_error_code"))
            puts JSON.generate({"type" => "ERROR", "object" => {"code" => code}})
            exit
          end
          events = fixture.fetch("responses").fetch(params.fetch("resourceVersion"), [])
          events.each { |event| puts(event.is_a?(String) ? event : JSON.generate(event)) }
          sleep 0.05
        else
          puts JSON.generate({"metadata" => {"resourceVersion" => "20"}, "items" => []})
        end
      RUBY
      File.chmod(0o700, client)
      locks = [MAIN, HOOK, INIT, DEBUG].zip(%w[a b c d]).map { |reference, hex| "#{reference}@#{digest(hex)}" }
      images = Conformance::K6ProjectImages.new(kubectl: client, kubeconfig: "test", namespace: NAMESPACE, locks: locks)
      yield images, queries
    ensure
      images&.stop_watch
    end
  end

  def wait_for_query(path, version)
    wait_for { File.file?(path) && File.read(path).include?("resourceVersion=#{version}") }
  end

  def wait_for
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    loop do
      return if yield

      raise "watch checkpoint did not appear" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.01
    end
  end

  def digest(hex) = "sha256:#{hex * 64}"

  def event(type, object) = {"type" => type, "object" => object}

  def container(reference, hex, state)
    identity = {"containerID" => "rubernetes://instance"}
    actual = {"name" => reference.split("/").last.delete_suffix(":1"), "image" => reference, "imageID" => "#{reference}@#{digest(hex)}",
              "state" => {state.to_s => identity}}
    actual.merge!(identity) if state == :running
    actual
  end

  def pod(name, uid, version, status)
    {"metadata" => {"name" => name, "namespace" => NAMESPACE, "uid" => uid, "resourceVersion" => version},
     "status" => status, "spec" => {"ignored" => "adversarial-private-pod-data"}}
  end
end
