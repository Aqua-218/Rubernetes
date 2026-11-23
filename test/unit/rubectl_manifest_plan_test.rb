# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/rubectl"
require "rubernetes/rubectl/manifest_plan"
require "base64"
require "fileutils"
require "stringio"
require "tmpdir"

class RubectlManifestPlanTest < Minitest::Test
  Plan = Rubernetes::Rubectl::ManifestPlan

  def test_lists_changed_paths_without_disclosing_secret_or_field_ownership_values
    before = {"metadata" => {"managedFields" => [{"fieldsV1" => {"v:\"old\"" => {}}}]},
              "data" => {"key/a~b" => "old", "remove" => nil}}
    after = {"metadata" => {"managedFields" => [{"fieldsV1" => {"v:\"new\"" => {}}}]},
             "data" => {"key/a~b" => "new", "add" => nil}}

    assert_equal %w[/data/add /data/key~1a~0b /data/remove /metadata/managedFields], Plan.changed_paths(before, after, "")
    assert_equal ["/1/image"], Plan.changed_paths([{}, {"image" => "old"}], [{}, {"image" => "new"}], "")
  end

  def test_server_generation_and_ownership_timestamps_do_not_change_the_plan
    build = ->(generation, time) { {"metadata" => {"generation" => generation, "managedFields" => [{"manager" => "team", "time" => time}]}} }

    assert_equal Plan.comparable(build.call(1, "yesterday")), Plan.comparable(build.call(2, "today"))
  end

  def test_plan_rejects_a_concurrent_edit_between_get_and_apply
    manifest = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "test"}}
    client = Object.new
    client.define_singleton_method(:get) { |*, **| manifest.merge("metadata" => {"name" => "test", "uid" => "uid", "resourceVersion" => "1"}) }
    client.define_singleton_method(:apply) do |*, dry_run:, **|
      raise "expected server dry-run" unless dry_run

      manifest.merge("metadata" => {"name" => "test", "uid" => "uid", "resourceVersion" => "2"})
    end

    error = assert_raises(Rubernetes::Client::Error) { Plan.for_resource(client, manifest, namespace: "dev", field_manager: "team", force: false) }
    assert_match(/changed while building the plan/, error.message)
  end

  def test_ruby_plan_and_apply_report_the_rejected_declaration_and_redact_secrets
    plaintext = "secret-token\\value"
    data = Base64.strict_encode64("stored-secret")
    resources = [
      {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "first"}},
      {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "owned"}, "stringData" => {"key" => plaintext}, "data" => {"key" => data}}
    ]
    sandbox = Object.new
    sandbox.define_singleton_method(:compile) do |_path, **_options, &block|
      block.call([1, 7])
      resources
    end
    reflected = [plaintext, Base64.strict_encode64(plaintext), data, "stored-secret"].join(" ")
    client, writes = rejecting_client(reflected)
    Dir.mktmpdir do |directory|
      Dir.chdir(directory) do
        FileUtils.mkdir_p("manifests")
        File.write("manifests/app.rb", "# evaluated by the injected sandbox")
        %w[plan apply].each do |command|
          stdout = StringIO.new
          stderr = StringIO.new
          arguments = [command, "--allow-code", "-f", File.expand_path("manifests/app.rb")]
          code = Rubernetes::Rubectl::CLI.run(arguments, client: client, sandbox: sandbox, stdout: stdout, stderr: stderr)

          assert_equal 1, code
          assert_empty stdout.string
          assert_equal "rubectl: manifests/app.rb:7: Secret/owned", stderr.string.lines.first.chomp
          status = JSON.parse(stderr.string.lines.last)

          assert_equal ["Conflict", 409], status.values_at("reason", "code")
          assert_equal "[REDACTED] [REDACTED] [REDACTED] [REDACTED]", status.fetch("message")
          assert_equal resources.last, writes.last.fetch(:resource)
          assert_equal command == "plan", writes.last.fetch(:dry_run)
        end
      end
    end
  end

  def test_text_plan_displays_the_local_declaration_line_and_retains_redaction
    resource = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "demo", "namespace" => "default"}}
    sandbox = Object.new
    sandbox.define_singleton_method(:compile) do |*, **, &locations|
      locations.call([4])
      [resource]
    end
    client, = rejecting_client("")
    Dir.mktmpdir do |directory|
      Dir.chdir(directory) do
        File.write("app.rb", "# compiled by the injected sandbox")
        stdout = StringIO.new
        code = Rubernetes::Rubectl::CLI.run(%w[plan --allow-code -f app.rb -o text --token demo], client: client, sandbox: sandbox, stdout: stdout)

        assert_equal 0, code
        assert_equal "app.rb:4  CREATE ConfigMap/default/[REDACTED]\n", stdout.string
      end
    end
    report = resource.merge("action" => "update", "changedPaths" => ["/data/line\nbreak"])

    assert_equal "UPDATE ConfigMap/default/demo\n  /data/line\\nbreak", Plan.text(report)
  end

  def test_json_yaml_and_piped_resources_keep_the_plain_api_error
    object = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "owned"}}
    client, = rejecting_client("field-manager ownership conflict")
    Dir.mktmpdir do |directory|
      json = File.join(directory, "manifest.json")
      yaml = File.join(directory, "manifest.yaml")
      File.write(json, JSON.generate(object))
      File.write(yaml, Psych.dump(object))
      %w[plan apply].product([json, yaml, "-"]).each do |command, filename|
        stderr = StringIO.new
        stdin = StringIO.new(Psych.dump(object))
        code = Rubernetes::Rubectl::CLI.run([command, "-f", filename], client: client, stdin: stdin, stdout: StringIO.new, stderr: stderr)

        assert_equal 1, code
        assert_equal ["Conflict", "field-manager ownership conflict"], JSON.parse(stderr.string).values_at("reason", "message")
      end
    end
  end

  private

  def rejecting_client(message)
    client = Object.new
    writes = []
    client.define_singleton_method(:get) do |*, **|
      raise Rubernetes::Client::APIError.new("not found", response: Struct.new(:status).new(404))
    end
    client.define_singleton_method(:apply) do |resource, dry_run: false, **|
      writes << {resource: resource, dry_run: dry_run}
      if resource.dig("metadata", "name") == "owned"
        status = {"reason" => "Conflict", "code" => 409, "message" => message}
        raise Rubernetes::Client::APIError.new(message, response: Struct.new(:status).new(409), status_object: status)
      end

      resource
    end
    [client, writes]
  end
end
