# frozen_string_literal: true

require "digest"
require "etc"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "time"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m0_source_inventory"

class M0GateTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  EXECUTABLES = %w[rubectl rubernetes-apiserver rubernetes-controller-manager rubernetes-scheduler rubernetes-agent rubernetes-proxy].freeze
  PROBES = %w[abi_manifest clone3_pid_namespace_mount_proc_pidfd_wait netlink_ack bpf_verifier kvm_capability errno_clone3 errno_pidfd
              errno_mount errno_netlink errno_bpf errno_kvm errno_namespace_exec source_input_stability].freeze
  ERRNO = {
    "errno_clone3" => ["clone3", "intentional:clone3"],
    "errno_pidfd" => ["pidfd_open", "intentional:pidfd"],
    "errno_mount" => ["mount", "intentional:mount"],
    "errno_netlink" => ["netlink_ack", "intentional:netlink"],
    "errno_bpf" => ["bpf(BPF_PROG_LOAD)", "intentional:bpf"],
    "errno_kvm" => ["kvm_probe", "intentional:kvm"],
    "errno_namespace_exec" => ["execve", "intentional:namespace-exec"]
  }.freeze

  def test_source_inventory_excludes_root_generator_workspaces
    assert(M0SourceInventory.excluded?("a11-generated.ABC123/sentinel"))
    refute(M0SourceInventory.excluded?("lib/a11-generated.ABC123/sentinel"))
    refute(M0SourceInventory.excluded?("a11-generated.short/sentinel"))
    assert(M0SourceInventory.excluded?("apps/dashboard/log/development.log"))
    assert(M0SourceInventory.excluded?("apps/dashboard/tmp/cache/x"))
    refute(M0SourceInventory.excluded?("apps/dashboard/app/models/user.rb"))
    refute(M0SourceInventory.excluded?("lib/apps/dashboard/log/x"))
  end

  def self.authoritative_minitest_inventory
    @authoritative_minitest_inventory ||= begin
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, "tools/milestones/m0_test_inventory.rb", chdir: ROOT)
      raise "Minitest inventory discovery failed: #{stderr}" unless status.success?

      JSON.parse(stdout)
    end
  end

  def self.current_gem_path
    @current_gem_path ||= begin
      # See M1GateTest#current_gem_path: fixed path required by the gate; reused when
      # rake test:parallel prebuilt it, built here under plain `rake test`.
      path = File.join(ROOT, "build/rubernetes-0.1.0.gem")
      unless ENV["RUBERNETES_TEST_FIXTURE_GEM_PREBUILT"] == "1" && File.file?(path)
        FileUtils.mkdir_p(File.dirname(path))
        stdout, stderr, status = Open3.capture3("gem", "build", "rubernetes.gemspec", "--output", path, chdir: ROOT)
        raise "current test gem build failed: #{stdout}#{stderr}" unless status.success?
      end

      path
    end
  end

  def test_gate_accepts_content_addressed_evidence_without_git_metadata
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      stdout, stderr, status = run_gate(write_valid_evidence(directory))

      assert_predicate(status, :success?, stdout)
      assert_empty(stderr)
      assert_equal(true, JSON.parse(stdout).fetch("passed"))
    end
  end

  def test_gate_rejects_artifacts_outside_the_evidence_directory
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest.fetch("artifacts").first["path"] = "../../etc/passwd"
      File.write(manifest_path, JSON.generate(manifest))

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert(JSON.parse(stdout).fetch("errors").any? { |error| error.include?("artifact escapes evidence directory") })
    end
  end

  def test_gate_rejects_probe_from_a_different_source_input
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      rewrite_json_artifact(manifest_path, "abi-probe-x86_64.json") { |probe| probe["input_sha256"] = "b" * 64 }

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "ABI probe input differs from manifest")
    end
  end

  def test_gate_rejects_aggregate_only_executable_spoofing
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      rewrite_json_artifact(manifest_path, "executables.json") do |report|
        report["results"].delete_at(0)
        report["count"] = 12
        report["failure_count"] = 0
      end

      stdout, = run_gate(manifest_path)
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes(errors, "all 6 executable help/version identities must appear exactly once")
      assert_includes(errors, "executable aggregate count is invalid")
    end
  end

  def test_gate_rejects_missing_command_identity_and_subject_linkage
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest.fetch("commands").first["name"] = "not_the_gem_build"
      manifest.fetch("subjects").find { |subject| subject["source_path"] == "exe/rubectl" }["source_path"] = "exe/not-rubectl"
      File.write(manifest_path, JSON.generate(manifest))

      stdout, = run_gate(manifest_path)
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes(errors, "required command inventory differs")
      assert_includes(errors, "required subject exe/rubectl is missing")
    end
  end

  def test_gate_rejects_symlinked_parent_artifact
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      evidence = File.join(directory, "source-inventory.json")
      link = File.join(directory, "linked")
      FileUtils.ln_s(directory, link)
      manifest = JSON.parse(File.read(manifest_path))
      manifest.fetch("artifacts").find do |entry|
        entry.fetch("path") == "source-inventory.json"
      end.update("path" => "linked/source-inventory.json")
      File.write(manifest_path, JSON.generate(manifest))

      stdout, = run_gate(manifest_path)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? do |error|
        error.include?("artifact escapes evidence directory") || error.include?("missing source-inventory.json")
      end)
      assert File.file?(evidence)
    end
  end

  def test_gate_rejects_subject_digest_from_an_old_source_tree
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      subject = manifest.fetch("subjects").find { |entry| entry.fetch("source_path") == "exe/rubectl" }
      subject["sha256"] = "f" * 64
      File.write(manifest_path, JSON.generate(manifest))

      stdout, = run_gate(manifest_path)
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes(errors, "subject digest mismatch subjects/rubectl")
      assert(errors.any? { |error| error.include?("subject source digest mismatch exe/rubectl") })
    end
  end

  def test_gate_rejects_junit_not_bound_to_rake_inventory
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      junit_path = File.join(directory, "junit.xml")
      junit = File.read(junit_path).sub(/command_sha256="[^"]+"/, %(command_sha256="#{"0" * 64}"))
      File.write(junit_path, junit)
      manifest = JSON.parse(File.read(manifest_path))
      artifact = manifest.fetch("artifacts").find { |entry| entry.fetch("path") == "junit.xml" }
      artifact.replace(evidence_entry(directory, "junit.xml"))
      File.write(manifest_path, JSON.generate(manifest))

      stdout, = run_gate(manifest_path)

      assert_includes(JSON.parse(stdout).fetch("errors"), "JUnit is not bound to the captured rake command")
    end
  end

  def test_gate_rehashes_the_current_source_inventory
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      inventory = JSON.parse(File.read(File.join(directory, "source-inventory.json")))
      inventory.fetch("entries").first["sha256"] = "a" * 64
      canonical = inventory.fetch("entries").sort_by do |entry|
        entry.fetch("path")
      end.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
      inventory["input_sha256"] = Digest::SHA256.hexdigest(canonical)
      manifest["input_sha256"] = inventory["input_sha256"]
      manifest["input_capture"]["start"] = {"sha256" => inventory["input_sha256"], "file_count" => inventory["entries"].length}
      manifest["input_capture"]["finish"] = manifest["input_capture"]["start"]
      File.write(File.join(directory, "source-inventory.json"), JSON.pretty_generate(inventory) << "\n")
      artifact = manifest.fetch("artifacts").find { |entry| entry.fetch("path") == "source-inventory.json" }
      artifact.replace(evidence_entry(directory, "source-inventory.json"))
      File.write(manifest_path, JSON.pretty_generate(manifest))

      stdout, = run_gate(manifest_path)

      assert_includes(JSON.parse(stdout).fetch("errors"), "source inventory does not match the current source tree")
    end
  end

  def test_gate_rejects_stale_probe_tool_and_host_identity
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      rewrite_json_artifact(manifest_path, "abi-probe-x86_64.json") do |probe|
        probe["tool_sha256"] = "b" * 64
        probe["host"]["release"] = "stale-kernel"
      end

      stdout, = run_gate(manifest_path)
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes(errors, "ABI probe is not bound to the current kernel probe tool")
      assert_includes(errors, "ABI probe host is not bound to the current host")
    end
  end

  def test_gate_rejects_empty_abi_payload_and_stale_native_source
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      rewrite_json_artifact(manifest_path, "abi-probe-x86_64.json") do |probe|
        probe.fetch("results").find { |entry| entry.fetch("name") == "bpf_verifier" }.fetch("result")["verifier_log"] = ""
      end
      rewrite_json_artifact(manifest_path, "native-boundary-scan.json") do |scan|
        scan.fetch("source_files").first["sha256"] = "c" * 64
      end

      stdout, = run_gate(manifest_path)
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes(errors, "BPF payload does not prove a loaded verifier program")
      assert(errors.any? { |error| error.include?("native boundary scan source is stale or unsafe") })
    end
  end

  def test_gate_rejects_executable_case_outside_the_report_interval
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      rewrite_json_artifact(manifest_path, "executables.json") do |report|
        report.fetch("results").first["started_at"] = (Time.iso8601(report.fetch("started_at")) - 1).iso8601(6)
      end

      stdout, = run_gate(manifest_path)

      assert(JSON.parse(stdout).fetch("errors").any? { |error| error.include?("result time is outside the report interval") })
    end
  end

  def test_gate_rejects_a_fake_gem_even_when_the_command_self_reports_success
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      File.write(File.join(directory, "rubernetes-0.1.0.gem"), "gem\n")

      stdout, = run_gate(manifest_path)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("built gem is invalid") || error.include?("gem_build output is not linked") })
    end
  end

  def test_gate_rejects_a_handwritten_single_testcase_junit
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      identity = self.class.authoritative_minitest_inventory.fetch("testcases").first
      classname = identity.fetch("classname")
      name = identity.fetch("name")
      result_digest = Digest::SHA256.hexdigest("#{classname}\0#{name}\0passed\n")
      identity_digest = Digest::SHA256.hexdigest("#{classname}\0#{name}\n")
      rake = manifest.fetch("commands").find { |entry| entry.fetch("name") == "rake_test" }
      rake["stdout"] = "1 runs, 0 assertions, 0 failures, 0 errors, 0 skips\n"
      test_entries = current_source_entries.select { |entry| entry.fetch("path").match?(%r{\Atest/.*_test\.rb\z}) }
      file_digest = Digest::SHA256.hexdigest(test_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join)
      attributes = {
        "name" => "rubernetes", "tests" => 1, "failures" => 0, "errors" => 0, "skipped" => 0,
        "reporter_path" => "test/support/junit_reporter.rb",
        "reporter_sha256" => Digest::SHA256.file(File.join(ROOT, "test/support/junit_reporter.rb")).hexdigest,
        "testcase_inventory_sha256" => result_digest, "testcase_inventory_count" => 1,
        "registered_testcase_inventory_sha256" => identity_digest, "registered_testcase_inventory_count" => 1,
        "executed_testcase_inventory_sha256" => identity_digest, "inventory_complete" => true,
        "command_sha256" => Digest::SHA256.hexdigest(JSON.generate(rake.fetch("command"))),
        "test_pattern" => "test/**/*_test.rb", "test_inventory_sha256" => file_digest,
        "test_inventory_count" => test_entries.length
      }.map { |key, value| %(#{key}="#{value}") }.join(" ")
      File.write(File.join(directory, "junit.xml"),
                 %(<testsuite #{attributes}><testcase classname="#{classname}" name="#{name}" time="0.001000"/></testsuite>))
      artifact = manifest.fetch("artifacts").find { |entry| entry.fetch("path") == "junit.xml" }
      artifact.replace(evidence_entry(directory, "junit.xml"))
      File.write(manifest_path, JSON.pretty_generate(manifest))

      stdout, = run_gate(manifest_path)

      assert_includes(JSON.parse(stdout).fetch("errors"), "JUnit does not contain the complete current Minitest runnable inventory")
    end
  end

  def test_gate_rejects_stale_evidence_from_the_year_2000
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest["started_at"] = "2000-01-01T00:00:00.000000Z"
      manifest["finished_at"] = "2000-01-01T00:00:01.000000Z"
      File.write(manifest_path, JSON.pretty_generate(manifest))

      stdout, = run_gate(manifest_path)

      assert_includes(JSON.parse(stdout).fetch("errors"), "evidence capture is stale")
    end
  end

  def test_gate_rejects_native_extension_not_loaded_by_the_abi_probe
    Dir.mktmpdir("rubernetes-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      rewrite_json_artifact(manifest_path, "abi-probe-x86_64.json") do |probe|
        probe.fetch("native_extension")["sha256"] = "d" * 64
      end

      stdout, = run_gate(manifest_path)

      assert_includes(JSON.parse(stdout).fetch("errors"), "ABI probe is not bound to the loaded native extension subject")
    end
  end

  private

  def write_valid_evidence(directory)
    timestamp = Time.now.utc.iso8601(6)
    source_entries = current_source_entries
    input_content = source_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    input_sha256 = Digest::SHA256.hexdigest(input_content)
    identity = {"sha256" => input_sha256, "file_count" => source_entries.length}
    commands = command_records(directory, timestamp, source_entries)

    write_json(directory, "source-inventory.json", {
                 "schema_version" => 1, "kind" => "m0_source_inventory", "input_sha256" => input_sha256,
                 "input_file_count" => source_entries.length, "entries" => source_entries
               })
    FileUtils.cp(self.class.current_gem_path, File.join(directory, "rubernetes-0.1.0.gem"))
    write_json(directory, "gem-build.json", commands.first)
    subjects = write_subjects(directory)
    write_json(directory, "executables.json", executable_report(subjects, timestamp, directory))
    native_entries = source_entries.select { |entry| entry.fetch("path").match?(%r{\Aext/rubernetes_linux/.*\.(?:c|cc|h)\z}) }
    write_json(directory, "native-boundary-scan.json", {
                 "schema_version" => 2, "kind" => "native_boundary_scan",
                 "command" => [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output", File.join(directory, "native-boundary-scan.json")],
                 "output_path" => File.join(directory, "native-boundary-scan.json"),
                 "tool_path" => "tools/milestones/native_boundary_scan.rb",
                 "tool_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/native_boundary_scan.rb")).hexdigest,
                 "started_at" => timestamp,
                 "finished_at" => timestamp,
                 "host" => {"sysname" => Etc.uname[:sysname], "release" => Etc.uname[:release], "machine" => Etc.uname[:machine], "ruby" => RUBY_DESCRIPTION},
                 "source_files" => native_entries,
                 "policy_branch_count" => 0, "retry_count" => 0, "authorization_count" => 0,
                 "state_machine_count" => 0, "findings" => [], "passed" => true
               })
    write_json(directory, "abi-probe-x86_64.json", abi_probe(input_sha256, timestamp, subjects, directory))
    test_entries = source_entries.select { |entry| entry.fetch("path").match?(%r{\Atest/.*_test\.rb\z}) }
    test_inventory_content = test_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    minitest_inventory = self.class.authoritative_minitest_inventory
    testcases = minitest_inventory.fetch("testcases").map { |item| [item.fetch("classname"), item.fetch("name")] }
    status_inventory = testcases.map { |classname, name| "#{classname}\0#{name}\0passed\n" }.sort.join
    identity_inventory = testcases.sort.map { |classname, name| "#{classname}\0#{name}\n" }.join
    junit_attributes = {
      "name" => "rubernetes", "tests" => testcases.length, "failures" => 0, "errors" => 0, "skipped" => 0,
      "reporter_path" => "test/support/junit_reporter.rb",
      "reporter_sha256" => Digest::SHA256.file(File.join(ROOT, "test/support/junit_reporter.rb")).hexdigest,
      "testcase_inventory_sha256" => Digest::SHA256.hexdigest(status_inventory),
      "testcase_inventory_count" => testcases.length,
      "registered_testcase_inventory_sha256" => Digest::SHA256.hexdigest(identity_inventory),
      "registered_testcase_inventory_count" => testcases.length,
      "executed_testcase_inventory_sha256" => Digest::SHA256.hexdigest(identity_inventory),
      "inventory_complete" => true,
      "command_sha256" => Digest::SHA256.hexdigest(JSON.generate(commands.find do |entry|
        entry.fetch("name") == "rake_test"
      end.fetch("command"))),
      "test_pattern" => "test/**/*_test.rb",
      "test_inventory_sha256" => Digest::SHA256.hexdigest(test_inventory_content),
      "test_inventory_count" => test_entries.length
    }
    attributes = junit_attributes.map { |key, value| %(#{key}="#{value}") }.join(" ")
    cases = testcases.map { |classname, name| %(<testcase classname="#{classname}" name="#{name}" time="0.001000"/>) }.join
    File.write(File.join(directory, "junit.xml"), %(<testsuite #{attributes}>#{cases}</testsuite>))

    artifacts = %w[abi-probe-x86_64.json executables.json gem-build.json junit.xml native-boundary-scan.json
                   source-inventory.json].sort.map do |name|
      evidence_entry(directory, name)
    end
    manifest = {
      "schema_version" => 3,
      "milestone" => "M0",
      "status" => "COMPLETE",
      "host" => {"architecture" => RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64").sub("amd64", "x86_64"),
                 "kernel" => Etc.uname[:release], "sysname" => Etc.uname[:sysname], "ruby" => RUBY_DESCRIPTION},
      "input_sha256" => input_sha256,
      "input_file_count" => source_entries.length,
      "input_stable" => true,
      "input_capture" => {"stable" => true, "start" => identity, "finish" => identity},
      "started_at" => timestamp,
      "finished_at" => timestamp,
      "commands" => commands,
      "result_counts" => {"commands" => 6, "command_failures" => 0, "artifacts" => 6, "subjects" => subjects.length,
                          "architecture_profiles" => 1, "source_files" => source_entries.length},
      "artifacts" => artifacts,
      "subjects" => subjects
    }
    manifest_path = File.join(directory, "manifest.json")
    File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
    manifest_path
  end

  def command_records(directory, timestamp, source_entries)
    values = {
      "gem_build" => ["gem", "build", "rubernetes.gemspec", "--output", File.join(directory, "rubernetes-0.1.0.gem")],
      "rake_test" => %w[bundle exec rake test],
      "executables" => [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", File.join(directory, "executables.json")],
      "native_boundary_scan" => [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output",
                                 File.join(directory, "native-boundary-scan.json")],
      "rbs_validate" => ["bundle", "exec", "rbs", "-I", "sig", "-I", "generated/rbs", "validate"],
      "kernel_probe_x86_64" => [RbConfig.ruby, "-I#{File.join(ROOT, "build/ext/rubernetes_linux")}", "tools/milestones/m0_kernel_probe.rb",
                                "--output", File.join(directory, "abi-probe-x86_64.json")]
    }
    test_entries = source_entries.select { |entry| entry.fetch("path").match?(%r{\Atest/.*_test\.rb\z}) }
    test_inventory_content = test_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    tool_paths = {
      "gem_build" => "rubernetes.gemspec", "rake_test" => "Gemfile",
      "executables" => "tools/milestones/executables_probe.rb",
      "native_boundary_scan" => "tools/milestones/native_boundary_scan.rb",
      "rbs_validate" => "Gemfile", "kernel_probe_x86_64" => "tools/milestones/m0_kernel_probe.rb"
    }
    values.map do |name, command|
      environment = if name == "rake_test"
                      {
                        "RUBERNETES_JUNIT" => File.join(directory, "junit.xml"),
                        "RUBERNETES_JUNIT_COMMAND_SHA256" => Digest::SHA256.hexdigest(JSON.generate(command)),
                        "RUBERNETES_JUNIT_TEST_PATTERN" => "test/**/*_test.rb",
                        "RUBERNETES_JUNIT_TEST_INVENTORY_SHA256" => Digest::SHA256.hexdigest(test_inventory_content),
                        "RUBERNETES_JUNIT_TEST_INVENTORY_COUNT" => test_entries.length.to_s
                      }
                    else
                      {}
                    end
      tool = tool_paths.fetch(name)
      {"name" => name, "command" => command, "started_at" => timestamp, "finished_at" => timestamp, "exit_status" => 0,
       "stdout" => if name == "rake_test"
                     "#{self.class.authoritative_minitest_inventory.fetch("testcase_count")} runs, 0 assertions, 0 failures, 0 errors, 0 skips\n"
                   elsif name == "gem_build"
                     "  Successfully built RubyGem\n  Name: rubernetes\n  Version: 0.1.0\n  File: rubernetes-0.1.0.gem\n"
                   else
                     ""
                   end,
       "stderr" => "", "environment" => environment, "tool_path" => tool,
       "tool_sha256" => Digest::SHA256.file(File.join(ROOT, tool)).hexdigest}
    end
  end

  def write_subjects(directory)
    source_paths = EXECUTABLES.map { |name| "exe/#{name}" }
    source_paths.push("generated/platform/linux/abi/x86_64.json", "build/ext/rubernetes_linux/rubernetes_linux.so",
                      "build/rubernetes-0.1.0.gem")
    source_paths.map do |source_path|
      source = source_path == "build/rubernetes-0.1.0.gem" ? self.class.current_gem_path : File.join(ROOT, source_path)
      basename = source_path == "build/rubernetes-0.1.0.gem" ? "rubernetes-0.1.0.gem" : File.basename(source_path)
      relative = "subjects/#{basename}"
      FileUtils.mkdir_p(File.join(directory, "subjects"))
      FileUtils.cp(source, File.join(directory, relative))
      evidence_entry(directory, relative).merge("source_path" => source_path)
    end
  end

  def executable_report(subjects, timestamp, directory)
    subject_index = subjects.to_h { |subject| [subject.fetch("source_path"), subject] }
    results = EXECUTABLES.product(%w[--help --version]).map do |executable, option|
      {
        "executable" => executable,
        "option" => option,
        "command" => [RbConfig.ruby, "-I#{ROOT}/lib", "#{ROOT}/exe/#{executable}", "--config", "/unreadable/m0-side-effect-sentinel",
                      option],
        "started_at" => timestamp,
        "finished_at" => timestamp,
        "exit_status" => 0,
        "stdout" => "#{executable} output\n",
        "stderr" => "",
        "binary_sha256" => subject_index.fetch("exe/#{executable}").fetch("sha256"),
        "passed" => true
      }
    end
    {"schema_version" => 1, "kind" => "m0_executables",
     "command" => [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", File.join(directory, "executables.json")],
     "output_path" => File.join(directory, "executables.json"),
     "tool_path" => "tools/milestones/executables_probe.rb",
     "tool_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/executables_probe.rb")).hexdigest,
     "started_at" => timestamp, "finished_at" => timestamp,
     "host" => {"sysname" => Etc.uname[:sysname], "release" => Etc.uname[:release], "machine" => Etc.uname[:machine], "ruby" => RUBY_DESCRIPTION},
     "count" => results.length, "failure_count" => 0, "results" => results}
  end

  def abi_probe(input_sha256, timestamp, subjects, directory)
    abi_subject = subjects.find { |entry| entry.fetch("source_path") == "generated/platform/linux/abi/x86_64.json" }
    native_subject = subjects.find { |entry| entry.fetch("source_path") == "build/ext/rubernetes_linux/rubernetes_linux.so" }
    native_sources = current_source_entries.select { |entry| entry.fetch("path").match?(%r{\Aext/rubernetes_linux/.*\.(?:c|cc|h|rb)\z}) }
    native_content = native_sources.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    results = PROBES.map do |name|
      result = if name == "abi_manifest"
                 {"manifest" => "generated/platform/linux/abi/x86_64.json", "manifest_sha256" => abi_subject.fetch("sha256"),
                  "manifest_bytes" => abi_subject.fetch("bytes"), "mismatch_count" => 0}
               elsif name == "clone3_pid_namespace_mount_proc_pidfd_wait"
                 {"pid" => 1234, "pidfd" => 9, "exit_status" => 0, "ps_pids" => [1], "ps_output" => "  1 ps\n"}
               elsif name == "netlink_ack"
                 {"sequence" => 60_000, "message_types" => [16]}
               elsif name == "bpf_verifier"
                 {"fd" => 5, "verifier_log" => "processed 2 insns"}
               elsif name == "kvm_capability"
                 {"api_version" => 12, "capabilities" => {"3" => 1, "9" => 64}}
               elsif name == "source_input_stability"
                 {"sha256" => input_sha256, "file_count" => current_source_entries.length}
               elsif ERRNO.key?(name)
                 operation, resource_id = ERRNO.fetch(name)
                 {"errno" => 22, "errno_name" => "EINVAL", "operation" => operation, "resource_id" => resource_id,
                  "details" => {}, "message" => "Invalid argument - #{operation}; resource=#{resource_id}"}
               else
                 {"observed" => true}
               end
      {"name" => name, "started_at" => timestamp, "finished_at" => timestamp, "passed" => true, "result" => result}
    end
    {
      "schema_version" => 2, "kind" => "m0_abi_probe", "architecture" => "x86_64",
      "input_sha256" => input_sha256, "input_file_count" => current_source_entries.length, "input_stable" => true,
      "command" => [RbConfig.ruby, "-I#{File.join(ROOT, "build/ext/rubernetes_linux")}", "tools/milestones/m0_kernel_probe.rb", "--output",
                    File.join(directory, "abi-probe-x86_64.json")],
      "output_path" => File.join(directory, "abi-probe-x86_64.json"),
      "tool_path" => "tools/milestones/m0_kernel_probe.rb",
      "tool_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/m0_kernel_probe.rb")).hexdigest,
      "started_at" => timestamp, "finished_at" => timestamp, "probe_count" => results.length,
      "host" => {"sysname" => Etc.uname[:sysname], "release" => Etc.uname[:release], "machine" => Etc.uname[:machine], "ruby" => RUBY_DESCRIPTION},
      "native_extension" => {"path" => "build/ext/rubernetes_linux/rubernetes_linux.so", "loaded_feature" => "build/ext/rubernetes_linux/rubernetes_linux.so",
                             "sha256" => native_subject.fetch("sha256"), "bytes" => native_subject.fetch("bytes"),
                             "source_sha256" => Digest::SHA256.hexdigest(native_content), "source_file_count" => native_sources.length,
                             "source_files" => native_sources},
      "failure_count" => 0, "results" => results
    }
  end

  def rewrite_json_artifact(manifest_path, name)
    directory = File.dirname(manifest_path)
    path = File.join(directory, name)
    document = JSON.parse(File.read(path))
    yield(document)
    File.write(path, JSON.pretty_generate(document) << "\n")
    manifest = JSON.parse(File.read(manifest_path))
    artifact = manifest.fetch("artifacts").find { |entry| entry.fetch("path") == name }
    artifact.replace(evidence_entry(directory, name))
    File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
  end

  def write_json(directory, name, document)
    File.write(File.join(directory, name), JSON.pretty_generate(document) << "\n")
  end

  def evidence_entry(directory, relative)
    path = File.join(directory, relative)
    {"path" => relative, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
  end

  def run_gate(manifest_path)
    Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m0_gate.rb"), manifest_path, chdir: ROOT)
  end

  def current_source_entries
    paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
      relative = path.delete_prefix("#{ROOT}/")
      next false if M0SourceInventory.excluded?(relative)

      # Another test's scratch (excluded above) can vanish between glob and lstat.
      begin
        File.lstat(path).file?
      rescue Errno::ENOENT
        false
      end
    end.sort
    paths.map do |path|
      {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
  end
end
