# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/milestones/report_output"

class MilestoneReportOutputTest < Minitest::Test
  def test_artifact_contains_exact_large_stdout_and_command_uses_only_its_reference
    Dir.mktmpdir do |directory|
      path = File.join(directory, "report.json")
      stdout = JSON.generate({"data" => "\u03bb" * (MilestoneReportOutput::EMBEDDED_LIMIT / 2)}) << "\n"
      input = File.join(directory, "input")
      File.binwrite(input, stdout)
      command, stderr, status = MilestoneReportOutput.capture(path, {}, [RbConfig.ruby, "-e", 'IO.copy_stream("input", STDOUT)'], chdir: directory)

      assert_predicate status, :success?
      assert_empty stderr
      command["name"] = "probe"
      artifact = {"path" => "report.json", "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}

      assert_equal stdout.b, File.binread(path)
      assert_operator JSON.generate(command).bytesize, :<, 256
      errors = []
      MilestoneReportOutput.validate([command], [artifact], errors)

      assert_empty errors
      %w[stdout_bytes stdout_sha256 stdout_artifact].each do |field|
        errors = []
        MilestoneReportOutput.validate([command.merge(field => nil)], [artifact], errors)

        refute_empty errors
      end
    end
  end

  def test_small_and_historical_embedded_output
    Dir.mktmpdir do |directory|
      content = "{\"ok\":true}\n"
      record, stderr, status = MilestoneReportOutput.capture(File.join(directory, "small.json"), {"VALUE" => content},
                                                             [RbConfig.ruby, "-e", 'print ENV.fetch("VALUE"); warn "details"; exit 7'], chdir: directory)

      assert_equal 7, status.exitstatus
      assert_equal "details\n", stderr
      errors = []
      MilestoneReportOutput.validate([record], [], errors)

      assert_equal({"stdout" => content}, record)
      assert_empty errors
    end
  end

  def test_missing_command_preserves_the_previous_report
    Dir.mktmpdir do |directory|
      path = File.join(directory, "report.json")
      File.write(path, "previous")
      assert_raises(Errno::ENOENT) do
        MilestoneReportOutput.capture(path, {}, [File.join(directory, "missing")], chdir: directory)
      end
      assert_equal ["report.json"], Dir.children(directory)
      assert_equal "previous", File.read(path)
    end
  end
end
