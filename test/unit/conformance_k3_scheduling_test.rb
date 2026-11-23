# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/lanes"

class ConformanceK3SchedulingTest < Minitest::Test
  K3 = Conformance::Lanes::K3

  def test_serial_specs_run_after_every_ordinary_chunk_in_separate_report_directories
    Dir.mktmpdir do |dir|
      runner = File.join(dir, "suite")
      report = "<testsuites><testsuite/></testsuites>\n"
      File.write(runner, <<~SH)
        #!/bin/sh
        for arg do
          case "$arg" in --report-dir=*) report=${arg#--report-dir=} ;; esac
        done
        case "$report" in
          */chunk-002) test -s "$report/../e2e-command-000.json" && test -s "$report/../e2e-command-001.json" || exit 1 ;;
        esac
        cat >"$report/junit_01.xml" <<'XML'
        #{report.chomp}
        XML
        echo "finished"
      SH
      File.chmod(0o755, runner)
      ordinary = (1..(K3::SPECS_PER_CHUNK + 1)).map { |number| {"id" => "case #{number}", "labels" => []} }
      serial = {"id" => "independent serial case", "labels" => ["Serial"]}
      selection = nil
      chunks, executions = K3.run_required(runner, File.join(dir, "kubeconfig"), dir, [serial, *ordinary]) do |planned|
        assert_empty Dir.glob(File.join(dir, "chunk-*"))
        selection = planned
      end

      assert_equal chunks, selection
      assert_equal [K3::SPECS_PER_CHUNK, 1, 1], chunks.map(&:size)
      assert_equal [serial.fetch("id")], chunks.last
      assert_equal([0, 0, 0], executions.map { |result| result.fetch("exit_status") })
      executions.each_with_index do |execution, index|
        path = File.join(dir, format("e2e-command-%03d.json", index))

        assert_equal execution, JSON.parse(File.binread(path))
        assert_equal "finished\n", Zlib::GzipReader.open(File.join(dir, execution.fetch("stdout_artifact")), &:read)
      end
      assert_equal 3, Dir.glob(File.join(dir, "chunk-*", "junit_01.xml.gz")).length
      assert_empty Dir.glob(File.join(dir, "chunk-*", "junit_01.xml"))
      assert_equal [Digest::SHA256.hexdigest(report)], executions.map { |result| result.dig("junit_report", "xml_sha256") }.uniq
      assert_raises(Errno::EEXIST) { K3.run_required(runner, File.join(dir, "kubeconfig"), dir, [serial, *ordinary]) }
    end
  end

  def test_a_complete_failed_runner_report_is_archived_and_a_timeout_report_stays_raw
    [false, true].each do |timed_out|
      Dir.mktmpdir do |dir|
        capture = lambda do |command, **|
          report_directory = command.last.delete_prefix("--report-dir=")
          File.write(File.join(report_directory, "junit_01.xml"), "<testsuites><testsuite/></testsuites>\n")
          {"exit_status" => 1, "timed_out" => timed_out}
        end
        execution = Conformance::Lanes.stub(:capture, capture) do
          K3.run_chunks("e2e.test", "kubeconfig", dir, [["case"]]).first
        end

        assert_equal 1, execution.fetch("exit_status")
        assert_equal timed_out, execution.fetch("timed_out")
        if timed_out
          refute execution.key?("junit_report")
          assert_path_exists File.join(dir, "chunk-000", "junit_01.xml")
        else
          assert_path_exists execution.fetch("junit_report").fetch("path")
          refute_path_exists File.join(dir, "chunk-000", "junit_01.xml")
        end
      end
    end
  end
end
