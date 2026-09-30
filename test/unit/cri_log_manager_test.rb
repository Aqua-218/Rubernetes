# frozen_string_literal: true

require "tmpdir"
require "zlib"
require_relative "../test_helper"
require "rubernetes/runtime/cri"

# kubelet containerLogManager for CRI runtimes: rotation at maxSize, reopen,
# at most maxFiles - 2 rotated files kept, older ones gzipped, leftovers of an
# interrupted compression cleaned up, a failed reopen undone.
class CRILogManagerTest < Minitest::Test
  Manager = Rubernetes::Runtime::CRI::LogManager

  class Client
    attr_reader :reopened
    attr_accessor :fail_reopen

    def initialize(path) = (@path = path) && (@reopened = [])

    def runtime(method, request = {}, **)
      case method
      when "ListContainers" then {"containers" => [{"id" => "c1", "state" => "CONTAINER_RUNNING"},
                                                   {"id" => "c2", "state" => "CONTAINER_EXITED"}]}
      when "ContainerStatus" then {"status" => {"log_path" => @path}}
      when "ReopenContainerLog"
        raise "runtime refused" if fail_reopen

        @reopened << request["container_id"]
        File.write(@path, "")
        {}
      end
    end
  end

  def setup
    @dir = Dir.mktmpdir("cri-log-manager")
    @log = File.join(@dir, "0.log")
    @client = Client.new(@log)
    @now = Time.utc(2026, 9, 24, 3, 0, 0)
    @manager = Manager.new(client: @client, max_size: 10, max_files: 4, clock: -> { @now })
  end

  def teardown = FileUtils.rm_rf(@dir)

  def entries = Dir.children(@dir).sort

  def test_a_small_log_is_left_alone
    File.write(@log, "short")
    @manager.rotate_logs

    assert_equal ["0.log"], entries
    assert_empty @client.reopened
  end

  def test_rotation_compression_and_retention
    3.times do |round|
      File.write(@log, "x" * 20)
      @manager.rotate_logs
      @now += 60

      assert_equal ["c1"] * (round + 1), @client.reopened
    end
    # Pruned to max_files - 2 before each rotation, so max_files files in all.
    assert_equal ["0.log", "0.log.20260924-030000.gz", "0.log.20260924-030100.gz", "0.log.20260924-030200"], entries
    assert_equal "x" * 20, Zlib::GzipReader.open(File.join(@dir, "0.log.20260924-030100.gz"), &:read)
    File.write(@log, "x" * 20)
    @manager.rotate_logs

    assert_equal ["0.log", "0.log.20260924-030100.gz", "0.log.20260924-030200.gz", "0.log.20260924-030300"], entries, "the oldest goes"
    assert_equal "", File.read(@log), "the runtime reopened a fresh log"
  end

  def test_leftovers_are_cleaned_and_a_failed_reopen_is_undone
    File.write(File.join(@dir, "0.log.20260924-020000.tmp"), "partial")
    File.write(File.join(@dir, "0.log.20260924-020100"), "done")
    File.write(File.join(@dir, "0.log.20260924-020100.gz"), "done")
    File.write(@log, "y" * 20)
    @client.fail_reopen = true
    errors = []
    Manager.new(client: @client, max_size: 10, max_files: 5, clock: -> { @now }, error_handler: lambda { |error, _id|
      errors << error
    }).rotate_logs

    assert_equal ["0.log", "0.log.20260924-020100.gz"], entries
    assert_equal "y" * 20, File.read(@log), "the rename was undone"
    assert_equal ["runtime refused"], errors.map(&:message)
  end
end
