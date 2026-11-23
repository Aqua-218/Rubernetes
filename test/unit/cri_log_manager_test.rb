# frozen_string_literal: true

require "tmpdir"
require "timeout"
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

  class ConcurrentClient
    attr_reader :reopened, :listed, :lookups
    attr_accessor :on_status, :on_reopen

    def initialize(logs, ids: logs.keys)
      @logs = logs
      @ids = ids
      @reopened = Queue.new
      @listed = Queue.new
      @lookups = Queue.new
    end

    def runtime(method, request = {})
      id = request["container_id"]
      case method
      when "ListContainers"
        @listed << true
        {"containers" => @ids.map { |name| {"id" => name, "state" => "CONTAINER_RUNNING"} }}
      when "ContainerStatus"
        @lookups << id
        @on_status&.call(id)
        {"status" => {"log_path" => @logs.fetch(id), "state" => "CONTAINER_RUNNING"}}
      when "ReopenContainerLog"
        @reopened << id
        @on_reopen&.call(id, @logs.fetch(id))
        File.open(@logs.fetch(id), "a") { |file| file.write("after #{id}\n") }
        {}
      else
        raise ArgumentError, "unexpected RPC #{method}"
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

  def test_negative_limit_disables_rotation_and_zero_still_rotates
    File.write(@log, "")
    disabled = Manager.new(client: @client, max_size: -1)
    disabled.start.rotate_logs
    disabled.stop

    assert_empty @client.reopened
    Manager.new(client: @client, max_size: 0).rotate_logs

    assert_equal ["c1"], @client.reopened
  end

  def test_max_size_uses_the_kubelet_quantity_int64_conversion
    accepted = {"10Mi" => 10_485_760, "9e18" => 9_000_000_000_000_000_000, "1.5e1" => 15,
                "-1" => -1, "0" => 0, "1e4294967296" => 1}

    accepted.each { |quantity, bytes| assert_equal bytes, Manager.parse_max_size(quantity), quantity }
    ["1m", "1000m", "1.0", "0.0", "-1m", "1.5Ki", "1Ei", "10e18", "9223372036854775807", "1e9223372036854775808", " 10Mi ", nil].each do |quantity|
      assert_raises(Rubernetes::Schema::Quantity::ParseError, quantity.inspect) { Manager.parse_max_size(quantity) }
    end
  end

  def test_the_manager_rotates_at_the_configured_quantity_boundary
    manager = Manager.new(client: @client, max_size: "1Ki", clock: -> { @now })
    File.write(@log, "x" * 1023)
    manager.rotate_logs

    assert_empty @client.reopened
    File.open(@log, "a") { |file| file.write("x") }
    manager.rotate_logs

    assert_equal ["c1"], @client.reopened
    assert_equal 1024, File.size("#{@log}.20260924-030000")
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

  def test_distinct_rotations_overlap_and_never_exceed_the_worker_bound
    logs = %w[a b c].to_h { |id| [id, File.join(@dir, "#{id}.log")] }
    logs.each do |id, path|
      File.write(path, "before rotation #{id}\n")
      File.write("#{path}.20260924-020000", "older #{id}\n")
    end
    client = ConcurrentClient.new(logs)
    permits = Queue.new
    client.on_reopen = ->(*) { permits.pop }
    manager = Manager.new(client: client, max_workers: 2, max_size: 10, max_files: 3, clock: -> { @now })
    scan = Thread.new { manager.rotate_logs }
    first = Array.new(2) { Timeout.timeout(3) { client.reopened.pop } }

    assert_equal 2, first.uniq.size
    assert_empty client.reopened
    assert_predicate scan, :alive?
    permits << true
    final = Timeout.timeout(3) { client.reopened.pop }

    assert_equal logs.keys.sort, (first + [final]).sort
    permits.close

    assert scan.join(3), "synchronous scan did not finish after the workers"
    logs.each do |id, path|
      assert_equal "before rotation #{id}\n", File.read("#{path}.20260924-030000")
      assert_equal "older #{id}\n", Zlib::GzipReader.open("#{path}.20260924-020000.gz", &:read)
      assert_equal "after #{id}\n", File.read(path)
    end
  ensure
    permits&.close
    scan&.join(3)
  end

  def test_one_scan_deduplicates_ids_and_paths_and_serializes_cleanup
    File.write(@log, "original")
    client = ConcurrentClient.new({"a" => @log, "alias" => File.join(@dir, ".", "0.log")}, ids: %w[a a alias])
    release = Queue.new
    client.on_reopen = ->(*) { release.pop }
    manager = Manager.new(client: client, max_workers: 2, max_size: 0, clock: -> { @now })
    scan = Thread.new { manager.rotate_logs }
    Timeout.timeout(3) { client.reopened.pop }
    cleanup = Thread.new { manager.clean(@log) }
    Timeout.timeout(3) { Thread.pass until cleanup.status == "sleep" }

    assert_path_exists "#{@log}.20260924-030000"
    release.close

    assert scan.join(3)
    assert cleanup.join(3)

    assert_equal 2, client.lookups.size
    assert_empty client.reopened
    assert_empty entries
  ensure
    release&.close
    scan&.join(3)
    cleanup&.join(3)
  end

  def test_cleanup_prevents_a_stale_scan_from_reopening_the_removed_log
    File.write(@log, "stale")
    client = ConcurrentClient.new({"a" => @log})
    release = Queue.new
    client.on_status = ->(*) { release.pop }
    manager = Manager.new(client: client, max_workers: 2, max_size: 0)
    scan = Thread.new { manager.rotate_logs }
    Timeout.timeout(3) { client.lookups.pop }
    manager.clean(@log)
    release.close

    assert scan.join(3)

    assert_empty client.reopened
    assert_empty entries
  ensure
    release&.close
    scan&.join(3)
  end

  def test_rotations_in_the_same_second_keep_distinct_payloads_in_retention_order
    5.times do |round|
      File.write(@log, "round #{round}\n" * 3)
      @manager.rotate_logs
    end
    retained = Dir.glob("#{@log}.*").sort_by { |path| path.delete_suffix(".gz") }.map do |path|
      path.end_with?(".gz") ? Zlib::GzipReader.open(path, &:read) : File.read(path)
    end

    assert_equal [2, 3, 4].map { |round| "round #{round}\n" * 3 }, retained
  end

  def test_failed_reopen_does_not_drop_old_or_new_bytes_or_block_other_workers
    peer = File.join(@dir, "peer.log")
    File.write(@log, "before failure")
    File.write("#{@log}.20260924-020000", "existing archive")
    File.write(peer, "peer before rotation")
    client = ConcurrentClient.new({"a" => @log, "peer" => peer})
    client.on_reopen = lambda do |id, path|
      next unless id == "a"

      File.write(path, "new bytes despite a failed response")
      raise "reopen response failed"
    end
    errors = Queue.new
    manager = Manager.new(client: client, max_workers: 2, max_size: 10, max_files: 2, clock: -> { @now },
                          error_handler: ->(error, id) { errors << [id, error.message] })
    manager.rotate_logs

    assert_equal ["a", "reopen response failed"], errors.pop(true)
    assert_equal "before failure", File.read("#{@log}.20260924-030000")
    assert_equal "existing archive", File.read("#{@log}.20260924-020000")
    assert_equal "new bytes despite a failed response", File.read(@log)
    assert_equal "peer before rotation", File.read("#{peer}.20260924-030000")
    assert_equal "after peer\n", File.read(peer)
  end

  def test_shutdown_releases_the_caller_without_leaving_a_second_monitor_or_starting_queued_work
    logs = %w[a b c].to_h { |id| [id, File.join(@dir, "#{id}.log")] }
    logs.each_value { |path| File.write(path, "before") }
    client = ConcurrentClient.new(logs)
    release = Queue.new
    client.on_reopen = ->(*) { release.pop }
    manager = Manager.new(client: client, max_workers: 2, max_size: 0)
    manager.start
    2.times { Timeout.timeout(3) { client.reopened.pop } }

    assert_same manager, Timeout.timeout(3) { manager.stop }
    manager.start

    assert_equal 1, client.listed.size
    assert_empty client.reopened
    release.close

    assert_same manager, Timeout.timeout(3) { manager.stop }

    assert_empty client.reopened
    assert_equal 2, client.lookups.size
    logs.each_value { |path| assert_path_exists path }
  ensure
    release&.close
    manager&.stop
  end
end
