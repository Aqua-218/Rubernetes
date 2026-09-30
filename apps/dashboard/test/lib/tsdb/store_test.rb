# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class Tsdb::StoreTest < ActiveSupport::TestCase
  M = Tsdb::Store::Matcher

  def setup
    @dir = Dir.mktmpdir("tsdb")
  end

  def teardown
    @store&.close
    FileUtils.rm_rf(@dir)
  end

  def open_store(**)
    @store = Tsdb::Store.new(@dir, **)
  end

  def labels(name, extra = {})
    {"__name__" => name}.merge(extra)
  end

  test "appends samples and selects them back by matchers" do
    store = open_store
    t0 = 1_700_000_000_000
    10.times do |i|
      store.append(labels("up", "job" => "apiserver", "instance" => "a:1"), t0 + (i * 15_000), 1.0)
      store.append(labels("up", "job" => "apiserver", "instance" => "b:1"), t0 + (i * 15_000), i.even? ? 1.0 : 0.0)
      store.append(labels("up", "job" => "node", "instance" => "n:1"), t0 + (i * 15_000), 1.0)
    end
    result = store.query([M.new(name: "__name__", op: "=", value: "up"), M.new(name: "job", op: "=", value: "apiserver")], t0,
                         t0 + (10 * 15_000))

    assert_equal 2, result.length
    assert_equal %w[a:1 b:1], result.map { |series, _| series.labels["instance"] }.sort
    assert_equal 10, result[0][1].length
    assert_equal [t0, 1.0], result.find { |s, _| s.labels["instance"] == "a:1" }[1].first

    regex = store.query([M.new(name: "__name__", op: "=", value: "up"), M.new(name: "instance", op: "=~", value: "[ab]:1")], t0,
                        t0 + 200_000)

    assert_equal 2, regex.length
    negative = store.query([M.new(name: "__name__", op: "=", value: "up"), M.new(name: "job", op: "!=", value: "node")], t0, t0 + 200_000)

    assert_equal 2, negative.length
    window = store.samples(result[0][0].id, t0 + 30_000, t0 + 60_000)

    assert_equal [t0 + 30_000, t0 + 45_000, t0 + 60_000], window.map(&:first)
    assert_equal %w[__name__ instance job], store.label_names
    assert_equal %w[apiserver node], store.label_values("job")
    assert_equal 3, store.series_count
  end

  test "out of order and duplicate timestamps are rejected per series" do
    store = open_store

    assert store.append(labels("m"), 100, 1.0)
    refute store.append(labels("m"), 100, 2.0)
    refute store.append(labels("m"), 50, 2.0)
    assert store.append(labels("m"), 101, 2.0)
    assert_equal [[100, 1.0], [101, 2.0]],
                 store.samples(store.select_series([M.new(name: "__name__", op: "=", value: "m")]).first.id, 0, 200)
  end

  test "the head survives a restart through the WAL" do
    store = open_store
    5.times { |i| store.append(labels("m", "k" => "v"), 1000 + i, i.to_f) }
    store.close
    @store = nil
    reopened = open_store
    series = reopened.select_series([M.new(name: "__name__", op: "=", value: "m")]).first

    assert_equal 5.times.map { |i| [1000 + i, i.to_f] }, reopened.samples(series.id, 0, 2000)
    # And appending continues without duplicating the recovered series.
    reopened.append(labels("m", "k" => "v"), 1005, 5.0)

    assert_equal 1, reopened.series_count
    assert_equal 6, reopened.samples(series.id, 0, 2000).length
  end

  test "blocks are cut from the head on the block boundary and read back seamlessly" do
    store = open_store(block_range_ms: 60_000)
    t0 = 600_000
    # 130 samples one second apart: spans more than two block ranges and
    # more than one 120-sample chunk.
    130.times { |i| store.append(labels("m"), t0 + (i * 1000), i.to_f) }
    store.maintain(t0 + 130_000)

    assert_operator store.blocks.length, :>=, 1
    series = store.select_series([M.new(name: "__name__", op: "=", value: "m")]).first

    assert_equal 130.times.map { |i| [t0 + (i * 1000), i.to_f] }, store.samples(series.id, 0, t0 + 200_000)
    stats = store.stats

    assert_operator stats["block_bytes"], :>, 0
    # The WAL was rewritten with only what is still in the head.
    assert_operator stats["wal_bytes"], :<, 130 * 25
    store.flush

    assert_equal 0, store.head_series_count
    assert_equal 130, store.samples(series.id, 0, t0 + 200_000).length
  end

  test "retention drops old blocks and orphaned series" do
    store = open_store(block_range_ms: 60_000, retention_ms: 120_000)
    t0 = 0
    5.times { |i| store.append(labels("old"), t0 + (i * 1000), 1.0) }
    store.flush

    assert_equal 1, store.blocks.length
    later = 10 * 60_000
    store.append(labels("new"), later, 1.0)
    store.maintain(later)

    assert_equal 0, store.blocks.length, "the old block is past retention"
    assert_equal ["new"], store.select_series([M.new(name: "__name__", op: "=~", value: ".+")]).map(&:metric)
  end

  test "stale markers are preserved bit-exactly" do
    store = open_store
    store.append(labels("m"), 1, 1.0)
    store.append(labels("m"), 2, Tsdb::Store::STALE_NAN)
    series = store.select_series([M.new(name: "__name__", op: "=", value: "m")]).first
    values = store.samples(series.id, 0, 10).map(&:last)

    assert Tsdb::Store.stale_marker?(values[1])
    refute Tsdb::Store.stale_marker?(Float::NAN)
  end

  test "batch append is one WAL flush and reports the count" do
    store = open_store
    rows = 1000.times.map { |i| [labels("batch", "i" => (i % 10).to_s), 1_000 + ((i / 10) * 1000), i.to_f] }

    assert_equal 1000, store.append_batch(rows)
    assert_equal 10, store.series_count
    assert_equal 100, store.samples(1, 0, 10**9).length
  end

  test "readers in another process see cut blocks" do
    store = open_store(block_range_ms: 1000)
    20.times { |i| store.append(labels("shared"), i * 100, i.to_f) }
    store.flush
    assert_raises(Tsdb::Store::AlreadyOpen) { Tsdb::Store.new(@dir) }
    reader = Tsdb::Store.new(@dir, readonly: true)
    begin
      assert_predicate reader, :readonly?
      assert_raises(Tsdb::Store::AlreadyOpen) { reader.append({"__name__" => "x"}, 1, 1.0) }
      series = reader.select_series([M.new(name: "__name__", op: "=", value: "shared")]).first

      assert_equal 20, reader.samples(series.id, 0, 10_000).length
    ensure
      reader.close
    end
  end

  test "binary-encoded labels are stored as text and found by equality matchers" do
    store = open_store
    # Net::HTTP bodies are ASCII-8BIT; SQLite would keep such strings as BLOBs
    # that never equal a TEXT parameter.
    store.append({"__name__".b => "apiserver_request_total".b, "job".b => "apiserver".b, "verb" => "GET"}, 1000, 1.0)
    found = store.select_series([M.new(name: "__name__", op: "=", value: "apiserver_request_total"),
                                 M.new(name: "job", op: "=", value: "apiserver")])

    assert_equal 1, found.length
    assert_equal Encoding::UTF_8, found.first.labels["job"].encoding
    # A second append with UTF-8 strings is the same series, not a duplicate.
    store.append({"__name__" => "apiserver_request_total", "job" => "apiserver", "verb" => "GET"}, 2000, 2.0)

    assert_equal 1, store.series_count
  end

  test "an index written with BLOB labels is repaired on open" do
    store = open_store
    db = store.instance_variable_get(:@db)
    db.execute("INSERT INTO series (fingerprint, metric, labels) VALUES (?, ?, ?)",
               ["f1", "old_total".b, JSON.generate({"__name__" => "old_total"}).b])
    db.execute("INSERT INTO labels (series_id, name, value) VALUES (?, ?, ?)", [1, "__name__".b, "old_total".b])

    assert_equal "blob", db.get_first_value("SELECT typeof(value) FROM labels")
    store.close
    @store = nil
    reopened = open_store

    assert_equal ["old_total"], reopened.select_series([M.new(name: "__name__", op: "=", value: "old_total")]).map(&:metric)
    assert_equal ["old_total"], reopened.label_values("__name__")
  end

  test "a writer in another process is refused by the directory lock" do
    store = open_store
    store.append(labels("m"), 1, 1.0)
    script = <<~RUBY
      $LOAD_PATH.unshift(#{File.expand_path("../../../lib", __dir__).inspect})
      require "tsdb/store"
      begin
        Tsdb::Store.new(ARGV[0])
        puts "opened"
      rescue Tsdb::Store::AlreadyOpen => e
        puts "refused: " + e.message
      end
      puts Tsdb::Store.new(ARGV[0], readonly: true).series_count
    RUBY
    out = IO.popen([RbConfig.ruby, "-e", script, @dir], &:read)

    assert_match(/\Arefused: .*pid #{Process.pid}/, out)
    assert_match(/^1$/, out, "readers are still admitted")
    store.close
    @store = nil

    assert_equal "opened\n1\n", IO.popen([RbConfig.ruby, "-e", script, @dir], &:read)
  end
end
