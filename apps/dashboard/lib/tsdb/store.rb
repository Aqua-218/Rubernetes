# frozen_string_literal: true

require "sqlite3"
require "json"
require "digest"
require "fileutils"
require "monitor"
require_relative "../prom/gorilla"

module Tsdb
  # A Prometheus-shaped time-series store: a label index in SQLite, samples
  # in Gorilla-compressed chunks, an in-memory head backed by a write-ahead
  # log, and blocks cut from the head on a fixed range with time-based
  # retention.
  #
  # Layout under +dir+:
  #   index.sqlite            series, labels, blocks, chunks
  #   wal/<n>.wal             head samples since the last block cut
  #   blocks/<id>.chunks      concatenated chunk bytes referenced by `chunks`
  #
  # One process appends (the scraper); any number of processes may read the
  # index and blocks.  The head (the last <= block_range of samples) lives in
  # the appending process, so queries run in that process too -- as they do
  # in Prometheus.
  class Store
    include MonitorMixin

    STALE_NAN_BITS = 0x7ff0000000000002
    STALE_NAN = [STALE_NAN_BITS].pack("Q>").unpack1("G")
    DEFAULT_BLOCK_RANGE_MS = 2 * 60 * 60 * 1000
    DEFAULT_RETENTION_MS = 15 * 24 * 60 * 60 * 1000
    MAX_CHUNK_SAMPLES = 120

    Series = Struct.new(:id, :metric, :labels, keyword_init: true)
    Matcher = Struct.new(:name, :op, :value, keyword_init: true) do
      def match?(actual)
        actual = actual.to_s
        case op
        when "=" then actual == value
        when "!=" then actual != value
        when "=~" then anchored.match?(actual)
        when "!~" then !anchored.match?(actual)
        else raise ArgumentError, "unknown matcher #{op}"
        end
      end

      def anchored
        @anchored ||= Regexp.new("\\A(?:#{value})\\z")
      end
    end

    # Closed head chunk with the bounds needed for block cutting, so nothing
    # has to be decoded to know what a chunk covers.
    ClosedChunk = Struct.new(:bytes, :min_time, :max_time, :count)

    class HeadSeries
      attr_reader :id, :labels, :chunks, :encoder
      attr_accessor :last_time, :last_value

      def initialize(id, labels)
        @id = id
        @labels = labels
        @chunks = [] # ClosedChunk list not yet cut into a block
        @encoder = nil
        @last_time = nil
        @last_value = nil
      end

      def append(timestamp, value)
        close_encoder if @encoder && @encoder.count >= MAX_CHUNK_SAMPLES
        @encoder ||= Prom::Gorilla::Encoder.new
        @encoder.append(timestamp, value)
        @last_time = timestamp
        @last_value = value
      end

      def close_encoder
        return if @encoder.nil?

        @chunks << ClosedChunk.new(@encoder.bytes, @encoder.min_time, @encoder.max_time, @encoder.count)
        @encoder = nil
      end

      def samples
        list = @chunks.flat_map { |chunk| Prom::Gorilla.decode(chunk.bytes) }
        list.concat(Prom::Gorilla.decode(@encoder.bytes)) if @encoder
        list
      end

      # Oldest sample time held in the head, without decoding anything.
      def min_time
        @chunks.first ? @chunks.first.min_time : @encoder&.min_time
      end

      def empty? = @chunks.empty? && @encoder.nil?
    end

    attr_reader :dir, :block_range_ms, :retention_ms

    class AlreadyOpen < StandardError; end

    OPEN_WRITERS = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache)
    OPEN_WRITERS_LOCK = Mutex.new

    def self.stale_marker?(value)
      value.is_a?(Float) && value.nan? && [value].pack("G").unpack1("Q>") == STALE_NAN_BITS
    end

    # One writer per directory per process (the head must be unique or two
    # instances treat each other's series as orphans); any number of
    # `readonly: true` readers, which never touch the WAL or the index.
    def initialize(dir, block_range_ms: DEFAULT_BLOCK_RANGE_MS, retention_ms: DEFAULT_RETENTION_MS, readonly: false)
      super()
      @dir = File.expand_path(dir)
      @block_range_ms = Integer(block_range_ms)
      @retention_ms = Integer(retention_ms)
      @readonly = readonly
      FileUtils.mkdir_p(File.join(@dir, "wal"))
      FileUtils.mkdir_p(File.join(@dir, "blocks"))
      unless @readonly
        OPEN_WRITERS_LOCK.synchronize do
          raise AlreadyOpen, "a Tsdb::Store is already writing #{@dir} in this process" if OPEN_WRITERS[@dir]

          OPEN_WRITERS[@dir] = self
        end
        begin
          acquire_writer_lock
        rescue StandardError
          OPEN_WRITERS_LOCK.synchronize { OPEN_WRITERS.delete(@dir) }
          raise
        end
      end
      @db = SQLite3::Database.new(File.join(@dir, "index.sqlite"))
      @db.busy_timeout = 10_000
      @db.execute("PRAGMA journal_mode=WAL")
      @db.execute("PRAGMA synchronous=NORMAL")
      create_schema
      repair_binary_text unless @readonly
      @series_by_fingerprint = {}
      @head = {}
      @wal = nil
      @wal_path = nil
      replay_wal
      return if @readonly

      remove_unreferenced_blocks
      open_wal
    end

    def readonly? = @readonly

    # ------------------------------------------------------------- writing

    # Append one sample.  Labels must include "__name__".
    def append(labels, timestamp_ms, value)
      raise AlreadyOpen, "read-only store" if @readonly

      synchronize do
        series = head_series_for(labels)
        return false if series.last_time && timestamp_ms <= series.last_time

        series.append(timestamp_ms, value)
        wal_write_sample(series.id, timestamp_ms, value)
        true
      end
    end

    # Append many samples and fsync the WAL once: [[labels, t, v], ...].
    def append_batch(rows)
      raise AlreadyOpen, "read-only store" if @readonly

      appended = 0
      synchronize do
        rows.each do |labels, timestamp_ms, value|
          series = head_series_for(labels)
          next if series.last_time && timestamp_ms <= series.last_time

          series.append(timestamp_ms, value)
          wal_write_sample(series.id, timestamp_ms, value)
          appended += 1
        end
        @wal.flush
      end
      appended
    end

    # Cut the head into a block when it has crossed a block boundary, then
    # apply retention.  Call after each scrape; cheap when nothing is due.
    def maintain(now_ms = current_ms)
      return if @readonly

      synchronize do
        # Block cuts happen at most once per block range; between them the
        # scan of the head is skipped entirely.
        if @next_cut_check.nil? || now_ms >= @next_cut_check
          oldest = @head.values.filter_map(&:min_time).min
          if oldest && now_ms - oldest >= @block_range_ms
            cut_head(now_ms)
          else
            @next_cut_check = oldest ? oldest + @block_range_ms : now_ms + 60_000
          end
        end
        if @next_retention_check.nil? || now_ms >= @next_retention_check
          apply_retention(now_ms)
          @next_retention_check = now_ms + 60_000
        end
      end
    end

    # Force every head sample into a block (shutdown, tests).
    def flush
      return if @readonly

      synchronize { cut_head(current_ms, all: true) }
    end

    def close
      synchronize do
        @wal&.close
        @db.close
        unless @readonly
          OPEN_WRITERS_LOCK.synchronize { OPEN_WRITERS.delete(@dir) if OPEN_WRITERS[@dir].equal?(self) }
          @lock_file&.close
          @lock_file = nil
        end
      end
    end

    # One writer per directory across processes, like Prometheus' data lock:
    # a second writer (a stray `rails test` or runner against the live data
    # directory) would treat the first's head series as orphans and delete
    # them.  The lock is an flock on <dir>/lock, released when the process
    # exits, so a crash never leaves the directory unwritable.
    def acquire_writer_lock
      @lock_file = File.open(File.join(@dir, "lock"), File::RDWR | File::CREAT, 0o644)
      if @lock_file.flock(File::LOCK_EX | File::LOCK_NB)
        @lock_file.truncate(0)
        @lock_file.write(Process.pid.to_s)
        @lock_file.flush
        return
      end

      owner = @lock_file.read.strip
      @lock_file.close
      @lock_file = nil
      raise AlreadyOpen, "#{@dir} is being written by another process#{" (pid #{owner})" unless owner.empty?}"
    end

    # ------------------------------------------------------------- reading

    # Series whose labels satisfy every matcher.  At least one matcher must
    # be an equality or a non-empty regex so the label index bounds the scan.
    def select_series(matchers)
      matchers = Array(matchers)
      raise ArgumentError, "at least one matcher is required" if matchers.empty?

      candidates = candidate_series_ids(matchers)
      return [] if candidates.empty?

      rows = candidates.each_slice(500).flat_map do |slice|
        placeholders = Array.new(slice.length, "?").join(",")
        @db.execute("SELECT id, metric, labels FROM series WHERE id IN (#{placeholders})", slice)
      end
      rows.filter_map do |id, metric, labels_json|
        labels = JSON.parse(labels_json)
        next unless matchers.all? { |matcher| matcher.match?(labels.fetch(matcher.name, "")) }

        Series.new(id: id, metric: metric, labels: labels)
      end
    end

    # Samples of one series inside [min_t, max_t], oldest first.
    def samples(series_id, min_t, max_t)
      list = []
      synchronize do
        rows = @db.execute("SELECT b.path, c.offset, c.length FROM chunks c JOIN blocks b ON b.id = c.block_id " \
                           "WHERE c.series_id = ? AND c.max_t >= ? AND c.min_t <= ? ORDER BY c.min_t", [series_id, min_t, max_t])
        rows.each do |path, offset, length|
          bytes = File.binread(File.join(@dir, "blocks", path), length, offset)
          list.concat(Prom::Gorilla.decode(bytes))
        end
        head = @head[series_id]
        list.concat(head.samples) if head
      end
      list.select { |t, _| t.between?(min_t, max_t) }
    end

    # [series, samples] pairs for every series matching +matchers+ that has
    # at least one sample in the range.
    def query(matchers, min_t, max_t)
      select_series(matchers).filter_map do |series|
        points = samples(series.id, min_t, max_t)
        next if points.empty?

        [series, points]
      end
    end

    def label_names(matchers = [])
      if matchers.empty?
        @db.execute("SELECT DISTINCT name FROM labels ORDER BY name").flatten
      else
        select_series(matchers).flat_map { |series| series.labels.keys }.uniq.sort
      end
    end

    def label_values(name, matchers = [])
      if matchers.empty?
        @db.execute("SELECT DISTINCT value FROM labels WHERE name = ? ORDER BY value", [name]).flatten
      else
        select_series(matchers).filter_map { |series| series.labels[name] }.uniq.sort
      end
    end

    def series_count
      @db.get_first_value("SELECT COUNT(*) FROM series")
    end

    def head_series_count
      synchronize { @head.length }
    end

    def blocks
      @db.execute("SELECT id, min_t, max_t, path, created_at FROM blocks ORDER BY min_t").map do |id, min_t, max_t, path, created|
        {"id" => id, "min_t" => min_t, "max_t" => max_t, "path" => path, "created_at" => created}
      end
    end

    def stats
      synchronize do
        {"series" => series_count, "head_series" => @head.length, "blocks" => blocks.length,
         "head_chunks" => @head.values.sum { |s| s.chunks.length + (s.encoder ? 1 : 0) },
         "wal_bytes" => (@wal_path && File.exist?(@wal_path) ? File.size(@wal_path) : 0),
         "block_bytes" => Dir.glob(File.join(@dir, "blocks", "*.chunks")).sum { |f| File.size(f) }}
      end
    end

    private

    def current_ms
      (Time.now.to_f * 1000).to_i
    end

    def create_schema
      @db.execute_batch(<<~SQL)
        CREATE TABLE IF NOT EXISTS series (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          fingerprint TEXT NOT NULL UNIQUE,
          metric TEXT NOT NULL,
          labels TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS labels (
          series_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS labels_name_value ON labels(name, value, series_id);
        CREATE INDEX IF NOT EXISTS labels_series ON labels(series_id);
        CREATE TABLE IF NOT EXISTS blocks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          min_t INTEGER NOT NULL,
          max_t INTEGER NOT NULL,
          path TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chunks (
          series_id INTEGER NOT NULL,
          block_id INTEGER NOT NULL,
          min_t INTEGER NOT NULL,
          max_t INTEGER NOT NULL,
          count INTEGER NOT NULL,
          offset INTEGER NOT NULL,
          length INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS chunks_series_time ON chunks(series_id, min_t, max_t);
        CREATE INDEX IF NOT EXISTS chunks_block ON chunks(block_id);
      SQL
    end

    # SQLite stores a binary-encoded Ruby string as a BLOB, and a BLOB never
    # equals the TEXT a query binds: series appended from an HTTP body (which
    # Net::HTTP hands over as ASCII-8BIT) would be invisible to every
    # matcher.  The exposition format is UTF-8, so label text is made UTF-8
    # here (invalid bytes are replaced rather than raised on).
    def text(value)
      string = value.to_s
      return string if string.encoding == Encoding::UTF_8 && string.valid_encoding?

      utf8 = string.dup.force_encoding(Encoding::UTF_8)
      utf8.valid_encoding? ? utf8 : string.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "\uFFFD")
    end

    # Index rows written before #text existed are BLOBs; cast them once.
    def repair_binary_text
      blobs = @db.get_first_value("SELECT COUNT(*) FROM labels WHERE typeof(value) = 'blob' OR typeof(name) = 'blob'")
      metrics = @db.get_first_value("SELECT COUNT(*) FROM series WHERE typeof(metric) = 'blob' OR typeof(labels) = 'blob'")
      return if blobs.zero? && metrics.zero?

      @db.transaction do
        @db.execute("UPDATE labels SET name = CAST(name AS TEXT), value = CAST(value AS TEXT) WHERE typeof(value) = 'blob' OR typeof(name) = 'blob'")
        @db.execute("UPDATE series SET metric = CAST(metric AS TEXT), labels = CAST(labels AS TEXT) WHERE typeof(metric) = 'blob' OR typeof(labels) = 'blob'")
      end
    end

    def fingerprint(labels)
      Digest::SHA256.hexdigest(labels.sort.map { |k, v| "#{k}\u0000#{v}" }.join("\u0001"))[0, 32]
    end

    def head_series_for(labels)
      labels = labels.to_h { |k, v| [text(k), text(v)] }
      metric = labels.fetch("__name__") { raise ArgumentError, "labels need __name__" }
      key = fingerprint(labels)
      id = @series_by_fingerprint[key]
      if id.nil?
        id = @db.get_first_value("SELECT id FROM series WHERE fingerprint = ?", [key])
        if id.nil?
          @db.transaction do
            @db.execute("INSERT INTO series (fingerprint, metric, labels) VALUES (?, ?, ?)", [key, metric, JSON.generate(labels)])
            id = @db.last_insert_row_id
            labels.each { |name, value| @db.execute("INSERT INTO labels (series_id, name, value) VALUES (?, ?, ?)", [id, name, value]) }
          end
        end
        @series_by_fingerprint[key] = id
      end
      @head[id] ||= HeadSeries.new(id, labels)
    end

    # ------------------------------------------------------------------ WAL
    #
    # Records: "S" + id(Q>) + t(q>) + v(G).  Series creation needs no record:
    # labels are already durable in the index when a sample is written.

    def open_wal
      @wal_path = File.join(@dir, "wal", "head.wal")
      @wal = File.open(@wal_path, "ab")
      @wal.binmode
      @wal.sync = false
    end

    def wal_write_sample(id, timestamp, value)
      @wal.write(["S", id, timestamp, value].pack("aQ>q>G"))
    end

    def replay_wal
      path = File.join(@dir, "wal", "head.wal")
      return unless File.file?(path)

      labels_by_id = {}
      File.open(path, "rb") do |io|
        until io.eof?
          record = io.read(25)
          break if record.nil? || record.bytesize < 25

          tag, id, timestamp, value = record.unpack("aQ>q>G")
          next unless tag == "S"

          labels = labels_by_id[id] ||= begin
            json = @db.get_first_value("SELECT labels FROM series WHERE id = ?", [id])
            json && JSON.parse(json)
          end
          next unless labels

          series = (@head[id] ||= HeadSeries.new(id, labels))
          @series_by_fingerprint[fingerprint(labels)] = id
          next if series.last_time && timestamp <= series.last_time

          series.append(timestamp, value)
        end
      end
    end

    # ---------------------------------------------------------------- blocks

    def cut_head(now_ms, all: false)
      boundary = all ? now_ms + 1 : now_ms - (now_ms % @block_range_ms)
      pending = []
      @head.each_value do |series|
        chunks = []
        remaining = []
        series.chunks.each do |chunk|
          if chunk.max_time < boundary
            chunks << [chunk.bytes, chunk.min_time, chunk.max_time, chunk.count]
          else
            remaining << chunk
          end
        end
        if series.encoder && (all || series.encoder.max_time < boundary)
          encoder = series.encoder
          chunks << [encoder.bytes, encoder.min_time, encoder.max_time, encoder.count]
          series.instance_variable_set(:@encoder, nil)
        end
        series.chunks.replace(remaining)
        pending << [series.id, chunks] unless chunks.empty?
      end
      return if pending.empty?

      min_t = pending.flat_map { |_, chunks| chunks.map { |c| c[1] } }.min
      max_t = pending.flat_map { |_, chunks| chunks.map { |c| c[2] } }.max
      path = format("%016x-%06x.chunks", min_t, rand(0xFFFFFF))
      offset = 0
      rows = []
      File.open(File.join(@dir, "blocks", path), "wb") do |io|
        pending.each do |series_id, chunks|
          chunks.each do |bytes, cmin, cmax, count|
            io.write(bytes)
            rows << [series_id, cmin, cmax, count, offset, bytes.bytesize]
            offset += bytes.bytesize
          end
        end
        io.fsync
      end
      @db.transaction do
        @db.execute("INSERT INTO blocks (min_t, max_t, path, created_at) VALUES (?, ?, ?, ?)", [min_t, max_t, path, now_ms])
        block_id = @db.last_insert_row_id
        rows.each do |series_id, cmin, cmax, count, off, len|
          @db.execute("INSERT INTO chunks (series_id, block_id, min_t, max_t, count, offset, length) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      [series_id, block_id, cmin, cmax, count, off, len])
        end
      end
      # Head series that are now empty leave the head; everything they had
      # is durable in the block, so the WAL can be rewritten without them.
      @head.delete_if { |_, series| series.empty? }
      @next_cut_check = nil
      rewrite_wal
    end

    def rewrite_wal
      @wal&.close
      tmp = "#{@wal_path}.tmp"
      File.open(tmp, "wb") do |io|
        @head.each_value do |series|
          series.samples.each { |t, v| io.write(["S", series.id, t, v].pack("aQ>q>G")) }
        end
        io.fsync
      end
      File.rename(tmp, @wal_path)
      open_wal
    end

    # A block file whose index rows never landed (a crash between the file
    # write and the transaction) is garbage; it can never be read.
    def remove_unreferenced_blocks
      known = @db.execute("SELECT path FROM blocks").flatten
      Dir.glob(File.join(@dir, "blocks", "*.chunks")).each do |file|
        FileUtils.rm_f(file) unless known.include?(File.basename(file))
      end
    end

    def apply_retention(now_ms)
      cutoff = now_ms - @retention_ms
      expired = @db.execute("SELECT id, path FROM blocks WHERE max_t < ?", [cutoff])
      return if expired.empty?

      @db.transaction do
        expired.each do |id, path|
          @db.execute("DELETE FROM chunks WHERE block_id = ?", [id])
          @db.execute("DELETE FROM blocks WHERE id = ?", [id])
          FileUtils.rm_f(File.join(@dir, "blocks", path))
        end
        head_ids = @head.keys
        orphans = @db.execute("SELECT s.id FROM series s WHERE NOT EXISTS (SELECT 1 FROM chunks c WHERE c.series_id = s.id)").flatten - head_ids
        orphans.each_slice(500) do |slice|
          placeholders = Array.new(slice.length, "?").join(",")
          @db.execute("DELETE FROM labels WHERE series_id IN (#{placeholders})", slice)
          @db.execute("DELETE FROM series WHERE id IN (#{placeholders})", slice)
        end
        orphans.each { |id| @series_by_fingerprint.delete_if { |_, sid| sid == id } }
      end
    end

    # ------------------------------------------------------------ selection

    def candidate_series_ids(matchers)
      # The most selective equality matcher bounds the candidate set; a
      # positive regex on a bounded label does too.  Negative matchers only
      # filter.
      bounding = matchers.select { |m| m.op == "=" && !m.value.empty? }
      if bounding.empty?
        bounding = matchers.select { |m| m.op == "=~" && !m.value.empty? && !m.value.match?(/\A\.[*+]\z/) }
        if bounding.empty?
          # Unbounded: every series (PromQL requires a non-empty matcher, the
          # API layer enforces it; here we honour the caller).
          return @db.execute("SELECT id FROM series").flatten
        end

        matcher = bounding.first
        values = @db.execute("SELECT DISTINCT value FROM labels WHERE name = ?", [matcher.name]).flatten.grep(matcher)
        return [] if values.empty?

        return values.each_slice(400).flat_map do |slice|
          placeholders = Array.new(slice.length, "?").join(",")
          @db.execute("SELECT series_id FROM labels WHERE name = ? AND value IN (#{placeholders})", [matcher.name, *slice]).flatten
        end.uniq
      end
      sets = bounding.map do |matcher|
        @db.execute("SELECT series_id FROM labels WHERE name = ? AND value = ?", [matcher.name, matcher.value]).flatten
      end
      sets.sort_by(&:length).reduce { |acc, ids| acc & ids }
    end
  end
end
