# frozen_string_literal: true

require_relative "exposition"
require_relative "../tsdb/store"

module Prom
  # Scrapes targets into a Tsdb::Store with Prometheus' ingestion rules:
  #   * every sample gets the target's `job`/`instance` and extra labels;
  #     a metric that already carries one of those keeps it as
  #     `exported_<label>` (honor_labels: false);
  #   * the synthetic series up, scrape_duration_seconds,
  #     scrape_samples_scraped, scrape_samples_post_metric_relabeling and
  #     scrape_series_added are written for every scrape, and up=0 for a
  #     failed one;
  #   * a series that a target served last time but not this time gets a
  #     stale marker, so it disappears from instant queries at once rather
  #     than lingering for the lookback delta; a failed scrape marks every
  #     series of the target stale.
  #   * exposition timestamps are ignored (as with honor_timestamps=false
  #     at scrape time they would be honoured; the components here do not
  #     emit them, and ignoring them keeps the store monotonic).
  class Scraper
    Status = Struct.new(:target, :health, :last_scrape_ms, :last_duration_seconds, :last_error, :samples, keyword_init: true)

    attr_reader :statuses

    def initialize(store, timeout_seconds: 10, clock: -> { (Time.now.to_f * 1000).to_i }, logger: nil)
      @store = store
      @timeout = timeout_seconds
      @clock = clock
      @logger = logger
      @previous = {}   # target key -> { fingerprint => labels }
      @statuses = {}   # target key -> Status
      @metadata = {}   # metric family name -> [{"type","help","unit"}]
      @mutex = Mutex.new
    end

    # /api/v1/metadata: family type and help as last served by any target.
    def metadata
      @mutex.synchronize { @metadata.dup }
    end

    # Scrape one target now.  Returns the Status.
    def scrape(target)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      scrape_time = @clock.call
      status = 0
      body = nil
      error = nil
      begin
        Timeout.timeout(@timeout) do
          status, body = target.fetch.call
        end
        error = "server returned HTTP status #{status}" unless status.to_i == 200
      rescue Timeout::Error
        error = "context deadline exceeded (#{@timeout}s)"
      rescue StandardError => e
        error = "#{e.class}: #{e.message}"
      end
      samples = []
      if error.nil?
        begin
          samples = Exposition.samples(body.to_s)
        rescue Exposition::ParseError => e
          error = "parse error: #{e.message}"
        end
      end
      duration = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      rows = []
      seen = {}
      if error.nil?
        samples.each do |sample|
          labels = target_labels(target, sample.name, sample.labels)
          key = labels.sort.to_s
          next if seen.key?(key) # duplicate series in one scrape: first wins

          seen[key] = labels
          rows << [labels, scrape_time, sample.value]
        end
      end
      previous = @mutex.synchronize { @previous[target.key] || {} }
      previous.each_key do |key|
        next if seen.key?(key)

        rows << [previous[key], scrape_time, Tsdb::Store::STALE_NAN]
      end
      base = {"job" => target.job, "instance" => target.instance}.merge(target.labels || {})
      rows << [base.merge("__name__" => "up"), scrape_time, error.nil? ? 1.0 : 0.0]
      rows << [base.merge("__name__" => "scrape_duration_seconds"), scrape_time, duration]
      rows << [base.merge("__name__" => "scrape_samples_scraped"), scrape_time, samples.length.to_f]
      rows << [base.merge("__name__" => "scrape_samples_post_metric_relabeling"), scrape_time, seen.length.to_f]
      added = seen.keys.count { |key| !previous.key?(key) }
      rows << [base.merge("__name__" => "scrape_series_added"), scrape_time, added.to_f]
      @store.append_batch(rows)
      result = Status.new(target: target, health: error.nil? ? "up" : "down", last_scrape_ms: scrape_time,
                          last_duration_seconds: duration.round(4), last_error: error, samples: seen.length)
      @mutex.synchronize do
        @previous[target.key] = seen
        @statuses[target.key] = result
      end
      @logger&.call(:warn, "scrape.failed", job: target.job, instance: target.instance, error: error) if error
      result
    end

    # Scrape a whole target set concurrently and forget targets that are gone
    # (their series get stale markers once).
    def scrape_all(targets, concurrency: 6)
      queue = Queue.new
      targets.each { |target| queue << target }
      workers = Array.new([concurrency, targets.length, 1].min) do
        Thread.new do
          loop do
            target = begin
              queue.pop(true)
            rescue ThreadError
              break
            end
            begin
              scrape(target)
            rescue StandardError => e
              @logger&.call(:error, "scrape.crashed", job: target.job, instance: target.instance, error: "#{e.class}: #{e.message}")
            end
          end
        end
      end
      workers.each(&:join)
      retire_missing(targets)
      @statuses.values
    end

    private

    def retire_missing(targets)
      live = targets.to_h { |t| [t.key, true] }
      gone = @mutex.synchronize { @previous.keys.reject { |key| live.key?(key) } }
      return if gone.empty?

      now = @clock.call
      rows = []
      gone.each do |key|
        (@previous[key] || {}).each_value { |labels| rows << [labels, now, Tsdb::Store::STALE_NAN] }
        status = @statuses[key]
        if status
          base = {"job" => status.target.job, "instance" => status.target.instance}.merge(status.target.labels || {})
          rows << [base.merge("__name__" => "up"), now, Tsdb::Store::STALE_NAN]
        end
      end
      @store.append_batch(rows) unless rows.empty?
      @mutex.synchronize do
        gone.each do |key|
          @previous.delete(key)
          @statuses.delete(key)
        end
      end
    end

    def target_labels(target, name, metric_labels)
      labels = {"__name__" => name}
      metric_labels.each { |k, v| labels[k] = v }
      extra = {"job" => target.job, "instance" => target.instance}.merge(target.labels || {})
      extra.each do |key, value|
        next if value.nil? || value.to_s.empty?

        if labels.key?(key) && labels[key] != value
          labels["exported_#{key}"] = labels[key]
        end
        labels[key] = value.to_s
      end
      labels
    end
  end
end
