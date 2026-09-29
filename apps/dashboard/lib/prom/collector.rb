# frozen_string_literal: true

require_relative "scraper"
require_relative "targets"
require_relative "../tsdb/store"
require_relative "../promql/engine"

module Prom
  # The long-running loop: discover targets, scrape them every interval,
  # evaluate rules, cut blocks and apply retention.  One instance per
  # process; the web server reads from the same Tsdb::Store (its head is
  # in this process), exactly like a Prometheus server.
  class Collector
    attr_reader :store, :scraper, :engine, :rules, :interval_seconds, :last_round_at, :discovery_error

    def initialize(store:, targets:, scraper: nil, engine: nil, rules: nil, interval_seconds: 15.0,
                   evaluation_interval_seconds: nil, logger: nil, clock: -> { (Time.now.to_f * 1000).to_i })
      @store = store
      @targets = targets
      @scraper = scraper || Scraper.new(store, logger: logger, clock: clock)
      @engine = engine || Promql::Engine.new(store)
      @rules = rules
      @interval_seconds = interval_seconds.to_f
      @evaluation_interval_seconds = (evaluation_interval_seconds || interval_seconds).to_f
      @logger = logger
      @clock = clock
      @thread = nil
      @stop = false
      @last_round_at = nil
      @last_evaluation_at = nil
      @discovery_error = nil
      @current_targets = []
      @mutex = Mutex.new
    end

    def targets
      @mutex.synchronize { @current_targets.dup }
    end

    # One scrape round (and rule evaluation when due).  Safe to call directly.
    def round(now_ms = @clock.call)
      round_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      discovered = begin
        found = @targets.respond_to?(:discover) ? @targets.discover : @targets.call
        @discovery_error = nil
        found
      rescue StandardError => e
        @discovery_error = "#{e.class}: #{e.message}"
        @logger&.call(:error, "discovery.failed", error: @discovery_error)
        targets
      end
      @mutex.synchronize { @current_targets = discovered }
      @scraper.scrape_all(discovered)
      if @rules && (@last_evaluation_at.nil? || now_ms - @last_evaluation_at >= @evaluation_interval_seconds * 1000 - 1)
        begin
          @rules.evaluate(@engine, now_ms)
        rescue StandardError => e
          @logger&.call(:error, "rules.failed", error: "#{e.class}: #{e.message}")
        end
        @last_evaluation_at = now_ms
      end
      @store.maintain(now_ms)
      @last_round_at = now_ms
      @scraper.statuses.values
    end

    def start
      return @thread if @thread&.alive?

      @stop = false
      @thread = Thread.new do
        Thread.current.name = "prom-collector"
        Thread.current.report_on_exception = false
        until @stop
          began = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            round
          rescue StandardError => e
            @logger&.call(:error, "collector.round_failed", error: "#{e.class}: #{e.message}")
          end
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - began
          sleep_for = [@interval_seconds - elapsed, 0.5].max
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + sleep_for
          sleep(0.25) while !@stop && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        end
      end
    end

    def stop
      @stop = true
      @thread&.join(@interval_seconds + 5)
      @thread = nil
    end

    def running? = @thread&.alive? == true
  end
end
