# frozen_string_literal: true

require "fileutils"
require "time"

module Rubernetes
  module Bootstrap
    class Shutdown
      Request = Data.define(:signal, :requested_at)
      SIGNAL_BYTES = {"INT" => "I".b.freeze, "TERM" => "T".b.freeze, "REQUESTED" => "R".b.freeze}.freeze
      BYTE_SIGNALS = SIGNAL_BYTES.invert.freeze

      def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @reader, @writer = IO.pipe
        @reader.binmode
        @writer.binmode
        @writer.sync = true
        @clock = clock
        @previous_handlers = {}
        @installed = false
        @closed = false
        @owner_pid = Process.pid
      end

      def install!
        raise "signal handlers are already installed" if @installed

        %w[INT TERM].each do |signal|
          @previous_handlers[signal] = Signal.trap(signal) { notify(signal) }
        end
        # SIGUSR1 dumps every thread's backtrace to stderr (the process log):
        # a control-plane process that stopped acting while its process and
        # leases look healthy is otherwise a black box.
        @previous_handlers["USR1"] = Signal.trap("USR1") { self.class.dump_threads }
        install_profiler_hook!
        @installed = true
        self
      end

      # RUBERNETES_STACKPROF=<directory>: SIGUSR2 starts a wall-clock
      # StackProf sample of the whole process; the next SIGUSR2 stops it and
      # writes <directory>/<process>-<pid>-<n>.dump (read with `stackprof`).
      # Thread dumps show where threads sit; only a sampler shows where the
      # time goes, and a Ruby control plane under load is otherwise opaque.
      # Off unless the variable is set, and harmless when the gem is absent.
      PROFILER_ENV = "RUBERNETES_STACKPROF"
      PROFILER_LIB_ENV = "RUBERNETES_STACKPROF_LIB"

      def install_profiler_hook!
        directory = ENV[PROFILER_ENV].to_s
        return if directory.empty?
        return unless self.class.load_stackprof

        @profile_runs = 0
        @previous_handlers["USR2"] = Signal.trap("USR2") { self.class.toggle_profile(directory, @profile_runs += 1) }
      end

      def self.load_stackprof
        require "stackprof"
        true
      rescue LoadError
        # Under bundler a gem outside the bundle is invisible; an explicit lib
        # directory lets a developer point at an installed copy.
        lib = ENV[PROFILER_LIB_ENV].to_s
        return false if lib.empty?

        $LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
        begin
          require "stackprof"
          true
        rescue LoadError => error
          $stderr.write("stackprof unavailable: #{error.message}\n")
          false
        end
      end

      def self.toggle_profile(directory, run)
        if StackProf.running?
          StackProf.stop
          # GC pauses are invisible to a sampler that only runs Ruby code:
          # report them alongside, with the heap size that drives their length.
          # (raw_data is only readable while the profiler is enabled.)
          gc_runs = Array(GC::Profiler.raw_data)
          gc_total = GC::Profiler.total_time
          GC::Profiler.disable
          FileUtils.mkdir_p(directory)
          path = File.join(directory, "#{File.basename($PROGRAM_NAME)}-#{Process.pid}-#{run / 2}.dump")
          StackProf.results(path)
          stat = GC.stat
          longest = gc_runs.map { |entry| entry[:GC_TIME] }.max || 0.0
          $stderr.write("stackprof: wrote #{path}; gc during sample: count=#{gc_runs.length} " \
                        "total=#{gc_total.round(3)}s longest=#{longest.round(3)}s " \
                        "(process totals: major=#{stat[:major_gc_count]} minor=#{stat[:minor_gc_count]} " \
                        "heap_live_slots=#{stat[:heap_live_slots]} old_objects=#{stat[:old_objects]} " \
                        "malloc_increase_bytes=#{stat[:malloc_increase_bytes]})\n")
          GC::Profiler.clear
        else
          GC::Profiler.enable
          # CPU mode: the profiling signal lands on the thread that is
          # running, so a multi-threaded server is attributed to the code
          # holding the GVL.  Wall mode only ever saw the idle main thread.
          mode = ENV.fetch("RUBERNETES_STACKPROF_MODE", "cpu").to_sym
          StackProf.start(mode: mode, interval: 1000, raw: true)
          $stderr.write("stackprof: sampling (#{mode}, 1 ms)\n")
        end
      rescue StandardError => error
        $stderr.write("stackprof: #{error.class}: #{error.message}\n")
      end

      def self.dump_threads(io = $stderr)
        lines = ["=== thread dump pid=#{Process.pid} at #{Time.now.utc.iso8601(3)} ==="]
        Thread.list.each do |thread|
          lines << "--- #{thread.inspect} status=#{thread.status.inspect}"
          Array(thread.backtrace).first(40).each { |frame| lines << "    #{frame}" }
        end
        io.write(lines.join("\n") << "\n")
        io.flush if io.respond_to?(:flush)
      rescue StandardError
        nil
      end

      def request!
        notify("REQUESTED")
        self
      end

      def requested?
        !@reader.wait_readable(0).nil?
      end

      def wait(timeout: nil)
        ready = @reader.wait_readable(timeout)
        return nil unless ready

        byte = @reader.read_nonblock(1)
        Request.new(signal: BYTE_SIGNALS.fetch(byte), requested_at: @clock.call)
      rescue IO::WaitReadable
        retry
      end

      def restore!
        return self unless @installed

        @previous_handlers.each { |signal, handler| Signal.trap(signal, handler) }
        @previous_handlers.clear
        @installed = false
        self
      end

      def close
        return if @closed

        restore!
        @reader.close
        @writer.close
        @closed = true
      end

      private

      # A forked child inherits both this pipe and the trap blocks that write
      # to it, and a workload signalled before it execs would otherwise report
      # its own TERM into the parent's shutdown pipe -- stopping the agent that
      # owns it.  Only the process that built the pipe may write to it.
      def notify(signal)
        return unless Process.pid == @owner_pid

        @writer.write_nonblock(SIGNAL_BYTES.fetch(signal), exception: false)
      end
    end
  end
end
