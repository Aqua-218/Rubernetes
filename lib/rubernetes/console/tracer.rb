# frozen_string_literal: true

require_relative "inspector"

module Rubernetes
  module Console
    # Calls of one method of the running process, reported as they return:
    # arguments, result and how long it took.  The trace is attached to that
    # method alone (TracePoint#enable(target:)) for as long as it is watched,
    # so nothing else in the process pays for it, and nothing was built into
    # the process beforehand to make it possible.
    module Tracer
      class Error < StandardError; end

      PARAMETERS = %i[req opt key keyreq].freeze
      STACK = :rubernetes_console_trace

      module_function

      # "Rubernetes::Scheduler::Framework#schedule" is an instance method,
      # "Rubernetes::Cluster.load_path_arguments" a method of the module.
      def resolve(target)
        owner, separator, name = target.to_s.rpartition(/[#.]/)
        raise Error, "name the method as Some::Class#method or Some::Module.method" if owner.empty? || name.empty?

        constant = Object.const_get(owner)
        separator == "#" ? constant.instance_method(name) : constant.method(name)
      rescue NameError => error
        raise Error, error.message
      end

      # Yields one Hash per finished call until `seconds` have passed or
      # `limit` calls were reported; returns the number of calls.
      def watch(target, seconds:, limit:)
        method = resolve(target)
        calls = Queue.new
        trace = TracePoint.new(:call, :return) { |point| observe(point, calls) }
        trace.enable(target: method)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
        reported = 0
        while reported < limit && (remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)).positive?
          call = calls.pop(timeout: remaining) or break
          yield(call)
          reported += 1
        end
        reported
      ensure
        trace&.disable
      end

      # The call is kept on its thread until it returns: a method may be
      # running on several threads, and may call itself.
      def observe(point, calls)
        stack = Thread.current.thread_variable_get(STACK) || Thread.current.thread_variable_set(STACK, [])
        if point.event == :call
          arguments = point.parameters.filter_map do |kind, name|
            [name.to_s, Inspector.summary(point.binding.local_variable_get(name))] if name && PARAMETERS.include?(kind)
          end
          stack << [Process.clock_gettime(Process::CLOCK_MONOTONIC), arguments.to_h]
        elsif (started, arguments = stack.pop)
          calls << {"at" => Time.now.utc.strftime("%H:%M:%S.%L"), "arguments" => arguments, "result" => Inspector.summary(point.return_value),
                    "milliseconds" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round(3),
                    "thread" => Thread.current.name || "thread-#{Thread.current.object_id}"}
        end
      end
    end
  end
end
