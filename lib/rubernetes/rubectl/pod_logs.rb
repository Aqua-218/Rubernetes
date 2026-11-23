# frozen_string_literal: true

require "date"
require "time"
require_relative "../schema/go_duration"

module Rubernetes
  module Rubectl
    # Resolve a single Pod and stream its selected container's log bytes.
    class PodLogs
      DEFAULT_CONTAINER = "kubectl.kubernetes.io/default-container"
      RFC3339 = /\A\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)\z/
      CONTAINER_GROUPS = {"containers" => nil, "ephemeralContainers" => "ephem", "initContainers" => "init"}.freeze
      MAX_TAIL = (1 << 63) - 1

      def self.add_options(parser, options)
        parser.on("-c", "--container NAME", "select a Pod container") { |value| options[:container] = value }
        parser.on("-f", "--[no-]follow[=BOOL]", TrueClass, "follow the log stream") { |value| options[:follow] = value }
        parser.on("-p", "--[no-]previous[=BOOL]", TrueClass, "read the previous instance of the container") { |value| options[:previous] = value }
        parser.on("--tail LINES", Integer, "show the last LINES lines (-1 for all)") { |value| options[:tail_lines] = value }
        parser.on("--[no-]timestamps[=BOOL]", TrueClass, "include a timestamp on each line") { |value| options[:timestamps] = value }
        parser.on("--since DURATION", "show logs newer than a duration (for example 30s or 1h30m)") { |value| options[:since] = value }
        parser.on("--since-time RFC3339", "show logs newer than a timestamp") { |value| options[:since_time] = value }
      end

      def initialize(arguments, options)
        target = arguments.first.to_s
        unless arguments.one? && target.match?(%r{\A(?:(?:pod|pods)/)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z})
          raise Client::UsageError, "logs requires one Pod name (POD or pod/POD)"
        end
        raise Client::UsageError, "logs does not accept an output format" if options[:output]

        @name = target.split("/").last
        @namespace = options[:namespace]
        @container = options[:container]
        @query = options.slice(:follow, :previous, :timestamps)
        @query[:tail_lines] = tail_lines(options[:tail_lines])
        @query[:since_time] = since_time(options[:since_time])
        @query[:since_seconds] = since_seconds(options[:since])
        raise Client::UsageError, "only one of --since-time and --since may be specified" if @query[:since_time] && @query[:since_seconds]
      end

      def write(client, stdout:, warning:)
        pod = client.get("pods", @name, namespace: @namespace)
        container = select_container(pod, warning)
        stdout.binmode
        client.pod_logs(@name, namespace: @namespace, container: container, **@query) do |chunk|
          stdout.write(chunk)
          stdout.flush
        rescue Errno::EPIPE
          # A downstream reader finished. Unwind the HTTP stream immediately.
          break
        end
      end

      private

      def select_container(pod, warning)
        containers = CONTAINER_GROUPS.flat_map do |section, suffix|
          Array(pod.dig("spec", section)).map { |entry| [entry.fetch("name"), suffix] }
        end
        names = containers.map(&:first)
        available = containers.map { |name, suffix| suffix ? "#{name} (#{suffix})" : name }.join(", ")
        if @container && !@container.empty?
          return @container if names.include?(@container)

          raise Client::UsageError, "container #{@container} is not valid for pod #{@name} out of: #{available}"
        end

        default = pod.dig("metadata", "annotations", DEFAULT_CONTAINER)
        if default && !default.empty?
          return default if names.include?(default)

          warning.call("Default container name #{default.inspect} not found in pod #{@name}")
        end

        first = pod.dig("spec", "containers", 0, "name")
        raise Client::UsageError, "pod #{@name} does not have any containers" unless first

        warning.call("Defaulted container #{first.inspect} out of: #{available}") if names.length > 1
        first
      end

      def tail_lines(value)
        return if value.nil? || value == -1
        return value if (0..MAX_TAIL).cover?(value)

        raise Client::UsageError, "--tail must be an integer between -1 and #{MAX_TAIL}"
      end

      def since_time(value)
        return if value.nil?

        if RFC3339.match?(value)
          year, month, day = value[0, 10].split("-").map(&:to_i)
          return Time.iso8601(value).utc.iso8601 if Date.valid_date?(year, month, day, Date::GREGORIAN)
        end
        raise Client::UsageError, "--since-time must be an RFC3339 timestamp with a UTC offset"
      end

      def since_seconds(value)
        return if value.nil?

        nanoseconds = Schema::GoDuration.parse(value)
        raise Client::UsageError, "--since must be non-negative" if nanoseconds.negative?

        Rational(nanoseconds, Schema::GoDuration::SECOND).round unless nanoseconds.zero?
      rescue Schema::GoDuration::ParseError
        raise Client::UsageError, "--since must be a duration such as 30s or 1h30m"
      end
    end
  end
end
