# frozen_string_literal: true

require "time"

module Rubernetes
  module Runtime
    module CRI
      # Container logs in the CRI format (kubelet pkg/kubelet/kuberuntime/logs):
      # one record per line, "<RFC3339Nano> <stdout|stderr> <P|F> <content>",
      # where P marks a partial line continued by the next record of the same
      # stream.  Read with the Pod log API's options: both streams unless one
      # is named, since a time, the last +tail+ lines, timestamps prefixed,
      # and follow (new records as the runtime appends them).
      module Logs
        Record = Struct.new(:time, :stream, :partial, :content)

        module_function

        def parse_line(line)
          time, stream, tag, content = line.chomp.split(" ", 4)
          return nil if time.nil? || !%w[stdout stderr].include?(stream)

          partial = tag == "P"
          content = content.to_s
          Record.new(time, stream, partial, partial ? content : "#{content}\n")
        end

        # Complete lines [time, stream, text] from the records, partials
        # joined to the full record that ends them (the first one's time).
        def lines(text)
          pending = {}
          result = []
          text.to_s.each_line do |raw|
            record = parse_line(raw)
            next if record.nil?

            started = pending[record.stream]
            if record.partial
              pending[record.stream] = started ? [started[0], started[1] + record.content] : [record.time, record.content]
              next
            end
            pending.delete(record.stream)
            result << [started ? started[0] : record.time, record.stream, (started ? started[1] : "") + record.content]
          end
          result
        end

        def select(entries, stream:, since:, tail:)
          wanted = stream.to_s
          entries = entries.select { |_time, name, _text| %w[all both].include?(wanted) || name == wanted } unless wanted.empty?
          if since
            limit = since.is_a?(Time) ? since : Time.parse(since.to_s)
            entries = entries.select { |time, _name, _text| Time.parse(time) >= limit }
          end
          entries = entries.last(Integer(tail)) if tail && Integer(tail) >= 0
          entries
        end

        def render(entries, timestamps:)
          entries.map { |time, _name, text| timestamps ? "#{time} #{text}" : text }.join.b
        end

        def read(path, follow: false, since: nil, tail: nil, stream: :all, timestamps: false, running: -> { false })
          text = File.exist?(path) ? File.binread(path) : "".b
          initial = render(select(lines(text), stream: stream, since: since, tail: tail), timestamps: timestamps)
          return initial unless follow

          Follow.new(path, initial, text.bytesize, stream: stream, timestamps: timestamps, running: running)
        end

        # The records appended after +offset+, until the container stops or
        # the reader closes.
        class Follow
          include Enumerable

          def initialize(path, initial, offset, stream:, timestamps:, running:, interval: 0.1)
            @path = path
            @initial = initial
            @offset = offset
            @stream = stream
            @timestamps = timestamps
            @running = running
            @interval = interval
            @closed = false
            @buffer = +""
          end

          def each
            return to_enum(:each) unless block_given?

            yield @initial unless @initial.empty?
            until @closed
              finished = !@running.call
              chunk = read_new
              yield chunk unless chunk.empty?
              break if finished

              sleep @interval
            end
            self
          end

          def close
            @closed = true
            self
          end

          def closed? = @closed

          private

          def read_new
            return "".b unless File.exist?(@path)

            size = File.size(@path)
            @offset = 0 if size < @offset
            return "".b if size == @offset

            data = File.open(@path, "rb") do |file|
              file.seek(@offset)
              file.read(size - @offset)
            end
            @offset = size
            @buffer << data
            complete, _, rest = @buffer.rpartition("\n")
            return "".b if complete.empty? && !@buffer.end_with?("\n")

            @buffer = rest
            Logs.render(Logs.select(Logs.lines("#{complete}\n"), stream: @stream, since: nil, tail: nil), timestamps: @timestamps)
          end
        end
      end
    end
  end
end
