# frozen_string_literal: true

require "cgi"
require "open3"
require "stringio"
require "time"
require "timeout"
require "uri"
require "zlib"
require_relative "../transport/response"

module Rubernetes
  module Node
    # kubelet /logs/: the node's /var/log through Go's http.FileServer
    # (enableSystemLogHandler, on by default), and with enableSystemLogQuery
    # the NodeLogQuery API (kubelet_server_journal.go):
    #
    #   /logs/?query=kubelet&sinceTime=...&untilTime=...&tailLines=N&pattern=re&boot=-1
    #
    # A query naming a service that journald knows reads journalctl; another
    # query reads <service>, <service>.log or <service>/<service>.log under the
    # log directory; a query with a '/' names one file.  Answers are
    # [status, headers, body] (body an Array or a chunk Enumerator).
    class SystemLogs
      DATE_LAYOUT = "%Y-%-m-%-d %-H:%-M:%-S"
      MAX_TAIL_LINES = 100_000
      MAX_SERVICE_LENGTH = 256
      MAX_SERVICES = 4
      SERVICE_UNSAFE = /[^a-zA-Z\-_.:0-9@]+/
      QUERY_TIMEOUT = 30
      CHUNK = 64 * 1024
      MIME = {".log" => "text/plain; charset=utf-8", ".txt" => "text/plain; charset=utf-8", ".json" => "application/json",
              ".gz" => "application/gzip", ".html" => "text/html; charset=utf-8", ".xml" => "text/xml; charset=utf-8"}.freeze

      Query = Struct.new(:services, :files, :since_time, :until_time, :tail_lines, :boot, :pattern, keyword_init: true) do
        def options? = !(since_time.nil? && until_time.nil? && tail_lines.nil? && boot.nil? && pattern.to_s.empty?)
      end

      def initialize(log_dir: "/var/log", query_enabled: false, journalctl: "journalctl", runner: nil)
        @log_dir = File.expand_path(log_dir)
        @query_enabled = query_enabled
        @journalctl = journalctl
        @runner = runner || method(:run_command)
      end

      # +path+ is the request path after "/logs/"; +params+ maps a query
      # parameter to its values.
      def call(path, params: {}, headers: {})
        if @query_enabled
          query, errors = parse_query(params)
          return error(400, aggregate(errors)) unless errors.empty?

          if query
            return error(406, "path not allowed in query mode") unless path.empty? || path == "/"

            errors = validate(query)
            return error(406, aggregate(errors)) unless errors.empty?
            return journal(query, headers) unless query.services.empty?

            path = query.files.first.tr("\\", "/") if query.files.length == 1
          end
        end
        serve_file(path)
      end

      # newNodeLogQuery: nil (no query at all) or the query, and its errors.
      def parse_query(params)
        errors = []
        values = ->(name) { Array(params[name] || params[name.to_sym]) }
        first = ->(name) { values.call(name).first.to_s }
        queries = values.call("query")
        services = []
        files = []
        queries.each do |entry|
          if entry.match?(%r{[/\\]})
            files << entry
          elsif !entry.strip.empty?
            services << entry
          end
        end
        errors << %(query: Invalid value: #{go_list(queries)}: may not be empty) if params.key?("query") && files.empty? && services.empty?
        since_time = parse_time(first.call("sinceTime"), "sinceTime", errors)
        until_time = parse_time(first.call("untilTime"), "untilTime", errors)
        boot = parse_integer(first.call("boot"), "boot", errors)
        tail_lines = parse_integer(first.call("tailLines"), "tailLines", errors)
        pattern = first.call("pattern")
        return [nil, errors] unless errors.empty?

        query = Query.new(services: services, files: files, since_time: since_time, until_time: until_time, tail_lines: tail_lines,
                          boot: boot, pattern: pattern)
        return [nil, []] if services.empty? && files.empty? && !query.options?

        [query, []]
      end

      def validate(query)
        errors = query.services.filter_map do |service|
          if service.length > MAX_SERVICE_LENGTH
            %(query: Invalid value: "#{service}": length must be less than #{MAX_SERVICE_LENGTH})
          elsif service.match?(SERVICE_UNSAFE)
            %(query: Invalid value: "#{service}": input contains unsupported characters)
          end
        end
        errors << "query: Too many: #{query.services.length}: must have at most #{MAX_SERVICES} items" if query.services.length > MAX_SERVICES
        if query.files.empty? && query.services.empty?
          errors << "query: Required value: cannot be empty with options"
        elsif !query.files.empty? && !query.services.empty?
          errors << %(query: Invalid value: "#{go_list(query.files)}, #{go_list(query.services)}": cannot specify a file and service)
        elsif query.files.length > 1
          errors << "query: Invalid value: #{go_list(query.files)}: cannot specify more than one file"
        elsif query.files.length == 1 && query.options?
          errors << "query: Invalid value: #{go_list(query.files)}: cannot specify file with options"
        elsif query.files.length == 1
          target = inside(query.files.first)
          errors << "query: Invalid value: #{go_list(query.files)}: statat #{query.files.first}: no such file or directory" unless target && File.exist?(target)
        end
        if query.since_time && query.until_time && query.since_time > query.until_time
          errors << "untilTime: Invalid value: \"#{query.until_time.utc.iso8601}\": must be after `sinceTime`"
        end
        errors << "boot: Invalid value: #{query.boot}: must be less than 1" if query.boot&.positive?
        if query.tail_lines && !(0..MAX_TAIL_LINES).cover?(query.tail_lines)
          errors << "tailLines: Invalid value: #{query.tail_lines}: must be between 0 and #{MAX_TAIL_LINES}, inclusive"
        end
        begin
          Regexp.new(query.pattern.to_s)
        rescue RegexpError => regexp_error
          errors << "pattern: Invalid value: \"#{query.pattern}\": #{regexp_error.message}"
        end
        errors
      end

      # getLoggingCmd.
      def journal_arguments(query, services)
        arguments = %w[--utc --no-pager --output=short-precise]
        arguments << "--since=#{query.since_time.utc.strftime(DATE_LAYOUT)}" if query.since_time
        arguments << "--until=#{query.until_time.utc.strftime(DATE_LAYOUT)}" if query.until_time
        arguments.push("--pager-end", "--lines=#{query.tail_lines}") if query.tail_lines
        services.each { |service| arguments << "--unit=#{service}" unless service.empty? }
        arguments << "--grep=#{query.pattern}" unless query.pattern.to_s.empty?
        arguments.push("--boot", query.boot.to_s) if query.boot
        arguments
      end

      private

      def journal(query, headers)
        body = +""
        native = []
        file_loggers = []
        units = journal_units
        query.services.each { |service| (units.include?("#{service}.service") ? native : file_loggers) << service }
        unless native.empty?
          output, succeeded, started = @runner.call([@journalctl, *journal_arguments(query, native)])
          body << output.to_s
          body << "\nerror: journal output not available\n" if !started && !succeeded && query.boot.to_i.zero?
        end
        if !file_loggers.empty? && query.options?
          body << "\noptions present and query resolved to log files for #{go_list(file_loggers)}\ntry without specifying options\n"
        elsif !file_loggers.empty?
          file_loggers.each { |service| body << heuristic_file_log(service) }
        end
        response_headers = {"content-type" => "text/plain;charset=UTF-8"}
        if header(headers, "accept-encoding") == "gzip"
          response_headers["content-encoding"] = "gzip"
          body = gzip(body)
        end
        [200, response_headers, [body]]
      end

      def journal_units
        output, succeeded, = @runner.call([@journalctl, "--field", "_SYSTEMD_UNIT"])
        succeeded ? output.to_s : ""
      end

      # heuristicsCopyFileLogs.
      def heuristic_file_log(service)
        [service.to_s, "#{service}.log", "#{service}/#{service}.log"].each do |name|
          target = inside(name)
          next unless target && File.file?(target)

          return File.binread(target)
        rescue SystemCallError => error
          return "\nerror getting log for #{service}: #{error.message}\n"
        end
        "\nlog not found for #{service}\n"
      end

      # http.FileServer(http.Dir(logDir)) under /logs/.
      def serve_file(path)
        request_path = "/#{path.to_s.sub(%r{\A/+}, "")}"
        return redirect("./") if request_path.end_with?("/index.html")

        target = inside(request_path)
        return error(404, "404 page not found") if target.nil? || !File.exist?(target)
        return error(403, "403 Forbidden") unless File.readable?(target)

        if File.directory?(target)
          return redirect("#{File.basename(request_path)}/") unless request_path.end_with?("/")

          index = File.join(target, "index.html")
          return file_response(index) if File.file?(index)

          return directory_listing(target)
        end
        return redirect("../#{File.basename(request_path)}") if request_path.end_with?("/")

        file_response(target)
      rescue Errno::EACCES
        error(403, "403 Forbidden")
      rescue SystemCallError
        error(500, "500 Internal Server Error")
      end

      def directory_listing(directory)
        entries = Dir.children(directory).sort.map do |name|
          name += "/" if File.directory?(File.join(directory, name))
          %(<a href="#{url_path(name)}">#{html_escape(name)}</a>\n)
        end
        body = "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n#{entries.join}</pre>\n"
        [200, {"content-type" => "text/html; charset=utf-8"}, [body]]
      end

      def file_response(target)
        size = File.size(target)
        headers = {"content-type" => content_type(target), "last-modified" => File.mtime(target).httpdate,
                   "content-length" => size.to_s}
        body = Enumerator.new do |yielder|
          File.open(target, "rb") do |file|
            while (chunk = file.read(CHUNK))
              yielder << chunk
            end
          end
        end
        Transport::Response.new(status: 200, headers: headers, body: body, stream: true, unbounded: true)
      end

      # mime.TypeByExtension, else http.DetectContentType's text/binary split.
      def content_type(target)
        known = MIME[File.extname(target).downcase]
        return known if known

        sample = File.binread(target, 512).to_s
        if sample.empty? || (sample.force_encoding(Encoding::UTF_8).valid_encoding? && !sample.match?(/[\x00-\x08\x0e-\x1a\x1c-\x1f]/))
          return "text/plain; charset=utf-8"
        end

        "application/octet-stream"
      end

      # http.Dir / os.OpenInRoot: the path cleaned and resolved beneath the
      # log directory; nil when it would leave it.
      def inside(path)
        cleaned = File.expand_path(path.to_s.tr("\\", "/").sub(%r{\A/+}, ""), @log_dir)
        cleaned == @log_dir || cleaned.start_with?("#{@log_dir}/") ? cleaned : nil
      end

      # net/url URL{Path: name}.String(): encodePath escaping; a first segment
      # with a ':' gets "./" so it cannot read as a scheme.
      def url_path(name)
        escaped = name.b.gsub(%r{[^A-Za-z0-9\-_.~$&+,/:;=@]}) { |byte| format("%%%02X", byte.ord) }
        escaped.split("/", 2).first.include?(":") ? "./#{escaped}" : escaped
      end

      # htmlReplacer.
      HTML = {"&" => "&amp;", "<" => "&lt;", ">" => "&gt;", '"' => "&#34;", "'" => "&#39;"}.freeze
      def html_escape(text) = text.gsub(/[&<>"']/, HTML)

      def redirect(location)
        [301, {"location" => location, "content-type" => "text/html; charset=utf-8"},
         ["<a href=\"#{html_escape(location)}\">Moved Permanently</a>.\n\n"]]
      end

      def error(status, message)
        [status, {"content-type" => "text/plain; charset=utf-8", "x-content-type-options" => "nosniff"}, ["#{message}\n"]]
      end

      def parse_time(value, name, errors)
        return nil if value.empty?

        Time.iso8601(value)
      rescue ArgumentError
        errors << %(#{name}: Invalid value: "#{value}": invalid time format)
        nil
      end

      def parse_integer(value, name, errors)
        return nil if value.empty?
        return Integer(value, 10) if value.match?(/\A[+-]?\d+\z/)

        errors << %(#{name}: Invalid value: "#{value}": strconv.Atoi: parsing "#{value}": invalid syntax)
        nil
      end

      def header(headers, name)
        return headers.header(name) if headers.respond_to?(:header)

        (headers || {}).each { |key, value| return value.to_s if key.to_s.casecmp(name).zero? }
        nil
      end

      def gzip(text)
        output = StringIO.new(+"")
        writer = Zlib::GzipWriter.new(output, Zlib::BEST_SPEED)
        writer.write(text)
        writer.close
        output.string
      end

      # [output, succeeded, started]: stdout and stderr together, as
      # kubelet's cmd.Stdout = cmd.Stderr = w, bounded by the query deadline.
      def run_command(argv)
        output = +""
        status = nil
        Open3.popen2e(*argv) do |stdin, stream, waiter|
          stdin.close
          begin
            Timeout.timeout(QUERY_TIMEOUT) { output << stream.read.to_s }
          rescue Timeout::Error
            begin
              Process.kill(:KILL, waiter.pid)
            rescue StandardError
              nil
            end
          end
          status = waiter.value
        end
        [output, status&.success?, true]
      rescue SystemCallError
        ["", false, false]
      end

      # utilerrors.Aggregate: one message alone, several in brackets.
      def aggregate(errors) = errors.length == 1 ? errors.first : "[#{errors.join(", ")}]"

      def go_list(values) = "[#{Array(values).join(" ")}]"
    end
  end
end
