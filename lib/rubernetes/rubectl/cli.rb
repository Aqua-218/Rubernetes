# frozen_string_literal: true

require "json"
require "optparse"
require "uri"

require_relative "../version"
require_relative "../client"
require_relative "kuberc"
require_relative "manifest_input"
require_relative "pod_logs"

module Rubernetes
  module Rubectl
    # Command dispatcher for the Rubectl client. It returns sysexits-compatible statuses instead
    # of calling Kernel.exit so embedders and tests retain control over process lifetime.
    class CLI
      EX_OK = 0
      EX_USAGE = 64
      EX_DATAERR = 65
      EX_UNAVAILABLE = 69
      EX_CONFIG = 78
      EX_INTERRUPTED = 130

      COMMANDS = %w[get create apply plan render cron patch delete watch logs raw disk extension].freeze
      # Commands that talk to the processes of a cluster on this host, not to
      # its API.
      LOCAL_COMMANDS = %w[console why trace].freeze
      PROJECT_ROOT = File.expand_path("../../..", __dir__).freeze
      DEFAULT_MANIFEST_REGISTRY_CANDIDATES = %w[
        generated/schema/registry.json
        generated/registry.json
      ].freeze
      DEFAULT_MANIFEST_OPENAPI_CANDIDATES = %w[
        generated/openapi/v2.json
        generated/openapi/openapi.json
      ].freeze

      # Resolves the generated schema artifacts used by the isolated Ruby manifest worker.
      # Keeping this lookup in the CLI makes the default path deterministic for both a source
      # checkout and a packaged gem while still allowing tests and embedders to inject artifacts.
      def self.default_manifest_paths(root: PROJECT_ROOT, registry_path: nil, openapi_path: nil)
        {
          registry_path: resolve_manifest_artifact(root, registry_path, DEFAULT_MANIFEST_REGISTRY_CANDIDATES, "registry"),
          openapi_path: resolve_manifest_artifact(root, openapi_path, DEFAULT_MANIFEST_OPENAPI_CANDIDATES, "OpenAPI")
        }.freeze
      end

      def self.default_manifest_sandbox(root: PROJECT_ROOT, registry_path: nil, openapi_path: nil, **)
        raise Client::RubyManifestIsolationError, "isolated Ruby manifest sandbox is unavailable" unless defined?(Rubernetes::Manifest::Sandbox)

        paths = default_manifest_paths(root: root, registry_path: registry_path, openapi_path: openapi_path)
        Rubernetes::Manifest::Sandbox.new(**paths, **)
      rescue ArgumentError, IOError, SystemCallError => error
        raise Client::RubyManifestIsolationError.new("cannot initialize Ruby manifest sandbox: #{error.message}", cause: error),
              cause: error
      end

      def self.run(argv = ARGV, stdout: $stdout, stderr: $stderr, stdin: $stdin, env: ENV, client: nil, client_factory: nil,
                   sandbox: nil, sandbox_factory: nil, registry_path: nil, openapi_path: nil)
        new(
          stdout: stdout,
          stderr: stderr,
          stdin: stdin,
          env: env,
          client: client,
          client_factory: client_factory,
          sandbox: sandbox,
          sandbox_factory: sandbox_factory,
          registry_path: registry_path,
          openapi_path: openapi_path
        ).run(argv)
      end

      def initialize(stdout: $stdout, stderr: $stderr, stdin: $stdin, env: ENV, client: nil, client_factory: nil,
                     sandbox: nil, sandbox_factory: nil, registry_path: nil, openapi_path: nil)
        @stdout = stdout
        @stderr = stderr
        @stdin = stdin
        @env = env
        @client = client
        @client_factory = client_factory
        @sandbox = sandbox
        @sandbox_factory = sandbox_factory
        @registry_path = registry_path
        @openapi_path = openapi_path
        @sensitive_values = []
      end

      def run(argv)
        arguments = Array(argv).dup
        return run_cluster(arguments.drop(1)) if arguments.first == "cluster"
        return run_console(arguments.first, arguments.drop(1)) if LOCAL_COMMANDS.include?(arguments.first)

        options = default_options
        command_probe = arguments.dup
        option_parser(default_options).order!(command_probe)
        parser = option_parser(options, logs: command_probe.first == "logs")
        parser.parse!(arguments)

        return print_help(parser) if options[:help]
        return print_version if options[:version]

        command = arguments.shift
        raise Client::UsageError, "a command is required; choose #{COMMANDS.join(", ")}" if command.nil?
        raise Client::UsageError, "unknown command #{command.inspect}; choose #{COMMANDS.join(", ")}" unless COMMANDS.include?(command)

        options[:output] ||= command == "disk" ? "text" : "json" unless command == "logs"
        remember_option_secrets(options)
        validate_invocation!(command, arguments, options)

        result = dispatch(command, arguments, options)
        return EX_OK if result == :no_output

        # What `render` prints is the manifest itself, for another client to
        # apply: a value that came in through --env belongs in it as it is.
        write_results(result, options[:output], redact: command != "render")
        EX_OK
      rescue OptionParser::ParseError, Client::UsageError => error
        write_error(error)
        EX_USAGE
      rescue Client::RubyManifestIsolationError, Client::ManifestError, Client::WatchStreamError => error
        write_error(error)
        EX_DATAERR
      rescue Client::ConfigurationError => error
        write_error(error)
        EX_CONFIG
      rescue Client::APIError => error
        write_api_error(error)
        1
      rescue Client::TransportError => error
        write_error(error)
        EX_UNAVAILABLE
      rescue Client::Error => error
        write_error(error)
        EX_DATAERR
      rescue Interrupt
        EX_INTERRUPTED
      end

      private

      def default_options
        {
          help: false,
          version: false,
          kubeconfig: nil,
          kuberc: nil,
          context: nil,
          namespace: nil,
          node: nil,
          output: nil,
          filenames: [],
          patch: nil,
          data: nil,
          patch_type: :merge,
          field_manager: "rubernetes",
          force: false,
          server: nil,
          token: nil,
          certificate_authority: nil,
          client_certificate: nil,
          client_key: nil,
          insecure_skip_tls_verify: false,
          allow_code: false,
          environment: [],
          manifest_registry: @registry_path,
          manifest_openapi: @openapi_path
        }
      end

      def option_parser(options, logs: false)
        OptionParser.new do |parser|
          parser.banner = "Usage: rubectl [options] COMMAND [arguments]"
          parser.on("-h", "--help", "show this help") { options[:help] = true }
          parser.on("-v", "--version", "show version") { options[:version] = true }
          parser.on("--kubeconfig PATH", "load kubeconfig from PATH") { |value| options[:kubeconfig] = value }
          parser.on("--kuberc PATH", "load the exec credential plugin policy from PATH") { |value| options[:kuberc] = value } unless Kuberc.disabled?(@env)
          parser.on("--context NAME", "select kubeconfig context") { |value| options[:context] = value }
          parser.on("-n", "--namespace NAME", "use namespace NAME") { |value| options[:namespace] = value }
          parser.on("-A", "--all-namespaces", "include every namespace in get, watch, and disk lists") { options[:all_namespaces] = true }
          parser.on("--node NAME", "filter the disk report to Pods on one node") { |value| options[:node] = value }
          parser.on("-o", "--output FORMAT", "output format (json, yaml, name, or text for plan and disk)") { |value| options[:output] = value }
          parser.on("-f", "--filename PATH", "read a manifest file (repeatable)") { |value| options[:filenames] << value } unless logs
          parser.on("--from RFC3339", "list CronJob times strictly after this instant") { |value| options[:cron_from] = value }
          parser.on("--count COUNT", Integer, "number of future times per CronJob (default 5, maximum 100)") { |value| options[:cron_count] = value }
          parser.on("-p", "--patch PATCH", "patch body or patch file") { |value| options[:patch] = value } unless logs
          parser.on("--data DATA", "raw request body or @FILE") { |value| options[:data] = value }
          parser.on("--type TYPE", "patch type: merge, json, strategic, or apply") { |value| options[:patch_type] = value }
          parser.on("--field-manager NAME", "server-side apply field manager") { |value| options[:field_manager] = value }
          parser.on("--force", "force server-side apply ownership") { options[:force] = true }
          parser.on("--server URL", "use URL instead of kubeconfig") { |value| options[:server] = value }
          parser.on("--token TOKEN", "use a bearer token") { |value| options[:token] = value }
          parser.on("--certificate-authority PATH", "use a CA file") { |value| options[:certificate_authority] = value }
          parser.on("--client-certificate PATH", "use a client certificate file") { |value| options[:client_certificate] = value }
          parser.on("--client-key PATH", "use a client key file") { |value| options[:client_key] = value }
          parser.on("--insecure-skip-tls-verify", "disable TLS certificate verification") { options[:insecure_skip_tls_verify] = true }
          parser.on("--allow-code", "allow Ruby manifests only through an isolated sandbox") { options[:allow_code] = true }
          parser.on("--env NAME", "allow one environment variable in an isolated Ruby manifest") { |value| options[:environment] << value }
          parser.on("--manifest-registry PATH", "use a generated manifest registry") { |value| options[:manifest_registry] = value }
          parser.on("--manifest-openapi PATH", "use generated manifest OpenAPI definitions") { |value| options[:manifest_openapi] = value }
          PodLogs.add_options(parser, options) if logs
        end
      end

      def print_help(parser)
        @stdout.puts(parser)
        @stdout.puts
        @stdout.puts("Commands: #{COMMANDS.join(", ")}")
        @stdout.puts("Pod logs: rubectl logs POD [-c CONTAINER] [-f] [-p] [--tail LINES] [--timestamps] [--since DURATION | --since-time RFC3339]")
        @stdout.puts("CronJob schedule: rubectl cron -f FILE --from RFC3339 [--count COUNT] [--allow-code]")
        @stdout.puts("Pod disk usage: rubectl disk [POD | --node NAME] [-n NAMESPACE | -A] [-o json]")
        @stdout.puts("Node filesystem usage: rubectl disk node/NAME [-o json]")
        @stdout.puts("Local clusters: rubectl cluster --help")
        @stdout.puts("Extensions written in Ruby: rubectl extension")
        @stdout.puts("Inside the running components: rubectl console, rubectl why, rubectl trace")
        EX_OK
      end

      # A cluster on this host; it has options of its own and needs no API
      # client, so it is parsed apart from the resource commands.
      def run_cluster(arguments)
        require_relative "../cluster/cli"

        Cluster::CLI.run(arguments, stdout: @stdout, stderr: @stderr)
      end

      def run_console(command, arguments)
        require_relative "../console/cli"

        Console::CLI.new(stdout: @stdout, stderr: @stderr, stdin: @stdin).run(command, arguments)
      end

      # `extension check` reads files only; the client is built when a
      # subcommand first needs the cluster.
      def run_extension(arguments, options)
        require_relative "../extension/cli"

        Extension::CLI.new(stdout: @stdout, client_factory: -> { build_client(options) }).run(arguments)
        :no_output
      end

      def print_version
        @stdout.puts("rubectl #{Rubernetes::VERSION}")
        EX_OK
      end

      def dispatch(command, arguments, options)
        return run_extension(arguments, options) if command == "extension"
        return run_cron(options) if command == "cron"

        # What `apply` would send, without a cluster: the manifests a file
        # declares, ready for any client (`| kubectl apply -f -`).
        if command == "render"
          resources = read_resources(options[:filenames], options)
          return {"apiVersion" => "v1", "kind" => "List", "items" => resources} if resources.size > 1 && options[:output].casecmp?("json")

          return resources
        end

        client = build_client(options)
        options = options.merge(namespace: :all) if options[:all_namespaces]
        case command
        when "raw"
          run_raw(client, arguments, options)
        when "get"
          run_get(client, arguments, options)
        when "disk"
          run_disk(client, arguments.first, options)
        when "create"
          run_create(client, arguments, options)
        when "apply"
          run_apply(client, arguments, options)
        when "plan"
          run_plan(client, options)
        when "patch"
          run_patch(client, arguments, options)
        when "delete"
          run_delete(client, arguments, options)
        when "watch"
          run_watch(client, arguments, options)
        when "logs"
          options.fetch(:log_request).write(client, stdout: @stdout, warning: ->(message) { @stderr.puts(redact_sensitive(message)) })
          :no_output
        end
      end

      def build_client(options)
        policy = Kuberc.load(path: options[:kuberc], env: @env, warn: ->(message) { @stderr.puts(redact_sensitive(message)) })
        client = if @client
                   @client
                 elsif @client_factory
                   @client_factory.call(options)
                 elsif options[:server]
                   context = Client::Kubeconfig::KubeContext.new(
                     name: "command-line",
                     server: options[:server],
                     namespace: options[:namespace] || Client::Kubeconfig::DEFAULT_NAMESPACE,
                     ca_file: options[:certificate_authority],
                     bearer_token: options[:token],
                     client_certificate_file: options[:client_certificate],
                     client_key_file: options[:client_key],
                     insecure_skip_tls_verify: options[:insecure_skip_tls_verify]
                   )
                   Client::KubernetesClient.new(context: context)
                 else
                   Client::KubernetesClient.from_kubeconfig(
                     path: options[:kubeconfig],
                     context: options[:context],
                     env: @env,
                     exec_policy: policy,
                     token: options[:token]
                   )
                 end
        remember_client_secrets(client)
        client
      end

      def run_raw(client, arguments, options)
        method = arguments.shift
        path = arguments.shift
        raise Client::UsageError, "raw requires METHOD PATH" if method.nil? || path.nil?
        raise Client::UsageError, "raw accepts only METHOD PATH" unless arguments.empty?

        body = raw_body(options[:data]) || file_body(options[:filenames].first)
        response = client.raw(method, path, body: body)
        return :no_output if response_body(response).empty?

        response_value(response)
      end

      def run_get(client, arguments, options)
        target = arguments.shift
        name = arguments.shift
        raise Client::UsageError, "get requires RESOURCE or PATH" if target.nil?
        raise Client::UsageError, "get accepts RESOURCE [NAME]" unless arguments.empty?

        client.get(target, name, namespace: options[:namespace])
      end

      def run_disk(client, name, options)
        if name&.start_with?("node/")
          require_relative "node_disk_usage"
          report = NodeDiskUsage.fetch(client, name.delete_prefix("node/"))
          return write_disk_report(NodeDiskUsage, report, options[:output])
        end

        require_relative "pod_disk_usage"

        report = if name
                   PodDiskUsage.fetch(client, name, namespace: options[:namespace])
                 else
                   PodDiskUsage.rank(client, **options.slice(:namespace, :node))
                 end
        write_disk_report(PodDiskUsage, report, options[:output])
      end

      def write_disk_report(usage, report, output)
        return report if output.casecmp?("json")

        @stdout.puts(redact_sensitive(usage.text(report)))
        :no_output
      end

      def run_create(client, arguments, options)
        raise Client::UsageError, "create accepts only -f/--filename" unless arguments.empty?

        resources = read_resources(options[:filenames], options)
        resources.map { |resource| client.create(resource, namespace: options[:namespace]) }
      end

      def run_apply(client, arguments, options)
        raise Client::UsageError, "apply accepts only -f/--filename" unless arguments.empty?

        read_manifest_inputs(options).map do |input|
          input.request { |resource| client.apply(resource, **options.slice(:namespace, :field_manager, :force)) }
        end
      end

      def run_plan(client, options)
        require_relative "manifest_plan"

        text = options[:output].casecmp?("text")
        reports = read_manifest_inputs(options).map do |input|
          report = input.request { |manifest| ManifestPlan.for_resource(client, manifest, **options.slice(:namespace, :field_manager, :force)) }
          text ? "#{input.source_location}  #{redact_sensitive(ManifestPlan.text(report))}" : report
        end
        return reports unless text

        @stdout.puts(reports)
        :no_output
      end

      def run_cron(options)
        require_relative "cron_preview"

        from = CronPreview.start_time(options[:cron_from])
        count = options.fetch(:cron_count, CronPreview::DEFAULT_COUNT)
        raise Client::UsageError, "--count must be between 1 and #{CronPreview::MAX_COUNT}" unless (1..CronPreview::MAX_COUNT).cover?(count)

        jobs = read_manifest_inputs(options).filter_map do |input|
          CronPreview.for_manifest(input, from: from, count: count, namespace: options[:namespace])
        end
        raise Client::ManifestError, "no batch/v1 CronJob found" if jobs.empty?

        {"from" => options[:cron_from], "cronJobs" => jobs}
      end

      def run_patch(client, arguments, options)
        target = arguments.shift
        raise Client::UsageError, "patch requires RESOURCE/NAME or PATH" if target.nil?
        raise Client::UsageError, "patch accepts one target" unless arguments.empty?

        patch_body = raw_body(options[:patch]) || raw_body(options[:data]) || file_body(options[:filenames].first)
        raise Client::UsageError, "patch requires --patch, --filename, or --data" if patch_body.nil?

        patch_body = parse_patch_argument(patch_body)

        if target.start_with?("/")
          client.patch(target, patch_body, type: options[:patch_type], namespace: options[:namespace])
        else
          resource, name, extra = target.split("/", 3)
          raise Client::UsageError, "patch target must be RESOURCE/NAME or an absolute API path" if resource.to_s.empty? || name.to_s.empty? || extra

          client.patch(
            resource,
            patch_body,
            name: name,
            type: options[:patch_type],
            namespace: options[:namespace]
          )
        end
      end

      def run_delete(client, arguments, options)
        target = arguments.shift
        name = arguments.shift
        raise Client::UsageError, "delete requires RESOURCE or PATH" if target.nil?
        raise Client::UsageError, "delete accepts RESOURCE [NAME]" unless arguments.empty?

        if options[:filenames].any?
          resources = read_resources(options[:filenames], options)
          return resources.map { |resource| client.delete(resource, namespace: options[:namespace]) }
        end

        client.delete(target, name, namespace: options[:namespace])
      end

      def run_watch(client, arguments, options)
        target = arguments.shift
        raise Client::UsageError, "watch requires RESOURCE or PATH" if target.nil?
        raise Client::UsageError, "watch accepts one target" unless arguments.empty?

        if client.respond_to?(:watch_each)
          client.watch_each(target, namespace: options[:namespace]) do |event|
            if event["type"] == "ERROR"
              detail = event.fetch("object").fetch("message", "Kubernetes API watch failed")
              raise Client::WatchStreamError, "Kubernetes API watch returned an ERROR event: #{detail}"
            end
            value = options[:output].to_s == "name" ? event.fetch("object") : event
            write_output(value, options[:output])
            @stdout.flush if @stdout.respond_to?(:flush)
          end
          return :no_output
        end

        if client.respond_to?(:watch_events)
          events = client.watch_events(target, namespace: options[:namespace])
          return :no_output if events.empty?

          return events
        end

        response = client.watch(target, namespace: options[:namespace])
        return :no_output if response_body(response).empty?

        response_value(response)
      end

      def read_resources(filenames, options)
        raise Client::UsageError, "-f/--filename is required" if filenames.empty?

        sandbox = (build_manifest_sandbox(options) if options[:allow_code] && filenames.any? { |filename| File.extname(filename).casecmp?(".rb") })
        reader = Client::ManifestReader.new(
          sandbox: sandbox,
          allow_code: options[:allow_code],
          environment: options[:environment],
          env: @env
        )
        filenames.flat_map do |filename|
          lines = nil
          resources = if filename == "-"
                        reader.load_content(@stdin.read(reader.max_bytes + 1).to_s, filename: filename)
                      else
                        reader.load(filename) { |declarations| lines = declarations }
                      end
          next resources unless block_given?

          resources.map.with_index { |resource, index| yield resource, filename, lines&.at(index) }
        end
      end

      def read_manifest_inputs(options)
        read_resources(options[:filenames], options) do |resource, filename, line|
          ManifestInput.new(resource, filename, line)
        end
      end

      def build_manifest_sandbox(options)
        return @sandbox if @sandbox

        paths = self.class.default_manifest_paths(
          registry_path: options[:manifest_registry],
          openapi_path: options[:manifest_openapi]
        )
        remember_sensitive_values(paths.values)
        return invoke_sandbox_factory(options, paths) if @sandbox_factory

        self.class.default_manifest_sandbox(**paths)
      end

      def invoke_sandbox_factory(options, paths)
        parameters = @sandbox_factory.parameters
        if parameters.any? { |kind, _name| %i[key keyreq keyrest].include?(kind) }
          keyword_arguments = paths.merge(options: options)
          accepts_keywords = parameters.any? { |kind, _name| kind == :keyrest }
          unless accepts_keywords
            names = parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
            keyword_arguments = keyword_arguments.select { |name, _value| names.include?(name) }
          end
          return @sandbox_factory.call(**keyword_arguments)
        end

        case @sandbox_factory.arity
        when 0
          @sandbox_factory.call
        when 1
          @sandbox_factory.call(options)
        when 2
          @sandbox_factory.call(paths[:registry_path], paths[:openapi_path])
        else
          @sandbox_factory.call(paths, options)
        end
      rescue ArgumentError, IOError, SystemCallError => error
        raise Client::RubyManifestIsolationError.new("cannot initialize Ruby manifest sandbox: #{error.message}", cause: error),
              cause: error
      end

      def parse_patch_argument(value)
        return value unless value.is_a?(String)
        return value unless value.lstrip.start_with?("{", "[")

        JSON.parse(value)
      rescue JSON::ParserError
        value
      end

      def file_body(path)
        return nil if path.nil?
        return @stdin.read if path == "-"

        File.binread(path)
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR => error
        raise Client::ManifestError.new("cannot read request body #{path}: #{error.message}", cause: error), cause: error
      end

      def raw_body(value)
        return nil if value.nil?
        return File.binread(value.delete_prefix("@")) if value.start_with?("@")

        value
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR => error
        path = value.delete_prefix("@")
        raise Client::ManifestError.new("cannot read request body #{path}: #{error.message}", cause: error), cause: error
      end

      def write_results(result, format, redact: true)
        values = result.is_a?(Array) ? result : [result]
        values.each do |value|
          next if value.nil?

          write_output(value, format, redact: redact)
        end
      end

      def write_output(value, format, redact: true)
        rendered = Client::Output.new(format: format).render(value)
        @stdout.write(redact ? redact_sensitive(rendered) : rendered)
        @stdout.write("\n") unless rendered.end_with?("\n")
        value
      end

      def response_body(response)
        if response.respond_to?(:body)
          body = response.body
          return "" if body.nil?
          return body if body.is_a?(String)

          return JSON.generate(body)
        end
        return response.to_s unless response.is_a?(Hash)

        JSON.generate(response)
      end

      def response_value(response)
        return response unless response.respond_to?(:body)
        return response.body unless response.body.is_a?(String)

        body = response_body(response)
        return nil if body.empty?

        JSON.parse(body)
      rescue JSON::ParserError
        body
      end

      def write_api_error(error)
        input = error.input if error.is_a?(ManifestInput::Rejected)
        declaration = input&.declaration
        @stderr.puts("rubectl: #{declaration}") if declaration

        if error.status_object.is_a?(Hash)
          status = input ? input.redact_error(error.status_object) : error.status_object
          @stderr.puts(redact_sensitive(JSON.generate(status)))
        elsif error.response
          body = response_body(error.response)
          body = error.message if body.empty?
          @stderr.puts(redact_sensitive(input ? input.redact_error(body) : body))
        else
          write_error(error)
        end
      end

      def write_error(error)
        location = "#{error.input.source_location}: " if error.is_a?(ManifestInput::Invalid)
        @stderr.puts("rubectl: #{location}#{redact_sensitive(error.message)}")
      end

      def remember_option_secrets(options)
        configured_kubeconfig = options[:kubeconfig] || @env["KUBECONFIG"]
        configured_kubeconfig ||= File.expand_path("~/.kube/config")
        kubeconfig_paths = configured_kubeconfig.to_s.split(File::PATH_SEPARATOR)
        path_values = [
          *kubeconfig_paths,
          options[:kuberc],
          @env["KUBERC"] == "off" ? nil : @env["KUBERC"],
          options[:certificate_authority],
          options[:client_certificate],
          options[:client_key],
          options[:manifest_registry],
          options[:manifest_openapi],
          *options[:filenames].reject { |filename| filename == "-" }
        ]
        path_values << options[:data].delete_prefix("@") if options[:data]&.start_with?("@")
        path_values << options[:patch].delete_prefix("@") if options[:patch]&.start_with?("@")
        remember_sensitive_values(options[:token], options[:server], path_values)
        options[:environment].each do |name|
          remember_sensitive_values(@env[name]) if @env.respond_to?(:key?) && @env.key?(name)
        end
      end

      def remember_client_secrets(client)
        contexts = []
        contexts << client.context if client.respond_to?(:context)
        contexts << client.rest_client.context if client.respond_to?(:rest_client) && client.rest_client.respond_to?(:context)
        contexts.compact.each do |context|
          token = if context.respond_to?(:bearer_token)
                    context.bearer_token
                  elsif context.respond_to?(:token)
                    context.token
                  elsif context.is_a?(Hash)
                    context[:bearer_token] || context["bearer_token"] || context[:token] || context["token"]
                  end
          remember_sensitive_values(token)
          remember_sensitive_values(context.client_key_data) if context.respond_to?(:client_key_data)
          %i[ca_file client_certificate_file client_key_file].each do |field|
            remember_sensitive_values(context.public_send(field)) if context.respond_to?(field)
          end
        end
      end

      def remember_sensitive_values(*values)
        values.flatten.compact.each do |value|
          string = value.to_s
          next if string.empty?

          variants = [string]
          begin
            encoded = JSON.generate(string)
            variants << encoded[1...-1]
          rescue JSON::GeneratorError
            # The literal form is still useful for non-JSON error messages.
          end
          @sensitive_values.concat(variants.reject(&:empty?))
        end
        @sensitive_values.uniq!
      end

      def redact_sensitive(value)
        original = value.to_s
        redacted = original.b.dup
        @sensitive_values.sort_by { |secret| -secret.bytesize }.each do |secret|
          redacted.gsub!(secret.b, "[REDACTED]".b)
        end
        redacted.force_encoding(original.encoding)
      end

      def validate_invocation!(command, arguments, options)
        raise Client::UsageError, "--node is only supported by disk" if options[:node] && command != "disk"
        raise Client::UsageError, "--from and --count are only supported by cron" if (options[:cron_from] || options[:cron_count]) && command != "cron"

        if options[:all_namespaces]
          raise Client::UsageError, "--all-namespaces is supported by get, watch, and disk" unless %w[get watch disk].include?(command)
          if (command == "disk" && arguments.any?) || (command == "get" && arguments.length > 1)
            raise Client::UsageError, "--all-namespaces requires omitting the resource name"
          end
        end

        case command
        when "raw"
          raise Client::UsageError, "raw requires METHOD PATH" unless arguments.length == 2
        when "get"
          raise Client::UsageError, "get requires RESOURCE or PATH" unless (1..2).cover?(arguments.length)
        when "disk"
          raise Client::UsageError, "disk accepts at most one Pod name or node/NAME" if arguments.length > 1 || arguments.first == ""
          raise Client::UsageError, "disk --node requires omitting the resource name" if options[:node] && !arguments.empty?
          raise Client::UsageError, "disk output must be text or json" unless %w[text json].include?(options[:output].downcase)
        when "create", "apply", "plan", "render", "cron"
          if command == "plan" && !(Client::Output::FORMATS + ["text"]).include?(options[:output].downcase)
            raise Client::UsageError, "plan output must be json, yaml, name, or text"
          end
          raise Client::UsageError, "cron output must be json or yaml" if command == "cron" && !%w[json yaml].include?(options[:output].downcase)
          raise Client::UsageError, "#{command} accepts only -f/--filename" unless arguments.empty?
          raise Client::UsageError, "-f/--filename is required" if options[:filenames].empty?
        when "patch"
          raise Client::UsageError, "patch requires RESOURCE/NAME or PATH" unless arguments.length == 1
          raise Client::UsageError, "patch requires --patch, --filename, or --data" unless options[:patch] || options[:data] || options[:filenames].any?
        when "delete"
          raise Client::UsageError, "delete requires RESOURCE or PATH" unless (1..2).cover?(arguments.length)
        when "watch"
          raise Client::UsageError, "watch requires RESOURCE or PATH" unless arguments.length == 1
        when "logs"
          options[:log_request] = PodLogs.new(arguments, options)
        end
      end

      class << self
        private

        def resolve_manifest_artifact(root, explicit_path, candidates, label)
          candidate_paths = if explicit_path
                              [File.expand_path(explicit_path, root)]
                            else
                              candidates.map { |relative| File.expand_path(relative, root) }
                            end
          path = candidate_paths.find do |candidate|
            File.file?(candidate) && File.readable?(candidate) && !File.symlink?(candidate)
          end
          return path unless path.nil?

          raise Client::RubyManifestIsolationError, "generated manifest #{label} artifact is unavailable"
        end
      end
    end
  end
end
