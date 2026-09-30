# frozen_string_literal: true

require "json"
require "optparse"
require "uri"

require_relative "../version"
require_relative "../client"

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

      COMMANDS = %w[get create apply patch delete watch raw].freeze
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
        unless defined?(Rubernetes::Manifest::Sandbox)
          raise Client::RubyManifestIsolationError, "isolated Ruby manifest sandbox is unavailable"
        end

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
        options = default_options
        parser = option_parser(options)
        parser.parse!(arguments)

        return print_help(parser) if options[:help]
        return print_version if options[:version]

        command = arguments.shift
        raise Client::UsageError, "a command is required; choose #{COMMANDS.join(", ")}" if command.nil?
        raise Client::UsageError, "unknown command #{command.inspect}; choose #{COMMANDS.join(", ")}" unless COMMANDS.include?(command)

        remember_option_secrets(options)
        validate_invocation!(command, arguments, options)

        result = dispatch(command, arguments, options)
        return EX_OK if result == :no_output

        write_results(result, options[:output])
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
          context: nil,
          namespace: nil,
          output: "json",
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

      def option_parser(options)
        OptionParser.new do |parser|
          parser.banner = "Usage: rubectl [options] COMMAND [arguments]"
          parser.on("-h", "--help", "show this help") { options[:help] = true }
          parser.on("-v", "--version", "show version") { options[:version] = true }
          parser.on("--kubeconfig PATH", "load kubeconfig from PATH") { |value| options[:kubeconfig] = value }
          parser.on("--context NAME", "select kubeconfig context") { |value| options[:context] = value }
          parser.on("-n", "--namespace NAME", "use namespace NAME") { |value| options[:namespace] = value }
          parser.on("-o", "--output FORMAT", "output as json, yaml, or name") { |value| options[:output] = value }
          parser.on("-f", "--filename PATH", "read a manifest file (repeatable)") { |value| options[:filenames] << value }
          parser.on("-p", "--patch PATCH", "patch body or patch file") { |value| options[:patch] = value }
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
        end
      end

      def print_help(parser)
        @stdout.puts(parser)
        @stdout.puts
        @stdout.puts("Commands: #{COMMANDS.join(", ")}")
        EX_OK
      end

      def print_version
        @stdout.puts("rubectl #{Rubernetes::VERSION}")
        EX_OK
      end

      def dispatch(command, arguments, options)
        client = build_client(options)
        case command
        when "raw"
          run_raw(client, arguments, options)
        when "get"
          run_get(client, arguments, options)
        when "create"
          run_create(client, arguments, options)
        when "apply"
          run_apply(client, arguments, options)
        when "patch"
          run_patch(client, arguments, options)
        when "delete"
          run_delete(client, arguments, options)
        when "watch"
          run_watch(client, arguments, options)
        end
      end

      def build_client(options)
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
                     env: @env
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

        if target.start_with?("/")
        end
        client.get(target, name, namespace: options[:namespace])
      end

      def run_create(client, arguments, options)
        raise Client::UsageError, "create accepts only -f/--filename" unless arguments.empty?

        resources = read_resources(options[:filenames], options)
        resources.map { |resource| client.create(resource, namespace: options[:namespace]) }
      end

      def run_apply(client, arguments, options)
        raise Client::UsageError, "apply accepts only -f/--filename" unless arguments.empty?

        resources = read_resources(options[:filenames], options)
        resources.map do |resource|
          client.apply(
            resource,
            namespace: options[:namespace],
            field_manager: options[:field_manager],
            force: options[:force]
          )
        end
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
          if resource.to_s.empty? || name.to_s.empty? || extra
            raise Client::UsageError, "patch target must be RESOURCE/NAME or an absolute API path"
          end

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

        sandbox = if options[:allow_code] && filenames.any? { |filename| File.extname(filename).casecmp?(".rb") }
                    build_manifest_sandbox(options)
                  end
        reader = Client::ManifestReader.new(
          sandbox: sandbox,
          allow_code: options[:allow_code],
          environment: options[:environment],
          env: @env
        )
        filenames.flat_map do |filename|
          filename == "-" ? reader.load_content(@stdin.read, filename: filename) : reader.load(filename)
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

      def write_results(result, format)
        values = result.is_a?(Array) ? result : [result]
        values.each do |value|
          next if value.nil?

          write_output(value, format)
        end
      end

      def write_output(value, format)
        rendered = Client::Output.new(format: format).render(value)
        @stdout.write(redact_sensitive(rendered))
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
        if error.status_object.is_a?(Hash)
          @stderr.puts(redact_sensitive(JSON.generate(error.status_object)))
        elsif error.response
          body = response_body(error.response)
          @stderr.puts(redact_sensitive(body.empty? ? error.message : body))
        else
          write_error(error)
        end
      end

      def write_error(error)
        @stderr.puts("rubectl: #{redact_sensitive(error.message)}")
      end

      def remember_option_secrets(options)
        configured_kubeconfig = options[:kubeconfig] || @env["KUBECONFIG"]
        configured_kubeconfig ||= File.expand_path("~/.kube/config")
        kubeconfig_paths = configured_kubeconfig.to_s.split(File::PATH_SEPARATOR)
        path_values = [
          *kubeconfig_paths,
          options[:certificate_authority],
          options[:client_certificate],
          options[:client_key],
          options[:manifest_registry],
          options[:manifest_openapi],
          *options[:filenames]
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
        case command
        when "raw"
          raise Client::UsageError, "raw requires METHOD PATH" unless arguments.length == 2
        when "get"
          raise Client::UsageError, "get requires RESOURCE or PATH" unless (1..2).cover?(arguments.length)
        when "create", "apply"
          raise Client::UsageError, "#{command} accepts only -f/--filename" unless arguments.empty?
          raise Client::UsageError, "-f/--filename is required" if options[:filenames].empty?
        when "patch"
          raise Client::UsageError, "patch requires RESOURCE/NAME or PATH" unless arguments.length == 1
          unless options[:patch] || options[:data] || options[:filenames].any?
            raise Client::UsageError, "patch requires --patch, --filename, or --data"
          end
        when "delete"
          raise Client::UsageError, "delete requires RESOURCE or PATH" unless (1..2).cover?(arguments.length)
        when "watch"
          raise Client::UsageError, "watch requires RESOURCE or PATH" unless arguments.length == 1
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
