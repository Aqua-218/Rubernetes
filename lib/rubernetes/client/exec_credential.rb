# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "pathname"
require "time"

require_relative "errors"

module Rubernetes
  module Client
    # Runs a kubeconfig `exec` credential plugin (client.authentication.k8s.io
    # ExecCredential, the mechanism behind `aws eks get-token`,
    # `gke-gcloud-auth-plugin`, `kubelogin`, ...) and returns what it printed.
    #
    # The plugin is a program the kubeconfig's owner chose, exactly as with
    # kubectl; it is started without a shell, its output is bounded, and a
    # plugin that never answers is killed.
    class ExecCredential
      API_VERSIONS = %w[client.authentication.k8s.io/v1 client.authentication.k8s.io/v1beta1].freeze
      INTERACTIVE_MODES = %w[Never IfAvailable Always].freeze
      MAX_OUTPUT_BYTES = 1_048_576
      DEFAULT_TIMEOUT = 120

      Result = Struct.new(:bearer_token, :client_certificate_data, :client_key_data, :expires_at, :certificate_chain, :private_key,
                          :certificate_identity, keyword_init: true) do
        def expired?(now = Time.now)
          !expires_at.nil? && expires_at <= now
        end
      end

      @cache = {}
      @cache_mutex = Mutex.new
      @expiry_mutex = Mutex.new
      @certificate_expirations = {}
      @observer = nil

      class << self
        attr_accessor :observer, :policy_observer, :rotation_observer

        # One plugin run per configuration for as long as the credential says
        # it is valid (a credential without an expiry lives as long as the
        # process, as in client-go).
        def fetch(config, **)
          provider(config, **).credentials
        end

        def provider(config, **)
          plugin = new(config, **)
          @cache_mutex.synchronize { @cache[plugin.cache_key] ||= plugin }
        end

        def certificate_expiry(provider, expiry)
          @expiry_mutex.synchronize do
            expiry ? @certificate_expirations[provider] = expiry : @certificate_expirations.delete(provider)
          end
        end

        def certificate_ttl
          @expiry_mutex.synchronize do
            earliest = @certificate_expirations.values.min
            earliest ? earliest - Time.now : Float::INFINITY
          end
        end

        def reset_cache!
          @cache_mutex.synchronize do
            @cache.clear
            @expiry_mutex.synchronize { @certificate_expirations.clear }
          end
        end

        def normalize_policy(policy)
          return if policy.nil?
          raise ConfigurationError, "exec plugin policy must be a mapping" unless policy.is_a?(Hash)
          raise ConfigurationError, "unknown exec plugin policy field" unless (policy.keys - %w[type allowlist]).empty?

          type = policy["type"]
          entries = policy["allowlist"]
          case type
          when nil, "", "AllowAll", "DenyAll"
            raise ConfigurationError, "exec plugin allowlist requires Allowlist policy" unless entries.nil?
          when "Allowlist"
            unless entries.is_a?(Array) && !entries.empty? && entries.all? { |entry| valid_allowlist_entry?(entry) }
              raise ConfigurationError, "exec plugin Allowlist policy requires normalized command entries"
            end
          else
            raise ConfigurationError, "unknown exec plugin policy #{type.inspect}"
          end
          return if type.nil? || type == ""

          {"type" => type.dup.freeze, "allowlist" => entries&.map { |entry| entry.dup.freeze }&.freeze}.freeze
        end

        private

        def valid_allowlist_entry?(entry)
          entry.is_a?(String) && !entry.empty? && !entry.include?("\0") && Pathname.new(entry).cleanpath.to_s == entry
        end
      end

      def initialize(config, cluster: {}, base_directory: Dir.pwd, env: ENV, stdin: $stdin, stderr: $stderr,
                     timeout: DEFAULT_TIMEOUT, policy: nil)
        @config = config
        @cluster = cluster
        @base_directory = base_directory
        @env = env
        @stdin = stdin
        @stderr = stderr
        @timeout = timeout
        @policy = self.class.normalize_policy(policy)
        @mutex = Mutex.new
        @clients = ObjectSpace::WeakMap.new
        validate_config!
      end

      def inspect = "#<#{self.class.name}>"

      def cache_key
        [@config, @cluster, @base_directory, @policy, @env, @stdin, @stderr, @timeout]
      end

      def credentials(client: nil)
        @mutex.synchronize do
          @clients[client] = true if client
          refresh_locked if @cached.nil? || @cached.expired?
          block_given? ? yield(@cached) : @cached
        end
      end

      def refresh_after_unauthorized(used)
        @mutex.synchronize { refresh_locked if @cached.equal?(used) }
      rescue UnsupportedCredentialError
        # Preserve the HTTP 401 and retain the cached credentials.
        nil
      end

      def call
        parse(run_plugin)
      end

      private

      def refresh_locked
        previous = @cached
        @cached = call
        leaf = @cached.certificate_chain&.first
        self.class.certificate_expiry(self, leaf&.not_after)
        return unless previous && previous.certificate_identity != @cached.certificate_identity

        previous_leaf = previous.certificate_chain&.first
        self.class.rotation_observer&.call(Time.now - previous_leaf.not_before) if previous_leaf
        @clients.each_key(&:reset_connections!)
      end

      def authorized_executable
        program = executable
        case @policy&.fetch("type", nil)
        when "DenyAll"
          denied!("policy set to DenyAll")
        when "Allowlist"
          resolved = find_executable(program)
          allowed = @policy.fetch("allowlist").any? do |entry|
            entry == program || (resolved && (entry == resolved || find_executable(entry) == resolved))
          end
          denied!("command is not permitted by the credential plugin allowlist") unless allowed

          program = resolved
        end
        self.class.policy_observer&.call(true)
        raise Errno::ENOENT, command unless program

        program
      end

      def denied!(reason)
        self.class.policy_observer&.call(false)
        raise UnsupportedCredentialError, "exec plugin #{command.inspect} not allowed: #{reason}"
      end

      def find_executable(program)
        if program.include?(File::SEPARATOR)
          path = File.expand_path(program)
          return path if File.file?(path) && File.executable?(path)

          return
        end

        path = @env.fetch("PATH") { ENV.fetch("PATH", "") }
        path.split(File::PATH_SEPARATOR, -1).each do |directory|
          candidate = File.join(directory.empty? ? "." : directory, program)
          next unless File.file?(candidate) && File.executable?(candidate)

          # Like exec.LookPath, stop if a bare command would come from a
          # relative PATH entry instead of running it from the working directory.
          return File.absolute_path?(candidate) ? File.expand_path(candidate) : nil
        end
        nil
      end

      def validate_config!
        fail_config("exec must be a mapping") unless @config.is_a?(Hash)
        fail_config("exec.apiVersion must be one of #{API_VERSIONS.join(", ")}") unless API_VERSIONS.include?(api_version)
        fail_config("exec.command must be a non-empty string") unless command.is_a?(String) && !command.empty?
        fail_config("exec.args must be a list of strings") unless arguments.all?(String)
        unless environment.all? { |entry| entry.is_a?(Hash) && entry["name"].is_a?(String) && entry["value"].is_a?(String) }
          fail_config("exec.env must be a list of name/value pairs")
        end
        fail_config("exec.interactiveMode must be one of #{INTERACTIVE_MODES.join(", ")}") unless INTERACTIVE_MODES.include?(interactive_mode)
      end

      def api_version
        @config["apiVersion"]
      end

      def command
        @config["command"]
      end

      def arguments
        Array(@config["args"])
      end

      def environment
        Array(@config["env"])
      end

      # v1 requires the field; v1beta1 predates it and behaves as IfAvailable.
      def interactive_mode
        @config.fetch("interactiveMode") { api_version.end_with?("/v1") ? nil : "IfAvailable" }
      end

      def interactive?
        terminal = @stdin.tty?
        case interactive_mode
        when "Never" then false
        when "Always"
          raise UnsupportedCredentialError, "exec plugin #{command.inspect} needs a terminal (interactiveMode: Always)" unless terminal

          true
        else terminal
        end
      end

      # A command with a directory part is relative to the kubeconfig, a bare
      # name is looked up in PATH (client-go's rule).
      def executable
        return command unless command.include?(File::SEPARATOR)

        File.expand_path(command, @base_directory)
      end

      def exec_info(interactive)
        spec = {"interactive" => interactive}
        spec["cluster"] = cluster_info if @config["provideClusterInfo"]
        JSON.generate("apiVersion" => api_version, "kind" => "ExecCredential", "spec" => spec)
      end

      def cluster_info
        info = {"server" => @cluster["server"]}
        info["tls-server-name"] = @cluster["tls-server-name"] if @cluster["tls-server-name"]
        info["insecure-skip-tls-verify"] = true if @cluster["insecure-skip-tls-verify"]
        authority = @cluster["certificate-authority-data"]
        authority ||= Base64.strict_encode64(File.binread(@cluster["certificate-authority"])) if @cluster["certificate-authority"]
        info["certificate-authority-data"] = authority if authority
        extension = Array(@cluster["extensions"]).find { |entry| entry["name"] == "client.authentication.k8s.io/exec" }
        info["config"] = extension["extension"] if extension
        info
      end

      def run_plugin
        interactive = interactive?
        child_env = environment.to_h { |entry| [entry["name"], entry["value"]] }
        child_env["KUBERNETES_EXEC_INFO"] = exec_info(interactive)
        program = authorized_executable
        reader, writer = IO.pipe
        pid = Process.spawn(child_env, [program, program], *arguments,
                            in: interactive ? @stdin : File::NULL, out: writer, err: @stderr, close_others: true)
        writer.close
        collect(pid, reader)
      rescue Errno::ENOENT, Errno::EACCES => error
        observe("plugin_not_found_error", 1)
        raise UnsupportedCredentialError, ["exec plugin #{command.inspect} cannot be started: #{error.message}",
                                           @config["installHint"]].compact.join("\n")
      rescue SystemCallError, IOError => error
        observe("client_internal_error", 1)
        raise UnsupportedCredentialError, "exec plugin #{command.inspect} failed to run: #{error.message}"
      ensure
        writer&.close unless writer&.closed?
        reader&.close
      end

      def collect(pid, reader)
        output = +""
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
        loop do
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          abort_plugin(pid, "did not answer within #{@timeout} s") unless remaining.positive? && reader.wait_readable(remaining)
          chunk = reader.read_nonblock(65_536, exception: false)
          next if chunk == :wait_readable
          break if chunk.nil?

          output << chunk
          abort_plugin(pid, "printed more than #{MAX_OUTPUT_BYTES} bytes") if output.bytesize > MAX_OUTPUT_BYTES
        end
        status = wait_for_exit(pid, deadline)
        if status.success?
          observe("no_error", 0)
          return output
        end

        observe("plugin_execution_error", status.exitstatus || -1)
        raise UnsupportedCredentialError, "exec plugin #{command.inspect} failed with #{status.to_s.sub(/\Apid \d+ /, "")}"
      end

      def wait_for_exit(pid, deadline)
        loop do
          result = Process.wait2(pid, Process::WNOHANG)
          return result.last if result

          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          abort_plugin(pid, "did not answer within #{@timeout} s") unless remaining.positive?
          sleep([0.01, remaining].min)
        end
      end

      def observe(status, code)
        self.class.observer&.call(status, code)
      end

      def abort_plugin(pid, reason)
        Process.kill("KILL", pid)
        Process.wait(pid)
        observe("plugin_execution_error", -1)
        raise UnsupportedCredentialError, "exec plugin #{command.inspect} #{reason}"
      end

      def parse(output)
        document = JSON.parse(output)
        fail_output("did not print an ExecCredential object") unless document.is_a?(Hash) && document["kind"] == "ExecCredential"
        unless document["apiVersion"] == api_version
          fail_output("answered with apiVersion #{document["apiVersion"].inspect}, the kubeconfig asks for #{api_version}")
        end
        status = document["status"]
        fail_output("returned no status") unless status.is_a?(Hash)

        result(status)
      rescue JSON::ParserError => error
        fail_output("printed invalid JSON: #{error.message.lines.first.to_s.strip}")
      end

      def result(status)
        token = status["token"]
        certificate = status["clientCertificateData"]
        key = status["clientKeyData"]
        unless [token, certificate, key].all? { |field| field.nil? || field.is_a?(String) }
          fail_output("returned a token, client certificate or private key that is not a string")
        end
        token = nil if token == ""
        certificate = nil if certificate == ""
        key = nil if key == ""
        fail_output("returned neither a token nor a client certificate") if token.nil? && certificate.nil? && key.nil?
        fail_output("returned a client certificate without its key (or the reverse)") if certificate.nil? != key.nil?
        fail_output("returned an invalid bearer token") if token && !(token.bytesize <= MAX_OUTPUT_BYTES && token.b.match?(/\A[!-~]+\z/n))

        chain, private_key = parse_certificate_pair(certificate, key) if certificate

        Result.new(bearer_token: token&.freeze, client_certificate_data: certificate&.freeze, client_key_data: key&.freeze,
                   expires_at: expiry(status["expirationTimestamp"]), certificate_chain: chain, private_key: private_key,
                   certificate_identity: chain&.map { |cert| cert.to_der.freeze }&.freeze).freeze
      end

      def parse_certificate_pair(certificate, key)
        chain = OpenSSL::X509::Certificate.load(certificate)
        private_key = OpenSSL::PKey.read(key, "")
        fail_output("returned a client certificate that does not match its private key") unless chain.first&.check_private_key(private_key)

        [chain.freeze, private_key]
      rescue OpenSSL::OpenSSLError, TypeError
        fail_output("returned an invalid client certificate or private key")
      end

      def expiry(value)
        value && Time.iso8601(value)
      rescue ArgumentError, TypeError
        fail_output("returned an invalid expirationTimestamp #{value.inspect}")
      end

      def fail_config(message)
        raise ConfigurationError, "kubeconfig #{message}"
      end

      def fail_output(message)
        raise UnsupportedCredentialError, "exec plugin #{command.inspect} #{message}"
      end
    end
  end
end
