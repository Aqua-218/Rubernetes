# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
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

      Result = Struct.new(:bearer_token, :client_certificate_data, :client_key_data, :expires_at, keyword_init: true) do
        def expired?(now = Time.now)
          !expires_at.nil? && expires_at <= now
        end
      end

      @cache = {}
      @cache_mutex = Mutex.new
      @observer = nil

      class << self
        # Told about every plugin run as (call_status, exit code, seconds the
        # returned client certificate is still valid); the REST client's
        # metrics listen here.
        attr_accessor :observer

        # One plugin run per configuration for as long as the credential says
        # it is valid (a credential without an expiry lives as long as the
        # process, as in client-go).
        def fetch(config, **)
          plugin = new(config, **)
          @cache_mutex.synchronize do
            cached = @cache[plugin.cache_key]
            return cached if cached && !cached.expired?

            @cache[plugin.cache_key] = plugin.call
          end
        end

        def reset_cache!
          @cache_mutex.synchronize { @cache.clear }
        end
      end

      def initialize(config, cluster: {}, base_directory: Dir.pwd, env: ENV, stdin: $stdin, stderr: $stderr,
                     timeout: DEFAULT_TIMEOUT)
        @config = config
        @cluster = cluster
        @base_directory = base_directory
        @env = env
        @stdin = stdin
        @stderr = stderr
        @timeout = timeout
        validate_config!
      end

      def cache_key
        [@config, @cluster, @base_directory].hash
      end

      def call
        result = parse(run_plugin)
        observe("no_error", 0, certificate_ttl(result))
        result
      end

      private

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
        reader, writer = IO.pipe
        pid = Process.spawn(child_env, [executable, executable], *arguments,
                            in: interactive ? @stdin : File::NULL, out: writer, err: @stderr, close_others: true)
        writer.close
        collect(pid, reader)
      rescue Errno::ENOENT, Errno::EACCES => error
        observe("plugin_not_found_error", 1)
        raise UnsupportedCredentialError, ["exec plugin #{command.inspect} cannot be started: #{error.message}",
                                           @config["installHint"]].compact.join("\n")
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
        _, status = Process.wait2(pid)
        return output if status.success?

        observe("plugin_execution_error", status.exitstatus || 1)
        raise UnsupportedCredentialError, "exec plugin #{command.inspect} failed with #{status.to_s.sub(/\Apid \d+ /, "")}"
      end

      def observe(status, code, ttl = nil)
        self.class.observer&.call(status, code, ttl)
      end

      def certificate_ttl(result)
        return Float::INFINITY unless result.client_certificate_data

        OpenSSL::X509::Certificate.new(result.client_certificate_data).not_after - Time.now
      rescue OpenSSL::X509::CertificateError
        fail_output("returned a client certificate that is not PEM")
      end

      def abort_plugin(pid, reason)
        Process.kill("KILL", pid)
        Process.wait(pid)
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
        fail_output("returned neither a token nor a client certificate") if token.nil? && certificate.nil? && key.nil?
        fail_output("returned a client certificate without its key (or the reverse)") if certificate.nil? != key.nil?

        Result.new(bearer_token: token, client_certificate_data: certificate, client_key_data: key,
                   expires_at: expiry(status["expirationTimestamp"])).freeze
      end

      def expiry(value)
        value && Time.iso8601(value)
      rescue ArgumentError
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
