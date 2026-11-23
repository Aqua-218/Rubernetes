# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require "timeout"

module Rubernetes
  module Manifest
    class Sandbox
      DEFAULT_TIMEOUT = 5
      DEFAULT_MAX_OUTPUT = 16 * 1024 * 1024
      DEFAULT_MAX_RESOURCES = 10_000
      FRAME_BYTES = 8

      def initialize(registry_path:, openapi_path:, timeout: DEFAULT_TIMEOUT,
                     max_output: DEFAULT_MAX_OUTPUT, max_resources: DEFAULT_MAX_RESOURCES)
        @registry_path = File.expand_path(registry_path)
        @openapi_path = File.expand_path(openapi_path)
        @timeout = Float(timeout)
        @max_output = Integer(max_output)
        @max_resources = Integer(max_resources)
      end

      # Resources alone are returned. The optional block receives the matching
      # declaration lines kept outside the Kubernetes object mappings.
      def compile(path, allow_code:, environment: [], env: ENV)
        raise Error, "Ruby manifests require --allow-code" unless allow_code

        manifest_path = File.expand_path(path)
        unless File.file?(manifest_path) && File.readable?(manifest_path)
          raise Error,
                "manifest must be a readable regular file: #{manifest_path}"
        end

        inherited_environment = environment.to_h do |name|
          raise Error, "invalid environment variable name #{name.inspect}" unless String(name).match?(/\A[A-Z_][A-Z0-9_]*\z/)

          [String(name), env.fetch(String(name))]
        end
        output, error, status = run_worker(manifest_path, inherited_environment)
        raise Error, "manifest sandbox failed: #{sanitize_error(error)}" unless status.success?
        raise Error, "manifest sandbox returned a truncated frame" if output.bytesize < FRAME_BYTES

        length = output.byteslice(0, FRAME_BYTES).unpack1("Q>")
        payload = output.byteslice(FRAME_BYTES, output.bytesize - FRAME_BYTES)
        raise Error, "manifest output exceeds #{@max_output} bytes" if length > @max_output
        raise Error, "manifest sandbox frame length mismatch" unless payload.bytesize == length

        compiled = JSON.parse(payload, max_nesting: 512)
        raise Error, "manifest sandbox output must be an object" unless compiled.is_a?(Hash)

        resources = compiled["resources"]
        raise Error, "manifest output must be an array" unless resources.is_a?(Array)
        raise Error, "manifest output exceeds #{@max_resources} resources" if resources.length > @max_resources

        lines = compiled["declarationLines"]
        unless lines.is_a?(Array) && lines.size == resources.size && lines.all? { |line| line.nil? || (line.is_a?(Integer) && line.positive?) }
          raise Error, "manifest sandbox returned invalid declaration lines"
        end

        yield lines if block_given?
        resources
      rescue Timeout::Error
        raise Error, "manifest sandbox exceeded #{@timeout} seconds"
      rescue JSON::ParserError => error
        raise Error.new("manifest sandbox returned invalid JSON: #{error.message}"), cause: error
      end

      private

      def run_worker(manifest_path, environment)
        entry = File.expand_path("sandbox_entry.rb", __dir__)
        worker = File.expand_path("worker.rb", __dir__)
        command = [
          "/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork", "--kill-child",
          RbConfig.ruby, entry,
          "--manifest", manifest_path,
          "--registry", @registry_path,
          "--openapi", @openapi_path,
          "--worker", worker,
          "--library", File.expand_path("../..", __dir__),
          "--ruby-prefix", RbConfig::CONFIG.fetch("prefix"),
          "--ruby-executable", RbConfig.ruby,
          "--max-output", @max_output.to_s,
          "--max-resources", @max_resources.to_s
        ]
        Dir.mktmpdir("rubernetes-manifest-root-") do |root|
          Open3.popen3(environment, *command, "--root", root, unsetenv_others: true, pgroup: true) do |input, output, errors, child|
            input.close
            Timeout.timeout(@timeout) { [*read_output(output, errors), child.value] }
          rescue Timeout::Error, Error
            # Stop the unshare process and its children before Open3 waits for
            # them. The namespace dies with its init, including descendants.
            begin
              Process.kill("KILL", -child.pid)
            rescue Errno::ESRCH
              # The worker may already have delivered its final bytes and exited.
            end
            raise
          end
        end
      rescue Errno::ENOENT => error
        raise Error.new("manifest sandbox requires Linux unshare: #{error.message}"), cause: error
      end

      def read_output(output, errors)
        streams = [output, errors]
        frame = +"".b
        detail = +"".b
        until streams.empty?
          IO.select(streams).first.each do |stream|
            chunk = stream.read_nonblock(16_384, exception: false)
            if chunk.nil?
              streams.delete(stream)
            elsif chunk == :wait_readable
              next
            elsif stream == output
              frame << chunk
              raise Error, "manifest output exceeds #{@max_output} bytes" if frame.bytesize > @max_output + FRAME_BYTES
            elsif detail.bytesize < 4096
              detail << chunk.byteslice(0, 4096 - detail.bytesize)
            end
          end
        end
        [frame, detail]
      end

      def sanitize_error(error)
        error.to_s.lines.first.to_s.strip.gsub(%r{/(?:home|root)/[^\s:]+}, "[redacted-path]")[0, 512]
      end
    end
  end
end
