#!/usr/bin/env ruby
# frozen_string_literal: true

# Shared, fail-closed machinery for the M3 control-loop evidence probes.
#
# The probes are intentionally small adapters around project-owned production
# classes.  They do not manufacture a successful report when a controller,
# scheduler, informer, or queue is unavailable.  A report is only marked PASS
# after the production object has been exercised and the source input has been
# shown to be stable for the complete measurement.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "time"

require File.expand_path("../../lib/rubernetes/version", __dir__)

module M3ProbeSupport
  ROOT = File.expand_path("../..", __dir__).freeze
  SOURCE_EXCLUSIONS = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/}
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"

  module_function

  def source_identity
    paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
      next false unless File.file?(path)

      relative = path.delete_prefix("#{ROOT}/")
      !relative.match?(SOURCE_EXCLUSIONS)
    end.sort
    entries = paths.map do |path|
      {
        "path" => path.delete_prefix("#{ROOT}/"),
        "sha256" => Digest::SHA256.file(path).hexdigest,
        "bytes" => File.size(path)
      }
    end
    {"sha256" => canonical_inventory_digest(entries), "file_count" => entries.length, "entries" => entries}
  end

  def canonical_inventory_digest(entries)
    content = entries.sort_by { |entry| entry.fetch("path") }.map do |entry|
      "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n"
    end.join
    Digest::SHA256.hexdigest(content)
  end

  def canonical_document_digest(document, excluded_keys: [])
    Digest::SHA256.hexdigest(JSON.generate(canonical_value(document, excluded_keys.map(&:to_s))))
  end

  def canonical_value(value, excluded_keys = [])
    excluded = excluded_keys.map(&:to_s)
    case value
    when Hash
      value.keys.map(&:to_s).reject { |key| excluded.include?(key) }.sort.each_with_object({}) do |key, result|
        source_key = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical_value(value.fetch(source_key), [])
      end
    when Array
      value.map { |child| canonical_value(child, []) }
    when String
      text_value(value)
    else
      value
    end
  end

  # Kernel readback (nftables rule userdata, packet bytes) can carry raw
  # bytes; canonical JSON must stay valid UTF-8, so non-text bytes become a
  # tagged hex string on both the digest and the written report.
  def text_value(value)
    return value if value.encoding == Encoding::UTF_8 && value.valid_encoding?

    utf8 = value.dup.force_encoding(Encoding::UTF_8)
    utf8.valid_encoding? ? utf8 : "hex:#{value.unpack1("H*")}"
  end

  def valid_digest?(value)
    value.is_a?(String) && value.match?(SHA256_PATTERN)
  end

  def iso8601_now
    Time.now.utc.iso8601(6)
  end

  def project_git_metadata_paths
    Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).filter_map do |path|
      relative = path.delete_prefix("#{ROOT}/")
      next unless relative.split("/").include?(".git")

      relative
    end.sort.uniq
  end

  # Load the public package and any newly-added production modules.  Loading
  # files by path keeps this lane compatible with parallel milestone work while
  # still refusing to treat a probe helper or a test double as production code.
  def load_production!
    $LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
    require "rubernetes"
    # Aggregators establish dependency order for the scheduler, proxy, and
    # volume packages; loading their children alphabetically would load
    # framework.rb before scores.rb and produce a misleading missing constant.
    %w[controller watch scheduler proxy volume].each do |package|
      require "rubernetes/#{package}"
    rescue LoadError, NameError
      # The caller will fail closed when the requested production class is
      # absent. Unrelated optional packages must not mask that diagnosis.
    end
    %w[network service storage].each do |directory|
      Dir.glob(File.join(ROOT, "lib", "rubernetes", directory, "*.rb")).each do |path|
        require path
      rescue LoadError, NameError
        # Probe-specific production availability is checked below.
      end
    end
    true
  end

  def constant(path)
    path.to_s.split("::").reject(&:empty?).reduce(Object) { |owner, name| owner.const_get(name, false) }
  rescue NameError
    nil
  end

  def first_constant(paths)
    Array(paths).find { |path| constant(path) }
  end

  def production_class?(value)
    value.is_a?(Class) || value.is_a?(Module)
  end

  def production_candidates(names, required_methods: [])
    Array(names).filter_map do |name|
      value = constant(name)
      next unless production_class?(value)
      next unless Array(required_methods).all? do |method_name|
        value.method_defined?(method_name.to_sym) || value.respond_to?(method_name.to_sym)
      end

      [name, value]
    end
  end

  # Call a production adapter across the small set of keyword/positional
  # signatures used by the project.  Argument-shape failures are retried with
  # the next documented shape; an adapter's own failure is propagated.
  def invoke(target, method_name, positional: [], keywords: {})
    callable = target.respond_to?(method_name) ? target.method(method_name) : nil
    raise NoMethodError, "production adapter does not implement ##{method_name}" unless callable

    attempts = []
    attempts << -> { callable.call(*positional, **keywords) } unless keywords.empty?
    attempts << -> { callable.call(*positional) }
    attempts << -> { callable.call(**keywords) } unless keywords.empty?
    # Some production namespaces expose a phase helper as a module method with
    # no arguments while the instance API accepts pod/node snapshots. Keep the
    # no-argument form as a final shape fallback; required-argument adapters
    # still propagate their ArgumentError when no shape matches.
    attempts << -> { callable.call }
    last_shape_error = nil
    attempts.each do |attempt|
      return attempt.call
    rescue ArgumentError => error
      last_shape_error = error
    end
    raise(last_shape_error || ArgumentError.new("unable to call ##{method_name}"))
  end

  def instantiate(klass, keyword_sets: [], positional_sets: [[]])
    Array(keyword_sets).each do |keywords|
      return klass.new(**keywords)
    rescue ArgumentError
      next
    end
    Array(positional_sets).each do |positional|
      return klass.new(*positional)
    rescue ArgumentError
      next
    end
    klass.new
  end

  def normalize(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source_key = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = normalize(value.fetch(source_key))
      end
    when Array
      value.map { |child| normalize(child) }
    when Time
      value.utc.iso8601(6)
    when Symbol
      value.to_s
    when String
      text_value(value)
    else
      # Nil responds to #to_h in Ruby (returning {}), but JSON null is a
      # meaningful transported value and must remain null for provenance
      # digests and independent oracle comparisons.
      !value.nil? && value.respond_to?(:to_h) && !value.is_a?(String) ? normalize(value.to_h) : value
    end
  end

  def digest(value)
    canonical_document_digest(normalize(value))
  end

  # Execute an explicitly configured external oracle or chaos runner and
  # decode only the JSON it wrote to stdout.  A Ruby probe must never turn its
  # own digest or a boolean supplied by the adapter into independent evidence;
  # the caller therefore has to provide runner provenance in the returned
  # document and gates validate that provenance separately.
  def run_external_json(env_keys:, input:, errors:, label:, default_command: nil, evidence_mode: false, capture: false)
    key = Array(env_keys).find { |candidate| ENV.key?(candidate) && !ENV.fetch(candidate).strip.empty? }
    built_in = Array(default_command).map(&:to_s)
    if evidence_mode
      if built_in.empty?
        errors << "#{label} built-in command is unavailable"
        return capture ? {"document" => nil, "execution" => nil} : nil
      end
      if key && Shellwords.split(ENV.fetch(key)) != built_in
        errors << "#{label} custom command override is forbidden in evidence mode"
        return capture ? {"document" => nil, "execution" => nil} : nil
      end
      command = built_in
    else
      command = if key
                  Shellwords.split(ENV.fetch(key))
                elsif default_command
                  built_in
                else
                  errors << "#{label} command is unavailable; set #{Array(env_keys).join(" or ")}"
                  return capture ? {"document" => nil, "execution" => nil} : nil
                end
    end
    if command.empty?
      errors << "#{label} command is empty"
      return capture ? {"document" => nil, "execution" => nil} : nil
    end

    # The transcript is bound to the reported input payload by byte equality
    # after the report is normalised (sorted keys), so the bytes piped to the
    # oracle are generated from the canonical form of the input.
    input_bytes = JSON.generate(canonical_value(input))
    stdout, stderr, status = Open3.capture3(*command, stdin_data: input_bytes, chdir: ROOT)
    execution = {
      "argv" => command,
      "stdin" => input_bytes,
      "stdin_sha256" => Digest::SHA256.hexdigest(input_bytes),
      "stdout" => stdout.to_s,
      "stdout_sha256" => Digest::SHA256.hexdigest(stdout.to_s),
      "stderr" => stderr.to_s,
      "stderr_sha256" => Digest::SHA256.hexdigest(stderr.to_s),
      "exit_status" => status.exitstatus,
      "success" => status.success?,
      "built_in" => built_in,
      "override_key" => key,
      "evidence_mode" => evidence_mode
    }
    unless status.success?
      detail = stderr.to_s.strip
      detail = "exit status #{status.exitstatus || 1}" if detail.empty?
      errors << "#{label} command failed: #{detail}"
      return capture ? {"document" => nil, "execution" => execution} : nil
    end
    if stdout.to_s.strip.empty?
      errors << "#{label} command returned no JSON"
      return capture ? {"document" => nil, "execution" => execution} : nil
    end

    document = JSON.parse(stdout, max_nesting: 512)
    capture ? {"document" => document, "execution" => execution} : document
  rescue ArgumentError => error
    errors << "#{label} command is invalid: #{error.message}"
    capture ? {"document" => nil, "execution" => nil} : nil
  rescue JSON::ParserError => error
    errors << "#{label} returned invalid JSON: #{error.message}"
    capture ? {"document" => nil, "execution" => nil} : nil
  rescue SystemCallError => error
    errors << "#{label} command could not be executed: #{error.message}"
    capture ? {"document" => nil, "execution" => nil} : nil
  end

  def report_runner_sha256
    Digest::SHA256.file($PROGRAM_NAME == "-" ? __FILE__ : $PROGRAM_NAME).hexdigest
  rescue Errno::ENOENT, TypeError
    Digest::SHA256.file(__FILE__).hexdigest
  end

  def run_report(kind:, adapter_name:, measurement_level: "L3", milestone: "M3", input_env_prefix: "RUBERNETES_M3", load_production: true)
    started_at = iso8601_now
    started_input = source_identity
    errors = []
    begin
      expected_sha = ENV.fetch("#{input_env_prefix}_INPUT_SHA256", nil)
      expected_count = ENV["#{input_env_prefix}_INPUT_FILE_COUNT"]&.to_i
      errors << "source input changed before probe execution" if expected_sha && expected_sha != started_input.fetch("sha256")
      if expected_count && expected_count.positive? && expected_count != started_input.fetch("file_count")
        errors << "source input file count changed before probe execution"
      end
      load_production! if errors.empty? && load_production
      payload = errors.empty? ? yield(started_input, errors) : {}
      payload = {} unless payload.is_a?(Hash)
    rescue StandardError => error
      payload = {}
      errors << "production measurement failed: #{error.class}: #{error.message}"
    end
    finished_input = source_identity
    input_stable = started_input.fetch("sha256") == finished_input.fetch("sha256") &&
                   started_input.fetch("file_count") == finished_input.fetch("file_count")
    errors << "source input changed during probe execution" unless input_stable
    runner_sha256 = report_runner_sha256
    provenance = {
      "source_sha256" => started_input.fetch("sha256"),
      "source_file_count" => started_input.fetch("file_count"),
      "runner_sha256" => runner_sha256,
      "command" => [RbConfig.ruby, File.basename($PROGRAM_NAME)],
      "process_id" => Process.pid,
      "measurement_id" => "#{kind}:#{started_input.fetch("sha256")[0, 16]}:#{Process.pid}",
      "started_at" => started_at,
      "finished_at" => iso8601_now
    }
    provenance["provenance_sha256"] = canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
    report = {
      "schema_version" => 1,
      "milestone" => milestone,
      "kind" => kind,
      "input_sha256" => started_input.fetch("sha256"),
      "input_file_count" => started_input.fetch("file_count"),
      "input_stable" => input_stable,
      "input_capture" => {
        "stable" => input_stable,
        "start" => {"sha256" => started_input.fetch("sha256"), "file_count" => started_input.fetch("file_count")},
        "finish" => {"sha256" => finished_input.fetch("sha256"), "file_count" => finished_input.fetch("file_count")}
      },
      "measurement_level" => measurement_level,
      "measurement_source" => payload.delete("measurement_source") || "production_module",
      "adapter" => {
        "name" => adapter_name,
        "version" => Rubernetes::VERSION,
        "runner_sha256" => runner_sha256
      },
      "provenance" => provenance,
      "started_at" => started_at,
      "finished_at" => iso8601_now,
      "attempt_count" => 1,
      "retry_count" => 0,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "flake_count" => 0,
      "failure_count" => errors.length,
      "errors" => errors,
      "available" => errors.empty?,
      "status" => errors.empty? ? "PASS" : "INCOMPLETE",
      "passed" => errors.empty?
    }.merge(payload)
    # Reassert fields that a production adapter must never be able to spoof.
    report["failure_count"] = errors.length
    report["errors"] = errors
    report["status"] = errors.empty? ? "PASS" : "INCOMPLETE"
    report["passed"] = errors.empty?
    # The written document and its digest must agree byte for byte, so the
    # report is normalized (binary-safe strings, sorted keys) before either.
    report = normalize(report)
    report["report_sha256"] = canonical_document_digest(report, excluded_keys: ["report_sha256"])
    puts(JSON.pretty_generate(report))
    exit(errors.empty? ? 0 : 1)
  end
end
