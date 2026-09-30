#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "etc"
require "json"
require "open3"
require "rbconfig"
require "rexml/document"
require "rubygems/package"
require "stringio"
require "time"
require "zlib"
require_relative "m0_source_inventory"

module M0Gate
  MAX_JSON_BYTES = 16 * 1024 * 1024
  MAX_EVIDENCE_AGE_SECONDS = 24 * 60 * 60
  MAX_CAPTURE_DURATION_SECONDS = 6 * 60 * 60
  MAX_FUTURE_SKEW_SECONDS = 5 * 60
  SHA256 = /\A[0-9a-f]{64}\z/
  EXECUTABLES = %w[rubectl rubernetes-apiserver rubernetes-controller-manager rubernetes-scheduler rubernetes-agent rubernetes-proxy].freeze
  OPTIONS = %w[--help --version].freeze
  COMMANDS = %w[gem_build rake_test executables native_boundary_scan rbs_validate kernel_probe_x86_64].freeze
  ARTIFACTS = %w[abi-probe-x86_64.json executables.json gem-build.json junit.xml native-boundary-scan.json source-inventory.json].freeze
  ABI_PROBES = %w[abi_manifest clone3_pid_namespace_mount_proc_pidfd_wait netlink_ack bpf_verifier kvm_capability errno_clone3 errno_pidfd
                  errno_mount errno_netlink errno_bpf errno_kvm errno_namespace_exec source_input_stability].freeze
  ERRNO_PROBES = {
    "errno_clone3" => ["clone3", "intentional:clone3"],
    "errno_pidfd" => ["pidfd_open", "intentional:pidfd"],
    "errno_mount" => ["mount", "intentional:mount"],
    "errno_netlink" => ["netlink_ack", "intentional:netlink"],
    "errno_bpf" => ["bpf(BPF_PROG_LOAD)", "intentional:bpf"],
    "errno_kvm" => ["kvm_probe", "intentional:kvm"],
    "errno_namespace_exec" => ["execve", "intentional:namespace-exec"]
  }.freeze
  ROOT = File.expand_path("../..", __dir__).freeze
  NATIVE_FORBIDDEN = {
    "authorization" => /\bauthori[sz](?:e|ation)\b/i,
    "retry" => /\b(?:retry|backoff)\b/i,
    "state_machine" => /\bstate[_ ]?machine\b/i,
    "orchestration_policy" => /\b(?:reconcile|scheduler|admission|policy_decision)\b/i
  }.freeze
  JUNIT_REPORTER_PATH = "test/support/junit_reporter.rb"
  MINITEST_INVENTORY_TOOL = "tools/milestones/m0_test_inventory.rb"

  class DuplicateJSONKeyError < StandardError; end

  class StrictHash < Hash
    def []=(key, value)
      raise DuplicateJSONKeyError, "duplicate JSON object key #{key.inspect}" if key?(key)

      super
    end
  end

  class << self
    def evaluate(manifest_path)
      manifest_path = File.expand_path(manifest_path)
      directory = File.dirname(manifest_path)
      errors = []
      manifest = parse_json(manifest_path, errors, "manifest")
      return result(errors) unless manifest.is_a?(Hash)

      validate_manifest(manifest, errors)
      validate_command_bindings(manifest, directory, errors)
      artifacts = validate_entries(manifest["artifacts"], directory, errors, "artifact")
      subjects = validate_entries(manifest["subjects"], directory, errors, "subject")
      artifact_index = artifacts.to_h { |entry| [File.basename(entry.fetch("path")), entry] }

      validate_required_artifacts(artifacts, errors)
      inventory = artifact_json(directory, artifact_index, "source-inventory.json", errors)
      validate_inventory(inventory, manifest, errors)
      validate_gem_build(artifact_json(directory, artifact_index, "gem-build.json", errors), manifest, subjects, directory, errors)
      validate_executables(artifact_json(directory, artifact_index, "executables.json", errors), subjects, manifest, directory, errors)
      validate_native_scan(artifact_json(directory, artifact_index, "native-boundary-scan.json", errors), inventory, manifest, directory,
                           errors)
      validate_abi(artifact_json(directory, artifact_index, "abi-probe-x86_64.json", errors), manifest, subjects, inventory, directory,
                   errors)
      validate_junit(directory, artifact_index, manifest, inventory, errors)
      validate_subjects(subjects, errors)
      validate_result_counts(manifest, artifacts, subjects, errors)
      result(errors)
    rescue Errno::ENOENT => error
      result(["evidence file is missing: #{error.message}"])
    rescue StandardError => error
      result(["gate could not validate evidence bundle: #{error.class}: #{error.message}"])
    end

    private

    def result(errors)
      {"schema_version" => 1, "milestone" => "M0", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors}
    end

    def parse_json(path, errors, label)
      if File.size(path) > MAX_JSON_BYTES
        errors << "#{label} exceeds the #{MAX_JSON_BYTES}-byte JSON limit"
        return nil
      end
      JSON.parse(File.binread(path), object_class: StrictHash, max_nesting: 100)
    rescue Errno::ENOENT
      errors << "#{label} is missing"
      nil
    rescue JSON::ParserError, DuplicateJSONKeyError => error
      errors << "#{label} is not valid JSON: #{error.message}"
      nil
    end

    def validate_manifest(manifest, errors)
      errors << "schema_version must be 3" unless manifest["schema_version"] == 3
      errors << "milestone must be M0" unless manifest["milestone"] == "M0"
      errors << "manifest status must be COMPLETE" unless manifest["status"] == "COMPLETE"
      errors << "input_sha256 must be a SHA-256 digest" unless digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless positive_integer?(manifest["input_file_count"])
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true

      host = manifest["host"]
      current_architecture = RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64").sub("amd64", "x86_64")
      current_uname = Etc.uname
      unless host.is_a?(Hash) && host["architecture"] == current_architecture && %w[kernel sysname ruby].all? { |key| nonempty?(host[key]) }
        errors << "host must identify Linux x86_64, kernel, and Ruby"
      end
      if host.is_a?(Hash)
        errors << "host sysname must be Linux" unless host["sysname"] == "Linux"
        errors << "host architecture does not match the current Ruby host" unless host["architecture"] == current_architecture
        errors << "host kernel does not match the current host" unless host["kernel"] == current_uname[:release]
        errors << "host Ruby does not match the current interpreter" unless host["ruby"] == RUBY_DESCRIPTION
      end
      %w[started_at finished_at].each { |key| validate_time(manifest[key], errors, key) }
      manifest_started = parse_time(manifest["started_at"])
      manifest_finished = parse_time(manifest["finished_at"])
      errors << "manifest time interval is invalid" if manifest_started && manifest_finished && manifest_finished < manifest_started
      now = Time.now.utc
      if manifest_started && manifest_finished
        errors << "evidence capture duration exceeds the M0 bound" if manifest_finished - manifest_started > MAX_CAPTURE_DURATION_SECONDS
        errors << "evidence capture is stale" if now - manifest_finished > MAX_EVIDENCE_AGE_SECONDS
        if manifest_started > now + MAX_FUTURE_SKEW_SECONDS || manifest_finished > now + MAX_FUTURE_SKEW_SECONDS
          errors << "evidence capture is in the future"
        end
      end

      capture = manifest["input_capture"]
      identity = {"sha256" => manifest["input_sha256"], "file_count" => manifest["input_file_count"]}
      unless capture.is_a?(Hash) && capture["stable"] == true && capture["start"] == identity && capture["finish"] == identity
        errors << "input_capture must contain identical stable manifest identities"
      end

      commands = manifest["commands"]
      unless commands.is_a?(Array)
        errors << "commands must be an array"
        return
      end
      names = commands.filter_map { |command| command["name"] if command.is_a?(Hash) }
      errors << "required command inventory differs" unless names.sort == COMMANDS.sort && names.uniq.length == names.length
      errors << "required commands are not in the monotonic evidence sequence" unless names == COMMANDS
      previous_finished = manifest_started
      commands.each do |command|
        unless command.is_a?(Hash)
          errors << "command entries must be objects"
          next
        end
        errors << "command #{command["name"].inspect} must exit zero" unless command["exit_status"] == 0
        errors << "command #{command["name"].inspect} argv must be non-empty" unless command["command"].is_a?(Array) && command["command"].all? do |value|
          nonempty?(value)
        end
        validate_time(command["started_at"], errors, "command #{command["name"]} started_at")
        validate_time(command["finished_at"], errors, "command #{command["name"]} finished_at")
        command_started = parse_time(command["started_at"])
        command_finished = parse_time(command["finished_at"])
        if command_started && command_finished && command_finished < command_started
          errors << "command #{command["name"].inspect} time interval is invalid"
        end
        if previous_finished && command_started && command_started < previous_finished
          errors << "command #{command["name"].inspect} starts before the previous command finished"
        end
        if manifest_started && command_started && command_started < manifest_started
          errors << "command #{command["name"].inspect} starts before the evidence capture"
        end
        if manifest_finished && command_finished && command_finished > manifest_finished
          errors << "command #{command["name"].inspect} finishes after the evidence capture"
        end
        previous_finished = command_finished if command_finished
      end
      validate_command_argv(commands, errors)
    end

    def validate_command_bindings(manifest, directory, errors)
      commands = Array(manifest["commands"]).grep(Hash)
      index = commands.to_h { |entry| [entry["name"], entry] }
      captured = capture_directory(manifest) || directory
      output_path = lambda do |name|
        command = index[name]
        value = command && Array(command["command"]).last
        path = value.to_s
        resolved = safe_evidence_path(directory, rebase_evidence_path(path, manifest, directory))
        errors << "command #{name} output path is not a regular file in the evidence directory" unless resolved && File.file?(resolved)
        errors << "command #{name} output path was captured outside the run directory" unless path.start_with?("#{captured}/")
        resolved ? path : nil
      end
      expected = {
        "gem_build" => ["gem", "build", "rubernetes.gemspec", "--output", output_path.call("gem_build")],
        "rake_test" => %w[bundle exec rake test],
        "executables" => [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", File.join(captured, "executables.json")],
        "native_boundary_scan" => [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output",
                                   File.join(captured, "native-boundary-scan.json")],
        "rbs_validate" => ["bundle", "exec", "rbs", "-I", "sig", "-I", "generated/rbs", "validate"],
        "kernel_probe_x86_64" => [RbConfig.ruby, "-I#{File.join(ROOT, "build/ext/rubernetes_linux")}",
                                  "tools/milestones/m0_kernel_probe.rb", "--output", File.join(captured, "abi-probe-x86_64.json")]
      }
      expected.each do |name, argv|
        actual = Array(index.dig(name, "command"))
        next if name == "gem_build" && argv.last.nil?

        errors << "command #{name} argv is not the exact captured command" unless actual == argv
      end

      rake = index["rake_test"]
      unless rake.is_a?(Hash) && rake["environment"].is_a?(Hash) && rake.dig("environment",
                                                                             "RUBERNETES_JUNIT") == File.join(captured, "junit.xml")
        errors << "rake_test must bind RUBERNETES_JUNIT to the captured junit.xml"
      end

      tool_paths = {
        "gem_build" => "rubernetes.gemspec",
        "rake_test" => "Gemfile",
        "executables" => "tools/milestones/executables_probe.rb",
        "native_boundary_scan" => "tools/milestones/native_boundary_scan.rb",
        "rbs_validate" => "Gemfile",
        "kernel_probe_x86_64" => "tools/milestones/m0_kernel_probe.rb"
      }
      tool_paths.each do |name, relative|
        command = index[name]
        expected_path = File.join(ROOT, relative)
        expected_hash = File.file?(expected_path) ? Digest::SHA256.file(expected_path).hexdigest : nil
        unless command.is_a?(Hash) && command["tool_path"] == relative && digest?(command["tool_sha256"]) && command["tool_sha256"] == expected_hash
          errors << "command #{name} is not bound to the current tool #{relative}"
        end
      end
    end

    def validate_command_argv(commands, errors)
      index = commands.grep(Hash).to_h { |entry| [entry["name"], Array(entry["command"])] }
      expected_tokens = {
        "gem_build" => ["gem", "build", "rubernetes.gemspec", "--output"],
        "rake_test" => %w[bundle exec rake test],
        "executables" => ["tools/milestones/executables_probe.rb", "--output"],
        "native_boundary_scan" => ["tools/milestones/native_boundary_scan.rb", "--output"],
        "rbs_validate" => ["bundle", "exec", "rbs", "-I", "sig", "-I", "generated/rbs", "validate"],
        "kernel_probe_x86_64" => ["tools/milestones/m0_kernel_probe.rb", "--output"]
      }
      expected_tokens.each do |name, tokens|
        argv = index.fetch(name, [])
        errors << "command #{name} does not execute the required adapter" unless tokens.all? { |token| argv.include?(token) }
      end
    end

    def validate_entries(value, directory, errors, label)
      unless value.is_a?(Array)
        errors << "#{label}s must be an array"
        return []
      end
      paths = []
      value.filter_map do |entry|
        unless entry.is_a?(Hash) && nonempty?(entry["path"])
          errors << "#{label} entry must contain a path"
          next
        end
        relative = entry["path"]
        errors << "duplicate #{label} path #{relative}" if paths.include?(relative)
        paths << relative
        path = safe_file(directory, relative)
        unless path
          errors << "#{label} escapes evidence directory #{relative}"
          next entry
        end
        errors << "#{label} sha256 is invalid #{relative}" unless digest?(entry["sha256"])
        errors << "#{label} byte count is invalid #{relative}" unless nonnegative_integer?(entry["bytes"])
        errors << "subject source_path is required #{relative}" if label == "subject" && !nonempty?(entry["source_path"])
        if File.file?(path) && !File.symlink?(path) && File.lstat(path).file?
          errors << "#{label} digest mismatch #{relative}" unless Digest::SHA256.file(path).hexdigest == entry["sha256"]
          errors << "#{label} byte count mismatch #{relative}" unless File.size(path) == entry["bytes"]
        else
          errors << "missing #{label} #{relative}"
        end
        entry
      end
    end

    def safe_file(directory, relative)
      return nil unless relative.is_a?(String) && !relative.empty? && !relative.start_with?("/")

      parts = relative.split("/")
      return nil if parts.any? { |part| part.empty? || part == "." || part == ".." }
      return nil if relative.include?("\0")
      return nil unless no_symlink_parents?(directory)

      expanded = File.expand_path(relative, directory)
      root = File.realpath(directory)
      return nil unless expanded.start_with?("#{root}/")
      return nil unless safe_component_chain?(root, expanded)

      expanded
    rescue Errno::ENOENT
      expanded
    end

    # The directory the run captured into (artifacts/milestones/M0/<run-id>).
    # Command identities are bound to it; a bundle copied into a later
    # milestone's evidence keeps those identities while its files are
    # checked where they now live.
    def capture_directory(manifest)
      run_id = manifest.is_a?(Hash) ? manifest["run_id"].to_s : ""
      return nil if run_id.empty? || run_id.include?("/") || run_id.include?("\0") || run_id.start_with?(".")

      File.join(ROOT, "artifacts/milestones/M0", run_id)
    end

    def rebase_evidence_path(value, manifest, directory)
      captured = capture_directory(manifest)
      path = value.to_s
      return path if captured.nil? || !path.start_with?("#{captured}/")

      File.join(directory, path.delete_prefix("#{captured}/"))
    end

    def safe_evidence_path(directory, value)
      return nil unless value.is_a?(String) && !value.empty? && !value.include?("\0")
      return nil unless no_symlink_parents?(directory)

      root = File.realpath(directory)
      expanded = File.expand_path(value, directory)
      return nil unless expanded.start_with?("#{root}/")

      relative = expanded.delete_prefix("#{root}/")
      safe_file(directory, relative)
    rescue Errno::ENOENT
      nil
    end

    def safe_component_chain?(root, path)
      current = root
      return false if File.symlink?(current)

      path.delete_prefix("#{root}/").split("/").each do |component|
        next if component.empty? || component == "."

        current = File.join(current, component)
        stat = File.lstat(current)
        return false if stat.symlink?
      rescue Errno::ENOENT
        # A missing final component is allowed so the caller can report a
        # precise missing-artifact error. Existing parent components have
        # already been checked above.
        return true
      end
      true
    rescue Errno::ENOENT
      false
    end

    def no_symlink_parents?(path)
      expanded = File.expand_path(path)
      current = File::SEPARATOR
      expanded.delete_prefix(File::SEPARATOR).split(File::SEPARATOR).each do |component|
        next if component.empty?

        current = File.join(current, component)
        stat = File.lstat(current)
        return false if stat.symlink?
      rescue Errno::ENOENT
        return true
      end
      true
    rescue Errno::ENOENT
      false
    end

    def validate_required_artifacts(artifacts, errors)
      names = artifacts.map { |entry| File.basename(entry.fetch("path")) }
      errors << "required artifact inventory differs" unless names.sort == ARTIFACTS.sort && names.uniq.length == names.length
    end

    def artifact_json(directory, index, name, errors)
      entry = index[name]
      unless entry
        errors << "#{name} is missing"
        return nil
      end
      path = safe_file(directory, entry.fetch("path"))
      path ? parse_json(path, errors, name) : nil
    end

    def validate_inventory(document, manifest, errors)
      unless document.is_a?(Hash) && document["schema_version"] == 1 && document["kind"] == "m0_source_inventory"
        errors << "source inventory schema is invalid"
        return
      end
      entries = document["entries"]
      unless entries.is_a?(Array) && entries.length == manifest["input_file_count"]
        errors << "source inventory count differs from manifest"
        return
      end
      paths = []
      entries.each do |entry|
        unless entry.is_a?(Hash) && safe_source_path?(entry["path"]) && digest?(entry["sha256"]) && nonnegative_integer?(entry["bytes"])
          errors << "source inventory contains an invalid entry"
          next
        end
        errors << "source inventory contains duplicate path #{entry["path"]}" if paths.include?(entry["path"])
        paths << entry["path"]
      end
      canonical = entries.sort_by do |entry|
        entry.fetch("path", "")
      end.map { |entry| "#{entry.fetch("path", "")}\0#{entry.fetch("sha256", "")}\n" }.join
      computed = Digest::SHA256.hexdigest(canonical)
      errors << "source inventory digest differs from manifest" unless computed == manifest["input_sha256"]
      unless document["input_sha256"] == computed && document["input_file_count"] == entries.length
        errors << "source inventory self identity differs"
      end

      current = current_source_inventory
      return if current && current["entries"] == entries

      errors << "source inventory does not match the current source tree"
    end

    def current_source_inventory
      return nil unless no_symlink_parents?(ROOT)

      paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
        relative = path.delete_prefix("#{ROOT}/")
        next false if M0SourceInventory.excluded?(relative)

        begin
          File.lstat(path).file? && safe_component_chain?(ROOT, path)
        rescue Errno::ENOENT
          false
        end
      end.sort
      entries = paths.map do |path|
        {
          "path" => path.delete_prefix("#{ROOT}/"),
          "sha256" => Digest::SHA256.file(path).hexdigest,
          "bytes" => File.size(path)
        }
      end
      content = entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
      {"sha256" => Digest::SHA256.hexdigest(content), "file_count" => entries.length, "entries" => entries}
    rescue StandardError
      nil
    end

    def validate_gem_build(document, manifest, subjects, directory, errors)
      command = Array(manifest["commands"]).find { |entry| entry["name"] == "gem_build" }
      errors << "gem-build.json must be the captured gem_build command" unless document.is_a?(Hash) && document == command
      return unless command.is_a?(Hash)

      output = Array(command["command"]).last
      gem_path = safe_evidence_path(directory, rebase_evidence_path(output, manifest, directory))
      unless gem_path && File.file?(gem_path) && !File.symlink?(gem_path)
        errors << "gem_build output is missing or unsafe"
        return
      end
      expected_spec = Gem::Specification.load(File.join(ROOT, "rubernetes.gemspec"))
      unless expected_spec
        errors << "current rubernetes.gemspec cannot be loaded"
        return
      end
      expected_filename = "rubernetes-#{expected_spec.version}.gem"
      errors << "gem_build output filename is invalid" unless File.basename(gem_path) == expected_filename
      stdout_lines = command["stdout"].to_s.lines.map(&:strip).reject(&:empty?)
      expected_stdout = ["Successfully built RubyGem", "Name: rubernetes", "Version: #{expected_spec.version}",
                         "File: #{expected_filename}"]
      errors << "gem_build stdout does not prove the built gem identity" unless stdout_lines == expected_stdout
      errors << "gem_build stderr must be empty" unless command["stderr"] == ""

      gem_subjects = subjects.select do |entry|
        entry["source_path"].to_s.match?(%r{(?:\A|/)rubernetes-#{Regexp.escape(expected_spec.version.to_s)}\.gem\z})
      end
      unless gem_subjects.length == 1 && gem_subjects.first["sha256"] == Digest::SHA256.file(gem_path).hexdigest && gem_subjects.first["bytes"] == File.size(gem_path)
        errors << "gem_build output is not linked to the captured gem subject"
      end

      package = Gem::Package.new(gem_path)
      package.verify
      actual_spec = package.spec
      metadata = lambda do |spec|
        {
          "name" => spec.name,
          "version" => spec.version.to_s,
          "authors" => spec.authors,
          "summary" => spec.summary,
          "description" => spec.description,
          "homepage" => spec.homepage,
          "licenses" => spec.licenses,
          "required_ruby_version" => spec.required_ruby_version.to_s,
          "bindir" => spec.bindir,
          "require_paths" => spec.raw_require_paths.sort,
          "extensions" => spec.extensions.sort,
          "executables" => spec.executables.sort,
          "runtime_dependencies" => spec.runtime_dependencies.map { |dependency| [dependency.name, dependency.requirement.to_s] }.sort
        }
      end
      errors << "built gem metadata differs from the current gemspec" unless metadata.call(actual_spec) == metadata.call(expected_spec)

      payload = gem_payload_entries(gem_path)
      expected_files = expected_spec.files.sort
      unless actual_spec.files.sort == expected_files && package.contents.sort == expected_files && payload.keys.sort == expected_files
        errors << "built gem file inventory differs from the current gemspec"
      end
      expected_files.each do |relative|
        source = File.join(ROOT, relative)
        entry = payload[relative]
        next if safe_source_path?(relative) && safe_component_chain?(ROOT,
                                                                     source) && File.file?(source) && !File.symlink?(source) && entry &&
                entry["sha256"] == Digest::SHA256.file(source).hexdigest && entry["bytes"] == File.size(source)

        errors << "built gem payload differs from current source #{relative}"
      end
    rescue Gem::Exception, Zlib::Error, IOError, ArgumentError => error
      errors << "built gem is invalid: #{error.class}: #{error.message}"
    end

    def gem_payload_entries(path)
      compressed = nil
      File.open(path, "rb") do |io|
        Gem::Package::TarReader.new(io) do |archive|
          archive.each { |entry| compressed = entry.read if entry.full_name == "data.tar.gz" }
        end
      end
      raise Gem::Package::Error, "data.tar.gz is missing" unless compressed

      result = {}
      Zlib::GzipReader.wrap(StringIO.new(compressed)) do |gzip|
        Gem::Package::TarReader.new(gzip) do |archive|
          archive.each do |entry|
            next if entry.directory?
            raise Gem::Package::Error, "non-file gem payload #{entry.full_name.inspect}" unless entry.file?
            raise Gem::Package::Error, "unsafe gem payload #{entry.full_name.inspect}" unless safe_source_path?(entry.full_name)

            bytes = entry.read
            raise Gem::Package::Error, "duplicate gem payload #{entry.full_name.inspect}" if result.key?(entry.full_name)

            result[entry.full_name] = {"sha256" => Digest::SHA256.hexdigest(bytes), "bytes" => bytes.bytesize}
          end
        end
      end
      result
    end

    def validate_executables(document, subjects, manifest, directory, errors)
      unless document.is_a?(Hash) && document["schema_version"] == 1 && document["kind"] == "m0_executables"
        errors << "executable report schema is invalid"
        return
      end
      expected_output = File.join(capture_directory(manifest) || directory, "executables.json")
      expected_command = [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", expected_output]
      unless Array(document["command"]) == expected_command && document["output_path"] == expected_output
        errors << "executable report command identity is invalid"
      end
      tool = File.join(ROOT, "tools/milestones/executables_probe.rb")
      unless document["tool_path"] == "tools/milestones/executables_probe.rb" && digest?(document["tool_sha256"]) && File.file?(tool) && document["tool_sha256"] == Digest::SHA256.file(tool).hexdigest
        errors << "executable report is not bound to the current probe tool"
      end
      validate_time(document["started_at"], errors, "executable report started_at")
      validate_time(document["finished_at"], errors, "executable report finished_at")
      report_started = parse_time(document["started_at"])
      report_finished = parse_time(document["finished_at"])
      manifest_started = parse_time(manifest["started_at"])
      manifest_finished = parse_time(manifest["finished_at"])
      command = Array(manifest["commands"]).find { |entry| entry["name"] == "executables" }
      command_started = parse_time(command && command["started_at"])
      command_finished = parse_time(command && command["finished_at"])
      if report_started && report_finished
        errors << "executable report time interval is invalid" if report_finished < report_started
        if (manifest_started && report_started < manifest_started) || (manifest_finished && report_finished > manifest_finished)
          errors << "executable report is outside the evidence capture"
        end
        unless command_started && command_finished && report_started >= command_started && report_finished <= command_finished
          errors << "executable report is outside the executables command interval"
        end
      end
      host = document["host"]
      current = Etc.uname
      unless host.is_a?(Hash) && host["sysname"] == current[:sysname] && host["release"] == current[:release] && host["machine"] == current[:machine] && host["ruby"] == RUBY_DESCRIPTION
        errors << "executable report host is not bound to the current host"
      end
      results = document["results"]
      unless results.is_a?(Array)
        errors << "executable results must be an array"
        return
      end
      identities = results.filter_map { |entry| [entry["executable"], entry["option"]] if entry.is_a?(Hash) }
      expected = EXECUTABLES.product(OPTIONS)
      unless identities.sort == expected.sort && identities.uniq.length == identities.length
        errors << "all 6 executable help/version identities must appear exactly once"
      end
      errors << "executable aggregate count is invalid" unless document["count"] == results.length && document["failure_count"] == results.count do |entry|
        entry["passed"] != true
      end
      subject_index = subjects.to_h { |entry| [entry["source_path"], entry] }
      results.each do |entry|
        next unless entry.is_a?(Hash)

        executable = entry["executable"]
        option = entry["option"]
        argv = Array(entry["command"])
        unless entry["passed"] == true && entry["exit_status"] == 0 && entry["stderr"] == "" && nonempty?(entry["stdout"])
          errors << "executable #{executable} #{option} did not pass cleanly"
        end
        expected_command = [RbConfig.ruby, "-I#{File.join(ROOT, "lib")}", File.join(ROOT, "exe", executable), "--config",
                            "/unreadable/m0-side-effect-sentinel", option]
        errors << "executable #{executable} #{option} command identity is invalid" unless argv == expected_command
        subject = subject_index["exe/#{executable}"]
        errors << "executable #{executable} binary digest is invalid" unless digest?(entry["binary_sha256"])
        unless subject && subject["sha256"] == entry["binary_sha256"]
          errors << "executable #{executable} is not linked to its captured binary"
        end
        validate_time(entry["started_at"], errors, "executable #{executable} started_at")
        validate_time(entry["finished_at"], errors, "executable #{executable} finished_at")
        result_started = parse_time(entry["started_at"])
        result_finished = parse_time(entry["finished_at"])
        unless result_started && result_finished && report_started && report_finished && result_finished >= result_started && result_started >= report_started && result_finished <= report_finished
          errors << "executable #{executable} result time is outside the report interval"
        end
      end
    end

    def validate_native_scan(document, inventory, manifest, directory, errors)
      unless document.is_a?(Hash) && document["schema_version"] == 2 && document["kind"] == "native_boundary_scan"
        errors << "native boundary scan schema is invalid"
        return
      end
      source_files = document["source_files"]
      expected = Array(inventory&.fetch("entries", nil)).select do |entry|
        entry["path"].match?(%r{\Aext/rubernetes_linux/.*\.(?:c|cc|h)\z})
      end
      errors << "native boundary scan source inventory differs" unless source_files.is_a?(Array) && source_files.sort_by do |entry|
        entry["path"]
      end == expected.sort_by do |entry|
               entry["path"]
             end
      expected_command = [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output"]
      actual_command = Array(document["command"])
      output_path = document["output_path"]
      output_file = safe_evidence_path(directory, rebase_evidence_path(output_path, manifest, directory))
      unless actual_command.length == 4 && actual_command.first(3) == expected_command && nonempty?(output_path) && actual_command.last == output_path && output_file && File.file?(output_file)
        errors << "native boundary scan command identity is invalid"
      end
      expected_tool = File.join(ROOT, "tools/milestones/native_boundary_scan.rb")
      unless document["tool_path"] == "tools/milestones/native_boundary_scan.rb" && digest?(document["tool_sha256"]) && File.file?(expected_tool) && document["tool_sha256"] == Digest::SHA256.file(expected_tool).hexdigest
        errors << "native boundary scan is not bound to the current scanner"
      end
      validate_time(document["started_at"], errors, "native boundary scan started_at")
      validate_time(document["finished_at"], errors, "native boundary scan finished_at")
      scan_started = parse_time(document["started_at"])
      scan_finished = parse_time(document["finished_at"])
      manifest_started = parse_time(manifest["started_at"])
      manifest_finished = parse_time(manifest["finished_at"])
      command = Array(manifest["commands"]).find { |entry| entry["name"] == "native_boundary_scan" }
      command_started = parse_time(command && command["started_at"])
      command_finished = parse_time(command && command["finished_at"])
      if scan_started && scan_finished
        errors << "native boundary scan time interval is invalid" if scan_finished < scan_started
        if (manifest_started && scan_started < manifest_started) || (manifest_finished && scan_finished > manifest_finished)
          errors << "native boundary scan is outside the evidence capture"
        end
        unless command_started && command_finished && scan_started >= command_started && scan_finished <= command_finished
          errors << "native boundary scan is outside its command interval"
        end
      end
      host = document["host"]
      current = Etc.uname
      unless host.is_a?(Hash) && host["sysname"] == current[:sysname] && host["release"] == current[:release] && host["machine"] == current[:machine] && host["ruby"] == RUBY_DESCRIPTION
        errors << "native boundary scan host is not bound to the current host"
      end
      Array(source_files).each do |entry|
        next unless entry.is_a?(Hash) && nonempty?(entry["path"])

        source = File.join(ROOT, entry["path"])
        unless safe_component_chain?(ROOT,
                                     source) && File.file?(source) && !File.symlink?(source) && Digest::SHA256.file(source).hexdigest == entry["sha256"] && File.size(source) == entry["bytes"]
          errors << "native boundary scan source is stale or unsafe #{entry["path"]}"
        end
      end
      findings = document["findings"]
      unless findings.is_a?(Array)
        errors << "native boundary findings must be an array"
        return
      end
      counts = {
        "retry_count" => findings.count { |finding| finding["rule"] == "retry" },
        "authorization_count" => findings.count { |finding| finding["rule"] == "authorization" },
        "state_machine_count" => findings.count { |finding| finding["rule"] == "state_machine" }
      }
      errors << "native boundary aggregate finding count is invalid" unless document["policy_branch_count"] == findings.length
      counts.each { |key, value| errors << "native boundary #{key} is invalid" unless document[key] == value }
      errors << "native boundary scan must contain zero findings" unless document["passed"] == true && findings.empty?
      findings.each do |finding|
        next unless finding.is_a?(Hash)

        path = finding["path"]
        line_number = finding["line"]
        expression = NATIVE_FORBIDDEN[finding["rule"]]
        source = expression && File.join(ROOT, path.to_s)
        parsed_line = Integer(line_number, exception: false)
        line = if source && safe_component_chain?(ROOT, source) && File.file?(source) && parsed_line&.positive?
                 File.readlines(source, chomp: true)[parsed_line - 1]
               end
        unless expression && line && line.match?(expression) && finding["text"] == line.strip
          errors << "native boundary finding is not bound to the current source text"
        end
      rescue ArgumentError, TypeError
        errors << "native boundary finding has an invalid line number"
      end
    end

    def validate_abi(document, manifest, subjects, inventory, directory, errors)
      unless document.is_a?(Hash) && document["schema_version"] == 2 && document["kind"] == "m0_abi_probe"
        errors << "ABI probe schema is invalid"
        return
      end
      errors << "one x86_64 ABI probe is required" unless document["architecture"] == "x86_64"
      unless document["input_sha256"] == manifest["input_sha256"] && document["input_file_count"] == manifest["input_file_count"] && document["input_stable"] == true
        errors << "ABI probe input differs from manifest"
      end
      captured = capture_directory(manifest) || directory
      expected_command = [RbConfig.ruby, "-I#{File.join(ROOT, "build/ext/rubernetes_linux")}", "tools/milestones/m0_kernel_probe.rb",
                          "--output", File.join(captured, "abi-probe-x86_64.json")]
      errors << "ABI probe command identity is invalid" unless Array(document["command"]) == expected_command && document["output_path"] == File.join(
        captured, "abi-probe-x86_64.json"
      )
      tool_path = File.join(ROOT, "tools/milestones/m0_kernel_probe.rb")
      unless document["tool_path"] == "tools/milestones/m0_kernel_probe.rb" && digest?(document["tool_sha256"]) && File.file?(tool_path) && document["tool_sha256"] == Digest::SHA256.file(tool_path).hexdigest
        errors << "ABI probe is not bound to the current kernel probe tool"
      end
      validate_time(document["started_at"], errors, "ABI probe started_at")
      validate_time(document["finished_at"], errors, "ABI probe finished_at")
      probe_started = parse_time(document["started_at"])
      probe_finished = parse_time(document["finished_at"])
      manifest_started = parse_time(manifest["started_at"])
      manifest_finished = parse_time(manifest["finished_at"])
      command = Array(manifest["commands"]).find { |entry| entry["name"] == "kernel_probe_x86_64" }
      command_started = parse_time(command && command["started_at"])
      command_finished = parse_time(command && command["finished_at"])
      if probe_started && probe_finished
        errors << "ABI probe time interval is invalid" if probe_finished < probe_started
        if (manifest_started && probe_started < manifest_started) || (manifest_finished && probe_finished > manifest_finished)
          errors << "ABI probe is outside the evidence capture"
        end
        unless command_started && command_finished && probe_started >= command_started && probe_finished <= command_finished
          errors << "ABI probe is outside its command interval"
        end
      end
      host = document["host"]
      current = Etc.uname
      unless host.is_a?(Hash) && host["sysname"] == current[:sysname] && host["release"] == current[:release] && host["machine"] == current[:machine] && host["ruby"] == RUBY_DESCRIPTION
        errors << "ABI probe host is not bound to the current host"
      end
      validate_native_extension(document["native_extension"], subjects, inventory, errors)
      results = document["results"]
      unless results.is_a?(Array)
        errors << "ABI probe results must be an array"
        return
      end
      names = results.filter_map { |entry| entry["name"] if entry.is_a?(Hash) }
      errors << "ABI probe inventory differs" unless names.sort == ABI_PROBES.sort && names.uniq.length == names.length
      errors << "ABI probe aggregates are invalid" unless document["probe_count"] == results.length && document["failure_count"] == results.count do |entry|
        entry["passed"] != true
      end
      errors << "ABI probes must have zero failures" unless document["failure_count"] == 0 && results.all? do |entry|
        entry["passed"] == true
      end
      results.each do |entry|
        unless entry.is_a?(Hash) && nonempty?(entry["name"]) && entry["passed"] == true && entry["result"].is_a?(Hash)
          errors << "ABI probe result has an invalid payload"
          next
        end

        validate_time(entry["started_at"], errors, "ABI probe #{entry["name"]} started_at")
        validate_time(entry["finished_at"], errors, "ABI probe #{entry["name"]} finished_at")
        result_started = parse_time(entry["started_at"])
        result_finished = parse_time(entry["finished_at"])
        unless result_started && result_finished && probe_started && probe_finished && result_finished >= result_started && result_started >= probe_started && result_finished <= probe_finished
          errors << "ABI probe #{entry["name"]} result time is outside the probe interval"
        end
        validate_abi_result(entry["name"], entry["result"], manifest, subjects, errors)
      end
      abi_manifest = results.find { |entry| entry["name"] == "abi_manifest" }&.fetch("result", nil)
      abi_subject = subjects.find { |entry| entry["source_path"] == "generated/platform/linux/abi/x86_64.json" }
      unless abi_manifest.is_a?(Hash) && abi_subject &&
             abi_manifest["manifest"] == abi_subject["source_path"] &&
             abi_manifest["manifest_sha256"] == abi_subject["sha256"] &&
             abi_manifest["manifest_bytes"] == abi_subject["bytes"] &&
             abi_manifest["mismatch_count"] == 0
        errors << "ABI manifest probe is not linked to the captured ABI subject"
      end
      ERRNO_PROBES.each do |name, (operation, resource_id)|
        value = results.find { |entry| entry["name"] == name }&.fetch("result", nil)
        unless value.is_a?(Hash) && value["errno"].to_i.positive? && value["operation"] == operation && value["resource_id"] == resource_id
          errors << "#{name} does not preserve errno, operation, and resource identity"
        end
      end
    end

    def validate_native_extension(value, subjects, inventory, errors)
      source_path = "build/ext/rubernetes_linux/rubernetes_linux.so"
      subject = subjects.find { |entry| entry["source_path"] == source_path }
      current_path = File.join(ROOT, source_path)
      unless value.is_a?(Hash) && subject && value["path"] == source_path && value["loaded_feature"] == source_path &&
             value["sha256"] == subject["sha256"] && value["bytes"] == subject["bytes"] &&
             File.file?(current_path) && !File.symlink?(current_path) && Digest::SHA256.file(current_path).hexdigest == value["sha256"] && File.size(current_path) == value["bytes"]
        errors << "ABI probe is not bound to the loaded native extension subject"
        return
      end
      header = File.binread(current_path, 20)
      unless header.start_with?("\x7FELF".b) && header.getbyte(4) == 2 && header.getbyte(5) == 1 && header.byteslice(18,
                                                                                                                     2).unpack1("v") == 62
        errors << "native extension is not an x86_64 little-endian ELF shared object"
      end

      expected_sources = Array(inventory&.fetch("entries", nil)).select do |entry|
        entry["path"].match?(%r{\Aext/rubernetes_linux/.*\.(?:c|cc|h|rb)\z})
      end.sort_by { |entry| entry.fetch("path") }
      actual_sources = value["source_files"]
      canonical = expected_sources.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
      unless actual_sources.is_a?(Array) && actual_sources.sort_by { |entry| entry["path"].to_s } == expected_sources &&
             value["source_file_count"] == expected_sources.length && value["source_sha256"] == Digest::SHA256.hexdigest(canonical)
        errors << "native extension is not bound to the current native build sources"
      end
    end

    def validate_abi_result(name, value, manifest, subjects, errors)
      case name
      when "abi_manifest"
        expected = subjects.find { |entry| entry["source_path"] == "generated/platform/linux/abi/x86_64.json" }
        unless expected && value["manifest"] == expected["source_path"] && value["manifest_sha256"] == expected["sha256"] && value["manifest_bytes"] == expected["bytes"] && value["mismatch_count"] == 0
          errors << "abi_manifest payload is not bound to the captured ABI subject"
        end
      when "clone3_pid_namespace_mount_proc_pidfd_wait"
        observed_pids = value["ps_output"].to_s.lines.filter_map { |line| line[/\A\s*(\d+)\s+/, 1]&.to_i }
        unless positive_integer?(value["pid"]) && positive_integer?(value["pidfd"]) && value["exit_status"] == 0 && value["ps_pids"] == [1] && observed_pids == [1] && value["ps_output"].to_s.match?(/\b1\b/)
          errors << "clone3 namespace payload does not prove pid namespace and pidfd wait semantics"
        end
      when "netlink_ack"
        unless value["sequence"] == 60_000 && value["message_types"].is_a?(Array) && !value["message_types"].empty? && value["message_types"].all? do |type|
          type.is_a?(Integer) && type >= 0
        end
          errors << "netlink payload does not prove the requested ACK sequence"
        end
      when "bpf_verifier"
        unless positive_integer?(value["fd"]) && nonempty?(value["verifier_log"]) && value["verifier_log"].match?(/processed\s+\d+\s+insns?/i)
          errors << "BPF payload does not prove a loaded verifier program"
        end
      when "kvm_capability"
        capabilities = value["capabilities"]
        unless value["api_version"] == 12 && capabilities.is_a?(Hash) && capabilities.keys.map(&:to_s).sort == %w[3
                                                                                                                  9] && capabilities.values.all?(Integer)
          errors << "KVM payload does not prove API and capability readback"
        end
      when *ERRNO_PROBES.keys
        unless positive_integer?(value["errno"]) && nonempty?(value["errno_name"]) && nonempty?(value["operation"]) && nonempty?(value["resource_id"]) && value["details"].is_a?(Hash) && nonempty?(value["message"]) && value["message"].include?(value["operation"]) && value["message"].include?(value["resource_id"])
          errors << "#{name} payload does not preserve errno identity"
        end
      when "source_input_stability"
        expected = {"sha256" => manifest["input_sha256"], "file_count" => manifest["input_file_count"]}
        errors << "source_input_stability payload does not bind the manifest input" unless value == expected
      else
        errors << "unknown ABI probe payload #{name.inspect}"
      end
    end

    def validate_junit(directory, index, manifest, inventory, errors)
      entry = index["junit.xml"]
      unless entry
        errors << "junit.xml is missing"
        return
      end
      path = safe_file(directory, entry.fetch("path"))
      root = REXML::Document.new(File.binread(path)).root
      unless root&.name == "testsuite"
        errors << "JUnit root must be testsuite"
        return
      end
      cases = root.get_elements(".//testcase")
      errors << "JUnit test aggregate differs from testcases" unless root.attributes["tests"].to_i == cases.length && cases.any?
      identities = cases.map do |testcase|
        classname = testcase.attributes["classname"].to_s
        name = testcase.attributes["name"].to_s
        status = if testcase.elements["skipped"]
                   "skipped"
                 elsif testcase.elements["failure"]
                   "failure"
                 elsif testcase.elements["error"]
                   "error"
                 else
                   "passed"
                 end
        errors << "JUnit testcase identity is invalid" if classname.empty? || name.empty?
        [classname, name, status]
      end
      errors << "JUnit testcase identities must be unique" unless identities.uniq.length == identities.length
      minitest_inventory = current_minitest_inventory(errors)
      expected_identities = Array(minitest_inventory && minitest_inventory["testcases"]).filter_map do |item|
        [item["classname"].to_s, item["name"].to_s] if item.is_a?(Hash)
      end.sort
      observed_identities = identities.map { |classname, name, _status| [classname, name] }.sort
      unless !expected_identities.empty? && observed_identities == expected_identities
        errors << "JUnit does not contain the complete current Minitest runnable inventory"
      end
      identity_content = observed_identities.map { |classname, name| "#{classname}\0#{name}\n" }.join
      identity_digest = Digest::SHA256.hexdigest(identity_content)
      unless root.attributes["inventory_complete"].to_s == "true" &&
             root.attributes["registered_testcase_inventory_count"].to_i == observed_identities.length &&
             root.attributes["registered_testcase_inventory_sha256"].to_s == identity_digest &&
             root.attributes["executed_testcase_inventory_sha256"].to_s == identity_digest
        errors << "JUnit registered and executed Minitest inventories differ"
      end
      testcase_inventory = identities.sort.map { |classname, name, status| "#{classname}\0#{name}\0#{status}\n" }.join
      expected_testcase_digest = Digest::SHA256.hexdigest(testcase_inventory)
      unless root.attributes["testcase_inventory_sha256"].to_s == expected_testcase_digest &&
             root.attributes["testcase_inventory_count"].to_i == cases.length
        errors << "JUnit testcase inventory is not bound to the captured result set"
      end
      reporter = File.join(ROOT, JUNIT_REPORTER_PATH)
      unless root.attributes["reporter_path"].to_s == JUNIT_REPORTER_PATH &&
             digest?(root.attributes["reporter_sha256"].to_s) && File.file?(reporter) &&
             root.attributes["reporter_sha256"].to_s == Digest::SHA256.file(reporter).hexdigest
        errors << "JUnit is not bound to the current authoritative reporter"
      end
      {"failures" => "failure", "errors" => "error", "skipped" => "skipped"}.each do |attribute, element|
        actual = root.get_elements(".//#{element}").length
        errors << "JUnit #{attribute} aggregate differs" unless root.attributes[attribute].to_i == actual
        errors << "JUnit #{attribute} must be zero" unless actual.zero?
      end
      rake = Array(manifest["commands"]).find { |command| command.is_a?(Hash) && command["name"] == "rake_test" }
      expected_command_digest = rake && Digest::SHA256.hexdigest(JSON.generate(Array(rake["command"])))
      unless expected_command_digest && root.attributes["command_sha256"].to_s == expected_command_digest
        errors << "JUnit is not bound to the captured rake command"
      end
      summary = rake && rake["stdout"].to_s.match(/(\d+)\s+runs?,\s+(\d+)\s+assertions?,\s+(\d+)\s+failures?,\s+(\d+)\s+errors?/)
      unless summary && root.attributes["tests"].to_i == summary[1].to_i &&
             root.attributes["failures"].to_i == summary[3].to_i &&
             root.attributes["errors"].to_i == summary[4].to_i
        errors << "JUnit aggregate is not bound to the captured test runner summary"
      end
      test_entries = Array(inventory&.fetch("entries", nil)).select { |entry| entry["path"].match?(%r{\Atest/.*_test\.rb\z}) }
      test_inventory_content = test_entries.sort_by do |entry|
        entry.fetch("path")
      end.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
      expected_inventory_digest = Digest::SHA256.hexdigest(test_inventory_content)
      unless root.attributes["test_pattern"].to_s == "test/**/*_test.rb" &&
             root.attributes["test_inventory_sha256"].to_s == expected_inventory_digest &&
             root.attributes["test_inventory_count"].to_i == test_entries.length &&
             minitest_inventory.is_a?(Hash) && minitest_inventory["file_count"] == test_entries.length
        errors << "JUnit test inventory is not bound to the complete rake test pattern"
      end
    rescue REXML::ParseException => error
      errors << "JUnit is invalid XML: #{error.message}"
    end

    def current_minitest_inventory(errors)
      tool = File.join(ROOT, MINITEST_INVENTORY_TOOL)
      unless File.file?(tool) && !File.symlink?(tool) && safe_component_chain?(ROOT, tool)
        errors << "Minitest inventory tool is missing or unsafe"
        return nil
      end
      # Discovery loads every test file in a fresh interpreter (~2 s). Its output is a
      # pure function of the test files, the tool and the interpreter, so repeated gate
      # evaluations in one process (the gate test suites evaluate it dozens of times)
      # reuse the validated document under that content-addressed key.
      cache_key = minitest_inventory_cache_key(tool)
      cached = MINITEST_INVENTORY_CACHE_MUTEX.synchronize { MINITEST_INVENTORY_CACHE[cache_key] }
      return cached if cached

      stdout, stderr, status = Open3.capture3(RbConfig.ruby, MINITEST_INVENTORY_TOOL, chdir: ROOT)
      unless status.success? && stderr.empty? && stdout.bytesize <= MAX_JSON_BYTES
        errors << "current Minitest inventory discovery failed"
        return nil
      end
      document = JSON.parse(stdout, object_class: StrictHash, max_nesting: 100)
      unless document.is_a?(Hash) && document["schema_version"] == 1 && document["kind"] == "m0_minitest_inventory" &&
             document["ruby"] == RUBY_DESCRIPTION && document["pattern"] == "test/**/*_test.rb" &&
             positive_integer?(document["file_count"]) && positive_integer?(document["testcase_count"]) && digest?(document["testcase_sha256"])
        errors << "current Minitest inventory schema is invalid"
        return nil
      end
      testcases = document["testcases"]
      identities = Array(testcases).filter_map do |item|
        [item["classname"].to_s, item["name"].to_s] if item.is_a?(Hash) && nonempty?(item["classname"]) && nonempty?(item["name"])
      end
      canonical = identities.sort.map { |classname, name| "#{classname}\0#{name}\n" }.join
      unless identities.uniq.length == identities.length && identities.length == document["testcase_count"] && Digest::SHA256.hexdigest(canonical) == document["testcase_sha256"]
        errors << "current Minitest inventory identity is invalid"
        return nil
      end
      MINITEST_INVENTORY_CACHE_MUTEX.synchronize { MINITEST_INVENTORY_CACHE[cache_key] = document }
      document
    rescue JSON::ParserError, DuplicateJSONKeyError => error
      errors << "current Minitest inventory is invalid JSON: #{error.message}"
      nil
    end

    MINITEST_INVENTORY_CACHE = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache)
    MINITEST_INVENTORY_CACHE_MUTEX = Mutex.new

    # Every input the discovery tool reads: the test files under the rake pattern
    # (path and content), the tool itself and the interpreter description.
    def minitest_inventory_cache_key(tool)
      files = Dir.glob(File.join(ROOT, "test/**/*_test.rb"))
      content = files.map { |path| "#{path.delete_prefix("#{ROOT}/")}\0#{Digest::SHA256.file(path).hexdigest}\n" }.join
      Digest::SHA256.hexdigest("#{RUBY_DESCRIPTION}\0#{Digest::SHA256.file(tool).hexdigest}\0#{content}")
    end

    def validate_subjects(subjects, errors)
      source_paths = subjects.filter_map { |entry| entry["source_path"] }
      required = EXECUTABLES.map do |name|
        "exe/#{name}"
      end + ["generated/platform/linux/abi/x86_64.json", "build/ext/rubernetes_linux/rubernetes_linux.so"]
      required.each { |path| errors << "required subject #{path} is missing" unless source_paths.count(path) == 1 }
      gems = source_paths.grep(%r{(?:\A|/)rubernetes-[0-9][^/]*\.gem\z})
      errors << "exactly one built Rubernetes gem subject is required" unless gems.length == 1
      errors << "subject inventory contains duplicate source paths" unless source_paths.uniq.length == source_paths.length
      subjects.each do |subject|
        source_path = subject["source_path"]
        unless safe_subject_source_path?(source_path)
          errors << "subject source path is invalid #{source_path.inspect}"
          next
        end

        current = File.join(ROOT, source_path)
        unless safe_component_chain?(ROOT, current) && File.file?(current) && !File.symlink?(current)
          errors << "subject source #{source_path} is missing or unsafe"
          next
        end
        errors << "subject source digest mismatch #{source_path}" unless Digest::SHA256.file(current).hexdigest == subject["sha256"]
        errors << "subject source byte count mismatch #{source_path}" unless File.size(current) == subject["bytes"]
      end
    end

    def validate_result_counts(manifest, artifacts, subjects, errors)
      commands = Array(manifest["commands"])
      expected = {
        "commands" => commands.length,
        "command_failures" => commands.count { |entry| entry["exit_status"] != 0 },
        "artifacts" => artifacts.length,
        "subjects" => subjects.length,
        "architecture_profiles" => 1,
        "source_files" => manifest["input_file_count"]
      }
      errors << "result_counts differs from captured evidence" unless manifest["result_counts"] == expected
    end

    def safe_source_path?(value)
      return false unless nonempty?(value) && !value.start_with?("/")

      parts = value.split("/")
      parts.none? { |part| part.empty? || part == "." || part == ".." } && !M0SourceInventory.excluded?(value)
    end

    def safe_subject_source_path?(value)
      return false unless nonempty?(value) && !value.start_with?("/") && !value.include?("\0")

      parts = value.split("/")
      !parts.empty? && !parts.include?("..") && !parts.include?(".") && !parts.include?("")
    end

    def validate_time(value, errors, label)
      Time.iso8601(value.to_s)
    rescue ArgumentError
      errors << "#{label} must be an ISO-8601 timestamp"
    end

    def parse_time(value)
      Time.iso8601(value.to_s)
    rescue ArgumentError
      nil
    end

    def digest?(value)
      value.is_a?(String) && value.match?(SHA256)
    end

    def positive_integer?(value)
      value.is_a?(Integer) && value.positive?
    end

    def nonnegative_integer?(value)
      value.is_a?(Integer) && value >= 0
    end

    def nonempty?(value)
      value.is_a?(String) && !value.empty?
    end
  end
end

if $PROGRAM_NAME == __FILE__
  manifest_path = ARGV.fetch(0) { abort "Usage: m0_gate.rb PATH/manifest.json" }
  result = M0Gate.evaluate(manifest_path)
  puts(JSON.pretty_generate(result))
  exit(result.fetch("passed") ? 0 : 1)
end
