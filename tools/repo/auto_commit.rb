#!/usr/bin/env ruby
# frozen_string_literal: true

# Record the working tree as commits: one changed file (or one edit) each.
#
# Nothing here infers intent.  A message reports what moved, where, and how a
# generated record's status and headline fields changed.  By default every
# contiguous edit is its own commit, named after the declaration it lands in
# (`--granularity hunk`); `--granularity file` records one commit per changed
# path and `--granularity cycle` records everything a cycle changed as one.
#
# How it works
# ------------
# The work tree is snapshotted once into a scratch index (a copy of the real
# one, then `git add -A`), so every commit is cut from the same instant and a
# file that keeps changing under a running test cycle cannot straddle two
# commits.  Every commit is then written in one `git fast-import` stream onto a
# temporary ref, and HEAD is advanced with a compare-and-swap: if something
# else committed meanwhile, the snapshot is thrown away and taken again on top
# of the new HEAD.  Nothing observable happens before that final step, so an
# interrupted run leaves the repository exactly as it found it.
#
# Only after HEAD has moved is the real index brought in line, and only for
# the paths that were recorded and whose index entries nobody else touched.
#
# Commits are ordered so that generated output lands after the sources it was
# produced from: sources first, then tests, tools, docs, schemas, generated
# records and vendored inputs.
#
# The author and committer are whoever `git var GIT_AUTHOR_IDENT` names: the
# recorder adds no trailers of its own besides `Cycle:`/`Cycle-Result:`.
#
# Usage:
#     ruby tools/repo/auto_commit.rb                       # record every edit
#     ruby tools/repo/auto_commit.rb --granularity file
#     ruby tools/repo/auto_commit.rb --cycle rake-test --status 0
#     ruby tools/repo/auto_commit.rb --dry-run --verbose
#     rake repo:commit                                     # the same, via rake
#     rake "repo:record[test:parallel]"                    # run a task, then record

require "json"
require "open3"
require "optparse"
require "pathname"
require "tempfile"
require "fileutils"

module Rubernetes
  module Repo
    module AutoCommit
      SUBJECT_LIMIT = 72
      TEXT_LIMIT = 16 * 1024 * 1024
      NULL_SHA = "0" * 40

      class GitError < RuntimeError; end
      class PatchMismatch < StandardError; end

      # ------------------------------------------------------------------
      # Repository-specific classification: longest prefix first.
      # ------------------------------------------------------------------
      SCOPES = [
        ["lib/rubernetes/api/", "api", "source"],
        ["lib/rubernetes/consensus/", "raft", "source"],
        ["lib/rubernetes/node/", "node", "source"],
        ["lib/rubernetes/volume/", "volume", "source"],
        ["lib/rubernetes/platform/", "platform", "source"],
        ["lib/rubernetes/network/", "network", "source"],
        ["lib/rubernetes/security/", "security", "source"],
        ["lib/rubernetes/schema/", "schema", "source"],
        ["lib/rubernetes/scheduler/", "scheduler", "source"],
        ["lib/rubernetes/controller/", "controller", "source"],
        ["lib/rubernetes/bootstrap/", "bootstrap", "source"],
        ["lib/rubernetes/image/", "image", "source"],
        ["lib/rubernetes/runtime/", "runtime", "source"],
        ["lib/rubernetes/proxy/", "proxy", "source"],
        ["lib/rubernetes/client/", "client", "source"],
        ["lib/rubernetes/rubectl/", "rubectl", "source"],
        ["lib/rubernetes/dra/", "dra", "source"],
        ["lib/rubernetes/storage/", "storage", "source"],
        ["lib/rubernetes/watch/", "watch", "source"],
        ["lib/rubernetes/transport/", "transport", "source"],
        ["lib/rubernetes/manifest/", "manifest", "source"],
        ["lib/rubernetes/metrics_server/", "metrics-server", "source"],
        ["lib/rubernetes/observability/", "observability", "source"],
        ["lib/rubernetes/support/", "support", "source"],
        ["lib/rubernetes/", "core", "source"],
        ["lib/", "lib", "source"],
        ["exe/", "cli", "source"],
        ["ext/", "ext", "source"],
        ["test/unit/", "unit", "tests"],
        ["test/integration/", "integration", "tests"],
        ["test/security/", "security", "tests"],
        ["test/conformance/", "conformance", "tests"],
        ["test/chaos/", "chaos", "tests"],
        ["test/e2e/", "e2e", "tests"],
        ["test/support/", "support", "tests"],
        ["test/fixtures/", "fixtures", "tests"],
        ["test/", "tests", "tests"],
        ["tools/repo/", "repo", "tools"],
        ["tools/milestones/", "milestones", "tools"],
        ["tools/conformance/", "conformance", "tools"],
        ["tools/test/", "test", "tools"],
        ["tools/", "tools", "tools"],
        ["spec/", "spec", "docs"],
        ["verification/", "verification", "verification"],
        ["schema/", "schema", "schemas"],
        ["sig/", "rbs", "schemas"],
        ["generated/", "generated", "evidence"],
        ["third_party/", "vendor", "provenance"],
        ["deploy/", "deploy", "config"],
        ["packaging/", "packaging", "build"],
        ["config/", "config", "config"],
        ["examples/", "examples", "docs"],
        ["benchmarks/", "benchmarks", "tools"],
        ["ruby/", "ruby", "build"],
        ["apps/dashboard/lib/promql/", "promql", "source"],
        ["apps/dashboard/lib/tsdb/", "tsdb", "source"],
        ["apps/dashboard/lib/prom/", "prom", "source"],
        ["apps/dashboard/app/", "dashboard", "source"],
        ["apps/dashboard/config/", "dashboard", "config"],
        ["apps/dashboard/test/", "dashboard", "tests"],
        ["apps/dashboard/", "dashboard", "source"],
        ["apps/", "apps", "source"]
      ].freeze

      ROOT_FILES = {
        "Gemfile" => %w[deps build],
        "Gemfile.lock" => %w[deps build],
        "Rakefile" => %w[build build],
        "rubernetes.gemspec" => %w[build build],
        ".ruby-version" => %w[build build],
        ".gitignore" => %w[repo build],
        ".gitattributes" => %w[repo build],
        "README.md" => %w[docs docs],
        "spec.md" => %w[spec docs],
        "LICENSE" => %w[docs docs]
      }.freeze

      CATEGORY_TYPE = {
        "source" => "feat", "tests" => "test", "docs" => "docs", "tools" => "chore",
        "scripts" => "chore", "schemas" => "chore", "verification" => "chore",
        "evidence" => "chore", "provenance" => "chore", "inventory" => "chore",
        "build" => "build", "ci" => "ci", "config" => "chore", "data" => "chore",
        "assets" => "chore", "other" => "chore"
      }.freeze

      CATEGORY_ORDER = %w[
        source tests tools scripts verification schemas build ci config docs data assets
        evidence provenance inventory other
      ].freeze

      CATEGORY_HEADING = {
        "source" => "Source", "tests" => "Tests", "tools" => "Tools", "scripts" => "Scripts",
        "verification" => "Verification", "schemas" => "Schemas", "build" => "Build", "ci" => "CI",
        "config" => "Config", "docs" => "Docs", "data" => "Data", "assets" => "Assets",
        "evidence" => "Evidence", "provenance" => "Provenance", "inventory" => "Inventory",
        "other" => "Other"
      }.freeze

      RECORD_CATEGORIES = %w[evidence inventory].freeze
      GENERATED_CATEGORIES = RECORD_CATEGORIES

      NOISE_FIELD = /(^|[._-])(at|time|timestamp|date|generated|elapsed|duration|seconds|ms|nonce|uuid|run_id|sha256|sha1|digest|hash|checksum)([._-]|$)/i

      # ------------------------------------------------------------------
      # Generic classification for anything the tables above do not name.
      # ------------------------------------------------------------------
      SOURCE_SUFFIXES = %w[
        .rb .rake .erb .c .h .cc .cpp .py .go .rs .js .ts .tsx .jsx .java .kt .swift .sh .bash
        .zsh .lua .pl .ex .exs .hs .ml .mli .tla .cfg .sail .lean .zig .nim .rbs
      ].freeze
      TEST_DIRS = %w[test tests spec specs __tests__ testing].freeze
      TEST_FILE = /(^|[._-])(test|spec)s?([._-]|$)/i
      DOC_DIRS = %w[doc docs documentation man manual guides handbook wiki].freeze
      DOC_SUFFIXES = %w[.md .markdown .rst .txt .adoc .org .tex].freeze
      DOC_FILES = %w[readme license licence changelog changes contributing authors notice copying].freeze
      SCHEMA_DIRS = %w[schema schemas openapi proto protos].freeze
      ASSET_SUFFIXES = {
        ".png" => "image", ".jpg" => "image", ".jpeg" => "image", ".gif" => "image", ".svg" => "image",
        ".ico" => "icon", ".woff" => "font", ".woff2" => "font", ".ttf" => "font", ".otf" => "font",
        ".mp3" => "audio", ".wav" => "audio", ".mp4" => "video", ".pdf" => "document"
      }.freeze
      ASSET_DIRS = %w[assets static public images img fonts media].freeze
      ASSET_CONTAINERS = %w[assets static public].freeze
      DATA_DIRS = %w[data datasets fixtures corpus corpora samples].freeze
      DATA_SUFFIXES = %w[.csv .tsv .jsonl .ndjson .parquet .sqlite .db .bin .dat].freeze
      SCRIPT_DIRS = %w[scripts script bin].freeze
      TOOL_DIRS = %w[tools tool tooling utils util].freeze
      CONFIG_DIRS = %w[config configs conf etc settings].freeze
      CONFIG_SUFFIXES = %w[.yaml .yml .toml .ini .cfg .conf .properties .env].freeze
      CI_DIRS = %w[.github .gitlab .circleci .buildkite].freeze
      CI_FILES = %w[.gitlab-ci.yml .travis.yml jenkinsfile azure-pipelines.yml].freeze
      BUILD_FILES = %w[
        makefile gnumakefile rakefile gemfile gemfile.lock cargo.toml cargo.lock package.json
        package-lock.json yarn.lock pnpm-lock.yaml go.mod go.sum setup.py pyproject.toml
        requirements.txt build.gradle pom.xml cmakelists.txt meson.build dockerfile
      ].freeze
      LOCK_FILES = %w[gemfile.lock cargo.lock package-lock.json yarn.lock pnpm-lock.yaml go.sum].freeze
      VENDOR_DIRS = %w[vendor third_party third-party node_modules external].freeze
      GENERIC_DIRS = %w[src lib app apps pkg internal cmd source sources main java kotlin].freeze

      # ------------------------------------------------------------------
      # Declarations: which definition an edit lands in.
      # ------------------------------------------------------------------
      ID = /[A-Za-z_]\w*/
      DECLARATION_PATTERNS = {
        "ruby" => [
          /\A\s*(?:def\s+(?:self\.)?|class\s+(?:<<\s+)?|module\s+)([A-Za-z_][\w?!.:]*)/,
          /\A\s*(?:describe|context|it|specify|scenario|feature|shared_examples)\s+['"](.+?)['"]/
        ],
        "python" => [/\A[ \t]*(?:async[ \t]+)?(?:def|class)[ \t]+(#{ID})/],
        "markdown" => [/\A {0,3}\#{1,6}[ \t]+(.+?)[ \t]*\#*[ \t]*\z/],
        "shell" => [/\A[ \t]*(?:function[ \t]+)?([A-Za-z_][\w-]*)[ \t]*\(\)/, /\A[ \t]*function[ \t]+([A-Za-z_][\w-]*)/],
        "toml" => [/\A[ \t]*\[\[?([^\]]+)\]\]?[ \t]*\z/],
        "ini" => [/\A[ \t]*\[([^\]]+)\][ \t]*\z/],
        "make" => [%r{\A([A-Za-z0-9_./$()%-]+)[ \t]*:(?!=)}, /\A(?:define|override)\s+(#{ID})/],
        "c" => [
          /\A\s*(?:typedef\s+)?(?:class|struct|union|enum|namespace)\s+(#{ID})\b/,
          /\A\s*#\s*define\s+(#{ID})/,
          /\A(?:[A-Za-z_][\w:<>,*&\s]*?[\s*&])?(~?#{ID}(?:::~?#{ID})*)\s*\([^;]*\z/,
          /\A#{ID}(?:::#{ID})*\s*\(\s*\z/
        ],
        "go" => [/\Afunc\s+(?:\([^)]*\)\s*)?(#{ID})/, /\A(?:type|var|const)\s+(#{ID})/],
        "yaml" => [/\A\s*(?:-\s+)?name\s*:\s*["']?(.+?)["']?\s*\z/, %r{\A\s*(?:-\s+)?([A-Za-z_][\w./-]*)\s*:(?:\s|\z)}],
        "json" => [/\A\s*"([^"]+)"\s*:/],
        "tla" => [
          /\A\s*(?:THEOREM|LEMMA|COROLLARY|PROPOSITION|ASSUME|AXIOM)\s+([A-Za-z_]\w*)/,
          /\A([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*==/,
          /\A-{4,}\s*MODULE\s+([A-Za-z_]\w*)/
        ],
        "rbs" => [/\A\s*(?:def\s+(?:self\.)?|class\s+|module\s+|interface\s+|type\s+)([A-Za-z_][\w?!.:]*)/],
        "dockerfile" => [/\A\s*FROM\s+\S+\s+(?:AS|as)\s+(\w+)/,
                         /\A\s*(FROM|RUN|COPY|ADD|ENV|ARG|WORKDIR|ENTRYPOINT|CMD|EXPOSE|LABEL|USER|VOLUME)\b/i],
        "plain" => []
      }.freeze
      STRICT_INDENT_LANGUAGES = %w[json yaml].freeze
      FLAT_LANGUAGES = %w[markdown toml ini make dockerfile tla].freeze
      LANGUAGE_BY_SUFFIX = {
        ".rb" => "ruby", ".rake" => "ruby", ".erb" => "ruby", ".gemspec" => "ruby", ".rbs" => "rbs",
        ".py" => "python", ".md" => "markdown", ".markdown" => "markdown",
        ".sh" => "shell", ".bash" => "shell", ".zsh" => "shell",
        ".toml" => "toml", ".ini" => "ini", ".conf" => "ini", ".service" => "ini", ".socket" => "ini",
        ".mk" => "make", ".c" => "c", ".h" => "c", ".cc" => "c", ".cpp" => "c", ".go" => "go",
        ".yaml" => "yaml", ".yml" => "yaml", ".json" => "json", ".tla" => "tla", ".cfg" => "ini"
      }.freeze
      LANGUAGE_BY_NAME = {
        "makefile" => "make", "rakefile" => "ruby", "gemfile" => "ruby", "dockerfile" => "dockerfile",
        ".gitignore" => "plain", ".gitattributes" => "plain", ".ruby-version" => "plain"
      }.freeze
      UNINFORMATIVE_NAMES = %w[
        namespace section end _ .PHONY if else for while switch catch return new do try with
        elif match case when unless until begin then export require yield in of not and or
        private protected public
      ].freeze

      HUNK_HEADER = /\A@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: (.*))?\z/

      module_function

      # ------------------------------------------------------------------ git

      class Git
        attr_reader :root, :git_dir

        def initialize(root)
          @root = root
          dir = run("rev-parse", "--git-dir").strip
          @git_dir = File.expand_path(dir, root)
        end

        def run(*args, check: true, index: nil, input: nil, binary: false)
          env = index ? {"GIT_INDEX_FILE" => index.to_s} : {}
          options = {chdir: root, binmode: true}
          options[:stdin_data] = input if input
          out, err, status = Open3.capture3(env, "git", *args, **options)
          raise GitError, "git #{args.join(" ")}: #{err.strip}" if check && !status.success?

          binary ? out : out.force_encoding(Encoding::UTF_8)
        end

        def status_of(*, input: nil)
          options = {chdir: root, binmode: true}
          options[:stdin_data] = input if input
          out, err, status = Open3.capture3({}, "git", *, **options)
          [status.exitstatus, out, err]
        end

        def head
          code, out, = status_of("rev-parse", "--verify", "-q", "HEAD^{commit}")
          code.zero? && !out.strip.empty? ? out.strip : nil
        end

        def tree_of(commit)
          return empty_tree if commit.nil?

          run("rev-parse", "#{commit}^{tree}").strip
        end

        def empty_tree
          run("hash-object", "-t", "tree", "--stdin", input: "".b).strip
        end

        def config(key, kind = nil)
          args = ["config"]
          args += ["--type", kind] if kind
          args += ["--get", key]
          value = run(*args, check: false).strip
          value.empty? ? nil : value
        end

        def ident(role)
          run("var", "GIT_#{role}_IDENT").strip
        end
      end

      # Read blobs through one long-lived `git cat-file --batch` process.
      class BlobReader
        def initialize(git)
          @stdin, @stdout, @wait = Open3.popen2("git", "cat-file", "--batch", chdir: git.root)
          @stdin.binmode
          @stdout.binmode
        end

        def read(sha)
          return nil if sha.nil? || sha == NULL_SHA

          @stdin.write("#{sha}\n")
          @stdin.flush
          header = @stdout.gets
          return nil if header.nil? || header.end_with?(" missing\n")

          size = Integer(header.split(" ")[2])
          payload = @stdout.read(size)
          @stdout.read(1)
          payload
        end

        def size(sha)
          payload = read(sha)
          payload&.bytesize
        end

        def close
          @stdin.close unless @stdin.closed?
          @stdout.close unless @stdout.closed?
          @wait.value
        rescue StandardError
          nil
        end
      end

      def repository_root
        out, status = Open3.capture2("git", "rev-parse", "--show-toplevel", err: File::NULL)
        status.success? && !out.strip.empty? ? out.strip : nil
      rescue Errno::ENOENT
        nil
      end

      # ------------------------------------------------------- classification

      def classify(path)
        return ROOT_FILES[path] if ROOT_FILES.key?(path)

        SCOPES.each do |prefix, scope, category|
          return [scope, category] if path.start_with?(prefix)
        end
        generic_classify(path)
      end

      def words_from_name(path)
        stem = File.basename(path.to_s)
        %w[.rb .rake .py .sh .md .json .toml .txt .gz .jsonl .yaml .yml .sha256 .tla .cfg .rbs .erb].each do |suffix|
          stem = stem[0...-suffix.length] if stem.end_with?(suffix)
        end
        stripped = stem.sub(/\.[A-Za-z][A-Za-z0-9]{0,5}\z/, "")
        stem = stripped unless stripped.empty?
        stem = stem.tr("_-", "  ")
        stem = stem.gsub(/(?<=[a-z0-9])(?=[A-Z])/, " ").gsub(/(?<=[A-Z])(?=[A-Z][a-z])/, " ")
        stem.split.join(" ").downcase
      end

      def scope_words(name)
        words = words_from_name(name).split
        scope = words.empty? ? name.downcase : words.join("-")
        scope[0, 24]
      end

      def generic_scope(parts, skip = [])
        parts[0...-1].reverse_each do |part|
          lowered = part.downcase
          next if GENERIC_DIRS.include?(lowered) || skip.include?(lowered) || lowered.start_with?(".")
          next if lowered.length <= 1

          return scope_words(part)
        end
        "repo"
      end

      def generic_classify(path)
        parts = path.split("/")
        name = parts[-1]
        lowered = name.downcase
        suffix = File.extname(name).downcase
        stem = File.basename(name, suffix).downcase
        all_dirs = parts[0...-1].map(&:downcase)
        dirs = []
        if parts.length > 1
          dirs << parts[0].downcase
          dirs << parts[-2].downcase
          dirs << parts[1].downcase if GENERIC_DIRS.include?(parts[0].downcase) && parts.length > 2
        end

        if CI_DIRS.include?(parts[0].downcase) || CI_FILES.include?(lowered)
          return %w[github docs] if parts[0].downcase == ".github" && parts.length > 1 && parts[1].downcase != "workflows"

          return %w[ci ci]
        end
        if BUILD_FILES.include?(lowered) || BUILD_FILES.include?(stem)
          scope = LOCK_FILES.include?(lowered) ? "deps" : "build"
          if parts.length > 1
            scope = generic_scope(parts, BUILD_FILES)
            scope = "build" if scope == "repo"
          end
          return [scope, "build"]
        end
        return %w[vendor provenance] unless (all_dirs & VENDOR_DIRS).empty?

        if !(dirs & TEST_DIRS).empty? || TEST_FILE.match?(name)
          scope = generic_scope(parts, TEST_DIRS)
          return [scope == "repo" ? "tests" : scope, "tests"]
        end
        if (!(dirs & DOC_DIRS).empty? || DOC_SUFFIXES.include?(suffix) || DOC_FILES.include?(stem) || DOC_FILES.include?(lowered)) && !(SOURCE_SUFFIXES.include?(suffix) && (dirs & DOC_DIRS).empty?)
          return %w[docs docs]
        end
        return %w[schemas schemas] unless (dirs & SCHEMA_DIRS).empty?

        if ASSET_SUFFIXES.key?(suffix) || !(dirs & ASSET_DIRS).empty?
          scope = generic_scope(parts, ASSET_CONTAINERS)
          return [scope == "repo" ? "assets" : scope, "assets"]
        end
        if !(dirs & DATA_DIRS).empty? || DATA_SUFFIXES.include?(suffix)
          scope = generic_scope(parts, DATA_DIRS)
          return [scope == "repo" ? "data" : scope, "data"]
        end
        return %w[scripts scripts] unless (dirs & SCRIPT_DIRS).empty?
        return %w[tools tools] unless (dirs & TOOL_DIRS).empty?

        if !(dirs & CONFIG_DIRS).empty? || CONFIG_SUFFIXES.include?(suffix) || name.start_with?(".") ||
           (suffix == ".json" && (all_dirs & GENERIC_DIRS).empty?)
          scope = generic_scope(parts, CONFIG_DIRS)
          return [scope == "repo" ? "config" : scope, "config"]
        end
        return [generic_scope(parts), "source"] if SOURCE_SUFFIXES.include?(suffix) || suffix == ".json" || !language_of(path).nil?

        [generic_scope(parts), "other"]
      end

      def asset_noun(path)
        ASSET_SUFFIXES.fetch(File.extname(path).downcase, "")
      end

      def human_size(size)
        return "?" if size.nil?

        value = size.to_f
        %w[B KiB MiB GiB].each do |unit|
          return (unit == "B" ? format("%d B", value) : format("%.1f %s", value, unit)) if value < 1024 || unit == "GiB"

          value /= 1024
        end
        format("%.1f GiB", value)
      end

      def join_phrases(phrases)
        case phrases.length
        when 0 then "repository state"
        when 1 then phrases[0]
        when 2 then "#{phrases[0]} and #{phrases[1]}"
        else "#{phrases[0]}, #{phrases[1]} and #{phrases[2]}"
        end
      end

      def plural(count, noun)
        "#{count} #{noun}#{"s" unless count == 1}"
      end

      # --------------------------------------------------------- declarations

      def language_of(path)
        name = File.basename(path.to_s)
        lowered = name.downcase
        return LANGUAGE_BY_NAME[lowered] if LANGUAGE_BY_NAME.key?(lowered)
        return "dockerfile" if lowered.start_with?("dockerfile.") || lowered.end_with?(".dockerfile")

        language = LANGUAGE_BY_SUFFIX[File.extname(name).downcase]
        return "plain" if language.nil? && File.extname(name).empty? && name.start_with?(".")

        language
      end

      def indent_of(line)
        line.length - line.lstrip.length
      end

      def match_declaration(line, language)
        DECLARATION_PATTERNS.fetch(language, []).each do |pattern|
          match = pattern.match(line)
          next unless match

          match.captures.each { |group| return group.strip if group && !group.strip.empty? }
          keyword = match[0].strip.sub(/\A[#\[@]+/, "").split("(").first.to_s.strip
          return keyword.empty? ? nil : keyword
        end
        nil
      end

      def clean_name(name)
        name.sub(/[.;,:{(]+\z/, "").strip.gsub(/\A["'`]+|["'`]+\z/, "").strip
      end

      def enclosing_declaration(lines, index, language)
        return "" if lines.empty? || !DECLARATION_PATTERNS.key?(language)

        index = index.clamp(0, lines.length - 1)
        limit = nil
        unless FLAT_LANGUAGES.include?(language)
          probe = index
          probe += 1 while probe < lines.length && probe < index + 8 && lines[probe].strip.empty?
          limit = indent_of(lines[probe]) if probe < lines.length && !lines[probe].strip.empty?
        end
        strict = STRICT_INDENT_LANGUAGES.include?(language)
        order = strict ? ((index - 1).downto(0).to_a + [index]) : index.downto(0).to_a
        order.each do |position|
          name = match_declaration(lines[position], language)
          next if name.nil?

          if limit && position != index
            indent = indent_of(lines[position])
            next if indent > limit || (strict && indent >= limit)
          end
          name = name.sub(/\A(\d+[.)]\s*)+/, "").strip if language == "markdown"
          name = clean_name(name)
          if name.empty? || UNINFORMATIVE_NAMES.include?(name) || name.length > 60
            next if position == index

            return ""
          end
          return name
        end
        ""
      end

      def introduced_declaration(new_lines, hunk, language)
        return "" unless DECLARATION_PATTERNS.key?(language) && !STRICT_INDENT_LANGUAGES.include?(language)

        start = hunk.first_new
        stop = [new_lines.length, [hunk.new_start - 1, 0].max + hunk.new_len].min
        added = hunk.lines.select { |line| line.start_with?("+") }.map { |line| line[1..] }
        return "" if added.empty?

        added_text = added.to_h { |line| [line, true] }
        shallowest = nil
        (start...stop).each do |position|
          line = new_lines[position]
          next if !added_text.key?(line.chomp) || line.strip.empty?

          indent = indent_of(line)
          shallowest = indent if shallowest.nil? || indent < shallowest
        end
        return "" if shallowest.nil?

        (start...stop).each do |position|
          line = new_lines[position]
          next if !added_text.key?(line.chomp) || indent_of(line) != shallowest

          name = match_declaration(line, language)
          next unless name

          name = clean_name(name)
          return name if !name.empty? && !UNINFORMATIVE_NAMES.include?(name) && name.length <= 60
        end
        ""
      end

      def declared_names(lines, language, limit = 12)
        return [] unless DECLARATION_PATTERNS.key?(language)

        names = []
        lines.each do |line|
          next if indent_of(line).positive? && !FLAT_LANGUAGES.include?(language)

          name = match_declaration(line, language)
          next unless name

          name = clean_name(name)
          next if name.empty? || UNINFORMATIVE_NAMES.include?(name) || names.include?(name) || name.length > 60

          names << name
          break if names.length > limit
        end
        names
      end

      # ------------------------------------------------------------ patches

      class Hunk
        attr_reader :old_start, :old_len, :new_start, :new_len, :lines, :added, :removed, :first_new, :first_old
        attr_accessor :context, :introduces

        def initialize(match, lines)
          @old_start = Integer(match[1])
          @old_len = match[2] ? Integer(match[2]) : 1
          @new_start = Integer(match[3])
          @new_len = match[4] ? Integer(match[4]) : 1
          @lines = lines
          @added = lines.count { |line| line.start_with?("+") }
          @removed = lines.count { |line| line.start_with?("-") }
          @context = ""
          @introduces = false
          leading = 0
          lines.each do |line|
            break if line.start_with?("+", "-")

            leading += 1 unless line.start_with?("\\")
          end
          @first_new = [new_start - 1, 0].max + leading
          @first_old = [old_start - 1, 0].max + leading
        end

        def churn
          added + removed
        end
      end

      def unquote_c(text)
        return text unless text.start_with?('"') && text.end_with?('"')

        inner = text[1...-1]
        inner.gsub(/\\(?:([0-7]{3})|(.))/) do
          if Regexp.last_match(1)
            Regexp.last_match(1).to_i(8).chr
          else
            {"n" => "\n", "t" => "\t", "\\" => "\\", '"' => '"', "a" => "\a", "b" => "\b", "f" => "\f",
             "r" => "\r", "v" => "\v"}.fetch(Regexp.last_match(2), Regexp.last_match(2))
          end
        end
      end

      def split_patch(text)
        result = {}
        path = nil
        hunks = []
        header = nil
        body = []
        flush = lambda do
          hunks << Hunk.new(header, body) if header
          header = nil
          body = []
        end
        raw_lines = text.split("\n", -1)
        raw_lines.pop if raw_lines.last == ""
        raw_lines.each do |raw|
          if raw.start_with?("diff --git ")
            flush.call
            result[path] = hunks if path && !hunks.empty?
            path = nil
            hunks = []
            next
          end
          if header.nil?
            if raw.start_with?("+++ ")
              name = raw[4..]
              name = name[0...-1] if name.end_with?("\t")
              name = unquote_c(name)
              path = name.start_with?("b/") ? name[2..] : name unless name == "/dev/null"
            elsif raw.start_with?("--- ") && path.nil?
              name = raw[4..]
              name = name[0...-1] if name.end_with?("\t")
              name = unquote_c(name)
              path = name.start_with?("a/") ? name[2..] : name unless name == "/dev/null"
            end
            if (match = HUNK_HEADER.match(raw))
              header = match
              body = []
            end
            next
          end
          if (match = HUNK_HEADER.match(raw))
            flush.call
            header = match
            body = []
            next
          end
          body << raw if raw.empty? || " +-\\".include?(raw[0])
        end
        flush.call
        result[path] = hunks if path && !hunks.empty?
        result
      end

      def split_lines(text)
        return [] if text.nil? || text.empty?

        parts = text.split("\n", -1)
        lines = parts[0...-1].map { |part| "#{part}\n" }
        lines << parts[-1] unless parts[-1].empty?
        lines
      end

      def apply_hunks(old, hunks)
        out = []
        position = 0
        hunks.each do |hunk|
          start = hunk.old_len.zero? ? hunk.old_start : hunk.old_start - 1
          raise PatchMismatch, "hunk out of order" if start < position || start > old.length

          out.concat(old[position...start])
          position = start
          pending = nil
          hunk.lines.each do |line|
            if line.start_with?("\\")
              out[-1] = out[-1][0...-1] if pending == "+" && !out.empty? && out[-1].end_with?("\n")
              next
            end
            tag = line.empty? ? " " : line[0]
            payload = line.empty? ? "" : line[1..]
            case tag
            when " ", "-"
              raise PatchMismatch, "hunk runs past end of file" if position >= old.length

              actual = old[position]
              raise PatchMismatch, "context does not match" if actual.chomp != payload

              out << actual if tag == " "
              position += 1
            when "+"
              out << "#{payload}\n"
            else
              raise PatchMismatch, "unexpected patch line #{line.inspect}"
            end
            pending = tag
          end
        end
        out.concat(old[position..] || [])
        out
      end

      # ---------------------------------------------------------- change set

      class Entry
        attr_reader :path, :old_path, :status, :old_mode, :new_mode, :old_sha, :new_sha, :scope, :category
        attr_accessor :added, :removed, :hunks, :declarations, :transition, :fields, :old_lines, :new_lines,
                      :attribute_nodiff, :defined, :old_size, :new_size, :binary

        def initialize(path, status, old_mode, new_mode, old_sha, new_sha, old_path = nil)
          @path = path
          @old_path = old_path
          @status = status
          @old_mode = old_mode
          @new_mode = new_mode
          @old_sha = old_sha
          @new_sha = new_sha
          @added = 0
          @removed = 0
          @scope, @category = AutoCommit.classify(path)
          @hunks = []
          @declarations = []
          @transition = nil
          @fields = []
          @old_lines = nil
          @new_lines = nil
          @attribute_nodiff = false
          @defined = []
          @old_size = nil
          @new_size = nil
          @binary = false
        end

        def churn = added + removed
        def regular? = %w[100644 100755].include?(new_mode)
        def letter = status[0]
      end

      def parse_raw(text)
        fields = text.split("\0", -1)
        entries = []
        cursor = 0
        while cursor < fields.length
          meta = fields[cursor]
          break unless meta.start_with?(":")

          old_mode, new_mode, old_sha, new_sha, status = meta[1..].split(" ")
          if %w[R C].include?(status[0])
            old_path = fields[cursor + 1]
            path = fields[cursor + 2]
            cursor += 3
          else
            old_path = nil
            path = fields[cursor + 1]
            cursor += 2
          end
          entries << Entry.new(path, status, old_mode, new_mode, old_sha, new_sha, old_path)
        end
        entries
      end

      def parse_numstat(text)
        fields = text.split("\0", -1)
        result = {}
        cursor = 0
        while cursor < fields.length
          item = fields[cursor]
          if item.empty?
            cursor += 1
            next
          end
          parts = item.split("\t", -1)
          if parts.length != 3
            cursor += 1
            next
          end
          added, removed, path = parts
          if path.empty?
            path = cursor + 2 < fields.length ? fields[cursor + 2] : ""
            cursor += 3
          else
            cursor += 1
          end
          result[path] = [Integer(added), Integer(removed)] if added.match?(/\A\d+\z/) && removed.match?(/\A\d+\z/)
        end
        result
      end

      def decode_text(payload)
        return nil if payload.nil? || payload.bytesize > TEXT_LIMIT || payload[0, 8192].include?("\0")

        split_lines(payload.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD"))
      end

      def encode_text(lines)
        lines.join.b
      end

      # ------------------------------------------------------- JSON records

      def read_json_status(payload)
        return nil unless payload.is_a?(Hash)

        %w[status state result outcome verdict].each do |key|
          status = payload[key]
          return status if status.is_a?(String) && status.length.between?(1, 24)
        end
        %w[passed success ok].each do |key|
          flag = payload[key]
          return (flag ? key : "not #{key}") if [true, false].include?(flag)
        end
        complete = payload["complete"]
        if [true, false].include?(complete)
          return "complete" if complete

          blockers = payload["blockers"]
          count = blockers.is_a?(Array) ? blockers.length : 0
          return count.positive? ? "blocked (#{count} blockers)" : "blocked"
        end
        available = payload["available"]
        return (available ? "available" : "unavailable") if [true, false].include?(available)

        nil
      end

      RECORD_SUFFIXES = %w[.json .jsonc .toml .lock].freeze

      def load_record(payload, path = "")
        return nil if payload.nil? || payload.bytesize > TEXT_LIMIT
        return nil unless File.extname(path).downcase == ".json"

        text = payload.dup.force_encoding(Encoding::UTF_8)
        return nil unless text.valid_encoding?

        JSON.parse(text)
      rescue JSON::ParserError
        nil
      end

      def flatten_record(record, depth = 2)
        flat = {}
        visit = lambda do |value, prefix, level|
          case value
          when Hash
            if level >= depth
              flat[prefix] = [:dict, value.length]
            else
              value.each { |key, item| visit.call(item, prefix.empty? ? key.to_s : "#{prefix}.#{key}", level + 1) }
            end
          when Array
            flat[prefix] = [:list, value.length]
          else
            flat[prefix] = value
          end
        end
        visit.call(record, "", 0)
        flat.delete("")
        flat
      end

      def format_value(value)
        if value.is_a?(Array) && value.length == 2 && %i[list dict].include?(value[0])
          return plural(value[1], value[0] == :list ? "item" : "key")
        end
        return value ? "true" : "false" if [true, false].include?(value)
        return "null" if value.nil?
        return format("%.6g", value) if value.is_a?(Float)

        if value.is_a?(String)
          text = value.tr("\n", " ")
          return (text.length <= 32 ? text : "#{text[0, 29]}...").inspect
        end
        value.to_s
      end

      MISSING = Object.new.freeze

      def changed_fields(before, after, limit = 6)
        return [] unless before.is_a?(Hash) && after.is_a?(Hash)

        old = flatten_record(before)
        new = flatten_record(after)
        lines = []
        extra = 0
        (old.keys | new.keys).sort.each do |key|
          next if NOISE_FIELD.match?(key) || %w[status complete available].include?(key)
          next if old.fetch(key, MISSING) == new.fetch(key, MISSING)

          if lines.length >= limit
            extra += 1
            next
          end
          lines << if !old.key?(key)
                     "#{key}: (new) #{format_value(new[key])}"
                   elsif !new.key?(key)
                     "#{key}: #{format_value(old[key])} -> (removed)"
                   else
                     "#{key}: #{format_value(old[key])} -> #{format_value(new[key])}"
                   end
        end
        lines << "... and #{plural(extra, "more field")}" if extra.positive?
        lines
      end

      def describe_transition(before, after)
        return nil if before.nil? && after.nil?
        return after.to_s if before.nil?
        return "#{before} -> (removed)" if after.nil?
        return after.to_s if before == after

        "#{before} -> #{after}"
      end

      # ------------------------------------------------------------ snapshot

      Options = Struct.new(:cycle, :status, :granularity, :context, :max_hunks, :message, :paths, :allow_empty,
                           :settle, :settle_max, :lock_timeout, :retries, :report, :dry_run, :verbose, :quiet,
                           keyword_init: true) do
        def self.defaults
          new(cycle: nil, status: nil, granularity: "hunk", context: 0, max_hunks: 200, message: nil, paths: [],
              allow_empty: false, settle: 0.2, settle_max: 5.0, lock_timeout: 30.0, retries: 5, report: nil,
              dry_run: false, verbose: false, quiet: false)
        end
      end

      class Snapshot
        attr_reader :base, :base_tree, :pre_staged, :entries, :index_before

        def initialize(git, blobs, options)
          @git = git
          @blobs = blobs
          @options = options
          @base = nil
          @base_tree = ""
          @pre_staged = []
          @entries = []
          @index_before = {}
          @scratch = nil
        end

        def take
          git = @git
          @base = git.head
          @base_tree = git.tree_of(@base)
          @scratch = File.join(git.git_dir, "auto-commit-index-#{Process.pid}-#{(Time.now.to_f * 1000).to_i}")
          real_index = File.join(git.git_dir, "index")
          if File.file?(real_index)
            FileUtils.cp(real_index, @scratch)
            stat = File.stat(real_index)
            # Git decides whether a stat-clean entry must be re-hashed by
            # comparing its mtime with the index file's own; keep it.
            File.utime(stat.atime, stat.mtime, @scratch)
            git.run("ls-files", "-s", "-z", index: @scratch).split("\0").each do |item|
              next if item.empty?

              meta, path = item.split("\t", 2)
              _mode, _sha, stage = meta.split(" ")
              raise GitError, "#{path} has unresolved merge conflicts; resolve them before recording" if stage != "0"

              @index_before[path] = meta
            end
            @pre_staged = AutoCommit.parse_raw(git.run("diff-index", "--cached", "--raw", "-z", "-M", @base_tree, index: @scratch))
            unless @pre_staged.empty?
              numstat = AutoCommit.parse_numstat(git.run("diff-index", "--cached", "--numstat", "-z", "-M", @base_tree, index: @scratch))
              @pre_staged.each do |entry|
                entry.added, entry.removed = numstat.fetch(entry.path, [0, 0])
                annotate_record(entry)
              end
            end
            pre_tree = git.run("write-tree", index: @scratch).strip
          else
            pre_tree = @base_tree
          end

          add_work_tree
          @entries = AutoCommit.parse_raw(git.run("diff-index", "--cached", "--raw", "-z", "-M", pre_tree, index: @scratch))
          return if @entries.empty?

          numstat = AutoCommit.parse_numstat(git.run("diff-index", "--cached", "--numstat", "-z", "-M", pre_tree, index: @scratch))
          patch = git.run("diff-index", "--cached", "-p", "--no-color", "--no-ext-diff", "--no-renames",
                          "-U#{[@options.context.to_i, 0].max}", pre_tree, index: @scratch)
          hunks_by_path = AutoCommit.split_patch(patch)
          @entries.each do |entry|
            entry.added, entry.removed = numstat.fetch(entry.path, [0, 0])
            entry.hunks = hunks_by_path.fetch(entry.path, [])
            annotate(entry)
          end
        end

        def add_work_tree
          if @options.paths.nil? || @options.paths.empty?
            @git.run("add", "-A", "--", ".", index: @scratch)
            return
          end
          @options.paths.each { |path| @git.run("add", "-A", "--", path, check: false, index: @scratch) }
        end

        def annotate_record(entry)
          return unless RECORD_SUFFIXES.include?(File.extname(entry.path).downcase)
          return unless entry.letter == "M"

          before = AutoCommit.load_record(@blobs.read(entry.old_sha), entry.path)
          after = AutoCommit.load_record(@blobs.read(entry.new_sha), entry.path)
          entry.transition = AutoCommit.describe_transition(AutoCommit.read_json_status(before), AutoCommit.read_json_status(after))
          entry.fields = AutoCommit.changed_fields(before, after)
        end

        def annotate(entry)
          annotate_record(entry)
          return if !entry.regular? && entry.letter != "D"
          return if entry.letter == "D" && !%w[100644 100755].include?(entry.old_mode)

          language = AutoCommit.language_of(entry.path)
          if %w[A D].include?(entry.letter)
            sha = entry.letter == "A" ? entry.new_sha : entry.old_sha
            if entry.churn.zero?
              entry.binary = true
              size = @blobs.size(sha)
              entry.letter == "A" ? entry.new_size = size : entry.old_size = size
              return
            end
            if language && entry.churn <= 20_000
              lines = AutoCommit.decode_text(@blobs.read(sha))
              entry.defined = AutoCommit.declared_names(lines, language) if lines
            end
            return
          end
          return unless entry.letter == "M"

          old_lines = AutoCommit.decode_text(@blobs.read(entry.old_sha))
          new_lines = AutoCommit.decode_text(@blobs.read(entry.new_sha))
          entry.old_lines = old_lines
          entry.new_lines = new_lines
          if entry.hunks.empty? && old_lines && new_lines
            entry.attribute_nodiff = true
            if entry.churn.zero?
              entry.added = new_lines.length
              entry.removed = old_lines.length
            end
          elsif entry.hunks.empty? && entry.churn.zero?
            entry.binary = true
            entry.old_size = @blobs.size(entry.old_sha)
            entry.new_size = @blobs.size(entry.new_sha)
          end
          return if language.nil? || entry.hunks.empty? || new_lines.nil? || old_lines.nil?

          entry.hunks.each do |hunk|
            if hunk.added.positive?
              hunk.context = AutoCommit.enclosing_declaration(new_lines, hunk.first_new, language)
              introduced = AutoCommit.introduced_declaration(new_lines, hunk, language)
              unless introduced.empty?
                hunk.context = introduced
                hunk.introduces = true
              end
            else
              hunk.context = AutoCommit.enclosing_declaration(old_lines, hunk.first_old, language)
            end
            entry.declarations << hunk.context if !hunk.context.empty? && !entry.declarations.include?(hunk.context)
          end
        end

        def close
          File.unlink(@scratch) if @scratch && File.exist?(@scratch)
        end
      end

      # -------------------------------------------------------------- units

      class Unit
        attr_reader :entries, :kind
        attr_accessor :hunk_index, :content, :subject, :body

        def initialize(entries, kind)
          @entries = entries
          @kind = kind
          @hunk_index = nil
          @content = nil
          @subject = ""
          @body = ""
        end

        def paths
          entries.flat_map do |entry|
            list = []
            list << entry.old_path if entry.old_path && entry.letter == "R"
            list << entry.path
            list
          end
        end
      end

      def dominant_category(entries)
        weight = Hash.new(0)
        entries.each { |entry| weight[entry.category] += [entry.churn, 1].max }
        CATEGORY_ORDER.each do |category|
          next unless weight.key?(category)
          return category if !RECORD_CATEGORIES.include?(category) && category != "provenance"
        end
        weight.max_by { |key, value| [value, -CATEGORY_ORDER.index(key)] }&.first || "other"
      end

      def commit_type(category, entries)
        base = CATEGORY_TYPE.fetch(category, "chore")
        return base unless base == "feat"

        relevant = entries.select { |entry| entry.category == category }
        return "feat" if relevant.any? { |entry| entry.letter == "A" }

        net = relevant.sum { |entry| entry.added - entry.removed }
        return "refactor" if net.negative?
        return "chore" if net.zero?

        "feat"
      end

      def subject_scope(category, entries)
        scopes = entries.select { |entry| entry.category == category }.map(&:scope).uniq
        return scopes.first if scopes.length == 1

        weight = Hash.new(0)
        entries.each { |entry| weight[entry.scope] += [entry.churn, 1].max if entry.category == category }
        return "repo" if weight.empty?

        ordered = weight.sort_by { |scope, value| [-value, scope] }
        return CATEGORY_HEADING.fetch(category, category).downcase if ordered.length > 2

        ordered.first.first
      end

      def subject_verb(entries, category)
        relevant = entries.select { |entry| entry.category == category }
        relevant = entries if relevant.empty?
        statuses = relevant.map(&:letter).uniq
        return "update" if statuses.empty?
        return "add" if statuses == ["A"]
        return "remove" if statuses == ["D"]
        return (statuses == ["R"] ? "rename" : "copy") if (statuses - %w[R C]).empty?
        return "refresh" if GENERATED_CATEGORIES.include?(category)

        "update"
      end

      def label_for(kind, scope)
        scope == kind ? kind : "#{kind}(#{scope})"
      end

      def cycle_trailers(cycle, status)
        lines = []
        if cycle && !cycle.to_s.empty?
          lines << "Cycle: #{cycle}"
          lines << "Cycle-Result: #{status.zero? ? "pass" : "fail (#{status})"}" unless status.nil?
        end
        lines
      end

      def entry_detail(entry)
        detail = entry.old_path ? "#{entry.old_path} -> #{entry.path}" : entry.path
        if entry.letter == "T" || (entry.old_mode != entry.new_mode && entry.letter == "M")
          detail += " (mode #{entry.old_mode} -> #{entry.new_mode})"
        end
        if entry.attribute_nodiff
          detail += " (#{plural(entry.removed, "line")} -> #{plural(entry.added, "line")})" if entry.added != entry.removed
        elsif entry.binary
          detail += case entry.letter
                    when "A" then " (#{human_size(entry.new_size)})"
                    when "D" then " (#{human_size(entry.old_size)})"
                    else " (#{human_size(entry.old_size)} -> #{human_size(entry.new_size)})"
                    end
        elsif entry.churn.positive?
          detail += " (+#{entry.added} -#{entry.removed})"
        end
        detail += " [#{entry.transition}]" if entry.transition
        detail
      end

      def file_message(entry, cycle, status)
        scope = entry.scope
        category = entry.category
        kind = CATEGORY_TYPE.fetch(category, "chore")
        if kind == "feat" && entry.letter == "M"
          net = entry.added - entry.removed
          kind = if net.positive?
                   "feat"
                 else
                   (net.negative? ? "refactor" : "chore")
                 end
        end
        verb = {"A" => "add", "D" => "remove", "R" => "rename", "C" => "copy", "T" => "retype"}[entry.letter]
        if verb.nil?
          verb = GENERATED_CATEGORIES.include?(category) ? "refresh" : "update"
          verb = "chmod" if entry.letter == "M" && entry.old_mode != entry.new_mode && entry.churn.zero?
        end
        names = entry.declarations
        noun = category == "assets" ? asset_noun(entry.path) : ""
        target = if %w[R C].include?(entry.letter)
                   "#{words_from_name(entry.old_path.to_s)} to #{words_from_name(entry.path)}"
                 elsif !names.empty? && entry.letter == "M"
                   names.length > 2 ? "#{names[0]} and #{names.length - 1} more" : join_phrases(names[0, 2])
                 else
                   value = words_from_name(entry.path)
                   value = File.basename(entry.path) if value.empty?
                   value = "#{value} #{noun}" if !noun.empty? && !value.end_with?(noun)
                   value
                 end
        label = label_for(kind, scope)
        subject = "#{label}: #{verb} #{target}"
        subject = "#{label}: #{verb} #{names[0]}" if subject.length > SUBJECT_LIMIT && !names.empty?
        subject = "#{label}: #{verb} #{File.basename(entry.path)}" if subject.length > SUBJECT_LIMIT
        subject = subject[0, SUBJECT_LIMIT]

        body = ["#{entry_detail(entry)}."]
        entry.fields.each { |field| body << "  #{field}" }
        if !names.empty?
          body << "" << "Declarations touched:"
          names[0, 20].each { |name| body << "  #{name}" }
          body << "  ... and #{names.length - 20} more" if names.length > 20
        elsif !entry.defined.empty?
          language = language_of(entry.path).to_s
          heading = if language == "markdown"
                      "Sections:"
                    elsif %w[json yaml toml ini].include?(language)
                      "Top-level keys:"
                    else
                      entry.letter == "A" ? "Declares:" : "Declared:"
                    end
          body << "" << heading
          entry.defined[0, 12].each { |name| body << "  #{name}" }
          body << "  ..." if entry.defined.length > 12
        elsif entry.attribute_nodiff
          body << "" << "Marked -diff in .gitattributes, so it is recorded whole rather than by section."
        elsif entry.binary && entry.letter == "M"
          body << "" << "Git treats this file as binary, so it is recorded whole."
        end
        trailers = cycle_trailers(cycle, status)
        body << "" unless trailers.empty?
        body.concat(trailers)
        [subject, "#{body.join("\n")}\n"]
      end

      def hunk_verb(hunk)
        return "add" if hunk.introduces
        return (hunk.context.empty? ? "add" : "extend") if hunk.removed.zero?
        return "remove" if hunk.added.zero?
        return "extend" if hunk.added > hunk.removed * 3
        return "trim" if hunk.removed > hunk.added * 3

        "revise"
      end

      def hunk_message(entry, hunk, cycle, status)
        kind = CATEGORY_TYPE.fetch(entry.category, "chore")
        kind = "refactor" if kind == "feat" && hunk.removed.positive? && hunk.added <= hunk.removed && !hunk.introduces
        verb = hunk_verb(hunk)
        where = hunk.added.positive? ? hunk.first_new + 1 : hunk.first_old + 1
        target = hunk.context.empty? ? "#{File.basename(entry.path)} at line #{where}" : hunk.context
        label = label_for(kind, entry.scope)
        subject = "#{label}: #{verb} #{target}"
        subject = "#{label}: #{verb} #{File.basename(entry.path)}" if subject.length > SUBJECT_LIMIT
        subject = subject[0, SUBJECT_LIMIT]
        first = if hunk.context.empty?
                  "One edit in #{entry.path} at line #{where}: +#{hunk.added} -#{hunk.removed}."
                else
                  "One edit in `#{hunk.context}` (#{entry.path}, line #{where}): +#{hunk.added} -#{hunk.removed}."
                end
        lines = [first]
        trailers = cycle_trailers(cycle, status)
        lines << "" unless trailers.empty?
        lines.concat(trailers)
        [subject, "#{lines.join("\n")}\n"]
      end

      def group_subject(entries, category, cycle, override)
        return override[0, SUBJECT_LIMIT] if override && !override.empty?

        scope = subject_scope(category, entries)
        kind = commit_type(category, entries)
        verb = subject_verb(entries, category)
        relevant = entries.select { |entry| entry.category == category }
        relevant = entries if relevant.empty?
        seen = []
        relevant.sort_by { |entry| [-entry.churn, entry.path] }.each do |entry|
          phrase = words_from_name(entry.path)
          seen << phrase if !phrase.empty? && !seen.include?(phrase)
          break if seen.length == 2
        end
        body = RECORD_CATEGORIES.include?(category) && cycle ? "#{join_phrases(seen)} records from #{cycle}" : join_phrases(seen)
        label = label_for(kind, scope)
        remaining = entries.length - seen.length
        subject = "#{label}: #{verb} #{body}"
        if subject.length > SUBJECT_LIMIT && seen.length > 1
          subject = "#{label}: #{verb} #{seen[0]}"
          remaining = entries.length - 1
        end
        if subject.length > SUBJECT_LIMIT
          subject = "#{label}: #{verb} #{plural(entries.length, "file")}"
          remaining = 0
        end
        suffix = " and #{remaining} more"
        subject = "#{subject}#{suffix}" if remaining.positive? && subject.length + suffix.length <= SUBJECT_LIMIT
        subject
      end

      def group_body(entries, cycle, status, opening = nil)
        lines = []
        if opening
          lines << opening << ""
        elsif cycle
          lines << if status.nil?
                     "Recorded after the `#{cycle}` cycle."
                   elsif status.zero?
                     "Recorded after `#{cycle}` completed successfully."
                   else
                     "Recorded after `#{cycle}` exited #{status} (fail-closed)."
                   end
          lines << ""
        end
        grouped = entries.group_by(&:category)
        CATEGORY_ORDER.each do |category|
          bucket = grouped[category]
          next if bucket.nil? || bucket.empty?

          bucket = bucket.sort_by(&:path)
          lines << "#{CATEGORY_HEADING[category]}:"
          bucket[0, 20].each do |entry|
            lines << "  #{entry.letter} #{entry_detail(entry)}"
            entry.fields[0, 3].each { |field| lines << "      #{field}" }
          end
          lines << "  ... and #{plural(bucket.length - 20, "more file")}" if bucket.length > 20
          lines << ""
        end
        total_added = entries.reject(&:attribute_nodiff).sum(&:added)
        total_removed = entries.reject(&:attribute_nodiff).sum(&:removed)
        lines << "#{plural(entries.length, "file")} changed, #{total_added} insertion#{"s" unless total_added == 1}(+), " \
                 "#{total_removed} deletion#{"s" unless total_removed == 1}(-)."
        trailers = cycle_trailers(cycle, status)
        lines << "" unless trailers.empty?
        lines.concat(trailers)
        "#{lines.join("\n").rstrip}\n"
      end

      def order_key(entry)
        [CATEGORY_ORDER.index(entry.category) || CATEGORY_ORDER.length, entry.path]
      end

      def plan_units(snapshot, options)
        cycle = options.cycle
        status = options.status
        units = []
        unless snapshot.pre_staged.empty?
          entries = snapshot.pre_staged
          unit = Unit.new(entries, "pre-staged")
          unit.subject = group_subject(entries, dominant_category(entries), cycle, nil)
          unit.body = group_body(entries, cycle, status, "Changes that were already staged when the recorder ran.")
          units << unit
        end
        entries = snapshot.entries.sort_by { |entry| order_key(entry) }
        return units if entries.empty?

        if options.granularity == "cycle"
          unit = Unit.new(entries, "cycle")
          unit.subject = group_subject(entries, dominant_category(entries), cycle, options.message)
          unit.body = group_body(entries, cycle, status)
          units << unit
          return units
        end
        entries.each do |entry|
          if options.granularity == "hunk"
            hunk_units = hunk_units_for(entry, options)
            unless hunk_units.empty?
              units.concat(hunk_units)
              next
            end
          end
          unit = Unit.new([entry], "file")
          unit.subject, unit.body = file_message(entry, cycle, status)
          units << unit
        end
        units
      end

      def hunk_units_for(entry, options)
        return [] if entry.letter != "M" || !entry.regular? || entry.old_mode != entry.new_mode
        return [] if entry.hunks.empty? || entry.hunks.length > options.max_hunks
        return [] if RECORD_CATEGORIES.include?(entry.category)
        return [] if entry.hunks.length == 1 && entry.hunks[0].context.empty?
        return [] if entry.old_lines.nil? || entry.new_lines.nil?

        begin
          full = apply_hunks(entry.old_lines, entry.hunks)
        rescue PatchMismatch
          return []
        end
        return [] if encode_text(full) != encode_text(entry.new_lines)

        units = []
        entry.hunks.each_with_index do |hunk, index|
          unit = Unit.new([entry], "hunk")
          unit.hunk_index = index
          if index < entry.hunks.length - 1
            begin
              unit.content = encode_text(apply_hunks(entry.old_lines, entry.hunks[0..index]))
            rescue PatchMismatch
              return []
            end
          end
          unit.subject, unit.body = hunk_message(entry, hunk, options.cycle, options.status)
          units << unit
        end
        units
      end

      # ------------------------------------------------------ writing commits

      def quote_path(path)
        raw = path.b
        return path unless raw.match?(/["\\\n]/) || path.start_with?('"')

        "\"#{raw.gsub("\\", "\\\\\\\\").gsub('"', '\\"').gsub("\n", "\\n")}\""
      end

      def data_block(payload)
        "data #{payload.bytesize}\n".b + payload.b + "\n".b
      end

      def fast_import_stream(units, ref, base, author, committer)
        out = "".b
        units.each_with_index do |unit, position|
          out << "commit #{ref}\n".b
          out << "author #{author}\n".b
          out << "committer #{committer}\n".b
          out << data_block("#{unit.subject}\n\n#{unit.body}".b)
          out << "from #{base}\n".b if position.zero? && base
          unit.entries.each do |entry|
            out << "D #{quote_path(entry.old_path)}\n".b if entry.old_path && entry.letter == "R"
            if entry.letter == "D"
              out << "D #{quote_path(entry.path)}\n".b
              next
            end
            path = quote_path(entry.path)
            if unit.kind == "hunk" && unit.content
              out << "M #{entry.new_mode} inline #{path}\n".b
              out << data_block(unit.content)
            else
              out << "M #{entry.new_mode} #{entry.new_sha} #{path}\n".b
            end
          end
          out << "\n".b
        end
        out << "done\n".b
        out
      end

      def write_commits(git, units, base)
        ref = "refs/auto-commit/#{Process.pid}-#{(Time.now.to_f * 1000).to_i}"
        author = git.ident("AUTHOR")
        committer = git.ident("COMMITTER")
        stream = fast_import_stream(units, ref, base, author, committer)
        begin
          git.run("fast-import", "--quiet", "--done", input: stream)
          tip = git.run("rev-parse", "--verify", ref).strip
          listing = base ? git.run("rev-list", "--reverse", "#{base}..#{tip}") : git.run("rev-list", "--reverse", tip)
          shas = listing.split
          raise GitError, "fast-import produced #{shas.length} commits for #{units.length} units" if shas.length != units.length

          if git.config("commit.gpgsign", "bool") == "true"
            shas = sign_chain(git, shas, base)
            tip = shas.last
          end
          [tip, shas]
        ensure
          git.run("update-ref", "-d", ref, check: false)
        end
      end

      def sign_chain(git, shas, base)
        parent = base
        signed = []
        shas.each do |sha|
          raw = git.run("cat-file", "commit", sha, binary: true)
          header, message = raw.split("\n\n", 2)
          tree = nil
          env = {}
          header.force_encoding(Encoding::UTF_8).split("\n").each do |line|
            key, value = line.split(" ", 2)
            case key
            when "tree" then tree = value
            when "author", "committer"
              if (match = /\A(.*) <([^>]*)> (\d+ [+-]\d{4})\z/.match(value))
                role = key.upcase
                env["GIT_#{role}_NAME"] = match[1]
                env["GIT_#{role}_EMAIL"] = match[2]
                env["GIT_#{role}_DATE"] = match[3]
              end
            end
          end
          args = ["commit-tree", "-S", tree]
          args += ["-p", parent] if parent
          out, err, status = Open3.capture3(env, "git", *args, chdir: git.root, stdin_data: message, binmode: true)
          raise GitError, "git commit-tree -S: #{err.strip}" unless status.success?

          parent = out.strip
          signed << parent
        end
        signed
      end

      def advance_head(git, tip, base, cycle)
        code, = git.status_of("update-ref", "-m", "auto-commit: #{cycle || "record"}", "HEAD", tip, base || NULL_SHA)
        code.zero?
      end

      def sync_index(git, snapshot, units, timeout)
        wanted = units.flat_map(&:paths).uniq
        return [] if wanted.empty?

        current = {}
        git.run("ls-files", "-s", "-z", check: false).split("\0").each do |item|
          next if item.empty?

          meta, path = item.split("\t", 2)
          current[path] = meta if wanted.include?(path)
        end
        stable = wanted.select { |path| snapshot.index_before[path] == current[path] }
        return wanted if stable.empty?

        payload = "#{stable.join("\0")}\0".b
        deadline = monotonic + timeout
        delay = 0.05
        loop do
          code, _out, err = git.status_of("reset", "-q", "--pathspec-from-file=-", "--pathspec-file-nul", "--", input: payload)
          break if code.zero?
          return wanted if !err.include?("index.lock") || monotonic > deadline

          sleep(delay)
          delay = [delay * 2, 1.0].min
        end
        git.run("update-index", "-q", "--refresh", check: false)
        wanted - stable
      end

      # ------------------------------------------------- settling and locking

      def candidate_paths(git, paths)
        args = ["--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"]
        args += ["--", *paths] if paths && !paths.empty?
        git.run(*args, check: false).split("\0").filter_map { |item| item[3..] if item.length > 3 }
      end

      def wait_until_settled(git, options)
        settle = options.settle.to_f
        return if settle <= 0

        deadline = monotonic + [options.settle_max.to_f, settle].max
        loop do
          newest = 0.0
          candidate_paths(git, options.paths).each do |path|
            newest = [newest, File.lstat(File.join(git.root, path)).mtime.to_f].max
          rescue SystemCallError
            next
          end
          age = Time.now.to_f - newest
          return if age >= settle || monotonic >= deadline

          sleep([settle - age, deadline - monotonic, settle].min.clamp(0.01, settle))
        end
      end

      class RecorderLock
        def initialize(git, timeout)
          @path = File.join(git.git_dir, "auto-commit.lock")
          @timeout = timeout
          @handle = nil
        end

        def acquire
          @handle = File.open(@path, "w")
          deadline = AutoCommit.monotonic + @timeout
          until @handle.flock(File::LOCK_EX | File::LOCK_NB)
            raise GitError, "another auto-commit run holds #{@path} (waited #{@timeout.to_i}s)" if AutoCommit.monotonic > deadline

            sleep(0.1)
          end
          self
        end

        def release
          return unless @handle

          @handle.flock(File::LOCK_UN)
          @handle.close
          @handle = nil
        end
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # -------------------------------------------------------------- driver

      def print_plan(units, verbose, prefix, io = $stdout)
        units.each do |unit|
          note = unit.kind == "pre-staged" ? "  (pre-staged)" : ""
          io.puts "#{prefix}#{unit.subject}#{note}"
          next unless verbose

          unit.body.chomp.split("\n").each { |line| io.puts "    #{line}" }
          io.puts
        end
      end

      def count_paths(units)
        units.flat_map(&:paths).uniq.length
      end

      def record(git, options, io: $stdout, err: $stderr)
        started = monotonic
        blobs = BlobReader.new(git)
        attempts = 0
        snapshot = nil
        units = nil
        tip = nil
        shas = nil
        begin
          loop do
            attempts += 1
            wait_until_settled(git, options)
            snapshot = Snapshot.new(git, blobs, options)
            begin
              snapshot.take
              units = plan_units(snapshot, options)
              if units.empty?
                if options.granularity == "cycle" && options.allow_empty
                  unit = Unit.new([], "cycle")
                  unit.subject = group_subject([], "other", options.cycle, options.message)
                  unit.body = group_body([], options.cycle, options.status)
                  units = [unit]
                else
                  io.puts "auto-commit: nothing to record" unless options.quiet
                  return {"commits" => [], "base" => snapshot.base, "head" => snapshot.base}
                end
              end
              if options.dry_run
                print_plan(units, options.verbose, "[dry-run] ", io)
                io.puts "auto-commit: would record #{plural(units.length, "commit")} across #{plural(count_paths(units), "file")}"
                return {"commits" => units.map { |unit| {"subject" => unit.subject, "paths" => unit.paths} },
                        "base" => snapshot.base, "head" => snapshot.base, "dry_run" => true}
              end
              tip, shas = write_commits(git, units, snapshot.base)
              break if advance_head(git, tip, snapshot.base, options.cycle)
              raise GitError, "HEAD moved during each of #{attempts} attempts; giving up" if attempts > options.retries

              err.puts "auto-commit: HEAD moved while recording; retaking the snapshot" unless options.quiet
            ensure
              snapshot.close
            end
          end
          unsynced = sync_index(git, snapshot, units, options.lock_timeout)
          unless options.quiet
            print_plan(units, options.verbose, "auto-commit: ", io)
            io.puts format("auto-commit: recorded %s across %s in %.2fs", plural(units.length, "commit"),
                           plural(count_paths(units), "file"), monotonic - started)
          end
          unless unsynced.empty?
            err.puts "auto-commit: the index could not be updated for #{plural(unsynced.length, "path")}; " \
                     "`git status` may show them as staged until `git reset -q -- <path>` is run"
          end
          {"commits" => shas.zip(units).map { |sha, unit| {"sha" => sha, "subject" => unit.subject, "paths" => unit.paths} },
           "base" => snapshot.base, "head" => tip, "attempts" => attempts, "unsynced" => unsynced,
           "seconds" => (monotonic - started).round(3)}
        ensure
          blobs.close
        end
      end

      def parse_arguments(argv)
        options = Options.defaults
        parser = OptionParser.new do |opts|
          opts.banner = "Usage: ruby tools/repo/auto_commit.rb [options] [-- paths...]"
          opts.on("--cycle NAME", "name of the cycle that produced these changes, e.g. rake-test") { |v| options.cycle = v }
          opts.on("--status N", Integer, "exit status of the cycle; recorded in the message, never fatal") { |v| options.status = v }
          opts.on("--granularity KIND", %w[file hunk cycle],
                  "hunk: one commit per contiguous edit (default); file: one per path; cycle: one for everything") { |v| options.granularity = v }
          opts.on("--context N", Integer, "lines of unchanged context that separate two edits (default 0)") { |v| options.context = v }
          opts.on("--max-hunks N", Integer, "above this many hunks a file is committed whole (default 200)") { |v| options.max_hunks = v }
          opts.on("-m", "--message SUBJECT", "override the subject line (cycle granularity only)") { |v| options.message = v }
          opts.on("--paths x,y,z", Array, "limit recording to these paths") { |v| options.paths = v }
          opts.on("--allow-empty", "commit even when nothing changed (cycle granularity only)") { options.allow_empty = true }
          opts.on("--settle SECONDS", Float, "wait until no candidate file was written within this many seconds (default 0.2)") do |v|
            options.settle = v
          end
          opts.on("--settle-max SECONDS", Float, "upper bound on the settle wait (default 5)") { |v| options.settle_max = v }
          opts.on("--lock-timeout SECONDS", Float, "seconds to wait for another recorder or an index lock (default 30)") do |v|
            options.lock_timeout = v
          end
          opts.on("--retries N", Integer, "times to retake the snapshot when HEAD moves underneath (default 5)") { |v| options.retries = v }
          opts.on("--report PATH", "write a JSON report of the commits made to this path") { |v| options.report = v }
          opts.on("--dry-run", "print the commits that would be made and change nothing") { options.dry_run = true }
          opts.on("-v", "--verbose", "print full commit messages") { options.verbose = true }
          opts.on("-q", "--quiet", "print nothing on success") { options.quiet = true }
        end
        rest = parser.parse(argv)
        options.paths = (options.paths || []) + rest
        options
      end

      def main(argv = ARGV, io: $stdout, err: $stderr, root: nil)
        options = parse_arguments(argv)
        root ||= repository_root
        if root.nil?
          err.puts "auto-commit: not a git repository; skipping"
          return 0
        end
        report = nil
        begin
          git = Git.new(root)
          lock = RecorderLock.new(git, options.lock_timeout).acquire
          begin
            report = record(git, options, io: io, err: err)
          ensure
            lock.release
          end
        rescue GitError => e
          err.puts "auto-commit: #{e.message}"
          return 0
        end
        if options.report
          report = report.merge("cycle" => options.cycle, "status" => options.status, "granularity" => options.granularity)
          File.write(options.report, "#{JSON.pretty_generate(report)}\n")
        end
        0
      end
    end
  end
end

exit(Rubernetes::Repo::AutoCommit.main(ARGV)) if $PROGRAM_NAME == __FILE__
