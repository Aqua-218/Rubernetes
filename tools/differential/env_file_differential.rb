#!/usr/bin/env ruby
# frozen_string_literal: true

# The EnvFiles parser (lib/rubernetes/node/env_file.rb) against kubelet's
# pkg/kubelet/util/env ParseEnv: generated env files (quoting, multi-line
# values, comments, stray whitespace, CRLF, missing '=', unclosed quotes,
# content after the closing quote) are parsed by both for a key; values and
# errors are compared (the file path in errors is normalised).
#
#   ruby tools/differential/env_file_differential.rb [--cases N] [--seed N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/node/env_file"

module EnvFileDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/env_file_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/srv/rubernetes/kubernetes-v1.36.2")
  KEYS = %w[A B KEY_1 C].freeze

  module_function

  def value(random)
    pieces = ["plain", "with space", "$HOME ${X}", "a#b", "", "x=y", "tab\there", "line1\nline2", "\n"]
    pieces.sample(random: random)
  end

  def line(random)
    key = KEYS.sample(random: random)
    case random.rand(20)
    when 0 then ""
    when 1 then "   "
    when 2 then "# comment #{key}='x'"
    when 3 then "#{key} ='v'"
    when 4 then "#{key}= 'v'"
    when 5 then "#{key}=unquoted"
    when 6 then "no-equals-here"
    when 7 then "='v'"
    when 8 then "#{key}='v' # trailing comment"
    when 9 then "#{key}='v' trailing junk"
    when 10 then "#{key}='unclosed"
    when 11 then "  \t#{key}='#{value(random)}'"
    when 12 then "#{key}='#{value(random)}'\r"
    when 13 then "#{key}=''"
    else "#{key}='#{value(random)}'"
    end
  end

  def cases(random, count)
    Array.new(count) do |index|
      lines = Array.new(random.rand(0..6)) { line(random) }
      content = lines.join("\n")
      content << "\n" if random.rand < 0.7
      {"name" => "case-#{index}", "content" => content, "key" => KEYS.sample(random: random)}
    end
  end

  def run_port(test_case, dir)
    path = File.join(dir, "env")
    File.write(path, test_case["content"])
    {"name" => test_case["name"], "value" => Rubernetes::Node::EnvFile.parse(path, test_case["key"])}
  rescue Rubernetes::Node::EnvFile::Error => error
    {"name" => test_case["name"], "value" => "", "error" => error.message}
  end

  def run_oracle(cases)
    Dir.mktmpdir("env-file-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("cases" => cases))
      source = File.realpath(SOURCE)
      target = File.join(source, "pkg/kubelet/util/env/zz_rubernetes_env_file_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output},
                                       "go", "test", "-overlay", overlay, "./pkg/kubelet/util/env",
                                       "-run", "TestRubernetesEnvFileOracle", "-count=1", chdir: source)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  def normalise(result) = result.merge("error" => result["error"]&.gsub(/"[^"]*\/env"/, '"ENV"')).compact

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_924
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 5000
    all = cases(Random.new(seed), count)
    expected = run_oracle(all)
    mismatches = Dir.mktmpdir("env-file-port") do |dir|
      all.zip(expected).filter_map do |test_case, want|
        got = run_port(test_case, dir)
        [test_case, normalise(want), normalise(got)] unless normalise(got) == normalise(want)
      end
    end
    mismatches.first(5).each do |test_case, want, got|
      puts "MISMATCH #{test_case["name"]} key=#{test_case["key"]} content=#{test_case["content"].inspect}"
      puts "  upstream: #{want.inspect}"
      puts "  port:     #{got.inspect}"
    end
    puts "#{all.length - mismatches.length}/#{all.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(EnvFileDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
