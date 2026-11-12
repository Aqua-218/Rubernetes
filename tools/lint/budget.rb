#!/usr/bin/env ruby
# frozen_string_literal: true

# A budget for what style cops do not measure: how big the files and methods
# of lib/ are, and how much of the code checks its own collaborators instead
# of calling them.
#
#   ruby tools/lint/budget.rb            # fail when anything grew past its budget
#   ruby tools/lint/budget.rb --update   # record the current numbers as the budget
#   ruby tools/lint/budget.rb --report   # print the numbers and the worst offenders
#
# The budget only ever goes down.  A file under the limits has no entry and
# must stay under them; a file over a limit is listed with the number it had
# when it was last recorded, and may shrink but not grow.  `--update` refuses
# to raise a recorded number, so a regression cannot be "fixed" by recording
# it.
#
# Measured per file:
#   lines            physical lines
#   longest_method   lines of its longest method
#   respond_to       calls of respond_to? -- a question about an object's
#                    shape that the object's type already answers
#   swallowed        `rescue StandardError` (or bare rescue) whose body is
#                    only nil, false, [] or {} -- an error nobody will see

require "json"
require "prism"

module Lint
  module Budget
    ROOT = File.expand_path("../..", __dir__)
    PATH = File.join(ROOT, "tools/lint/budget.json")
    LIMITS = {"lines" => 800, "longest_method" => 60, "respond_to" => 0, "swallowed" => 0}.freeze
    QUIET = %w[nil false true [] {}].freeze

    module_function

    def files
      Dir[File.join(ROOT, "lib/**/*.rb")].reject { |path| path.end_with?("_pb.rb") }.sort
    end

    def measure(path)
      result = Prism.parse_file(path)
      numbers = {"lines" => File.foreach(path).count, "longest_method" => 0, "respond_to" => 0, "swallowed" => 0}
      pending = [result.value]
      while (node = pending.pop)
        case node
        when Prism::DefNode
          numbers["longest_method"] = [numbers["longest_method"], node.location.end_line - node.location.start_line + 1].max
        when Prism::CallNode
          numbers["respond_to"] += 1 if node.name == :respond_to?
        when Prism::RescueNode
          numbers["swallowed"] += 1 if swallows?(node)
        end
        pending.concat(node.compact_child_nodes)
      end
      numbers
    end

    def swallows?(node)
      broad = node.exceptions.empty? || node.exceptions.any? { |exception| exception.slice == "StandardError" }
      body = node.statements&.body || []
      broad && (body.empty? || (body.length == 1 && QUIET.include?(body.first.slice)))
    end

    # Only what is over a limit is worth a line in the budget.
    def over(numbers)
      numbers.select { |name, value| value > LIMITS.fetch(name) }
    end

    def current
      files.to_h { |path| [path.delete_prefix("#{ROOT}/"), over(measure(path))] }.reject { |_path, numbers| numbers.empty? }
    end

    def recorded
      File.file?(PATH) ? JSON.parse(File.read(PATH)).fetch("files") : {}
    end

    def violations(now, budget)
      now.flat_map do |path, numbers|
        numbers.filter_map do |name, value|
          allowed = budget.dig(path, name) || LIMITS.fetch(name)
          "#{path}: #{name} is #{value}, budget #{allowed}" if value > allowed
        end
      end
    end

    def totals(entries)
      LIMITS.keys.to_h { |name| [name, entries.sum { |_path, numbers| numbers.fetch(name, 0) }] }
    end

    def write(now)
      document = {"limits" => LIMITS, "totals" => totals(now), "files" => now.sort.to_h}
      File.write(PATH, "#{JSON.pretty_generate(document)}\n")
    end

    def run(argv)
      now = current
      budget = recorded
      case argv.first
      when "--report" then report(now)
      when "--update"
        grown = budget.empty? ? [] : violations(now, budget)
        return fail_with(grown, "refusing to record a budget that grew:") unless grown.empty?

        write(now)
        puts "budget recorded: #{now.length} files over a limit, totals #{totals(now)}"
      else
        failures = violations(now, budget)
        return fail_with(failures, "over budget (shrink the code, or split it; the budget is not raised):") unless failures.empty?

        slack = budget.count { |path, numbers| numbers.any? { |name, value| now.dig(path, name).to_i < value } }
        puts "within budget; #{slack} files are now under their recorded numbers (run --update to lock that in)"
      end
      0
    end

    def report(now)
      puts JSON.pretty_generate("limits" => LIMITS, "over_budget_totals" => totals(now), "files_over_a_limit" => now.length)
      LIMITS.each_key do |name|
        worst = now.select { |_path, numbers| numbers.key?(name) }.max_by(8) { |_path, numbers| numbers.fetch(name) }
        puts "#{name}:", *worst.map { |path, numbers| format("  %6d  %s", numbers.fetch(name), path) }
      end
    end

    def fail_with(lines, heading)
      warn heading, *lines.map { |line| "  #{line}" }
      1
    end
  end
end

exit(Lint::Budget.run(ARGV)) if $PROGRAM_NAME == __FILE__
