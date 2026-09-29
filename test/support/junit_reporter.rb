# frozen_string_literal: true

require "digest"
require "fileutils"
require "minitest"

module Rubernetes
  module TestSupport
    class JUnitReporter < Minitest::StatisticsReporter
      def initialize(path, options = {})
        super($stdout, options)
        @path = path
        @test_results = []
      end

      def record(result)
        super
        @test_results << result
      end

      def report
        super
        FileUtils.mkdir_p(File.dirname(@path))
        File.write(@path, xml_document)
      end

      private

      # Keep the XML report tied to the reporter implementation and to the
      # exact set of result identities observed by Minitest.  Aggregate
      # counters alone are not evidence: a hand-written one-test XML file can
      # otherwise satisfy the milestone gate.
      def testcase_inventory_digest
        content = @test_results.map do |result|
          status = if result.skipped?
                      "skipped"
                    elsif result.failure
                      "failure"
                    else
                      "passed"
                    end
          "#{result.class_name}\0#{result.name}\0#{status}\n"
        end.sort.join
        Digest::SHA256.hexdigest(content)
      end

      def executed_testcase_identities
        @test_results.map { |result| [result.class_name.to_s, result.name.to_s] }.uniq.sort
      end

      def registered_testcase_identities
        Minitest::Runnable.runnables.flat_map do |runnable|
          name = runnable.name.to_s
          next [] if name.empty? || !runnable.respond_to?(:runnable_methods)

          runnable.runnable_methods.map { |method_name| [name, method_name.to_s] }
        end.uniq.sort
      end

      def identity_digest(identities)
        Digest::SHA256.hexdigest(identities.map { |classname, name| "#{classname}\0#{name}\n" }.join)
      end

      def xml_document
        failures = @test_results.count { |result| !result.passed? && !result.skipped? }
        skipped = @test_results.count(&:skipped?)
        duration = @test_results.sum(&:time)
        cases = @test_results.map { |result| test_case(result) }.join
        registered = registered_testcase_identities
        executed = executed_testcase_identities
        attributes = {
          "name" => "rubernetes",
          "tests" => @test_results.length,
          "failures" => failures,
          "errors" => 0,
          "skipped" => skipped,
          "time" => format("%.6f", duration),
          "reporter_path" => "test/support/junit_reporter.rb",
          "reporter_sha256" => Digest::SHA256.file(File.expand_path(__FILE__)).hexdigest,
          "testcase_inventory_sha256" => testcase_inventory_digest,
          "testcase_inventory_count" => @test_results.length,
          "registered_testcase_inventory_sha256" => identity_digest(registered),
          "registered_testcase_inventory_count" => registered.length,
          "executed_testcase_inventory_sha256" => identity_digest(executed),
          "inventory_complete" => registered == executed,
          "command_sha256" => ENV["RUBERNETES_JUNIT_COMMAND_SHA256"],
          "test_pattern" => ENV["RUBERNETES_JUNIT_TEST_PATTERN"],
          "test_inventory_sha256" => ENV["RUBERNETES_JUNIT_TEST_INVENTORY_SHA256"],
          "test_inventory_count" => ENV["RUBERNETES_JUNIT_TEST_INVENTORY_COUNT"]
        }.compact.map { |key, value| %(#{key}="#{escape(value)}") }.join(" ")
        %(<?xml version="1.0" encoding="UTF-8"?>\n) +
          %(<testsuite #{attributes}>#{cases}</testsuite>\n)
      end

      def test_case(result)
        body = if result.skipped?
                 "<skipped/>"
               elsif result.failure
                 failure = result.failure
                 %(<failure type="#{escape(failure.class.name)}" message="#{escape(failure.message)}">#{escape(failure.backtrace&.join("\n").to_s)}</failure>)
               else
                 ""
               end
        %(<testcase classname="#{escape(result.class_name)}" name="#{escape(result.name)}" time="#{format("%.6f", result.time)}">#{body}</testcase>)
      end

      def escape(value)
        String(value).gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;").gsub('"', "&quot;").gsub("'", "&apos;")
      end
    end
  end
end

module Minitest
  def self.plugin_rubernetes_junit_init(_options)
    reporter << Rubernetes::TestSupport::JUnitReporter.new(ENV.fetch("RUBERNETES_JUNIT"))
  end

  extensions << "rubernetes_junit" if ENV["RUBERNETES_JUNIT"]
end
