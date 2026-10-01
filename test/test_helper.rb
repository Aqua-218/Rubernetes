# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

# The suite is written against minitest 5 (the Gemfile pins ~> 5.25).  Outside
# bundler RubyGems would activate the newest installed minitest, and minitest 6
# (pulled in by apps/dashboard's bundle) ships without minitest/mock.
gem "minitest", "~> 5.25"
require "minitest/autorun"
require "minitest/mock"
require "rubernetes"

require_relative "support/junit_reporter" if ENV["RUBERNETES_JUNIT"]
