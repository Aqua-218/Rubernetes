# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "rubernetes"

require_relative "support/junit_reporter" if ENV["RUBERNETES_JUNIT"]
