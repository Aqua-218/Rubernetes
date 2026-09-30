ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
$LOAD_PATH.unshift(File.expand_path(__dir__)) unless $LOAD_PATH.include?(File.expand_path(__dir__))

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    # The runtime is a process singleton and the store lives in temp dirs:
    # one process keeps the tests honest.
    parallelize(workers: 1)

    # Add more helper methods to be used by all tests here...
  end
end
