# frozen_string_literal: true

require_relative "rubectl/cli"

module Rubernetes
  module Rubectl
    def self.run(argv = ARGV, **)
      CLI.run(argv, **)
    end
  end
end
