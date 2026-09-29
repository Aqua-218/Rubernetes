# frozen_string_literal: true

require_relative "rubectl/cli"

module Rubernetes
  module Rubectl
    def self.run(argv = ARGV, **options)
      CLI.run(argv, **options)
    end
  end
end
