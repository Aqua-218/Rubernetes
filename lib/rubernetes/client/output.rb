# frozen_string_literal: true

require "json"
require "psych"

require_relative "errors"

module Rubernetes
  module Client
    # Formats Kubernetes responses for human and machine consumption.
    class Output
      FORMATS = %w[json yaml name].freeze

      def self.render(value, format: "json")
        new(format: format).render(value)
      end

      def initialize(format: "json")
        @format = format.to_s.downcase
        unless FORMATS.include?(@format)
          raise UsageError, "unsupported output format #{@format.inspect}; choose " + FORMATS.join(", ")
        end
      end

      def render(value)
        case @format
        when "json"
          JSON.pretty_generate(value)
        when "yaml"
          Psych.dump(value, line_width: -1)
        when "name"
          render_names(value)
        end
      rescue JSON::GeneratorError, Psych::Exception => error
        raise Error.new("cannot format response as #{@format}: #{error.message}", cause: error), cause: error
      end

      def write(value, io: $stdout)
        rendered = render(value)
        io.write(rendered)
        io.write("\n") unless rendered.end_with?("\n")
        value
      end

      private

      def render_names(value)
        resources = if value.is_a?(Hash) && value["items"].is_a?(Array)
                      value["items"]
                    elsif value.is_a?(Hash)
                      [value]
                    else
                      Array(value)
                    end
        resources.filter_map do |resource|
          next unless resource.is_a?(Hash)
          kind = resource["kind"]
          name = resource.dig("metadata", "name")
          next if kind.to_s.empty? || name.to_s.empty?

          "#{kind.to_s.downcase}/#{name}"
        end.join("\n")
      end
    end

    Formatter = Output
  end
end
