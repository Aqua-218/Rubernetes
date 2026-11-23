# frozen_string_literal: true

require "strscan"

module Rubernetes
  module API
    module CRD
      # Resolve the property and map-key accessors allowed in a CEL rule's
      # fieldPath against the structural schema at that rule's location.
      module CELFieldPath
        ESCAPES = {"a" => "\a", "b" => "\b", "f" => "\f", "n" => "\n", "r" => "\r", "t" => "\t", "v" => "\v",
                   "'" => "'", "\\" => "\\"}.freeze

        module_function

        def segments(path, schema)
          scanner = StringScanner.new(path)
          result = []
          until scanner.eos?
            return unless schema.is_a?(Hash)

            key = accessor(scanner)
            return unless key

            if (properties = schema["properties"])
              return unless properties.key?(key)

              schema = properties[key]
              result << key
            elsif schema["additionalProperties"]
              schema = schema["additionalProperties"]
              result << "[#{key}]"
            else
              return
            end
          end
          result
        end

        def accessor(scanner)
          return scanner[1] if scanner.scan(/\.([^.\[\]]+)/)
          return unless scanner.scan(/\['((?:\\.|[^'\\])*)'\]/)

          scanner[1].gsub(/\\(.)/) { ESCAPES.fetch(Regexp.last_match(1)) { return nil } }
        end
      end
    end
  end
end
