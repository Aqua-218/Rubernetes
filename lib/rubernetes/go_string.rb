# frozen_string_literal: true

module Rubernetes
  module GoString
    # strconv.Quote uses short escapes for these characters and escapes Unicode
    # separators, controls and other non-printable characters.
    def self.quote(text)
      escaped = text.gsub(/[^\p{L}\p{M}\p{N}\p{P}\p{S} ]|["\\]/) do |char|
        case char
        when "\a", "\b", "\f", "\n", "\r", "\t", "\v", '"', "\\" then char.inspect[1...-1]
        else
          code = char.ord
          pattern = if code < 0x20 || code == 0x7f
                      "\\x%02x"
                    elsif code < 0x10000
                      "\\u%04x"
                    else
                      "\\U%08x"
                    end
          format(pattern, code)
        end
      end
      "\"#{escaped}\""
    end
  end
end
