# frozen_string_literal: true

require "fiddle"

module Rubernetes
  module Platform
    module Linux
      module Syscall
        Result = Data.define(:value, :errno)

        HANDLE = Fiddle::Handle::DEFAULT
        FUNCTIONS = (0..6).to_h do |arity|
          argument_types = Array.new(arity + 1, Fiddle::TYPE_LONG)
          [arity, Fiddle::Function.new(HANDLE["syscall"], argument_types, Fiddle::TYPE_LONG)]
        end.freeze

        def self.call(number, *arguments)
          function = FUNCTIONS.fetch(arguments.length) do
            raise ArgumentError, "unsupported syscall arity: #{arguments.length}"
          end
          prepared = arguments.map { |argument| argument.respond_to?(:to_ptr) ? argument.to_ptr.to_i : Integer(argument) }
          value = function.call(Integer(number), *prepared)
          # R-1.2: capture errno before constructing any Ruby object or message.
          errno = Fiddle.last_error
          Result.new(value: value, errno: errno)
        end
      end
    end
  end
end
