# frozen_string_literal: true

module Dashboard
  module Errors
    class Error < StandardError; end
    class Forbidden < Error; end
    class Unavailable < Error; end
    class BadRequest < Error; end
  end
end
