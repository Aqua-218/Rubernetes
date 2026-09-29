# frozen_string_literal: true

require_relative "transport/errors"
require_relative "transport/headers"
require_relative "transport/request"
require_relative "transport/response"
require_relative "transport/http_server"

module Rubernetes
  # HTTP and socket adapters used by the API process boundary.
  module Transport
    Adapter = HTTPServer unless const_defined?(:Adapter, false)
  end
end
