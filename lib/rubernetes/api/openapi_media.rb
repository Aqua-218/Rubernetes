# frozen_string_literal: true

require_relative "negotiation"
require_relative "status"

module Rubernetes
  module API
    # kube-openapi sorts Accept clauses by preference and serves the first
    # matching representation, including the legacy gnostic media type.
    module OpenAPIMedia
      def negotiate(accept)
        return Negotiation::JSON_TYPE if accept.to_s.strip.empty?

        supported = self::SUPPORTED_TYPES
        Negotiation.parse_accept(accept).each do |clause|
          media = supported.find { |type| clause.matches?(type) }
          return media == self::DEPRECATED_TYPE ? self::CONTENT_TYPE : media if media
        end
        raise Status::NotAcceptable.new("only the following media types are accepted: #{supported.join(", ")}")
      end
    end
  end
end
