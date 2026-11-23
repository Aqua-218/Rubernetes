# frozen_string_literal: true

require "json"

require_relative "../schema/codec/protobuf"

module Rubernetes
  module API
    # Both gnostic versions encode free-form JSON values as YAML in field 2.
    module OpenAPIProtobufAny
      YAML_SPECIAL_CHARACTERS = /[\u007f-\u009f\u2028\u2029\ufffe\uffff]/

      module_function

      def encode(value)
        # YAML readers can fold Unicode line breaks or reject control
        # characters which JSON allows literally in a quoted string.
        yaml = JSON.generate(value).gsub(YAML_SPECIAL_CHARACTERS) { |character| format("\\u%04x", character.ord) }
        Schema::Codec::Protobuf.encode_field(2, yaml, type: :string)
      end
    end
  end
end
