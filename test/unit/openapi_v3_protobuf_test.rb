# frozen_string_literal: true

require "yaml"

require_relative "../test_helper"
require "rubernetes/api"

class OpenAPIV3ProtobufLiteralTest < Minitest::Test
  API = Rubernetes::API
  WIRE = Rubernetes::Schema::Codec::Protobuf

  def test_example_and_extension_values_preserve_types_and_unicode
    value = {"text" => ["1e6", "false", "\u0085\u2028\u2029😀\u007f\u0080\ufffe\uffff"], "number" => 100, "empty" => nil}
    document = {
      "openapi" => "3.0.0", "info" => {"title" => "API", "version" => "1"}, "paths" => {},
      "components" => {"examples" => {"widget" => {"value" => value}}}, "x-widget" => value
    }
    bytes = API::OpenAPIV3Protobuf.encode(document)
    examples = field(bytes, 5, 4)
    example = field(examples, 1, 2, 1)

    assert_equal value, YAML.safe_load(field(example, 3, 2))
    assert_equal value, YAML.safe_load(field(bytes, 9, 2, 2))
  end

  private

  def field(message, *numbers)
    numbers.reduce(message) do |bytes, number|
      selected = WIRE.parse_fields(bytes).find { |entry| entry.fetch(:number) == number }
      raise KeyError, "protobuf field #{number} is absent" unless selected

      selected.fetch(:value)
    end
  end
end
