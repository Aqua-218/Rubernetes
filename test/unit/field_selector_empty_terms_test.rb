# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# fields.ParseSelector skips empty terms: client-go's fields.AndSelectors with an
# empty base selector renders ",type!=helm.sh/release.v1", which is exactly how
# ingress-nginx lists Secrets.  labels.Parse rejects an empty requirement, so a
# label selector keeps failing on it.
class FieldSelectorEmptyTermsTest < Minitest::Test
  Selectors = Rubernetes::API::Selectors

  def test_field_selector_skips_empty_terms
    %w[,type!=helm.sh/release.v1 type!=helm.sh/release.v1, ,,type!=helm.sh/release.v1,,].each do |value|
      selector = Selectors.new(field_selector: value).field

      assert_equal 1, selector.requirements.length, value
      assert selector.matches?({"type" => "Opaque"}), value
      refute selector.matches?({"type" => "helm.sh/release.v1"}), value
    end
  end

  def test_label_selector_still_rejects_an_empty_requirement
    error = assert_raises(Rubernetes::API::Selector::Error) { Selectors.new(label_selector: ",app=web") }
    assert_match(/cannot be empty/, error.message)
  end
end
