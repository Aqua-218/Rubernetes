# frozen_string_literal: true

require_relative "../test_helper"

class VersionTest < Minitest::Test
  def test_version_is_a_frozen_semantic_version
    assert_match(/\A\d+\.\d+\.\d+\z/, Rubernetes::VERSION)
    assert_predicate(Rubernetes::VERSION, :frozen?)
  end
end

