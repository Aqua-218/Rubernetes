# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security"

# resource.Quantity is decimal-exact.  Parsing "500m" through a Float suffix
# (1e-3.to_r) made it a hair over one half, so a Pod requesting 500m against a
# cpu quota of 1 with 500m used was refused: 0.5000000000000000104 + 0.5 > 1.
class QuotaQuantityExactTest < Minitest::Test
  Quantity = Rubernetes::Security::Admission::Plugins::Quantity

  def test_milli_values_are_exact
    assert_equal 1r, Quantity.parse("500m") + Quantity.parse("500m")
    refute_operator Quantity.parse("500m") + Quantity.parse("500m"), :>, Quantity.parse("1")
    assert_operator Quantity.parse("600m") + Quantity.parse("500m"), :>, Quantity.parse("1")
  end

  def test_binary_and_decimal_suffixes_are_exact
    assert_equal 1024r**3, Quantity.parse("1Gi")
    assert_equal 30 * 1024r**3, Quantity.parse("30Gi")
    assert_equal 252 * 1024r**2, Quantity.parse("252Mi")
    assert_equal 10r**9, Quantity.parse("1G")
    assert_equal Rational(1, 10**9), Quantity.parse("1n")
    assert_equal 32_212_254_720r, Quantity.parse("32212254720")
  end

  def test_format_round_trips_milli_and_integers
    assert_equal "500m", Quantity.format(Quantity.parse("500m"))
    assert_equal "1", Quantity.format(Quantity.parse("1000m"))
    assert_equal "32212254720", Quantity.format(Quantity.parse("30Gi"))
  end
end
