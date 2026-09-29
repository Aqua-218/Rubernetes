# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security/cel"

class SecurityCELTest < Minitest::Test
  CEL = Rubernetes::Security::CEL

  def setup
    @cel = CEL::Evaluator.new
  end

  def ev(expression, variables = {})
    @cel.evaluate(expression, variables)
  end

  def test_arithmetic_comparison_and_logic
    assert_equal 7, ev("1 + 2 * 3")
    assert_equal(-2, ev("-7 / 3"))
    assert_equal(-1, ev("-7 % 3"))
    assert_equal 2.5, ev("5.0 / 2.0")
    assert_equal true, ev("1 < 2 && 2 <= 2 && 3 > 2 && 'a' < 'b'")
    assert_equal true, ev("1 == 1.0")
    assert_equal false, ev("1u == 2u")
    assert_equal true, ev("(true || 1/0 > 0) && (false || true)")
    assert_equal true, ev("false ? 1/0 == 0 : true")
    assert_equal "yes", ev("2 in [1, 2, 3] ? 'yes' : 'no'")
    assert_equal true, ev("'a' in {'a': 1}")
    assert_raises(CEL::EvaluationError) { ev("1 / 0") }
    assert_raises(CEL::EvaluationError) { ev("9223372036854775807 + 1") }
    assert_raises(CEL::TypeMismatch) { ev("1 + 'a'") }
  end

  def test_strings_lists_and_maps
    assert_equal 5, ev("size('hello')")
    assert_equal true, ev("'hello'.contains('ell') && 'hello'.startsWith('he') && 'hello'.endsWith('lo')")
    assert_equal true, ev("'abc-123'.matches('^[a-z]+-[0-9]+$')")
    assert_equal ["a", "b"], ev("'a,b'.split(',')")
    assert_equal "a-b", ev("['a','b'].join('-')")
    assert_equal "HELLO", ev("'hello'.upperAscii()")
    assert_equal "ell", ev("'hello'.substring(1, 4)")
    assert_equal [1, 2], ev("[3, 1, 2].filter(x, x < 3).map(x, x).isSorted() ? [1, 2] : [0]")
    assert_equal [2, 4], ev("[1, 2].map(x, x * 2)")
    assert_equal true, ev("[1, 2, 3].exists(x, x == 2) && ![1, 2].exists_one(x, x > 0)")
    assert_equal 6, ev("[1, 2, 3].sum()")
    assert_equal({"a" => 1}, ev("{'a': 1}"))
    assert_equal 2, ev("{'a': 1, 'b': 2}['b']")
    assert_equal true, ev("has(m.a) && !has(m.z)", {"m" => {"a" => 1}})
    assert_raises(CEL::EvaluationError) { ev("m.z", {"m" => {}}) }
    assert_equal "d", ev("m.?z.orValue('d')", {"m" => {}})
    assert_equal 1, ev("m.?a.value()", {"m" => {"a" => 1}})
    assert_equal true, ev("sets.contains([1,2,3], [1,3]) && sets.intersects([1], [1,2])")
    assert_equal "1 pods, 2.50", ev("'%d pods, %.2f'.format([1, 2.5])")
  end

  def test_conversions_types_time_and_duration
    assert_equal 42, ev("int('42')")
    assert_equal "42", ev("string(42)")
    assert_equal 3.0, ev("double(3)")
    assert_equal "int", ev("type(1)").to_s
    assert_equal true, ev("duration('1h') > duration('30m')")
    assert_equal 90, ev("duration('1m30s').getSeconds()")
    assert_equal true, ev("timestamp('2026-09-06T00:00:00Z') < timestamp('2026-09-07T00:00:00Z')")
    assert_equal 2026, ev("timestamp('2026-09-06T00:00:00Z').getFullYear()")
    assert_equal true, ev("timestamp('2026-09-06T00:00:00Z') + duration('24h') == timestamp('2026-09-07T00:00:00Z')")
    assert_equal true, ev("bool('true') && !bool('false')")
    assert_equal true, ev("b'abc' == bytes('abc')")
  end

  def test_kubernetes_extension_libraries
    assert_equal true, ev("quantity('1Gi') > quantity('500Mi') && isQuantity('2') && !isQuantity('x')")
    assert_equal 1073741824, ev("quantity('1Gi').asInteger()")
    assert_equal true, ev("quantity('1.5Gi').sub(quantity('0.5Gi')) == quantity('1Gi')")
    assert_equal true, ev("ip('10.0.0.1').family() == 4 && isIP('::1') && !isIP('nope')")
    assert_equal true, ev("cidr('10.0.0.0/8').containsIP('10.1.2.3') && !cidr('10.0.0.0/8').containsIP('192.168.1.1')")
    assert_equal 8, ev("cidr('10.0.0.0/8').prefixLength()")
    assert_equal "example.com", ev("url('https://example.com:8443/path?a=1').getHostname()")
    assert_equal "8443", ev("url('https://example.com:8443/path?a=1').getPort()")
    assert_equal true, ev("isURL('https://x') && semver('1.2.3').isGreaterThan(semver('1.2.0'))")
    assert_equal ["a1", "b2"], ev("'a1 b2 c'.findAll('[a-z][0-9]')")
    assert_equal "b2", ev("'a1 b2'.find('b[0-9]')")
    assert_equal [1, 2, 3], ev("[[1], [2, 3]].flatten()")
    assert_equal [1, 2], ev("[1, 1, 2].distinct()")
    assert_equal 3, ev("[1, 3, 2].max()")
  end

  def test_authorizer_library_and_cost_limit
    allow = Object.new
    allow.define_singleton_method(:authorize) { |attrs| attrs.verb == "get" ? Rubernetes::Security::Authorization::Decision.allow : Rubernetes::Security::Authorization::Decision.deny("no") }
    library = CEL::Library.new(authorizer: allow)
    cel = CEL::Evaluator.new(library: library)
    user = Rubernetes::Security::UserInfo.new(name: "alice")
    authz = CEL::Library::Authorizer.new(allow, user, nil)
    assert_equal true, cel.evaluate("authorizer.group('').resource('pods').namespace('ns').check('get').allowed()", {"authorizer" => authz})
    assert_equal false, cel.evaluate("authorizer.group('').resource('pods').check('delete').allowed()", {"authorizer" => authz})
    assert_equal "no", cel.evaluate("authorizer.path('/x').check('delete').reason()", {"authorizer" => authz})
    tiny = CEL::Evaluator.new(cost_limit: 50)
    assert_raises(CEL::EvaluationError) { tiny.evaluate("[1,2,3,4,5,6,7,8,9,10].all(x, [1,2,3,4,5,6,7,8,9,10].all(y, x + y > 0))") }
    assert_raises(CEL::SyntaxError) { ev("1 +") }
    assert_raises(CEL::SyntaxError) { ev("a.b(") }
    assert_raises(CEL::EvaluationError) { ev("unknownVar") }
    assert_raises(CEL::EvaluationError) { ev("nosuch(1)") }
  end
end
