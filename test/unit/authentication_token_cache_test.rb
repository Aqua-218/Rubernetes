# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security"

# kube-apiserver caches successful bearer-token authentications for 10 s
# (tokencache, TokenSuccessCacheTTL); we verified the ServiceAccount JWT and
# looked the ServiceAccount and bound Pod up on every request -- ~2 ms, most
# of a GET in conformance traces.
class AuthenticationTokenCacheTest < Minitest::Test
  S = Rubernetes::Security

  class Counting
    attr_reader :calls

    def initialize(result) = (@result = result; @calls = 0)

    def authenticate(_context)
      @calls += 1
      @result
    end

    def authenticate_token(_token, _audiences)
      @calls += 1
      @result
    end

    def issue_marker = :inner
  end

  def context(token)
    S::Authentication::RequestContext.new(headers: {"authorization" => "Bearer #{token}"}, path: "/api")
  end

  def result
    S::AuthenticationResult.new(user: S::UserInfo.new(name: "system:serviceaccount:ns:sa"), authenticator: "sa")
  end

  def test_a_success_is_reused_until_the_ttl_passes
    now = 100.0
    inner = Counting.new(result)
    cache = S::Authentication::TokenCache.new(inner, success_ttl: 10, clock: -> { now })

    3.times { assert_equal "system:serviceaccount:ns:sa", cache.authenticate(context("t1")).user.name }
    assert_equal 1, inner.calls
    now += 10.5
    cache.authenticate(context("t1"))
    assert_equal 2, inner.calls, "expired entries are verified again"
    cache.authenticate(context("t2"))
    assert_equal 3, inner.calls, "another token is another entry"
  end

  def test_failures_and_unrecognised_tokens_are_not_cached
    inner = Counting.new(nil)
    cache = S::Authentication::TokenCache.new(inner)
    2.times { assert_nil cache.authenticate(context("t")) }
    assert_equal 2, inner.calls

    raising = Class.new { def authenticate(_context) = raise(Rubernetes::Security::AuthenticationError, "expired") }.new
    cache = S::Authentication::TokenCache.new(raising)
    assert_raises(S::AuthenticationError) { cache.authenticate(context("t")) }
  end

  def test_token_review_audiences_are_part_of_the_key
    inner = Counting.new(result)
    cache = S::Authentication::TokenCache.new(inner)
    cache.authenticate_token("t", ["api"])
    cache.authenticate_token("t", ["api"])
    cache.authenticate_token("t", ["vault"])
    assert_equal 2, inner.calls
  end

  def test_requests_without_a_bearer_token_pass_through_and_other_methods_delegate
    inner = Counting.new(result)
    cache = S::Authentication::TokenCache.new(inner)
    2.times { cache.authenticate(S::Authentication::RequestContext.new(headers: {}, path: "/api")) }
    assert_equal 2, inner.calls
    assert_equal :inner, cache.issue_marker
  end
end
