# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# apimachinery's proxy handler answers ".../proxy" (no trailing slash) with a
# 301 to ".../proxy/" and proxies ".../proxy/" itself.  Request#path has its
# trailing slash stripped so routing need not care about it, and the redirect
# was decided from that normalized path -- so ".../proxy/" was redirected to
# ".../proxy/" for ever.  Every e2e read through a pod or service proxy died
# with "stopped after 10 redirects": "[sig-apps] ReplicationController /
# ReplicaSet should serve a basic image on each replica" and "[sig-network]
# Proxy version v1 should proxy through a service and a pod".
class APIProxyTrailingSlashTest < Minitest::Test
  Request = Rubernetes::API::Request

  PROXY = "/api/v1/namespaces/default/pods/web/proxy"

  def test_the_client_spelling_of_the_path_survives_normalization
    assert_equal "#{PROXY}/", Request.new(path: "#{PROXY}/").raw_path
    assert_equal PROXY, Request.new(path: PROXY).raw_path
    assert_equal PROXY, Request.new(path: "#{PROXY}/").path, "routing still sees no trailing slash"
  end

  def test_the_query_string_is_not_part_of_the_raw_path
    request = Request.new(path: "#{PROXY}/?first=1")

    assert_equal "#{PROXY}/", request.raw_path
    assert_equal({"first" => "1"}, request.query)
  end

  def test_rebuilding_a_request_keeps_the_trailing_slash
    rebuilt = Request.new(path: "#{PROXY}/").with(method: "POST")

    assert_equal "#{PROXY}/", rebuilt.raw_path
    assert_equal PROXY, rebuilt.path
  end

  # Only the bare proxy root redirects; a path below it is proxied as written.
  def test_a_path_under_the_proxy_root_is_not_a_redirect_candidate
    assert_equal "#{PROXY}/read", Request.new(path: "#{PROXY}/read").raw_path
    refute Request.new(path: "#{PROXY}/read").raw_path.end_with?("/proxy")
    refute Request.new(path: "#{PROXY}/").raw_path.end_with?("/proxy")
    assert Request.new(path: PROXY).raw_path.end_with?("/proxy")
  end
end
