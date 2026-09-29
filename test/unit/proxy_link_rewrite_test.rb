# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# A server behind /api/v1/namespaces/ns/pods/name/proxy has no idea it is being
# proxied and answers with href="/rewriteme".  The API server rewrites those
# absolute links so a client following one stays inside the proxy
# (apimachinery util/proxy/transport.go Transport.RoundTrip and rewriteURL);
# without it the link points at the API server's own root.  "[sig-network]
# Proxy version v1 should proxy through a service and a pod" checks the exact
# rewritten text.
class ProxyLinkRewriteTest < Minitest::Test
  Server = Rubernetes::API::Server

  PREFIX = "/api/v1/namespaces/proxy-1/pods/agnhost/proxy"

  def server = Server.allocate

  def rewrite(body, content_type: "text/html", prefix: PREFIX)
    server.send(:rewrite_proxy_html, body, content_type, prefix)
  end

  def test_an_absolute_link_is_prefixed_with_the_proxy_path
    assert_equal(%(<a href="#{PREFIX}/rewriteme">test</a>),
                 rewrite(%(<a href="/rewriteme">test</a>)))
  end

  # A relative link already resolves against the proxied path.
  def test_a_relative_link_is_left_alone
    assert_equal(%(<a href="rewriteme">test</a>), rewrite(%(<a href="rewriteme">test</a>)))
  end

  def test_a_link_to_another_host_is_left_alone
    body = %(<a href="http://example.com/rewriteme">test</a>)

    assert_equal(body, rewrite(body))
  end

  # Rewriting an already-rewritten link would double the prefix.
  def test_an_already_prefixed_link_is_left_alone
    body = %(<a href="#{PREFIX}/rewriteme">test</a>)

    assert_equal(body, rewrite(body))
  end

  def test_a_trailing_slash_survives_the_join
    assert_equal(%(<a href="#{PREFIX}/sub/">test</a>), rewrite(%(<a href="/sub/">test</a>)))
  end

  # Only the attributes upstream's atomsToAttrs table names carry URLs.
  def test_only_url_attributes_are_rewritten
    assert_equal(%(<a href="#{PREFIX}/x" title="/y">t</a>),
                 rewrite(%(<a href="/x" title="/y">t</a>)))
    assert_equal(%(<img src="#{PREFIX}/i.png" alt="/not-a-url">),
                 rewrite(%(<img src="/i.png" alt="/not-a-url">)))
    assert_equal(%(<form action="#{PREFIX}/submit"><input src="#{PREFIX}/b.png"></form>),
                 rewrite(%(<form action="/submit"><input src="/b.png"></form>)))
  end

  def test_a_tag_that_carries_no_url_is_untouched
    body = %(<div data-href="/x">text</div>)

    assert_equal(body, rewrite(body))
  end

  # Upstream rewrites only text/html; a JSON body that happens to contain a
  # quoted path must come back byte for byte.
  def test_a_non_html_body_is_returned_unchanged
    body = %({"href": "/rewriteme"})

    assert_equal(body, rewrite(body, content_type: "application/json"))
  end

  def test_a_request_outside_a_proxy_path_rewrites_nothing
    body = %(<a href="/rewriteme">test</a>)

    assert_equal(body, rewrite(body, prefix: ""))
  end

  # A redirect points at the proxied server's own path and needs the same
  # treatment.
  def test_the_location_header_is_rewritten
    assert_equal("#{PREFIX}/next", server.send(:rewrite_proxy_url, "/next", PREFIX))
    assert_equal("next", server.send(:rewrite_proxy_url, "next", PREFIX))
  end

  Request = Struct.new(:path)
  Route = Struct.new(:subresource_path)

  # A namespace may itself be called "proxy", so the prefix is the request path
  # minus the part that was forwarded, never the path up to the word.
  def test_the_prefix_is_the_request_path_minus_what_was_forwarded
    assert_equal(PREFIX, server.send(:proxy_path_prefix,
                                     Request.new("#{PREFIX}/rewriteme?a=b"), Route.new("rewriteme")))
  end

  def test_a_bare_proxy_path_keeps_its_prefix
    assert_equal(PREFIX, server.send(:proxy_path_prefix, Request.new("#{PREFIX}/"), Route.new("")))
    assert_equal(PREFIX, server.send(:proxy_path_prefix, Request.new(PREFIX), Route.new(nil)))
  end

  def test_a_namespace_named_proxy_does_not_confuse_the_prefix
    path = "/api/v1/namespaces/proxy/pods/agnhost/proxy"

    assert_equal(path, server.send(:proxy_path_prefix, Request.new("#{path}/deep/x"), Route.new("deep/x")))
  end
end
