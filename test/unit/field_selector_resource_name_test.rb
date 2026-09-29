# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"

# RequestInfoFactory: a list or watch whose field selector requires
# metadata.name=<name> is authorized as a request for that name, so an RBAC
# rule with resourceNames allows it.  An aggregated API server reads
# kube-system/extension-apiserver-authentication exactly this way (the
# extension-apiserver-authentication-reader Role); without it the server
# cannot trust the aggregator's front-proxy identity.
class FieldSelectorResourceNameTest < Minitest::Test
  S = Rubernetes::Security
  API = Rubernetes::API

  def setup
    source = Object.new
    role = {"metadata" => {"name" => "extension-apiserver-authentication-reader", "namespace" => "kube-system"},
            "rules" => [{"apiGroups" => [""], "resources" => %w[configmaps], "resourceNames" => %w[extension-apiserver-authentication],
                         "verbs" => %w[get list watch]}]}
    binding = {"metadata" => {"name" => "reader", "namespace" => "kube-system"},
               "roleRef" => {"kind" => "Role", "name" => role["metadata"]["name"]},
               "subjects" => [{"kind" => "ServiceAccount", "name" => "default", "namespace" => "wardle"}]}
    source.define_singleton_method(:cluster_roles) { [] }
    source.define_singleton_method(:cluster_role_bindings) { [] }
    source.define_singleton_method(:roles) { |namespace| namespace == "kube-system" ? [role] : [] }
    source.define_singleton_method(:role_bindings) { |namespace| namespace == "kube-system" ? [binding] : [] }
    tokens = S::Authentication::StaticTokenFile.new(S::Authentication::StaticTokenFile.parse(
                                                      "sa-token,system:serviceaccount:wardle:default,1,\"system:serviceaccounts,system:serviceaccounts:wardle\"\n"
                                                    ))
    pipeline = S::Pipeline.new(authenticator: S::Authentication::Union.new(authenticators: [tokens]),
                               authorizer: S::Authorization::Union.new(authorizers: [S::Authorization::RBAC.new(source: source)]))
    @server = API::Server.new(store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil), security: pipeline)
  end

  def list(query)
    @server.call(API::Request.new(method: "GET", path: "/api/v1/namespaces/kube-system/configmaps#{query}",
                                  headers: {"authorization" => "Bearer sa-token"}))
  end

  def test_the_named_list_is_allowed_and_an_unnamed_one_is_not
    assert_equal 200, list("?fieldSelector=metadata.name%3Dextension-apiserver-authentication").status
    assert_equal 200, list("?fieldSelector=metadata.name%3D%3Dextension-apiserver-authentication&watch=false").status
    assert_equal 403, list("").status
    assert_equal 403, list("?fieldSelector=metadata.name%3Dother").status
    assert_equal 403, list("?fieldSelector=metadata.name!%3Dextension-apiserver-authentication").status
  end

  def test_exact_match_parsing
    match = S::Pipeline.method(:exact_field_match)
    assert_equal "x", match.call("a=b,metadata.name==x", "metadata.name")
    assert_equal "a,b", match.call('metadata.name=a\,b', "metadata.name")
    assert_nil match.call("metadata.name!=x", "metadata.name")
  end
end
