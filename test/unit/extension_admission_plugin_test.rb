# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/security_admission_fake_context"
require "rubernetes/extension"
require "rubernetes/extension/admission_plugin"

# validate and mutate blocks of stored Extension objects decide about API
# requests, at the end of the admission chain.
class ExtensionAdmissionPluginTest < Minitest::Test
  E = Rubernetes::Extension
  A = Rubernetes::Security::Admission
  S = Rubernetes::Security

  def setup
    @context = SecurityAdmissionFakeContext.new
    @now = 100.0
    @plugin = E::AdmissionPlugin.new(context: @context, clock: -> { @now })
    @chain = A::Chain.new(plugins: [@plugin])
  end

  def store(name, source, generation: 1)
    @context.put("extensions", nil, name, {"metadata" => {"name" => name, "uid" => "#{name}-uid", "generation" => generation,
                                                          "resourceVersion" => generation.to_s},
                                           "spec" => {"source" => source}}, group: E::GROUP)
    @now += E::AdmissionPlugin::REFRESH_SECONDS
  end

  def attributes(object: nil, operation: "CREATE", resource: "pods", group: "", subresource: "", old_object: nil, name: "web")
    object ||= {"metadata" => {"name" => name, "labels" => {}}} unless operation == "DELETE"
    A::Attributes.new(operation: operation, user: S::UserInfo.new(name: "alice", groups: ["dev"]), group: group, version: "v1",
                      resource: resource, kind: "Pod", subresource: subresource, namespace: "shop", name: name, object: object,
                      old_object: old_object)
  end

  def admit(attrs)
    @chain.admit(attrs)
    @chain.validate(attrs)
    attrs
  end

  def test_without_extensions_every_request_passes_untouched
    attrs = attributes

    refute @plugin.handles?(attrs)
    assert_same attrs.object, admit(attrs).object
  end

  def test_a_validating_hook_refuses_with_its_own_words
    store("team-rules", 'validate("pods") { |request| request.reject("Pods need a team label") unless request.object.dig("metadata", "labels", "team") }')

    error = assert_raises(A::Rejected) { admit(attributes) }

    assert_equal "extension team-rules denied the request: Pods need a team label", error.message
    assert_equal 403, error.code
    admit(attributes(object: {"metadata" => {"name" => "web", "labels" => {"team" => "web"}}}))
  end

  def test_a_mutating_hook_changes_the_object_that_is_then_validated
    store("labels", <<~RUBY)
      mutate("pods", on: :create) { |request| request.object["metadata"]["labels"]["touched-by"] = request.user.name }
      validate("pods") { |request| request.reject("not mutated") unless request.object.dig("metadata", "labels", "touched-by") == "alice" }
    RUBY

    assert_equal "alice", admit(attributes).object.dig("metadata", "labels", "touched-by")
  end

  def test_a_validating_hook_cannot_change_what_is_stored
    store("sneaky", 'validate("pods") { |request| request.object["metadata"]["labels"]["sneaked"] = "in" }')

    refute admit(attributes).object.dig("metadata", "labels").key?("sneaked")
  end

  def test_hooks_see_only_the_resources_and_operations_they_named
    store("picky", <<~RUBY)
      validate("deployments.apps", on: :delete) { |request| request.reject("no deleting \#{request.name}") }
      validate("pods/status") { |request| request.reject("no status writes") }
    RUBY

    admit(attributes)
    admit(attributes(resource: "deployments", group: "apps"))
    admit(attributes(resource: "deployments", operation: "DELETE"))
    deletion = assert_raises(A::Rejected) { admit(attributes(resource: "deployments", group: "apps", operation: "DELETE")) }
    status_write = assert_raises(A::Rejected) { admit(attributes(subresource: "status", operation: "UPDATE")) }

    assert_match(/no deleting web/, deletion.message)
    assert_match(/no status writes/, status_write.message)
  end

  def test_a_star_matches_every_resource_but_no_subresource
    store("all", 'validate("*") { |request| request.reject("closed") }')

    assert_raises(A::Rejected) { admit(attributes(resource: "configmaps")) }
    admit(attributes(subresource: "status", operation: "UPDATE"))
  end

  # However broken or greedy an extension is, it can be taken out again.
  def test_requests_for_extensions_themselves_never_reach_a_hook
    store("lockout", 'validate("*", "*/*", on: %i[create update delete]) { |request| request.reject("locked") }')

    refute @plugin.handles?(attributes(resource: "extensions", group: E::GROUP, operation: "DELETE"))
    assert_raises(A::Rejected) { admit(attributes(operation: "DELETE")) }
  end

  def test_a_hook_that_raises_refuses_the_request_and_is_counted
    store("broken", 'validate("pods") { |request| request.no_such_method }')

    error = assert_raises(A::Rejected) { admit(attributes) }

    assert_equal 500, error.code
    assert_match(/extension broken validate hook pods failed: NoMethodError/, error.message)
    assert_equal 1, @context.get("extensions", nil, "broken", group: E::GROUP).dig("status", "components", "admission", "failures")
  end

  def test_a_warning_reaches_the_client_and_the_request_passes
    store("nag", 'validate("pods") { |request| request.warn("please add a team label") }')

    assert_equal ["please add a team label"], admit(attributes).warnings
  end

  def test_a_new_version_takes_over_within_the_refresh_interval
    store("rule", 'validate("pods") { |request| request.reject("v1") }')

    assert_match(/v1/, assert_raises(A::Rejected) { admit(attributes) }.message)

    @context.put("extensions", nil, "rule", {"metadata" => {"name" => "rule", "uid" => "rule-uid", "generation" => 2, "resourceVersion" => "2"},
                                             "spec" => {"source" => 'validate("pods") { |request| request.reject("v2") }'}}, group: E::GROUP)

    assert_match(/v1/, assert_raises(A::Rejected) { admit(attributes) }.message, "within the interval the loaded set is used")

    @now += E::AdmissionPlugin::REFRESH_SECONDS

    assert_match(/v2/, assert_raises(A::Rejected) { admit(attributes) }.message)
    assert @context.get("extensions", nil, "rule", group: E::GROUP).dig("status", "components", "admission", "loaded")
  end

  def test_a_list_that_fails_keeps_the_loaded_hooks
    store("rule", 'validate("pods") { |request| request.reject("still here") }')
    assert_raises(A::Rejected) { admit(attributes) }
    @now += E::AdmissionPlugin::REFRESH_SECONDS

    @context.stub(:list!, ->(*, **) { raise IOError, "store is away" }) do
      assert_match(/still here/, assert_raises(A::Rejected) { admit(attributes) }.message)
    end
  end
end
