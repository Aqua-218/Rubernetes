# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"
require_relative "../support/security_admission_fake_context"

# Admission reinvocation (admission/reinvocation.go and the reinvocation
# contexts of the mutating webhook and mutating policy dispatchers, v1.36.2).
# tools/differential/map_reinvocation_differential.rb compares the policy side
# with upstream on random chains; these pin the individual rules.
class AdmissionReinvocationTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Admission
  GROUP = "admissionregistration.k8s.io"
  RULE = {"apiGroups" => [""], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["configmaps"]}.freeze

  class Recorder < A::Plugin
    def initialize(inner, trace)
      super(inner.name)
      @inner = inner
      @trace = trace
    end

    def admit(attributes)
      @trace << "#{name}:#{attributes.reinvocation? ? 1 : 0}"
      @inner.admit(attributes)
    end
  end

  def setup
    @context = SecurityAdmissionFakeContext.new
    @context.put("namespaces", nil, "team", {"metadata" => {"name" => "team"}})
    @trace = []
  end

  def attributes(object)
    A::Attributes.new(operation: "CREATE", user: S::UserInfo.new(name: "alice"), group: "", version: "v1", resource: "configmaps",
                      kind: "ConfigMap", namespace: "team", name: "cm", object: object)
  end

  def config_map(labels = {})
    {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm", "namespace" => "team", "labels" => labels},
     "data" => {"k" => "v"}}
  end

  def put_policy(name, expression, reinvocation: "IfNeeded", match_conditions: nil)
    spec = {"failurePolicy" => "Fail", "reinvocationPolicy" => reinvocation,
            "matchConstraints" => {"namespaceSelector" => {}, "objectSelector" => {}, "resourceRules" => [RULE]},
            "mutations" => [{"patchType" => "ApplyConfiguration", "applyConfiguration" => {"expression" => expression}}]}
    spec["matchConditions"] = match_conditions if match_conditions
    @context.put("mutatingadmissionpolicies", nil, name, {"metadata" => {"name" => name}, "spec" => spec}, group: GROUP)
    @context.put("mutatingadmissionpolicybindings", nil, name, {"metadata" => {"name" => name}, "spec" => {"policyName" => name}},
                 group: GROUP)
  end

  def label(key, value) = %(Object{metadata: Object.metadata{labels: {"#{key}": #{value}}}})

  def policy_chain
    A::Chain.new(plugins: [Recorder.new(A::Registry.factories.fetch("MutatingAdmissionPolicy").call(@context, {}), @trace)])
  end

  def test_policy_invocations_run_again_only_when_promoted
    # "a" mirrors b (IfNeeded), "b" sets b (Never): b's change promotes a, which
    # sees the new value on the second pass; b is not run again.
    put_policy("a", label("a", %(object.?metadata.labels["b"].orValue("none"))))
    put_policy("b", label("b", %("x")), reinvocation: "Never")
    attrs = attributes(config_map)
    policy_chain.admit(attrs)

    assert_equal %w[MutatingAdmissionPolicy:0 MutatingAdmissionPolicy:1], @trace
    assert_equal({"a" => "x", "b" => "x"}, attrs.object.dig("metadata", "labels"))
  end

  def test_no_policy_is_called_for_the_first_time_on_reinvocation
    # "a" is gated on a label only "b" sets: skipped on the first pass, so it
    # is not called on the second either, although it matches by then.
    put_policy("a", label("a", %("ran")),
               match_conditions: [{"name" => "gate", "expression" => %(object.?metadata.labels["gate"].orValue("") == "open")}])
    put_policy("b", label("gate", %("open")))
    attrs = attributes(config_map)
    policy_chain.admit(attrs)

    assert_equal %w[MutatingAdmissionPolicy:0 MutatingAdmissionPolicy:1], @trace
    assert_equal({"gate" => "open"}, attrs.object.dig("metadata", "labels"))
  end

  def test_an_applied_patch_asks_for_reinvocation_even_without_a_change
    # VersionedAttributes.Dirty: any applied patch requests the second pass.
    put_policy("a", "Object{}", reinvocation: "Never")
    attrs = attributes(config_map)
    policy_chain.admit(attrs)

    assert_predicate attrs, :reinvoke_requested?
    assert_equal %w[MutatingAdmissionPolicy:0 MutatingAdmissionPolicy:1], @trace
  end

  def test_an_in_tree_change_on_the_first_pass_promotes_every_invoked_policy
    put_policy("a", label("a", %(object.?metadata.labels["tree"].orValue("none"))))
    tree = Class.new(A::Plugin) { define_method(:admit) { |attrs| attrs.object["metadata"]["labels"]["tree"] = "t" } }.new("Tree")
    attrs = attributes(config_map)
    A::Chain.new(plugins: [Recorder.new(A::Registry.factories.fetch("MutatingAdmissionPolicy").call(@context, {}), @trace),
                           tree]).admit(attrs)

    assert_equal({"a" => "t", "tree" => "t"}, attrs.object.dig("metadata", "labels"))
  end

  # dispatchOne: the scheme defaulter runs over every patched object, so the
  # next policy already sees the defaulted fields.
  def test_each_patch_is_defaulted_before_the_next_policy
    @context.define_singleton_method(:default_object) do |_group, _version, _kind, object|
      object.merge("data" => {"defaulted" => "yes"}.merge(object["data"] || {}))
    end
    put_policy("a", label("a", %("x")), reinvocation: "Never")
    put_policy("b", label("seen", %(object.data["defaulted"])), reinvocation: "Never")
    attrs = attributes(config_map)
    policy_chain.admit(attrs)

    assert_equal "yes", attrs.object.dig("metadata", "labels", "seen")
  end

  def webhook_client(patches)
    calls = []
    client = Object.new
    client.define_singleton_method(:call) do |config, review, timeout_seconds:|
      url = config["url"]
      calls << url
      response = {"uid" => review["request"]["uid"], "allowed" => true}
      patch = patches[url]&.call(review["request"]["object"])
      if patch
        response["patchType"] = "JSONPatch"
        response["patch"] = [JSON.generate(patch)].pack("m0")
      end
      [200, {"response" => response}]
    end
    [client, calls]
  end

  def hook(name, url, reinvocation)
    {"name" => name, "clientConfig" => {"url" => url}, "rules" => [RULE], "sideEffects" => "None", "admissionReviewVersions" => ["v1"],
     "reinvocationPolicy" => reinvocation}
  end

  def test_webhooks_are_reinvoked_by_uid_after_a_later_change
    client, calls = webhook_client("https://mark/" => lambda { |object|
      object.dig("metadata", "labels", "mark") ? nil : [{"op" => "add", "path" => "/metadata/labels/mark", "value" => "m"}]
    })
    # Two hooks share a name: their UIDs differ by the duplicate index.
    @context.put("mutatingwebhookconfigurations", nil, "w",
                 {"metadata" => {"name" => "w"}, "webhooks" => [hook("same", "https://observe/", "IfNeeded"), hook("same", "https://observe-2/", "Never"),
                                                                hook("mark", "https://mark/", "Never")]}, group: GROUP)
    attrs = attributes(config_map)
    A::Chain.new(plugins: [A::Registry.factories.fetch("MutatingAdmissionWebhook").call(@context, {"client" => client})]).admit(attrs)

    assert_equal %w[https://observe/ https://observe-2/ https://mark/ https://observe/], calls
    assert_predicate attrs, :reinvocation?
  end

  def test_a_webhook_that_changes_nothing_does_not_reinvoke
    client, calls = webhook_client({})
    @context.put("mutatingwebhookconfigurations", nil, "w",
                 {"metadata" => {"name" => "w"}, "webhooks" => [hook("h", "https://observe/", "IfNeeded")]}, group: GROUP)
    attrs = attributes(config_map)
    A::Chain.new(plugins: [A::Registry.factories.fetch("MutatingAdmissionWebhook").call(@context, {"client" => client})]).admit(attrs)

    assert_equal %w[https://observe/], calls
    refute_predicate attrs, :reinvocation?
  end

  # The reinvocation pass runs every in-tree mutating plugin again, so each
  # must be idempotent (upstream checks this with WithReinvocationTesting).
  def test_default_in_tree_mutators_are_idempotent
    @context.put("serviceaccounts", "team", "default", {"metadata" => {"name" => "default", "namespace" => "team", "uid" => "sa-uid"}})
    @context.put("limitranges", "team", "limits",
                 {"metadata" => {"name" => "limits", "namespace" => "team"},
                  "spec" => {"limits" => [{"type" => "Container", "default" => {"cpu" => "200m"}, "defaultRequest" => {"cpu" => "100m"}}]}})
    @context.put("storageclasses", nil, "standard",
                 {"metadata" => {"name" => "standard", "annotations" => {"storageclass.kubernetes.io/is-default-class" => "true"}}}, group: "storage.k8s.io")
    chain = A::Registry.default_chain(context: @context)
    mutators = chain.plugins.select { |plugin| plugin.mutating? && !plugin.reinvokable? }

    refute_empty mutators
    objects = {
      ["", "v1", "pods",
       "Pod"] => {"metadata" => {"name" => "p", "namespace" => "team"}, "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}},
      ["", "v1", "persistentvolumeclaims",
       "PersistentVolumeClaim"] => {"metadata" => {"name" => "c", "namespace" => "team"}, "spec" => {"accessModes" => ["ReadWriteOnce"]}}
    }
    objects.each do |(group, version, resource, kind), object|
      attrs = A::Attributes.new(operation: "CREATE", user: S::UserInfo.new(name: "alice"), group: group, version: version, resource: resource,
                                kind: kind, namespace: "team", name: object.dig("metadata", "name"), object: Marshal.load(Marshal.dump(object)))
      run = -> { mutators.each { |plugin| plugin.admit(attrs) if plugin.handles?(attrs) } }
      run.call
      first = Marshal.load(Marshal.dump(attrs.object))

      refute_equal object, first, "the #{kind} fixture exercises at least one mutator"
      attrs.mark_reinvocation!
      run.call

      assert_equal first, attrs.object, "#{kind}: a second pass of the in-tree mutators changed the object"
    end
  end
end
