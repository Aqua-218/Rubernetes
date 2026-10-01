#!/usr/bin/env ruby
# frozen_string_literal: true

# MutatingAdmissionPolicy reinvocation (Security::Admission::Chain and the
# MutatingAdmissionPolicy plugin) against upstream's reinvoker and mutating
# policy dispatcher: random policies (counters, constants, mirrors, no-op and
# JSONPatch mutations, failing expressions, gates, params), bindings, param
# ConfigMaps and in-tree stub mutators around the policy plugin go to
# test/conformance/kubernetes/map_reinvocation_oracle (compiled into
# k8s.io/apiserver/pkg/admission/plugin/policy/mutating through a go test
# overlay) and to the port; the final labels/annotations/data, the refusal
# and the plugin call trace (which passes ran) must match.
#
#   ruby tools/differential/map_reinvocation_differential.rb [--seed N] [--cases N]

require "json"
require "open3"
require "tmpdir"
$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "rubernetes"
require "rubernetes/api"
require "rubernetes/security"

module MAPReinvocationDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/map_reinvocation_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  PACKAGE = "k8s.io/apiserver/pkg/admission/plugin/policy/mutating"
  A = Rubernetes::Security::Admission
  GROUP = "admissionregistration.k8s.io"
  PARAMS = [%w[pa1 a one], %w[pa2 a two], %w[pb1 b three]].freeze

  module_function

  def pick(random, list) = list.sample(random: random)
  def maybe(random, probability = 0.3) = random.rand < probability

  def apply(expression) = {"patchType" => "ApplyConfiguration", "applyConfiguration" => {"expression" => expression}}
  def json_patch(expression) = {"patchType" => "JSONPatch", "jsonPatch" => {"expression" => expression}}
  def set_label(key, value) = apply(%(Object{metadata: Object.metadata{labels: {#{key}: #{value}}}}))

  def mutation(random, index, parameterised)
    label = "p#{index}"
    kinds = %w[counter counter const mirror noop jsonpatch testfail error gate]
    kinds += %w[param param] if parameterised
    case pick(random, kinds)
    when "counter" then set_label(%("#{label}"), %(string(int(object.?metadata.labels["#{label}"].orValue("0")) + 1)))
    when "const" then set_label(%("#{label}"), %("set"))
    when "mirror"
      other = pick(random, %w[p0 p1 p2 p3 gate tree-0 mirror-0])
      set_label(%("#{label}"), %(object.?metadata.labels["#{other}"].orValue("none")))
    when "noop" then apply("Object{}")
    when "jsonpatch" then json_patch(%([JSONPatch{op: "add", path: "/data/#{label}", value: "v"}]))
    when "testfail"
      json_patch(%([JSONPatch{op: "test", path: "/data/seed", value: "nope"}, JSONPatch{op: "add", path: "/data/#{label}", value: "t"}]))
    when "error" then set_label(%("#{label}"), %(object.data["missing-#{label}"]))
    when "gate" then set_label(%("gate"), %("open"))
    when "param" then set_label(%("#{label}-" + params.metadata.name), "params.data.v")
    end
  end

  def policy(random, index)
    parameterised = maybe(random, 0.3)
    spec = {
      "failurePolicy" => pick(random, %w[Fail Ignore]),
      "reinvocationPolicy" => pick(random, %w[Never IfNeeded IfNeeded]),
      "matchConstraints" => {"matchPolicy" => "Equivalent", "namespaceSelector" => {}, "objectSelector" => {},
                             "resourceRules" => [{"apiGroups" => [""], "apiVersions" => ["v1"], "resources" => ["configmaps"], "operations" => ["CREATE"]}]},
      "mutations" => Array.new(random.rand(1..2)) { mutation(random, index, parameterised) }
    }
    spec["paramKind"] = {"apiVersion" => "v1", "kind" => "ConfigMap"} if parameterised
    if maybe(random, 0.3)
      spec["matchConditions"] = [
        pick(random, [{"name" => "gated", "expression" => %(object.?metadata.labels["gate"].orValue("") == "open")},
                      {"name" => "ungated", "expression" => %(object.?metadata.labels["gate"].orValue("") != "open")},
                      {"name" => "broken", "expression" => %(object.data["missing"] == "x")}])
      ]
    end
    {"apiVersion" => "#{GROUP}/v1", "kind" => "MutatingAdmissionPolicy", "metadata" => {"name" => "p#{index}"}, "spec" => spec}
  end

  def bindings(random, policy)
    name = policy.dig("metadata", "name")
    count = maybe(random, 0.1) ? 0 : random.rand(1..2)
    Array.new(count) do |j|
      spec = {"policyName" => name}
      if policy.dig("spec", "paramKind")
        spec["paramRef"] = if maybe(random, 0.3)
                             {"name" => pick(random, %w[pa1 pb1 missing]), "namespace" => "default"}
                           else
                             {"selector" => {"matchLabels" => {"set" => pick(random, %w[a a b c])}}, "namespace" => "default"}
                           end
        spec["paramRef"]["parameterNotFoundAction"] = pick(random, %w[Deny Allow])
      end
      {"apiVersion" => "#{GROUP}/v1", "kind" => "MutatingAdmissionPolicyBinding", "metadata" => {"name" => "#{name}-b#{j}"}, "spec" => spec}
    end
  end

  def tree(random, index)
    if maybe(random, 0.5)
      {"name" => "Tree#{index}", "type" => "set", "key" => "tree-#{index}", "value" => "x"}
    else
      {"name" => "Tree#{index}", "type" => "mirror", "key" => "mirror-#{index}", "from" => pick(random, %w[p0 p1 gate])}
    end
  end

  def cases(random, count)
    Array.new(count) do
      policies = Array.new(random.rand(1..4)) { |i| policy(random, i) }
      before = Array.new(random.rand(0..2)) { |i| tree(random, i) }
      after = Array.new(random.rand(0..2)) { |i| tree(random, before.length + i) }
      labels = {}
      labels["p0"] = "5" if maybe(random, 0.2)
      labels["gate"] = "open" if maybe(random, 0.1)
      metadata = {"name" => "cm", "namespace" => "default"}
      metadata["labels"] = labels if labels.any?
      {"object" => {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => metadata, "data" => {"seed" => "1"}},
       "params" => PARAMS.map do |name, set, value|
         {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => name, "namespace" => "default", "labels" => {"set" => set}},
          "data" => {"v" => value}}
       end,
       "policies" => policies, "bindings" => policies.flat_map { |item| bindings(random, item) },
       "chain" => before + [{"name" => "MutatingAdmissionPolicy", "type" => "policy"}] + after}
    end
  end

  class Context
    def initialize(registry)
      @objects = Hash.new { |hash, key| hash[key] = {} }
      @registry = registry
    end

    def put(resource, namespace, name, object, group: "")
      @objects[[group, resource, namespace.to_s]][name] = object
    end

    def get(resource, namespace, name, group: "", version: "v1") = @objects[[group, resource, namespace.to_s]][name]

    def list(resource, namespace = nil, group: "", version: "v1")
      return @objects.select { |(g, r, _), _| g == group && r == resource }.values.flat_map(&:values) if namespace.nil?

      @objects[[group, resource, namespace.to_s]].values
    end

    def namespace(name) = get("namespaces", nil, name)
    def feature_enabled?(_gate) = false
    def clock = -> { Time.now.utc }
    def authorizer = nil
    def cel = nil
    def resource_for_kind(_group, kind) = "#{kind.downcase}s"
    def type_for(group, version, kind) = @registry.type_converter(group, version).type_for(group, version, kind)
  end

  class TreeStub < A::Plugin
    def initialize(spec, trace)
      super(spec["name"])
      @spec = spec
      @trace = trace
    end

    def admit(attributes)
      @trace << "#{name}:#{attributes.reinvocation? ? 1 : 0}"
      labels = (attributes.object["metadata"]["labels"] ||= {})
      case @spec["type"]
      when "set" then labels[@spec["key"]] = @spec["value"]
      when "mirror" then labels[@spec["key"]] = labels.fetch(@spec["from"], "none")
      end
    end
  end

  class PolicyStub < A::Plugin
    def initialize(plugin, trace)
      super(plugin.name)
      @plugin = plugin
      @trace = trace
    end

    def admit(attributes)
      @trace << "#{name}:#{attributes.reinvocation? ? 1 : 0}"
      @plugin.admit(attributes)
    end
  end

  def blank(value) = value.nil? || value.empty? ? nil : value

  def run_port(registry, test_case)
    context = Context.new(registry)
    context.put("namespaces", nil, "default", {"metadata" => {"name" => "default"}})
    test_case["params"].each { |param| context.put("configmaps", "default", param.dig("metadata", "name"), param) }
    test_case["policies"].each { |item| context.put("mutatingadmissionpolicies", nil, item.dig("metadata", "name"), item, group: GROUP) }
    test_case["bindings"].each do |item|
      context.put("mutatingadmissionpolicybindings", nil, item.dig("metadata", "name"), item, group: GROUP)
    end
    trace = []
    plugins = test_case["chain"].map do |step|
      if step["type"] == "policy"
        PolicyStub.new(A::Registry.factories.fetch("MutatingAdmissionPolicy").call(context, {}), trace)
      else
        TreeStub.new(step, trace)
      end
    end
    object = Marshal.load(Marshal.dump(test_case["object"]))
    attributes = A::Attributes.new(operation: "CREATE", user: Rubernetes::Security::UserInfo.new(name: "admin"), group: "", version: "v1",
                                   resource: "configmaps", kind: "ConfigMap", namespace: "default", name: "cm", object: object)
    error = nil
    begin
      A::Chain.new(plugins: plugins).admit(attributes)
    rescue A::Rejected => rejected
      error = {"code" => rejected.code, "reason" => rejected.reason, "message" => rejected.message,
               "causes" => blank(Array(rejected.details&.fetch("causes", nil)).map { |cause| cause["message"] })}
    end
    final = attributes.object
    {"labels" => blank(final.dig("metadata", "labels")), "annotations" => blank(final.dig("metadata", "annotations")),
     "data" => blank(final["data"]), "error" => error, "trace" => trace}
  end

  def normalize_oracle(result)
    result.merge("labels" => blank(result["labels"]), "annotations" => blank(result["annotations"]), "data" => blank(result["data"]),
                 "error" => result["error"]&.merge("causes" => blank(result["error"]["causes"])))
  end

  def run_oracle(cases)
    Dir.mktmpdir("map-reinvocation-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate(cases))
      source = File.realpath(SOURCE)
      package = File.join(source, "staging/src", PACKAGE)
      File.write(overlay, JSON.generate("Replace" => {File.join(package, "zz_rubernetes_oracle_test.go") => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output},
                                       "go", "test", "-overlay", overlay, PACKAGE,
                                       "-run", "TestRubernetesMAPReinvocationOracle", "-count=1", chdir: source)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output))
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_927
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 400
    list = cases(Random.new(seed), count)
    registry = Rubernetes::API::FieldManagerRegistry.new(openapi: Rubernetes::API::OpenAPIRepository.new)
    mismatches = list.zip(run_oracle(list)).filter_map do |test_case, want|
      want = normalize_oracle(want)
      got = run_port(registry, test_case)
      [test_case, want, got] unless got == want
    end
    mismatches.first(4).each do |test_case, want, got|
      puts "MISMATCH #{JSON.generate(test_case.slice("policies", "bindings", "chain"))[0, 2500]}"
      puts "  upstream: #{JSON.generate(want)}"
      puts "  port:     #{JSON.generate(got)}"
    end
    puts "#{list.length - mismatches.length}/#{list.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(MAPReinvocationDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
