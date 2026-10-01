#!/usr/bin/env ruby
# frozen_string_literal: true

# ValidatingAdmissionPolicy type checking (Security::Admission::PolicyTypeChecker
# and the CEL checker port under lib/rubernetes/security/cel/check) against
# upstream's TypeChecker as kube-controller-manager runs it: random policies
# -- resource rules over built-in kinds (wildcards, subresources, unmapped
# resources, several kinds), paramKinds, variables, and validation
# expressions / messageExpressions built from the kinds' own schemas (valid
# and invalid field paths, type confusions, macros, optionals, string
# formats, literals, request/namespaceObject/authorizer/params/variables) --
# go to test/conformance/kubernetes/cel_typecheck_oracle/typecheck_test.go
# (compiled into k8s.io/kubernetes/pkg/controller/validatingadmissionpolicystatus
# through a go test overlay).  The expression warnings must match exactly;
# only the nanosecond suffix upstream gives object type names and the index
# of free type variables (nondeterministic upstream) are normalized.
#
#   ruby tools/differential/vap_type_checking_differential.rb [--seed N] [--cases N]

require "json"
$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "rubernetes"
require "rubernetes/security"
require "rubernetes/security/admission/policy_type_checker"
require_relative "../schema/import_cel_type_checking"

module VAPTypeCheckingDifferential
  PTC = Rubernetes::Security::Admission::PolicyTypeChecker
  TARGETS = [
    ["apps", "v1", "deployments", "Deployment"], ["", "v1", "pods", "Pod"], ["", "v1", "configmaps", "ConfigMap"],
    ["", "v1", "services", "Service"], ["", "v1", "secrets", "Secret"], ["", "v1", "namespaces", "Namespace"],
    ["batch", "v1", "jobs", "Job"], ["batch", "v1", "cronjobs", "CronJob"], ["apps", "v1", "statefulsets", "StatefulSet"],
    ["apps", "v1", "daemonsets", "DaemonSet"], ["networking.k8s.io", "v1", "ingresses", "Ingress"],
    ["apiextensions.k8s.io", "v1", "customresourcedefinitions", "CustomResourceDefinition"], ["", "v1", "nodes", "Node"],
    ["", "v1", "persistentvolumeclaims", "PersistentVolumeClaim"], ["autoscaling", "v2", "horizontalpodautoscalers", "HorizontalPodAutoscaler"],
    ["rbac.authorization.k8s.io", "v1", "roles", "Role"], ["coordination.k8s.io", "v1", "leases", "Lease"],
    ["admissionregistration.k8s.io", "v1", "validatingadmissionpolicies", "ValidatingAdmissionPolicy"],
    ["policy", "v1", "poddisruptionbudgets", "PodDisruptionBudget"], ["example.com", "v1", "widgets", "Widget"]
  ].freeze
  UNMAPPED = ["unmapped.example.com", "v1", "things"].freeze
  KINDS = (TARGETS.map(&:last) + %w[ConfigMap]).uniq.freeze
  LITERALS = ["1", "'a'", "true", "1.5", "2u", "null", "b'x'", "[1, 2]", "['a']", "{'a': 1}", "duration('1s')",
              "timestamp('2020-01-01T00:00:00Z')"].freeze
  REGEXES = ["a+", "[", "(?i)x", "a{2}", "^a.*$", "(", "\\\\d+"].freeze
  DURATIONS = ["1s", "1x", "-1h30m", "", "1.5h", "0", "10000000000000h"].freeze
  TIMESTAMPS = ["2020-01-01T00:00:00Z", "2020-13-01T00:00:00Z", "not-a-time", "2020-01-01T00:00:00.5+01:00", "0000-01-01T00:00:00Z"].freeze
  FORMATS = ["'%d'", "'%s'", "'%f'", "'%.2f'", "'%x'", "'%b'", "'%o'", "'%e'", "'%q'", "'%'", "'%.'", "'%s %s'", "'100%%'", "'%d'"].freeze
  EXTRAS = [
    "authorizer.group('apps').resource('deployments').check('get').allowed()", "authorizer.path('/x').check('get').reason() == ''",
    "authorizer.foo", "authorizer.serviceAccount('ns', 'sa').group('').resource('pods').namespace('n').check('get').errored()",
    "isURL('https://x')", "url('https://x').getHost() == 'x'", "ip('1.2.3.4').family() == 4", "cidr('10.0.0.0/8').containsIP('1.2.3.4')",
    "[1, 2].sum() > 0", "['a'].join(',') == 'a'", "'abc'.indexOf('b') == 1", "sets.contains([1], [1])", "undefinedFn(1)", "x",
    "optional.of(1).value() == 1", "[?optional.none()].size() == 0", "math.greatest(1, 2) == 2", "quantity('1Gi').isGreaterThan(quantity('1'))",
    "'a'.charAt(0) == 'a'", "'a b'.split(' ').size() == 2", "[3, 1].sort()[0] == 1", "size('abc') == 3", "int('1') == 1", "dyn(1) == 'a'",
    "type(1) == int", "1 + 'a' == 2", "true && 1", "1 || false", "(1 > 0 ? 'a' : 2) == 'a'", "!1", "-'a'", "[1, 'a'].size() > 0",
    "{'a': 1, 'b': 'c'}.size() > 0", "{1: 'a', 'b': 'c'}.size() > 0", "[[1], ['a']].size() > 0", "request.operation == 'CREATE'",
    "request.userInfo.username.startsWith('system:')", "request.kind.kind == 1", "request.nope", "request.userInfo.extra['a'][0] == 'x'",
    "namespaceObject.metadata.labels['a'] == 'b'", "namespaceObject.spec.x", "namespaceObject.status.phase == 1",
    "has(request.userInfo)", "request.dryRun == 'x'", "semver('1.0.0').isLessThan(semver('2.0.0'))", "format.dns1123Label().validate('a').hasValue()",
    "[1, 2].map(x, x * 2)[0] == 2", "[1, 2].filter(x, x)", "{'a': 1}.all(k, k == 1)", "[1].exists_one(x, x == 'a')",
    "[1, 2].all(i, v, i < v)", "{'a': 1}.transformMap(k, v, v + 1)['a'] == 2", "[1].transformList(i, v, v).size() == 1",
    "[2, 1].sortBy(x, x)[0] == 1", "authorizer.requestResource.check('get').allowed()", "authorizer.requestResource.check(1).allowed()",
    "authorizer.requestResource.subresource('x').namespace('n').check('get').reason() == ''", "optional.of(1).optMap(x, x + 1).value() == " \
                                                                                              "2", "optional.of(1).optFlatMap(x, optional.of(x)).hasValue()",
    "'x'.format([1, 2]) == 'x'", "cel.bind(x, 1, x + 1) == 2", "[1, 2].reverse()[0] == 2", "strings.quote('a') == 'a'",
    "'a'.lowerAscii().upperAscii() == 'A'", "[1, 2, 2].distinct().size() == 2", "lists.range(3).size() == 3", "[1].first().value() == 1"
  ].freeze

  module_function

  def pick(random, list) = list.sample(random: random)
  def maybe(random, probability) = random.rand < probability

  def checker
    @checker ||= PTC.new(rest_mapper: method(:map_resource), type_name_suffix: -> { 0 })
  end

  def mapping
    @mapping ||= TARGETS.to_h do |group, version, resource, kind|
      ["#{group}/#{version}/#{resource}", [{"group" => group, "version" => version, "kind" => kind}]]
    end
  end

  def map_resource(group, version, resource)
    Array(mapping["#{group}/#{version}/#{resource}"]).map { |gvk| gvk.values_at("group", "version", "kind") }
  end

  def decl_for(target)
    @decls ||= {}
    @decls[target] ||= checker.decl_type_for([target[0], target[1], target[3]]).last
  end

  # A random selection path from an expression of the given DeclType:
  # [text, DeclType of the result or nil (dyn / unknown)].
  def walk(random, text, decl, depth)
    return [text, decl] if decl.nil? || depth.zero? || maybe(random, 0.15)

    case decl.kind
    when :object
      return [text, decl] if decl.fields.empty?

      return ["#{text}.#{pick(random, %w[nonExisting bogus spec2 item])}", nil] if maybe(random, 0.08)

      name, field = decl.fields.to_a.sample(random: random)
      name = name.delete_prefix("__").delete_suffix("__") if name.start_with?("__") && name.end_with?("__") && maybe(random, 0.7)
      selector = maybe(random, 0.1) ? ".?" : "."
      walk(random, "#{text}#{selector}#{name}", field, depth - 1)
    when :list
      return [text, decl] if maybe(random, 0.4)

      walk(random, "#{text}[0]", decl.elem, depth - 1)
    when :map
      return [text, decl] if maybe(random, 0.4)

      walk(random, maybe(random, 0.5) ? "#{text}['k']" : "#{text}.k", decl.elem, depth - 1)
    else [text, decl]
    end
  end

  def leaf_expression(random, path, decl)
    kind = decl&.kind == :simple ? decl.cel.kind : decl&.kind
    options = ["#{path} == #{pick(random, LITERALS)}", "has(#{path})", "#{path} != null", "size(#{path}) > 0", "string(#{path}) == ''"]
    case kind
    when :string then options += ["#{path}.startsWith('a')", "#{path}.matches('#{pick(random, REGEXES)}')", "#{path}.size() > 1",
                                  "#{path} + 1 == 'a'", "#{path} in ['a', 'b']", "#{path}.lowerAscii() == 'a'", "'%s'.format([#{path}]) == ''"]
    when :int then options += ["#{path} > 1", "#{path} + 1 > 0", "#{path} > '1'", "#{path} * 2.0 > 1", "#{path} / 0 == 1",
                               "'%d'.format([#{path}]) == ''"]
    when :bool then options += ["#{path} && true", "#{path} || 1", "!#{path}"]
    when :list
      element = "x"
      options += ["#{path}.all(#{element}, #{element} == 1)", "#{path}.exists(#{element}, #{element}.name == 'a')", "#{path}.map(#{element}, #{element}.foo).size() > 0",
                  "#{path}.filter(#{element}, #{element} != null).size() > 0", "#{path}.exists_one(#{element}, true)", "#{path}.size() > 0",
                  "#{path}.all(i, v, i < 10)", "#{path}[0] == 1", "1 in #{path}"]
    when :map then options += ["#{path}.all(k, k.startsWith('a'))", "'a' in #{path}", "#{path}['a'] == 1", "#{path}.size() > 0"]
    when :object then options += ["#{path}.?name.orValue('') == ''", "#{path} == {}", "#{path}.nope == 1"]
    when :timestamp then options += ["#{path} > timestamp('2020-01-01T00:00:00Z')", "#{path}.getFullYear() > 1"]
    end
    pick(random, options)
  end

  def object_expression(random, target, root = "object")
    path, decl = walk(random, root, decl_for(target), 6)
    leaf_expression(random, path, decl)
  end

  def extra_expression(random)
    case random.rand(5)
    when 0 then "duration('#{pick(random, DURATIONS)}') > duration('0s')"
    when 1 then "timestamp('#{pick(random, TIMESTAMPS)}') > timestamp('2000-01-01T00:00:00Z')"
    when 2 then "#{pick(random, FORMATS)}.format([#{Array.new(random.rand(0..2)) do
      pick(random, ["1", "'a'", "1.5", "true", "[1]", "{'a': 1}", "duration('1s')", "null", "b'x'", "2u", "object"])
    end.join(", ")}]) == ''"
    else pick(random, EXTRAS)
    end
  end

  # Argument expressions by CEL type name, for random calls.
  POOL = {
    "int" => ["1", "-2", "object.metadata.generation", "size('a')"], "uint" => ["2u", "uint(1)"], "double" => ["1.5", "-0.5"],
    "string" => ["'a'", "object.metadata.name", "'1.2.3.4'", "'https://x/y'", "'10.0.0.0/8'", "'1Gi'", "'1.0.0'"],
    "bytes" => ["b'x'"], "bool" => ["true", "has(object.metadata)"], "null_type" => ["null"],
    "list" => ["[1, 2]", "['a', 'b']", "[]", "object.metadata.finalizers", "[1.5]"], "map" => ["{'a': 1}", "{}", "object.metadata.labels"],
    "google.protobuf.Duration" => ["duration('1s')"], "google.protobuf.Timestamp" => ["timestamp('2020-01-01T00:00:00Z')", "object.metadata.creationTimestamp"],
    "optional_type" => ["optional.of(1)", "optional.none()", "object.?metadata.?name"], "type" => ["type(1)", "int", "string"],
    "net.IP" => ["ip('1.2.3.4')"], "net.CIDR" => ["cidr('10.0.0.0/8')"], "kubernetes.Quantity" => ["quantity('1Gi')"],
    "kubernetes.URL" => ["url('https://x')"], "kubernetes.Semver" => ["semver('1.0.0')"], "dyn" => ["dyn(1)", "object.spec"],
    "kubernetes.authorization.Authorizer" => ["authorizer"], "kubernetes.NamedFormat" => ["format.dns1123Label()"]
  }.freeze
  SKIPPED_FUNCTIONS = /\A(@|cel\.@|_\?\._|_\[\?_\])|@not_strictly_false/

  def functions
    # Functions named by a CEL keyword only make ANTLR syntax errors.
    @functions ||= PTC::Declarations.document.fetch("functions").reject do |function|
      function["name"].match?(SKIPPED_FUNCTIONS) || PTC::CEL_RESERVED.include?(function["name"])
    end
  end

  def argument_for(random, type, depth)
    return random_call(random, depth - 1) if depth.positive? && maybe(random, 0.2)

    name = type && type["kind"] == "type_param" ? pick(random, POOL.keys) : type&.fetch("name", nil)
    name = "dyn" if name.nil? || name.empty?
    pick(random, POOL.fetch(name) { POOL.fetch(pick(random, POOL.keys)) })
  end

  OPERATORS = {"_+_" => "+", "_-_" => "-", "_*_" => "*", "_/_" => "/", "_%_" => "%", "_==_" => "==", "_!=_" => "!=",
               "_<_" => "<", "_<=_" => "<=", "_>_" => ">", "_>=_" => ">=", "_&&_" => "&&", "_||_" => "||", "@in" => "in"}.freeze

  # A random call of a declared function: arguments typed for one of its
  # overloads, or (sometimes) arbitrary.
  def random_call(random, depth = 2)
    function = pick(random, functions)
    overload = pick(random, function["overloads"])
    args = Array(overload["args"]).map { |type| maybe(random, 0.8) ? argument_for(random, type, depth) : argument_for(random, nil, depth) }
    name = function["name"]
    case name
    when *OPERATORS.keys then "(#{args[0]} #{OPERATORS[name]} #{args[1]})"
    when "!_" then "!#{args[0]}"
    when "-_" then "-(#{args[0]})"
    when "_[_]" then "#{args[0]}[#{args[1]}]"
    when "_?_:_" then "(#{args[0]} ? #{args[1]} : #{args[2]})"
    else
      if overload["member"]
        "#{args[0]}.#{name}(#{args[1..].join(", ")})"
      else
        "#{name}(#{args.join(", ")})"
      end
    end
  end

  def expression(random, target, variables, params)
    parts = Array.new(random.rand(1..2)) do
      next random_call(random) if maybe(random, 0.3)

      case random.rand(10)
      when 0..3 then object_expression(random, target)
      when 4 then object_expression(random, target, "oldObject")
      when 5 then if variables.any? && maybe(random,
                                             0.7)
                    "variables.#{pick(random, variables)} == 1"
                  else
                    "variables.#{pick(random, %w[v0 nope])} == 1"
                  end
      when 6 then params ? object_expression(random, params, "params") : "params.data['x'] == 'y'"
      else extra_expression(random)
      end
    end
    parts.length == 1 ? parts.first : parts.join(pick(random, [" && ", " || "]))
  end

  def rule(random)
    targets = Array.new(random.rand(1..2)) { pick(random, TARGETS) }
    targets << UNMAPPED if maybe(random, 0.1)
    groups = targets.map(&:first).uniq
    versions = targets.map { |target| target[1] }.uniq
    resources = targets.map { |target| target[2] }.uniq
    groups = ["*"] if maybe(random, 0.05)
    resources += ["pods/status"] if maybe(random, 0.1)
    resources = ["*"] if maybe(random, 0.03)
    [{"apiGroups" => groups, "apiVersions" => versions, "resources" => resources, "operations" => ["CREATE"]}, targets.first]
  end

  def policy(random, index)
    rules = Array.new(random.rand(1..2)) { rule(random) }
    target = rules.first.last
    target = TARGETS.first if target == UNMAPPED
    spec = {"matchConstraints" => {"resourceRules" => rules.map(&:first)}}
    params = nil
    if maybe(random, 0.35)
      params = pick(random, [TARGETS[2], TARGETS[0], nil])
      spec["paramKind"] = if params
                            {"apiVersion" => params[0].empty? ? params[1] : "#{params[0]}/#{params[1]}", "kind" => params[3]}
                          else
                            pick(random,
                                 [{"apiVersion" => "a/b/c", "kind" => "X"}, {"apiVersion" => "example.com/v1", "kind" => "Widget"}, {"kind" => "ConfigMap"}])
                          end
    end
    names = []
    if maybe(random, 0.3)
      spec["variables"] = Array.new(random.rand(1..3)) do |i|
        names << "v#{i}"
        {"name" => "v#{i}", "expression" => pick(random, ["1", "'a'", "[1, 2]", "{'a': [1]}", "object.metadata.name", "object.spec",
                                                          "duration('1s')", "1 + 'a'", "variables.v0", "optional.of(1)", "[1, 'a']",
                                                          "timestamp('2020-01-01T00:00:00Z')", "object.metadata.labels"])}
      end
    end
    spec["validations"] = Array.new(random.rand(1..3)) do
      validation = {"expression" => expression(random, target, names, params)}
      if maybe(random, 0.25)
        validation["messageExpression"] = pick(random, ["'bad: ' + #{walk(random, "object", decl_for(target), 4).first}", "'x'", "1",
                                                        "string(object.metadata.name)", "'%s'.format([object.metadata.name])"])
      end
      validation
    end
    {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "ValidatingAdmissionPolicy", "metadata" => {"name" => "p#{index}"},
     "spec" => spec}
  end

  def normalize(warnings)
    return nil if warnings.nil?

    # Upstream numbers free type variables nondeterministically (the same
    # policy checked twice can print _var6 or _var7), so the index is masked.
    pattern = /\b(#{KINDS.join("|")})\d+/
    warnings.map do |warning|
      {"fieldRef" => warning["fieldRef"], "warning" => warning["warning"].gsub(pattern, '\1#').gsub(/\b_var\d+/, "_var#")}
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_927
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 300
    random = Random.new(seed)
    policies = Array.new(count) { |index| policy(random, index) }
    oracle = CELTypeCheckingImporter.run(CELTypeCheckingImporter::KCM_PACKAGE, "TestRubernetesTypeCheckOracle",
                                         {"mapping" => mapping, "policies" => policies})
    mismatches = policies.zip(oracle).filter_map do |policy, want|
      got = normalize(checker.check(policy)&.map(&:to_h))
      want = normalize(want)
      [policy, want, got] unless got == want
    end
    mismatches.first(5).each do |policy, want, got|
      puts "MISMATCH #{JSON.generate(policy["spec"])[0, 1500]}"
      puts "  upstream: #{JSON.generate(want)[0, 1500]}"
      puts "  port:     #{JSON.generate(got)[0, 1500]}"
    end
    warned = oracle.count { |result| result && !result.empty? }
    puts "#{policies.length - mismatches.length}/#{policies.length} match (#{warned} with warnings)"
    mismatches.empty? ? 0 : 1
  end
end

exit(VAPTypeCheckingDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
