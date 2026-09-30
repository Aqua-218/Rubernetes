#!/usr/bin/env ruby
# frozen_string_literal: true

# The field manager (lib/rubernetes/api/managed_fields) against upstream's
# managedfields + structured-merge-diff: random sequences of updates and
# server-side applies by several managers on Deployments, ConfigMaps and
# Services go to test/conformance/kubernetes/managedfields_oracle (compiled
# into k8s.io/apimachinery/pkg/util/managedfields through a go test overlay)
# and to the port; the live object, its managedFields (times aside) and
# every error must match.
#
#   ruby tools/differential/managed_fields_differential.rb [--seed N] [--cases N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/api/managed_fields"

module ManagedFieldsDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/managedfields_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  OPENAPI = File.join(ROOT, "generated/openapi/v3")
  MF = Rubernetes::API::ManagedFields
  MANAGERS = %w[alpha beta gamma kubectl].freeze

  module_function

  def schemas
    @schemas ||= %w[api/v1.json apis/apps/v1.json].each_with_object({}) do |file, all|
      all.merge!(JSON.parse(File.read(File.join(OPENAPI, file))).dig("components", "schemas"))
    end
  end

  def pick(random, list) = list.sample(random: random)
  def some(random, list, max: list.length) = list.sample(random.rand(0..max), random: random)

  def labels(random)
    some(random, %w[app tier team], max: 3).to_h { |key| [key, pick(random, %w[x y z])] }
  end

  def container(random, name)
    item = {"name" => name}
    item["image"] = pick(random, %w[nginx:1 nginx:2 busybox]) if random.rand < 0.9
    ports = some(random, [{"containerPort" => 80, "protocol" => "TCP"}, {"containerPort" => 443, "protocol" => "TCP"},
                          {"containerPort" => 53, "protocol" => "UDP"}], max: 2)
    item["ports"] = ports.map { |port| port.merge(random.rand < 0.3 ? {"name" => pick(random, %w[web dns])} : {}) } if ports.any?
    env = some(random, %w[A B C], max: 2).map { |key| {"name" => key, "value" => pick(random, %w[1 2 3])} }
    item["env"] = env if env.any?
    item["args"] = some(random, %w[--a --b --c], max: 2) if random.rand < 0.3
    item
  end

  def deployment(random)
    object = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "d"}}
    meta_labels = labels(random)
    object["metadata"]["labels"] = meta_labels if meta_labels.any?
    object["metadata"]["annotations"] = {"note" => pick(random, %w[a b])} if random.rand < 0.3
    spec = {}
    spec["replicas"] = random.rand(1..4) if random.rand < 0.6
    spec["selector"] = {"matchLabels" => {"app" => pick(random, %w[x y])}} if random.rand < 0.5
    spec["strategy"] = {"type" => pick(random, %w[Recreate RollingUpdate])} if random.rand < 0.3
    names = some(random, %w[one two three], max: 3)
    template = {}
    template_labels = labels(random)
    template["metadata"] = {"labels" => template_labels} if template_labels.any?
    pod = {}
    pod["containers"] = names.map { |name| container(random, name) } if names.any?
    pod["tolerations"] = [{"key" => pick(random, %w[k1 k2]), "operator" => "Exists"}] if random.rand < 0.2
    pod["nodeSelector"] = {"disk" => pick(random, %w[ssd hdd])} if random.rand < 0.2
    template["spec"] = pod if pod.any?
    spec["template"] = template if template.any?
    object["spec"] = spec if spec.any?
    object["status"] = {"replicas" => random.rand(0..3), "observedGeneration" => random.rand(1..2)} if random.rand < 0.4
    object
  end

  def config_map(random)
    object = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "c"}}
    meta_labels = labels(random)
    object["metadata"]["labels"] = meta_labels if meta_labels.any?
    data = some(random, %w[k1 k2 k3 k4], max: 3).to_h { |key| [key, pick(random, %w[v1 v2])] }
    object["data"] = data if data.any?
    object
  end

  def service(random)
    object = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "s"}}
    spec = {}
    ports = some(random, [80, 443, 8080], max: 2).map do |port|
      item = {"port" => port}
      item["protocol"] = pick(random, %w[TCP UDP]) if random.rand < 0.5
      item["targetPort"] = pick(random, [port, "web"]) if random.rand < 0.5
      item
    end
    spec["ports"] = ports if ports.any?
    spec["selector"] = {"app" => pick(random, %w[x y])} if random.rand < 0.6
    spec["type"] = pick(random, %w[ClusterIP NodePort]) if random.rand < 0.4
    object["spec"] = spec if spec.any?
    object["status"] = {"loadBalancer" => {"ingress" => [{"ip" => pick(random, %w[1.1.1.1 2.2.2.2])}]}} if random.rand < 0.3
    object
  end

  # The less common inputs: set lists, invalid applies, duplicate keys in
  # an update, kubectl's client-side-apply annotation, and a null in the
  # last apply.
  def perturb(random, object, op, last:)
    meta = object["metadata"]
    meta["finalizers"] = some(random, %w[a/x b/y c/z], max: 3) if random.rand < 0.15
    if random.rand < 0.08
      applied = JSON.generate(object.merge("metadata" => meta.except("annotations")))
      meta["annotations"] = (meta["annotations"] || {}).merge("kubectl.kubernetes.io/last-applied-configuration" => applied)
    end
    containers = object.dig("spec", "template", "spec", "containers")
    if op == "update" && containers&.any? && random.rand < 0.1
      containers.first["env"] = [{"name" => "D", "value" => "1"}, {"name" => "D", "value" => "2"}]
    end
    return unless op == "apply"

    roll = random.rand
    if roll < 0.02
      (object["spec"] ||= {})["replicas"] = "three" if object["kind"] == "Deployment"
    elsif roll < 0.04
      (object["spec"] ||= {})["bogus"] = 1 unless object["kind"] == "ConfigMap"
    elsif roll < 0.05
      meta["managedFields"] = []
    elsif roll < 0.06
      object["kind"] = "Other"
    elsif roll < 0.07
      object["apiVersion"] = object["kind"] == "Deployment" ? "apps/v1beta1" : "v2"
    elsif last && roll < 0.15 && object["kind"] == "Deployment"
      (object["spec"] ||= {})["replicas"] = nil
    end
  end

  def cases(random, count)
    Array.new(count) do |index|
      kind = pick(random, %w[Deployment ConfigMap Service])
      builder = {"Deployment" => :deployment, "ConfigMap" => :config_map, "Service" => :service}.fetch(kind)
      group, version = kind == "Deployment" ? %w[apps v1] : ["", "v1"]
      subresource = ""
      reset = []
      roll = random.rand
      if kind == "Service" && roll < 0.35
        reset = [["status"]]
      elsif kind == "Service" && roll < 0.6
        subresource = "status"
        reset = [["spec"]]
      elsif kind == "Deployment" && roll < 0.25
        subresource = "status"
        reset = [["spec"], %w[metadata labels]]
      end
      count = random.rand(1..6)
      steps = Array.new(count) do |position|
        op = random.rand < 0.55 ? "apply" : "update"
        object = send(builder, random)
        perturb(random, object, op, last: position == count - 1)
        {"op" => op, "manager" => pick(random, MANAGERS), "force" => random.rand < 0.25, "object" => object}
      end
      {"name" => "case/#{index}", "group" => group, "version" => version, "kind" => kind, "subresource" => subresource,
       "reset" => reset, "steps" => steps}
    end
  end

  def type_converter
    @type_converter ||= MF::Schema::TypeConverter.from_components(schemas)
  end

  def reset_set(paths)
    return nil if paths.empty?

    MF::FieldPath::Set.from_paths(paths.map { |path| path.map { |part| MF::FieldPath::PathElement.field(part) } })
  end

  def run_port(test_case)
    manager = MF::FieldManager.new(type_converter: type_converter, group: test_case["group"], version: test_case["version"],
                                   kind: test_case["kind"], subresource: test_case["subresource"],
                                   reset_fields: reset_set(test_case["reset"]), clock: -> { Time.utc(2026, 1, 1) })
    api_version = test_case["group"].empty? ? test_case["version"] : "#{test_case["group"]}/#{test_case["version"]}"
    live = {"apiVersion" => api_version, "kind" => test_case["kind"]}
    steps = test_case["steps"].map do |step|
      object = JSON.parse(JSON.generate(step["object"]))
      if step["op"] == "update"
        fields = manager.update(live: live, new_object: object, manager: step["manager"])
        live = with_fields(object, fields)
      else
        merged, fields = manager.apply(live: live, config: object, manager: step["manager"], force: step["force"])
        live = with_fields(merged, fields)
      end
      view(live)
    rescue StandardError => error
      {"error" => error.message}
    end
    {"name" => test_case["name"], "steps" => steps}
  end

  def with_fields(object, fields)
    meta = (object["metadata"] || {}).except("managedFields")
    meta["managedFields"] = fields if fields
    object.merge("metadata" => meta)
  end

  def view(object)
    meta = (object["metadata"] || {}).dup
    fields = meta.delete("managedFields") || []
    content = object.merge("metadata" => meta)
    content.delete("metadata") if meta.empty?
    {"object" => content, "managedFields" => fields.map { |entry| entry.except("time") }}
  end

  def normalize(step)
    return {"error" => step["error"]} if step["error"]

    fields = Array(step["managedFields"]).map { |entry| entry.reject { |_, value| value.nil? || value == "" } }
      .sort_by do |entry|
      [entry["operation"], entry["manager"], entry["apiVersion"],
       entry["subresource"].to_s]
    end
    {"object" => canonical(step["object"]), "managedFields" => canonical(fields)}
  end

  def canonical(value)
    case value
    when Hash then value.keys.sort.to_h { |key| [key, canonical(value[key])] }
    when Array then value.map { |item| canonical(item) }
    when Float then value == value.floor ? value.to_i : value
    else value
    end
  end

  def run_oracle(cases)
    Dir.mktmpdir("managedfields-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("schemas" => schemas, "cases" => cases))
      package = File.join(File.realpath(SOURCE), "staging/src/k8s.io/apimachinery/pkg/util/managedfields")
      File.write(overlay, JSON.generate("Replace" => {File.join(package, "zz_rubernetes_oracle_test.go") => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output},
                                       "go", "test", "-overlay", overlay, "k8s.io/apimachinery/pkg/util/managedfields",
                                       "-run", "TestRubernetesManagedFieldsOracle", "-count=1", chdir: SOURCE)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_925
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 500
    list = cases(Random.new(seed), count)
    mismatches = list.zip(run_oracle(list)).filter_map do |test_case, want|
      got = run_port(test_case)
      index = want["steps"].each_index.find { |i| normalize(want["steps"][i]) != normalize(got["steps"][i] || {}) }
      [test_case, index, want, got] if index
    end
    mismatches.first(3).each do |test_case, index, want, got|
      puts "MISMATCH #{test_case["name"]} step #{index}"
      test_case["steps"].first(index + 1).each do |step|
        puts "  #{step["op"]} #{step["manager"]} force=#{step["force"]} #{JSON.generate(step["object"])}"
      end
      puts "  upstream: #{JSON.generate(normalize(want["steps"][index]))}"
      puts "  port:     #{JSON.generate(normalize(got["steps"][index] || {}))}"
    end
    puts "#{list.length - mismatches.length}/#{list.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(ManagedFieldsDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
