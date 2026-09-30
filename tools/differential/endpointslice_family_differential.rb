#!/usr/bin/env ruby
# frozen_string_literal: true

# The EndpointSlice controller's address families
# (lib/rubernetes/controller/endpointslice_controller.rb service_address_types
# and endpoint_groups) against staging/src/k8s.io/endpointslice utils.go
# getAddressTypesForService and getEndpointAddresses: generated Services
# (ipFamilies of every shape, headfull / headless / undefaulted clusterIP)
# and Pod IP lists (single- and dual-stack, either order, irregular
# spellings) are given to both; the supported address types and the Pod
# addresses per type are compared.
#
#   ruby tools/differential/endpointslice_family_differential.rb [--cases N] [--seed N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/controller"

module EndpointSliceFamilyDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/endpointslice_family_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/srv/rubernetes/kubernetes-v1.36.2")
  V4 = %w[10.240.0.2 10.241.7.9 192.168.1.1 10.0.0.1].freeze
  V6 = %w[fd00:d8::2 fd00:d8:1::a 2001:db8::1 fd00:d8:2:0:0:0:0:3].freeze

  module_function

  def cases(random, count)
    Array.new(count) do |index|
      families = [[], %w[IPv4], %w[IPv6], %w[IPv4 IPv6], %w[IPv6 IPv4]].sample(random: random)
      cluster_ip = ["", "None", V4.sample(random: random), V6.sample(random: random)].sample(random: random)
      pod_ips = case random.rand(6)
                when 0 then []
                when 1 then [V4.sample(random: random)]
                when 2 then [V6.sample(random: random)]
                when 3 then [V4.sample(random: random), V6.sample(random: random)]
                when 4 then [V6.sample(random: random), V4.sample(random: random)]
                else [V4.sample(random: random), V4.sample(random: random), V6.sample(random: random)]
                end
      {"name" => "case-#{index}", "ipFamilies" => families, "clusterIP" => cluster_ip, "podIPs" => pod_ips}
    end
  end

  def run_port(test_case)
    controller = Rubernetes::Controller::EndpointSliceController.new
    spec = {"selector" => {"app" => "web"}, "ports" => [{"port" => 80}]}
    spec["ipFamilies"] = test_case["ipFamilies"] unless test_case["ipFamilies"].empty?
    spec["clusterIP"] = test_case["clusterIP"] unless test_case["clusterIP"].empty?
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => test_case["name"], "namespace" => "ns", "uid" => "u"},
               "spec" => spec}
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "p-u", "labels" => {"app" => "web"}},
           "spec" => {"nodeName" => "n"},
           "status" => {"podIP" => test_case["podIPs"].first, "podIPs" => test_case["podIPs"].map { |ip| {"ip" => ip} },
                        "phase" => "Running", "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    groups = controller.send(:endpoint_groups, service, [pod])
    {"name" => test_case["name"], "addressTypes" => groups.keys.sort,
     "addresses" => groups.to_h { |type, endpoints| [type, endpoints.flat_map { |endpoint| endpoint["addresses"] }] }}
  end

  def run_oracle(cases)
    Dir.mktmpdir("endpointslice-family-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("cases" => cases))
      source = File.realpath(SOURCE)
      target = File.join(source, "staging/src/k8s.io/endpointslice/zz_rubernetes_family_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output},
                                       "go", "test", "-overlay", overlay, "k8s.io/endpointslice",
                                       "-run", "TestRubernetesEndpointSliceFamilyOracle", "-count=1", chdir: source)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  # utilnet.ParseIPSloppy(...).String() canonicalises an IPv6 spelling; the
  # port keeps the Pod's own string (the API server already stores it
  # canonical), so the comparison canonicalises both sides.
  def normalise(result)
    result.merge("addresses" => result["addresses"].transform_values { |ips| ips.map { |ip| IPAddr.new(ip).to_s } })
  end

  def main(argv)
    require "ipaddr"
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_927
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 2000
    all = cases(Random.new(seed), count)
    expected = run_oracle(all)
    mismatches = all.zip(expected).filter_map do |test_case, want|
      got = run_port(test_case)
      [test_case, normalise(want), normalise(got)] unless normalise(got) == normalise(want)
    end
    mismatches.first(5).each do |test_case, want, got|
      puts "MISMATCH #{test_case.inspect}"
      puts "  upstream: #{want.inspect}"
      puts "  port:     #{got.inspect}"
    end
    puts "#{all.length - mismatches.length}/#{all.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(EndpointSliceFamilyDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
