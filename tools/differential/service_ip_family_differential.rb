#!/usr/bin/env ruby
# frozen_string_literal: true

# Service ipFamilies / ipFamilyPolicy defaulting and validation
# (lib/rubernetes/api/service_allocator.rb) against kube-apiserver v1.36.2
# (pkg/registry/core/service/storage/alloc.go initIPFamilyFields), the
# oracle image run in dual-stack mode (--service-cluster-ip-range
# 10.96.0.0/12,fd00:d8:5::/112).  A fixed matrix of Services -- headfull,
# headless with and without a selector, every explicit ipFamilyPolicy and
# ipFamilies shape, ExternalName, explicit cluster IPs, the invalid
# combinations -- is created on both; the HTTP status, the stored
# ipFamilies / ipFamilyPolicy / clusterIP families and the error message of
# a rejected one are compared.
#
#   ruby tools/differential/service_ip_family_differential.rb --kubeconfig <dual-stack Rubernetes kubeconfig>
#
# The Rubernetes cluster must serve the same two service CIDRs (the
# linux-amd64-dualstack-native profile does).

require "json"
require "ipaddr"
require "net/http"
require "openssl"
require "optparse"
require "yaml"
require_relative "../milestones/m1_kubernetes_oracle"

module ServiceIPFamilyDifferential
  ORACLE_RANGES = "10.96.0.0/12,fd00:d8:5::/112"

  module_function

  def cases
    base = ->(name, spec) { {"name" => name, "spec" => {"ports" => [{"port" => 80}]}.merge(spec)} }
    sel = {"selector" => {"app" => "x"}}
    [
      base.call("plain", sel),
      base.call("plain-prefer", sel.merge("ipFamilyPolicy" => "PreferDualStack")),
      base.call("plain-require", sel.merge("ipFamilyPolicy" => "RequireDualStack")),
      base.call("plain-v6", sel.merge("ipFamilies" => ["IPv6"])),
      base.call("plain-v6-require", sel.merge("ipFamilies" => ["IPv6"], "ipFamilyPolicy" => "RequireDualStack")),
      base.call("plain-v6-prefer", sel.merge("ipFamilies" => ["IPv6"], "ipFamilyPolicy" => "PreferDualStack")),
      base.call("plain-both", sel.merge("ipFamilies" => %w[IPv4 IPv6])),
      base.call("plain-both-reversed", sel.merge("ipFamilies" => %w[IPv6 IPv4])),
      base.call("plain-both-single", sel.merge("ipFamilies" => %w[IPv4 IPv6], "ipFamilyPolicy" => "SingleStack")),
      base.call("plain-clusterip-v6", sel.merge("clusterIP" => "fd00:d8:5::77")),
      base.call("plain-clusterips-both", sel.merge("clusterIPs" => ["10.96.0.77", "fd00:d8:5::78"])),
      base.call("plain-clusterips-both-single",
                sel.merge("clusterIPs" => ["10.96.0.79", "fd00:d8:5::79"], "ipFamilyPolicy" => "SingleStack")),
      base.call("headless-selector", sel.merge("clusterIP" => "None")),
      base.call("headless-selector-prefer", sel.merge("clusterIP" => "None", "ipFamilyPolicy" => "PreferDualStack")),
      base.call("headless-selector-require", sel.merge("clusterIP" => "None", "ipFamilyPolicy" => "RequireDualStack")),
      base.call("headless-selector-v6", sel.merge("clusterIP" => "None", "ipFamilies" => ["IPv6"])),
      base.call("headless-selector-both-single",
                sel.merge("clusterIP" => "None", "ipFamilies" => %w[IPv4 IPv6], "ipFamilyPolicy" => "SingleStack")),
      base.call("headless-selectorless", {"clusterIP" => "None"}),
      base.call("headless-selectorless-single", {"clusterIP" => "None", "ipFamilyPolicy" => "SingleStack"}),
      base.call("headless-selectorless-prefer", {"clusterIP" => "None", "ipFamilyPolicy" => "PreferDualStack"}),
      base.call("headless-selectorless-v6", {"clusterIP" => "None", "ipFamilies" => ["IPv6"]}),
      base.call("headless-selectorless-v6-single", {"clusterIP" => "None", "ipFamilies" => ["IPv6"], "ipFamilyPolicy" => "SingleStack"}),
      base.call("headless-selectorless-both", {"clusterIP" => "None", "ipFamilies" => %w[IPv6 IPv4]}),
      base.call("headless-selectorless-both-single",
                {"clusterIP" => "None", "ipFamilies" => %w[IPv4 IPv6], "ipFamilyPolicy" => "SingleStack"}),
      base.call("external-name", {"type" => "ExternalName", "externalName" => "example.com"}),
      base.call("external-name-families",
                {"type" => "ExternalName", "externalName" => "example.com", "ipFamilies" => ["IPv4"], "ipFamilyPolicy" => "SingleStack"}),
      base.call("nodeport-prefer", sel.merge("type" => "NodePort", "ipFamilyPolicy" => "PreferDualStack"))
    ]
  end

  def observe(response)
    status = response[:status]
    body = response[:body]
    if status == 201
      spec = body.fetch("spec")
      {"status" => status,
       "ipFamilies" => spec["ipFamilies"], "ipFamilyPolicy" => spec["ipFamilyPolicy"],
       "clusterIPFamilies" => Array(spec["clusterIPs"]).map do |ip|
         if ip == "None"
           "None"
         else
           (IPAddr.new(ip).ipv6? ? "IPv6" : "IPv4")
         end
       end,
       "clusterIP" => if spec["clusterIP"] == "None"
                        "None"
                      else
                        (spec["clusterIP"].to_s.empty? ? "" : "allocated")
                      end}
    else
      {"status" => status, "message" => normalise_message(body.is_a?(Hash) ? body["message"].to_s : body.to_s)}
    end
  end

  # Field paths and values are compared; the object name is the same on both.
  def normalise_message(message)
    message.gsub(/\s+/, " ").strip
  end

  def run_matrix(namespace)
    cases.to_h do |test_case|
      object = {"apiVersion" => "v1", "kind" => "Service",
                "metadata" => {"name" => test_case["name"], "namespace" => namespace}, "spec" => test_case["spec"]}
      response = yield(:post, "/api/v1/namespaces/#{namespace}/services", object)
      [test_case["name"], observe(response)]
    end.to_h
  end

  def run_oracle
    M1KubernetesOracle::DockerCluster.new(extra_api_args: ["--service-cluster-ip-range=#{ORACLE_RANGES}"]).with_client do |client, _evidence|
      namespace = "svc-family-#{Process.pid}"
      client.request(method: :post, path: "/api/v1/namespaces",
                     body: JSON.generate({"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace}}))
      run_matrix(namespace) do |method, path, body|
        response = client.request(method: method, path: path, body: JSON.generate(body))
        {status: response.status, body: response.body}
      end
    end
  end

  def run_port(kubeconfig)
    config = YAML.safe_load_file(kubeconfig)
    cluster = config.fetch("clusters").first.fetch("cluster")
    user = config.fetch("users").first.fetch("user")
    uri = URI(cluster.fetch("server"))
    http = Net::HTTP.new(uri.hostname, uri.port, nil)
    http.use_ssl = true
    http.ca_file = cluster.fetch("certificate-authority")
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.cert = OpenSSL::X509::Certificate.new(File.read(user.fetch("client-certificate")))
    http.key = OpenSSL::PKey.read(File.read(user.fetch("client-key")))
    call = lambda do |method, path, body|
      request = {post: Net::HTTP::Post, delete: Net::HTTP::Delete}.fetch(method).new(path)
      request["Content-Type"] = "application/json"
      request.body = JSON.generate(body) if body
      response = http.request(request)
      parsed = begin
        JSON.parse(response.body)
      rescue JSON::ParserError
        response.body
      end
      {status: response.code.to_i, body: parsed}
    end
    namespace = "svc-family-#{Process.pid}"
    call.call(:post, "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace}})
    results = run_matrix(namespace) { |method, path, body| call.call(method, path, body) }
    call.call(:delete, "/api/v1/namespaces/#{namespace}", nil)
    results
  end

  def main(argv)
    kubeconfig = ENV.fetch("RUBERNETES_CONFORMANCE_KUBECONFIG", nil)
    OptionParser.new do |parser|
      parser.on("--kubeconfig PATH") { |value| kubeconfig = value }
    end.parse!(argv)
    abort "a dual-stack Rubernetes kubeconfig is required (--kubeconfig)" if kubeconfig.nil?

    expected = run_oracle
    got = run_port(kubeconfig)
    mismatches = expected.keys.reject { |name| expected[name] == got[name] }
    mismatches.each do |name|
      puts "MISMATCH #{name}"
      puts "  upstream: #{expected[name].inspect}"
      puts "  port:     #{got[name].inspect}"
    end
    puts "#{expected.length - mismatches.length}/#{expected.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(ServiceIPFamilyDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
