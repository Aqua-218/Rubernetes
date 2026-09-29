#!/usr/bin/env ruby
# frozen_string_literal: true

# M6 exit criterion 6: malformed, oversized, duplicate-key and
# content-negotiation fuzz corpus against the production API server with
# the full security pipeline.  A case fails when the server raises through
# the handler (500 InternalError with an exception class), hangs past the
# per-request deadline, or lets an unauthorized principal through.  Every
# generated input is reproducible from the seed; failing inputs are written
# to the crash corpus.

require "securerandom"
require "timeout"

require_relative "m6_probe_support"

module M6FuzzProbe
  module_function

  def malformed_bodies(random)
    nested = ("[" * 600) + ("]" * 600)
    duplicate = '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"dup","name":"dup2"},"data":{"a":"1","a":"2"}}'
    invalid_utf8 = "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"".b + [0xff, 0xfe].pack("C*") + "\"}}".b
    with_nul = "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"a".b + [0].pack("C") + "b\"}}".b
    yaml_bomb = "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
    [
      ["empty", ""],
      ["truncated_json", '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"'],
      ["deep_nesting", nested],
      ["duplicate_keys", duplicate],
      ["space_in_name", JSON.generate("apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "bad name"})],
      ["nul_in_name", with_nul],
      ["invalid_utf8", invalid_utf8],
      ["wrong_types", JSON.generate("apiVersion" => 1, "kind" => [], "metadata" => "x")],
      ["huge_value", "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"big\"},\"data\":{\"k\":\"#{"x" * 100_000}\"}}"],
      ["oversized", "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"over\"},\"data\":{\"k\":\"#{"y" * 3_200_000}\"}}"],
      ["yaml_bomb", yaml_bomb],
      ["random_bytes", random.bytes(512)],
      ["random_json_like", "{" + Array.new(50) { "\"#{random.alphanumeric(5)}\":#{random.rand(3).zero? ? "\"#{random.alphanumeric(8)}\"" : random.rand(1 << 40)}" }.join(",") + "}"]
    ]
  end

  def negotiation_headers
    [
      {"accept" => "application/vnd.kubernetes.protobuf"},
      {"accept" => "application/json;as=Table;v=v1;g=meta.k8s.io"},
      {"accept" => "text/html"},
      {"accept" => "*/*;q=0"},
      {"accept" => "application/json;q=abc"},
      {"content-type" => "application/xml"},
      {"content-type" => "application/merge-patch+json; charset=utf-16"},
      {"content-type" => "application/yaml"},
      {"accept-encoding" => "br"},
      {"accept" => "application/json" * 200}
    ]
  end

  def paths(random)
    ["/api/v1/namespaces/default/configmaps", "/api/v1/namespaces/../../etc/passwd", "/api/v1/namespaces/default/configmaps/%00",
     "/apis/apps/v1/namespaces/default/deployments/#{random.alphanumeric(300)}", "/api/v1/namespaces/default/pods?labelSelector=#{"a" * 10_000}",
     "/api/v1/namespaces/default/pods?fieldSelector=metadata.name%3D%3D%3D", "/api/v1/namespaces/default/pods?limit=-1&continue=%FF",
     "/api/v1/namespaces/default/pods?watch=true&resourceVersion=abc", "/openapi/v3/apis/../../etc", "/apis/%2e%2e/%2e%2e",
     "/api/v1/namespaces/default/secrets?resourceVersion=99999999999999999999"]
  end

  def exercise(service, crash_corpus, id, method, path, body: nil, headers: {}, token: "admin-token")
    started = M5ProbeSupport.monotonic
    response = Timeout.timeout(10) { M6ProbeSupport.request(service, method, path, raw_body: body, token: token, headers: headers) }
    elapsed = M5ProbeSupport.monotonic - started
    body_document = response.body.is_a?(Hash) ? response.body : nil
    panic = response.status == 500 && body_document && body_document["reason"] == "InternalError"
    message = body_document && body_document["message"].to_s
    leaks = message && message.match?(/Error\z|#<|\.rb:\d+|NoMethodError|undefined method/)
    passed = !panic && !leaks && response.status.between?(200, 499)
    crash_corpus << {"id" => id, "method" => method, "path" => path, "body_sha256" => body && Digest::SHA256.hexdigest(body.to_s), "status" => response.status, "message" => message} unless passed
    {"id" => id, "method" => method, "path" => path[0, 120], "status" => response.status, "elapsed_seconds" => elapsed.round(4), "panic" => panic == true, "internal_leak" => leaks == true, "passed" => passed}
  rescue Timeout::Error
    crash_corpus << {"id" => id, "method" => method, "path" => path, "hang" => true}
    {"id" => id, "method" => method, "path" => path[0, 120], "hang" => true, "passed" => false}
  rescue StandardError => error
    crash_corpus << {"id" => id, "method" => method, "path" => path, "exception" => "#{error.class}: #{error.message}"}
    {"id" => id, "method" => method, "path" => path[0, 120], "exception" => error.class.name, "passed" => false}
  end

  def run(seed: 20_260_906, iterations: 40)
    started_at = M6ProbeSupport.now
    random = Random.new(seed)
    service = M6ProbeSupport.build_service
    service.send(:install_bootstrap_objects)
    cases = []
    crash_corpus = []
    malformed_bodies(random).each do |name, body|
      %w[POST PUT PATCH].each do |method|
        target = method == "POST" ? "/api/v1/namespaces/default/configmaps" : "/api/v1/namespaces/default/configmaps/x"
        headers = method == "PATCH" ? {"content-type" => "application/merge-patch+json"} : {}
        headers = {"content-type" => "application/yaml"} if name == "yaml_bomb"
        cases << exercise(service, crash_corpus, "body-#{name}-#{method.downcase}", method, target, body: body, headers: headers)
      end
    end
    negotiation_headers.each_with_index do |headers, index|
      cases << exercise(service, crash_corpus, "negotiation-#{index}", "GET", "/api/v1/namespaces/default/configmaps", headers: headers)
      cases << exercise(service, crash_corpus, "negotiation-#{index}-post", "POST", "/api/v1/namespaces/default/configmaps",
                        body: JSON.generate("apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "n#{index}"}), headers: headers)
    end
    paths(random).each_with_index { |path, index| cases << exercise(service, crash_corpus, "path-#{index}", "GET", path) }
    content_types = ["application/json", "application/merge-patch+json", "application/strategic-merge-patch+json", "application/json-patch+json", "application/apply-patch+yaml"]
    iterations.times do |round|
      pairs = Array.new(random.rand(1..20)) do
        value = [random.rand(1 << 62).to_s, "\"#{random.alphanumeric(random.rand(0..64))}\"", "null", "[]", "{}", "true"].sample(random: random)
        "\"#{random.alphanumeric(random.rand(1..40))}\":#{value}"
      end
      body = "{#{pairs.join(",")}}"
      cases << exercise(service, crash_corpus, "random-#{round}", %w[POST PUT PATCH DELETE].sample(random: random), "/api/v1/namespaces/default/configmaps/r#{round}",
                        body: body, headers: {"content-type" => content_types.sample(random: random)})
    end
    # Policy bypass: malformed input replayed by an unauthorized user must stay 401/403.
    bypass = []
    malformed_bodies(random).first(6).each do |name, body|
      response = M6ProbeSupport.request(service, "POST", "/api/v1/namespaces/default/configmaps", raw_body: body, token: "bob-token")
      bypass << {"id" => "bypass-#{name}", "status" => response.status, "passed" => [401, 403].include?(response.status)}
    end
    anonymous = M6ProbeSupport.request(service, "POST", "/api/v1/namespaces/default/configmaps", raw_body: "{}")
    bypass << {"id" => "bypass-anonymous", "status" => anonymous.status, "passed" => [401, 403].include?(anonymous.status)}
    cases.concat(bypass)
    M6ProbeSupport.emit(M6ProbeSupport.report(
      kind: "m6_fuzz_summary", measurement_level: "integration_tested", started_at: started_at, cases: cases,
      extra: {"seed" => seed, "iterations" => iterations, "crash_corpus" => crash_corpus, "panics" => cases.count { |entry| entry["panic"] },
              "hangs" => cases.count { |entry| entry["hang"] }, "policy_bypasses" => bypass.count { |entry| !entry["passed"] },
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/api/server.rb lib/rubernetes/security/pipeline.rb lib/rubernetes/api/request.rb])}
    ))
  end
end

M6FuzzProbe.run if $PROGRAM_NAME == __FILE__
