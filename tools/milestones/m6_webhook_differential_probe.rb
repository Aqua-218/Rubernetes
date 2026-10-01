#!/usr/bin/env ruby
# frozen_string_literal: true

# M6 exit criterion 4 (webhook half): admission webhook timeout, failure
# policy, reinvocation, match policy and AdmissionReview version negotiation
# are compared between the production API server and the pinned
# kube-apiserver oracle.  One TLS webhook backend (the project's own
# Transport::HTTPServer) serves both: it is reachable by the oracle container
# through the Docker network gateway and by the local server on the loopback
# address.  Each scenario registers the same webhook configuration on both
# servers, submits the same ConfigMap, and compares the normalized outcome.

require "openssl"
require "socket"

require_relative "m6_probe_support"
require_relative "m1_kubernetes_oracle"
require "rubernetes/transport"

module M6WebhookDifferentialProbe
  class Backend
    attr_reader :port, :ca_certificate, :calls

    def initialize(bind:)
      @calls = Hash.new(0)
      @ca_certificate, key, certificate = issue_certificates(bind)
      @server = Rubernetes::Transport::HTTPServer.new(method(:handle), host: "0.0.0.0", port: 0, cert: certificate, key: key,
                                                                       read_timeout: 60, shutdown_timeout: 2)
      @server.start
      @port = @server.port
      @bind = bind
    end

    def stop
      @server.stop
    end

    def handle(request)
      path = request.path
      @calls[path] += 1
      review = JSON.parse(request.body.to_s)
      uid = review.dig("request", "uid")
      version = review["apiVersion"]
      response = case path
                 when "/allow" then {"uid" => uid, "allowed" => true}
                 when "/deny" then {"uid" => uid, "allowed" => false,
                                    "status" => {"code" => 403, "message" => "denied by probe webhook", "reason" => "Forbidden"}}
                 when "/label-a", "/label-b"
                   label = path.delete_prefix("/label-")
                   existing = review.dig("request", "object", "metadata", "labels") || {}
                   patch = if existing.empty?
                             [{"op" => "add", "path" => "/metadata/labels",
                               "value" => {label => "1"}}]
                           else
                             [{"op" => "add", "path" => "/metadata/labels/#{label}",
                               "value" => "1"}]
                           end
                   {"uid" => uid, "allowed" => true, "patchType" => "JSONPatch", "patch" => [JSON.generate(patch)].pack("m0")}
                 when "/count"
                   # Records how often it was invoked (reinvocation policy) in the object.
                   count = @calls[path]
                   {"uid" => uid, "allowed" => true, "patchType" => "JSONPatch",
                    "patch" => [JSON.generate([{"op" => "add", "path" => "/data", "value" => {"invocations" => count.to_s}}])].pack("m0")}
                 when "/sleep"
                   sleep 6
                   {"uid" => uid, "allowed" => true}
                 when "/warn"
                   {"uid" => uid, "allowed" => true, "warnings" => ["probe warning"]}
                 else
                   {"uid" => uid, "allowed" => false, "status" => {"code" => 500, "message" => "unknown path"}}
                 end
      Rubernetes::Transport::Response.json({"apiVersion" => version, "kind" => "AdmissionReview", "response" => response}, status: 200)
    end

    def url(path, host:)
      "https://#{host}:#{@port}#{path}"
    end

    def ca_bundle
      [@ca_certificate.to_pem].pack("m0")
    end

    private

    def issue_certificates(bind)
      ca_key = OpenSSL::PKey::EC.generate("prime256v1")
      ca = OpenSSL::X509::Certificate.new
      ca.version = 2
      ca.serial = 1
      ca.subject = OpenSSL::X509::Name.new([%w[CN m6-webhook-ca]])
      ca.issuer = ca.subject
      ca.public_key = ca_key
      ca.not_before = Time.now - 60
      ca.not_after = Time.now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new(ca, ca)
      ca.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
      ca.add_extension(factory.create_extension("keyUsage", "keyCertSign", true))
      ca.sign(ca_key, OpenSSL::Digest.new("SHA256"))
      key = OpenSSL::PKey::EC.generate("prime256v1")
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = 2
      certificate.subject = OpenSSL::X509::Name.new([%w[CN m6-webhook]])
      certificate.issuer = ca.subject
      certificate.public_key = key
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new(ca, certificate)
      sans = bind.map { |address| address.match?(/\A[\d.]+\z/) ? "IP:#{address}" : "DNS:#{address}" }.join(",")
      certificate.add_extension(factory.create_extension("subjectAltName", sans))
      certificate.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth"))
      certificate.sign(ca_key, OpenSSL::Digest.new("SHA256"))
      [ca, key, certificate]
    end
  end

  class OracleClient
    def initialize(client) = @client = client

    def call(method, path, body: nil, headers: {})
      response = @client.request(method: method.downcase.to_sym, path: path, body: body && JSON.generate(body), headers: headers)
      [response.status, response.body, response.headers]
    end
  end

  class LocalClient
    def initialize(service) = @service = service

    def call(method, path, body: nil, headers: {})
      response = M6ProbeSupport.request(@service, method, path, body: body, token: "admin-token", headers: headers)
      [response.status, response.body, response.headers]
    end
  end

  module_function

  RULE = {"apiGroups" => [""], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["configmaps"],
          "scope" => "Namespaced"}.freeze

  def webhook(name, path, backend, host, extra = {})
    {"name" => name, "clientConfig" => {"url" => backend.url(path, host: host), "caBundle" => backend.ca_bundle}, "rules" => [RULE],
     "sideEffects" => "None", "admissionReviewVersions" => ["v1"], "failurePolicy" => "Fail", "timeoutSeconds" => 3,
     "namespaceSelector" => {"matchLabels" => {"m6-webhook" => "yes"}}}.merge(extra)
  end

  def scenarios(backend, host)
    [
      {"id" => "validating_allow", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("allow.probe.example.com", "/allow", backend, host)]},
      {"id" => "validating_deny", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("deny.probe.example.com", "/deny", backend, host)]},
      {"id" => "timeout_fail_policy", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("slow.probe.example.com", "/sleep", backend, host, "timeoutSeconds" => 2, "failurePolicy" => "Fail")]},
      {"id" => "timeout_ignore_policy", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("slow.probe.example.com", "/sleep", backend, host, "timeoutSeconds" => 2, "failurePolicy" => "Ignore")]},
      {"id" => "mutating_patch_and_warning", "kind" => "MutatingWebhookConfiguration",
       "webhooks" => [webhook("a.probe.example.com", "/label-a", backend, host), webhook("w.probe.example.com", "/warn", backend, host)]},
      {"id" => "reinvocation_if_needed", "kind" => "MutatingWebhookConfiguration",
       "webhooks" => [webhook("count.probe.example.com", "/count", backend, host, "reinvocationPolicy" => "IfNeeded"),
                      webhook("b.probe.example.com", "/label-b", backend, host)]},
      {"id" => "reinvocation_never", "kind" => "MutatingWebhookConfiguration",
       "webhooks" => [webhook("count.probe.example.com", "/count", backend, host, "reinvocationPolicy" => "Never"), webhook("b.probe.example.com", "/label-b", backend, host)]},
      {"id" => "match_policy_exact_misses_other_version", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("deny.probe.example.com", "/deny", backend, host, "matchPolicy" => "Exact", "rules" => [RULE.merge("apiVersions" => ["v2"])])]},
      {"id" => "match_conditions_skip", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("deny.probe.example.com", "/deny", backend, host, "matchConditions" => [{"name" => "never", "expression" => "object.metadata.name == 'other'"}])]},
      {"id" => "unsupported_review_version", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("deny.probe.example.com", "/deny", backend, host, "admissionReviewVersions" => ["v1beta1"])]},
      {"id" => "dry_run_side_effects_unknown", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("deny.probe.example.com", "/deny", backend, host, "sideEffects" => "Unknown")], "dry_run" => true},
      {"id" => "object_selector_excludes", "kind" => "ValidatingWebhookConfiguration",
       "webhooks" => [webhook("deny.probe.example.com", "/deny", backend, host, "objectSelector" => {"matchLabels" => {"target" => "yes"}})]}
    ]
  end

  def resource_for(kind)
    kind == "MutatingWebhookConfiguration" ? "mutatingwebhookconfigurations" : "validatingwebhookconfigurations"
  end

  def run_scenario(client, scenario, backend, index)
    name = "m6-probe-#{scenario["id"].tr("_", "-")}"
    resource = resource_for(scenario["kind"])
    configuration = {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => scenario["kind"], "metadata" => {"name" => name},
                     "webhooks" => scenario["webhooks"]}
    status, body, = client.call("POST", "/apis/admissionregistration.k8s.io/v1/#{resource}", body: configuration)
    result = {"configuration_status" => status}
    unless status == 201
      result["configuration_error"] = body.is_a?(Hash) ? body["message"] : body.to_s[0, 200]
      return result
    end
    sleep 1.5 # the oracle's webhook informer must observe the configuration
    query = scenario["dry_run"] ? "?dryRun=All" : ""
    configmap = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "target-#{index}", "namespace" => "m6-webhook"},
                 "data" => {"k" => "v"}}
    backend.calls.delete("/count") # the reinvocation counter is per scenario
    before = backend.calls.dup
    status, body, headers = client.call("POST", "/api/v1/namespaces/m6-webhook/configmaps#{query}", body: configmap)
    result["status"] = status
    if body.is_a?(Hash) && body["kind"] == "Status"
      result["reason"] = body["reason"]
      result["message_fragments"] = ["denied by probe webhook", "failed calling webhook", "context deadline exceeded", "timeout"].select do |fragment|
        body["message"].to_s.include?(fragment)
      end.sort
    elsif body.is_a?(Hash)
      result["labels"] = body.dig("metadata", "labels")
      result["data"] = body["data"]
    end
    warning = headers.respond_to?(:[]) ? (headers["warning"] || headers["Warning"]) : nil
    result["warning"] = warning.to_s.include?("probe warning")
    result["calls"] = backend.calls.each_with_object({}) do |(path, count), delta|
      delta[path] = count - before.fetch(path, 0) if count - before.fetch(path, 0) != 0
    end
    client.call("DELETE", "/apis/admissionregistration.k8s.io/v1/#{resource}/#{name}")
    result
  end

  def prepare(client)
    client.call("POST", "/api/v1/namespaces",
                body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "m6-webhook", "labels" => {"m6-webhook" => "yes"}}})
  end

  def docker_gateway(network)
    output = `docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' #{network} 2>/dev/null`.strip
    output.empty? ? nil : output
  end

  def run
    started_at = M6ProbeSupport.now
    cluster = M1KubernetesOracle::DockerCluster.new
    local_service = M6ProbeSupport.build_service
    local_service.send(:install_bootstrap_objects)
    local_results = {}
    oracle_results = {}
    evidence = nil
    gateway = nil
    backend = nil
    begin
      cluster.with_client do |client, oracle_evidence|
        evidence = oracle_evidence
        gateway = docker_gateway(cluster.network_name) || "172.17.0.1"
        backend = Backend.new(bind: ["127.0.0.1", gateway])
        oracle_client = OracleClient.new(client)
        prepare(oracle_client)
        scenarios(backend, gateway).each_with_index do |scenario, index|
          oracle_results[scenario["id"]] = run_scenario(oracle_client, scenario, backend, index)
        end
        local_client = LocalClient.new(local_service)
        prepare(local_client)
        scenarios(backend, "127.0.0.1").each_with_index do |scenario, index|
          local_results[scenario["id"]] = run_scenario(local_client, scenario, backend, index)
        end
      end
    ensure
      backend&.stop
    end
    cases = (oracle_results.keys | local_results.keys).map do |id|
      expected = oracle_results[id]
      actual = local_results[id]
      {"id" => id, "oracle" => expected, "rubernetes" => actual, "passed" => !expected.nil? && expected == actual}
    end
    M6ProbeSupport.emit(M6ProbeSupport.report(
      kind: "m6_webhook_differential", measurement_level: "differentially_tested", started_at: started_at, cases: cases,
      extra: {"oracle" => evidence, "docker_gateway" => gateway,
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/security/admission/plugins/webhooks.rb lib/rubernetes/transport/http_server.rb])}
    ))
  end
end

M6WebhookDifferentialProbe.run if $PROGRAM_NAME == __FILE__
