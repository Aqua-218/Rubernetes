# frozen_string_literal: true

# Shared helpers for the M6 API-surface probes: an in-process API server
# assembled from the production bootstrap classes (generated catalog,
# security pipeline with RBAC bootstrap, admission chain, CRDs, aggregation).

require "digest"
require "json"
require "tmpdir"

require_relative "m5_probe_support"
$LOAD_PATH.unshift File.join(M5ProbeSupport::ROOT, "lib")
require "rubernetes/api"
require "rubernetes/security"
require "rubernetes/bootstrap/api_server_service"
require "rubernetes/bootstrap/structured_logger"

module M6ProbeSupport
  ROOT = M5ProbeSupport::ROOT
  CORPUS = File.join(ROOT, "schema/kubernetes/v1.36.2")
  DEFAULTS = File.join(ROOT, "schema/kubernetes/v1.36.2-defaults")

  module_function

  def now = M5ProbeSupport.now
  def digest(value) = M5ProbeSupport.digest(value)

  # The evidence runner binds the probe to the captured source identity via
  # RUBERNETES_M6_INPUT_SHA256 / RUBERNETES_M6_INPUT_FILE_COUNT.
  def report(kind:, measurement_level:, started_at:, cases:, extra: {})
    document = M5ProbeSupport.report(kind: kind, measurement_level: measurement_level, started_at: started_at, cases: cases, extra: extra)
    document.merge("milestone" => "M6",
                   "input_sha256" => ENV.fetch("RUBERNETES_M6_INPUT_SHA256", document["input_sha256"]),
                   "input_file_count" => ENV["RUBERNETES_M6_INPUT_FILE_COUNT"] ? Integer(ENV["RUBERNETES_M6_INPUT_FILE_COUNT"]) : document["input_file_count"])
  end

  def emit(document)
    M5ProbeSupport.emit(document)
  end

  def logger(io = File.open(File::NULL, "w"))
    Rubernetes::Bootstrap::StructuredLogger.new(io: io, process_name: "rubernetes-apiserver", level: "warn")
  end

  # Build the production APIServerService with a memory store and the full
  # security section; returns the service (not started: no listener).
  def build_service(security: default_security, feature_gates: {}, store: nil, runtime_config: {})
    config = {"bind_address" => "127.0.0.1", "port" => 0, "max_body_bytes" => 3_145_728, "watch_history_limit" => 100_000,
              "security" => security.merge("feature_gates" => feature_gates), "runtime_config" => runtime_config}
    Rubernetes::Bootstrap::APIServerService.new(config: config, logger: logger, store: store)
  end

  def default_security
    dir = Dir.mktmpdir("m6-security")
    tokens = File.join(dir, "tokens.csv")
    File.write(tokens, "admin-token,admin,1,system:masters\nalice-token,alice,2\nbob-token,bob,3,developers\n")
    {"authentication" => {"token_file" => tokens, "anonymous" => {"enabled" => true}},
     "authorization" => {"modes" => %w[Node RBAC]},
     "admission" => {},
     "audit" => {"policy_file" => write_audit_policy(dir)},
     "flow_control" => {"enabled" => true}}
  end

  def write_audit_policy(dir)
    path = File.join(dir, "audit-policy.yaml")
    File.write(path, "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: RequestResponse\n")
    path
  end

  def request(service, method, path, body: nil, token: nil, headers: {}, raw_body: nil)
    headers = headers.dup
    headers["authorization"] = "Bearer #{token}" if token
    headers["content-type"] ||= "application/json" if body || raw_body
    payload = raw_body || (body && JSON.generate(body))
    service.api_server.call(Rubernetes::API::Request.new(method: method, path: path, headers: headers, body: payload))
  end

  def corpus_discovery(name)
    JSON.parse(File.read(File.join(DEFAULTS, "bootstrap", "discovery-#{name}.json")))
  end
end
