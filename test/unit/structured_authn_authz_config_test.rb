# frozen_string_literal: true

require "tmpdir"
require "yaml"
require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/bootstrap"
require "rubernetes/storage/memory_store"
require "rubernetes/observability/metrics"

# --authorization-config / --authentication-config: structured files with
# validation, webhook matchConditions (CEL over the SubjectAccessReview),
# and automatic reload with the config-controller metrics.
class StructuredAuthnAuthzConfigTest < Minitest::Test
  Z = Rubernetes::Security::Authorization
  A = Rubernetes::Security::Authentication
  S = Rubernetes::Security

  def cel = S::CEL::Evaluator.new

  def user(name, groups: ["system:authenticated"])
    S::UserInfo.new(name: name, uid: "u-#{name}", groups: groups, extra: {})
  end

  def attributes(user, verb:, resource:, namespace: "default")
    Z::Attributes.new(user: user, verb: verb, api_group: "", api_version: "v1", resource: resource, namespace: namespace, name: "x")
  end

  def webhook_entry(name, kubeconfig, conditions: [], failure_policy: "NoOpinion")
    {"type" => "Webhook", "name" => name,
     "webhook" => {"timeout" => "3s", "authorizedTTL" => "30s", "unauthorizedTTL" => "30s", "subjectAccessReviewVersion" => "v1",
                   "matchConditionSubjectAccessReviewVersion" => "v1", "failurePolicy" => failure_policy,
                   "connectionInfo" => {"type" => "KubeConfigFile", "kubeConfigFile" => kubeconfig},
                   "matchConditions" => conditions.map { |expression| {"expression" => expression} }}}
  end

  def authz_document(authorizers)
    {"apiVersion" => "apiserver.config.k8s.io/v1", "kind" => "AuthorizationConfiguration", "authorizers" => authorizers}
  end

  def write_kubeconfig(dir)
    path = File.join(dir, "webhook.kubeconfig")
    File.write(path, {"apiVersion" => "v1", "kind" => "Config", "current-context" => "hook",
                      "clusters" => [{"name" => "hook", "cluster" => {"server" => "https://127.0.0.1:1", "insecure-skip-tls-verify" => true}}],
                      "users" => [{"name" => "hook", "user" => {"token" => "t"}}],
                      "contexts" => [{"name" => "hook", "context" => {"cluster" => "hook", "user" => "hook"}}]}.to_yaml)
    File.chmod(0o600, path)
    path
  end

  # -- AuthorizationConfiguration validation --------------------------------

  def test_authorization_configuration_validation
    Dir.mktmpdir do |dir|
      kubeconfig = write_kubeconfig(dir)
      good = Z::Configuration.from_h(authz_document([{"type" => "Node", "name" => "node"}, {"type" => "RBAC", "name" => "rbac"},
                                                     webhook_entry("audit.example.com", kubeconfig,
                                                                   conditions: ['request.resourceAttributes.namespace == "kube-system"'])]), cel: cel)

      assert_equal %w[Node RBAC Webhook], good.authorizers.map(&:type)
      assert_equal %w[Node RBAC], good.non_webhook_types
      assert_in_delta(3.0, good.authorizers.last.webhook.timeout)
      assert_equal ['request.resourceAttributes.namespace == "kube-system"'], good.authorizers.last.webhook.match_conditions

      invalid = lambda do |authorizers, pattern|
        error = assert_raises(Z::Configuration::InvalidError) { Z::Configuration.from_h(authz_document(authorizers), cel: cel) }
        assert_match(pattern, error.message, error.message)
      end
      invalid.call([], /at least one authorization mode/)
      invalid.call([{"type" => "RBAC", "name" => "a"}, {"type" => "RBAC", "name" => "b"}], /type: Duplicate value: "RBAC"/)
      invalid.call([{"type" => "RBAC", "name" => "a"}, {"type" => "Node", "name" => "a"}], /name: Duplicate value: "a"/)
      invalid.call([{"type" => "RBAC", "name" => "Bad_Name"}], /authorizer name is invalid/)
      invalid.call([{"type" => "Fancy", "name" => "a"}], /Unsupported value: "Fancy"/)
      invalid.call([{"type" => "Webhook", "name" => "a"}], /webhook: Required value: required when type=Webhook/)
      invalid.call([{"type" => "RBAC", "name" => "a", "webhook" => {}}], /may only be specified when type=Webhook/)
      broken = webhook_entry("w", kubeconfig)
      broken["webhook"].merge!("timeout" => "45s", "failurePolicy" => "Sometimes", "subjectAccessReviewVersion" => "v2")
      invalid.call([broken], /timeout: Invalid value: must be > 0s and <= 30s/)
      invalid.call([broken], /failurePolicy: Unsupported value: "Sometimes"/)
      invalid.call([broken], /subjectAccessReviewVersion: Unsupported value: "v2"/)
      missing = webhook_entry("w", "/nonexistent/kubeconfig")
      invalid.call([missing], /kubeConfigFile: Invalid value: error loading file/)
      relative = webhook_entry("w", "relative.kubeconfig")
      invalid.call([relative], /must be an absolute path/)
      no_version = webhook_entry("w", kubeconfig, conditions: ["true"])
      no_version["webhook"].delete("matchConditionSubjectAccessReviewVersion")
      invalid.call([no_version], /matchConditionSubjectAccessReviewVersion: Required value/)
      bad_cel = webhook_entry("w", kubeconfig, conditions: ["request.user =="])
      invalid.call([bad_cel], /matchConditions\[0\].expression: Invalid value: compilation failed/)
      in_cluster = webhook_entry("w", kubeconfig)
      in_cluster["webhook"]["connectionInfo"] = {"type" => "InClusterConfig", "kubeConfigFile" => kubeconfig}
      invalid.call([in_cluster], /can only be set when type=KubeConfigFile/)

      error = assert_raises(Z::Configuration::InvalidError) do
        Z::Configuration.from_h(authz_document([{"type" => "RBAC", "name" => "rbac"}]), cel: cel, require_non_webhook_types: %w[Node RBAC])
      end
      assert_match(/non-webhook authorizer types must not change on reload/, error.message)
      assert_equal good, Z::Configuration.from_h(good.document, cel: cel)
    end
  end

  def test_go_durations
    assert_in_delta(30.0, Z::Configuration.parse_duration("30s", "f"))
    assert_in_delta(90.0, Z::Configuration.parse_duration("1m30s", "f"))
    assert_in_delta(0.5, Z::Configuration.parse_duration("500ms", "f"))
    assert_in_delta(7200.0, Z::Configuration.parse_duration("2h", "f"))
    assert_raises(Z::Configuration::InvalidError) { Z::Configuration.parse_duration("30", "f") }
    assert_raises(Z::Configuration::InvalidError) { Z::Configuration.parse_duration("soon", "f") }
  end

  # -- matchConditions on the webhook authorizer ------------------------------

  def global = Rubernetes::Observability::Metrics.global

  def counter(name, labels)
    line = global.render_own.lines.find do |candidate|
      candidate.start_with?("#{name}{") && labels.all? do |label|
        candidate.include?(label)
      end
    end
    line ? line.split.last.to_f : 0.0
  end

  def test_match_conditions_gate_the_webhook
    calls = []
    transport = lambda do |body|
      calls << JSON.parse(body)
      [200, JSON.generate({"status" => {"allowed" => true}})]
    end
    conditions = Z::MatchConditions.new(expressions: ['request.resourceAttributes.namespace == "kube-system"', "request.user != \"system:anonymous\""],
                                        cel: cel, authorizer_name: "gate.example.com")
    webhook = Z::Webhook.new(transport: transport, name: "gate.example.com", match_conditions: conditions)
    exclusions_before = counter("apiserver_authorization_match_condition_exclusions_total", ['name="gate.example.com"', 'type="Webhook"'])

    assert_predicate webhook.authorize(attributes(user("alice"), verb: "get", resource: "pods", namespace: "kube-system")), :allowed?
    assert_equal 1, calls.length
    assert_equal "gate.example.com", webhook.name
    skipped = webhook.authorize(attributes(user("alice"), verb: "get", resource: "pods", namespace: "default"))

    assert_predicate skipped, :no_opinion?, "a false match condition skips the webhook"
    assert_equal 1, calls.length
    assert_equal exclusions_before + 1,
                 counter("apiserver_authorization_match_condition_exclusions_total", ['name="gate.example.com"', 'type="Webhook"'])
    assert_operator counter("apiserver_authorization_match_condition_evaluation_seconds_count", ['name="gate.example.com"']), :>=, 2

    # An expression that does not yield a bool is an evaluation error: the
    # failure policy decides, and the error is counted.
    bogus = Z::MatchConditions.new(expressions: ["request.user"], cel: cel, authorizer_name: "broken.example.com")
    errors_before = counter("apiserver_authorization_match_condition_evaluation_errors_total", ['name="broken.example.com"'])
    lenient = Z::Webhook.new(transport: transport, name: "broken.example.com", match_conditions: bogus)

    assert_predicate lenient.authorize(attributes(user("alice"), verb: "get", resource: "pods")), :no_opinion?
    strict = Z::Webhook.new(transport: transport, name: "broken.example.com", match_conditions: bogus, failure_policy: "Deny")

    assert_predicate strict.authorize(attributes(user("alice"), verb: "get", resource: "pods")), :denied?
    assert_equal 1, calls.length, "the webhook is never called on a match error"
    assert_equal errors_before + 2,
                 counter("apiserver_authorization_match_condition_evaluation_errors_total", ['name="broken.example.com"'])
    assert_predicate Z::Webhook.new(transport: transport).authorize(attributes(user("alice"), verb: "get", resource: "pods")), :allowed?,
                     "no conditions: always called"
  end

  # -- the reload controller ---------------------------------------------------

  def test_reload_controller_semantics_and_metrics
    Dir.mktmpdir do |dir|
      path = File.join(dir, "authz.yaml")
      File.write(path, "v1")
      applied = []
      loads = []
      metrics = Rubernetes::Observability::Metrics.new
      controller = S::ConfigReloadController.new(kind: "authorization", path: path, apiserver_id: "apiserver-a", metrics: metrics, clock: lambda {
        1234.0
      },
                                                 initial_bytes: "v1", initial_config: {"v" => 1},
                                                 load: lambda { |bytes|
                                                   loads << bytes
                                                   raise ArgumentError, "bad config" if bytes.include?("bad")

                                                   {"v" => bytes.strip}
                                                 },
                                                 apply: lambda { |config|
                                                   raise IOError, "cannot apply" if config["v"] == "v3"

                                                   applied << config
                                                 })
      controller.note_loaded

      assert_match(
        /apiserver_authorization_config_controller_last_config_info\{apiserver_id_hash="sha256:[0-9a-f]{64}",hash="#{S::ConfigReloadController.data_hash("v1")}"\} 1/, metrics.render_own
      )
      refute controller.check!, "unchanged bytes are not a reload"
      assert_empty loads

      File.write(path, "v2")

      assert controller.check!
      assert_equal [{"v" => "v2"}], applied
      text = metrics.render_own

      assert_match(/apiserver_authorization_config_controller_automatic_reloads_total\{[^}]*status="success"\} 1/, text)
      assert_match(/apiserver_authorization_config_controller_automatic_reload_last_timestamp_seconds\{[^}]*status="success"\} 1234/, text)
      assert_equal 1, text.scan("apiserver_authorization_config_controller_last_config_info{").length, "only the current hash is exposed"
      assert_match(/last_config_info\{[^}]*hash="#{S::ConfigReloadController.data_hash("v2")}"\} 1/, text)

      File.write(path, "bad")

      refute controller.check!
      assert_match(/automatic_reloads_total\{[^}]*status="failure"\} 1/, metrics.render_own)
      refute controller.check!, "an invalid file is not retried until it changes"
      assert_equal 2, loads.length
      assert_match(/automatic_reloads_total\{[^}]*status="failure"\} 1/, metrics.render_own)

      File.write(path, "v3")

      refute controller.check!
      assert_match(/automatic_reloads_total\{[^}]*status="failure"\} 2/, metrics.render_own)
      assert_kind_of IOError, controller.last_error

      File.write(path, "v2\n")

      refute controller.check!, "different bytes, same parsed configuration: nothing to apply"
      assert_equal 1, applied.length

      File.delete(path)

      refute controller.check!
      assert_match(/automatic_reloads_total\{[^}]*status="failure"\} 3/, metrics.render_own)
    end
  end

  # -- AuthenticationConfiguration --------------------------------------------

  def jwt_entry(url = "https://issuer.example", audiences: ["k8s"])
    {"issuer" => {"url" => url, "audiences" => audiences}, "claimMappings" => {"username" => {"claim" => "sub", "prefix" => "oidc:"}}}
  end

  def authn_document(jwt, anonymous: nil)
    {"apiVersion" => "apiserver.config.k8s.io/v1", "kind" => "AuthenticationConfiguration",
     "jwt" => jwt}.merge(anonymous ? {"anonymous" => anonymous} : {})
  end

  def test_authentication_configuration_validation
    good = A::Configuration.from_h(authn_document([jwt_entry], anonymous: {"enabled" => true, "conditions" => [{"path" => "/healthz"}]}))

    assert_equal 1, good.jwt.length
    assert_equal({"enabled" => true, "conditions" => [{"path" => "/healthz"}]}, good.anonymous)
    invalid = lambda do |document, pattern|
      error = assert_raises(A::Configuration::InvalidError) { A::Configuration.from_h(document) }
      assert_match(pattern, error.message, error.message)
    end
    invalid.call(authn_document([jwt_entry, jwt_entry]), /issuer.url: Duplicate value/)
    invalid.call(authn_document([jwt_entry("http://issuer.example")]), /URL scheme must be https/)
    invalid.call(authn_document([jwt_entry(audiences: [])]), /at least one issuer.audiences is required/)
    invalid.call(authn_document([jwt_entry(audiences: %w[a b])]), /audienceMatchPolicy must be MatchAny/)
    no_username = jwt_entry.merge("claimMappings" => {"username" => {"claim" => "sub"}})
    invalid.call(authn_document([no_username]), /prefix is required when claim is set/)
    invalid.call(authn_document([], anonymous: {"enabled" => false, "conditions" => [{"path" => "/x"}]}),
                 /enabled should be set to true when conditions are defined/)
    invalid.call(authn_document([]).merge("kind" => "Other"), /kind must be AuthenticationConfiguration/)
    error = assert_raises(A::Configuration::InvalidError) { A::Configuration.from_h(authn_document([jwt_entry]), disallowed_issuers: ["https://issuer.example"]) }
    assert_match(/must not overlap with disallowed issuers/, error.message)
  end

  def test_authentication_union_replaces_the_file_authenticators_in_place
    a = Object.new
    b = Object.new
    c = Object.new
    d = Object.new
    union = A::Union.new(authenticators: [a, b, c])
    union.replace([b], [d])

    assert_equal [a, d, c], union.authenticators
    union.replace([d], [])

    assert_equal [a, c], union.authenticators
    union.replace([], [b])

    assert_equal [a, c, b], union.authenticators
  end

  # -- through the assembly --------------------------------------------------

  def test_assembly_builds_from_files_and_reloads
    Dir.mktmpdir do |dir|
      kubeconfig = write_kubeconfig(dir)
      authz_path = File.join(dir, "authz.yaml")
      File.write(authz_path, authz_document([{"type" => "Node", "name" => "node"}, {"type" => "RBAC", "name" => "rbac"}]).to_yaml)
      authn_path = File.join(dir, "authn.yaml")
      File.write(authn_path, authn_document([jwt_entry], anonymous: {"enabled" => false}).to_yaml)
      config = {"authorization" => {"config_file" => authz_path}, "authentication" => {"config_file" => authn_path},
                "flow_control" => {"enabled" => false}}
      assembly = Rubernetes::Bootstrap::SecurityAssembly.new(config: config, store: Rubernetes::Storage::MemoryStore.new, key_for: lambda { |*|
        ""
      }, apiserver_id: "apiserver-a")
      pipeline = assembly.pipeline

      assert_equal %w[Node RBAC], pipeline.authorizer.modes
      refute pipeline.authenticator.anonymous.enabled
      assert(pipeline.authenticator.authenticators.any? { |authenticator| authenticator.respond_to?(:authenticate_token) })
      assert_equal %w[authentication authorization], assembly.reload_controllers.map(&:kind).sort

      authz_controller = assembly.reload_controllers.find { |controller| controller.kind == "authorization" }
      File.write(authz_path, authz_document([{"type" => "Node", "name" => "node"}, {"type" => "RBAC", "name" => "rbac"},
                                             webhook_entry("audit.example.com", kubeconfig,
                                                           conditions: ['request.resourceAttributes.namespace == "kube-system"'])]).to_yaml)

      assert authz_controller.check!
      assert_equal %w[Node RBAC audit.example.com], pipeline.authorizer.modes, "the pipeline's union sees the new chain"
      File.write(authz_path, authz_document([{"type" => "RBAC", "name" => "rbac"}]).to_yaml)

      refute authz_controller.check!, "dropping a non-webhook authorizer is refused"
      assert_match(/non-webhook authorizer types must not change/, authz_controller.last_error.message)
      assert_equal %w[Node RBAC audit.example.com], pipeline.authorizer.modes

      authn_controller = assembly.reload_controllers.find { |controller| controller.kind == "authentication" }
      before = pipeline.authenticator.authenticators.dup
      File.write(authn_path, authn_document([jwt_entry, jwt_entry("https://other.example")], anonymous: {"enabled" => false}).to_yaml)

      assert authn_controller.check!
      after = pipeline.authenticator.authenticators

      assert_equal before.length + 1, after.length
      File.write(authn_path, authn_document([jwt_entry], anonymous: {"enabled" => true}).to_yaml)

      refute authn_controller.check!
      assert_match(/anonymous: Forbidden: changed from initial configuration file/, authn_controller.last_error.message)
      assert_equal after, pipeline.authenticator.authenticators
    end
  end

  def validate_security(security)
    Rubernetes::Bootstrap::Config.allocate.tap do |config|
      config.instance_variable_set(:@process_name, "rubernetes-apiserver")
    end.send(:validate_security!, security)
  end

  def test_process_config_rejects_mixing_file_and_flags
    Dir.mktmpdir do |dir|
      base = {"authorization" => {"config_file" => File.join(dir, "authz.yaml"), "modes" => ["RBAC"]}}
      error = assert_raises(Rubernetes::Bootstrap::Config::Error) { validate_security(base) }
      assert_match(/modes cannot be combined with config_file/, error.message)
      authn = {"authentication" => {"config_file" => File.join(dir, "authn.yaml"), "anonymous" => {"enabled" => true}}}
      error = assert_raises(Rubernetes::Bootstrap::Config::Error) { validate_security(authn) }
      assert_match(/anonymous cannot be combined with config_file/, error.message)
      validate_security({"authorization" => {"config_file" => File.join(dir, "authz.yaml")}})
      error = assert_raises(Rubernetes::Bootstrap::Config::Error) { validate_security({"authorization" => {"config_file" => "relative.yaml"}}) }
      assert_match(/config_file/, error.message)
    end
  end
end
