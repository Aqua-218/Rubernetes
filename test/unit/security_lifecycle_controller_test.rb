# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller/security_lifecycle"

class SecurityLifecycleControllerTest < Minitest::Test
  Controller = Rubernetes::Controller

  def test_registration_factory_declares_concrete_owners_watches_and_pinned_metadata
    definitions = Controller::SecurityLifecycleRegistration.definitions

    assert_equal Controller::SecurityLifecycleRegistration::CONTROLLER_NAMES.sort, definitions.map(&:name).sort
    assert_equal "disruption-controller",
                 Controller::SecurityLifecycleRegistration.metadata("disruption-controller").fetch("name")
    definitions.each do |definition|
      refute_equal Controller::BaseController, definition.implementation
      refute_nil definition.implementation
      assert definition.reconcile_block.respond_to?(:call)
      assert_equal Controller::BuiltinControllerCorpus.fetch(definition.name).sync_targets, definition.sync_targets
      refute_empty definition.watches
      assert_empty definition.owns
    end
    disruption = definitions.find { |definition| definition.name == "disruption-controller" }
    assert_includes disruption.watches.map(&:via), :label
    assert_includes disruption.watches.map { |watch| watch.resource.kind }, "Pod"
  end

  def test_registration_predicates_only_enqueue_owned_lifecycle_inputs
    definitions = Controller::SecurityLifecycleRegistration.definitions
    bootstrap = definitions.find { |definition| definition.name == "bootstrap-signer-controller" }
    token_cleaner = definitions.find { |definition| definition.name == "token-cleaner-controller" }
    ttl = definitions.find { |definition| definition.name == "ttl-controller" }

    assert_equal ["Job"], ttl.sync_targets

    ordinary_secret = {"kind" => "Secret", "type" => "Opaque",
                       "metadata" => {"name" => "ordinary", "namespace" => "default"}}
    bootstrap_secret = ordinary_secret.merge(
      "type" => "bootstrap.kubernetes.io/token",
      "metadata" => {"name" => "bootstrap-token-abcdef", "namespace" => "kube-system"}
    )
    secret_watch = bootstrap.watches.find { |watch| watch.resource.kind == "Secret" }
    refute secret_watch.predicate.call(ordinary_secret)
    assert secret_watch.predicate.call(bootstrap_secret)
    assert token_cleaner.watches.fetch(0).predicate.call(bootstrap_secret)

    config_watch = bootstrap.watches.find { |watch| watch.resource.kind == "ConfigMap" }
    refute config_watch.predicate.call({"kind" => "ConfigMap", "metadata" => {"name" => "other", "namespace" => "kube-public"}})
    assert config_watch.predicate.call({"kind" => "ConfigMap", "metadata" => {"name" => "cluster-info", "namespace" => "kube-public"}})
    refute ttl.watches.fetch(0).predicate.call({"kind" => "Job", "spec" => {}})
    assert ttl.watches.fetch(0).predicate.call({"kind" => "Job", "spec" => {"ttlSecondsAfterFinished" => 1},
                                                "status" => {"completionTime" => Time.now.utc.iso8601}})
  end

  def test_disruption_controller_computes_safe_pdb_status_and_is_idempotent
    now = Time.utc(2026, 1, 1)
    pdb = pdb_object(min_available: 1)
    pods = [pod("ready", ready: true), pod("unready", ready: false)]
    controller = Controller::DisruptionController.new

    first = controller.plan(pdb, pods: pods, now: now)
    assert_equal 1, first.status.fetch("currentHealthy")
    assert_equal 1, first.status.fetch("desiredHealthy")
    assert_equal 2, first.status.fetch("expectedPods")
    assert_equal 0, first.status.fetch("disruptionsAllowed")
    assert_equal :status_update, first.operations.fetch(0).action

    persisted = pdb.merge("status" => first.status)
    second = controller.plan(persisted, pods: pods, now: now)
    assert_empty second.operations
  end

  def test_disruption_controller_does_not_mutate_pods_or_unrelated_pdbs
    pdb = pdb_object(min_available: 1)
    pods = [pod("ready", ready: true)]
    snapshot = Marshal.load(Marshal.dump(pods))
    result = Controller::DisruptionController.new.plan(pdb, pods: pods, now: Time.utc(2026, 1, 1))

    assert_equal snapshot, pods
    assert result.operations.all? { |operation| operation.resource.kind == "PodDisruptionBudget" }
  end

  def test_csr_approver_requires_explicit_authorization_and_does_not_touch_denied_requests
    csr = csr_object
    controller = Controller::CertificateSigningRequestApprovingController.new

    assert_empty controller.plan(csr).operations
    approved = controller.plan(csr, authorized: true)
    assert_equal ["Approved"], approved.status.fetch("conditions").map { |condition| condition.fetch("type") }
    assert_equal :status_update, approved.operations.fetch(0).action

    denied = csr.merge("status" => {"conditions" => [{"type" => "Denied", "status" => "True"}]})
    assert_empty controller.plan(denied, authorized: true).operations
  end

  def test_csr_signer_clamps_duration_and_signs_only_approved_requests
    csr = csr_object.merge("status" => {"conditions" => [{"type" => "Approved", "status" => "True"}]})
    controller = Controller::CertificateSigningRequestSigningController.new

    assert_equal 600, controller.duration_for(1, 3_600)
    assert_equal 3_600, controller.duration_for(7_200, 3_600)
    result = controller.plan(csr, certificate: "signed")
    assert_equal "signed", result.status.fetch("certificate")
    assert_equal :status_update, result.operations.fetch(0).action
    assert_empty controller.plan(csr_object).operations
    denied = csr.merge("status" => {"conditions" => [
      {"type" => "Approved", "status" => "True"}, {"type" => "Denied", "status" => "True"}
    ]})
    assert_empty controller.plan(denied, certificate: "must-not-sign").operations
  end

  def test_csr_and_pcr_cleaners_apply_time_windows_and_uid_guarded_deletes
    now = Time.utc(2026, 1, 2)
    old_csr = csr_object.merge(
      "metadata" => csr_object.fetch("metadata").merge("creationTimestamp" => (now - 90_000).iso8601)
    )
    csr_result = Controller::CertificateSigningRequestCleanerController.new.plan(old_csr, now: now)
    assert_equal :delete, csr_result.operations.fetch(0).action
    assert_equal "u-csr", csr_result.operations.fetch(0).object.dig("metadata", "uid")

    pcr = {
      "apiVersion" => "certificates.k8s.io/v1beta1", "kind" => "PodCertificateRequest",
      "metadata" => {"name" => "pcr", "namespace" => "default", "uid" => "u-pcr",
                      "creationTimestamp" => (now - 1_801).iso8601}, "status" => {}
    }
    pcr_result = Controller::PodCertificateRequestCleanerController.new.plan(pcr, now: now)
    assert_equal :delete, pcr_result.operations.fetch(0).action
    assert_equal Controller::SecurityLifecycleSupport::PCR, pcr_result.operations.fetch(0).resource
  end

  def test_ttl_controller_rechecks_fresh_job_and_never_deletes_active_job
    now = Time.utc(2026, 1, 1)
    job = job_object(ttl: 10, completion_time: now - 20)
    controller = Controller::TTLController.new
    assert_equal :delete, controller.plan(job, now: now).operations.fetch(0).action

    changed = job.merge("spec" => {"ttlSecondsAfterFinished" => 100})
    assert_empty controller.plan(job, fresh: changed, now: now).operations
    active = job.merge("status" => {})
    assert_empty controller.plan(active, now: now).operations
  end

  def test_bootstrap_signer_recomputes_only_valid_tokens_and_is_idempotent
    now = Time.utc(2026, 1, 1)
    config_map = {
      "apiVersion" => "v1", "kind" => "ConfigMap",
      "metadata" => {"name" => "cluster-info", "namespace" => "kube-public", "uid" => "u-cm"},
      "data" => {"kubeconfig" => "cluster", "jws-kubeconfig-old" => "stale"}
    }
    token = bootstrap_secret("abcdef", "secret", now + 3_600)
    expired = bootstrap_secret("123456", "expired", now - 1)
    result = Controller::BootstrapSignerController.new.plan(config_map, secrets: [token, expired], now: now)
    data = result.operations.fetch(0).object.fetch("data")
    assert data.key?("jws-kubeconfig-abcdef")
    refute data.key?("jws-kubeconfig-old")
    refute data.key?("jws-kubeconfig-123456")
    assert_empty Controller::BootstrapSignerController.new.plan(result.operations.fetch(0).object,
                                                                  secrets: [token, expired], now: now).operations
  end

  def test_token_cleaner_only_deletes_expired_bootstrap_tokens
    now = Time.utc(2026, 1, 1)
    expired = bootstrap_secret("abcdef", "secret", now - 1)
    active = bootstrap_secret("123456", "secret", now + 60)
    controller = Controller::TokenCleanerController.new

    assert_equal :delete, controller.plan(expired, now: now).operations.fetch(0).action
    assert_empty controller.plan(active, now: now).operations
    ordinary = active.merge("type" => "Opaque")
    assert_empty controller.plan(ordinary, now: now).operations
    malformed = active.merge("data" => active.fetch("data").merge("expiration" => "not-a-time"))
    assert_equal :delete, controller.plan(malformed, now: now).operations.fetch(0).action
  end

  def test_node_ipam_allocates_non_overlapping_cidrs_and_preserves_existing_assignment
    node_a = node_object("node-a")
    node_b = node_object("node-b")
    nodes = [node_a, node_b]
    controller = Controller::NodeIPAMController.new
    first = controller.plan(node_a, nodes: nodes, cluster_cidr: "10.244.0.0/16", node_cidr_mask_size: 24)
    assigned_a = first.operations.fetch(0).object.dig("spec", "podCIDR")
    second = controller.plan(node_b, nodes: nodes, cluster_cidr: "10.244.0.0/16", node_cidr_mask_size: 24)
    assigned_b = second.operations.fetch(0).object.dig("spec", "podCIDR")
    refute_equal assigned_a, assigned_b

    existing = node_a.merge("spec" => {"podCIDR" => assigned_a, "podCIDRs" => [assigned_a]})
    assert_empty controller.plan(existing, nodes: [existing, node_b], cluster_cidr: "10.244.0.0/16",
                                 node_cidr_mask_size: 24).operations
  end

  private

  def pdb_object(min_available:)
    {"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget",
     "metadata" => {"name" => "web-pdb", "namespace" => "default", "uid" => "u-pdb", "generation" => 3},
     "spec" => {"selector" => {"matchLabels" => {"app" => "web"}}, "minAvailable" => min_available},
     "status" => {}}
  end

  def pod(name, ready:)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}",
                     "labels" => {"app" => "web"}},
     "status" => {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False"}]}}
  end

  def csr_object
    {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest",
     "metadata" => {"name" => "csr", "uid" => "u-csr"},
     "spec" => {"signerName" => "kubernetes.io/kube-apiserver-client-kubelet",
                 "username" => "system:node:node-a", "usages" => ["client auth"]}, "status" => {}}
  end

  def job_object(ttl:, completion_time:)
    {"apiVersion" => "batch/v1", "kind" => "Job",
     "metadata" => {"name" => "job", "namespace" => "default", "uid" => "u-job"},
     "spec" => {"ttlSecondsAfterFinished" => ttl},
     "status" => {"completionTime" => completion_time.iso8601}}
  end

  def bootstrap_secret(token_id, token_secret, expiration)
    {"apiVersion" => "v1", "kind" => "Secret", "type" => "bootstrap.kubernetes.io/token",
     "metadata" => {"name" => "bootstrap-token-#{token_id}", "namespace" => "kube-system", "uid" => "u-#{token_id}"},
     "data" => {"token-id" => token_id, "token-secret" => token_secret,
                "usage-bootstrap-signing" => "true", "expiration" => expiration.iso8601}}
  end

  def node_object(name)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "uid" => "uid-#{name}"}, "spec" => {}}
  end
end
