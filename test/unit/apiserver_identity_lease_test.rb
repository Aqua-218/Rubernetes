# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"

# APIServerIdentity: each API server keeps a kube-system Lease labelled
# apiserver.kubernetes.io/identity=kube-apiserver, held by
# "<lease name>_<uuid>", an hour long; expired ones are collected.  The
# kubernetes Service Endpoints still follow the Leases renewed in the last
# 30 seconds.
class APIServerIdentityLeaseTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @now = Time.utc(2026, 9, 24, 12, 0, 0)
    registry = API::Registry.new
    registry.register(API::Resource.new(group: "coordination.k8s.io", version: "v1", resource: "leases", kind: "Lease", scope: :namespaced))
    @server = API::Server.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil))
    @server.call(API::Request.new(method: "POST", path: "/api/v1/namespaces", headers: {"content-type" => "application/json"},
                                  body: JSON.generate({"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "kube-system"}}),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
    @reconciler = Rubernetes::Bootstrap::KubernetesServiceReconciler.new(
      api_server: @server, logger: nil, advertise_address: "10.0.0.1", secure_port: 6443, service_cidrs: ["10.96.0.0/12"],
      identity: "control-0", clock: -> { @now }
    )
  end

  def leases
    @server.call(API::Request.new(method: "GET", path: "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases",
                                  identity: {"username" => "admin", "groups" => ["system:masters"]})).body["items"]
  end

  def put_lease(name, renew:, label: "kube-apiserver", endpoint: "10.0.0.9:6443", duration: 3600)
    body = {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
            "metadata" => {"name" => name, "namespace" => "kube-system", "labels" => {"apiserver.kubernetes.io/identity" => label},
                           "annotations" => {"rubernetes.io/endpoint" => endpoint}},
            "spec" => {"holderIdentity" => "#{name}_x", "leaseDurationSeconds" => duration, "renewTime" => renew.iso8601(6)}}
    @server.call(API::Request.new(method: "POST", path: "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases",
                                  headers: {"content-type" => "application/json"}, body: JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def test_the_identity_lease_matches_kube_apiserver
    @reconciler.send(:renew_lease)
    lease = leases.find { |item| item["metadata"]["name"].start_with?("apiserver-") }

    assert_equal "apiserver-k3e5qbho2wnaagwsgzixikgt5q", lease["metadata"]["name"]
    assert_equal "kube-apiserver", lease["metadata"]["labels"]["apiserver.kubernetes.io/identity"]
    refute_empty lease["metadata"]["labels"]["kubernetes.io/hostname"].to_s
    assert_match(/\Aapiserver-k3e5qbho2wnaagwsgzixikgt5q_\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/, lease["spec"]["holderIdentity"])
    assert_equal 3600, lease["spec"]["leaseDurationSeconds"]
  end

  # The loopback client writes as kube-apiserver, and a renewal is an Update
  # of the Lease read (leasecontroller), so one Update entry of that manager
  # covers the lease.
  def test_renewals_are_updates_by_kube_apiserver
    @reconciler.send(:renew_lease)
    @now += 10
    @reconciler.send(:renew_lease)
    lease = leases.find { |item| item["metadata"]["name"].start_with?("apiserver-") }

    assert_equal @now.iso8601(6), lease["spec"]["renewTime"]
    managers = lease["metadata"]["managedFields"].map { |entry| entry.values_at("manager", "operation") }

    assert_equal [%w[kube-apiserver Update]], managers
  end

  def test_endpoints_follow_recent_renewals_and_expired_leases_are_collected
    @reconciler.send(:renew_lease)
    put_lease("apiserver-peer", renew: @now - 10, endpoint: "10.0.0.2:6443")
    put_lease("apiserver-quiet", renew: @now - 120, endpoint: "10.0.0.3:6443")
    put_lease("apiserver-gone", renew: @now - 7200, endpoint: "10.0.0.4:6443")
    put_lease("apiserver-legacy", renew: @now - 5, label: "rubernetes-apiserver", endpoint: "10.0.0.5:6443", duration: 30)
    addresses = @reconciler.send(:live_addresses).map { |entry| entry["ip"] }

    assert_equal %w[10.0.0.1 10.0.0.2 10.0.0.5], addresses
    names = leases.map { |item| item["metadata"]["name"] }

    refute_includes names, "apiserver-gone"
    assert_includes names, "apiserver-quiet", "a quiet but unexpired Lease stays"
  end
end
