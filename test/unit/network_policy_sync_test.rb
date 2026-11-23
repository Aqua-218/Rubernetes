# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap/assembler"

class NetworkPolicySyncTest < Minitest::Test
  Sync = Rubernetes::Bootstrap::NetworkPolicySync

  class Client
    attr_reader :calls, :streams

    def initialize(lists)
      @lists = lists
      @streams = lists.to_h { |resource, _| [resource, Queue.new] }
      @calls = Queue.new
    end

    def get(resource, namespace:, api_version:, query:)
      @calls.push([:list, resource, namespace, api_version, query])
      result = @lists.fetch(resource)
      raise result if result.is_a?(Exception)

      result
    end

    def watch_each(resource, namespace:, api_version:, query:)
      @calls.push([:watch, resource, namespace, api_version, query])
      stream = @streams.fetch(resource)
      Enumerator.new do |events|
        loop do
          object = stream.pop
          break unless object

          events << object
        end
      end
    end
  end

  class Engine
    attr_reader :publications

    def initialize
      @publications = Queue.new
      @failures = Queue.new
    end

    def fail_next
      @failures.push(true)
    end

    def apply(policies, namespace_labels:, pod_index:)
      unless @failures.empty?
        @failures.pop
        raise IOError, "kernel policy publication failed"
      end

      @publications.push([policies, namespace_labels, pod_index])
    end
  end

  class Log
    attr_reader :errors

    def initialize
      @errors = Queue.new
    end

    def warn(event, **fields)
      @errors.push([event, fields])
    end
  end

  def setup
    @lists = {
      "pods" => kube_list("8", [pod("remote", "r1", "other", "10.1.0.7"), pod("target", "l1", "worker", "10.1.0.99")]),
      "namespaces" => kube_list("9", [namespace("peer", "allowed")]),
      "networkpolicies" => kube_list("10", [policy])
    }
    @client = Client.new(@lists)
    @engine = Engine.new
    @logger = Log.new
    @sync = Sync.new(client: @client, engine: @engine, node_name: "worker", logger: @logger)
  end

  def teardown
    @sync.stop
  end

  def test_start_applies_all_three_lists_and_keeps_owned_local_ip
    @sync.start(pods: [attached_pod])

    assert_predicate @sync, :ready?
    policies, labels, pods = pop(@engine.publications)

    assert_equal(["default-deny"], policies.map { |item| item.dig("metadata", "name") })
    assert_equal({"peer" => {"access" => "allowed"}}, labels)
    local = pods.find { |item| item.fetch("local") }
    remote = pods.find { |item| !item.fetch("local") }

    assert_equal ["10.1.0.5"], local.fetch("ips")
    assert_equal({"current" => "yes"}, local.fetch("labels"))
    assert_equal ["10.1.0.7"], remote.fetch("ips")
    assert_equal [{"name" => "dns", "containerPort" => 53, "protocol" => "UDP"}], remote.fetch("ports")

    calls = Array.new(6) { pop(@client.calls) }
    watches = calls.select { |type, *| type == :watch }.to_h { |_, resource, _, _, query| [resource, query.fetch("resourceVersion")] }

    assert_equal({"pods" => "8", "namespaces" => "9", "networkpolicies" => "10"}, watches)
    assert_includes calls, [:list, "networkpolicies", :all, "networking.k8s.io/v1", nil]
    assert_includes calls, [:list, "namespaces", nil, "v1", nil]
  end

  def test_watch_relist_prunes_stale_policy_and_retries_after_publish_error
    @sync.start(pods: [attached_pod])
    pop(@engine.publications)
    @engine.fail_next
    @lists["networkpolicies"] = kube_list("20", [])
    @client.streams.fetch("networkpolicies").push({"type" => "ERROR", "object" => {"code" => 410}})

    assert_equal "network.policy.watch_failed", pop(@logger.errors).first
    assert_equal "network.policy.publish_failed", pop(@logger.errors).first
    assert_empty pop(@engine.publications).first
    assert_predicate @sync, :ready?
  end

  def test_modifications_delete_different_uid_and_skip_unrelated_pod_status
    @sync.start(pods: [])
    pop(@engine.publications)
    source = @client.streams.fetch("pods")
    remote = pod("remote", "r1", "other", "10.1.0.7")
    source.push(event("MODIFIED", remote.merge("status" => remote.fetch("status").merge("message" => "unrelated")), "11"))
    source.push(event("DELETED", pod("remote", "older-uid", "other", "10.1.0.7"), "12"))
    source.push(event("MODIFIED", pod("remote", "r1", "other", "10.1.0.8"), "13"))

    assert_equal([["10.1.0.8"]], pop(@engine.publications).last.map { |item| item.fetch("ips") })
    source.push(event("DELETED", pod("remote", "r1", "other", "10.1.0.8"), "14"))

    assert_empty pop(@engine.publications).last
  end

  def test_a_failed_initial_list_does_not_publish_a_partial_snapshot
    @lists["networkpolicies"] = ArgumentError.new("invalid list")
    assert_raises(ArgumentError) { @sync.start(pods: [attached_pod]) }
    assert_empty @engine.publications
    refute_predicate @sync, :ready?
  end

  def test_initial_list_retries_a_temporary_control_plane_failure
    pending = @lists.fetch("networkpolicies")
    @lists["networkpolicies"] = IOError.new("API unavailable")
    startup = Thread.new { @sync.start(pods: [attached_pod]) }

    assert_equal "network.policy.initial_list_retry", pop(@logger.errors).first
    assert_empty @engine.publications
    @lists["networkpolicies"] = pending
    startup.value

    assert_equal 1, pop(@engine.publications).first.length
    assert_predicate @sync, :ready?
  end

  private

  def kube_list(version, items)
    {"metadata" => {"resourceVersion" => version}, "items" => items}
  end

  def pop(queue)
    Timeout.timeout(3) { queue.pop }
  end

  def event(type, object, version)
    {"type" => type, "object" => object.merge("metadata" => object.fetch("metadata").merge("resourceVersion" => version))}
  end

  def namespace(name, access)
    {"metadata" => {"name" => name, "uid" => name, "labels" => {"access" => access}}}
  end

  def policy
    {"metadata" => {"name" => "default-deny", "uid" => "p1", "namespace" => "peer"},
     "spec" => {"podSelector" => {}, "policyTypes" => ["Ingress"]}}
  end

  def pod(name, uid, node, ip)
    {"metadata" => {"name" => name, "uid" => uid, "namespace" => "peer", "labels" => {"current" => "yes"}},
     "spec" => {"nodeName" => node, "containers" => [{"ports" => [{"name" => "dns", "containerPort" => 53, "protocol" => "UDP"}]}]},
     "status" => {"podIPs" => [{"ip" => ip}]}}
  end

  def attached_pod
    {"namespace" => "peer", "name" => "target", "uid" => "l1", "ips" => ["10.1.0.5"], "interface" => "veth123",
     "labels" => {}, "ports" => [], "local" => true}
  end
end
