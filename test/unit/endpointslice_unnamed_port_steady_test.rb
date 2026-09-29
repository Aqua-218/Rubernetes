# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# A Service port without a name gets an EndpointSlice port named "" (upstream
# getEndpointPorts always sets Name), and the API server stores it that way.
# The controller left the key out of its candidate, so the stored slice never
# compared equal: every sync rewrote it, and each rewrite's watch event queued
# the next.  With the 200 unnamed-port Services of "[sig-network] Service
# endpoints latency should not be very high" the controller spent all its
# time rewriting slices and the median latency was 26 s.
class EndpointSliceUnnamedPortSteadyTest < Minitest::Test
  Controller = Rubernetes::Controller::EndpointSliceController

  def service
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => "latency-svc", "namespace" => "ns", "uid" => "svc-uid"},
     "spec" => {"selector" => {"app" => "a"}, "ipFamilies" => ["IPv4"], "ports" => [{"protocol" => "TCP", "port" => 80, "targetPort" => 9376}]}}
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "p-uid", "labels" => {"app" => "a"}},
     "spec" => {"nodeName" => "worker-0", "containers" => [{"name" => "c", "image" => "i"}]},
     "status" => {"phase" => "Running", "podIP" => "10.242.0.3",
                  "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def test_the_port_name_is_the_empty_string_as_upstream_writes_it
    create = Controller.new.plan(service, pods: [pod], endpoint_slices: []).operations.first

    assert_equal [{"name" => "", "protocol" => "TCP", "port" => 9376}], create.object["ports"]
  end

  def test_a_slice_as_the_api_stored_it_needs_no_update
    created = Controller.new.plan(service, pods: [pod], endpoint_slices: []).operations.first.object
    stored = Marshal.load(Marshal.dump(created))
    stored["metadata"].merge!("uid" => "slice-uid", "resourceVersion" => "12", "generation" => 1)

    assert_empty Controller.new.plan(service, pods: [pod], endpoint_slices: [stored]).operations
  end
end
