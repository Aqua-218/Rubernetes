# frozen_string_literal: true

require_relative "http_probe_headers"

module Rubernetes
  module GRPCHealthProbe
    module_function

    def check(address, service, timeout)
      require "grpc"
      require "grpc/health/v1/health_services_pb"
      # The kubelet installs its own TCP dialer. A node's HTTP proxy must
      # not receive a health check addressed to a Pod IP.
      channel = {"grpc.enable_http_proxy" => 0, "grpc.primary_user_agent" => HTTPProbeHeaders::USER_AGENT}
      stub = ::Grpc::Health::V1::Health::Stub.new(address, :this_channel_is_insecure, channel_args: channel, timeout: timeout)
      request = ::Grpc::Health::V1::HealthCheckRequest.new(service: service.to_s)
      response = stub.check(request, deadline: Time.now + timeout)
      status = response.status.to_s
      {"success" => status == "SERVING", "message" => "gRPC health check status: #{status}"}
    rescue LoadError => error
      {"success" => false, "message" => "gRPC probe unavailable: #{error.message}"}
    rescue ::GRPC::DeadlineExceeded
      {"success" => false, "message" => "gRPC probe timed out after #{timeout}s"}
    rescue ::GRPC::BadStatus => error
      {"success" => false, "message" => "gRPC probe failed: #{error.message}"}
    end
  end
end
