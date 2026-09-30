# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime/cri/client"
require "tmpdir"
require_relative "../support/grpc_fake_server"

# The CRI client's long-lived gRPC helper against a fake runtime.v1 server in
# another process (grpc is never loaded into the calling process).  The fake
# is a spawned interpreter, not a fork: a fork after an earlier in-process
# grpc test made grpc refuse to start and the server never bound its socket.
class CRIClientTest < Minitest::Test
  Client = Rubernetes::Runtime::CRI::Client
  GENERATED = File.expand_path("../../lib/rubernetes/runtime/cri/generated", __dir__)

  def serve(socket)
    GRPCFakeServer.spawn(socket, <<~RUBY, requires: [File.join(GENERATED, "cri_runtime_v1_services_pb")])
      v1 = Rubernetes::Runtime::CRI::Generated::RuntimeV1
      runtime = Class.new(v1::RuntimeService::Service) do
        define_method(:version) do |request, _call|
          v1::VersionResponse.new(version: request.version, runtime_name: "fake", runtime_version: "1.0", runtime_api_version: "v1")
        end
        define_method(:container_status) do |request, _call|
          raise GRPC::NotFound, "container \#{request.container_id} not found" unless request.container_id == "c1"

          v1::ContainerStatusResponse.new(status: v1::ContainerStatus.new(id: "c1", state: :CONTAINER_RUNNING, exit_code: 0))
        end
        define_method(:exec_sync) do |request, _call|
          sleep 0.3 if request.cmd.first == "slow"
          v1::ExecSyncResponse.new(stdout: request.cmd.join(" ").b, exit_code: 3)
        end
      end
      images = Class.new(v1::ImageService::Service) do
        define_method(:list_images) do |_request, _call|
          v1::ListImagesResponse.new(images: [v1::Image.new(id: "sha256:abc", repo_tags: ["busybox:1.36"], size: 42)])
        end
      end
      server.handle(runtime)
      server.handle(images)
    RUBY
  end

  def with_client
    Dir.mktmpdir("cri-client") do |dir|
      socket = File.join(dir, "cri.sock")
      pid = serve(socket)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 60
      sleep 0.05 until File.socket?(socket) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      client = Client.new(endpoint: "unix://#{socket}", timeout: 20)
      yield client
    ensure
      client&.close
      GRPCFakeServer.stop(pid)
    end
  end

  def test_runtime_and_image_calls
    # An earlier in-process grpc test in the same run may have loaded grpc
    # already; the assertion is about THIS client not loading it.
    preloaded = defined?(::GRPC::Core)
    with_client do |client|
      version = client.runtime("Version", {"version" => "v1"})

      assert_equal %w[v1 fake v1], version.values_at("version", "runtime_name", "runtime_api_version")
      status = client.runtime("ContainerStatus", {"container_id" => "c1"})

      assert_equal "CONTAINER_RUNNING", status.dig("status", "state")
      assert_equal "busybox:1.36", client.image("ListImages").dig("images", 0, "repo_tags", 0)
      refute defined?(::GRPC::Core), "grpc stays out of the calling process" unless preloaded
    end
  end

  def test_errors_carry_the_grpc_code_and_calls_run_concurrently
    with_client do |client|
      error = assert_raises(Client::Error) { client.runtime("ContainerStatus", {"container_id" => "nope"}) }
      assert_equal Client::NOT_FOUND, error.code
      assert_includes error.message, "container nope not found"
      results = Array.new(4) do |index|
        Thread.new do
          client.runtime("ExecSync", {"container_id" => "c1", "cmd" => ["slow", index.to_s]})
        end
      end.map(&:value)

      assert_equal(["slow 0", "slow 1", "slow 2", "slow 3"], results.map { |result| result["stdout"].unpack1("m") })
    end
  end

  def test_a_dead_helper_is_restarted
    with_client do |client|
      client.runtime("Version")
      helper = client.instance_variable_get(:@helper)
      Process.kill(:KILL, helper[:pid])
      helper[:thread].join(5)

      assert_equal "fake", client.runtime("Version")["runtime_name"]
    end
  end
end
