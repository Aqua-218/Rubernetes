# frozen_string_literal: true

require "net/http"
require "stringio"
require "timeout"
require "tmpdir"
require "yaml"
require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/runtime/cri"

class KubeletImagePullConcurrencyTest < Minitest::Test
  Image = Rubernetes::Image
  CRI = Rubernetes::Runtime::CRI
  PROCESS = "rubernetes-agent"

  class StatusClient
    def rest_client = nil
    def apply(object, **) = object
    def create(_path, object) = object
  end

  class FixtureAssembler < Rubernetes::Bootstrap::Assembler
    private

    def build_api_client(_process) = StatusClient.new
  end

  class BlockingRegistry
    attr_reader :entered

    def initialize
      @entered = Queue.new
      @releases = %w[first second third cri].to_h { |name| [name, Queue.new] }
    end

    def pull(reference, platform:, rootfs:, unpack:)
      transfer(reference.tag)
      digest = Image::Digest.parse("sha256:#{Digest::SHA256.hexdigest(reference.to_s)}")
      config = {"os" => platform.os, "architecture" => platform.architecture, "config" => {"Cmd" => ["/bin/sh"]}}
      Image::Image.new(reference: reference.with_digest(digest), manifest: Struct.new(:digest).new(digest),
                       config: JSON.generate(config), rootfs: rootfs, config_object: config)
    end

    def runtime(_method, _request = {}, **) = {}

    def image(method, request, **)
      return {"image" => {"id" => "cached"}} if method == "ImageStatus"

      raise "unexpected CRI ImageService method #{method}" unless method == "PullImage"

      transfer(request.dig("image", "image"))
      {"image_ref" => "pulled"}
    end

    def release(name, outcome = :ok) = @releases.fetch(name).push(outcome)

    def release_all = @releases.each_key { |name| release(name) }

    private

    def transfer(name)
      @entered.push(name)
      outcome = @releases.fetch(name).pop(timeout: 5)
      raise Image::RegistryError, "registry failed #{name}" if outcome == :fail
      raise "registry fixture timed out waiting for #{name}" unless outcome
    end
  end

  def test_default_serializes_native_and_cri_pulls_without_blocking_cri_cache_hits
    with_agent({}, cri: true) do |service, registry, workers|
      workers << start_pod(service, "first")

      assert_equal "first", registry.entered.pop(timeout: 2)

      backend = service.runtime.backends.fetch("cri")

      assert_equal({"id" => "cached"}, backend.ensure_image("cached"))
      workers << Thread.new { backend.ensure_image("cri", {"imagePullPolicy" => "Always"}) }

      assert_nil registry.entered.pop(timeout: 0.1)

      registry.release("first", :fail)

      assert_equal "cri", registry.entered.pop(timeout: 2)
      registry.release("cri")

      assert_equal({"image_ref" => "pulled"}, thread_result(workers.last))
      assert_image_pull_failure(thread_result(workers.first))
    end
  end

  def test_limit_two_is_shared_by_concurrent_pods_and_failure_releases_one_slot
    with_agent({"maxParallelImagePulls" => 2}) do |service, registry, workers|
      assert_equal({"serializeImagePulls" => false, "maxParallelImagePulls" => 2}, image_pull_configz(service))

      workers << start_pod(service, "first")

      assert_equal "first", registry.entered.pop(timeout: 2)
      workers << start_pod(service, "second")

      assert_equal "second", registry.entered.pop(timeout: 2)
      workers << start_pod(service, "third")

      assert_nil registry.entered.pop(timeout: 0.1)

      registry.release("first", :fail)

      assert_equal "third", registry.entered.pop(timeout: 2)
      assert_image_pull_failure(thread_result(workers.first))
    end
  end

  def test_parallel_mode_without_maximum_lets_all_waiting_pods_pull
    with_agent({"serializeImagePulls" => false}) do |service, registry, workers|
      %w[first second third].each { |name| workers << start_pod(service, name) }

      assert_equal %w[first second third], Array.new(3) { registry.entered.pop(timeout: 2) }.compact.sort
    end
  end

  private

  def assert_image_pull_failure(result)
    assert_equal "ErrImagePull", result.status.dig("containerStatuses", 0, "state", "waiting", "reason")
  end

  def with_agent(settings, cri: false)
    Dir.mktmpdir("kubelet-image-pull-limit") do |directory|
      registry = BlockingRegistry.new
      workers = []
      native = File.join(directory, "agent.yml")
      component = File.join(directory, "kubelet-config")
      process = {"streaming" => {"host" => "127.0.0.1", "port" => 0}, "image" => {"staging_root" => directory}}
      %w[sandbox_root log_root journal_path].each { |key| process[key] = File.join(directory, key) }
      process["cri"] = {"enabled" => true, "endpoint" => File.join(directory, "cri.sock")} if cri
      File.write(native, YAML.dump({"processes" => {PROCESS => process}}))
      typed = {"apiVersion" => "kubelet.config.k8s.io/v1beta1", "kind" => "KubeletConfiguration", "healthzPort" => 0}
      File.write(component, YAML.dump(typed.merge(settings)))
      Image::Puller.stub(:new, registry) do
        CRI::Client.stub(:new, registry) do
          service = FixtureAssembler.new(process_name: PROCESS, config_path: native, kubelet_config_path: component,
                                         log_io: StringIO.new).build.service
          yield service, registry, workers
        ensure
          registry.release_all
          workers.each { |thread| thread_result(thread) }
        end
      end
    end
  end

  def start_pod(service, name)
    pod = {"metadata" => {"name" => name, "namespace" => "default", "uid" => name},
           "spec" => {"containers" => [{"name" => "application", "image" => "example.invalid/test:#{name}", "imagePullPolicy" => "Always"}]}}
    Thread.new { service.node_agent.lifecycle.start(pod) }
  end

  def thread_result(thread) = Timeout.timeout(3) { thread.value }

  def image_pull_configz(service)
    service.send(:start_streaming_server!)
    port = service.instance_variable_get(:@streaming_server).port
    response = Net::HTTP.new("127.0.0.1", port, nil).get("/configz")

    assert_equal "200", response.code
    JSON.parse(response.body).fetch("kubeletconfig").slice("serializeImagePulls", "maxParallelImagePulls")
  ensure
    service.send(:stop_streaming_server!)
  end
end
