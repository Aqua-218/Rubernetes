# frozen_string_literal: true

require "open3"
require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/node"

# kubelet's runtimeclass manager: the Pod's RuntimeClass object names the
# handler; the node's table (native, microVM, CRI handlers, runtime_classes)
# answers for names the API does not know.
class RuntimeClassResolutionTest < Minitest::Test
  class Reader
    def initialize(objects) = @objects = objects

    def get(_resource, name)
      raise "API unavailable" if name == "flaky"

      @objects[name]
    end
  end

  def resolver(process = {}, objects = {})
    Rubernetes::Bootstrap::Assembler.allocate.send(:runtime_class_resolver, process, reader: Reader.new(objects))
  end

  def pod(name) = {"spec" => {"runtimeClassName" => name}}

  def test_the_runtime_class_object_names_the_handler
    process = {"cri" => {"enabled" => true, "endpoint" => "/run/c.sock", "handlers" => {"cri-runc" => "runc"}}}
    resolve = resolver(process, "sandboxed" => {"handler" => "cri-runc"}, "microvm" => {"handler" => "rubernetes-firecracker"})

    assert_equal "cri-runc", resolve.call(pod("sandboxed"))
    assert_equal "rubernetes-firecracker", resolve.call(pod("microvm"))
    assert_nil resolve.call({"spec" => {}})
  end

  def test_the_node_table_answers_when_the_api_does_not
    process = {"cri" => {"enabled" => true, "endpoint" => "/run/c.sock", "handlers" => {"cri-runc" => "runc"}},
               "runtime_classes" => {"flaky" => "rubernetes-native"}}
    resolve = resolver(process)

    assert_equal "cri-runc", resolve.call(pod("cri-runc")), "a CRI handler is also a RuntimeClass name"
    assert_equal "rubernetes-native", resolve.call(pod("flaky")), "an unreadable API falls back"
    error = assert_raises(Rubernetes::Node::Lifecycle::LifecycleError) { resolve.call(pod("missing")) }
    assert_includes error.message, %(runtime class "missing" is not provided)
  end

  def test_the_standalone_agent_loads_the_cri_runtime_multiplexer
    script = <<~RUBY
      require "tmpdir"
      require "rubernetes/bootstrap/cli"

      Dir.mktmpdir do |directory|
        paths = {"sandbox_root" => File.join(directory, "sandboxes"), "log_root" => File.join(directory, "logs"),
                 "cgroup_root" => File.join(directory, "cgroups"), "journal_path" => File.join(directory, "journal")}
        cri = {"enabled" => true, "endpoint" => File.join(directory, "containerd.sock"), "log_root" => File.join(directory, "cri")}
        assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent")
        runtime = assembler.send(:build_runtime, {"runtime_paths" => paths, "cri" => cri})
        puts runtime.class.name
        puts runtime.handler_for({})
        selected = assembler.send(:build_runtime, {"runtime_paths" => paths, "cri" => cri.merge("default_handler" => "cri")})
        puts selected.handler_for({})
        puts selected.handler_for({}, runtime_class: "rubernetes-native")
        observer = assembler.send(:build_runtime_observer, selected)
        puts observer.external_observer? && observer.call.empty?
        puts assembler.send(:native_image_roots, selected).empty?
      end
    RUBY
    library = File.expand_path("../../lib", __dir__)
    output, errors, status = Open3.capture3(RbConfig.ruby, "-I", library, "-e", script)

    assert_predicate status, :success?, errors
    assert_equal %w[Rubernetes::Runtime::Multiplexer rubernetes-native cri rubernetes-native true true], output.lines.map(&:strip)
  end

  def test_node_reports_the_default_cri_runtime_name_and_version
    require "rubernetes/runtime/cri"
    results = [{"runtime_name" => "containerd", "runtime_version" => "v2.3.6"}]
    client = Object.new
    client.define_singleton_method(:runtime) do |_method, _request|
      results.shift || raise(Rubernetes::Runtime::CRI::Client::Error, "unavailable")
    end
    backend = Rubernetes::Runtime::CRI::Backend.new(client: client)
    agent = Rubernetes::Node::Agent.allocate
    agent.instance_variable_set(:@runtime, backend)

    assert_equal "containerd://2.3.6", agent.send(:container_runtime_version)
    assert_equal "containerd://Unknown", agent.send(:container_runtime_version)
  end

  def test_default_cri_handler_must_belong_to_the_enabled_runtime
    config = Rubernetes::Bootstrap::Config.allocate
    base = {"enabled" => true, "endpoint" => "/run/containerd.sock", "default_handler" => "cri"}

    config.send(:validate_agent_cri!, base)
    assert_raises(Rubernetes::Bootstrap::Config::Error) { config.send(:validate_agent_cri!, base.merge("enabled" => false)) }
    assert_raises(Rubernetes::Bootstrap::Config::Error) do
      config.send(:validate_agent_cri!, base.merge("handlers" => {"runc-local" => "runc"}))
    end
  end
end
