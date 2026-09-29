# frozen_string_literal: true

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
end
