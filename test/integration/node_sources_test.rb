# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/source_manager"

class NodeSourcesTest < Minitest::Test
  def test_static_manifests_and_api_pods_merge_without_duplicate_mirrors
    Dir.mktmpdir("rubernetes-static") do |directory|
      File.write(File.join(directory, "static.yaml"), <<~YAML)
        apiVersion: v1
        kind: Pod
        metadata:
          name: local
          namespace: default
        spec:
          containers:
          - name: app
            image: example/app:1
      YAML
      manager = Rubernetes::Node::SourceManager.new(node_name: "node-a", manifest_dir: directory)
      static = manager.load_static
      api = [
        {"kind" => "Pod", "metadata" => {"name" => "remote", "namespace" => "default"}, "spec" => {"nodeName" => "node-b"}},
        {"kind" => "Pod", "metadata" => {"name" => "api", "namespace" => "default"}, "spec" => {"nodeName" => "node-a"}},
        {"kind" => "Pod", "metadata" => {"name" => "local", "namespace" => "default", "uid" => "mirror-uid",
                                         "annotations" => {"kubernetes.io/config.mirror" => "old"}},
         "spec" => {"nodeName" => "node-a"}}
      ]

      merged = manager.merge(api_pods: api, static_pods: static)
      keys = merged.map { |pod| [pod.dig("metadata", "namespace"), pod.dig("metadata", "name")] }

      assert_equal([%w[default api], %w[default local]], keys)
      local = merged.find { |pod| pod.dig("metadata", "name") == "local" }

      assert_equal("file", local.dig("metadata", "annotations", "kubernetes.io/config.source"))
      assert_equal("node-a", local.dig("spec", "nodeName"))
      assert_equal("mirror-uid", local.dig("metadata", "uid"))
    end
  end

  def test_multi_document_yaml_and_mirror_writer_reconcile
    calls = []
    writer = Object.new
    writer.define_singleton_method(:create) do |resource:, namespace:, name:, object:|
      calls << [:create, resource, namespace, name, object]
    end
    Dir.mktmpdir("rubernetes-static") do |directory|
      File.write(File.join(directory, "pods.yaml"), <<~YAML)
        ---
        apiVersion: v1
        kind: Pod
        metadata: {name: first}
        spec: {containers: [{name: c, image: x}]}
        ---
        apiVersion: v1
        kind: Pod
        metadata: {name: second}
        spec: {containers: [{name: c, image: y}]}
      YAML
      manager = Rubernetes::Node::SourceManager.new(node_name: "node-a", manifest_dir: directory, mirror_writer: writer)
      manager.refresh
    end

    assert_equal(2, calls.length)
    assert(calls.all? { |call| call[1] == "v1/pods" })
    assert(calls.all? { |call| call[4].dig("metadata", "annotations", "kubernetes.io/config.mirror") })
  end
end
