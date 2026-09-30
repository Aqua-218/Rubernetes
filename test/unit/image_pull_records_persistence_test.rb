# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/image/pull_records"
require "rubernetes/node/kubelet_metrics"

# KubeletEnsureSecretPulledImages' pull manager state on disk: intents
# before a pull, records after, reloaded at startup, and the
# kubelet_imagemanager_* series over it.
class ImagePullRecordsPersistenceTest < Minitest::Test
  PullRecords = Rubernetes::Image::PullRecords

  def test_intents_and_records_persist_and_reload
    Dir.mktmpdir do |dir|
      checks = []
      records = PullRecords.new(policy: PullRecords::ALWAYS_VERIFY, directory: dir, metrics_observer: ->(result) { checks << result })
      records.record_intent("registry.example/app:1.0")
      assert_equal 1, Dir.children(File.join(dir, "pulling")).length
      usage = records.usage
      assert_equal 1, usage[:on_disk_intents]
      assert_equal 1, usage[:in_memory_intents]

      secret = PullRecords::Credentials.secret(uid: "u1", namespace: "team", name: "regcred", hash: "abc")
      records.record_pulled("registry.example/app", "sha256:deadbeef", secret)
      records.clear_intent("registry.example/app:1.0")
      usage = records.usage
      assert_equal 0, usage[:on_disk_intents]
      assert_equal 1, usage[:on_disk_records]
      assert_equal 1, usage[:in_memory_records]
      document = JSON.parse(File.read(Dir.glob(File.join(dir, "pulled", "*.json")).first))
      assert_equal "ImagePulledRecord", document["kind"]
      assert_equal "sha256:deadbeef", document["imageRef"]
      assert_equal "abc", document.dig("credentialMapping", "registry.example/app", "kubernetesSecrets", 0, "hash")

      same = -> { [[{uid: "u1", namespace: "team", name: "regcred", hash: "abc"}], nil] }
      other = -> { [[{uid: "u2", namespace: "team", name: "other", hash: "zzz"}], nil] }
      refute records.must_attempt_pull?("registry.example/app", "sha256:deadbeef", same)
      assert records.must_attempt_pull?("registry.example/app", "sha256:deadbeef", other)
      assert_equal %w[pull_not_required pull_required], checks

      reloaded = PullRecords.new(policy: PullRecords::ALWAYS_VERIFY, directory: dir)
      refute reloaded.must_attempt_pull?("registry.example/app", "sha256:deadbeef", same)
      assert_equal 1, reloaded.usage[:in_memory_records]
    end
  end

  def test_kubelet_metrics_export_the_pull_manager_state
    Dir.mktmpdir do |dir|
      records = PullRecords.new(policy: PullRecords::ALWAYS_VERIFY, directory: dir)
      metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0")
      metrics.pull_records = records
      records.record_intent("registry.example/app:1.0")
      records.record_pulled("registry.example/app", "sha256:1", PullRecords::Credentials.node)
      records.must_attempt_pull?("registry.example/app", "sha256:1", -> { [[], nil] })
      text = metrics.registry.render
      assert_includes text, "kubelet_imagemanager_ondisk_pullintents 1"
      assert_includes text, "kubelet_imagemanager_ondisk_pulledrecords 1"
      assert_match(/kubelet_imagemanager_inmemory_pulledrecords_usage_percent 0\.1/, text)
      assert_match(/kubelet_imagemanager_image_mustpull_checks_total\{result="pull_not_required"\} 1/, text)
    end
  end
end
