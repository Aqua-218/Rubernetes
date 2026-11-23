# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/k6_corpus"

class K6ProjectRuntimeResidueTest < Minitest::Test
  Observer = Conformance::K6ProjectRuntimeResidue
  Records = Rubernetes::Volume::RecordFiles
  PROJECT = "k6-project"
  BASELINE_POD = "11111111-1111-4111-8111-111111111111"
  PROJECT_POD = "22222222-2222-4222-8222-222222222222"
  FOREIGN_POD = "33333333-3333-4333-8333-333333333333"

  def test_measures_new_project_identities_without_counting_other_workloads
    with_root do |observer|
      network(BASELINE_POD, namespace: PROJECT)
      volume("already-present", BASELINE_POD)
      baseline = observer.snapshot
      network(PROJECT_POD, namespace: PROJECT)
      network(FOREIGN_POD, namespace: "other")
      volume("owned", PROJECT_POD)
      volume("foreign", FOREIGN_POD)
      mount("owned", "12")
      folder = File.join(@root, "persistent-volumes", "owned-path")
      FileUtils.mkdir_p(folder)
      prior = observer.snapshot.merge(paths: {"owned-path" => PROJECT})
      result = observer.compare(namespace: PROJECT, baseline: baseline, observations: [prior], post: observer.snapshot)

      assert_equal "residue", result.fetch("status")
      assert_equal({"worker-0" => "measured"}, result.fetch("workers"))
      residues = result.fetch("residue")

      assert_equal %w[Attachment IPAMLease Mount NetworkOperation ProvisionedPath Publish Stage Volume], residues.map { |entry| entry.fetch("kind") }.sort
      assert_equal [PROJECT_POD], residues.filter_map { |entry| entry["pod_uid"] }.uniq
      assert_empty result.fetch("unattributed")
    end
  end

  def test_terminal_entries_are_history_and_a_leftover_mount_can_use_an_earlier_volume_reference
    with_root do |observer|
      baseline = observer.snapshot
      network(PROJECT_POD, namespace: PROJECT, operation_state: "removed", lease_state: "released")
      volume("owned", PROJECT_POD)
      observed = observer.snapshot
      Records.new(path: volume_path("volumes"), fsync: false).delete("owned")

      clean = observer.compare(namespace: PROJECT, baseline: baseline, observations: [observed], post: observer.snapshot)

      assert_equal "clean", clean.fetch("status")
      assert clean.fetch("passed")

      mount("owned", "12")
      remaining = observer.compare(namespace: PROJECT, baseline: baseline, observations: [observed], post: observer.snapshot)

      assert_equal "residue", remaining.fetch("status")
      assert_equal(["Mount"], remaining.fetch("residue").map { |entry| entry.fetch("kind") })
    end
  end

  def test_a_baseline_mount_reused_by_the_project_is_a_new_owned_identity
    with_root do |observer|
      network(FOREIGN_POD, namespace: "other")
      volume("shared", FOREIGN_POD)
      mount("shared", "12")
      baseline = observer.snapshot
      network(PROJECT_POD, namespace: PROJECT)
      volume("shared", PROJECT_POD)
      result = observer.compare(namespace: PROJECT, baseline: baseline, observations: [], post: observer.snapshot)
      remaining = result.fetch("residue").find { |entry| entry["kind"] == "Mount" }

      assert_equal PROJECT_POD, remaining.fetch("pod_uid")
      assert_equal "12", remaining.fetch("mount_id")
    end
  end

  def test_unattributed_state_and_missing_worker_never_allow_a_clean_result
    with_root do |observer|
      baseline = observer.snapshot
      mount("unknown", "12")
      result = observer.compare(namespace: PROJECT, baseline: baseline, observations: [], post: observer.snapshot)

      assert_equal "unmeasured", result.fetch("status")
      assert_empty result.fetch("residue")
      assert_equal(["Mount"], result.fetch("unattributed").map { |entry| entry.fetch("kind") })

      missing = Observer.new(root: @root, workers: %w[worker-0 worker-1]).snapshot
      result = observer.compare(namespace: PROJECT, baseline: missing, observations: [], post: observer.snapshot)

      assert_equal "unmeasured", result.fetch("status")
      assert_equal "unmeasured", result.fetch("workers").fetch("worker-1")
    end
  end

  def test_kubeconfig_binds_state_and_external_cni_is_explicitly_unmeasured
    with_root do |_observer|
      kubeconfig = File.join(@root, "kubeconfig")
      endpoint = "https://127.0.0.1:16043"
      File.write(kubeconfig, YAML.dump("current-context" => "fixture", "contexts" => [{"name" => "fixture", "context" => {"cluster" => "cluster"}}],
                                       "clusters" => [{"name" => "cluster", "cluster" => {"server" => endpoint}}]))
      config = write_agent_config
      put_json(File.join(@root, "cluster.json"),
               {"kind" => "conformance_cluster", "kubeconfig" => kubeconfig, "endpoint" => endpoint,
                "processes" => [{"name" => "agent-worker-0", "executable" => "rubernetes-agent", "config" => config}]})
      reader = Observer.local(kubeconfig: kubeconfig)

      assert_equal "measured", reader.snapshot.fetch(:workers).fetch("worker-0")

      write_agent_config(plugin: "cni")
      evidence = reader.snapshot

      assert_equal "unmeasured", evidence.fetch(:workers).fetch("worker-0")
      assert_match(/external CNI/, evidence.fetch(:errors).first)

      unrelated = File.join(@root, "remote-kubeconfig")
      File.write(unrelated, "other fixture")

      refute_predicate Observer.local(kubeconfig: unrelated), :available?
    end
  end

  def test_a_corrupt_export_never_serializes_raw_state_or_reports_it_clean
    with_root do |observer|
      baseline = observer.snapshot
      secret = "private-pod-data"
      target = File.join(@root, "network", "worker-0", "state.json")
      FileUtils.mkdir_p(File.dirname(target))
      File.write(target, "{#{secret}")
      result = observer.compare(namespace: PROJECT, baseline: baseline, observations: [], post: observer.snapshot)

      assert_equal "unmeasured", result.fetch("status")
      refute_includes JSON.generate(result), secret
    end
  end

  def test_project_runs_api_stages_on_an_unmeasured_cluster_without_certifying_cleanup
    with_root do |_observer|
      corpus = Conformance::K6Corpus
      kubeconfig = File.join(@root, "kubeconfig")
      File.write(kubeconfig, "remote")
      checker = Conformance::K6ProjectResidue.new(kubectl: "kubectl", kubeconfig: kubeconfig)
      baseline = {resources: {}, errors: []}
      images = Minitest::Mock.new
      images.expect(:start_watch, nil)
      images.expect(:stop_watch, nil)
      def images.during(_stage)
        yield
      end
      %w[ready smoke restart].each { |stage| images.expect(:capture, nil, [stage]) }
      images.expect(:result, {"passed" => true})
      ran = []
      run_stage = lambda do |_project, id, _namespace, _options|
        ran << id
        {"stage" => id, "passed" => true}
      end
      clean_uninstall = {"stage" => "uninstall", "passed" => true}
      result = checker.stub(:snapshot, baseline) do
        checker.stub(:residue, []) do
          Conformance::K6ProjectResidue.stub(:new, checker) do
            Conformance::K6ProjectImages.stub(:new, images) do
              corpus.stub(:project_stage, run_stage) do
                corpus.stub(:project_uninstall, clean_uninstall) { corpus.run_project({"name" => "remote", "images" => []}, {kubeconfig: kubeconfig}) }
              end
            end
          end
        end
      end

      assert_equal %w[install ready smoke scale upgrade rollback restart], ran
      assert result.fetch("api_passed")
      refute result.fetch("passed")
      assert_equal "unmeasured", result.dig("runtime_residue", "status")
      assert_empty result.fetch("residue")
      images.verify
    end
  end

  private

  def with_root
    Dir.mktmpdir("k6-runtime-residue") do |root|
      @root = root
      FileUtils.mkdir_p(File.dirname(volume_path("volumes")))
      yield Observer.new(root: root, workers: ["worker-0"])
    end
  end

  def write_agent_config(plugin: nil)
    path = File.join(@root, "agent.yml")
    network = {"state_path" => File.join(@root, "network", "worker-0", "state.json"), "plugin" => plugin}.compact
    agent = {"network" => network, "volume" => {"data_dir" => File.dirname(volume_path("volumes"))}}
    File.write(path, YAML.dump("processes" => {"rubernetes-agent" => agent}))
    path
  end

  def volume_path(name)
    File.join(@root, "runtime", "worker-0", "volumes", "#{name}.json")
  end

  def volume(id, pod)
    target = File.join(@root, "runtime", "worker-0", "pods", "volumes", pod, "volumes", id)
    record = {"id" => id, "state" => "Published", "spec" => {"podUid" => pod},
              "attachments" => {"worker-0" => {"pods" => [pod]}},
              "stages" => {"#{target}-stage" => {}}, "publishes" => {"#{pod}\0#{target}" => {"pod" => pod, "target" => target}}}
    Records.new(path: volume_path("volumes"), fsync: false).write(id, record)
  end

  def mount(id, mount_id)
    record = {"volumeId" => id, "target" => File.join(@root, "volume", id), "mountId" => mount_id}
    Records.new(path: volume_path("mounts"), fsync: false).write(id, record)
  end

  def network(pod, namespace:, operation_state: "committed", lease_state: "committed")
    path = File.join(@root, "network", "worker-0", "state.json")
    sandbox = "pod#{pod}-0123456789ab"
    operation = "add:#{sandbox}"
    state = File.exist?(path) ? JSON.parse(File.binread(path)) : {"operations" => {}}
    state.fetch("operations")[operation] = {"id" => operation, "sandbox_id" => sandbox, "state" => operation_state}
    put_json(path, state)

    ipam_path = "#{path}.ipam.json"
    ipam = File.exist?(ipam_path) ? JSON.parse(File.binread(ipam_path)) : {"leases" => {}, "operations" => {}}
    ipam.fetch("leases")[operation] = {"operation_id" => operation, "sandbox_id" => sandbox, "state" => lease_state,
                                       "ip" => "10.240.0.#{pod[0]}"}
    ipam.fetch("operations")[operation] = {"sandbox_id" => sandbox, "metadata" => {"metadata" => {"uid" => pod, "namespace" => namespace}}}
    put_json(ipam_path, ipam)
  end

  def put_json(path, value)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.generate(value))
  end
end
