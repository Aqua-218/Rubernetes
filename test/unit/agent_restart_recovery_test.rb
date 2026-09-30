# frozen_string_literal: true

require "digest"
require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/native"
require "rubernetes/platform/linux"

# Restarting an agent while its Pods run failed recovery (RecoveryRequired)
# every time -- found restarting worker-2 on 2026-09-24:
# * the ledger records a workload's executable as "sha256:<hex>" and the
#   observer compared it with the bare hex, so every live process looked like
#   pid reuse;
# * a namespace's kernel evidence sits under kernel_identity, which the
#   observer never read, so every namespace was "unverifiable";
# * an empty cgroup counted as live because its directory exists;
# * a dead operation's workspace, never adopted by the restarted runtime, had
#   no cleaner that knew it.
class AgentRestartRecoveryTest < Minitest::Test
  Observer = Rubernetes::Runtime::Native::KernelObserver
  Adapters = Rubernetes::Platform::Linux::NativeAdapters

  class FakeLedger
    def initialize(resources) = @resources = resources
    def resources(include_released: false) = @resources
  end

  def observe(claim) = Observer.new(ledger: FakeLedger.new([claim])).list_resources

  def start_time(pid)
    stat = File.read("/proc/#{pid}/stat")
    stat[(stat.rindex(")") + 1)..].split[19]
  end

  def test_a_prefixed_executable_digest_matches_the_live_process
    digest = Digest::SHA256.hexdigest(File.binread("/proc/self/exe"))
    claim = {"kind" => "process", "id" => "sb:c", "identity" => "process:sb:c", "owner" => "op",
             "metadata" => {"workload_pid" => Process.pid, "workload_start_time" => start_time(Process.pid),
                            "workload_executable_digest" => "sha256:#{digest}"}}
    entry = observe(claim).fetch(0)

    assert_equal true, entry.dig("metadata", "live")
    refute entry.dig("metadata", "identity_mismatch"), "the same executable, whatever the digest's prefix"
  end

  def test_namespace_evidence_is_read_from_the_kernel_identity
    links = %w[net uts].to_h { |name| [name, File.readlink("/proc/self/ns/#{name}")] }
    claim = {"kind" => "namespace", "id" => "sb", "identity" => "namespace:sb", "owner" => "op",
             "metadata" => {"kernel_identity" => {"pid" => Process.pid, "namespace_links" => links}}}

    assert_equal true, observe(claim).fetch(0).dig("metadata", "live")
    pid = Process.spawn("/bin/true")
    Process.wait(pid)
    gone = claim.merge("metadata" => {"kernel_identity" => {"pid" => pid, "namespace_links" => links}})

    assert_empty observe(gone), "its holder is gone: the namespace is gone, not unverifiable"
  end

  def test_an_empty_cgroup_is_dead_and_a_populated_one_live
    Dir.mktmpdir("rbn-cg-") do |directory|
      stat = File.stat(directory)
      claim = {"kind" => "cgroup", "id" => directory, "identity" => "cgroup:x", "owner" => "op",
               "metadata" => {"path" => directory, "inode" => stat.ino, "device" => stat.dev}}
      File.write(File.join(directory, "cgroup.events"), "populated 0\nfrozen 0\n")

      assert_equal false, observe(claim).fetch(0).dig("metadata", "live")
      File.write(File.join(directory, "cgroup.events"), "populated 1\nfrozen 0\n")

      assert_equal true, observe(claim).fetch(0).dig("metadata", "live")
    end
  end

  def test_an_orphan_workspace_directory_is_removed_only_inside_the_root
    Dir.mktmpdir("rbn-ws-") do |root|
      adapter = Adapters::OverlayFilesystemAdapter.new(root: root, namespace_adapter: Object.new)
      directory = File.join(root, "pod1.c")
      FileUtils.mkdir_p(File.join(directory, "root"))
      workspace = Rubernetes::Runtime::Native::Filesystem::Workspace.new(id: "pod1.c", root: File.join(directory, "root"),
                                                                         upper: nil, work: nil, identity: "workspace:pod1.c", image_digest: nil)

      assert adapter.cleanup(workspace: workspace)
      refute_path_exists directory
      elsewhere = workspace.with(id: "pod2.c", root: "/srv/elsewhere")
      FileUtils.mkdir_p(File.join(root, "pod2.c"))
      assert_raises(Adapters::EffectError) { adapter.cleanup(workspace: elsewhere) }
      assert_path_exists File.join(root, "pod2.c"), "a workspace whose recorded root is outside is never touched"
    end
  end
end
