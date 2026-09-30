# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

# KEP-1710 SELinux volume checks: the label a Pod's containers imply per
# volume, -o context mounts for supported volumes, container / Pod / volume
# label mismatches counted as errors (RWOP) or warnings, and the tracker
# forgetting Pods on release.
class VolumeSELinuxTest < Minitest::Test
  SELinux = Rubernetes::Volume::SELinux
  Node = Rubernetes::Node

  def setup
    @metrics = Node::KubeletMetrics.new(node_name: "worker-0")
    @logger_events = []
    @logger = Object.new
    events = @logger_events
    @logger.define_singleton_method(:warn) { |event, **fields| events << [event, fields] }
  end

  def render = @metrics.registry.render_own

  def options(level, type: "container_t", user: nil)
    {"type" => type, "level" => level, "user" => user}.compact
  end

  def pv_spec(name: "pv-1", modes: ["ReadWriteOncePod"], csi: "driver.example.com")
    spec = {"name" => "data", "persistentVolume" => name, "accessModes" => modes}
    csi ? spec.merge("csi" => {"driver" => csi, "volumeHandle" => "h"}) : spec.merge("backend" => "hostPath", "path" => "/tmp")
  end

  def tracker(feature_gates: {}, selinux_mount: true, translator: SELinux::FakeTranslator.new)
    driver = {"apiVersion" => "storage.k8s.io/v1", "kind" => "CSIDriver", "metadata" => {"name" => "driver.example.com"},
              "spec" => {"seLinuxMount" => selinux_mount}}
    SELinux::Tracker.new(translator: translator, metrics: @metrics, feature_gates: feature_gates, logger: @logger,
                         csi_driver_reader: ->(name) { name == "driver.example.com" ? driver : nil })
  end

  def test_container_contexts_follow_the_effective_security_context
    pod = {"spec" => {"securityContext" => {"seLinuxOptions" => options("s0:c1,c2")},
                      "initContainers" => [{"name" => "init", "volumeMounts" => [{"name" => "data", "mountPath" => "/d"}]}],
                      "containers" => [{"name" => "a", "securityContext" => {"seLinuxOptions" => options("s0:c3,c4")},
                                        "volumeMounts" => [{"name" => "data", "mountPath" => "/d"}, {"name" => "cfg", "mountPath" => "/c"}]},
                                       {"name" => "b", "volumeMounts" => []}]}}
    contexts = SELinux.container_contexts(pod)

    assert_equal [options("s0:c1,c2"), options("s0:c3,c4")], contexts["data"]
    assert_equal [options("s0:c3,c4")], contexts["cfg"]
    assert_empty contexts["none"]
  end

  def test_access_mode_and_mount_support_rules
    assert_equal "inline", SELinux.access_mode({"name" => "x", "backend" => "emptyDir"})
    assert_equal "RWOP", SELinux.access_mode(pv_spec)
    assert_equal "RWX", SELinux.access_mode(pv_spec(modes: %w[ReadWriteOnce ReadWriteMany]))
    assert_equal "RWO", SELinux.access_mode(pv_spec(modes: %w[ReadWriteOnce]))
    assert SELinux.volume_supports_mount?(pv_spec), "RWOP volumes are SELinux-mounted by default"
    refute SELinux.volume_supports_mount?(pv_spec(modes: %w[ReadWriteOnce]))
    refute SELinux.volume_supports_mount?(pv_spec(modes: %w[ReadWriteOnce ReadWriteOncePod]))
    assert SELinux.volume_supports_mount?(pv_spec(modes: %w[ReadWriteMany]), {"SELinuxMount" => true})
    refute SELinux.volume_supports_mount?({"name" => "x", "backend" => "emptyDir"}, {"SELinuxMount" => true})
    assert SELinux.plugin_supports_context_mount?(pv_spec, csi_driver: {"spec" => {"seLinuxMount" => true}})
    refute SELinux.plugin_supports_context_mount?(pv_spec, csi_driver: {"spec" => {}})
    refute SELinux.plugin_supports_context_mount?(pv_spec(csi: nil), csi_driver: nil)
    assert_equal "kubernetes.io/csi:driver.example.com", SELinux.plugin_label(pv_spec)
    assert_equal "kubernetes.io/host-path", SELinux.plugin_label(pv_spec(csi: nil))
    assert_equal 'context="system_u:object_r:container_file_t:s0:c1,c2"',
                 SELinux.mount_option("system_u:object_r:container_file_t:s0:c1,c2")
  end

  def test_fake_translator_builds_file_labels
    fake = SELinux::FakeTranslator.new

    assert_equal "system_u:object_r:container_t:s0:c1,c2", fake.file_label(options("s0:c1,c2"))
    assert_equal "", fake.file_label(nil)
    assert_equal "", fake.file_label({"type" => "container_t"}), "the fake needs a level"
    refute_predicate SELinux::FakeTranslator.new(enabled: false), :enabled?
  end

  def test_real_translator_applies_user_and_level_over_the_file_context
    Dir.mktmpdir do |dir|
      config = File.join(dir, "config")
      File.write(config, "SELINUX=enforcing\nSELINUXTYPE=targeted\n")
      FileUtils.mkdir_p(File.join(dir, "fs"))
      File.write(File.join(dir, "fs", "enforce"), "1")
      random = Object.new
      random.define_singleton_method(:random_number) { |_max| 5 }
      translator = SELinux::Translator.new(selinuxfs: File.join(dir, "fs"), config: config, random: random)

      assert_predicate translator, :enabled?
      assert_equal "system_u:object_r:container_file_t:s0:c1,c2", translator.file_label(options("s0:c1,c2"))
      assert_equal "unconfined_u:object_r:container_file_t:s0:c1,c2", translator.file_label(options("s0:c1,c2", user: "unconfined_u"))
      assert_equal "system_u:object_r:container_file_t:s0:c5,c6", translator.file_label({"type" => "spc_t"}), "no level: a unique MCS pair"
      assert_equal "", translator.file_label({})
      File.write(config, "SELINUX=disabled\n")

      refute_predicate translator, :enabled?
      assert_equal "", translator.file_label(options("s0:c1,c2"))
    end
    refute_predicate SELinux::Translator.new(selinuxfs: "/nonexistent/selinux"), :enabled?
  end

  def test_admitted_volume_is_mounted_with_its_label
    subject = tracker
    label = subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2"), options("s0:c1,c2")])

    assert_equal "system_u:object_r:container_t:s0:c1,c2", label
    assert_match(
      %r{volume_manager_selinux_volumes_admitted_total\{access_mode="RWOP",volume_plugin="kubernetes.io/csi:driver.example.com"\} 1}, render
    )
    # Same Pod again (a retry) and a second Pod with the same label: fine.
    assert_equal label, subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2")])
    assert_equal label, subject.admit(pod_uid: "p2", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2")])
    assert_equal %w[p1 p2], subject.volumes.fetch("pv/pv-1")[:pods].sort
    subject.forget(pod_uid: "p1", volume_name: "data", spec: pv_spec)

    assert_equal %w[p2], subject.volumes.fetch("pv/pv-1")[:pods]
    subject.forget(pod_uid: "p2", volume_name: "data", spec: pv_spec)

    assert_empty subject.volumes
  end

  def test_unsupported_access_mode_and_unsupported_driver_mount_without_context
    subject = tracker

    assert_nil subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec(modes: %w[ReadWriteOnce]), contexts: [options("s0:c1,c2")]),
               "RWO without SELinuxMount: label recorded, mount without -o context"
    assert_match(%r{volumes_admitted_total\{access_mode="RWO",volume_plugin="kubernetes.io/csi:driver.example.com"\} 1}, render)
    no_mount = tracker(selinux_mount: false)

    assert_nil no_mount.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2")])
    assert_nil tracker(translator: SELinux::FakeTranslator.new(enabled: false)).admit(pod_uid: "p1", volume_name: "data", spec: pv_spec,
                                                                                      contexts: [options("s0:c1,c2")])
    recursive = pv_spec.merge("pod" => {"spec" => {"securityContext" => {"seLinuxChangePolicy" => "Recursive"}}})

    assert_nil tracker.admit(pod_uid: "p1", volume_name: "data", spec: recursive, contexts: [options("s0:c1,c2")]),
               "Recursive opts out of -o context"
    inline = {"name" => "scratch", "backend" => "emptyDir"}

    assert_nil tracker.admit(pod_uid: "p1", volume_name: "scratch", spec: inline, contexts: [options("s0:c1,c2")])
    assert_match(%r{volumes_admitted_total\{access_mode="inline",volume_plugin="kubernetes.io/empty-dir"\} 1}, render)
  end

  def test_pod_context_mismatch_is_an_error_for_rwop_and_a_warning_otherwise
    subject = tracker
    error = assert_raises(SELinux::MultipleLabelsError) do
      subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2"), options("s0:c3,c4")])
    end
    assert_match(/more than one SELinux label/, error.message)
    assert_match(/volume_manager_selinux_pod_context_mismatch_errors_total\{access_mode="RWOP"\} 1/, render)
    assert_nil subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec(modes: %w[ReadWriteMany]),
                             contexts: [options("s0:c1,c2"), options("s0:c3,c4")])
    assert_match(/volume_manager_selinux_pod_context_mismatch_warnings_total\{access_mode="RWX"\} 1/, render)
    assert_equal "volume.selinux_pod_context_mismatch", @logger_events.last.first
  end

  def test_volume_context_mismatch_between_pods
    subject = tracker
    subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2")])
    error = assert_raises(SELinux::ConflictError) do
      subject.admit(pod_uid: "p2", volume_name: "data", spec: pv_spec, contexts: [options("s0:c9,c9")])
    end
    assert_match(/conflicting SELinux labels of volume data/, error.message)
    assert_match(
      %r{volume_manager_selinux_volume_context_mismatch_errors_total\{access_mode="RWOP",volume_plugin="kubernetes.io/csi:driver.example.com"\} 1}, render
    )

    rwx = pv_spec(name: "pv-shared", modes: %w[ReadWriteMany])
    subject.admit(pod_uid: "p1", volume_name: "shared", spec: rwx, contexts: [options("s0:c1,c2")])

    assert_nil subject.admit(pod_uid: "p2", volume_name: "shared", spec: rwx, contexts: [options("s0:c9,c9")])
    assert_match(
      %r{volume_manager_selinux_volume_context_mismatch_warnings_total\{access_mode="RWX",volume_plugin="kubernetes.io/csi:driver.example.com"\} 1}, render
    )
    # A driver without seLinuxMount never compares labels.
    plain = tracker(selinux_mount: false)
    plain.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2")])

    assert_nil plain.admit(pod_uid: "p2", volume_name: "data", spec: pv_spec, contexts: [options("s0:c9,c9")])
    refute_match(/volume_context_mismatch_errors_total\{[^}]*\} 2/, render)
  end

  def test_translation_error_counts_container_context
    broken = Object.new
    broken.define_singleton_method(:enabled?) { true }
    broken.define_singleton_method(:file_label) { |_options| raise SELinux::TranslationError, "bad option" }
    subject = SELinux::Tracker.new(translator: broken, metrics: @metrics, logger: @logger, csi_driver_reader: lambda { |_|
      {"spec" => {"seLinuxMount" => true}}
    })
    assert_raises(SELinux::TranslationError) { subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec, contexts: [options("s0:c1,c2")]) }
    assert_match(/volume_manager_selinux_container_errors_total\{access_mode="RWOP"\} 1/, render)
    assert_nil subject.admit(pod_uid: "p1", volume_name: "data", spec: pv_spec(modes: %w[ReadWriteOnce]), contexts: [options("s0:c1,c2")])
    assert_match(/volume_manager_selinux_container_warnings_total\{access_mode="RWO"\} 1/, render)
  end

  # -- through PodVolumes ----------------------------------------------------

  class Reader
    def initialize(objects) = @objects = objects
    def get(resource, name, namespace: nil) = @objects[[resource, name]]
  end

  def pod(uid, level, volume: {"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}})
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p-#{uid}", "namespace" => "ns", "uid" => uid},
     "spec" => {"securityContext" => {"seLinuxOptions" => options(level)},
                "containers" => [{"name" => "c", "volumeMounts" => [{"name" => "data", "mountPath" => "/data"}]}],
                "volumes" => [volume]}}
  end

  def with_pod_volumes(modes: ["ReadWriteOncePod"])
    Dir.mktmpdir do |dir|
      host_path = File.join(dir, "pv")
      FileUtils.mkdir_p(host_path)
      openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
      security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
      manager = Rubernetes::Volume::Manager.new(data_dir: dir, fsync: false, path_security: security)
      volumes = Node::PodVolumes.new(volume: manager, root: File.join(dir, "pods"), node_name: "worker-0")
      volumes.instance_variable_set(:@reader, Reader.new({
                                                           %w[persistentvolumeclaims
                                                              claim] => {"metadata" => {"name" => "claim"},
                                                                         "spec" => {"volumeName" => "pv-1"}, "status" => {"phase" => "Bound"}},
                                                           %w[persistentvolumes
                                                              pv-1] => {"metadata" => {"name" => "pv-1"},
                                                                        "spec" => {"accessModes" => modes,
                                                                                   "capacity" => {"storage" => "1Gi"}, "hostPath" => {"path" => host_path}}}
                                                         }))
      volumes.selinux_tracker = SELinux::Tracker.new(translator: SELinux::FakeTranslator.new, metrics: @metrics, logger: @logger,
                                                     csi_driver_reader: ->(_) {})
      yield volumes
    end
  end

  def test_pod_volumes_admit_and_forget_through_prepare_and_release
    skip "hostPath volumes need openat2 as root" unless Process.uid.zero?

    with_pod_volumes do |volumes|
      first = pod("u1", "s0:c1,c2")
      handle = volumes.prepare(first)

      assert_equal "pv/pv-1", handle.dig("mounts", "data", "selinuxVolume")
      assert_equal ["u1"], volumes.selinux_tracker.volumes.fetch("pv/pv-1")[:pods]
      assert_match(%r{volumes_admitted_total\{access_mode="RWOP",volume_plugin="kubernetes.io/host-path"\} 1}, render)
      # hostPath has no -o context support: labels are recorded but never compared.
      second = volumes.prepare(pod("u2", "s0:c9,c9"))
      volumes.release(pod("u2", "s0:c9,c9"), second)
      volumes.release(first, handle)

      assert_empty volumes.selinux_tracker.volumes
    end
  end

  def test_pod_volumes_conflict_fails_the_mount_and_rolls_back
    with_pod_volumes do |volumes|
      conflicting = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u3"},
                     "spec" => {"containers" => [{"name" => "a", "securityContext" => {"seLinuxOptions" => options("s0:c1,c2")}, "volumeMounts" => [{"name" => "data", "mountPath" => "/a"}]},
                                                 {"name" => "b", "securityContext" => {"seLinuxOptions" => options("s0:c3,c4")},
                                                  "volumeMounts" => [{"name" => "data", "mountPath" => "/b"}]}],
                                "volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}}]}}
      error = assert_raises(Node::PodVolumes::SELinuxConflict) { volumes.prepare(conflicting) }
      assert_match(/more than one SELinux label/, error.message)
      assert_empty volumes.selinux_tracker.volumes
      assert_match(/pod_context_mismatch_errors_total\{access_mode="RWOP"\} 1/, render)
    end
  end

  def test_csi_mount_options_carry_the_context_flag
    spec = {"csi" => {"driver" => "d", "volumeHandle" => "h"}, "mountOptions" => ["noatime"],
            "selinuxMountLabel" => "system_u:object_r:container_file_t:s0:c1,c2"}
    record = Struct.new(:spec).new(spec)
    backend = Rubernetes::Volume::RemoteBackend.allocate
    backend.instance_variable_set(:@spec, spec)
    csi = Object.new
    csi.define_singleton_method(:pod_context?) { true }
    backend.instance_variable_set(:@csi, csi)
    context = backend.send(:kubelet_csi_context, {})

    assert_equal ["noatime", 'context="system_u:object_r:container_file_t:s0:c1,c2"'], context["mountOptions"]
    _ = record
  end
end
