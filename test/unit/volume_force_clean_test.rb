# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "rubernetes/volume/manager"

# kubelet's reconstruction fallback: a volume whose backend is Unknown at
# startup has its mount points force-unmounted and forgotten, counted in
# force_cleaned_failed_volume_operations_total / _errors_total.
class VolumeForceCleanTest < Minitest::Test
  class FakeMounts
    attr_reader :unmounted

    def initialize(fail_on: [])
      @unmounted = []
      @fail_on = fail_on
    end

    def find_mount(target) = {"target" => target, "mountId" => "1"}

    def unmount(target:, **)
      raise IOError, "busy" if @fail_on.include?(target)

      @unmounted << target
      true
    end
  end

  def write_record(dir, id, state:, publishes:)
    FileUtils.mkdir_p(File.join(dir, "volumes.json.d"))
    File.write(File.join(dir, "volumes.json.d", "#{id}.json"),
               JSON.generate("id" => id, "spec" => {"name" => id, "capacityBytes" => 1}, "backend" => "csi", "state" => state,
                             "generation" => 3, "attachments" => {}, "stages" => {}, "publishes" => publishes,
                             "createdAt" => "2026-09-30T00:00:00Z", "updatedAt" => "2026-09-30T00:00:00Z"))
  end

  def test_unknown_volumes_are_force_cleaned_and_counted
    Dir.mktmpdir do |dir|
      write_record(dir, "vol-unknown", state: "Unknown",
                                       publishes: {"pod-a\u0000/mnt/a" => {"pod" => "pod-a", "target" => "/mnt/a"},
                                                   "pod-b\u0000/mnt/b" => {"pod" => "pod-b", "target" => "/mnt/b"}})
      write_record(dir, "vol-ok", state: "Published", publishes: {"pod-c\u0000/mnt/c" => {"pod" => "pod-c", "target" => "/mnt/c"}})
      mounts = FakeMounts.new(fail_on: ["/mnt/b"])
      manager = Rubernetes::Volume::Manager.new(data_dir: dir, csi: Object.new, mount_adapter: mounts, fsync: false)
      stats = manager.reconstruction_stats

      assert_equal 2, stats[:attempted]
      assert_equal 1, stats[:errors]
      assert_equal 2, stats[:force_cleaned]
      assert_equal 1, stats[:force_clean_errors]
      assert_equal ["/mnt/a"], mounts.unmounted
      record = manager.fetch_record("vol-unknown")

      assert_equal ["pod-b\u0000/mnt/b"], record.publishes.keys, "the cleaned mount is forgotten, the failed one kept"
      assert_equal 1, manager.fetch_record("vol-ok").publishes.length, "healthy records are untouched"
    end
  end
end
