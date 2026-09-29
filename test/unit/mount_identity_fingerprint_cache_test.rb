# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"

# Mount#fingerprint is memoized per identity-field values; registering the
# n-th mount must not re-digest the n-1 records already in the ledger.
class MountIdentityFingerprintCacheTest < Minitest::Test
  Ledger = Rubernetes::Volume::MountIdentityLedger

  def mount(target:, mount_id:)
    Ledger::Mount.new(volume_id: "v", source: "/src", target: target, mount_id: mount_id, filesystem_uuid: nil,
                      device_id: "0:50", owner: "o", stage_path: nil, generation: 1, secret: false, root: "/x",
                      source_identity: "/src", filesystem_uuid_available: false, filesystem: "ext4",
                      identity_version: Ledger::IDENTITY_VERSION, legacy: false, bind: true)
  end

  def test_fingerprint_is_computed_once_while_fields_are_unchanged
    subject = mount(target: "/a", mount_id: "10")
    calls = 0
    original = Ledger.method(:identity_fingerprint)
    Ledger.define_singleton_method(:identity_fingerprint) { |fields| calls += 1; original.call(fields) }
    first = subject.fingerprint
    3.times { assert_equal first, subject.fingerprint }
    assert_equal 1, calls
  ensure
    Ledger.define_singleton_method(:identity_fingerprint, original) if original
  end

  def test_changing_an_identity_field_changes_the_fingerprint
    subject = mount(target: "/a", mount_id: "10")
    before = subject.fingerprint
    subject.mount_id = "11"
    refute_equal before, subject.fingerprint
    assert_equal mount(target: "/a", mount_id: "11").fingerprint, subject.fingerprint
  end

  def test_registering_many_mounts_still_detects_a_target_conflict
    ledger = Ledger.new
    200.times do |i|
      ledger.register(volume_id: "v#{i}", source: "/src#{i}", target: "/t#{i}", mount_id: (100 + i).to_s, filesystem_uuid: nil,
                      device_id: "0:50", owner: "o", root: "/r#{i}", source_identity: "/src#{i}", filesystem_uuid_available: false,
                      filesystem: "ext4", bind: true)
    end
    assert_raises(Rubernetes::Volume::MountIdentityError) do
      ledger.register(volume_id: "other", source: "/other", target: "/t5", mount_id: "999", filesystem_uuid: nil,
                      device_id: "0:50", owner: "o", root: "/o", source_identity: "/other", filesystem_uuid_available: false,
                      filesystem: "ext4", bind: true)
    end
  end
end
