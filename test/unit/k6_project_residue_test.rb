# frozen_string_literal: true

require "minitest/mock"
require_relative "../test_helper"
require_relative "../../tools/conformance/k6_project_residue"

class K6ProjectResidueTest < Minitest::Test
  PROJECT = "k6-storage"

  def setup
    @checker = Conformance::K6ProjectResidue.new(kubectl: "unused", kubeconfig: "unused")
  end

  def test_async_csi_reclaim_can_finish_after_thirty_seconds
    original = volume("original")
    replacement = volume("replacement")
    clock = 0
    list = ->(_resource) { [{"items" => [clock < 45 ? original : replacement]}, nil] }

    @checker.stub(:get, list) do
      Process.stub(:clock_gettime, ->(_source) { clock }) do
        @checker.stub(:sleep, ->(seconds) { clock += seconds }) do
          assert @checker.await_volume_reclaim(PROJECT, snapshot, snapshot(original))
        end
      end
    end

    assert_equal 45, clock
  end

  def test_retained_other_namespace_and_baseline_volumes_do_not_trigger_a_wait
    baseline = volume("baseline", name: "preexisting")
    retained = volume("retained", name: "retained-pv", policy: "Retain")
    foreign = volume("foreign", name: "foreign-pv", namespace: "different-project")

    @checker.stub(:get, ->(*) { flunk "unrelated volumes must not cause polling" }) do
      refute @checker.await_volume_reclaim(PROJECT, snapshot(baseline), snapshot(baseline, retained, foreign))
    end
  end

  def test_an_unreclaimed_project_volume_has_a_bounded_wait
    original = volume("original")
    clock = 0
    @checker.stub(:get, [{"items" => [original]}, nil]) do
      Process.stub(:clock_gettime, ->(_source) { clock }) do
        @checker.stub(:sleep, ->(seconds) { clock += seconds }) do
          assert @checker.await_volume_reclaim(PROJECT, snapshot, snapshot(original))
        end
      end
    end

    assert_equal 120, clock
  end

  private

  def volume(uid, name: "pvc-project", namespace: PROJECT, policy: "Delete")
    {"metadata" => {"name" => name, "uid" => uid},
     "spec" => {"claimRef" => {"namespace" => namespace}, "persistentVolumeReclaimPolicy" => policy}}
  end

  def snapshot(*volumes)
    entries = volumes.to_h { |pv| [pv.fetch("metadata").values_at("name", "uid"), pv] }
    {resources: {"persistentvolumes" => entries}, errors: []}
  end
end
