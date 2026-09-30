# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/schema"

# StatefulSetSemanticRevisionComparison: a revision stored before a field
# was defaulted still describes the set, so no new revision (and no rolling
# update) follows.
class StatefulSetSemanticRevisionTest < Minitest::Test
  Controller = Rubernetes::Controller

  def set(image: "web:1")
    {"apiVersion" => "apps/v1", "kind" => "StatefulSet",
     "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "set-uid", "generation" => 2},
     "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "web"}},
                "template" => {"metadata" => {"labels" => {"app" => "web"}},
                               "spec" => {"containers" => [{"name" => "web", "image" => image, "terminationMessagePath" => "/dev/termination-log",
                                                            "terminationMessagePolicy" => "File", "imagePullPolicy" => "IfNotPresent"}],
                                          "restartPolicy" => "Always", "dnsPolicy" => "ClusterFirst"}}}}
  end

  # Written before terminationMessagePolicy/dnsPolicy etc. were defaulted.
  def old_revision
    template = {"metadata" => {"labels" => {"app" => "web"}}, "spec" => {"containers" => [{"name" => "web", "image" => "web:1"}]},
                "$patch" => "replace"}
    {"apiVersion" => "apps/v1", "kind" => "ControllerRevision",
     "metadata" => {"name" => "web-abc", "namespace" => "ns", "resourceVersion" => "7",
                    "ownerReferences" => [{"apiVersion" => "apps/v1", "kind" => "StatefulSet", "name" => "web", "uid" => "set-uid", "controller" => true}]},
     "revision" => 1, "data" => {"spec" => {"template" => template}}}
  end

  # The set as stored: the API server defaulted it on create.
  def reconcile(owner)
    controller = Controller::StatefulSetController.new
    stored = controller.send(:default_stateful_set, owner)
    controller.send(:reconcile_revisions, stored, [old_revision], [], 0)
  end

  def test_a_revision_that_only_lacks_defaults_is_reused
    result = reconcile(set)

    assert_equal "web-abc", Controller::Support.name(result[:update])
    assert_empty result[:operations]
  end

  def test_a_real_change_still_makes_a_new_revision
    result = reconcile(set(image: "web:2"))

    refute_equal "web-abc", Controller::Support.name(result[:update])
    assert(result[:operations].any? { |operation| operation.action == :create })
  end
end
