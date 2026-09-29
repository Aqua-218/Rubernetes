# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema/codec/kubernetes_protobuf"

# metav1.AddToGroupVersion registers DeleteOptions and the other option kinds
# in every group version, and client-go types a DELETE body with the
# resource's group.  The bytes below are what k8s.io/apimachinery v0.36.1's
# protobuf serializer emits for
#   AppsV1().Deployments(ns).Delete(ctx, name, DeleteOptions{PropagationPolicy: Orphan})
# A codec that knew DeleteOptions only under "v1" rejected them, the server
# fell back to the default policy and cascaded ("[sig-api-machinery] Garbage
# collector should orphan RS created by deployment when
# deleteOptions.PropagationPolicy is Orphan").
class ProtobufGroupTypedOptionsTest < Minitest::Test
  APPS_V1_DELETE_OPTIONS_ORPHAN = ["6b3873000a180a07617070732f7631120d44656c6574654f7074696f6e73120822064f727068616e1a002200"].pack("H*").freeze

  def test_apps_v1_typed_delete_options_decode_to_meta_delete_options
    decoded = Rubernetes::Schema::Codec::KubernetesProtobuf.new.decode(APPS_V1_DELETE_OPTIONS_ORPHAN)

    assert_equal "apps/v1", decoded["apiVersion"]
    assert_equal "DeleteOptions", decoded["kind"]
    assert_equal "Orphan", decoded["propagationPolicy"]
  end

  def test_option_kinds_resolve_under_any_group
    codec = Rubernetes::Schema::Codec::KubernetesProtobuf.new
    %w[DeleteOptions ListOptions GetOptions CreateOptions UpdateOptions PatchOptions Status].each do |kind|
      %w[v1 apps/v1 batch/v1 example.com/v1alpha1].each do |api_version|
        refute_nil codec.descriptor_for(api_version: api_version, kind: kind), "#{api_version} #{kind}"
      end
    end
  end
end
