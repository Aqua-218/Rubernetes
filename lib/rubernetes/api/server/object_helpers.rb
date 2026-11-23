# frozen_string_literal: true

require_relative "../../support/object_tree"

require_relative "../object_copy"

module Rubernetes
  module API
    class Server
      # Small questions and conversions every handler needs: which kind a resource
      # is, metadata access, generation tracking, and copies.
      module ObjectHelpers
        include ObjectCopy

        DAEMONSET_TEMPLATE_GENERATION = "deprecated.daemonset.template.generation"

        private

        def resource_details(route, name: route.name)
          details = {"kind" => route.resource.resource, "name" => name.to_s}
          details["group"] = route.resource.group unless route.resource.group.to_s.empty?
          details
        end

        def resource_conflict(route, message, subresource: nil)
          details = resource_details(route)
          details["kind"] += "/#{subresource}" if subresource
          resource = [details["kind"], details["group"]].compact.join(".")
          Status::Conflict.new("Operation cannot be fulfilled on #{resource} #{route.name.inspect}: #{message}", details: details)
        end

        def missing_resource(route)
          Status::NotFound.new("#{qualified_resource(route.resource)} #{route.name.inspect} not found", details: resource_details(route))
        end

        def existing_resource(route, name)
          Status::AlreadyExists.new("#{qualified_resource(route.resource)} #{name.inspect} already exists", details: resource_details(route, name: name))
        end

        def qualified_resource(resource)
          [resource.resource, resource.group].reject { |part| part.to_s.empty? }.join(".")
        end

        def csr_resource?(resource)
          resource.group.to_s == "certificates.k8s.io" && resource.resource.to_s == "certificatesigningrequests"
        end

        def namespace_resource?(resource)
          resource.kind == "Namespace" && resource.group.to_s.empty?
        end

        def resource_triple(resource)
          [resource.group.to_s, resource.version.to_s, resource.resource.to_s]
        end

        def replication_controller_resource?(resource)
          resource.kind == "ReplicationController" && resource.group.to_s.empty?
        end

        def persistent_volume_resource?(resource)
          resource.kind == "PersistentVolume" && resource.group.to_s.empty?
        end

        def persistent_volume_claim_resource?(resource)
          resource.kind == "PersistentVolumeClaim" && resource.group.to_s.empty?
        end

        def pod_resource?(resource)
          resource.kind == "Pod" && resource.group.to_s.empty?
        end

        # metadata.generation is server-owned: every strategy that tracks it sets
        # it to 1 in PrepareForCreate, whatever the client sent
        # (pkg/registry/core/pod/strategy.go and ~30 peers).  Ours kept a
        # client-supplied value, so a Pod created with generation 100 kept it --
        # "[sig-node] Pods Extended (pod generation) custom-set generation on new
        # pods" checks for exactly 1.
        # The built-in kinds whose registry strategy sets metadata.generation
        # (`Generation = 1` in pkg/registry/**/strategy.go of the pinned tree,
        # plus CustomResourceDefinition).  Namespace, Service, Node, ConfigMap
        # and the other kinds with a spec but no strategy generation never carry
        # one, exactly as kube-apiserver serves them.  Custom resources always
        # do (apiextensions customresource strategy SetGeneration(1)).
        GENERATION_TRACKED_KINDS = %w[
          MutatingAdmissionPolicy MutatingAdmissionPolicyBinding MutatingWebhookConfiguration
          ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding ValidatingWebhookConfiguration
          DaemonSet Deployment ReplicaSet StatefulSet CronJob Job Pod PodTemplate ReplicationController
          EndpointSlice FlowSchema PriorityLevelConfiguration Ingress IngressClass NetworkPolicy
          PodDisruptionBudget DeviceClass DeviceTaintRule ResourceSlice PriorityClass CustomResourceDefinition
        ].freeze

        def tracks_generation?(object, resource)
          return false unless object.is_a?(Hash)
          # Without a resource (the service allocator preparing its own
          # IPAddress objects) the object's shape decides.
          return object["spec"].is_a?(Hash) if resource.nil?
          return true if resource.custom?

          GENERATION_TRACKED_KINDS.include?(resource.kind.to_s)
        end

        def apply_generation(object, existing, subresource: nil, resource: nil)
          return object if subresource == "status" || !object.is_a?(Hash)
          return update_csi_driver_generation(resource, object, existing) if resource && csi_driver_resource?(resource)
          return object unless tracks_generation?(object, resource)

          # Only metadata.generation changes: copy the top level and metadata.
          candidate = object.transform_keys(&:to_s)
          candidate["metadata"] = candidate["metadata"].is_a?(Hash) ? candidate["metadata"].transform_keys(&:to_s) : {}
          if existing.nil?
            candidate["metadata"]["generation"] = 1
          elsif generation_changed?(resource, existing, candidate)
            candidate["metadata"]["generation"] = metadata_value(existing, "generation").to_i + 1
          elsif metadata_value(existing, "generation")
            candidate["metadata"]["generation"] = metadata_value(existing, "generation").to_i
          end
          apply_daemonset_template_generation(resource, candidate, existing)
        end

        # apps/daemonset/strategy.go stores the Pod template generation
        # separately from metadata.generation. The apps/v1 conversion exposes
        # that value as an annotation for the DaemonSet controller.
        def apply_daemonset_template_generation(resource, object, existing = nil)
          return object unless resource && resource.kind == "DaemonSet" && resource.group == "apps" && !resource.custom?

          previous = existing || object
          raw = metadata_value(previous, "annotations")&.fetch(DAEMONSET_TEMPLATE_GENERATION, nil)
          generation = Integer(raw.to_s, 10, exception: false) || (existing && metadata_value(existing, "generation").to_i) || 1
          generation = [generation, 1].max
          generation += 1 if existing && existing.dig("spec", "template") != object.dig("spec", "template")
          annotations = metadata_value(object, "annotations") || {}
          object["metadata"]["annotations"] = annotations.merge(DAEMONSET_TEMPLATE_GENERATION => generation.to_s)
          object
        end

        def generation_changed?(resource, existing, candidate)
          return existing.except("metadata") != candidate.except("metadata") if resource&.custom?

          existing["spec"] != candidate["spec"]
        end

        def stringify_keys(value) = ObjectTree.stringify_keys(value)

        def symbolize_keys(value)
          value.each_with_object({}) { |(key, item), copy| copy[key.to_sym] = item }
        end

        def metadata_value(object, key)
          metadata = object.is_a?(Hash) ? (object["metadata"] || object[:metadata] || {}) : {}
          metadata[key] || metadata[key.to_sym]
        end
      end
    end
  end
end
