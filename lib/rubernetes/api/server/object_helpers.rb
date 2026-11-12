# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Small questions and conversions every handler needs: which kind a resource
      # is, metadata access, generation tracking, and copies.
      module ObjectHelpers
        private

        def resource_details(route, name: route.name)
          details = {"kind" => route.resource.resource, "name" => name.to_s}
          details["group"] = route.resource.group unless route.resource.group.to_s.empty?
          details
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
          return object unless tracks_generation?(object, resource)

          # Only metadata.generation changes: copy the top level and metadata.
          candidate = object.transform_keys(&:to_s)
          candidate["metadata"] = candidate["metadata"].is_a?(Hash) ? candidate["metadata"].transform_keys(&:to_s) : {}
          if existing.nil?
            candidate["metadata"]["generation"] = 1
          elsif existing["spec"] != candidate["spec"]
            candidate["metadata"]["generation"] = metadata_value(existing, "generation").to_i + 1
          elsif metadata_value(existing, "generation")
            candidate["metadata"]["generation"] = metadata_value(existing, "generation").to_i
          end
          candidate
        end

        def stringify_keys(value)
          case value
          when Hash then value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = stringify_keys(item) }
          when Array then value.map { |item| stringify_keys(item) }
          else value
          end
        end

        def symbolize_keys(value)
          value.each_with_object({}) { |(key, item), copy| copy[key.to_sym] = item }
        end

        def metadata_value(object, key)
          metadata = object.is_a?(Hash) ? (object["metadata"] || object[:metadata] || {}) : {}
          metadata[key] || metadata[key.to_sym]
        end

        def deep_copy(value)
          case value
          when Hash then value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = deep_copy(item) }
          when Array then value.map { |item| deep_copy(item) }
          else value
          end
        end
      end
    end
  end
end
