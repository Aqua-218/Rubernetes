# frozen_string_literal: true

require_relative "../../schema/declarative_validation"
require_relative "../../schema/dra_feature_fields"
require_relative "../../schema/job_selector"
require_relative "../../schema/persistent_volume_claim_sources"
require_relative "../crd/cel_validation"
require_relative "../secret_data"
require_relative "../object_meta_wire"
require_relative "../pod_wire"

module Rubernetes
  module API
    class Server
      # Defaulting and validation of an object against its resource's schema, the
      # ObjectMeta invariants, and the managedFields a write is recorded with.
      module SchemaApplication
        POD_SPEC_PATHS = PodWire::POD_SPEC_PATHS

        private

        def resource_pool_status_request_resource?(resource)
          resource && !resource.custom? && resource.group == "resource.k8s.io" && resource.kind == "ResourcePoolStatusRequest"
        end

        # DropDisabledPodFields preserves the field on objects already using
        # it when the feature gate is turned off.
        def drop_disabled_pod_fields(resource, object, old: nil)
          object = drop_disabled_hostname_override(resource, object, old: old)
          drop_disabled_stop_signals(resource, object, old: old)
        end

        def drop_disabled_hostname_override(resource, object, old:)
          return object if resource.custom? || feature_gate_enabled?(Schema::KubernetesValidator::HOSTNAME_OVERRIDE_GATE)

          path = POD_SPEC_PATHS[resource.kind]
          return object unless path

          validator = Schema::KubernetesValidator
          field = "hostnameOverride"
          return object if validator.fetch(validator.dig_path(object, path), field).nil? || !old&.dig(*path, field).nil?

          deep_copy(object).tap { |result| result.dig(*path).delete(field) }
        end

        def drop_disabled_stop_signals(resource, object, old: nil)
          return object if resource.custom? || feature_gate_enabled?(ContainerStopSignals::GATE)

          path = POD_SPEC_PATHS[resource.kind]
          return object unless path && (resource.group.to_s.empty? || %w[apps batch].include?(resource.group.to_s))
          return object unless stop_signals_in_use?(object.dig(*path))
          return object if old && stop_signals_in_use?(old.dig(*path))

          result = deep_copy(object)
          pod_spec_containers(result.dig(*path)).each do |container|
            next if ContainerStopSignals.custom_signal(container).nil?

            lifecycle = container.fetch("lifecycle")
            lifecycle.delete("stopSignal")
            container.delete("lifecycle") if lifecycle.values.all?(&:nil?)
          end
          result
        end

        def stop_signals_in_use?(spec)
          pod_spec_containers(spec).any? { |container| !ContainerStopSignals.custom_signal(container).nil? }
        end

        def drop_disabled_volume_projections(resource, object, old:)
          return object if resource.custom?

          path = POD_SPEC_PATHS[resource.kind]
          return object unless path && (resource.group.to_s.empty? || %w[apps batch].include?(resource.group.to_s))

          validator = Schema::KubernetesValidator
          fields = validator::PROJECTION_FEATURE_GATES.reject { |_, gate| feature_gate_enabled?(gate) }.keys
          return object if fields.empty?

          projection_entries = lambda do |root|
            validator.projected_volumes(root&.dig(*path)).flat_map do |projection, _|
              validator.projection_sources(projection).grep(Hash)
            end
          end
          previous = projection_entries.call(old)
          fields.reject! { |field| previous.any? { |source| !source[field].nil? } }
          return object if fields.empty? || projection_entries.call(object).none? { |source| fields.any? { |field| source.key?(field) } }

          deep_copy(object).tap do |result|
            projection_entries.call(result).each { |source| fields.each { |field| source.delete(field) } }
          end
        end

        def pod_spec_containers(spec)
          return [] unless spec.is_a?(Hash)

          ContainerStopSignals::CONTAINER_FIELDS.flat_map { |field| Array(spec[field]).grep(Hash) }
        end

        # A null decodes to the zero value of the typed ResourceRequirements
        # struct. Apply must compare that value before recording ownership.
        def normalize_null_container_resources!(resource, object)
          path = POD_SPEC_PATHS[resource.kind]
          return if path.nil? || resource.custom?

          spec = path.reduce(object) { |value, field| value[field] if value.is_a?(Hash) }
          pod_spec_containers(spec).each do |container|
            container["resources"] = {} if container.key?("resources") && container["resources"].nil?
          end
        end

        # ObjectMeta and core invariants beyond the OpenAPI schema; the Status
        # matches apierrors.NewInvalid.
        def validate_object!(resource, object, old: nil)
          kind = resource.kind
          unless resource.custom?
            errors = Schema::KubernetesValidator.kube_finalizer_errors(resource.group, kind, object["metadata"])
            raise invalid_resource(resource, object, errors) unless errors.empty?
          end
          if !resource.custom? && (POD_SPEC_PATHS.key?(kind) || kind == "RuntimeClass")
            gates = feature_gate_enabled?(TaintToleration::GATE) ? [TaintToleration::GATE] : []
            validator = Schema::KubernetesValidator
            errors = validator.pod_hostname_override_errors(object, kind) + validator.taint_comparison_errors(object, old, kind, gates)
            raise invalid_resource(resource, object, errors) unless errors.empty?
          end
          causes = ObjectValidation.validate(kind, object, old: old, namespaced: resource.namespaced?, custom: resource.custom?)
          causes.concat(CRD::CELValidation.errors(object, old: old)) if causes.empty? && crd_resource?(resource)
          causes.concat(storage_version_validation(object)) if storage_version_resource?(resource)
          return object if causes.empty?

          name = metadata_value(object, "name")
          details = invalid_details(resource, name, causes.map { |cause| {"reason" => cause.reason, "message" => cause.message, "field" => cause.field} })
          raise Status::Invalid.new(ObjectValidation.status_message(qualified_kind(resource), name, causes), details: details)
        end

        # Not every schema contract accepts a field-validation directive; the ones
        # that do drop undeclared fields, the ones that do not keep their own default.
        def apply_defaulting(target, object, unknown_fields, old = nil)
          if old && target.method(:default).parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :old }
            return target.default(object, unknown_fields: unknown_fields, old: old)
          end

          target.default(object, unknown_fields: unknown_fields)
        rescue ArgumentError
          target.default(object)
        end

        # A mutating webhook adds fields the client never sent -- a whole
        # container, in the conformance spec "should mutate pod and apply
        # defaults after mutation" -- and upstream defaults the patched object
        # again before anything else looks at it
        # (admission/plugin/webhook/mutating/patch.go).  Without that the added
        # container has no terminationMessagePolicy, no imagePullPolicy and no
        # resources.
        def redefault_after_mutation(resource, object, before, unknown_fields: :preserve, operation: :create)
          return object unless object.is_a?(Hash) && object != before

          apply_defaults_only(resource, object, unknown_fields: unknown_fields, operation: operation)
        end

        def apply_defaults_only(resource, object, unknown_fields: :preserve, old: nil, operation: :create)
          object = ObjectMetaWire.omit_empty_finalizers(object)
          object = PodWire.normalize(object) if PodWire.resource?(resource)
          object = PodWire.normalize_resource_selectors(resource, object)
          object = default_volume_limit_scaling(resource, object)
          # SSA computes ownership on the submitted v1 patch before this
          # conversion. Ordinary writes track the resulting data map.
          object = SecretData.normalize_request(object) if SecretData.resource?(resource)
          schema = resource.schema
          defaulting = schema_hash_defaulting(schema)
          if defaulting
            operation = :decode_create if operation == :create && Schema::JobSelector.resource?(resource)
            defaulting.apply_hash(object, unknown_fields: unknown_fields, kubernetes_admission_defaults: operation, old: old)
          elsif schema_defaults?(schema)
            apply_defaulting(schema, object, unknown_fields, old)
          else
            object
          end
        end

        def apply_schema(resource, object, operation: nil, old: nil, unknown_fields: :preserve, subresource: nil)
          prior = old if operation.to_s.casecmp?("update")
          object = default_schema_for_write(resource, object, unknown_fields: unknown_fields, old: prior)
          validate_schema(resource, object, operation: operation, old: old, subresource: subresource)
        end

        def default_schema_for_write(resource, object, unknown_fields: :preserve, old: nil)
          # Only a stored object in this very version is a defaulted baseline:
          # a view converted from another storage version was defaulted
          # against that version's schema.
          baseline = old if old.is_a?(Hash) && old.frozen? && old["apiVersion"] == resource.api_version
          apply_defaults_only(resource, object, unknown_fields: unknown_fields, old: baseline, operation: old ? :update : :decode_create)
        end

        def validate_schema(resource, object, operation:, old: nil, subresource: nil)
          result = drop_disabled_hostname_override(resource, object, old: old)
          result = drop_disabled_lease_fields(resource, result, old)
          result = drop_disabled_volume_projections(resource, result, old: old)
          result = Schema::DRAFeatureFields.prepare(resource, result, old, method(:feature_gate_enabled?))
          spread_gates = disabled_topology_spread_gates(resource, subresource)
          result = Schema::KubernetesValidator.prepare_topology_spread(result, old, resource.kind, spread_gates) if spread_gates
          if !resource.custom? && Schema::KubernetesValidator.pdb_v1?(resource)
            result = Schema::KubernetesValidator.prepare_pod_disruption_budget(result, status_update: subresource == "status")
          end
          if persistent_volume_claim_resource?(resource) && subresource.nil?
            sources = Schema::PersistentVolumeClaimSources
            result = sources.prepare(result, old, cross_namespace: feature_gate_enabled?(sources::CROSS_NAMESPACE_GATE))
            old = sources.normalize(old)
          end
          identity_causes = immutable_uid_causes(old, result) if operation == :update && old
          validator = schema_validator(resource.schema)
          raise invalid_resource(resource, result, identity_causes) if !validator && identity_causes
          return result unless validator

          options = {}
          if !resource.custom? && resource.group == "scheduling.k8s.io" &&
             Schema::KubernetesValidator::SCHEDULING_DECLARATIVE_KINDS.include?(resource.kind)
            gates = Schema::KubernetesValidator::SCHEDULING_VALIDATION_FEATURES.keys.select do |gate|
              feature_gate_enabled?(gate)
            end
            result = Schema::KubernetesValidator.prepare_scheduling_validation(result, old, resource.kind, gates, subresource)
            options[:declarative_options] = subresource.to_s == "status" ? [] : gates
          elsif resource.group == "autoscaling" && resource.kind == "HorizontalPodAutoscaler" &&
                (feature_gate_enabled?("HPAScaleToZero") || old&.dig("spec", "minReplicas") == 0)
            options[:declarative_options] = ["HPAScaleToZero"]
          elsif persistent_volume_resource?(resource) && feature_gate_enabled?("MutablePVNodeAffinity")
            options[:declarative_options] = ["MutablePVNodeAffinity"]
          end
          if POD_SPEC_PATHS.key?(resource.kind) && !resource.custom? && feature_gate_enabled?(TaintToleration::GATE)
            (options[:declarative_options] ||= []) << TaintToleration::GATE
          end
          userns = Schema::KubernetesValidator::USER_NAMESPACES_HOST_NETWORK_GATE
          (options[:declarative_options] ||= []) << userns if POD_SPEC_PATHS.key?(resource.kind) && !resource.custom? && feature_gate_enabled?(userns)
          (options[:declarative_options] ||= []).concat(spread_gates.map { |gate| "#{gate}=false" }) if spread_gates && !spread_gates.empty?
          observe_declarative_validation(resource, validator, result, old: old, operation: operation, subresource: subresource,
                                                                      options: options.fetch(:declarative_options, []))
          validation = validator.validate(result, unknown_fields: :preserve,
                                                  operation: operation, old: old, subresource: subresource, **options)
          raise Status::Invalid.new("resource validation failed") if validation == false

          validation = identity_causes + (validation.is_a?(Array) ? validation : []) if identity_causes
          raise invalid_resource(resource, result, validation) if validation.is_a?(Array) && !validation.empty?

          result
        end

        def disabled_topology_spread_gates(resource, subresource)
          return unless subresource.to_s.empty? && POD_SPEC_PATHS.key?(resource.kind) && !resource.custom?

          Schema::KubernetesValidator::TOPOLOGY_SPREAD_GATES.reject { |gate| feature_gate_enabled?(gate) }
        end

        def drop_disabled_lease_fields(resource, object, old)
          return object unless resource.group == "coordination.k8s.io" && resource.resource == "leases"
          return object if feature_gate_enabled?("CoordinatedLeaderElection")

          spec = object["spec"]
          return object unless spec.is_a?(Hash)

          disabled = %w[strategy preferredHolder].select { |field| old&.dig("spec", field).nil? && spec.key?(field) }
          disabled.empty? ? object : object.merge("spec" => spec.except(*disabled))
        end

        # Advancing a comparison or panic counter does not change an API
        # response for a strategy that shadows the generated rules.
        def observe_declarative_validation(resource, validator, object, old:, operation:, subresource:, options:)
          return unless %i[create update].include?(operation)
          return unless validator.is_a?(Schema::Validator)

          schema = validator.definition.name
          return unless Schema::DeclarativeValidation.shadowed?(schema, subresource)

          identifier = [resource.kind.downcase, subresource, operation].compact.join("_")
          observe_declarative_comparison(identifier, schema, object, old, operation, options, subresource: subresource)
        end

        def prepare_declarative_comparison_object(schema, object, old, subresource)
          if schema == Schema::DeclarativeValidation::CSR && subresource.to_s.empty?
            object.merge("status" => old&.fetch("status", nil))
          elsif Schema::DeclarativeValidation::RESOURCE_SCHEMAS.include?(schema)
            preparation = Schema::DeclarativeResourcePreparation.new(method(:feature_gate_enabled?))
            preparation.prepare(schema.split(".").last, object, old, subresource)
          else
            object
          end
        end

        def observe_declarative_comparison(identifier, schema, object, old, operation, options = [], subresource: nil)
          begin
            object = prepare_declarative_comparison_object(schema, object, old, subresource)
            count = Schema::DeclarativeValidation.mismatches(schema, object, old, operation, options: options, subresource: subresource)
          rescue StandardError => error
            @metrics.declarative_validation_panic(identifier)
            @logger&.error("apiserver.declarative_validation.panic", validation_identifier: identifier, error: error.message)
            return
          end
          return if count.zero?

          @metrics.declarative_validation_mismatch(identifier, count)
          @logger&.error("apiserver.declarative_validation.mismatch", validation_identifier: identifier, discrepancies: count)
        end

        # apierrors.NewInvalid for the causes a schema validator reported.
        def qualified_kind(resource)
          resource.group.to_s.empty? ? resource.kind : "#{resource.kind}.#{resource.group}"
        end

        def invalid_resource(resource, object, validation)
          causes = validation.map { |cause| validation_cause(cause, object) }
          rendered = causes.map { |cause| [cause["field"], cause["message"]].compact.join(": ") }
          rendered.uniq!
          name = metadata_value(object, "name")
          body = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
          Status::Invalid.new("#{qualified_kind(resource)} #{name.to_s.inspect} is invalid: #{body}",
                              details: invalid_details(resource, name, causes))
        end

        def invalid_details(resource, name, causes)
          details = {"kind" => resource.kind, "causes" => causes}
          details["group"] = resource.group unless resource.group.to_s.empty?
          details["name"] = name unless name.to_s.empty?
          details
        end

        # fieldmanager.UpdateNoErrors for a write that is not an apply: the
        # managed fields the object is stored with (nil for none), from the
        # live object and the one written -- decoded and defaulted, before
        # mutating admission, where upstream's handlers run it.
        def record_managed_update(request, route, existing, object)
          @field_managers.field_manager(route.resource, route.subresource)
            .update(live: existing, new_object: object, manager: update_manager(request))
        end

        # The object with +managed_fields+ as its metadata.managedFields (none
        # when empty).  Stored objects are frozen, so nothing is changed in place.
        def with_managed_fields(object, managed_fields)
          return object unless object.is_a?(Hash)

          metadata = object["metadata"].is_a?(Hash) ? object["metadata"] : {}
          metadata = if managed_fields.nil? || managed_fields.empty?
                       metadata.except("managedFields")
                     else
                       metadata.merge("managedFields" => managed_fields)
                     end
          object.merge("metadata" => metadata)
        end
      end
    end
  end
end
