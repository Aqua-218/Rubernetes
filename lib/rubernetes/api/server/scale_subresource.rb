# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The autoscaling/v1 Scale subresource: the projection of a workload (or a
      # custom resource's scale paths) and the writes that go through it.
      module ScaleSubresource
        private

        SCALE_API_VERSION = "autoscaling/v1"

        # autoscaling/v1 Scale projection of a workload object, the form the
        # scale client (kubectl scale, HPA) reads and writes.  A custom
        # resource's comes from its CRD's specReplicasPath, statusReplicasPath
        # and labelSelectorPath (scaleFromCustomResource); +for_update+ marks
        # a spec replicas the object does not have with the sentinel instead
        # of failing.
        def scale_view(object, resource = nil, for_update: false)
          paths = custom_scale_paths(resource)
          metadata = object.fetch("metadata", {})
          identity = metadata.slice("name", "namespace", "uid", "resourceVersion", "creationTimestamp")
          return builtin_scale_view(object, identity) unless paths

          spec_path = paths[:spec_replicas].to_s
          spec, found = nested_int64(object, spec_path)
          unless found
            raise Status::InternalError.new("the spec replicas field #{ManagedFields::Value.go_quote(spec_path)} does not exist") unless for_update

            spec = INVALID_SPEC_REPLICAS
          end
          status, = nested_int64(object, paths[:status_replicas].to_s)
          selector = paths[:label_selector].to_s.empty? ? nil : object.dig(*split_replicas_path(paths[:label_selector]))
          scale_status = {"replicas" => status || 0}
          scale_status["selector"] = selector if selector.is_a?(String) && !selector.empty?
          {"kind" => "Scale", "apiVersion" => SCALE_API_VERSION, "metadata" => identity,
           "spec" => {"replicas" => spec || 0}, "status" => scale_status}
        end

        INVALID_SPEC_REPLICAS = -2_147_483_648

        def builtin_scale_view(object, identity)
          selector = object.dig("spec", "selector")
          status = {"replicas" => Integer(object.dig("status", "replicas") || 0)}
          selector_text = selector_string(selector)
          status["selector"] = selector_text unless selector_text.nil? || selector_text.empty?
          {
            "kind" => "Scale", "apiVersion" => SCALE_API_VERSION, "metadata" => identity,
            "spec" => {"replicas" => Integer(object.dig("spec", "replicas") || 0)},
            "status" => status
          }
        end

        def custom_scale_paths(resource)
          return nil unless resource&.custom?

          resource.schema.scale_paths
        end

        # splitReplicasPath.
        def split_replicas_path(path) = path.to_s.delete_prefix(".").split(".")

        # unstructured.NestedInt64: [value, found]; a value of another type is
        # an error.
        def nested_int64(object, path)
          parts = split_replicas_path(path)
          value = parts.reduce(object) do |node, key|
            return [nil, false] unless node.is_a?(Hash) && node.key?(key)

            node[key]
          end
          return [value, true] if value.is_a?(Integer)

          type = value.is_a?(Float) ? "float64" : value.class.name.downcase
          raise Status::InternalError.new("#{path} accessor error: #{value.inspect} is of the type #{type}, expected int64")
        end

        # The managedFields entries a Scale is seen with (ScaleHandler
        # ToSubresource), and the parent's paths per version.
        def scale_mappings(resource)
          paths = custom_scale_paths(resource)
          @field_managers.scale_mappings(resource, replicas_path: paths && split_replicas_path(paths[:spec_replicas]))
        end

        def live_scale(route, existing)
          view = scale_view(existing, route.resource, for_update: true)
          entries = begin
            ManagedFields::ScaleHandler.to_subresource(existing.dig("metadata", "managedFields"), scale_mappings(route.resource))
          rescue ManagedFields::Entries::DecodeError
            nil
          end
          view["metadata"] = view["metadata"].merge("managedFields" => entries) if entries
          view
        end

        # metav1.FormatLabelSelector / labels.FormatLabels for the selector
        # forms workloads use (LabelSelector, or the map ReplicationController
        # keeps in spec.selector).
        def selector_string(selector)
          return nil unless selector.is_a?(Hash)

          if selector.key?("matchLabels") || selector.key?("matchExpressions")
            requirements = (selector["matchLabels"] || {}).sort.map { |key, value| "#{key}=#{value}" }
            Array(selector["matchExpressions"]).each do |expression|
              key = expression["key"]
              values = Array(expression["values"]).sort.join(",")
              requirements << case expression["operator"]
                              when "In" then "#{key} in (#{values})"
                              when "NotIn" then "#{key} notin (#{values})"
                              when "Exists" then key.to_s
                              when "DoesNotExist" then "!#{key}"
                              else "#{key} #{expression["operator"]} (#{values})"
                              end
            end
            requirements.join(",")
          else
            selector.sort.map { |key, value| "#{key}=#{value}" }.join(",")
          end
        end

        # The Scale a write produced: its replicas (ValidateScale, and the
        # sentinel check of a custom resource that never had replicas).
        def scale_body!(scale, route)
          raise Status::BadRequest.new("wrong object passed to Scale update: #{scale.inspect}") unless scale.is_a?(Hash)

          kind = scale["kind"].to_s
          raise Status::BadRequest.new("wrong object passed to Scale update: kind #{kind.inspect}") unless kind.empty? || kind == "Scale"

          replicas = scale.dig("spec", "replicas") || 0
          unless replicas.is_a?(Integer)
            raise Status::BadRequest.new("json: cannot unmarshal #{replicas.class.name.downcase} into Go struct field ScaleSpec.spec.replicas of type int32")
          end
          if replicas == INVALID_SPEC_REPLICAS && (paths = custom_scale_paths(route.resource))
            raise Status::BadRequest.new("the spec replicas field #{ManagedFields::Value.go_quote(paths[:spec_replicas].to_s)} cannot be empty")
          end

          if replicas.negative?
            cause = {"reason" => "FieldValueInvalid", "field" => "spec.replicas",
                     "message" => "Invalid value: #{replicas}: must be greater than or equal to 0"}
            raise Status::Invalid.new(
              "Scale.autoscaling #{route.name.to_s.inspect} is invalid: spec.replicas: #{cause["message"]}",
              details: {"name" => route.name.to_s, "group" => "autoscaling", "kind" => "Scale", "causes" => [cause]}
            )
          end
          replicas
        end

        def scale_update(existing, replicas, resource = nil)
          object = deep_copy(existing)
          path = (paths = custom_scale_paths(resource)) ? split_replicas_path(paths[:spec_replicas]) : %w[spec replicas]
          node = path[0...-1].reduce(object) { |parent, key| parent[key].is_a?(Hash) ? parent[key] : (parent[key] = {}) }
          node[path.last] = replicas
          object
        end

        def validate_scale_wire!(request, scale, apply: false)
          raise Status::BadRequest.new("Scale must be an object") unless scale.is_a?(Hash)

          resource = @scale_resource ||= typed_subresource("autoscaling", "v1", "Scale", "scales")
          if apply
            validator = resource.schema.validator
            error = validator.wire_type_error(validator.errors(scale, unknown_fields: :preserve))
            raise Status::Error.new(message: "failed to create typed patch object: #{error}", code: 500, reason: nil) if error
          end
          enforce_field_validation(resource, scale, request, duplicates: request_duplicate_fields(request), apply: apply)
        end

        # A PUT or non-apply PATCH of /scale: the Scale field manager records
        # the write against the Scale the parent projects, and its entries go
        # back onto the parent (ScaleHandler ToParent).
        def scale_update_response(request, route, existing, namespace, scale)
          validate_scale_wire!(request, scale)
          check_storage_uid!(route, existing, scale) if request.method.to_s == "PUT"
          live = live_scale(route, existing)
          entries = @field_managers.scale_field_manager.update(live: live, new_object: scale, manager: update_manager(request))
          scale_write_response(route, existing, namespace, scale, entries, dry_run: dry_run?(request))
        end

        # Server-side apply to /scale.
        def scale_apply_response(request, route, existing, namespace, document)
          raise Status::BadRequest.new("error decoding YAML: apply patch must be an object") unless document.is_a?(Hash)

          validate_scale_wire!(request, document, apply: true)
          live = live_scale(route, existing)
          merged, entries = begin
            @field_managers.scale_field_manager.apply(live: live, config: stringify_keys(document),
                                                      manager: query(request, "fieldManager").to_s,
                                                      force: truthy?(query(request, "force")))
          rescue ManagedFields::FieldManager::Error, ManagedFields::TypedValue::Error => error
            raise Status::InternalError.new(error.message)
          end
          scale_write_response(route, existing, namespace, merged, entries, dry_run: dry_run?(request))
        end

        def scale_write_response(route, existing, namespace, scale, entries, dry_run: false)
          if scale.is_a?(Hash)
            match_request_namespace!(scale, route)
            check_update_name!(scale, route)
          end
          if !route.resource.custom? && route.resource.group.to_s.empty? && route.resource.kind == "ReplicationController" &&
             scale.is_a?(Hash) && scale["spec"].is_a?(Hash) && scale.dig("spec", "replicas").is_a?(Integer)
            previous_scale = scale_view(existing, route.resource, for_update: true)
            observe_declarative_comparison("scale_scale_update", Schema::DeclarativeValidation::SCALE, scale, previous_scale, :update)
          end
          replicas = scale_body!(scale, route)
          check_scale_uid!(route, existing, scale) unless route.resource.custom?
          expected = scale.dig("metadata", "resourceVersion")
          checked_update_version!(route, existing, parse_update_version(expected)) unless expected.to_s.empty?
          object = scale_update(existing, replicas, route.resource)
          object = apply_schema(route.resource, object, operation: :update, old: existing)
          parent = begin
            ManagedFields::ScaleHandler.to_parent(existing.dig("metadata", "managedFields"), entries,
                                                  route.resource.api_version, scale_mappings(route.resource))
          rescue ManagedFields::Entries::DecodeError
            existing.dig("metadata", "managedFields")
          end
          object = with_managed_fields(object, parent)
          object = apply_generation(object, existing, subresource: route.subresource, resource: route.resource)
          return json_response(scale_view(object, route.resource)) if dry_run

          updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                  object: object, resource_version: metadata_value(existing, "resourceVersion"))
          json_response(scale_view(updated, route.resource))
        end
      end
    end
  end
end
