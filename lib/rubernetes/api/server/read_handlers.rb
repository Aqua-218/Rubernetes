# frozen_string_literal: true

require_relative "../watch_websocket"

module Rubernetes
  module API
    class Server
      # GET, LIST and WATCH of a stored resource, with the list and watch option
      # validation of metav1.ListOptions.
      module ReadHandlers
        private

        def register_sharded_watch_metrics
          @metrics.register("apiserver_watch_shards_total", type: :gauge, labels: %w[group resource],
                                                            help: "[ALPHA] Number of active sharded watch connections broken by resource type.")
          @metrics.register("apiserver_watch_filtered_events_total", type: :counter, labels: %w[group resource],
                                                                     help: "[ALPHA] Counter of events filtered out by shard selector " \
                                                                           "during watch dispatch, broken by resource type.")
        end

        def get_response(route)
          namespace = storage_namespace(route, operation: :get)
          object = default_on_read(route.resource, @store.get(resource: route.resource, namespace: namespace, name: route.name))
          object = scale_view(object, route.resource) if route.subresource == "scale"
          json_response(object)
        rescue MemoryStore::NotFound
          raise missing_resource(route)
        end

        def list_item(resource, object)
          if resource.custom?
            object.merge("apiVersion" => resource.api_version, "kind" => resource.kind)
          else
            object.except("apiVersion", "kind")
          end
        end

        def list_response(request, route)
          namespace = storage_namespace(route, operation: :list)
          validate_list_options!(request)
          selectors = selectors_from(request)
          result = list_page(request, route, namespace, selectors)
          json_response(list_payload(route, result, selectors))
        end

        def list_page(request, route, namespace, selectors)
          @store.list(
            resource: route.resource,
            namespace: namespace,
            selectors: selectors,
            resource_version: query(request, "resourceVersion"),
            resource_version_match: query(request, "resourceVersionMatch"),
            limit: list_limit(request, selectors),
            continue_token: query(request, "continue")
          )
        end

        def list_payload(route, result, selectors, items: result.items)
          payload = {
            "apiVersion" => route.resource.api_version,
            "kind" => route.resource.list_kind,
            "metadata" => {"resourceVersion" => result.resource_version.to_s},
            # kube-apiserver serializes built-in list items without their
            # TypeMeta: the list envelope's apiVersion/kind identify the item
            # type.  Custom resources are unstructured and keep theirs
            # (apiextensions-apiserver serves UnstructuredList, whose items are
            # whole objects), and clients such as the dynamic informer rely on it.
            "items" => items.map { |object| list_item(route.resource, default_on_read(route.resource, deep_copy(object))) }
          }
          payload["metadata"]["continue"] = result.continue_token if result.continue_token
          payload["metadata"]["remainingItemCount"] = result.remaining_item_count unless result.remaining_item_count.nil?
          # Built-in lists embed ListMeta. UnstructuredList has no shardInfo
          # accessor in v1.36.2, though its items are still filtered.
          payload["metadata"]["shardInfo"] = {"selector" => selectors.shard.to_s} if selectors.shard && !route.resource.custom?
          payload
        end

        def list_limit(request, selectors)
          limit = integer_query(request, "limit")
          return if selectors.shard && query(request, "resourceVersion") == "0" && query(request, "continue").to_s.empty?

          limit
        end

        def validate_list_options!(request)
          match = query(request, "resourceVersionMatch")
          send_initial = query(request, "sendInitialEvents")
          causes = []
          unless match.nil? || match.to_s.empty?
            if query(request, "resourceVersion").to_s.empty?
              causes << {
                "reason" => "FieldValueForbidden",
                "message" => "Forbidden: resourceVersionMatch is forbidden unless resourceVersion is provided",
                "field" => "resourceVersionMatch"
              }
            end
            unless query(request, "continue").to_s.empty?
              causes << {
                "reason" => "FieldValueForbidden",
                "message" => "Forbidden: resourceVersionMatch is forbidden when continue is provided",
                "field" => "resourceVersionMatch"
              }
            end
            unless %w[Exact NotOlderThan].include?(match.to_s)
              causes << {
                "reason" => "FieldValueNotSupported",
                "message" => "Unsupported value: #{match.inspect}: supported values: \"Exact\", \"NotOlderThan\"",
                "field" => "resourceVersionMatch"
              }
            end
            if match.to_s == "Exact" && query(request, "resourceVersion").to_s == "0"
              causes << {
                "reason" => "FieldValueForbidden",
                "message" => "Forbidden: resourceVersionMatch \"exact\" is forbidden for resourceVersion \"0\"",
                "field" => "resourceVersionMatch"
              }
            end
          end
          unless send_initial.nil?
            causes << {
              "reason" => "FieldValueForbidden",
              "message" => "Forbidden: sendInitialEvents is forbidden for list",
              "field" => "sendInitialEvents"
            }
          end
          invalid_list_options!(causes)
        end

        # apierrors.NewInvalid for ListOptions, when there is anything to report.
        def invalid_list_options!(causes)
          return if causes.empty?

          rendered = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }
          summary = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
          raise Status::Invalid.new(
            "ListOptions.meta.k8s.io \"\" is invalid: #{summary}",
            details: {"group" => "meta.k8s.io", "kind" => "ListOptions", "causes" => causes}
          )
        end

        def watch_response(request, route)
          namespace = storage_namespace(route, operation: :watch)
          validate_watch_options!(request)
          selection = watch_selection(request, route)
          upgrade_headers = WatchWebSocket.headers(request)
          initial_events = query(request, "sendInitialEvents")
          stream = @store.watch(
            resource: route.resource,
            namespace: namespace,
            selectors: watch_selectors(request, route),
            resource_version: query(request, "resourceVersion"),
            resource_version_match: query(request, "resourceVersionMatch"),
            allow_bookmarks: truthy?(query(request, "allowWatchBookmarks")),
            send_initial_events: (truthy?(initial_events) unless initial_events.nil?),
            timeout_seconds: integer_query(request, "timeoutSeconds"),
            object_defaults: watch_object_defaults(route.resource, selection)
          )
          return websocket_watch_response(request, route, upgrade_headers, stream, selection) if upgrade_headers

          Response.new(status: 200, headers: {"content-type" => "application/json",
                                              "cache-control" => "no-cache, private"},
                       body: stream, unbounded: true)
        end

        def validate_watch_options!(request)
          send_initial_value = query(request, "sendInitialEvents")
          resource_version_match = query(request, "resourceVersionMatch")
          resource_version_match_present = !resource_version_match.nil? && !resource_version_match.to_s.empty?
          send_initial_present = !send_initial_value.nil?
          causes = []
          if resource_version_match_present && !send_initial_present
            causes << {
              "reason" => "FieldValueForbidden",
              "message" => "Forbidden: resourceVersionMatch is forbidden for watch unless sendInitialEvents is provided",
              "field" => "resourceVersionMatch"
            }
          end
          if send_initial_present && resource_version_match != "NotOlderThan"
            causes << {
              "reason" => "FieldValueForbidden",
              "message" => "Forbidden: sendInitialEvents requires setting resourceVersionMatch to NotOlderThan",
              "field" => "resourceVersionMatch"
            }
          end
          if resource_version_match_present && resource_version_match != "NotOlderThan"
            causes << {
              "reason" => "FieldValueNotSupported",
              "message" => "Unsupported value: #{resource_version_match.inspect}: supported values: \"NotOlderThan\"",
              "field" => "resourceVersionMatch"
            }
          end
          if resource_version_match_present && !query(request, "continue").to_s.empty?
            causes << {
              "reason" => "FieldValueForbidden",
              "message" => "Forbidden: resourceVersionMatch is forbidden when continue is provided",
              "field" => "resourceVersionMatch"
            }
          end
          invalid_list_options!(causes)
        end

        def selectors_from(request)
          shard_selector = query(request, "shardSelector") if feature_gate_enabled?(ShardSelector::GATE)
          Selectors.new(label_selector: query(request, "labelSelector"), field_selector: query(request, "fieldSelector"),
                        shard_selector: shard_selector)
        rescue ShardSelector::Error => error
          # v1.36.2 hands ordinary storage errors back as HTTP 500 without
          # a Status reason field.
          raise Status::Error.new(message: "invalid shard selector: #{error.message}", code: 500, reason: "")
        end

        def watch_selectors(request, route)
          selectors = selectors_from(request)
          return selectors unless route.name

          if selectors.field.empty?
            name = Selector::Requirement.new(key: "metadata.name", operator: :equals, values: [route.name])
            return Selectors.new(label: selectors.label, field: Selector.new([name]), shard: selectors.shard)
          end

          name = selectors.field.requirements.find { |term| term.key == "metadata.name" && term.operator == :equals }
          raise Status::BadRequest.new("fieldSelector metadata.name doesn't match requested name") unless name&.values == [route.name]

          selectors
        end

        def written_view(route, object)
          return Schema::JobSelector.decode_labels(object) if Schema::JobSelector.resource?(route.resource)

          object
        end

        def watch_object_defaults(resource, selection)
          if persistent_volume_claim_resource?(resource)
            return lambda do |object|
              claim = default_on_read(resource, object)
              selection.protobuf? || selection.partial_metadata? ? claim : PersistentVolumeClaimWire.claim(claim)
            end
          end
          return unless @service_allocator.service?(resource) || default_volume_limit_scaling?(resource)

          ->(object) { default_on_read(resource, object) }
        end

        # apiextensions applies a structural schema's defaults when an object is
        # read from storage as well as on write: a default added to the CRD
        # after the object was stored is visible on the next GET/LIST.
        def default_on_read(resource, object)
          return Schema::PersistentVolumeClaimSources.normalize(object) if persistent_volume_claim_resource?(resource)
          return @service_allocator.default_service_on_read(object) if @service_allocator.service?(resource)

          object = default_volume_limit_scaling(resource, object)
          return object unless object.is_a?(Hash) && resource.custom?

          resource.schema.default(object)
        rescue StandardError
          object
        end
      end
    end
  end
end
