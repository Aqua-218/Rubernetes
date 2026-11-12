# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # GET, LIST and WATCH of a stored resource, with the list and watch option
      # validation of metav1.ListOptions.
      module ReadHandlers
        private

        def get_response(route)
          namespace = storage_namespace(route, operation: :get)
          object = default_on_read(route.resource, @store.get(resource: route.resource, namespace: namespace, name: route.name))
          if route.subresource == "status"
            object = status_view(object)
          elsif route.subresource == "scale"
            object = scale_view(object, route.resource)
          end
          json_response(object)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                     details: resource_details(route))
        end

        def list_item(resource, object)
          if resource.custom?
            object.merge("apiVersion" => resource.api_version, "kind" => resource.kind)
          else
            object.reject { |key, _| %w[apiVersion kind].include?(key) }
          end
        end

        def list_response(request, route)
          namespace = storage_namespace(route, operation: :list)
          validate_list_options!(request)
          selectors = selectors_from(request)
          result = @store.list(
            resource: route.resource,
            namespace: namespace,
            selectors: selectors,
            resource_version: query(request, "resourceVersion"),
            resource_version_match: query(request, "resourceVersionMatch"),
            limit: integer_query(request, "limit"),
            continue_token: query(request, "continue")
          )
          payload = {
            "apiVersion" => route.resource.api_version,
            "kind" => route.resource.list_kind,
            "metadata" => {"resourceVersion" => result.resource_version.to_s},
            # kube-apiserver serializes built-in list items without their
            # TypeMeta: the list envelope's apiVersion/kind identify the item
            # type.  Custom resources are unstructured and keep theirs
            # (apiextensions-apiserver serves UnstructuredList, whose items are
            # whole objects), and clients such as the dynamic informer rely on it.
            "items" => result.items.map { |object| list_item(route.resource, default_on_read(route.resource, deep_copy(object))) }
          }
          payload["metadata"]["continue"] = result.continue_token if result.continue_token
          payload["metadata"]["remainingItemCount"] = result.remaining_item_count unless result.remaining_item_count.nil?
          json_response(payload)
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
          stream = @store.watch(
            resource: route.resource,
            namespace: namespace,
            selectors: selectors_from(request),
            resource_version: query(request, "resourceVersion"),
            resource_version_match: query(request, "resourceVersionMatch"),
            allow_bookmarks: truthy?(query(request, "allowWatchBookmarks")),
            send_initial_events: truthy?(query(request, "sendInitialEvents")),
            timeout_seconds: integer_query(request, "timeoutSeconds")
          )
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
          Selectors.new(label_selector: query(request, "labelSelector"), field_selector: query(request, "fieldSelector"))
        end

        # kube-apiserver serves the whole object from the status subresource
        # (GET and after PUT/PATCH); only the writable fields differ.
        def status_view(object)
          object
        end

        # The body a write through +route+ answers with.
        def written_view(route, object)
          route.subresource == "status" ? status_view(object) : object
        end

        # apiextensions applies a structural schema's defaults when an object is
        # read from storage as well as on write: a default added to the CRD
        # after the object was stored is visible on the next GET/LIST.
        def default_on_read(resource, object)
          return object unless object.is_a?(Hash) && resource.custom?

          resource.schema.default(object)
        rescue StandardError
          object
        end
      end
    end
  end
end
