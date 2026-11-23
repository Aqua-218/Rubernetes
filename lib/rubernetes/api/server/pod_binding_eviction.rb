# frozen_string_literal: true

require_relative "../../label_requirement"

module Rubernetes
  module API
    class Server
      # pods/binding and pods/eviction, with the PodDisruptionBudget check an
      # eviction has to pass.
      module PodBindingAndEviction
        private

        # pkg/registry/core/pod/storage/storage.go BindingREST: the scheduler
        # assigns a node by POSTing a Binding; the pod's nodeName is set once
        # (a second binding conflicts) and PodScheduled=True is recorded.
        def binding_response(request, route)
          raise Status::MethodNotAllowed.new("verb #{request.method} is not supported for pods/binding") unless request.method == "POST"

          validate_write_options!(request, "CreateOptions")
          namespace = storage_namespace(route, operation: :update)
          object = admitted_pod_action(request, route, "Binding", "v1", namespace)
          node_name = binding_node(object)
          # The legacy bindings collection uses the same Pod storage strategy.
          if route.resource.resource == "bindings"
            route = route.dup
            route.resource = @registry.find_gvr(group: "", version: "v1", resource: "pods")
            route.name = metadata_value(object, "name")
          end
          existing = @store.get(resource: route.resource, namespace: namespace, name: route.name)
          ensure_binding_allowed!(object, route, existing)
          unless dry_run?(request)
            updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                    object: bound_pod(existing, object, node_name),
                                    resource_version: metadata_value(existing, "resourceVersion"))
            after_commit(route.resource, updated)
          end
          json_response({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Success", "code" => 201},
                        status: 201)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
        end

        def ensure_binding_allowed!(binding, route, pod)
          preconditions = binding.fetch("metadata", {}).slice("uid", "resourceVersion")
          preconditions.each do |key, value|
            next if value.to_s.empty? || metadata_value(pod, key) == value

            label = key == "uid" ? "UID" : "ResourceVersion"
            detail = "Precondition failed: #{label} in precondition: #{value}, #{label} in object meta: #{metadata_value(pod, key)}"
            raise Status::Conflict.new("Operation cannot be fulfilled on pods #{route.name.inspect}: StorageError: invalid object, Code: 4, " \
                                       "Key: /pods/#{route.namespace}/#{route.name}, ResourceVersion: 0, AdditionalErrorMsg: #{detail}",
                                       details: resource_details(route))
          end
          assigned = pod.dig("spec", "nodeName").to_s
          reason = if metadata_value(pod, "deletionTimestamp")
                     "is being deleted, cannot be assigned to a host"
                   elsif !assigned.empty?
                     "is already assigned to node #{assigned.inspect}"
                   elsif !Array(pod.dig("spec", "schedulingGates")).empty?
                     "has non-empty .spec.schedulingGates"
                   end
          return unless reason

          raise Status::Conflict.new("Operation cannot be fulfilled on pods/binding #{route.name.inspect}: pod #{route.name} #{reason}",
                                     details: {"name" => route.name, "kind" => "pods/binding"})
        end

        def admitted_pod_action(request, route, kind, version, namespace)
          body = request_body(request)
          raise Status::BadRequest.new("request body must be a JSON object") unless body.is_a?(Hash)

          object = stringify_keys(body)
          provided = object["kind"].to_s
          raise Status::BadRequest.new("expected #{kind}, got #{provided.inspect}") unless provided.empty? || provided == kind

          match_request_namespace!(object, route)
          name = metadata_value(object, "name").to_s
          raise Status::BadRequest.new("name in URL does not match name in #{kind} object") if route.name && name != route.name
          raise Status::BadRequest.new("metadata.name is required") if name.empty?

          object["kind"] = kind
          object["apiVersion"] ||= version
          admitted_for_create_subresource(request, route, object, namespace, dry_run: dry_run?(request))
        end

        def binding_node(object)
          target = object["target"]
          raise Status::BadRequest.new("target is required") unless target.is_a?(Hash)

          target_kind = target["kind"].to_s
          raise Status::BadRequest.new("target.kind #{target_kind.inspect} is not supported (expected Node)") unless target_kind.empty? || target_kind == "Node"

          node_name = target["name"].to_s
          raise Status::BadRequest.new("target.name is required") if node_name.empty?

          node_name
        end

        # The Pod as the binding leaves it: assigned, carrying the Binding's
        # annotations and labels, and PodScheduled=True.
        def bound_pod(existing, binding, node_name)
          candidate = deep_copy(existing)
          candidate["spec"] ||= {}
          candidate["spec"]["nodeName"] = node_name
          annotations = binding.dig("metadata", "annotations")
          if annotations.is_a?(Hash) && !annotations.empty?
            candidate["metadata"]["annotations"] = (candidate["metadata"]["annotations"] || {}).merge(stringify_keys(annotations))
          end
          # setPodNodeAndMetadata: the Binding's labels (PodTopologyLabels puts
          # the Node's zone and region there) overwrite the Pod's.
          labels = binding.dig("metadata", "labels")
          candidate["metadata"]["labels"] = (candidate["metadata"]["labels"] || {}).merge(stringify_keys(labels)) if labels.is_a?(Hash) && !labels.empty?
          candidate["status"] ||= {}
          # ClearingNominatedNodeNameAfterBinding (Beta, on).
          candidate["status"].delete("nominatedNodeName")
          now = @clock.call.utc.iso8601
          conditions = Array(candidate["status"]["conditions"]).reject { |condition| condition["type"] == "PodScheduled" }
          conditions << {"type" => "PodScheduled", "status" => "True", "lastProbeTime" => nil, "lastTransitionTime" => now}
          candidate["status"]["conditions"] = conditions
          candidate
        end

        # pkg/registry/core/pod/storage/eviction.go: an Eviction deletes the pod
        # through the delete options it carries once those options validate.
        def eviction_response(request, route)
          raise Status::MethodNotAllowed.new("verb #{request.method} is not supported for pods/eviction") unless request.method == "POST"

          validate_write_options!(request, "CreateOptions")
          namespace = storage_namespace(route, operation: :delete)
          object = admitted_pod_action(request, route, "Eviction", "policy/v1", namespace)
          delete_options = eviction_delete_options(request, route, object)
          existing = begin
            @store.get(resource: route.resource, namespace: namespace, name: route.name)
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
          end
          dry_run = !Array(delete_options["dryRun"]).empty?
          caller_version = eviction_precondition!(delete_options, existing)
          unhealthy_budget = check_disruption_budgets!(namespace, existing, dry_run: dry_run)
          existing = mark_evicted(route.resource, namespace, route.name, existing) unless dry_run
          delete_evicted_pod(route, namespace, existing, delete_options, pin_version: !!(caller_version || unhealthy_budget))
          json_response({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Success", "code" => 201}, status: 201)
        rescue MemoryStore::Conflict
          raise retry_disruption_budget(unhealthy_budget) if unhealthy_budget && !caller_version

          raise
        end

        # Merge CreateOptions.dryRun into the embedded DeleteOptions.
        def eviction_delete_options(request, route, object)
          delete_options = object["deleteOptions"].nil? ? {} : object["deleteOptions"]
          raise Status::BadRequest.new("deleteOptions must be an object") unless delete_options.is_a?(Hash)

          if delete_options[DeleteHandler::UNSAFE_DELETE_OPTION] == true
            cause = {"reason" => "FieldValueInvalid", "field" => "deleteOptions.#{DeleteHandler::UNSAFE_DELETE_OPTION}",
                     "message" => "Invalid value: true: can not be set for pod eviction, try after removing the option"}
            raise Status::Invalid.new("Eviction.policy #{route.name.inspect} is invalid: #{cause.fetch("message")}",
                                      details: {"group" => "policy", "kind" => "Eviction", "name" => route.name, "causes" => [cause]})
          end

          requested = Array(request.query_values("dryRun"))
          content = Array(delete_options["dryRun"])
          if content.empty? && !requested.empty?
            delete_options["dryRun"] = requested
          elsif !requested.empty? && content != requested
            raise Status::Error.new(message: "Non-matching dry-run options in request and content: [#{requested.join(" ")}] and [#{content.join(" ")}]",
                                    code: 500, reason: "")
          end
          validate_delete_options!(delete_options)
          delete_options
        end

        # eviction.go addConditionAndDeletePod: a resourceVersion precondition
        # the CALLER set is checked against the Pod before the DisruptionTarget
        # condition is written and then moved to the version that write
        # produced. Evicting an exempt unhealthy pod also pins the version so it
        # cannot become healthy between the check and delete. Pinning other deletes
        # to our own condition write's version instead made any writer that
        # slipped in between (the node publishing status for the Pod it had
        # just seen change) fail the eviction with "expected resourceVersion
        # N, current is N+1" ("DisruptionController should block an eviction
        # until the PDB is updated to allow it").
        #
        # Returns the caller's precondition, nil when there is none.
        def eviction_precondition!(delete_options, existing)
          caller_version = delete_options.dig("preconditions", "resourceVersion")
          {"uid" => ["UID", "deleted and then recreated"], "resourceVersion" => %w[ResourceVersion modified]}.each do |field, (label, reason)|
            expected = delete_options.dig("preconditions", field)
            actual = metadata_value(existing, field)
            next if expected.to_s.empty? || expected == actual

            name = metadata_value(existing, "name")
            raise Status::Conflict.new("Operation cannot be fulfilled on Pod #{name.inspect}: the #{label} in the precondition (#{expected}) " \
                                       "does not match the #{label} in record (#{actual}). The object might have been #{reason}",
                                       details: {"kind" => "Pod", "name" => name})
          end
          caller_version unless caller_version.to_s.empty?
        end

        # Eviction follows the Pod strategy for its grace period and finalizers.
        def delete_evicted_pod(route, namespace, existing, delete_options, pin_version:)
          return unless Array(delete_options["dryRun"]).empty?

          expected = metadata_value(existing, "resourceVersion") if pin_version
          existing, pending = prepare_deletion(route, namespace, existing, delete_options, dry_run: false, expected: expected)
          remove_deleted_object(route, namespace, existing, repin_after_mark(expected, existing)) unless pending
        end

        # eviction.go addConditionAndDeletePod: an evicted Pod is told that it is
        # going away because something evicted it, before it is deleted, so that
        # a controller can tell an involuntary disruption from the Pod's own
        # failure.  We deleted it silently, so a Job whose podFailurePolicy
        # ignores failures matching DisruptionTarget had nothing to match and
        # counted every eviction as a real failure ("[sig-apps] Job should allow
        # to use a pod failure policy to ignore failure matching on
        # DisruptionTarget condition").
        def mark_evicted(resource, namespace, name, existing)
          candidate = deep_copy(existing)
          candidate["status"] ||= {}
          conditions = Array(candidate["status"]["conditions"]).reject { |condition| condition["type"] == "DisruptionTarget" }
          conditions << {"type" => "DisruptionTarget", "status" => "True",
                         "reason" => "EvictionByEvictionAPI", "message" => "Eviction API: evicting",
                         "lastProbeTime" => nil, "lastTransitionTime" => @clock.call.utc.iso8601}
          candidate["status"]["conditions"] = conditions
          updated = @store.update(resource: resource, namespace: namespace, name: name, object: candidate,
                                  resource_version: metadata_value(existing, "resourceVersion"))
          after_commit(resource, updated)
          updated
        rescue MemoryStore::NotFound, MemoryStore::Conflict
          # Something else is already changing this Pod; the eviction itself is
          # what matters and still has to go through.
          existing
        end

        PDB_RESOURCE = "poddisruptionbudgets"

        DISRUPTION_BUDGET_CAUSE = "DisruptionBudget"

        def check_disruption_budgets!(namespace, pod, dry_run: false)
          return if %w[Pending Succeeded Failed].include?(pod.dig("status", "phase")) || metadata_value(pod, "deletionTimestamp")

          budgets = disruption_budgets_for(namespace, pod)
          return if budgets.empty?

          if budgets.length > 1
            raise Status::InternalError.new("This pod has more than one PodDisruptionBudget, which the eviction subresource does not support.")
          end

          budget = budgets.first
          status = budget["status"] || {}
          name = budget.dig("metadata", "name")
          return name if allow_unhealthy_eviction?(pod, budget, status)

          check_disruption_budget!(budget, status, name)
          spend_disruption(namespace, budget, pod) unless dry_run
          nil
        end

        def allow_unhealthy_eviction?(pod, budget, status)
          return false if Controller::Support.ready?(pod)
          return true if budget.dig("spec", "unhealthyPodEvictionPolicy") == "AlwaysAllow"

          desired = status["desiredHealthy"].to_i
          desired.positive? && status["currentHealthy"].to_i >= desired
        end

        def check_disruption_budget!(budget, status, name)
          raise retry_disruption_budget(name) if status["observedGeneration"].to_i < budget.dig("metadata", "generation").to_i

          allowed = status["disruptionsAllowed"].to_i
          raise Status::Forbidden.new("poddisruptionbudgets.policy #{name.to_s.inspect} is forbidden: pdb disruptions allowed is negative") if allowed.negative?
          return if allowed.positive?

          message = if status["currentHealthy"].to_i <= status["desiredHealthy"].to_i
                      "The disruption budget #{name} needs #{status["desiredHealthy"].to_i} healthy pods " \
                        "and has #{status["currentHealthy"].to_i} currently"
                    else
                      "The disruption budget #{name} does not allow evicting pods currently"
                    end
          raise Status::TooManyRequests.new(
            "Cannot evict pod as it would violate the pod's disruption budget.",
            retry_after_seconds: 0,
            details: {"causes" => [{"reason" => DISRUPTION_BUDGET_CAUSE, "message" => message}]}
          )
        end

        def retry_disruption_budget(name)
          Status::TooManyRequests.new(
            "Cannot evict pod as it would violate the pod's disruption budget.",
            retry_after_seconds: 10,
            details: {"causes" => [{"reason" => DISRUPTION_BUDGET_CAUSE,
                                    "message" => "The disruption budget #{name} is still being processed by the server."}]}
          )
        end

        def disruption_budgets_for(namespace, pod)
          descriptor = disruption_budget_descriptor
          return [] if descriptor.nil?

          labels = pod.dig("metadata", "labels") || {}
          @store.list(resource: descriptor, namespace: namespace, selectors: nil).items.select { |budget| budget_selects?(budget, labels) }
        rescue MemoryStore::Error, Status::Error
          []
        end

        # A PodDisruptionBudget with an empty selector matches every Pod in its
        # namespace (apis/policy/validation: an empty LabelSelector selects all),
        # which is exactly how the conformance specs write the "block everything"
        # budget.
        def budget_selects?(budget, labels)
          selector = budget.dig("spec", "selector")
          return false if selector.nil?

          match = selector["matchLabels"] || {}
          return false unless match.all? { |key, value| labels[key.to_s].to_s == value.to_s }

          Array(selector["matchExpressions"]).all? do |expression|
            key = expression["key"].to_s
            values = Array(expression["values"]).map(&:to_s)
            LabelRequirement.matches?(expression["operator"].to_s, labels[key].to_s, values, present: labels.key?(key))
          end
        end

        # The registry's own entry, not a synthesised descriptor: StoreAdapter
        # keys storage off it and requires `selectors:`.  Passing neither raised
        # ArgumentError into the blanket rescue around the lookup, so every Pod
        # looked unprotected and eviction never respected a budget.
        def disruption_budget_descriptor
          @registry.find_gvr(group: "policy", version: "v1", resource: "poddisruptionbudgets") ||
            Controller::ResourceDescriptor.parse("PodDisruptionBudget")
        end

        def spend_disruption(namespace, budget, pod)
          descriptor = disruption_budget_descriptor
          return nil if descriptor.nil?

          # The eviction has been allowed; a budget that cannot be written
          # (it changed meanwhile, say) does not take that back.
          best_effort do
            updated = deep_copy(budget)
            status = updated["status"] ||= {}
            status["disruptionsAllowed"] = [status["disruptionsAllowed"].to_i - 1, 0].max
            disrupted = status["disruptedPods"] ||= {}
            disrupted[pod.dig("metadata", "name").to_s] = @clock.call.utc.iso8601(6)
            @store.update(resource: descriptor, namespace: namespace,
                          name: updated.dig("metadata", "name"), object: updated,
                          resource_version: metadata_value(budget, "resourceVersion"))
          end
        end

        # apimachinery field.Error rendering for a DeleteOptions issue: the
        # value is quoted like field.Error.ErrorBody and the reason follows
        # errors.NewInvalid's cause mapping.
        def delete_options_cause(options, issue)
          reason, includes_value = {
            required: ["FieldValueRequired", false], unsupported: ["FieldValueNotSupported", true],
            forbidden: ["FieldValueForbidden", false], duplicate: ["FieldValueDuplicate", true]
          }.fetch(issue.code, ["FieldValueInvalid", true])
          value = issue.path.reduce(options) { |current, segment| current.is_a?(Hash) ? current[segment.to_s] : nil }
          rendered_value = value.is_a?(String) ? value.inspect : JSON.generate(value)
          type = issue.kubernetes_error_type
          detail = issue.message.to_s
          message = includes_value ? "#{type}: #{rendered_value}" : type
          message = "#{message}: #{detail}" unless detail.empty?
          {"reason" => reason, "message" => message, "field" => issue.kubernetes_field}
        end
      end
    end
  end
end
