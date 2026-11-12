# frozen_string_literal: true

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

          object, node_name = binding_and_node(request, route)
          namespace = storage_namespace(route, operation: :update)
          existing = begin
            @store.get(resource: route.resource, namespace: namespace, name: route.name)
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
          end
          assigned = existing.dig("spec", "nodeName").to_s
          unless assigned.empty?
            raise Status::Conflict.new("Operation cannot be fulfilled on pods/binding #{route.name.to_s.inspect}: " \
                                       "pod #{route.name} is already assigned to node #{assigned.inspect}")
          end

          updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                  object: bound_pod(existing, object, node_name),
                                  resource_version: metadata_value(existing, "resourceVersion"))
          after_commit(route.resource, updated)
          json_response({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Success", "code" => 201},
                        status: 201)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
        end

        # The decoded Binding and the node it names, once both are well formed.
        def binding_and_node(request, route)
          body = request_body(request)
          raise Status::BadRequest.new("request body must be a JSON object") unless body.is_a?(Hash)

          object = stringify_keys(body)
          kind = object["kind"].to_s
          raise Status::BadRequest.new("expected a Binding, got #{kind.inspect}") unless kind.empty? || kind == "Binding"

          name = object.dig("metadata", "name").to_s
          raise Status::BadRequest.new("name in URL does not match name in Binding object") if !name.empty? && name != route.name.to_s

          target = object["target"]
          raise Status::BadRequest.new("target is required") unless target.is_a?(Hash)

          target_kind = target["kind"].to_s
          raise Status::BadRequest.new("target.kind #{target_kind.inspect} is not supported (expected Node)") unless target_kind.empty? || target_kind == "Node"

          node_name = target["name"].to_s
          raise Status::BadRequest.new("target.name is required") if node_name.empty?

          [object, node_name]
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

          delete_options = eviction_delete_options(request, route)
          namespace = storage_namespace(route, operation: :delete)
          existing = begin
            @store.get(resource: route.resource, namespace: namespace, name: route.name)
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
          end
          # An Eviction is checked against every PodDisruptionBudget that selects
          # the Pod: a budget with no disruptions left refuses it with 429
          # (pkg/registry/core/pod/storage/eviction.go:418-457), and a successful
          # eviction spends one disruption.  None of that existed, so eviction
          # was an unconditional delete and
          # "[sig-apps] DisruptionController should block an eviction until the
          # PDB is updated to allow it" could never pass.
          dry_run = delete_options.is_a?(Hash) && !Array(delete_options["dryRun"]).empty?
          check_disruption_budgets!(namespace, existing, dry_run: dry_run)
          caller_version = eviction_precondition!(delete_options, existing)
          existing = mark_evicted(route.resource, namespace, route.name, existing) unless dry_run
          delete_evicted_pod(route, namespace, existing, delete_options, pin_version: !caller_version.nil?)
          json_response({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Success", "code" => 201}, status: 201)
        end

        # The deleteOptions of a well-formed Eviction (nil when it has none),
        # once they validate.
        def eviction_delete_options(request, route)
          body = request_body(request)
          raise Status::BadRequest.new("request body must be a JSON object") unless body.is_a?(Hash)

          object = stringify_keys(body)
          kind = object["kind"].to_s
          raise Status::BadRequest.new("expected an Eviction, got #{kind.inspect}") unless kind.empty? || kind == "Eviction"

          name = object.dig("metadata", "name").to_s
          raise Status::BadRequest.new("name in URL does not match name in Eviction object") if !name.empty? && name != route.name.to_s

          delete_options = object["deleteOptions"]
          return delete_options unless delete_options.is_a?(Hash)

          issues = Schema::KubernetesValidator.delete_options_errors(delete_options)
          return delete_options if issues.empty?

          causes = issues.map { |issue| delete_options_cause(delete_options, issue) }
          rendered = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }
          summary = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
          raise Status::Invalid.new("DeleteOptions.meta.k8s.io \"\" is invalid: #{summary}",
                                    details: {"group" => "meta.k8s.io", "kind" => "DeleteOptions", "causes" => causes})
        end

        # eviction.go addConditionAndDeletePod: a resourceVersion precondition
        # the CALLER set is checked against the Pod before the DisruptionTarget
        # condition is written and then moved to the version that write
        # produced; an eviction without one pins nothing.  Pinning the delete
        # to our own condition write's version instead made any writer that
        # slipped in between (the node publishing status for the Pod it had
        # just seen change) fail the eviction with "expected resourceVersion
        # N, current is N+1" ("DisruptionController should block an eviction
        # until the PDB is updated to allow it").
        #
        # Returns the caller's precondition, nil when there is none.
        def eviction_precondition!(delete_options, existing)
          caller_version = delete_options.is_a?(Hash) ? delete_options.dig("preconditions", "resourceVersion") : nil
          if caller_version && caller_version.to_s != metadata_value(existing, "resourceVersion").to_s
            raise Status::Conflict.new("the ResourceVersion in the precondition (#{caller_version}) does not match the ResourceVersion in record " \
                                       "(#{metadata_value(existing, "resourceVersion")}). The object might have been modified")
          end

          caller_version
        end

        # An Eviction without deleteOptions deletes the Pod outright; with
        # them, their propagation policy applies unless they ask for a dry run.
        def delete_evicted_pod(route, namespace, existing, delete_options, pin_version:)
          if delete_options.is_a?(Hash) && Array(delete_options["dryRun"]).empty?
            if orphan_deletion?(delete_options)
              orphan_dependents(route.resource, namespace, existing)
            else
              cascade_delete_dependents(existing)
            end
            delete_one(route.resource, namespace, route.name, existing, pin_version: pin_version)
          elsif !delete_options.is_a?(Hash)
            delete_one(route.resource, namespace, route.name, existing, pin_version: false)
          end
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
          budgets = disruption_budgets_for(namespace, pod)
          return if budgets.empty?

          budgets.each do |budget|
            status = budget["status"] || {}
            name = budget.dig("metadata", "name")
            # eviction.go checkAndDecrement: only a budget the controller has
            # not caught up with yet carries a retry hint.  A budget that simply
            # allows no disruption answers 429 with retryAfterSeconds 0: client-go
            # retries a 429 that has Retry-After on its own, ten times, so the
            # 10 s hint we sent made every refused eviction take 100 s
            # ("DisruptionController should block an eviction until the PDB is
            # updated to allow it": 209 s against kube-apiserver's 8 s).
            if status["observedGeneration"].to_i < budget.dig("metadata", "generation").to_i
              raise Status::TooManyRequests.new(
                "Cannot evict pod as it would violate the pod's disruption budget.",
                retry_after_seconds: 10,
                details: {"causes" => [{"reason" => DISRUPTION_BUDGET_CAUSE,
                                        "message" => "The disruption budget #{name} is still being processed by the server."}]}
              )
            end
            allowed = status["disruptionsAllowed"].to_i
            if allowed.negative?
              raise Status::Forbidden.new("poddisruptionbudgets.policy #{name.to_s.inspect} is forbidden: pdb disruptions allowed is negative")
            end
            next if allowed.positive?

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
          return if dry_run

          budgets.each { |budget| spend_disruption(namespace, budget, pod) }
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
            present = labels.key?(key)
            case expression["operator"].to_s
            when "In" then present && values.include?(labels[key].to_s)
            when "NotIn" then !present || !values.include?(labels[key].to_s)
            when "Exists" then present
            when "DoesNotExist" then !present
            else false
            end
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
