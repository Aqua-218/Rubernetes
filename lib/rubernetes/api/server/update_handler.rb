# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # PUT of a resource: optimistic concurrency and the unconditional-update
      # retry, the no-op check, and the registry strategies' PrepareForUpdate hooks.
      module UpdateHandler
        private

        # storage.Interface#GuaranteedUpdate re-reads and re-applies an
        # UNCONDITIONAL update when the object moved between the read and the
        # write; only a caller-supplied resourceVersion turns that race into a
        # 409.  Without the retry a client PUT racing a controller -- the root
        # CA publisher refilling kube-root-ca.crt -- failed with "changed during
        # update" where kube-apiserver just succeeds.
        MAX_UNCONDITIONAL_UPDATE_ATTEMPTS = 8

        def update_response(request, route)
          attempts = 0
          begin
            attempts += 1
            update_response_once(request, route, retry_conflicts: attempts < MAX_UNCONDITIONAL_UPDATE_ATTEMPTS)
          rescue UnconditionalUpdateConflict
            retry
          end
        end

        class UnconditionalUpdateConflict < StandardError; end

        # managedFields take part: an update that changes nothing keeps them as
        # they were (ManagedFields::FieldManager), and one that only strips them
        # (managedFields: [{}]) is a real write, as it is upstream.
        NOOP_IGNORED_METADATA = %w[resourceVersion].freeze

        def noop_update?(object, existing)
          return false unless object.is_a?(Hash) && existing.is_a?(Hash)

          # Stored metav1.Time fields are second precision, so an update carrying
          # the same instants with sub-second digits (the node agent stamps
          # status that way) is still no change.  Comparing the raw strings made
          # every such status sync a real write.
          # The stored object was truncated on its way in (StoreAdapter
          # #convert_in), so only the submitted one needs it; truncate_times
          # never mutates its argument, so neither side is copied.
          strip = lambda do |value|
            metadata = value["metadata"]
            return value unless metadata.is_a?(Hash)

            value.merge("metadata" => metadata.except(*NOOP_IGNORED_METADATA))
          end
          # An object that cannot be compared is written like any other change.
          best_effort { strip.call(StoreAdapter.time_codec.truncate_times(object)) == strip.call(existing) } || false
        end

        def update_response_once(request, route, retry_conflicts: false)
          namespace = storage_namespace(route, operation: :update)
          validate_write_options!(request, "UpdateOptions")
          if route.subresource == "scale"
            existing = @store.get(resource: route.resource, namespace: namespace, name: route.name)
            return scale_update_response(request, route, existing, namespace, request_body(request))
          end

          object = phase("update.normalize") { normalize_object(request, route) }
          existing, cached = read_for_update(route, namespace, object)
          ensure_name!(object, route.name)
          expected = metadata_value(object, "resourceVersion")
          unconditional = expected.to_s.empty?
          refuse_unconditional_update!(route) if unconditional
          # Strategy.AllowCreateOnUpdate: a PUT to an object that does not exist
          # CREATES it for the kinds whose strategy says so (Lease,
          # LeaseCandidate, Endpoints, Event, LimitRange, Service).  Answering
          # 404 for those made a client that PUTs its own object -- which is how
          # leases and endpoints are written -- fail against us and work
          # everywhere else.
          return create_response(request, route) if existing.nil? && allow_create_on_update?(route.resource)

          ensure_update_target!(route, existing, expected, unconditional)
          object = preserve_metadata(object, existing)
          unknown_mode = enforce_field_validation(route.resource, object, request,
                                                  duplicates: request_duplicate_fields(request))
          object = apply_subresource_strategy(route, existing, object)
          object = admitted_for_update(request, route, existing, object, namespace, unknown_mode)
          return json_response(written_view(route, dry_run_view(object, namespace))) if dry_run?(request)

          # Truncated once: the no-op check compares it, and the store takes it
          # as is instead of truncating it again in convert_in.
          object = StoreAdapter.time_codec.truncated_frozen(object) if object.is_a?(Hash)
          return json_response(written_view(route, existing)) if unchanged_update?(request, object, existing)

          resource_version = unconditional ? metadata_value(existing, "resourceVersion") : expected
          updated = store_update(route, namespace, object, resource_version, cached: cached)
          after_commit(route.resource, updated) if route.subresource.nil?
          finalize_object_removal(route.resource, namespace, updated)
          phase("update.respond") { json_response(written_view(route, updated)) }
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                     details: resource_details(route))
        rescue MemoryStore::Conflict
          raise UnconditionalUpdateConflict if retry_conflicts && unconditional

          raise Status::Conflict.new("#{route.resource.kind} #{route.name.inspect} changed during update",
                                     details: resource_details(route))
        end

        # GuaranteedUpdate with cachedExistingObject: an update that names the
        # resourceVersion it read starts from this replica's copy, without a
        # linearizable read.  The write proposes that version and the state
        # machine refuses it if the object moved on, so a stale copy costs a
        # 409 the client would have got anyway -- never a lost update.  A copy
        # that does not match (or is missing) may just be behind: read again
        # through the barrier before judging.
        #
        # Returns the stored object and whether it came from the cached read.
        def read_for_update(route, namespace, object)
          hinted = metadata_value(object, "resourceVersion").to_s
          cached = false
          unless hinted.empty?
            existing = cached_store_read { @store.get(resource: route.resource, namespace: namespace, name: route.name) }
            cached = existing.is_a?(Hash) && metadata_value(existing, "resourceVersion").to_s == hinted
          end
          existing = @store.get(resource: route.resource, namespace: namespace, name: route.name) unless cached
          [existing, cached]
        end

        # Strategy.AllowUnconditionalUpdate() == false: these kinds refuse an
        # update that carries no resourceVersion, exactly as a CRD does
        # (pkg/registry/*/*/strategy.go).  Accepting one let a client
        # last-write-wins over a Lease, a PDB or a webhook configuration that
        # upstream would have rejected.
        def refuse_unconditional_update!(route)
          return unless strict_update?(route.resource)

          raise Status::Invalid.new("#{route.resource.resource} #{route.name.inspect} is invalid: metadata.resourceVersion: Invalid value: 0x0: must be " \
                                    "specified for an update",
                                    details: resource_details(route))
        end

        # registry.Store#Update: an object submitted without a resourceVersion
        # is an *unconditional* update wherever the strategy allows one, which
        # every built-in kind does.  Upstream's own conformance tests rely on
        # it -- "should update ConfigMap successfully" updates the object it
        # built locally, never having read the one the server stored -- so
        # rejecting it fails the spec outright.  A resourceVersion that *is*
        # present is still enforced as an optimistic-concurrency precondition.
        def ensure_update_target!(route, existing, expected, unconditional)
          if unconditional && existing.nil?
            raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                       details: resource_details(route))
          end
          ensure_expected_version!(existing, expected) unless unconditional
        end

        # The object as it will be stored: checked against its schema, given
        # the registry's PrepareForUpdate, passed through mutating admission,
        # validated, passed through validating admission, with its generation.
        def admitted_for_update(request, route, existing, object, namespace, unknown_mode)
          object = phase("update.schema") do
            apply_schema(route.resource, object, operation: :update, old: existing, subresource: route.subresource,
                                                 unknown_fields: unknown_mode)
          end
          object = prepare_registry_update(route.resource, existing, object) if route.subresource.nil?
          object = before_mutation = with_managed_fields(object, record_managed_update(request, route, existing, object))
          object = admit_mutating(request, route, "UPDATE", object, existing, namespace)
          object = redefault_after_mutation(route.resource, object, before_mutation, unknown_fields: unknown_mode)
          authorize_resource_claim_status!(request, route, existing, object)
          phase("update.validate") { validate_object!(route.resource, object, old: existing) } unless route.subresource == "status"
          admit_validating(request, route, "UPDATE", object, existing, namespace)
          apply_generation(object, existing, subresource: route.subresource, resource: route.resource)
        end

        # etcd3 GuaranteedUpdate skips the write when the encoded object is
        # unchanged: a PUT that changes nothing leaves the resourceVersion
        # alone.  Bumping it made every controller resync (EndpointSlices
        # every few seconds) a new revision, which every other writer of the
        # object then lost a 409 to.
        def unchanged_update?(request, object, existing)
          comparison_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          unchanged = phase("update.noop_check") { noop_update?(object, existing) }
          # apiserver_request_timestamp_comparison_time{code_path}: the old vs
          # new comparison (time fields normalised) of an UPDATE or PATCH.
          @metrics&.observe("apiserver_request_timestamp_comparison_time", Process.clock_gettime(Process::CLOCK_MONOTONIC) - comparison_started,
                            {"code_path" => request.method.to_s == "PATCH" ? "patch" : "update"})
          unchanged
        end

        # An update that started from the cached copy proposes through the
        # same cached path (see read_for_update).
        def store_update(route, namespace, object, resource_version, cached:)
          write = lambda do
            @store.update(resource: route.resource, namespace: namespace, name: route.name,
                          object: object, resource_version: resource_version)
          end
          cached ? cached_store_read(&write) : write.call
        end

        def preserve_metadata(object, existing)
          # Only metadata changes here: copy it and the top level, and share
          # the rest -- the request's object was already copied into string
          # keys by normalize_object and the caller drops it.
          result = object.transform_keys(&:to_s)
          result["metadata"] = result["metadata"].is_a?(Hash) ? result["metadata"].transform_keys(&:to_s) : {}
          existing_metadata = existing["metadata"] || {}
          # ValidateObjectMetaUpdate treats these as immutable; upstream's
          # registry preserves them from the stored object rather than taking
          # whatever the client sent.  deletionGracePeriodSeconds belongs to the
          # same set -- a client must not be able to shorten or clear the grace
          # period the API server granted.
          %w[uid creationTimestamp deletionTimestamp deletionGracePeriodSeconds].each do |key|
            if existing_metadata.key?(key)
              result["metadata"][key] = deep_copy(existing_metadata[key])
            else
              result["metadata"].delete(key)
            end
          end
          # generation never goes backwards.
          if existing_metadata.key?("generation") && result["metadata"]["generation"].to_i < existing_metadata["generation"].to_i
            result["metadata"]["generation"] = existing_metadata["generation"]
          end
          result["metadata"]["namespace"] = existing_metadata["namespace"] if existing_metadata.key?("namespace")
          result
        end

        # PrepareForUpdate hooks of the registry strategies that own
        # allocations (Service ClusterIPs and NodePorts follow type changes).
        def prepare_registry_update(resource, existing, object)
          object = drop_stateful_set_disabled_fields(resource, object, existing)
          if csr_resource?(resource) && existing.is_a?(Hash) && object.is_a?(Hash)
            # csrStrategy.PrepareForUpdate: a request is immutable except
            # through its /status and /approval subresources.
            result = deep_copy(object)
            existing.key?("spec") ? result["spec"] = deep_copy(existing["spec"]) : result.delete("spec")
            existing.key?("status") ? result["status"] = deep_copy(existing["status"]) : result.delete("status")
            return result
          end
          return object unless @service_allocator && @service_allocator.service?(resource)

          @service_allocator.prepare_update(existing, object)
        end

        # pkg/registry/*/*/strategy.go AllowCreateOnUpdate() == true.
        ALLOW_CREATE_ON_UPDATE = [["coordination.k8s.io", "v1", "leases"],
                                  ["coordination.k8s.io", "v1beta1", "leases"],
                                  ["coordination.k8s.io", "v1alpha2", "leasecandidates"],
                                  ["coordination.k8s.io", "v1beta1", "leasecandidates"],
                                  ["", "v1", "endpoints"],
                                  ["", "v1", "events"],
                                  ["events.k8s.io", "v1", "events"],
                                  ["", "v1", "limitranges"],
                                  ["", "v1", "services"]].freeze

        # Strategy.AllowUnconditionalUpdate() == false.
        STRICT_UPDATE_RESOURCES = [
          ["admissionregistration.k8s.io", "mutatingwebhookconfigurations"],
          ["admissionregistration.k8s.io", "validatingwebhookconfigurations"],
          ["admissionregistration.k8s.io", "validatingadmissionpolicies"],
          ["admissionregistration.k8s.io", "validatingadmissionpolicybindings"],
          ["admissionregistration.k8s.io", "mutatingadmissionpolicies"],
          ["admissionregistration.k8s.io", "mutatingadmissionpolicybindings"],
          ["internal.apiserver.k8s.io", "storageversions"],
          ["certificates.k8s.io", "clustertrustbundles"],
          ["certificates.k8s.io", "podcertificaterequests"],
          ["coordination.k8s.io", "leases"],
          ["coordination.k8s.io", "leasecandidates"],
          ["node.k8s.io", "runtimeclasses"],
          ["policy", "poddisruptionbudgets"],
          ["storage.k8s.io", "csidrivers"],
          ["storage.k8s.io", "csinodes"],
          ["storage.k8s.io", "csistoragecapacities"],
          ["storage.k8s.io", "volumeattachments"],
          ["storagemigration.k8s.io", "storageversionmigrations"]
        ].freeze

        def strict_update?(resource)
          return false if resource.nil?
          return true if resource.custom?

          STRICT_UPDATE_RESOURCES.include?([resource.group.to_s, resource.resource.to_s])
        end

        def allow_create_on_update?(resource)
          return false if resource.nil?
          return false if resource.custom?

          ALLOW_CREATE_ON_UPDATE.include?(resource_triple(resource))
        end

        # statefulset strategy dropStatefulSetDisabledFields: with
        # MaxUnavailableStatefulSet off (Beta, off by default) a new
        # rollingUpdate.maxUnavailable is dropped unless the old object used it.
        def drop_stateful_set_disabled_fields(resource, object, existing)
          return object unless resource.kind == "StatefulSet" && resource.group.to_s == "apps"
          return object if feature_gate_enabled?("MaxUnavailableStatefulSet")
          return object unless object.is_a?(Hash) && !object.dig("spec", "updateStrategy", "rollingUpdate", "maxUnavailable").nil?
          return object if existing.is_a?(Hash) && !existing.dig("spec", "updateStrategy", "rollingUpdate", "maxUnavailable").nil?

          result = deep_copy(object)
          result["spec"]["updateStrategy"]["rollingUpdate"].delete("maxUnavailable")
          result
        end
      end
    end
  end
end
