# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class StatefulSetController < WorkloadController
        private

        def revision_data_for(resource)
          template_value = revision_template_value(Support.value(Support.spec(resource), "template", {}))
          template_value["$patch"] = "replace" if template_value.is_a?(Hash)
          {"spec" => {"template" => template_value}}
        end

        # Kubernetes serializes a typed PodTemplate into the revision patch.
        # Null fields such as ObjectMeta.annotations and Container.env are
        # omitted from that projection, even if a chart rendered them.
        def revision_template_value(value)
          case value
          when Hash
            value.compact.transform_values { |child| revision_template_value(child) }
          when Array
            value.map { |child| revision_template_value(child) }
          else
            Support.deep_copy(value)
          end
        end

        # getStatefulSetRevisions + truncateHistory.
        def reconcile_revisions(owner, revisions, pods, collision_count)
          data = revision_data_for(owner)
          if revisions.nil?
            update = revision_for(owner, data, Support.controller_revision_hash(data, collision_count), 1)
            return {current: update, update: update, operations: [], collision_count: collision_count}
          end

          owned_revisions = Array(revisions).select do |revision|
            next false unless Support.kind(revision) == "ControllerRevision"
            next true if Support.owner_reference_matches?(owner, revision, controller: true)

            Support.namespace(revision) == Support.namespace(owner) &&
              Support.name(revision).start_with?("#{Support.name(owner)}-")
          end.sort_by { |revision| [revision_number(revision), Support.creation_time(revision).to_f, Support.name(revision)] }
          next_number = owned_revisions.empty? ? 1 : revision_number(owned_revisions.last) + 1
          operations = []
          equivalent = owned_revisions.select { |revision| revision_data_equal?(revision, data) }
          if equivalent.any? && Support.name(equivalent.last) == Support.name(owned_revisions.last)
            update_revision = owned_revisions.last
          elsif equivalent.any?
            # Rolling back: the equivalent revision becomes the newest one.
            update_revision = Support.deep_copy(equivalent.last)
            update_revision["revision"] = next_number
            operations << operation_update(equivalent.last, update_revision, descriptor: CONTROLLER_REVISION,
                                                                             reason: "statefulset controller revision rollback")
          elsif owned_revisions.any? && set_matches_latest_revision?(owner, data, owned_revisions.last)
            # StatefulSetSemanticRevisionComparison: the latest revision, once
            # restored and defaulted, is this spec -- only its stored form
            # differs (a field defaulted since it was written).
            update_revision = owned_revisions.last
          else
            loop do
              hash = Support.controller_revision_hash(data, collision_count)
              update_revision = revision_for(owner, data, hash, next_number)
              colliding = owned_revisions.find { |revision| Support.name(revision) == Support.name(update_revision) }
              break if colliding.nil?

              # Name collision with different content: bump the probe, as
              # history.CreateControllerRevision does.
              collision_count += 1
            end
            operations << operation_create(update_revision, descriptor: CONTROLLER_REVISION, owner: owner,
                                                            reason: "statefulset controller revision")
            owned_revisions << update_revision
          end

          current_name = Support.value(Support.status(owner), "currentRevision", nil).to_s
          current = owned_revisions.find { |revision| Support.name(revision) == current_name } || update_revision
          history_limit = Support.integer(Support.value(Support.spec(owner), "revisionHistoryLimit", 10), 10)
          live = [Support.name(current), Support.name(update_revision)] + pods.map { |pod| Support.labels(pod)[REVISION_LABEL].to_s }
          history = owned_revisions.reject { |revision| live.include?(Support.name(revision)) }
          if history_limit >= 0 && history.length > history_limit
            history.first(history.length - history_limit).each do |revision|
              operations << operation_delete(revision, descriptor: CONTROLLER_REVISION, reason: "statefulset revision history limit")
            end
          end
          {current: current, update: update_revision, operations: operations, collision_count: collision_count}
        end

        # setMatchesLatestExistingRevision (StatefulSetSemanticRevisionComparison,
        # Beta on): would restoring +latest+ into the set, with defaults
        # applied, produce +data+?  A positive answer is remembered per set
        # UID, generation and revision resourceVersion.
        REVISION_EQUALITY_CACHE_SIZE = 10_000

        def set_matches_latest_revision?(owner, data, latest)
          key = [Support.uid(owner), Support.value(Support.metadata(owner), "generation", nil),
                 Support.value(Support.metadata(latest), "resourceVersion", nil)]
          @revision_equality ||= {}
          return true if @revision_equality.key?(key)

          restored = default_stateful_set(apply_revision(owner, latest))
          return false unless Support.canonical(revision_data_for(restored)) == Support.canonical(data)

          @revision_equality.delete(@revision_equality.keys.first) while @revision_equality.size >= REVISION_EQUALITY_CACHE_SIZE
          @revision_equality[key] = true
          true
        end

        # legacyscheme.Scheme.Default for apps/v1 StatefulSet.
        def default_stateful_set(object)
          definition = stateful_set_definition
          return object unless definition

          Support.deep_copy(definition.defaulting.apply_hash(object, kubernetes_admission_defaults: true))
        rescue StandardError
          # An object the schema cannot default is compared as it stands.
          object
        end

        # The generated apps/v1 StatefulSet schema; false where the generated
        # types are not installed.
        def stateful_set_definition
          @stateful_set_definition ||= begin
            require File.expand_path("../../../../generated/ruby/kubernetes_types", __dir__)
            Rubernetes::Generated.definition_for("io.k8s.api.apps.v1.StatefulSet")
          rescue LoadError
            false
          end
        end

        # history.NewControllerRevision with the StatefulSet annotations copied.
        def revision_for(owner, data, revision_hash, number)
          template_labels = Support.value(Support.value(Support.value(data, "spec", {}), "template", {}), "metadata", {})
          template_labels = Support.value(template_labels, "labels", {})
          template_labels = {} unless template_labels.is_a?(Hash)
          revision = {
            "apiVersion" => "apps/v1", "kind" => "ControllerRevision",
            "metadata" => {"name" => "#{Support.name(owner)}-#{revision_hash}",
                           "namespace" => Support.namespace(owner),
                           "labels" => Support.deep_copy(template_labels).merge("controller.kubernetes.io/hash" => revision_hash),
                           "ownerReferences" => [Support.owner_reference(owner)]},
            "revision" => number,
            "data" => Support.deep_copy(data)
          }
          annotations = Support.annotations(owner)
          revision["metadata"]["annotations"] = Support.deep_copy(annotations) unless annotations.empty?
          revision
        end

        def revision_data_equal?(revision, data)
          Support.canonical(revision_data(revision)) == Support.canonical(data)
        end

        def revision_data(revision)
          raw = Support.value(revision, "data", nil)
          raw = JSON.parse(raw) if raw.is_a?(String)
          return raw if raw.is_a?(Hash)

          spec = Support.value(revision, "spec", nil)
          spec.is_a?(Hash) ? {"spec" => Support.deep_copy(spec)} : {}
        rescue JSON::ParserError
          {}
        end

        def revision_number(revision)
          Support.integer(Support.value(revision, "revision", nil),
                          Support.integer(Support.annotations(revision)["controller.kubernetes.io/revision"], 0))
        end

        def find_revision(revisions, revision)
          text = revision.to_s
          Array(revisions).select { |candidate| Support.kind(candidate) == "ControllerRevision" }.find do |candidate|
            Support.name(candidate) == text || revision_number(candidate).to_s == text ||
              Support.labels(candidate)[REVISION_LABEL].to_s == text ||
              Support.name(candidate).end_with?("-#{text}")
          end
        end

        def apply_revision(resource, revision)
          data = revision_data(revision)
          revision_spec = Support.value(data, "spec", data)
          return Support.deep_copy(resource) unless revision_spec.is_a?(Hash)

          candidate = Support.deep_copy(resource)
          candidate["spec"] ||= {}
          %w[template updateStrategy podManagementPolicy ordinals volumeClaimTemplates].each do |field|
            next unless revision_spec.key?(field)

            candidate["spec"][field] = Support.deep_copy(revision_spec[field])
          end
          candidate
        end

        def apply_rollback_annotation(resource, revisions)
          annotation = Support.annotations(resource)["statefulset.kubernetes.io/rollback-to"]
          return resource if annotation.to_s.empty? || revisions.nil?

          revision = find_revision(revisions, annotation)
          raise ArgumentError, "StatefulSet revision #{annotation.inspect} was not found" unless revision

          candidate = apply_revision(resource, revision)
          candidate["metadata"] ||= {}
          candidate["metadata"]["annotations"] = Support.annotations(candidate).dup
          candidate["metadata"]["annotations"].delete("statefulset.kubernetes.io/rollback-to")
          candidate
        end
      end
    end
  end
end
