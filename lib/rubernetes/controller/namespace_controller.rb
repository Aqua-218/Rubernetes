# frozen_string_literal: true

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # Drives Namespace termination: delete every namespaced object first,
    # then remove the built-in "kubernetes" finalizer only after the namespace
    # snapshot is empty.  Cluster-scoped objects and the Namespace itself are
    # never treated as content.
    class NamespaceController < BaseController
      NAMESPACE = ResourceDescriptor.parse("Namespace")
      KUBERNETES_FINALIZER = "kubernetes"

      # pkg/controller/namespace/deletion/status_condition_utils.go: the
      # deleter publishes ALL of these on every pass, "False" with the ok
      # reason when that part went fine.  Clients read the presence of the
      # condition as proof the controller processed the namespace at all --
      # "[sig-api-machinery] OrderedNamespaceDeletion namespace deletion should
      # delete pod first" waits for NamespaceDeletionContentFailure before it
      # checks anything else.
      CONDITION_OK = {
        "NamespaceDeletionDiscoveryFailure" => ["ResourcesDiscovered", "All resources successfully discovered"],
        "NamespaceDeletionGVParsingFailure" => ["ParsedGroupVersions", "All legacy kube types successfully parsed"],
        "NamespaceDeletionContentFailure" => ["ContentDeleted",
                                              "All content successfully deleted, may be waiting on finalization"],
        "NamespaceContentRemaining" => ["ContentRemoved", "All content successfully removed"],
        "NamespaceFinalizersRemaining" => ["ContentHasNoFinalizers", "All content-preserving finalizers finished"]
      }.freeze

      # pkg/controller/namespace/deletion/namespaced_resources_deleter.go
      # deleteAllContent: with OrderedNamespaceDeletion every Pod goes first and
      # nothing else is touched until none remain, so a workload is never
      # stripped of the ConfigMaps and Secrets it is still running on.
      POD_KIND = "Pod"

      include SecondarySupport

      def plan(namespace, store: nil, objects: nil, **_options)
        adapter = adapter_for(store)
        observed = !objects.nil? || !adapter.nil?
        # Content is looked up inside this namespace, not by enumerating the
        # whole cluster and filtering: only namespaced kinds can hold it, and
        # a cluster-wide sweep of every kind is what made one empty-namespace
        # deletion cost hundreds of list calls.
        terminating_namespace = !Support.value(Support.metadata(namespace), "deletionTimestamp", nil).nil?
        # Only a terminating namespace needs its contents enumerated.  Reading
        # them for an Active one costs a list per namespaced kind -- over a
        # hundred of them -- on every namespace event, for an answer that is
        # never used.
        objects ||= if !terminating_namespace
                      []
                    elsif adapter.respond_to?(:namespaced_contents)
                      adapter.namespaced_contents(Support.name(namespace))
                    elsif adapter
                      adapter.all
                    else
                      []
                    end
        contents = Array(objects).select do |object|
          Support.kind(object) != "Namespace" &&
            !Support.namespace(object).nil? &&
            Support.namespace(object).to_s == Support.name(namespace).to_s
        end
        terminating = terminating_namespace
        desired_phase = terminating ? "Terminating" : "Active"
        operations = []
        pods = contents.select { |object| Support.kind(object) == POD_KIND }
        deletable = pods.empty? ? contents : pods
        if terminating
          deletable.each do |object|
            operations << operation_delete(object, descriptor: ResourceDescriptor.parse(object),
                                                   reason: "namespace content deletion")
          end
        end

        candidate = Support.deep_copy(namespace)
        candidate["status"] = Support.deep_copy(Support.status(namespace))
        candidate["status"]["phase"] = desired_phase
        if terminating && observed && contents.empty?
          candidate["spec"] = Support.deep_copy(Support.spec(namespace))
          raw_finalizers = Support.value(candidate["spec"], "finalizers", nil)
          raw_finalizers ||= Support.value(Support.metadata(namespace), "finalizers", nil)
          finalizers = Array(raw_finalizers).map(&:to_s)
          finalizers.delete(KUBERNETES_FINALIZER)
          candidate["spec"]["finalizers"] = finalizers unless raw_finalizers.nil? && finalizers.empty?
        end
        if Support.spec(namespace) != Support.spec(candidate)
          spec_candidate = Support.deep_copy(namespace)
          spec_candidate["spec"] = Support.deep_copy(candidate["spec"])
          operations << operation_update(namespace, spec_candidate, descriptor: NAMESPACE,
                                                                    reason: "namespace finalizer removal")
        end
        status = Support.deep_copy(candidate.fetch("status"))
        status["conditions"] = deletion_conditions(status["conditions"], contents) if terminating && observed
        events = if terminating && !contents.empty?
                   [{"type" => "Warning", "reason" => "NamespaceDeletionContentFailure",
                     "message" => "#{contents.length} namespaced resource(s) remain"}]
                 else
                   []
                 end
        result_for(namespace, operations, status: status, events: events)
      end

      private

      # Every condition on every pass: the failing ones carry what remains, the
      # rest carry their "ok" wording.
      def deletion_conditions(conditions, contents)
        values = conditions
        CONDITION_OK.each do |type, (reason, message)|
          values = upsert_condition(values, type, "False", reason, message)
        end
        return values if contents.empty?

        remaining = contents.group_by { |object| Support.kind(object).to_s }
          .map { |kind, items| "#{kind} has #{items.length} resource instances" }
          .sort
        values = upsert_condition(values, "NamespaceContentRemaining", "True", "SomeResourcesRemain",
                                  "Some resources are remaining: #{remaining.join(", ")}")
        finalizers = contents.flat_map { |object| Array(Support.value(Support.metadata(object), "finalizers", [])) }
          .map(&:to_s).tally
        return values if finalizers.empty?

        described = finalizers.map { |finalizer, count| "#{finalizer} in #{count} resource instances" }.sort
        upsert_condition(values, "NamespaceFinalizersRemaining", "True", "SomeFinalizersRemain",
                         "Some content in the namespace has finalizers remaining: #{described.join(", ")}")
      end

      def upsert_condition(conditions, type, condition_status, reason, message = nil)
        values = Array(conditions).map { |condition| Support.deep_copy(condition) }
        current = values.find { |condition| Support.value(condition, "type", "").to_s == type }
        if current
          current["status"] = condition_status
          current["reason"] = reason
          current["message"] = message if message
        else
          entry = {"type" => type, "status" => condition_status, "reason" => reason}
          entry["message"] = message if message
          values << entry
        end
        values
      end
    end
  end
end
