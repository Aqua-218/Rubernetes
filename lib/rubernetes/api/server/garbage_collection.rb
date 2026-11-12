# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The propagation policy of a delete, applied synchronously: cascading to
      # dependents, or orphaning them.
      module GarbageCollection
        # Kinds that can own dependents; a leaf delete (Pod, ConfigMap) skips the
        # dependent scan entirely.
        CASCADE_OWNER_KINDS = %w[Deployment ReplicaSet ReplicationController StatefulSet DaemonSet Job CronJob].freeze

        private

        # kubectl's default is --cascade=background: dependents go too, unless
        # propagationPolicy is Orphan (then their owner reference is stripped).
        #
        # Returns the owner as marking it left it, the resourceVersion its
        # removal is pinned to, and whether it now waits for the garbage
        # collector (a foreground deletion) instead of being removed.
        def propagate_deletion(route, namespace, existing, expected, delete_options)
          if garbage_collection_unsupported?(route.resource)
            [existing, expected, false]
          elsif orphan_deletion?(delete_options, route.resource)
            orphan_before_deletion(route, namespace, existing, expected)
          else
            cascade_before_deletion(route, namespace, existing, expected, delete_options)
          end
        end

        # Upstream marks the owner as being deleted (deletionTimestamp plus
        # the orphan finalizer) BEFORE its dependents are released, so a
        # controller that sees a released Pod matching its selector does a
        # fresh read, finds its owner going away, and refuses to adopt it
        # back.  Releasing the dependents of a still-live owner raced that
        # guard: the ReplicationController re-adopted its own orphaned Pods,
        # was deleted, and the garbage collector then removed every Pod it
        # had just re-adopted -- "[sig-api-machinery] Garbage collector
        # should orphan pods created by rc if delete options say so" kept 0
        # of 100.  The resourceVersion precondition was already checked
        # before, so the final delete no longer pins the version this mark
        # moved.
        def orphan_before_deletion(route, namespace, existing, expected)
          existing = mark_owner_deleting(route, namespace, existing)
          expected = repin_after_mark(expected, existing)
          orphan_dependents(route.resource, namespace, existing)
          [existing, expected, false]
        end

        # Same reason as the orphan branch: the owner is marked as being
        # deleted before its dependents go, so its own controller stops
        # replacing them.  Deleting the Pods of a still-live
        # ReplicationController let it create new ones in the window before
        # it was removed, and those outlived it -- "[sig-api-machinery]
        # Garbage collector should keep the rc around until all its pods are
        # deleted if the deleteOptions says so" found Pods left after the rc.
        #
        # Foreground (registry/generic/registry/store.go
        # deletionFinalizersForGarbageCollection): the owner keeps the
        # foregroundDeletion finalizer and stays readable until the garbage
        # collector has seen every dependent gone, and only then is it
        # removed.  Removing it right after the synchronous cascade let a
        # creation batch its controller had already started land Pods after
        # the cascade had listed them; "[sig-api-machinery] Garbage
        # collector should keep the rc around until all its pods are deleted
        # if the deleteOptions says so" found them outliving the rc.
        def cascade_before_deletion(route, namespace, existing, expected, delete_options)
          owner = CASCADE_OWNER_KINDS.include?(route.resource.kind.to_s)
          foreground = foreground_deletion?(delete_options) && owner
          if owner
            existing = mark_owner_deleting(route, namespace, existing, finalizer: foreground ? FOREGROUND_FINALIZER : nil)
            expected = repin_after_mark(expected, existing)
          end
          cascade_delete_dependents(existing, owner_kind: route.resource.kind)
          [existing, expected, foreground && Array(metadata_value(existing, "finalizers")).include?(FOREGROUND_FINALIZER)]
        end

        # Finalizers only the owning controller ever removes.  Once the owner is
        # deleted nothing can clear them, so a cascaded dependent would hang in
        # Terminating forever (the Job spec's "there are N pods left").
        OWNER_MANAGED_FINALIZERS = {"Job" => %w[batch.kubernetes.io/job-tracking]}.freeze

        def cascade_delete_dependents(owner, visited: {}, owner_kind: nil)
          uid = metadata_value(owner, "uid").to_s
          return if uid.empty? || visited[uid]

          kind = (owner_kind || owner["kind"]).to_s
          return unless visited.any? || CASCADE_OWNER_KINDS.include?(kind)

          visited[uid] = true
          namespace = metadata_value(owner, "namespace")
          ORPHAN_DEPENDENT_RESOURCES.each do |group, version, plural|
            descriptor = @registry.find_gvr(group: group, version: version, resource: plural)
            next if descriptor.nil?

            listing = @store.list(resource: descriptor, namespace: descriptor.namespaced? ? namespace : nil, selectors: nil)
            listing.items.each do |item|
              references = Array(item.dig("metadata", "ownerReferences"))
              next unless references.any? { |reference| reference["uid"].to_s == uid }

              # garbagecollector.go attemptToDeleteItem: a dependent that still
              # has an owner which is not going away is not deleted; only the
              # reference to this owner is removed.  Deleting it anyway took the
              # Pods "[sig-api-machinery] Garbage collector should not delete
              # dependents that have both valid owner and owner that's waiting
              # for dependents to be deleted" gives a second owner (2 of 50 left).
              if other_live_owner?(item, uid, namespace)
                best_effort { release_dependent(descriptor, item, uid) }
                next
              end

              cascade_delete_dependents(item, visited: visited)
              item = release_owner_finalizers(descriptor, item, kind)
              # One dependent that cannot be deleted does not stop the others.
              best_effort { delete_one(descriptor, item.dig("metadata", "namespace"), item.dig("metadata", "name"), item) }
            end
          rescue StandardError
            next
          end
        end

        def other_live_owner?(item, uid, namespace)
          Array(item.dig("metadata", "ownerReferences")).any? do |reference|
            # An owner that cannot be looked up is not known to be alive.
            best_effort { live_owner_other_than?(reference, uid, namespace) } || false
          end
        end

        def live_owner_other_than?(reference, uid, namespace)
          return false if reference["uid"].to_s == uid

          api_version = reference["apiVersion"].to_s
          group, version = api_version.include?("/") ? api_version.split("/", 2) : ["", api_version]
          resource = @registry.find_gvk(group: group, version: version, kind: reference["kind"].to_s)
          return false if resource.nil?

          owner = begin
            @store.get(resource: resource, namespace: resource.namespaced? ? namespace : nil, name: reference["name"].to_s)
          rescue MemoryStore::NotFound
            nil
          end
          owner && metadata_value(owner, "uid").to_s == reference["uid"].to_s && metadata_value(owner, "deletionTimestamp").nil?
        end

        def release_dependent(descriptor, item, uid)
          ORPHAN_CONFLICT_ATTEMPTS.times do
            updated = deep_copy(item)
            updated["metadata"]["ownerReferences"] = Array(updated["metadata"]["ownerReferences"]).reject do |reference|
              reference["uid"].to_s == uid
            end
            @store.update(resource: descriptor, namespace: item.dig("metadata", "namespace"), name: item.dig("metadata", "name"),
                          object: updated, resource_version: metadata_value(item, "resourceVersion"))
            return
          rescue MemoryStore::Conflict
            item = @store.get(resource: descriptor, namespace: item.dig("metadata", "namespace"), name: item.dig("metadata", "name"))
            return unless Array(item.dig("metadata", "ownerReferences")).any? { |reference| reference["uid"].to_s == uid }
          end
        end

        def release_owner_finalizers(descriptor, item, owner_kind)
          managed = OWNER_MANAGED_FINALIZERS[owner_kind.to_s]
          return item if managed.nil?

          finalizers = Array(item.dig("metadata", "finalizers"))
          remaining = finalizers - managed
          return item if remaining.length == finalizers.length

          updated = deep_copy(item)
          if remaining.empty?
            updated["metadata"].delete("finalizers")
          else
            updated["metadata"]["finalizers"] = remaining
          end
          @store.update(resource: descriptor, namespace: item.dig("metadata", "namespace"),
                        name: item.dig("metadata", "name"), object: updated,
                        resource_version: metadata_value(item, "resourceVersion"))
        rescue StandardError
          item
        end

        # Strategy.DefaultGarbageCollectionPolicy: when the client sends no
        # propagation policy the RESOURCE decides, and for backwards
        # compatibility core/v1 ReplicationController and batch/v1 Job default to
        # ORPHANING their dependents rather than deleting them
        # (pkg/registry/core/replicationcontroller/strategy.go,
        # pkg/registry/batch/job/strategy.go).  Events support no cascade at all.
        # Defaulting everything to cascade deleted Pods that upstream keeps.
        DEFAULT_ORPHAN_DEPENDENTS = [["", "v1", "replicationcontrollers"],
                                     ["batch", "v1", "jobs"],
                                     ["batch", "v1", "cronjobs"]].freeze

        GARBAGE_COLLECTION_UNSUPPORTED = [["", "v1", "events"],
                                          ["events.k8s.io", "v1", "events"]].freeze

        def foreground_deletion?(delete_options)
          delete_options["propagationPolicy"].to_s == "Foreground"
        end

        def orphan_deletion?(delete_options, resource = nil)
          policy = delete_options["propagationPolicy"].to_s
          return true if policy == "Orphan" || delete_options["orphanDependents"] == true
          return false unless policy.empty? && delete_options["orphanDependents"].nil?
          return false if resource.nil?

          DEFAULT_ORPHAN_DEPENDENTS.include?(resource_triple(resource))
        end

        def garbage_collection_unsupported?(resource)
          return false if resource.nil?

          GARBAGE_COLLECTION_UNSUPPORTED.include?(resource_triple(resource))
        end

        # Garbage collector "orphan" finalizer, applied synchronously: every
        # dependent that names this object as an owner loses that reference
        # and lives on (the GC spec deletes a Deployment with
        # propagationPolicy=Orphan and expects its ReplicaSet to stay, unowned).
        ORPHAN_DEPENDENT_RESOURCES = [["", "v1", "pods"], ["apps", "v1", "replicasets"], ["batch", "v1", "jobs"],
                                      ["apps", "v1", "controllerrevisions"], ["", "v1", "persistentvolumeclaims"],
                                      ["discovery.k8s.io", "v1", "endpointslices"], ["", "v1", "endpoints"],
                                      ["", "v1", "secrets"], ["", "v1", "configmaps"]].freeze

        def orphan_dependents(resource, namespace, owner)
          uid = metadata_value(owner, "uid").to_s
          return if uid.empty?

          ORPHAN_DEPENDENT_RESOURCES.each do |group, version, plural|
            descriptor = @registry.find_gvr(group: group, version: version, resource: plural)
            next if descriptor.nil?
            next if resource.namespaced? && !descriptor.namespaced?

            listing = @store.list(resource: descriptor, namespace: resource.namespaced? ? namespace : nil, selectors: nil)
            listing.items.each { |item| orphan_one_dependent(descriptor, item, uid) }
          rescue StandardError
            next
          end
        end

        # A dependent that could not be released keeps an owner reference to an
        # object that is about to stop existing, and the garbage collector then
        # deletes it -- the very thing an orphaning delete asks not to happen.
        # One rescue covered the whole collection, so a single conflicting Pod
        # abandoned every Pod after it: "[sig-api-machinery] Garbage collector
        # should orphan pods created by rc if delete options say so" kept 35 of
        # 100.  Each dependent now stands on its own and a conflict is re-read
        # and retried, as the garbage collector's orphaning does upstream.
        ORPHAN_CONFLICT_ATTEMPTS = 5

        def orphan_one_dependent(descriptor, item, uid)
          namespace = item.dig("metadata", "namespace")
          name = item.dig("metadata", "name")
          attempts = 0
          current = item
          begin
            references = Array(current.dig("metadata", "ownerReferences"))
            return unless references.any? { |reference| reference["uid"].to_s == uid }

            updated = deep_copy(current)
            updated["metadata"]["ownerReferences"] = references.reject { |reference| reference["uid"].to_s == uid }
            updated["metadata"].delete("ownerReferences") if updated["metadata"]["ownerReferences"].empty?
            @store.update(resource: descriptor, namespace: namespace, name: name,
                          object: updated, resource_version: metadata_value(current, "resourceVersion"))
          rescue MemoryStore::Conflict
            attempts += 1
            raise if attempts >= ORPHAN_CONFLICT_ATTEMPTS

            current = @store.get(resource: descriptor, namespace: namespace, name: name)
            retry
          end
        rescue MemoryStore::NotFound
          # Already gone; nothing left to release.
          nil
        rescue StandardError => error
          @logger&.warn("orphan.dependent_failed", object: [namespace, name].compact.join("/"),
                                                   error: error.class.name, message: error.message)
        end
      end
    end
  end
end
