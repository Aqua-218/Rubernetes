# frozen_string_literal: true

require_relative "typed"

module Rubernetes
  module API
    module ManagedFields
      # A manager's field set at the API version it was recorded in.
      VersionedSet = Struct.new(:set, :api_version, :applied)

      # merge.Conflict / merge.Conflicts.
      class Conflicts < StandardError
        attr_reader :conflicts

        # +conflicts+: [[manager_id, path], ...].
        def initialize(conflicts)
          @conflicts = conflicts
          super("#{conflicts.length} conflicts")
        end

        # ConflictsFromManagers, in a stable order (upstream iterates a map).
        def self.from_managers(sets)
          list = sets.keys.sort.flat_map do |manager|
            sets[manager].set.each_path.map { |path| [manager, path] }
          end
          new(list)
        end

        def to_set = FieldPath::Set.from_paths(@conflicts.map(&:last))
      end

      # The object is not available in a manager's version
      # (IsMissingVersionError).
      class MissingVersion < StandardError; end

      # sigs.k8s.io/structured-merge-diff/v6/merge.Updater with an
      # IgnoreFilter of exclude sets (the strategy's reset fields).
      class Updater
        # +converter+ responds to convert(typed_value, api_version) and
        # raises MissingVersion; +ignored+ maps an API version to the set of
        # fields ignored for it (nil for none).
        def initialize(converter:, ignored: ->(_version) {})
          @converter = converter
          @ignored = ignored
        end

        def update(live, new_object, version, managers, manager)
          managers = reconcile(live, managers)
          managers, comparison = update_managers(live, new_object, version, managers, manager, true)
          previous = managers[manager] || VersionedSet.new(FieldPath::Set.new, version, false)
          set = previous.set.difference(comparison.removed).union(comparison.modified).union(comparison.added)
          ignored = @ignored.call(version)
          set = set.recursive_difference(ignored) if ignored
          managers[manager] = VersionedSet.new(set, version, false)
          managers.delete(manager) if set.empty?
          [new_object, managers]
        end

        # The merged object (nil when it equals the live one) and the
        # managers.
        def apply(live, config, version, managers, manager, force)
          managers = reconcile(live, managers)
          merged = live.merge(config)
          last = managers[manager]
          set = config.to_field_set
          ignored = @ignored.call(version)
          set = set.recursive_difference(ignored) if ignored
          managers[manager] = VersionedSet.new(set, version, true)
          merged = prune(merged, managers, manager, last)
          managers, = update_managers(live, merged, version, managers, manager, force)
          merged = nil if Value.equal?(strip_nulls(live), strip_nulls(merged))
          [merged, managers]
        end

        private

        # A typed value's view as a value (the typed nils are absent).
        def strip_nulls(typed_value)
          value = typed_value.value
          typed_value.typed? ? deep_compact(value) : value
        end

        def deep_compact(value)
          case value
          when Hash then value.each_with_object({}) { |(key, item), out| out[key.to_s] = deep_compact(item) unless item.nil? }
          when Array then value.map { |item| deep_compact(item) }
          else value
          end
        end

        def update_managers(old_object, new_object, version, managers, workflow, force)
          conflicts = {}
          removed = {}
          comparison = old_object.compare(new_object)
          versions = {version => comparison.exclude(@ignored.call(version))}
          managers.keys.each do |manager|
            next if manager == workflow

            entry = managers[manager]
            compared = versions[entry.api_version]
            unless compared
              begin
                old_versioned = @converter.convert(old_object, entry.api_version)
                new_versioned = @converter.convert(new_object, entry.api_version)
              rescue MissingVersion
                managers.delete(manager)
                next
              end
              compared = versions[entry.api_version] =
                old_versioned.compare(new_versioned).exclude(@ignored.call(entry.api_version))
            end
            conflict = entry.set.intersection(compared.modified.union(compared.added))
            conflicts[manager] = VersionedSet.new(conflict, entry.api_version, false) unless conflict.empty?
            removed[manager] = VersionedSet.new(compared.removed, entry.api_version, false) unless compared.removed.empty?
          end
          raise Conflicts.from_managers(conflicts) if !force && conflicts.any?

          conflicts.each do |manager, conflict|
            entry = managers[manager]
            managers[manager] = VersionedSet.new(entry.set.difference(conflict.set), entry.api_version, entry.applied)
          end
          removed.each do |manager, gone|
            entry = managers[manager]
            next unless entry

            managers[manager] = VersionedSet.new(entry.set.difference(gone.set), entry.api_version, entry.applied)
          end
          managers.delete_if { |_manager, entry| entry.set.empty? }
          [managers, comparison]
        end

        def prune(merged, managers, applying, last)
          return merged if last.nil? || last.set.empty?

          version = last.api_version
          begin
            converted = @converter.convert(merged, version)
          rescue MissingVersion
            return merged
          end
          model = converted.model
          type_ref = converted.type_ref
          pruned = converted.remove_items(last.set.ensure_named_fields_are_members(model, type_ref))
          pruned = add_back_owned_items(converted, pruned, version, managers, applying)
          pruned = add_back_dangling_items(converted, pruned, last)
          @converter.convert(pruned, managers[applying].api_version)
        end

        def add_back_owned_items(merged, pruned, pruned_version, managers, _applying)
          managed_at = {}
          managers.each_value do |entry|
            managed_at[entry.api_version] = (managed_at[entry.api_version] || FieldPath::Set.new).union(entry.set)
          end
          if (managed = managed_at.delete(pruned_version))
            merged, pruned = add_back_owned_for_version(merged, pruned, pruned_version, managed)
          end
          managed_at.each do |version, managed|
            merged, pruned = add_back_owned_for_version(merged, pruned, version, managed)
          end
          pruned
        end

        def add_back_owned_for_version(merged, pruned, version, managed)
          begin
            merged = @converter.convert(merged, version)
            pruned = @converter.convert(pruned, version)
          rescue MissingVersion
            return [merged, pruned]
          end
          model = merged.model
          type_ref = merged.type_ref
          merged_set = merged.to_field_set.ensure_named_fields_are_members(model, type_ref)
          pruned_set = pruned.to_field_set.ensure_named_fields_are_members(model, type_ref)
          keep = pruned_set.union(managed.ensure_named_fields_are_members(model, type_ref))
          [merged, merged.remove_items(merged_set.difference(keep))]
        end

        def add_back_dangling_items(merged, pruned, last)
          begin
            converted = @converter.convert(pruned, last.api_version)
          rescue MissingVersion
            return merged
          end
          model = merged.model
          type_ref = merged.type_ref
          pruned_set = converted.to_field_set.ensure_named_fields_are_members(model, type_ref)
          merged_set = merged.to_field_set.ensure_named_fields_are_members(model, type_ref)
          last_set = last.set.ensure_named_fields_are_members(model, type_ref)
          merged.remove_items(merged_set.difference(pruned_set).intersection(last_set))
        end

        # reconcileManagedFieldsWithSchemaChanges.
        def reconcile(live, managers)
          result = {}
          managers.each do |manager, entry|
            begin
              typed = @converter.convert(live, entry.api_version)
            rescue MissingVersion
              next
            end
            reconciled = typed.reconcile_field_set(entry.set)
            result[manager] = reconciled ? VersionedSet.new(reconciled, entry.api_version, entry.applied) : entry
          end
          result
        end
      end
    end
  end
end
