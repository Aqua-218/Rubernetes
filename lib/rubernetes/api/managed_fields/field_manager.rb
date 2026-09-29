# frozen_string_literal: true

require "json"
require "time"
require_relative "updater"
require_relative "../status"

module Rubernetes
  module API
    module ManagedFields
      LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"
      MAX_UPDATE_MANAGERS = 10
      ANCIENT_CHANGES = "ancient-changes"
      BEFORE_FIRST_APPLY = "before-first-apply"
      CURRENT_OPERATION = "current-operation"
      TOTAL_ANNOTATION_SIZE_LIMIT = 256 * 1024

      PE = FieldPath::PathElement
      # stripMetaManager: identity and bookkeeping metadata nobody owns.
      STRIP_SET = FieldPath::Set.from_paths(
        [[PE.field("apiVersion")], [PE.field("kind")], [PE.field("metadata")]] +
        %w[name namespace creationTimestamp selfLink uid clusterName generation managedFields resourceVersion]
          .map { |name| [PE.field("metadata"), PE.field(name)] }
      )

      # fieldpath.ManagedFields plus each manager's time.
      Managed = Struct.new(:fields, :times) do
        def self.empty = new({}, {})
      end

      # managedfields.go: ManagedFieldsEntry <-> managers.
      module Entries
        class DecodeError < StandardError; end

        module_function

        # BuildManagerIdentifier: the entry without fieldsType, fieldsV1 and
        # time (and without apiVersion for an Apply), as encoding/json
        # writes it.
        def identifier(manager:, operation:, api_version: nil, subresource: nil)
          parts = []
          parts << %("manager":#{Value.json_string(manager.to_s)}) unless manager.to_s.empty?
          parts << %("operation":#{Value.json_string(operation.to_s)}) unless operation.to_s.empty?
          if operation.to_s != "Apply" && !api_version.to_s.empty?
            parts << %("apiVersion":#{Value.json_string(api_version.to_s)})
          end
          parts << %("subresource":#{Value.json_string(subresource.to_s)}) unless subresource.to_s.empty?
          "{#{parts.join(",")}}"
        end

        def parse_identifier(id)
          JSON.parse(id)
        rescue JSON::ParserError
          {}
        end

        def value(entry, key)
          return nil unless entry.is_a?(Hash)

          entry.key?(key) ? entry[key] : entry[key.to_sym]
        end

        # fieldsV1 content => its set, and set => the fieldsV1 it encodes to.
        # An object's managedFields come back on nearly every write, so the
        # same few sets are decoded again and again; sets never change, so
        # an unchanged set also encodes to the object it was read from.
        SETS = {}
        SETS_LIMIT = 8192
        ENCODED = ObjectSpace::WeakMap.new
        CACHE_LOCK = Mutex.new

        def decode_set(fields)
          cached = CACHE_LOCK.synchronize { SETS[fields] }
          return cached if cached

          set = FieldPath::Set.from_fields_v1(fields)
          key = deep_freeze(deep_dup(fields))
          CACHE_LOCK.synchronize do
            SETS.clear if SETS.length >= SETS_LIMIT
            SETS[key] = set
            ENCODED[set] = key
          end
          set
        end

        def deep_dup(value)
          case value
          when Hash then value.each_with_object({}) { |(key, item), out| out[key] = deep_dup(item) }
          when Array then value.map { |item| deep_dup(item) }
          else value
          end
        end

        # DecodeManagedFields.
        def decode(entries)
          managed = Managed.empty
          Array(entries).each_with_index do |entry, index|
            raise DecodeError, "managed fields entry #{index} is not an object" unless entry.is_a?(Hash)

            operation = value(entry, "operation").to_s
            raise DecodeError, "operation must be `Apply` or `Update`" unless %w[Apply Update].include?(operation)

            api_version = value(entry, "apiVersion").to_s
            raise DecodeError, "apiVersion must not be empty" if api_version.empty?

            case value(entry, "fieldsType").to_s
            when "FieldsV1" then nil
            when "" then raise DecodeError, "missing fieldsType in managed fields entry #{index}"
            else raise DecodeError, "invalid fieldsType #{value(entry, "fieldsType").to_s.inspect} in managed fields entry #{index}"
            end
            id = identifier(manager: value(entry, "manager"), operation: operation, api_version: api_version,
                            subresource: value(entry, "subresource"))
            set = begin
              fields = value(entry, "fieldsV1") || {}
              fields.is_a?(Hash) ? decode_set(fields) : FieldPath::Set.from_fields_v1(fields)
            rescue FieldPath::DecodeError => error
              raise DecodeError, "error decoding versioned set from #{entry.inspect}: error decoding set: #{error.message}"
            end
            managed.fields[id] = VersionedSet.new(set, api_version, operation == "Apply").freeze
            managed.times[id] = value(entry, "time")
          end
          managed
        end

        # encodeManagedFields: sorted by operation, time (seconds), manager,
        # apiVersion and subresource; nil when there are none.
        def encode(managed)
          return nil if managed.fields.empty?

          entries = managed.fields.map do |id, versioned|
            parsed = parse_identifier(id)
            entry = {}
            entry["manager"] = parsed["manager"] unless parsed["manager"].to_s.empty?
            entry["operation"] = versioned.applied ? "Apply" : (parsed["operation"] || "Update")
            entry["apiVersion"] = versioned.api_version.to_s
            time = managed.times[id]
            entry["time"] = time if time
            entry["fieldsType"] = "FieldsV1"
            entry["fieldsV1"] = fields_v1(versioned.set)
            entry["subresource"] = parsed["subresource"] unless parsed["subresource"].to_s.empty?
            entry
          end
          entries.sort_by do |entry|
            [entry["operation"].to_s, seconds(entry["time"]), entry["manager"].to_s, entry["apiVersion"].to_s,
             entry["subresource"].to_s]
          end
        end

        def fields_v1(set)
          cached = CACHE_LOCK.synchronize { ENCODED[set] }
          return cached if cached

          emitted = deep_freeze(set.to_fields_v1)
          CACHE_LOCK.synchronize { ENCODED[set] = emitted }
          emitted
        end

        def deep_freeze(value)
          value.each_value { |child| deep_freeze(child) } if value.is_a?(Hash)
          value.freeze
        end

        def seconds(time)
          return 0 if time.nil?

          Time.iso8601(time.to_s).to_i
        rescue ArgumentError
          0
        end

        # isResetManagedFields: [] or [{}].
        def reset?(entries)
          return false unless entries.is_a?(Array)
          return true if entries.empty?

          entries.length == 1 && entries.first.is_a?(Hash) && entries.first.empty?
        end

        # conflict.go printManager.
        def print_manager(id)
          parsed = parse_identifier(id)
          text = Value.go_quote(parsed["manager"].to_s)
          text = "#{text} with subresource #{Value.go_quote(parsed["subresource"].to_s)}" unless parsed["subresource"].to_s.empty?
          return text unless parsed["operation"] == "Update"

          time = parsed["time"]
          return "#{text} using #{parsed["apiVersion"]}" if time.nil?

          "#{text} using #{parsed["apiVersion"]} at #{Time.iso8601(time).utc.iso8601}"
        end

        # NewConflictError.
        def conflict_error(conflicts)
          list = conflicts.conflicts
          causes = list.map do |manager, path|
            {"reason" => "FieldManagerConflict", "message" => "conflict with #{print_manager(manager)}",
             "field" => FieldPath.path_string(path)}
          end
          message = if list.length == 1
                      manager, path = list.first
                      "Apply failed with 1 conflict: conflict with #{print_manager(manager)}: #{FieldPath.path_string(path)}"
                    else
                      grouped = list.group_by(&:first)
                      lines = grouped.keys.sort.flat_map do |manager|
                        ["conflicts with #{print_manager(manager)}:"] +
                          grouped[manager].map { |_, path| "- #{FieldPath.path_string(path)}" }
                      end
                      "Apply failed with #{list.length} conflicts: #{lines.join("\n")}"
                    end
          Status::Conflict.new(message, details: {"causes" => causes})
        end
      end

      # versionConverter: a typed value in another version of the same kind.
      class VersionConverter
        # +types+: ->(group, version, kind) { [model, type_ref] or nil }.
        def initialize(types:, group:, kind:, object_converter: nil)
          @types = types
          @group = group.to_s
          @kind = kind.to_s
          @object_converter = object_converter
        end

        def convert(typed_value, api_version)
          return typed_value if typed_value.api_version.to_s == api_version.to_s

          group, version = split(api_version)
          raise MissingVersion, "no corresponding type for #{api_version}" unless group == @group

          model, type_ref = @types.call(group, version, @kind)
          raise MissingVersion, "no corresponding type for #{api_version}, Kind=#{@kind}" if model.nil?

          value = typed_value.value
          if @object_converter
            begin
              value = @object_converter.call(value, typed_value.api_version, api_version.to_s)
            rescue MissingVersion
              raise
            rescue StandardError => error
              raise MissingVersion, error.message
            end
          end
          TypedValue.new(value, model, type_ref, typed: typed_value.typed?, api_version: api_version.to_s)
        end

        def split(api_version)
          parts = api_version.to_s.split("/", 2)
          parts.length == 1 ? ["", parts.first] : parts
        end
      end

      # The field manager of one kind (and subresource), assembled as
      # NewDefaultFieldManager assembles it: versionCheck, lastAppliedUpdater,
      # lastAppliedManager, skipNonApplied (track on create), capManagers,
      # buildManagerInfo, managedFieldsUpdater, stripMeta, structuredMerge.
      class FieldManager
        class Error < StandardError; end

        attr_reader :api_version

        # +reset_fields+: the strategy's GetResetFields as a FieldPath::Set
        # (applied to every version).  +object_converter+:
        # ->(object, from_api_version, to_api_version) for multi-version
        # kinds; nil when versions share one shape.  +version_types+ finds
        # the type of the kind in another version (default: the same
        # converter).
        def initialize(type_converter:, group:, version:, kind:, subresource: nil, reset_fields: nil,
                       object_converter: nil, version_types: nil, new_object: nil, clock: -> { Time.now.utc })
          @type_converter = type_converter
          @zero_object = new_object || {}
          @group = group.to_s
          @version = version.to_s
          @kind = kind.to_s
          @api_version = @group.empty? ? @version : "#{@group}/#{@version}"
          @subresource = subresource.to_s
          @clock = clock
          reset = reset_fields
          @updater = Updater.new(
            converter: VersionConverter.new(types: version_types || ->(g, v, k) { type_converter.type_for(g, v, k) },
                                            group: @group, kind: @kind, object_converter: object_converter),
            ignored: ->(_version) { reset }
          )
        end

        def subresource? = !@subresource.empty?

        # FieldManager.UpdateNoErrors: the managedFields +new_object+ is
        # stored with (nil for none).  +live+ is nil for a create, which
        # starts from the kind's new (zero) object.
        def update(live:, new_object:, manager:)
          live ||= @zero_object
          unchanged = unchanged_write(live, new_object)
          return unchanged.last if unchanged

          managed = decode_live_or_new(live, new_object)
          managed = pipeline_update(live, new_object, managed, manager)
          Entries.encode(managed)
        rescue Error, TypedValue::Error, MissingVersion, Entries::DecodeError, FieldPath::DecodeError
          nil
        end

        # FieldManager.Apply: [object, managed_fields] -- the merged object
        # (the live one when the apply changed nothing) and its managedFields.
        def apply(live:, config:, manager:, force:)
          live ||= {}
          managed = begin
            Entries.decode(metadata(live)["managedFields"])
          rescue Entries::DecodeError => error
            raise Error, "failed to decode managed fields: #{error.message}"
          end
          check_version!(config)
          object, managed = last_applied_update(live, config, managed, manager, force)
          [object, Entries.encode(managed)]
        end

        private

        def metadata(object)
          meta = object.is_a?(Hash) ? object["metadata"] : nil
          meta.is_a?(Hash) ? meta : {}
        end

        # A write that changes nothing (managedFields aside) compares to no
        # change for every manager, so the live entries stand as they are.
        # [true, entries] or nil.
        def unchanged_write(live, new_object)
          return nil unless new_object.is_a?(Hash) && live.is_a?(Hash) && !live.empty?

          live_meta = metadata(live)
          new_meta = metadata(new_object)
          provided = new_meta["managedFields"]
          return nil if Entries.reset?(provided)
          return nil unless subresource? || provided.nil? || provided == live_meta["managedFields"]
          return nil unless live.length == new_object.length && live_meta.except("managedFields") == new_meta.except("managedFields")
          return nil unless new_object.all? { |key, value| key == "metadata" || (live.key?(key) && live[key] == value) }

          [true, live_meta["managedFields"]]
        end

        def decode_live_or_new(live, new_object)
          live_managed = -> { Entries.decode(metadata(live)["managedFields"]) rescue Managed.empty }
          return live_managed.call if subresource?

          provided = metadata(new_object)["managedFields"]
          return Managed.empty if Entries.reset?(provided)

          managed = begin
            Entries.decode(provided)
          rescue Entries::DecodeError
            nil
          end
          return live_managed.call if managed.nil? || managed.fields.empty?

          managed
        end

        # ---- Update --------------------------------------------------------

        def pipeline_update(live, new_object, managed, manager)
          # skipNonAppliedManager with DefaultTrackOnCreateProbability 1.
          return managed if managed.fields.empty? && !metadata(live)["uid"].to_s.empty?

          cap_update(live, new_object, managed, manager)
        end

        def cap_update(live, new_object, managed, manager)
          id = manager_id(manager, "Update")
          managed = timed_update(live, new_object, managed, id)
          cap_managers(managed)
        end

        # managedFieldsUpdater.Update around stripMeta and structuredMerge.
        def timed_update(live, new_object, managed, id)
          managed = structured_update(live, new_object, managed, CURRENT_OPERATION)
          strip!(managed.fields, CURRENT_OPERATION)
          current = managed.fields.delete(CURRENT_OPERATION)
          if current
            previous = managed.fields[id]
            managed.fields[id] = previous ? VersionedSet.new(current.set.union(previous.set), current.api_version, current.applied) : current
            managed.times[id] = timestamp
          end
          managed
        end

        def structured_update(live, new_object, managed, manager)
          # Nobody owns metadata.managedFields (stripMeta), so leaving it out
          # of both sides changes nothing but the cost of the comparison.
          new_typed = typed(without_managed_fields(new_object))
          live_typed = typed(without_managed_fields(live))
          _, fields = @updater.update(live_typed, new_typed, @api_version, managed.fields, manager)
          Managed.new(fields, managed.times)
        end

        # ---- Apply ---------------------------------------------------------

        # versionCheckManager.
        def check_version!(config)
          api_version = config["apiVersion"].to_s
          kind = config["kind"].to_s
          return if api_version == @api_version && kind == @kind

          group, version = api_version.include?("/") ? api_version.split("/", 2) : ["", api_version]
          raise Status::BadRequest.new("invalid object type: #{gvk_string(group, version, kind)}")
        end

        # schema.GroupVersionKind.String: "group/version, Kind=kind", the
        # slash kept for the core group.
        def gvk_string(group, version, kind) = "#{group}/#{version}, Kind=#{kind}"

        # lastAppliedUpdater.
        def last_applied_update(live, config, managed, manager, force)
          object, managed = last_applied_manager(live, config, managed, manager, force)
          if manager == "kubectl" && last_applied?(object)
            object = set_last_applied(object, build_last_applied(config))
          end
          [object, managed]
        end

        # lastAppliedManager: kubectl's conflicts with values it set through
        # client-side apply are not conflicts.
        def last_applied_manager(live, config, managed, manager, force)
          copy = Managed.new(managed.fields.dup, managed.times.dup)
          skip_non_applied_apply(live, config, copy, manager, force)
        rescue Conflicts => conflicts
          raise Entries.conflict_error(conflicts) unless manager == "kubectl"

          allowed = begin
            allowed_conflicts_from_last_applied(live)
          rescue StandardError
            nil
          end
          raise Entries.conflict_error(conflicts) if allowed.nil?

          remaining = conflicts.to_set.difference(allowed)
          unless remaining.empty?
            kept = conflicts.conflicts.reject { |_, path| allowed.has?(path) }
            raise Entries.conflict_error(Conflicts.new(kept))
          end
          skip_non_applied_apply(live, config, Managed.new(managed.fields.dup, managed.times.dup), manager, true)
        end

        def allowed_conflicts_from_last_applied(live)
          annotations = metadata(live)["annotations"]
          text = annotations.is_a?(Hash) ? annotations[LAST_APPLIED].to_s : ""
          raise Error, "no last applied annotation" if text.empty?

          last = JSON.parse(text)
          raise Error, "unexpected last applied version" unless last.is_a?(Hash) && last["apiVersion"].to_s == @api_version

          # ObjectToTyped without AllowDuplicates: a live object with
          # duplicate list keys makes the allowance fail, and every conflict
          # stands.
          live_typed = typed(without_managed_fields(live))
          raise Error, "invalid live object" unless live_typed.validate.empty?

          last_typed = typed(last, typed: false)
          raise Error, "invalid last applied object" unless last_typed.validate.empty?

          set = last_typed.to_field_set
          comparison = last_typed.compare(live_typed)
          set.difference(comparison.modified).difference(comparison.added).difference(comparison.removed)
        end

        def skip_non_applied_apply(live, config, managed, manager, force)
          if managed.fields.empty?
            empty = {"apiVersion" => config["apiVersion"], "kind" => config["kind"]}
            managed = cap_managers(timed_update(empty, live, managed, manager_id(BEFORE_FIRST_APPLY, "Update")))
          end
          id = manager_id(manager, "Apply")
          object, managed = timed_apply(live, config, managed, id, force)
          [object, cap_managers(managed)]
        end

        # managedFieldsUpdater.Apply around stripMeta and structuredMerge.
        def timed_apply(live, config, managed, id, force)
          object, managed = structured_apply(live, config, managed, id, force)
          strip!(managed.fields, id)
          if object
            managed.times[id] = timestamp
          else
            object = live.merge("metadata" => metadata(live).except("managedFields"))
          end
          [object, managed]
        end

        def structured_apply(live, config, managed, id, force)
          patch_version = config["apiVersion"].to_s
          unless patch_version == @api_version
            raise Status::BadRequest.new("Incorrect version specified in apply patch. " \
                                         "Specified patch version: #{patch_version}, expected: #{@api_version}")
          end
          raise Status::BadRequest.new("metadata.managedFields must be nil") unless metadata(config)["managedFields"].nil?

          config_typed = typed(config, typed: false)
          errors = config_typed.validate
          unless errors.empty?
            raise Error, "failed to create typed patch object (#{object_gvknn(config)}): #{validation_message(errors)}"
          end
          live_typed = typed(live)
          merged, fields = @updater.apply(live_typed, config_typed, @api_version, managed.fields, id, force)
          [merged&.value, Managed.new(fields, managed.times)]
        end

        def validation_message(errors)
          errors.length == 1 ? errors.first : (["errors:"] + errors.map { |error| "  #{error}" }).join("\n")
        end

        def object_gvknn(object)
          meta = metadata(object)
          name = meta["name"].to_s
          namespace = meta.key?("namespace") ? meta["namespace"].to_s : ""
          group, version = @api_version.include?("/") ? @api_version.split("/", 2) : ["", @api_version]
          "#{namespace}/#{name}; #{gvk_string(group, version, @kind)}"
        end

        # ---- shared --------------------------------------------------------

        def typed(object, typed: true)
          model, type_ref = @type_converter.type_for(@group, @version, @kind)
          raise Error, "no corresponding type for #{gvk_string(@group, @version, @kind)}" if model.nil?

          TypedValue.new(object || {}, model, type_ref, typed: typed, api_version: @api_version)
        end

        def without_managed_fields(object)
          meta = metadata(object)
          return object || {} unless meta.key?("managedFields")

          object.merge("metadata" => meta.except("managedFields"))
        end

        def manager_id(manager, operation)
          name = manager.to_s.empty? ? "unknown" : manager.to_s
          Entries.identifier(manager: name, operation: operation, api_version: @api_version, subresource: @subresource)
        end

        def strip!(fields, id)
          entry = fields[id]
          return unless entry

          set = entry.set.difference(STRIP_SET)
          if set.empty?
            fields.delete(id)
          else
            fields[id] = VersionedSet.new(set, entry.api_version, entry.applied)
          end
        end

        def timestamp = @clock.call.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # capManagersManager.capUpdateManagers.
        def cap_managers(managed)
          updaters = managed.fields.reject { |_, entry| entry.applied }.keys
          return managed if updaters.length <= MAX_UPDATE_MANAGERS

          updaters.sort_by! { |id| [Entries.seconds(managed.times[id]), id] }
          first_by_version = {}
          length = updaters.length
          updaters.each do |id|
            break if length <= MAX_UPDATE_MANAGERS

            entry = managed.fields[id]
            version = entry.api_version
            bucket = Entries.identifier(manager: ANCIENT_CHANGES, operation: "Update", api_version: version)
            first = first_by_version[version]
            unless first
              first_by_version[version] = id
              next
            end
            unless managed.fields.key?(bucket)
              managed.fields[bucket] = managed.fields.delete(first)
            end
            managed.fields[bucket] = VersionedSet.new(entry.set.union(managed.fields[bucket].set), entry.api_version, entry.applied)
            managed.fields.delete(id)
            length -= 1
            managed.times[bucket] = managed.times[id]
          end
          managed
        end

        def last_applied?(object)
          annotations = metadata(object)["annotations"]
          annotations.is_a?(Hash) && !annotations[LAST_APPLIED].to_s.empty?
        end

        # buildLastApplied: the applied configuration without the annotation,
        # as UnstructuredJSONScheme encodes it.
        def build_last_applied(config)
          meta = metadata(config)
          annotations = meta["annotations"].is_a?(Hash) ? meta["annotations"].except(LAST_APPLIED) : nil
          copy = config.merge("metadata" => meta.merge("annotations" => annotations).compact)
          "#{Value.to_json(copy)}\n"
        end

        def set_last_applied(object, value)
          meta = metadata(object)
          annotations = (meta["annotations"].is_a?(Hash) ? meta["annotations"] : {}).merge(LAST_APPLIED => value)
          size = annotations.sum { |key, item| key.to_s.bytesize + item.to_s.bytesize }
          annotations = annotations.except(LAST_APPLIED) if size > TOTAL_ANNOTATION_SIZE_LIMIT
          object.merge("metadata" => meta.merge("annotations" => annotations))
        end
      end

      # managedfields.ScaleHandler: a parent's replicas ownership seen from
      # (and written back through) the scale subresource.
      module ScaleHandler
        SCALE_API_VERSION = "autoscaling/v1"
        REPLICAS = [PE.field("spec"), PE.field("replicas")].freeze

        module_function

        # +mappings+: parent API version => replicas path (element array).
        def to_subresource(parent_entries, mappings)
          managed = Entries.decode(parent_entries)
          fields = {}
          times = {}
          managed.fields.each do |id, entry|
            path = mappings[entry.api_version]
            next if path.nil? || !entry.set.has?(path)

            fields[id] = VersionedSet.new(FieldPath::Set.from_paths([REPLICAS]), SCALE_API_VERSION, entry.applied)
            times[id] = managed.times[id]
          end
          Entries.encode(Managed.new(fields, times))
        end

        def to_parent(parent_entries, scale_entries, group_version, mappings)
          parent = Entries.decode(parent_entries)
          scale = Entries.decode(scale_entries).fields
          fields = {}
          times = {}
          parent.fields.each do |id, entry|
            next unless mappings.key?(entry.api_version)

            path = mappings[entry.api_version]
            if path.nil? || !entry.set.has?(path)
              fields[id] = entry
              times[id] = parent.times[id]
              next
            end
            if scale.key?(id)
              fields[id] = entry
              times[id] = parent.times[id]
              scale.delete(id)
            else
              set = entry.set.difference(FieldPath::Set.from_paths([path]))
              unless set.empty?
                fields[id] = VersionedSet.new(set, entry.api_version, entry.applied)
                times[id] = parent.times[id]
              end
            end
          end
          scale.each do |id, entry|
            next unless entry.set.has?(REPLICAS)

            fields[id] = VersionedSet.new(FieldPath::Set.from_paths([mappings[group_version]]), group_version, entry.applied)
            times[id] = parent.times[id]
          end
          Entries.encode(Managed.new(fields, times))
        end
      end
    end
  end
end
