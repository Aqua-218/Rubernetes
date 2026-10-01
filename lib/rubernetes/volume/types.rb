# frozen_string_literal: true

require "digest"
require "json"
require "time"

module Rubernetes
  module Volume
    module Types
      module_function

      def key(hash, name, default = nil)
        return default unless hash.respond_to?(:key?)

        return hash[name] if hash.key?(name)

        string = name.to_s
        return hash[string] if hash.key?(string)

        snake = string.gsub(/([A-Z])/, '_\\1').downcase.sub(/^_/, "")
        return hash[snake.to_sym] if hash.key?(snake.to_sym)
        return hash[snake] if hash.key?(snake)

        default
      end

      def present?(value)
        !value.nil? && !(value.respond_to?(:empty?) && value.empty?)
      end

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, child), copy| copy[deep_copy(key)] = deep_copy(child) }
        when Array
          value.map { |child| deep_copy(child) }
        when String
          value.dup
        else
          value
        end
      end

      # Freeze the complete object graph returned from a durable store.  A
      # shallow freeze is insufficient here because callers could otherwise
      # mutate nested attachment or specification hashes behind the ledger.
      def deep_freeze(value)
        case value
        when Hash
          value.each do |key, child|
            deep_freeze(key)
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
            original = value.key?(key) ? value[key] : value[key.to_sym]
            result[key] = canonical(original)
          end
        when Array
          value.map { |child| canonical(child) }
        when Time
          value.utc.iso8601(9)
        when Symbol
          value.to_s
        else
          value
        end
      end

      def digest(value)
        Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
      end

      def parse_capacity(value)
        if value.is_a?(Integer)
          raise CapacityError, "capacity must be positive" unless value.positive?

          return value
        end

        text = String(value).strip
        raise CapacityError, "capacity must be a positive quantity" if text.empty?

        match = /\A(\d+(?:\.\d+)?)([EPTGMK]i?|m)?\z/i.match(text)
        raise CapacityError, "invalid capacity quantity #{value.inspect}" unless match

        number = Float(match[1])
        suffix = match[2].to_s
        multipliers = {
          "" => 1, "m" => 0.001,
          "k" => 1_000, "K" => 1_000, "Ki" => 1_024, "ki" => 1_024,
          "M" => 1_000_000, "Mi" => 1_048_576, "mi" => 1_048_576,
          "G" => 1_000_000_000, "Gi" => 1_073_741_824, "gi" => 1_073_741_824,
          "T" => 1_000_000_000_000, "Ti" => 1_099_511_627_776, "ti" => 1_099_511_627_776,
          "P" => 1_000_000_000_000_000, "Pi" => 1_125_899_906_842_624, "pi" => 1_125_899_906_842_624,
          "E" => 1_000_000_000_000_000_000, "Ei" => 1_152_921_504_606_846_976, "ei" => 1_152_921_504_606_846_976
        }
        # Kubernetes treats the suffix as case-insensitive in the user-facing
        # quantity parser, while the quantity's canonical form is immaterial to
        # this in-memory binding contract.
        # Accept the case variants emitted by clients while retaining the
        # distinction between decimal milli (m) and decimal mega (M).
        normalized_suffix = if suffix.length == 2 && suffix.end_with?("i", "I")
                              "#{suffix[0].upcase}i"
                            elsif suffix.length == 1 && suffix.casecmp?("m")
                              suffix == "m" ? "m" : "M"
                            else
                              suffix.upcase
                            end
        multiplier = multipliers.fetch(normalized_suffix) do
          raise CapacityError, "unsupported capacity suffix #{suffix.inspect}"
        end
        bytes = (number * multiplier).ceil
        raise CapacityError, "capacity is outside the supported range" unless number.finite? && bytes.is_a?(Integer)
        raise CapacityError, "capacity must be positive" unless bytes.positive?

        bytes
      rescue ArgumentError, TypeError, FloatDomainError
        raise CapacityError, "capacity must be a positive quantity"
      end

      def normalize_access_modes(value)
        modes = Array(value).map do |mode|
          text = mode.to_s
          aliases = {
            "RWO" => "ReadWriteOnce", "ROX" => "ReadOnlyMany", "RWX" => "ReadWriteMany",
            "RWOP" => "ReadWriteOncePod", "ReadWriteOncePod" => "ReadWriteOncePod",
            "ReadWriteOnce" => "ReadWriteOnce", "ReadOnlyMany" => "ReadOnlyMany",
            "ReadWriteMany" => "ReadWriteMany"
          }
          aliases.fetch(text) { raise ValidationError, "unsupported access mode #{mode.inspect}" }
        end.uniq
        raise ValidationError, "at least one access mode is required" if modes.empty?
        if modes.include?("ReadWriteOncePod") && modes.length > 1
          raise ValidationError,
                "ReadWriteOncePod cannot be combined with another access mode"
        end

        modes.freeze
      end

      def bool(value, default: false)
        return default if value.nil?
        return value if [true, false].include?(value)

        case value.to_s.downcase
        when "true", "1", "yes" then true
        when "false", "0", "no" then false
        else raise ValidationError, "expected boolean, got #{value.inspect}"
        end
      end

      def identifier(value, field = "identifier")
        text = String(value)
        raise ValidationError, "#{field} must not be empty" if text.empty?
        raise ValidationError, "#{field} contains an unsafe NUL" if text.include?("\0")

        path_sensitive = field.to_s.match?(/(?:volume|snapshot|operation|mount|device|filesystem)\s*(?:id|key)?/i)
        raise ValidationError, "#{field} contains an unsafe path separator" if path_sensitive && (text.include?("/") || text.include?("\\"))
        raise ValidationError, "#{field} contains an unsafe path component" if [".", ".."].include?(text)
        raise ValidationError, "#{field} contains a control character" if text.each_byte.any?(&:zero?) || text.match?(/[[:cntrl:]]/)

        text.freeze
      rescue TypeError
        raise ValidationError, "#{field} must be a string"
      end
    end

    # Immutable result objects intentionally expose both Ruby readers and a
    # Kubernetes-shaped hash, making them convenient for API and test callers.
    class Identity
      attr_reader :name, :vendor_version, :plugin_version, :supports

      def initialize(name: "rubernetes", vendor_version: "0.1.0", plugin_version: "v1", supports: [])
        @name = Types.identifier(name, "plugin name")
        @vendor_version = Types.identifier(vendor_version, "vendor version")
        @plugin_version = Types.identifier(plugin_version, "plugin version")
        @supports = Array(supports).map(&:to_s).uniq.freeze
        freeze
      end

      def to_h
        {"name" => name, "vendorVersion" => vendor_version, "pluginVersion" => plugin_version,
         "supports" => supports}
      end

      alias vendorVersion vendor_version
      alias pluginVersion plugin_version

      def capabilities
        supports
      end
    end

    class VolumeRecord
      attr_reader :id, :spec, :backend, :state, :generation, :attachments, :stages, :publishes,
                  :operation, :capacity_bytes, :created_at, :updated_at

      def initialize(id:, spec:, backend:, state: "Declared", generation: 0, attachments: {}, stages: {}, publishes: {}, operation: nil,
                     capacity_bytes: nil, created_at: Time.now.utc, updated_at: Time.now.utc)
        @id = Types.identifier(id, "volume id")
        @spec = Types.deep_freeze(Types.deep_copy(spec))
        @backend = Types.identifier(backend, "backend")
        @state = state.to_s.freeze
        raise ValidationError, "unknown volume state #{@state.inspect}" unless StateMachine::STATES.include?(@state)

        @generation = Integer(generation)
        raise ValidationError, "volume generation must not be negative" if @generation.negative?

        @attachments = Types.deep_freeze(Types.deep_copy(attachments))
        @stages = Types.deep_freeze(Types.deep_copy(stages))
        @publishes = Types.deep_freeze(Types.deep_copy(publishes))
        @operation = operation && Types.deep_freeze(Types.deep_copy(operation))
        @capacity_bytes = capacity_bytes && Types.parse_capacity(capacity_bytes)
        @created_at = created_at.is_a?(Time) ? created_at.utc : Time.parse(created_at.to_s).utc
        @updated_at = updated_at.is_a?(Time) ? updated_at.utc : Time.parse(updated_at.to_s).utc
        freeze
      end

      def with(**changes)
        self.class.new(
          id: changes.fetch(:id, id), spec: changes.fetch(:spec, spec), backend: changes.fetch(:backend, backend),
          state: changes.fetch(:state, state), generation: changes.fetch(:generation, generation),
          attachments: changes.fetch(:attachments, attachments), stages: changes.fetch(:stages, stages),
          publishes: changes.fetch(:publishes, publishes), operation: changes.fetch(:operation, operation),
          capacity_bytes: changes.fetch(:capacity_bytes, capacity_bytes), created_at: created_at,
          updated_at: changes.fetch(:updated_at, Time.now.utc)
        )
      end

      def to_h
        {
          "id" => id, "spec" => Types.deep_copy(spec), "backend" => backend, "state" => state,
          "generation" => generation, "attachments" => Types.deep_copy(attachments),
          "stages" => Types.deep_copy(stages), "publishes" => Types.deep_copy(publishes),
          "operation" => Types.deep_copy(operation), "capacityBytes" => capacity_bytes,
          "createdAt" => created_at.iso8601(6), "updatedAt" => updated_at.iso8601(6)
        }
      end

      alias volume_id id
      alias capacity capacity_bytes
      alias status state

      def [](key)
        to_h[key.to_s]
      end
    end

    class SnapshotRecord
      attr_reader :id, :source_id, :name, :size_bytes, :ready_to_use, :content, :identity,
                  :created_at, :metadata

      def initialize(id:, source_id:, name: nil, size_bytes: 0, ready_to_use: true, content: nil,
                     identity: nil, created_at: Time.now.utc, metadata: {})
        @id = Types.identifier(id, "snapshot id")
        @source_id = Types.identifier(source_id, "source volume id")
        @name = name&.to_s
        @size_bytes = Integer(size_bytes)
        @ready_to_use = ready_to_use == true
        @content = Types.deep_freeze(Types.deep_copy(content)) unless content.nil?
        @identity = identity && Types.deep_freeze(Types.deep_copy(identity))
        @created_at = created_at.is_a?(Time) ? created_at.utc : Time.parse(created_at.to_s).utc
        @metadata = Types.deep_freeze(Types.deep_copy(metadata))
        freeze
      end

      def to_h
        {"id" => id, "sourceId" => source_id, "name" => name, "sizeBytes" => size_bytes,
         "readyToUse" => ready_to_use, "content" => Types.deep_copy(content),
         "identity" => Types.deep_copy(identity), "createdAt" => created_at.iso8601(6),
         "metadata" => Types.deep_copy(metadata)}
      end

      alias source_id source_id
      alias ready_to_use ready_to_use
    end

    class Stats
      attr_reader :used_bytes, :capacity_bytes, :available_bytes, :inodes_used, :inodes,
                  :timestamp, :volume_id

      def initialize(volume_id:, used_bytes: 0, capacity_bytes: 0, available_bytes: nil,
                     inodes_used: 0, inodes: nil, timestamp: Time.now.utc)
        @volume_id = Types.identifier(volume_id, "volume id")
        @used_bytes = Integer(used_bytes)
        @capacity_bytes = Integer(capacity_bytes)
        raise ValidationError, "volume stats cannot contain negative byte counts" if @used_bytes.negative? || @capacity_bytes.negative?

        @available_bytes = available_bytes.nil? ? [@capacity_bytes - @used_bytes, 0].max : Integer(available_bytes)
        raise ValidationError, "volume stats cannot contain negative available bytes" if @available_bytes.negative?

        @inodes_used = Integer(inodes_used)
        @inodes = inodes.nil? ? nil : Integer(inodes)
        @timestamp = timestamp.is_a?(Time) ? timestamp.utc : Time.parse(timestamp.to_s).utc
        freeze
      end

      def to_h
        {"volumeId" => volume_id, "usedBytes" => used_bytes, "capacityBytes" => capacity_bytes,
         "availableBytes" => available_bytes, "inodesUsed" => inodes_used, "inodes" => inodes,
         "timestamp" => timestamp.iso8601(6)}
      end

      def [](key)
        to_h[key.to_s]
      end
    end

    class RecoveryReport
      attr_reader :owned, :orphans, :missing, :identity_mismatches, :unknown, :actions, :errors

      def initialize(owned: [], orphans: [], missing: [], identity_mismatches: [], unknown: [], actions: [], errors: [])
        @owned = Array(owned).freeze
        @orphans = Array(orphans).freeze
        @missing = Array(missing).freeze
        @identity_mismatches = Array(identity_mismatches).freeze
        @unknown = Array(unknown).freeze
        @actions = Array(actions).freeze
        @errors = Array(errors).freeze
        freeze
      end

      def to_h
        {"owned" => owned, "orphans" => orphans, "missing" => missing,
         "identityMismatches" => identity_mismatches, "unknown" => unknown,
         "actions" => actions, "errors" => errors}
      end

      def [](key)
        to_h[key.to_s]
      end

      def fetch(key, *args)
        value = self[key]
        return value unless value.nil?
        return args.first unless args.empty?

        raise KeyError, "key not found: #{key.inspect}"
      end

      alias identity_mismatches identity_mismatches
    end
  end
end
