# frozen_string_literal: true

require "securerandom"
require "digest"
require "json"
require "time"

module Rubernetes
  module Controller
    # The controller manager's registry (component-base legacyregistry: the
    # controllers record into one process-wide registry); nil outside a
    # controller manager, where recording is a no-op.
    class << self
      attr_accessor :metrics
    end

    # Recording into Controller.metrics.
    module ControllerMetrics
      module_function

      def increment(name, labels = {}, by: 1)
        Controller.metrics&.increment(name, labels, by: by)
      rescue StandardError
        nil
      end

      def observe(name, value, labels = {})
        Controller.metrics&.observe(name, value, labels)
      rescue StandardError
        nil
      end

      def set(name, value, labels = {})
        Controller.metrics&.set(name, value, labels)
      rescue StandardError
        nil
      end
    end

    # Small, dependency-free helpers used by planners.  All resource values
    # crossing a controller boundary are copied first; informer objects are
    # intentionally treated as immutable snapshots.
    module Support
      module_function

      # The controller whose operations the current thread is applying, so a
      # store can issue each write the way that controller's upstream
      # counterpart does (UpdateStatus, a status patch or a status apply).
      def current_controller = Thread.current[:rubernetes_controller]

      def with_controller(name)
        previous = Thread.current[:rubernetes_controller]
        Thread.current[:rubernetes_controller] = name&.to_s
        yield
      ensure
        Thread.current[:rubernetes_controller] = previous
      end

      # names.SimpleNameGenerator: five lowercase alphanumerics without vowels
      # (upstream's alphabet "bcdfghjklmnpqrstvwxz2456789").
      GENERATE_NAME_ALPHABET = "bcdfghjklmnpqrstvwxz2456789".freeze

      def random_suffix(length = 5)
        Array.new(length) { GENERATE_NAME_ALPHABET[SecureRandom.random_number(GENERATE_NAME_ALPHABET.length)] }.join
      end

      def value(hash, key, default = nil)
        return default unless hash.is_a?(Hash)

        if hash.key?(key)
          hash[key]
        elsif hash.key?(key.to_s)
          hash[key.to_s]
        elsif hash.key?(key.to_sym)
          hash[key.to_sym]
        else
          default
        end
      end

      def metadata(object)
        candidate = value(object, "metadata", {})
        candidate.is_a?(Hash) ? candidate : {}
      end

      def spec(object)
        candidate = value(object, "spec", {})
        candidate.is_a?(Hash) ? candidate : {}
      end

      def status(object)
        candidate = value(object, "status", {})
        candidate.is_a?(Hash) ? candidate : {}
      end

      def name(object)
        value(metadata(object), "name", "").to_s
      end

      def namespace(object)
        value(metadata(object), "namespace", nil)&.to_s
      end

      def uid(object)
        value(metadata(object), "uid", nil)&.to_s
      end

      def kind(object)
        value(object, "kind", "").to_s
      end

      def api_version(object)
        value(object, "apiVersion", nil) || value(object, "api_version", nil)
      end

      def creation_time(object)
        parse_time(value(metadata(object), "creationTimestamp", nil))
      end

      def parse_time(value)
        return value if value.is_a?(Time)
        return nil if value.nil? || value.to_s.empty?

        Time.parse(value.to_s).utc
      rescue ArgumentError, TypeError
        nil
      end

      def deep_copy(value, seen = nil)
        case value
        when Hash
          return seen.fetch(value) if seen&.key?(value)

          copy = {}
          (seen ||= {}.compare_by_identity)[value] = copy
          value.each { |key, child| copy[deep_copy(key, seen)] = deep_copy(child, seen) }
          copy
        when Array
          return seen.fetch(value) if seen&.key?(value)

          copy = []
          (seen ||= {}.compare_by_identity)[value] = copy
          value.each { |child| copy << deep_copy(child, seen) }
          copy
        when String
          value.dup
        else
          value
        end
      end

      def deep_freeze(value, seen = nil)
        return value if value.nil? || value.is_a?(Numeric) || value == true || value == false
        return value if seen&.key?(value)

        (seen ||= {}.compare_by_identity)[value] = true
        case value
        when Hash
          value.each { |key, child| deep_freeze(key, seen); deep_freeze(child, seen) }
        when Array
          value.each { |child| deep_freeze(child, seen) }
        end
        value.freeze
      end

      # Values this module has already frozen all the way down are shared
      # rather than copied again: a caller cannot mutate them either way.
      DEEP_FROZEN = ObjectSpace::WeakMap.new

      def immutable_copy(value)
        return value if DEEP_FROZEN.key?(value)

        result = deep_freeze(deep_copy(value))
        DEEP_FROZEN[result] = true if result.is_a?(Hash) || result.is_a?(Array)
        result
      end

      def deep_frozen?(value)
        DEEP_FROZEN.key?(value)
      end

      def canonical(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, child), result|
            result[key.to_s] = canonical(child)
          end.sort.to_h
        when Array
          value.map { |child| canonical(child) }
        when Time
          value.utc.iso8601(9)
        else
          value
        end
      end

      def digest(value)
        Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
      end

      def get_path(object, path)
        Array(path.to_s.split(".")).reject(&:empty?).reduce(object) do |current, segment|
          current.is_a?(Hash) ? value(current, segment, nil) : nil
        end
      end

      def set_path(object, path, child)
        segments = Array(path.to_s.split(".")).reject(&:empty?)
        raise ArgumentError, "path must not be empty" if segments.empty?

        cursor = object
        segments[0...-1].each do |segment|
          cursor[segment] = {} unless cursor[segment].is_a?(Hash)
          cursor = cursor[segment]
        end
        cursor[segments.last] = child
        object
      end

      def merge_hash(base, patch)
        result = deep_copy(base || {})
        (patch || {}).each do |key, value|
          if value.is_a?(Hash) && result[key].is_a?(Hash)
            result[key] = merge_hash(result[key], value)
          else
            result[key] = deep_copy(value)
          end
        end
        result
      end

      def labels(object)
        candidate = value(metadata(object), "labels", {})
        candidate.is_a?(Hash) ? candidate : {}
      end

      def annotations(object)
        candidate = value(metadata(object), "annotations", {})
        candidate.is_a?(Hash) ? candidate : {}
      end

      # labels.Selector.String() of a LabelSelector (metav1.
      # LabelSelectorAsSelector): requirements sorted by key, values sorted.
      def selector_string(selector)
        return "" if selector.nil?
        return selector.to_s if selector.is_a?(String)

        requirements = []
        (value(selector, "matchLabels", nil) || {}).each { |key, expected| requirements << [key.to_s, "#{key}=#{expected}"] }
        Array(value(selector, "matchExpressions", nil)).each do |expression|
          key = value(expression, "key", "").to_s
          values = Array(value(expression, "values", [])).map(&:to_s).sort.join(",")
          text = case value(expression, "operator", "").to_s
                 when "In" then "#{key} in (#{values})"
                 when "NotIn" then "#{key} notin (#{values})"
                 when "Exists" then key
                 when "DoesNotExist" then "!#{key}"
                 end
          requirements << [key, text] if text
        end
        requirements.sort_by(&:first).map(&:last).join(",")
      end

      def selector_matches?(selector, object)
        return true if selector.nil? || selector == {} || selector.to_s.empty?
        return !!selector.call(object) if selector.respond_to?(:call)

        labels = labels(object)
        if selector.is_a?(Hash)
          match_labels = value(selector, "matchLabels", nil)
          match_expressions = value(selector, "matchExpressions", nil)
          # A LabelSelector (either field, even without matchLabels) rather
          # than a plain label map.
          if match_labels.is_a?(Hash) || !match_expressions.nil? ||
             selector.key?("matchLabels") || selector.key?(:matchLabels)
            return false if match_labels.is_a?(Hash) && !match_labels.empty? && !selector_matches?(match_labels, object)
            expressions = Array(match_expressions)
            return expressions.all? do |expression|
              key = value(expression, "key", "").to_s
              operator = value(expression, "operator", "In").to_s
              values = Array(value(expression, "values", [])).map(&:to_s)
              actual = labels[key]
              case operator
              when "In" then values.include?(actual.to_s)
              when "NotIn" then !values.include?(actual.to_s)
              when "Exists" then labels.key?(key)
              when "DoesNotExist" then !labels.key?(key)
              else false
              end
            end
          end
          return selector.all? do |key, expected|
            actual = labels[key.to_s] || labels[key.to_sym]
            expected.is_a?(Array) ? expected.map(&:to_s).include?(actual.to_s) : actual.to_s == expected.to_s
          end
        end

        selector.to_s.split(",").all? do |expression|
          text = expression.strip
          next true if text.empty?

          if (match = text.match(/\A(.+?)\s+in\s*\(([^)]*)\)\z/i))
            Array(match[2].split(",")).map(&:strip).include?((labels[match[1].strip] || "").to_s)
          elsif (match = text.match(/\A(.+?)\s+notin\s*\(([^)]*)\)\z/i))
            !Array(match[2].split(",")).map(&:strip).include?((labels[match[1].strip] || "").to_s)
          elsif (match = text.match(/\A(.+?)\s*(!=|==|=)\s*(.*)\z/))
            actual = labels[match[1].strip]
            match[2] == "!=" ? actual.to_s != match[3].strip : actual.to_s == match[3].strip
          else
            labels.key?(text)
          end
        end
      end

      def owner_references(object)
        refs = value(metadata(object), "ownerReferences", [])
        refs.is_a?(Array) ? refs.select { |ref| ref.is_a?(Hash) } : []
      end

      def ref_value(ref, key, default = nil)
        value(ref, key, default)
      end

      def owner_reference(owner, controller: true, block_owner_deletion: true)
        owner_kind = kind(owner)
        owner_api_version = api_version(owner) || default_api_version(owner_kind)
        {
          "apiVersion" => owner_api_version.to_s,
          "kind" => owner_kind,
          "name" => name(owner),
          "uid" => uid(owner),
          "controller" => !!controller,
          "blockOwnerDeletion" => !!block_owner_deletion
        }.reject { |_key, value| value.nil? || value.to_s.empty? }
      end

      def default_api_version(kind)
        group = %w[Deployment ReplicaSet StatefulSet DaemonSet ControllerRevision].include?(kind) ? "apps" :
                %w[Job CronJob].include?(kind) ? "batch" :
                kind == "Lease" ? "coordination.k8s.io" : ""
        version = "v1"
        group.empty? ? version : "#{group}/#{version}"
      end

      def owner_reference_matches?(owner, dependent, controller: nil)
        owner_uid = uid(owner)
        owner_kind = kind(owner)
        owner_name = name(owner)
        owner_namespace = namespace(owner)
        # A Kubernetes ownerReference is an identity edge, not a name-based
        # association.  Refusing an owner without a UID prevents a stale
        # object (or an object recreated with the same name) from adopting a
        # dependent that belongs to a different incarnation.
        return false if owner_uid.nil? || owner_uid.empty?

        owner_references(dependent).any? do |ref|
          ref_kind = ref_value(ref, "kind", "").to_s
          ref_name = ref_value(ref, "name", "").to_s
          ref_uid = ref_value(ref, "uid", nil)&.to_s
          ref_controller = ref_value(ref, "controller", nil)
          next false unless ref_kind == owner_kind && ref_name == owner_name
          if controller != nil
            controller_flag = ref_controller == true || ref_controller.to_s.casecmp("true").zero?
            next false unless controller_flag == controller
          end
          next false unless ref_uid == owner_uid

          dependent_namespace = namespace(dependent)
          next false if owner_namespace && dependent_namespace.nil?

          owner_namespace.nil? || owner_namespace == dependent_namespace
        end
      end

      def condition(object, type)
        conditions = value(status(object), "conditions", [])
        return nil unless conditions.is_a?(Array)

        conditions.find { |item| value(item, "type", "").to_s == type.to_s }
      end

      def ready?(object)
        ready_condition = condition(object, "Ready")
        return value(status(object), "ready", false) == true if ready_condition.nil?

        value(ready_condition, "status", "").to_s == "True"
      end

      def integer(value, default = 0)
        return default if value.nil? || value.to_s.empty?

        Integer(value)
      rescue ArgumentError, TypeError
        default
      end

      # rand.SafeEncodeString alphabet (staging/src/k8s.io/apimachinery/pkg/util/rand/rand.go:83).
      SAFE_ENCODE_ALPHANUMS = "bcdfghjklmnpqrstvwxz2456789".freeze
      FNV_32_OFFSET = 2_166_136_261
      FNV_32_PRIME = 16_777_619

      # FNV-1a 32-bit (hash/fnv New32a), the hasher behind controller.ComputeHash.
      def fnv32a(bytes)
        bytes.to_s.each_byte.reduce(FNV_32_OFFSET) do |hash, byte|
          ((hash ^ byte) * FNV_32_PRIME) & 0xffffffff
        end
      end

      # FNV-1 32-bit (hash/fnv New32), used by history.HashControllerRevision.
      def fnv32(bytes)
        bytes.to_s.each_byte.reduce(FNV_32_OFFSET) do |hash, byte|
          ((hash * FNV_32_PRIME) & 0xffffffff) ^ byte
        end
      end

      def safe_encode_string(text)
        text.to_s.each_char.map { |char| SAFE_ENCODE_ALPHANUMS[char.ord % SAFE_ENCODE_ALPHANUMS.length] }.join
      end

      # controller.ComputeHash: FNV-1a over the PodTemplateSpec, then the
      # little-endian collisionCount in an 8-byte buffer, encoded with the
      # vowel-free alphabet so hashes read like upstream ReplicaSet suffixes.
      # The Go implementation hashes a spew dump of the typed struct; the
      # canonical JSON form is the equivalent deterministic serialization here.
      def pod_template_hash(template, collision_count = nil)
        bytes = JSON.generate(canonical(template))
        bytes += [Integer(collision_count)].pack("V") + "\0\0\0\0" unless collision_count.nil?
        safe_encode_string(fnv32a(bytes).to_s)
      end

      # history.HashControllerRevision: FNV-1 over the revision data followed
      # by the decimal collision probe.
      def controller_revision_hash(data, probe = nil)
        bytes = JSON.generate(canonical(data))
        bytes += Integer(probe).to_s unless probe.nil?
        safe_encode_string(fnv32(bytes).to_s)
      end

      # pkg/api/v1/pod/util.go IsPodAvailable.
      def pod_available?(pod, min_ready_seconds, now)
        return false unless ready?(pod) && condition(pod, "Ready")

        minimum = integer(min_ready_seconds, 0)
        return true if minimum.zero?

        transition = parse_time(value(condition(pod, "Ready"), "lastTransitionTime", nil))
        !transition.nil? && !now.nil? && transition + minimum <= now
      end

      def quantity(value, total, mode: :floor, default: 0)
        return default if value.nil?
        return [integer(value, default), 0].max unless value.to_s.end_with?("%")

        percentage = Float(value.to_s.delete_suffix("%"))
        scaled = total.to_f * percentage / 100.0
        result = mode == :ceil ? scaled.ceil : scaled.floor
        [result, 0].max
      rescue ArgumentError, TypeError
        default
      end
    end
  end
end
