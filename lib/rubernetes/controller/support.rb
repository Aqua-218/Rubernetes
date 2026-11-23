# frozen_string_literal: true

require "securerandom"
require "digest"
require "json"
require "time"

require_relative "../support/object_graph"
require_relative "../api/status"
require_relative "../api/selectors"

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
      GENERATE_NAME_ALPHABET = "bcdfghjklmnpqrstvwxz2456789"

      def random_suffix(length = 5)
        Array.new(length) { GENERATE_NAME_ALPHABET[SecureRandom.random_number(GENERATE_NAME_ALPHABET.length)] }.join
      end

      def unique_pod_name(prefix, names)
        loop do
          name = "#{prefix}-#{random_suffix}"
          return name if names.add?(name)
        end
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

      def service_endpoint_labels(service)
        result = labels(service).except("service.kubernetes.io/headless")
        cluster_ip = value(spec(service), "clusterIP")
        result["service.kubernetes.io/headless"] = "" if cluster_ip.to_s.empty? || cluster_ip == "None"
        result
      end

      # endpointslice/util: completed Pods are excluded from both endpoint APIs.
      def pod_in_endpoints?(pod, include_terminating:)
        pod_status = status(pod)
        return false if %w[Succeeded Failed].include?(value(pod_status, "phase"))
        return false if !include_terminating && terminating_endpoint_pod?(pod)

        primary_ip = value(pod_status, "podIP") || value(pod_status, "podIp")
        !primary_ip.to_s.empty? || !Array(value(pod_status, "podIPs")).empty?
      end

      def terminating_endpoint_pod?(pod)
        !value(metadata(pod), "deletionTimestamp").nil?
      end

      def pod_endpoint_ips(pod)
        pod_status = status(pod)
        ips = Array(value(pod_status, "podIPs")).filter_map do |entry|
          ip = value(entry, "ip").to_s
          ip unless ip.empty?
        end
        return ips unless ips.empty?

        primary_ip = value(pod_status, "podIP") || value(pod_status, "podIp")
        primary_ip.to_s.empty? ? [] : [primary_ip.to_s]
      end

      def endpoint_hostname(pod, service)
        pod_spec = spec(pod)
        hostname = value(pod_spec, "hostname")
        return if hostname.to_s.empty? || value(pod_spec, "subdomain") != name(service)

        hostname if namespace(pod).to_s == namespace(service).to_s
      end

      # endpointslice.FindPort resolves a named Service port on each Pod.
      # App containers take precedence, followed by restartable init containers.
      def service_endpoint_ports(service, pod, include_empty_name:)
        Array(value(spec(service), "ports")).filter_map do |port|
          protocol = value(port, "protocol", "TCP")
          target = value(port, "targetPort") || value(port, "port")
          number = target.is_a?(String) ? named_container_port(pod, target, protocol) : target
          next unless number.is_a?(Integer) && number.positive?

          result = {"port" => number, "protocol" => protocol}
          name = value(port, "name").to_s
          result["name"] = name if include_empty_name || !name.empty?
          app_protocol = value(port, "appProtocol")
          result["appProtocol"] = app_protocol unless app_protocol.to_s.empty?
          result
        end
      end

      def named_container_port(pod, name, protocol)
        %w[containers initContainers].each do |group|
          Array(value(spec(pod), group)).each do |container|
            next if group == "initContainers" && value(container, "restartPolicy") != "Always"

            match = Array(value(container, "ports")).find { |port| value(port, "name") == name && value(port, "protocol", "TCP") == protocol }
            return value(match, "containerPort") if match
          end
        end
        nil
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

      DEEP_FROZEN = ObjectSpace::WeakMap.new

      def deep_copy(value, seen = nil) = ObjectGraph.copy(value, seen)
      def deep_freeze(value, seen = nil) = ObjectGraph.deep_freeze(value, seen)
      def immutable_copy(value) = ObjectGraph.immutable_copy(value, DEEP_FROZEN)
      def deep_frozen?(value) = DEEP_FROZEN.key?(value)

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
          result[key] = if value.is_a?(Hash) && result[key].is_a?(Hash)
                          merge_hash(result[key], value)
                        else
                          deep_copy(value)
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

        requirements = (value(selector, "matchLabels", nil) || {}).map { |key, expected| [key.to_s, "#{key}=#{expected}"] }
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
        selector_predicate(selector).call(object)
      end

      # Compile once per reconciliation when one selector is tested against a
      # collection. Never cache across updates to the owning resource.
      def selector_predicate(selector)
        return ->(object) { !!selector.call(object) } if selector.respond_to?(:call)
        return ->(_object) { true } if selector.nil?

        if selector.is_a?(Hash)
          return ->(object) { selector_labels_match?(selector, labels(object)) } unless structured_label_selector?(selector)

          match_labels = value(selector, "matchLabels")
          requirements = Array(value(selector, "matchExpressions")).map do |expression|
            operator = LABEL_EXPRESSION_OPERATORS[value(expression, "operator", "In").to_s]
            return ->(_object) { false } unless operator

            API::Selector::Requirement.new(key: value(expression, "key", ""), operator: operator, values: value(expression, "values", []))
          end
        else
          requirements = API::Selector.parse(selector, skip_empty_terms: true).requirements
        end
        lambda do |object|
          candidate = labels(object)
          (!match_labels.is_a?(Hash) || selector_labels_match?(match_labels, candidate)) &&
            requirements.all? { |requirement| label_requirement_matches?(requirement, candidate) }
        end
      rescue API::Selector::Error
        ->(_object) { false }
      end

      LABEL_EXPRESSION_OPERATORS = {"In" => :in, "NotIn" => :not_in,
                                    "Exists" => :exists, "DoesNotExist" => :not_exists}.freeze

      def structured_label_selector?(selector)
        # These field names are also legal plain label keys. Recognize the
        # structured form by its value shapes so a Service map can use them.
        match_labels = value(selector, "matchLabels")
        expressions = value(selector, "matchExpressions")
        match_labels.is_a?(Hash) || (expressions.is_a?(Array) && expressions.all?(Hash)) ||
          (match_labels.nil? && (selector.key?("matchLabels") || selector.key?(:matchLabels)))
      end

      # Some callers also accept a legacy matchLabels wrapper for a plain
      # map. Only unwrap when the value is itself a map.
      def unwrap_match_labels(selector)
        match_labels = value(selector, "matchLabels")
        match_labels.is_a?(Hash) ? match_labels : selector
      end

      def selector_labels_match?(selector, labels)
        selector.all? do |key, expected|
          key = key.to_s
          key = key.to_sym unless labels.key?(key)
          next false unless labels.key?(key)

          actual = labels[key].to_s
          expected.is_a?(Array) ? expected.any? { |candidate| candidate.to_s == actual } : actual == expected.to_s
        end
      end

      def text_selector_matches?(selector, labels)
        API::Selector.parse(selector, skip_empty_terms: true).requirements.all? do |requirement|
          label_requirement_matches?(requirement, labels)
        end
      rescue API::Selector::Error
        false
      end

      def label_requirement_matches?(requirement, labels)
        key = requirement.key
        key = key.to_sym unless labels.key?(key)
        requirement.matches?(labels[key], present: labels.key?(key))
      end

      def owner_references(object)
        refs = value(metadata(object), "ownerReferences", [])
        refs.is_a?(Array) ? refs.grep(Hash) : []
      end

      def controller_owner_reference(object)
        owner_references(object).find { |ref| ref_value(ref, "controller", false).to_s.casecmp?("true") }
      end

      def ref_value(ref, key, default = nil)
        value(ref, key, default)
      end

      # RecheckDeletionTimestamp before claiming an orphan from an informer.
      def adoption_allowed?(adapter, owner, descriptor)
        return true unless Builtins::AdapterCapability.live_reads?(adapter)

        fresh = adapter.find_live(descriptor, name: name(owner), namespace: namespace(owner))
        !fresh.nil? && uid(fresh).to_s == uid(owner).to_s && value(metadata(fresh), "deletionTimestamp", nil).nil?
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
        group = if %w[Deployment ReplicaSet StatefulSet DaemonSet ControllerRevision].include?(kind)
                  "apps"
                elsif %w[Job CronJob].include?(kind)
                  "batch"
                else
                  kind == "Lease" ? "coordination.k8s.io" : ""
                end
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

          unless controller.nil?
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
      SAFE_ENCODE_ALPHANUMS = "bcdfghjklmnpqrstvwxz2456789"
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

      QUANTITY_SUFFIXES = {
        "Ki" => 1024.0, "Mi" => 1024.0**2, "Gi" => 1024.0**3, "Ti" => 1024.0**4,
        "Pi" => 1024.0**5, "Ei" => 1024.0**6, "n" => 1e-9, "u" => 1e-6,
        "m" => 1e-3, "k" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12,
        "P" => 1e15, "E" => 1e18
      }.freeze

      def quantity_to_base(value)
        return value.to_f if value.is_a?(Numeric)

        text = value.to_s.strip
        return 0.0 if text.empty?
        return text.to_f if text.match?(/\A-?(?:\d+(?:\.\d+)?|\.\d+)\z/)

        suffix, multiplier = QUANTITY_SUFFIXES.find { |candidate, _| text.end_with?(candidate) }
        return text.to_f unless suffix

        text.delete_suffix(suffix).to_f * multiplier
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
