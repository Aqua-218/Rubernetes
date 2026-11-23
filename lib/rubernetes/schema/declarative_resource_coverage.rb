# frozen_string_literal: true

module Rubernetes
  module Schema
    # The CoveredByDeclarative checks in pkg/apis/resource/validation/validation.go.
    # Their identities are collected independently of validation-gen. The REST
    # response continues to come from the resource's normal validators.
    class DeclarativeResourceCoverage
      KV = KubernetesValidator
      EFFECTS = %w[NoExecute NoSchedule None].freeze
      ATTRIBUTES = %w[bool int string version bools ints strings versions].freeze

      def initialize(schema, object, old)
        @legacy_api = schema.include?(".v1beta1.")
        @object = object
        @old = old
        @expected = []
      end

      def errors(kind, operation, subresource)
        spec = @object["spec"]
        case kind
        when "DeviceClass" then device_class(spec || {})
        when "ResourceSlice" then resource_slice(spec || {})
        when "ResourceClaim"
          if subresource == "status"
            claim_status
          elsif operation == :create
            claim_spec(spec)
          elsif (spec || {}) != (@old&.fetch("spec", nil) || {})
            add(%w[spec], :invalid, "immutable")
          end
        end
        @expected
      end

      private

      def add(path, code, origin = nil)
        @expected << [code, path, origin]
      end

      def bounded(list, path, max, key = nil)
        return unless list.is_a?(Array)

        if max && list.length > max
          add(path, :too_many, "maxItems")
          return
        end
        return unless block_given? || key

        seen = {}
        list.each_with_index do |entry, index|
          item_path = path + [index.to_s]
          yield(entry, item_path) if block_given?
          next unless key

          value = key.call(entry)
          add(item_path, :duplicate) if seen[value]
          seen[value] = true
        end
      end

      def named(field)
        ->(object) { KV.fetch(object, field).to_s }
      end

      def format(path, name, invalid)
        add(path, :invalid, "format=k8s-#{name}") if invalid
      end

      def validate_enum(path, value, list, required: false, optional: true)
        if required && value.to_s.empty?
          add(path, :required)
        elsif (!optional || !value.to_s.empty?) && !list.include?(value)
          add(path, :unsupported)
        end
      end

      def driver(path, value)
        name = value.to_s
        if name.empty?
          add(path, :required)
          return
        end

        add(path, :too_long, "maxLength") if name.bytesize > 63
        format(path, "long-name-caseless", !KV.dns1123_subdomain_messages(name.downcase).empty?)
      end

      def opaque_driver(config, path)
        opaque = KV.fetch(config, "opaque")
        driver(path + %w[opaque driver], opaque["driver"]) if opaque.is_a?(Hash)
      end

      def device_class(spec)
        name = KV.fetch(@object["metadata"], "name").to_s
        format(%w[metadata name], "long-name", !name.empty? && !KV.dns1123_subdomain_messages(name).empty?)
        bounded(KV.fetch(spec, "selectors"), %w[spec selectors], 32)
        bounded(KV.fetch(spec, "config"), %w[spec config], 32) { |config, path| opaque_driver(config, path) }
        name = KV.fetch(spec, "extendedResourceName")
        return unless name.is_a?(String)

        invalid = !name.include?("/") || name.include?("kubernetes.io/") || name.start_with?("requests.") ||
                  !KV.qualified_name_messages("requests.#{name}").empty?
        format(%w[spec extendedResourceName], "extended-resource-name", invalid)
      end

      def claim_spec(spec)
        devices = KV.fetch(spec, "devices")
        base = %w[spec devices]
        bounded(KV.fetch(devices, "requests"), base + ["requests"], 32, named("name")) do |entry, path|
          claim_request(entry, path)
        end
        bounded(KV.fetch(devices, "constraints"), base + ["constraints"], 32) do |entry, path|
          request_references(entry, path)
          attribute = KV.fetch(entry, "matchAttribute")
          match_attribute(attribute, path + ["matchAttribute"]) if attribute.is_a?(String)
        end
        bounded(KV.fetch(devices, "config"), base + ["config"], 32) do |entry, path|
          request_references(entry, path)
          opaque_driver(entry, path)
        end
      end

      def claim_request(entry, path)
        exact = KV.fetch(entry, "exactly")
        exact_path = path + ["exactly"]
        if @legacy_api
          scalars = !KV.fetch(entry, "deviceClassName").to_s.empty? || !KV.fetch(entry, "allocationMode").to_s.empty? ||
                    KV.fetch(entry, "count").to_i != 0
          compound = %w[selectors adminAccess tolerations capacity].any? { |name| !KV.fetch(entry, name).nil? }
          exact = entry if scalars || compound
          exact_path = path
        end
        alternatives = KV.fetch(entry, "firstAvailable")
        if alternatives.is_a?(Array) && !alternatives.empty?
          return unless exact.nil?

          bounded(alternatives, path + ["firstAvailable"], 8, named("name")) do |item, item_path|
            name = KV.fetch(item, "deviceClassName").to_s
            if name.empty?
              add(item_path + ["deviceClassName"], :required)
            else
              format(item_path + ["deviceClassName"], "long-name", !KV.dns1123_subdomain_messages(name).empty?)
            end
            device_request(item, item_path)
          end
        elsif exact
          device_request(exact, exact_path)
        end
      end

      def device_request(item, path)
        bounded(KV.fetch(item, "selectors"), path + ["selectors"], 32)
        validate_enum(path + ["allocationMode"], KV.fetch(item, "allocationMode"), %w[All ExactCount], optional: false)
        tolerations(item, path)
      end

      def tolerations(item, path)
        bounded(KV.fetch(item, "tolerations"), path + ["tolerations"], nil) do |toleration, item_path|
          key = KV.fetch(toleration, "key").to_s
          format(item_path + ["key"], "label-key", !key.empty? && !KV.qualified_name_messages(key).empty?)
          validate_enum(item_path + ["operator"], KV.fetch(toleration, "operator"), %w[Equal Exists], required: true)
          validate_enum(item_path + ["effect"], KV.fetch(toleration, "effect"), EFFECTS)
        end
      end

      def match_attribute(value, path)
        prefix, id, extra = value.split("/", -1)
        return if extra

        origin = "format=k8s-resource-fully-qualified-name"
        if id.nil?
          add(path, :invalid, origin)
          id = value
        elsif prefix.empty?
          add(path, :invalid, origin)
        else
          add(path, :too_long, origin) if prefix.bytesize > 63
          add(path, :invalid, origin) unless KV.dns1123_subdomain_messages(prefix.downcase).empty?
        end
        add(path, :too_long, origin) if id.bytesize > 32
        add(path, :invalid, origin) unless id.match?(DeclarativeRules::C_IDENTIFIER)
      end

      def request_references(entry, path)
        bounded(KV.fetch(entry, "requests"), path + ["requests"], 32, ->(name) { name })
      end

      def share_id(entry, path)
        id = KV.fetch(entry, "shareID")
        format(path + ["shareID"], "uuid", id.is_a?(String) && !id.match?(DeclarativeRules::UUID))
      end

      def claim_status
        status = @object["status"] || {}
        bounded(KV.fetch(status, "reservedFor"), %w[status reservedFor], 256, named("uid"))
        # The internal SharedDeviceID key maps both absent and empty IDs to
        # the empty string. The generated comparator checks pointer presence.
        device_key = ->(device) { KV.claim_device_id(device) }
        bounded(KV.fetch(status, "devices"), %w[status devices], nil, device_key) do |device, path|
          share_id(device, path)
          device_network(KV.fetch(device, "networkData"), path + ["networkData"])
        end

        allocation = KV.fetch(status, "allocation")
        old = @old&.dig("status", "allocation")
        return unless allocation.is_a?(Hash)

        if old
          add(%w[status allocation], :invalid, "update") unless allocation == old
        else
          allocation_results(allocation["devices"])
        end
      end

      def device_network(network, path)
        {"interfaceName" => 256, "hardwareAddress" => 128}.each do |field, max|
          add(path + [field], :too_long, "maxBytes") if KV.fetch(network, field).to_s.bytesize > max
        end
        bounded(KV.fetch(network, "ips"), path + ["ips"], 16, ->(ip) { ip })
      end

      def allocation_results(devices)
        base = %w[status allocation devices]
        bounded(KV.fetch(devices, "results"), base + ["results"], 32) do |entry, path|
          driver(path + ["driver"], KV.fetch(entry, "driver"))
          pool = KV.fetch(entry, "pool").to_s
          if pool.empty?
            add(path + ["pool"], :required)
          else
            origin = "format=k8s-resource-pool-name"
            add(path + ["pool"], :too_long, origin) if pool.bytesize > 253
            invalid = pool.split("/", -1).any? { |part| !KV.dns1123_subdomain_messages(part).empty? }
            format(path + ["pool"], "resource-pool-name", invalid)
          end
          binding_conditions(entry, path)
          share_id(entry, path)
        end
        bounded(KV.fetch(devices, "config"), base + ["config"], 64) do |entry, path|
          validate_enum(path + ["source"], KV.fetch(entry, "source"), %w[FromClass FromClaim], required: true)
          request_references(entry, path)
          opaque_driver(entry, path)
        end
      end

      def binding_conditions(entry, path)
        %w[bindingConditions bindingFailureConditions].each do |field|
          bounded(KV.fetch(entry, field), path + [field], 4)
        end
      end

      def resource_slice(spec)
        devices = KV.fetch(spec, "devices")
        previous = Array(@old&.dig("spec", "devices"))
        entries = Array(devices).map { |device| KV.fetch(device, "basic") || device }
        advanced = entries.any? do |device|
          %w[taints consumesCounters].any? { |field| !Array(KV.fetch(device, field)).empty? } ||
            (KV.fetch(device, "attributes") || {}).values.any? do |attribute|
              ATTRIBUTES.last(4).any? { |field| !KV.fetch(attribute, field).nil? }
            end
        end
        # The outer device limit has no CoveredByDeclarative marker, but it
        # short-circuits the checks of each individual device.
        if entries.length <= (advanced ? 64 : 128)
          entries.each_with_index do |device, index|
            old_device = previous.find { |old| KV.fetch(old, "name") == KV.fetch(devices[index], "name") }
            path = ["spec", "devices", index.to_s]
            if @legacy_api
              path += ["basic"]
              old_device = KV.fetch(old_device, "basic")
            end
            slice_device(device, old_device, path)
          end
        end
        bounded(KV.fetch(spec, "sharedCounters"), %w[spec sharedCounters], 8, named("name")) do |counter, path|
          counter_names(counter, path, "name", 32)
        end
      end

      def slice_device(device, old, path)
        attributes = KV.fetch(device, "attributes")
        if attributes.is_a?(Hash)
          attributes.each do |name, attribute|
            add(path + ["attributes", "[#{name}]"], :invalid, "union") if ATTRIBUTES.count { |field| !KV.fetch(attribute, field).nil? } != 1
          end
        end
        taints = KV.fetch(device, "taints")
        if Array(taints) != Array(KV.fetch(old, "taints"))
          bounded(taints, path + ["taints"], 16) do |entry, item_path|
            validate_enum(item_path + ["effect"], KV.fetch(entry, "effect"), EFFECTS, required: true)
          end
        end
        bounded(KV.fetch(device, "consumesCounters"), path + ["consumesCounters"], 2, named("counterSet")) do |counter, item_path|
          counter_names(counter, item_path, "counterSet", 32)
        end
        binding_conditions(device, path)
      end

      def counter_names(counter, path, item_name, limit)
        name = KV.fetch(counter, item_name).to_s
        if name.empty?
          add(path + [item_name], :required)
        else
          format(path + [item_name], "short-name", !KV.dns1123_label_messages(name).empty?)
        end
        counts = KV.fetch(counter, "counters")
        return unless counts.is_a?(Hash) && counts.length <= limit

        format(path + ["counters"], "short-name", counts.keys.any? { |key| !KV.dns1123_label_messages(key).empty? })
      end
    end
  end
end
